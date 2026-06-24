from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from common import (
    BENCHMARKS_DIR,
    RUNS_DIR,
    SUITES,
    candidate_duplicate_key,
    candidate_is_actionable,
    candidate_is_meaningful,
    candidate_is_oracle_confirmed,
    candidate_score,
    first_trace_times,
    load_yaml,
    normalize_expected_schema,
    read_json,
    safe_float,
    safe_int,
    suite_case_expected_path,
    write_json,
)

MEANINGFUL_LABELS = {
    "PanicAfterUnsafe",
    "InsideUnsafePanic",
    "DangerousPathReached",
    "OracleConfirmedBug",
    "SuspiciousCandidate",
}

NOISE_LABELS = {
    "Noise",
    "ContractPanic",
    "BlockingPanic",
    "HarnessMisuse",
}

CONFIRMED_ORACLES = {
    "AddressSanitizerDoubleFree",
    "AddressSanitizerUseAfterFree",
    "AddressSanitizerOutOfBounds",
    "AddressSanitizerInvalidFree",
    "AddressSanitizerLeak",
    "MiriUndefinedBehavior",
}

# A clean ASan/Miri replay is not proof that a candidate is security-irrelevant.
# Negative truth must come from adjudicated candidate annotations or controlled
# benchmark ground truth, never from NoOracleFinding.
NEGATIVE_ORACLES: set[str] = set()

UNKNOWN_PRIMARY_LABELS = {"Unknown"}
NON_REPORTED_PRIMARY_LABELS = {"Noise", "Unknown"}
EPOCH_LIKE_MS = 100_000_000_000  # ms since 1970; prevents treating wall-clock timestamps as durations.


def div_or_none(num: float, den: float) -> float | None:
    return None if den == 0 else num / den


def safe_div(num: float, den: float) -> float:
    """Backward-compatible helper for metrics where an empty denominator means 0."""
    return 0.0 if den == 0 else num / den


TRUE_VALUES = {"1", "true", "yes", "y", "positive", "relevant"}
FALSE_VALUES = {"0", "false", "no", "n", "negative", "irrelevant"}


def parse_optional_bool(value: Any) -> bool | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    raise ValueError(f"invalid boolean value in candidate truth CSV: {value!r}")


def normalize_truth_row(row: dict[str, Any]) -> dict[str, Any] | None:
    security_relevant = parse_optional_bool(row.get("security_relevant"))
    if security_relevant is None:
        return None
    normalized: dict[str, Any] = {
        "security_relevant": security_relevant,
        "truth_source": str(row.get("truth_source") or "candidate-adjudication"),
        "rationale": str(row.get("rationale") or ""),
        "candidate_id": str(row.get("candidate_id") or "").strip(),
        "input_sha256": str(row.get("input_sha256") or "").strip().lower(),
        "suite": str(row.get("suite") or "").strip(),
        "case": str(row.get("case") or "").strip(),
    }
    for field in ["primary_label", "relation", "harness_status", "oracle_verdict"]:
        value = str(row.get(field) or "").strip()
        if value:
            normalized[field] = value
    return normalized


def load_candidate_truth(path: Path | None) -> dict[str, Any]:
    index: dict[str, Any] = {
        "path": str(path.resolve()) if path else None,
        "by_candidate_id": {},
        "by_case_sha256": {},
        "rows_loaded": 0,
        "rows_skipped_incomplete": 0,
    }
    if path is None:
        return index
    if not path.exists():
        raise FileNotFoundError(f"candidate truth CSV not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"security_relevant"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise RuntimeError(f"candidate truth CSV missing columns: {sorted(missing)}")
        for raw in reader:
            normalized = normalize_truth_row(dict(raw))
            if normalized is None:
                index["rows_skipped_incomplete"] += 1
                continue
            candidate_id = normalized.get("candidate_id")
            case = normalized.get("case")
            digest = normalized.get("input_sha256")
            if not candidate_id and not (case and digest):
                raise RuntimeError(
                    "each completed candidate truth row needs candidate_id or both case and input_sha256"
                )
            if candidate_id:
                existing = index["by_candidate_id"].get(candidate_id)
                if existing is not None and existing["security_relevant"] != normalized["security_relevant"]:
                    raise RuntimeError(f"conflicting truth rows for candidate_id={candidate_id}")
                index["by_candidate_id"][candidate_id] = normalized
            if case and digest:
                key = (case, digest)
                existing = index["by_case_sha256"].get(key)
                if existing is not None and existing["security_relevant"] != normalized["security_relevant"]:
                    raise RuntimeError(f"conflicting truth rows for case/input_sha256={key}")
                index["by_case_sha256"][key] = normalized
            index["rows_loaded"] += 1
    return index


def candidate_truth_for_meta(meta: dict[str, Any], index: dict[str, Any]) -> dict[str, Any] | None:
    candidate_id = str(meta.get("candidate_id") or "").strip()
    if candidate_id and candidate_id in index.get("by_candidate_id", {}):
        return dict(index["by_candidate_id"][candidate_id])
    case = str(meta.get("case") or meta.get("crate") or "").strip()
    digest = str(meta.get("input_sha256") or "").strip().lower()
    if case and digest:
        match = index.get("by_case_sha256", {}).get((case, digest))
        if match is not None:
            return dict(match)
    return None


def load_expected(suite: str, case: str) -> dict[str, Any] | None:
    """Load expected.yaml for a run.

    generated_harness runs often use a real benchmark case as the crate name while the
    run suite is generated_harness. In that situation, fall back to benchmarks/*/<case>
    so cargo-fuzz+RustDPR pilots over micro/taxonomy/regression cases can still use the
    original ground truth. If multiple benchmark suites contain the same case name, we
    avoid guessing and return None.
    """
    direct = suite_case_expected_path(suite, case)
    if direct.exists():
        return normalize_expected_schema(load_yaml(direct) or {})

    if suite != "generated_harness":
        return None

    matches: list[Path] = []
    if BENCHMARKS_DIR.exists():
        for suite_dir in BENCHMARKS_DIR.iterdir():
            if not suite_dir.is_dir() or suite_dir.name == "generated_harness":
                continue
            expected = suite_dir / case / "expected.yaml"
            if expected.exists():
                matches.append(expected)
    if len(matches) == 1:
        return normalize_expected_schema(load_yaml(matches[0]) or {})
    return None


def iter_runs(
    suite: str,
    *,
    candidate_truth_index: dict[str, Any] | None = None,
    allow_case_truth_for_candidates: bool = False,
    run_indices: set[int] | None = None,
) -> list[dict[str, Any]]:
    rows = []
    candidate_truth_index = candidate_truth_index or load_candidate_truth(None)
    suite_dir = RUNS_DIR / suite
    if not suite_dir.exists():
        return rows
    seen_run_dirs: set[str] = set()
    for classification_path in sorted(suite_dir.rglob("classification.json")):
        run_dir = classification_path.parent
        run_dir_key = str(run_dir.resolve())
        if run_dir_key in seen_run_dirs:
            continue
        seen_run_dirs.add(run_dir_key)
        classification = read_json(classification_path)
        meta_path = run_dir / "run_meta.json"
        if not meta_path.exists():
            raise RuntimeError(f"run_meta.json not found for run: {run_dir}")
        meta = read_json(meta_path)
        run_index = int(meta.get("run_index", 1) or 1)
        if run_indices and run_index not in run_indices:
            continue
        case = meta["case"]
        unit_of_analysis = str(meta.get("unit_of_analysis") or "run")
        truth_source = None
        if unit_of_analysis == "candidate":
            expected = candidate_truth_for_meta(meta, candidate_truth_index)
            if expected is not None:
                truth_source = expected.get("truth_source") or "candidate-adjudication"
            elif allow_case_truth_for_candidates:
                expected = load_expected(suite, case)
                truth_source = "legacy-case-truth-for-candidate" if expected is not None else None
            else:
                expected = None
        else:
            expected = load_expected(suite, case)
            truth_source = "benchmark-expected-yaml" if expected is not None else None
        rows.append(
            {
                "suite": suite,
                "case": case,
                "run_dir": str(run_dir),
                "tool": meta["tool"],
                "variant": meta["variant"],
                "mode": meta.get("mode", "deterministic"),
                "seed": meta["seed"],
                "run_index": run_index,
                "unit_of_analysis": unit_of_analysis,
                "classification": classification,
                "expected": expected,
                "truth_source": truth_source,
                "meta": meta,
            }
        )
    return rows


def iter_campaign_records(suite: str, *, run_indices: set[int] | None = None) -> list[dict[str, Any]]:
    """Load campaign observations, including seeds that produced zero artifacts.

    These records contribute only to campaign support and CPU-hour/yield
    denominators. They are never treated as classified candidates.
    """
    rows: list[dict[str, Any]] = []
    suite_dir = RUNS_DIR / suite
    if not suite_dir.exists():
        return rows
    for path in sorted(suite_dir.rglob("campaign_record.json")):
        meta = read_json(path)
        run_index = int(meta.get("run_index", 1) or 1)
        if run_indices and run_index not in run_indices:
            continue
        rows.append(
            {
                "suite": suite,
                "case": meta.get("case") or meta.get("crate") or "unknown",
                "run_dir": str(path.parent),
                "tool": meta.get("tool", "unknown"),
                "variant": meta.get("variant", "unknown"),
                "mode": meta.get("mode", "campaign"),
                "seed": meta.get("seed", 0),
                "run_index": run_index,
                "unit_of_analysis": "campaign",
                "classification": {},
                "expected": None,
                "truth_source": None,
                "meta": meta,
            }
        )
    return rows


def confusion_counts(rows: list[dict[str, Any]], field: str) -> dict[str, Any]:
    labels = set()
    pairs = []
    for row in rows:
        expected = row.get("expected")
        if not expected:
            continue
        exp = expected.get(field)
        act = row["classification"].get(field)
        labels.add(exp)
        labels.add(act)
        pairs.append((exp, act))

    label_list = sorted(x for x in labels if x is not None)
    matrix = {a: {b: 0 for b in label_list} for a in label_list}
    for exp, act in pairs:
        if exp in matrix and act in matrix[exp]:
            matrix[exp][act] += 1

    per_label = {}
    for label in label_list:
        tp = matrix[label][label]
        fp = sum(matrix[other][label] for other in label_list if other != label)
        fn = sum(matrix[label][other] for other in label_list if other != label)
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        f1 = safe_div(2 * precision * recall, precision + recall)
        per_label[label] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    macro_f1 = safe_div(sum(v["f1"] for v in per_label.values()), len(per_label)) if per_label else 0.0
    total_tp = sum(per_label[l]["tp"] for l in per_label)
    total_fp = sum(per_label[l]["fp"] for l in per_label)
    total_fn = sum(per_label[l]["fn"] for l in per_label)
    micro_p = safe_div(total_tp, total_tp + total_fp)
    micro_r = safe_div(total_tp, total_tp + total_fn)
    micro_f1 = safe_div(2 * micro_p * micro_r, micro_p + micro_r)

    return {
        "labels": label_list,
        "matrix": matrix,
        "per_label": per_label,
        "macro_f1": macro_f1,
        "micro_f1": micro_f1,
    }


def load_run_artifact(row: dict[str, Any], filename: str) -> dict[str, Any] | None:
    path = Path(row["run_dir"]) / filename
    if not path.exists():
        return None
    return read_json(path)


def classification_notes(row: dict[str, Any]) -> dict[str, Any]:
    notes = row["classification"].get("notes")
    return notes if isinstance(notes, dict) else {}


def evidence_source(row: dict[str, Any]) -> dict[str, Any]:
    classification = row["classification"]
    source = classification.get("evidence_source")
    if isinstance(source, dict):
        return source
    notes_source = classification_notes(row).get("evidence_source")
    if isinstance(notes_source, dict):
        return notes_source
    meta_source = (row.get("meta") or {}).get("evidence_source")
    return meta_source if isinstance(meta_source, dict) else {}


def replay_summary_for_row(row: dict[str, Any]) -> dict[str, Any] | None:
    meta = row.get("meta") or {}
    candidates = []
    if meta.get("replay_summary"):
        candidates.append(Path(str(meta["replay_summary"])))
    if meta.get("rustdpr_replay_summary_path"):
        candidates.append(Path(str(meta["rustdpr_replay_summary_path"])))
    candidates.append(Path(row["run_dir"]) / "replay_summary.json")
    for path in candidates:
        if path.exists():
            return read_json(path)
    return None


def has_missing_replay_evidence(row: dict[str, Any]) -> bool:
    """True when RustDPR could not obtain independent replay trace evidence.

    Missing replay evidence is not noise. It should be excluded from precision/FPR
    denominators and reported separately as unsupported infrastructure/evidence.
    """
    classification = row["classification"]
    meta = row.get("meta") or {}
    source = evidence_source(row)
    replay = replay_summary_for_row(row) or {}
    fired = set(classification_notes(row).get("fired_rules") or [])
    decision_path = " ".join(str(x) for x in (classification_notes(row).get("decision_path") or []))
    replay_status = str(meta.get("replay_status") or replay.get("status") or "")

    return bool(
        source.get("missing_independent_trace")
        or "missing-rustdpr-independent-trace" in fired
        or replay_status in {"missing-rustdpr-trace", "no-inputs"}
        or "missing-rustdpr-independent-trace" in decision_path
    )


def has_independent_trace_evidence(row: dict[str, Any]) -> bool:
    trace = load_run_artifact(row, "trace_log.json")
    if trace and len(trace.get("events") or []) > 0:
        return True
    meta = row.get("meta") or {}
    if str(meta.get("unit_of_analysis") or row.get("unit_of_analysis") or "run") == "candidate":
        # Candidate-level experiments must never fall back to an aggregate trace.
        return safe_int(meta.get("replay_trace_events"), 0) > 0
    if safe_int(meta.get("replay_combined_trace_events"), 0) > 0:
        return True
    replay = replay_summary_for_row(row) or {}
    return safe_int(replay.get("combined_trace_events"), 0) > 0


def is_reported_candidate(row: dict[str, Any]) -> bool:
    if has_missing_replay_evidence(row):
        return False
    classification = row["classification"]
    primary = str(classification.get("primary_label") or "Unknown")
    if primary in NON_REPORTED_PRIMARY_LABELS:
        return False
    return True


def is_review_queue_candidate(row: dict[str, Any]) -> bool:
    """True only for candidates RustDPR would actually send to reviewers.

    RustDPR is a triage/validation layer, so its main precision/FPR should be
    computed over the review queue, not over every classification it emits for
    every replayed input. Missing independent replay evidence is unsupported and
    never enters the review queue.
    """
    if has_missing_replay_evidence(row):
        return False
    return bool(row["classification"].get("review_required"))


def truth_status(row: dict[str, Any]) -> bool | None:
    """Return ground-truth security relevance if assessable, otherwise None.

    Priority: oracle-confirmed positive > benchmark expected.yaml > explicit negative
    oracle verdict. We intentionally do not let a pipeline's own primary_label define
    truth, because that makes crash-only baselines self-confirming.
    """
    classification = row["classification"]
    oracle = str(classification.get("oracle_verdict") or "Unknown")
    if oracle in CONFIRMED_ORACLES:
        return True
    expected = row.get("expected")
    if expected is not None:
        return bool(expected.get("security_relevant"))
    if oracle in NEGATIVE_ORACLES:
        return False
    return None


def is_true_candidate(row: dict[str, Any]) -> bool:
    return truth_status(row) is True


def confidence_rank(row: dict[str, Any]) -> float:
    classification = row["classification"]
    reached_count = len(classification.get("reached_dangerous_sites") or [])
    return candidate_score(
        classification,
        reached_count=reached_count,
        replay_stable=replay_stable_for_row(row),
        duplicate_ordinal=1,
    )


def ranked_assessable_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    assessable = [row for row in rows if truth_status(row) is not None and not has_missing_replay_evidence(row)]
    return sorted(assessable, key=confidence_rank, reverse=True)


def precision_at_k_counts(rows: list[dict[str, Any]], k: int) -> tuple[int, int] | None:
    ranked = ranked_assessable_rows(rows)[:k]
    if not ranked:
        return None
    return sum(1 for row in ranked if is_true_candidate(row)), len(ranked)


def precision_at_k(rows: list[dict[str, Any]], k: int) -> float | None:
    counts = precision_at_k_counts(rows, k)
    if counts is None:
        return None
    num, den = counts
    return div_or_none(num, den)


def recall_at_k_counts(rows: list[dict[str, Any]], k: int) -> tuple[int, int] | None:
    assessable = [row for row in rows if truth_gain(row) is not None]
    positives = [row for row in assessable if (truth_gain(row) or 0.0) > 0.0]
    if not positives:
        return None
    ranked = sorted(assessable, key=confidence_rank, reverse=True)[:k]
    return sum(1 for row in ranked if (truth_gain(row) or 0.0) > 0.0), len(positives)


def ndcg_at_k_support(rows: list[dict[str, Any]], k: int) -> tuple[float, float] | None:
    gains = [(row, truth_gain(row)) for row in rows]
    assessable = [(row, gain) for row, gain in gains if gain is not None]
    if not assessable:
        return None
    ideal_gains = sorted((float(gain) for _, gain in assessable), reverse=True)
    if not any(gain > 0 for gain in ideal_gains):
        return None
    ranked_gains = [float(gain) for _, gain in sorted(assessable, key=lambda x: confidence_rank(x[0]), reverse=True)]
    return dcg_at_k(ranked_gains, k), dcg_at_k(ideal_gains, k)


def mean_reciprocal_rank(rows: list[dict[str, Any]]) -> float | None:
    assessable = [row for row in rows if truth_status(row) is not None and not has_missing_replay_evidence(row)]
    if not assessable:
        return None
    ranked = sorted(assessable, key=confidence_rank, reverse=True)
    for idx, row in enumerate(ranked, start=1):
        if is_true_candidate(row):
            return 1.0 / idx
    return 0.0


def reviews_to_first_confirmed(rows: list[dict[str, Any]]) -> int | None:
    ranked = sorted((r for r in rows if not has_missing_replay_evidence(r)), key=confidence_rank, reverse=True)
    reviewed = 0
    for row in ranked:
        if row["classification"].get("review_required") or row["classification"].get("primary_label") not in {"Noise", "Unknown"}:
            reviewed += 1
        if is_true_candidate(row):
            return max(reviewed, 1)
    return None


def replay_stable_for_row(row: dict[str, Any]) -> bool:
    classification = row["classification"]
    if "replay_stable" in classification:
        return bool(classification.get("replay_stable"))
    summary = Path(row["run_dir"]) / "replay_summary.json"
    if summary.exists():
        replay = read_json(summary)
        return bool(replay.get("stable") or replay.get("replay_stable"))
    queue = Path(row["run_dir"]) / "oracle_queue" / "oracle_queue_result.json"
    if queue.exists():
        data = read_json(queue)
        return bool(data.get("stable") or data.get("replay_stable"))
    replay = replay_summary_for_row(row)
    if replay:
        return bool(replay.get("stable") or replay.get("replay_stable"))
    return False


def truth_gain(row: dict[str, Any]) -> float | None:
    truth = truth_status(row)
    if truth is None or has_missing_replay_evidence(row):
        return None
    if not truth:
        return 0.0
    if candidate_is_oracle_confirmed(row["classification"]):
        return 3.0
    if candidate_is_actionable(row["classification"]):
        return 2.0
    return 1.0


def recall_at_k(rows: list[dict[str, Any]], k: int) -> float | None:
    counts = recall_at_k_counts(rows, k)
    if counts is None:
        return None
    num, den = counts
    return div_or_none(num, den)


def oracle_confirmed_at_k(rows: list[dict[str, Any]], k: int) -> int | None:
    eligible = [row for row in rows if not has_missing_replay_evidence(row)]
    if not eligible:
        return None
    ranked = sorted(eligible, key=confidence_rank, reverse=True)[:k]
    return sum(1 for row in ranked if candidate_is_oracle_confirmed(row["classification"]))


def dcg_at_k(gains: list[float], k: int) -> float:
    import math

    total = 0.0
    for idx, gain in enumerate(gains[:k], start=1):
        total += (2.0**gain - 1.0) / math.log2(idx + 1)
    return total


def ndcg_at_k(rows: list[dict[str, Any]], k: int) -> float | None:
    support = ndcg_at_k_support(rows, k)
    if support is None:
        return None
    dcg, ideal = support
    return div_or_none(dcg, ideal)


def dangerous_ids_for_row(row: dict[str, Any]) -> set[str]:
    site_map = load_run_artifact(row, "site_map.json")
    if not site_map:
        return set()
    return {str(site.get("site_id")) for site in site_map.get("dangerous_sites", []) if site.get("site_id") is not None}


def row_time_origin_ms(row: dict[str, Any], trace: dict[str, Any] | None = None) -> int | None:
    meta = row.get("meta") or {}
    for key in ["run_start_time_ms", "start_time_ms", "start_ts_millis", "start_timestamp_ms", "fuzz_start_time_ms"]:
        value = meta.get(key)
        if value is not None:
            parsed = safe_int(value, -1)
            if parsed >= 0:
                return parsed
    if trace is None:
        trace = load_run_artifact(row, "trace_log.json")
    times = first_trace_times(trace, dangerous_ids_for_row(row)) if trace else {}
    first = times.get("first_event_time_ms")
    return first if first is not None else None


def normalize_event_time_ms(value: Any, row: dict[str, Any], trace: dict[str, Any] | None = None) -> int | None:
    if value is None:
        return None
    raw = safe_int(value, -1)
    if raw < 0:
        return None
    if raw < EPOCH_LIKE_MS:
        return raw
    origin = row_time_origin_ms(row, trace)
    if origin is not None and origin >= EPOCH_LIKE_MS and raw >= origin:
        return raw - origin
    # Avoid reporting a wall-clock timestamp as a duration.
    return None


def candidate_first_seen_ms(row: dict[str, Any]) -> int | None:
    classification = row["classification"]
    trace = load_run_artifact(row, "trace_log.json")
    for key in ["first_seen_time_ms", "dangerous_hit_time_ms", "panic_time_ms"]:
        normalized = normalize_event_time_ms(classification.get(key), row, trace)
        if normalized is not None:
            return normalized
    times = first_trace_times(trace, dangerous_ids_for_row(row)) if trace else {}
    raw = times.get("dangerous_hit_time_ms") or times.get("panic_time_ms") or times.get("first_event_time_ms")
    return normalize_event_time_ms(raw, row, trace)


def time_to_first_actionable_ms(rows: list[dict[str, Any]]) -> int | None:
    values = [candidate_first_seen_ms(row) for row in rows if candidate_is_actionable(row["classification"]) and not has_missing_replay_evidence(row)]
    values = [value for value in values if value is not None]
    return min(values) if values else None


def time_to_first_oracle_confirmed_ms(rows: list[dict[str, Any]]) -> int | None:
    values: list[int] = []
    for row in rows:
        if not candidate_is_oracle_confirmed(row["classification"]) or has_missing_replay_evidence(row):
            continue
        queue = Path(row["run_dir"]) / "oracle_queue" / "oracle_queue_result.json"
        if queue.exists():
            data = read_json(queue)
            normalized = normalize_event_time_ms(data.get("oracle_end_time_ms"), row)
            if normalized is not None:
                values.append(normalized)
                continue
        meta = row.get("meta") or {}
        normalized = normalize_event_time_ms(meta.get("oracle_end_time_ms"), row)
        if normalized is not None:
            values.append(normalized)
        else:
            first_seen = candidate_first_seen_ms(row)
            if first_seen is not None:
                values.append(first_seen)
    return min(values) if values else None


def oracle_budget_for_row(row: dict[str, Any]) -> tuple[int, float]:
    meta = row.get("meta") or {}
    oracle_runs = safe_int(meta.get("oracle_runs"), 0)
    oracle_cpu = safe_float(meta.get("oracle_cpu_sec"), 0.0)
    queue = Path(row["run_dir"]) / "oracle_queue" / "oracle_queue_result.json"
    if queue.exists():
        data = read_json(queue)
        rows = data.get("oracle_rows") or []
        oracle_runs += len(rows)
        oracle_cpu += safe_float(data.get("oracle_cpu_sec") or data.get("oracle_wall_sec"), 0.0)
    if row["classification"].get("oracle_verdict") not in {None, "Unknown"} and oracle_runs == 0:
        oracle_runs = 1
    return oracle_runs, oracle_cpu


def duplicate_collapse_ratio(rows: list[dict[str, Any]]) -> float:
    eligible = [row for row in rows if not has_missing_replay_evidence(row)]
    if not eligible:
        return 0.0
    keys = {candidate_duplicate_key(row["classification"], row.get("meta") or {}) for row in eligible}
    return safe_div(len(eligible), len(keys))


def cpu_hours_for_rows(rows: list[dict[str, Any]]) -> float:
    """Return campaign CPU-hours without charging the same fuzz budget per artifact.

    Candidate-level cargo-fuzz runs produce one metrics row per artifact, but all
    artifacts from a seed/run share one campaign budget. We therefore deduplicate
    by campaign_id and charge the maximum recorded campaign budget once.
    """
    campaign_seconds: dict[str, float] = {}
    ungrouped_seconds = 0.0
    for row in rows:
        meta = row.get("meta") or {}
        budget = safe_float(
            meta.get("campaign_budget_seconds")
            or meta.get("fuzz_budget_seconds")
            or meta.get("budget_seconds"),
            0.0,
        )
        campaign_id = str(meta.get("campaign_id") or "").strip()
        if campaign_id:
            campaign_seconds[campaign_id] = max(campaign_seconds.get(campaign_id, 0.0), budget)
        else:
            ungrouped_seconds += budget
    seconds = sum(campaign_seconds.values()) + ungrouped_seconds
    if seconds <= 0.0:
        seconds = sum(oracle_budget_for_row(row)[1] for row in rows)
    return seconds / 3600.0


def compute_wdpc(row: dict[str, Any]) -> float:
    site_map = load_run_artifact(row, "site_map.json")
    if not site_map:
        return 0.0

    classification = row["classification"]
    reached = set(classification.get("reached_dangerous_sites") or [])

    dangerous_sites = site_map.get("dangerous_sites") or []
    total_weight = 0.0
    reached_weight = 0.0

    for site in dangerous_sites:
        weight = float(site.get("kind_weight", 1.0) or 1.0)
        total_weight += weight
        if site.get("site_id") in reached:
            reached_weight += weight

    return safe_div(reached_weight, total_weight)


def compute_ttds(row: dict[str, Any]) -> int | None:
    trace = load_run_artifact(row, "trace_log.json")
    site_map = load_run_artifact(row, "site_map.json")
    if not trace or not site_map:
        return None

    dangerous_ids = {
        site.get("site_id")
        for site in site_map.get("dangerous_sites", [])
    }

    for idx, event in enumerate(trace.get("events", [])):
        if event.get("Hit", {}).get("site_id") in dangerous_ids:
            return idx
        if event.get("type") == "Hit" and event.get("site_id") in dangerous_ids:
            return idx

    return None


def support_entry(
    *,
    numerator: int | float | None = None,
    denominator: int | float | None = None,
    included_runs: int | None = None,
    excluded_missing_evidence: int | None = None,
    excluded_unassessable: int | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "included_runs": included_runs,
        "excluded_missing_evidence": excluded_missing_evidence,
        "excluded_unassessable": excluded_unassessable,
        "note": note,
    }


def compute_group_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    campaign_rows = [r for r in rows if str(r.get("unit_of_analysis") or "run") == "campaign"]
    observation_rows = [r for r in rows if str(r.get("unit_of_analysis") or "run") != "campaign"]
    total = len(observation_rows)
    missing_evidence = [r for r in observation_rows if has_missing_replay_evidence(r)]
    evidence_rows = [r for r in observation_rows if not has_missing_replay_evidence(r)]
    trace_rows = [r for r in observation_rows if has_independent_trace_evidence(r)]
    candidate_rows = [
        r for r in observation_rows if str(r.get("unit_of_analysis") or "run") == "candidate"
    ]

    def candidate_truth_key(row: dict[str, Any]) -> str:
        # Count the same artifact content once across repeated campaigns.  The
        # adjudication template is keyed by case + full SHA-256 for the same
        # reason.  candidate_id remains the fallback for legacy rows without a
        # digest.
        meta = row.get("meta") or {}
        case = str(row.get("case") or meta.get("case") or meta.get("crate") or "")
        digest = str(meta.get("input_sha256") or "").strip().lower()
        if case and digest:
            return f"{case}:{digest}"
        return str(
            meta.get("candidate_id")
            or f"{case}:{meta.get('input_id') or row.get('run_dir')}"
        )

    unique_candidate_keys = {candidate_truth_key(row) for row in candidate_rows}
    unique_annotated_candidate_keys = {
        candidate_truth_key(row) for row in candidate_rows if row.get("expected") is not None
    }
    campaign_ids = {
        str((row.get("meta") or {}).get("campaign_id"))
        for row in rows
        if (row.get("meta") or {}).get("campaign_id")
    }
    truth_source_counts = Counter(
        str(row.get("truth_source") or "unassessable") for row in observation_rows
    )

    # All classified/reported outputs are useful diagnostics, but RustDPR's main
    # triage precision/FPR should be computed over the review queue only.
    reported = [r for r in observation_rows if is_reported_candidate(r)]
    reported_assessable = [r for r in reported if truth_status(r) is not None]
    reported_truth_positive = [r for r in reported_assessable if truth_status(r) is True]
    reported_truth_negative = [r for r in reported_assessable if truth_status(r) is False]
    reported_label_meaningful = [r for r in reported if r["classification"].get("primary_label") in MEANINGFUL_LABELS]
    unassessable_reported = [r for r in reported if truth_status(r) is None]

    review_queue = [r for r in evidence_rows if is_review_queue_candidate(r)]
    review_assessable = [r for r in review_queue if truth_status(r) is not None]
    review_truth_positive = [r for r in review_assessable if truth_status(r) is True]
    review_truth_negative = [r for r in review_assessable if truth_status(r) is False]
    review_unassessable = [r for r in review_queue if truth_status(r) is None]

    negative_truth_rows = [r for r in evidence_rows if truth_status(r) is False]
    negative_truth_reported = [r for r in negative_truth_rows if is_reported_candidate(r)]
    negative_truth_reviewed = [r for r in negative_truth_rows if is_review_queue_candidate(r)]
    security_relevant_truth_rows = [r for r in evidence_rows if truth_status(r) is True]
    security_relevant_detected = [r for r in security_relevant_truth_rows if is_reported_candidate(r)]
    security_relevant_reviewed = [r for r in security_relevant_truth_rows if is_review_queue_candidate(r)]

    oracle_confirmed = [r for r in evidence_rows if r["classification"].get("oracle_verdict") in CONFIRMED_ORACLES]
    review_required = review_queue

    label_counts = Counter(r["classification"].get("primary_label") for r in observation_rows)
    relation_counts = Counter(r["classification"].get("relation") for r in observation_rows)
    oracle_counts = Counter(r["classification"].get("oracle_verdict") for r in observation_rows)
    harness_counts = Counter(r["classification"].get("harness_status") for r in observation_rows)

    expected_available = [r for r in observation_rows if r.get("expected")]
    security_relevant_expected = [r for r in expected_available if r["expected"].get("security_relevant")]
    true_meaningful_all_classified = [r for r in security_relevant_expected if is_reported_candidate(r)]
    true_meaningful_review_queue = [r for r in security_relevant_expected if is_review_queue_candidate(r)]

    wdpcs = [compute_wdpc(r) for r in evidence_rows]
    ttds_values = [compute_ttds(r) for r in evidence_rows]
    ttds_values = [v for v in ttds_values if v is not None]

    replay_summaries = []
    for r in observation_rows:
        replay = replay_summary_for_row(r)
        if replay:
            replay_summaries.append(replay)
    reproducible = [x for x in replay_summaries if x.get("stable") or x.get("replay_stable")]

    raw_count_rows = campaign_rows if campaign_rows else observation_rows
    raw_panic_count = sum(
        int((r.get("meta") or {}).get("raw_panic_count", 0) or 0) for r in raw_count_rows
    )
    raw_crash_count = sum(
        int((r.get("meta") or {}).get("raw_crash_count", 0) or 0) for r in raw_count_rows
    )
    unsafe_hit_count = sum(
        int((r.get("meta") or {}).get("unsafe_hit_count", 0) or 0) for r in observation_rows
    )
    harness_misuse = [
        r
        for r in evidence_rows
        if r["classification"].get("harness_status") in {"LikelyMisuse", "Invalid"}
        or r["classification"].get("primary_label") == "HarnessMisuse"
    ]
    reviews_first = reviews_to_first_confirmed(observation_rows)
    actionable = [r for r in evidence_rows if candidate_is_actionable(r["classification"])]
    oracle_budget_rows = [oracle_budget_for_row(r) for r in evidence_rows]
    oracle_runs_total = sum(x[0] for x in oracle_budget_rows)
    oracle_cpu_total = sum(x[1] for x in oracle_budget_rows)
    cpu_hours = cpu_hours_for_rows(rows)
    ttae_ms = time_to_first_actionable_ms(observation_rows)
    ttoc_ms = time_to_first_oracle_confirmed_ms(observation_rows)

    precision1 = precision_at_k(observation_rows, 1)
    precision3 = precision_at_k(observation_rows, 3)
    precision5 = precision_at_k(observation_rows, 5)
    precision10 = precision_at_k(observation_rows, 10)
    recall10 = recall_at_k(observation_rows, 10)
    ndcg10 = ndcg_at_k(observation_rows, 10)
    mrr = mean_reciprocal_rank(observation_rows)
    oc1 = oracle_confirmed_at_k(observation_rows, 1)
    oc5 = oracle_confirmed_at_k(observation_rows, 5)
    oc10 = oracle_confirmed_at_k(observation_rows, 10)

    p1_counts = precision_at_k_counts(observation_rows, 1)
    p5_counts = precision_at_k_counts(observation_rows, 5)
    p10_counts = precision_at_k_counts(observation_rows, 10)
    r10_counts = recall_at_k_counts(observation_rows, 10)
    ndcg10_support = ndcg_at_k_support(observation_rows, 10)
    assessable_rank_rows = ranked_assessable_rows(observation_rows)

    support = {
        "candidate_truth_coverage": support_entry(
            numerator=len(unique_annotated_candidate_keys),
            denominator=len(unique_candidate_keys),
            included_runs=len(candidate_rows),
            note="unique candidate artifacts with adjudicated truth; case-level truth is excluded by default",
        ),
        "mcp": support_entry(
            numerator=len(review_truth_positive),
            denominator=len(review_assessable),
            included_runs=len(review_assessable),
            excluded_missing_evidence=len(missing_evidence),
            excluded_unassessable=len(review_unassessable),
            note="MAIN: truth-based precision over the review queue (review_required=true); pipeline primary_label is not used as truth",
        ),
        "mcp_all_classified_diagnostic": support_entry(
            numerator=len(reported_truth_positive),
            denominator=len(reported_assessable),
            included_runs=len(reported_assessable),
            excluded_missing_evidence=len(missing_evidence),
            excluded_unassessable=len(unassessable_reported),
            note="DIAGNOSTIC: truth-based precision over all non-noise/non-unknown classified outputs, not the main triage precision",
        ),
        "label_mcp_diagnostic": support_entry(
            numerator=len(reported_label_meaningful),
            denominator=len(reported),
            included_runs=len(reported),
            excluded_missing_evidence=len(missing_evidence),
            note="diagnostic only: uses the pipeline output label, so it is not a fair baseline precision metric",
        ),
        "panic_noise_fpr": support_entry(
            numerator=len(negative_truth_reviewed),
            denominator=len(negative_truth_rows),
            included_runs=len(negative_truth_rows),
            excluded_missing_evidence=len(missing_evidence),
            excluded_unassessable=total - len(missing_evidence) - len(negative_truth_rows) - len(security_relevant_truth_rows),
            note="MAIN: false-positive rate among assessable truth-negative/noise cases that entered the review queue",
        ),
        "panic_noise_fpr_all_classified_diagnostic": support_entry(
            numerator=len(negative_truth_reported),
            denominator=len(negative_truth_rows),
            included_runs=len(negative_truth_rows),
            excluded_missing_evidence=len(missing_evidence),
            excluded_unassessable=total - len(missing_evidence) - len(negative_truth_rows) - len(security_relevant_truth_rows),
            note="DIAGNOSTIC: false-positive rate over all non-noise/non-unknown classified outputs",
        ),
        "oracle_confirmed_rate": support_entry(numerator=len(oracle_confirmed), denominator=len(evidence_rows), included_runs=len(evidence_rows), excluded_missing_evidence=len(missing_evidence)),
        "oracle_confirmed_per_reported": support_entry(numerator=len(oracle_confirmed), denominator=len(reported), included_runs=len(reported), excluded_missing_evidence=len(missing_evidence)),
        "oracle_confirmed_per_review_queue": support_entry(numerator=len([r for r in review_queue if candidate_is_oracle_confirmed(r["classification"])]), denominator=len(review_queue), included_runs=len(review_queue), excluded_missing_evidence=len(missing_evidence)),
        "review_load": support_entry(numerator=len(review_required), denominator=len(evidence_rows), included_runs=len(evidence_rows), excluded_missing_evidence=len(missing_evidence)),
        "reproducibility_rate": support_entry(
            numerator=len(reproducible),
            denominator=len(replay_summaries),
            included_runs=len(replay_summaries),
            note="candidate is stable only when every configured replay is non-zero, emits independent RustDPR trace evidence, and uses one stable exit code",
        ),
        "harness_misuse_rejection_rate": support_entry(numerator=len(harness_misuse), denominator=len(evidence_rows), included_runs=len(evidence_rows), excluded_missing_evidence=len(missing_evidence)),
        "review_queue_recall": support_entry(numerator=len(security_relevant_reviewed), denominator=len(security_relevant_truth_rows), included_runs=len(security_relevant_truth_rows), excluded_missing_evidence=len(missing_evidence), note="truth-positive evidence-supported runs retained in the review queue"),
        "security_relevant_recall": support_entry(numerator=len(security_relevant_reviewed), denominator=len(security_relevant_truth_rows), included_runs=len(security_relevant_truth_rows), excluded_missing_evidence=len(missing_evidence), note="MAIN recall uses the review queue; see security_relevant_recall_all_classified_diagnostic for the old all-classified recall"),
        "security_relevant_recall_all_classified_diagnostic": support_entry(numerator=len(security_relevant_detected), denominator=len(security_relevant_truth_rows), included_runs=len(security_relevant_truth_rows), excluded_missing_evidence=len(missing_evidence), note="DIAGNOSTIC: truth-positive evidence-supported runs detected anywhere in all classified outputs"),
        "precision_at_1": support_entry(numerator=None if p1_counts is None else p1_counts[0], denominator=0 if p1_counts is None else p1_counts[1], included_runs=len(assessable_rank_rows), excluded_missing_evidence=len(missing_evidence)),
        "precision_at_5": support_entry(numerator=None if p5_counts is None else p5_counts[0], denominator=0 if p5_counts is None else p5_counts[1], included_runs=len(assessable_rank_rows), excluded_missing_evidence=len(missing_evidence)),
        "precision_at_10": support_entry(numerator=None if p10_counts is None else p10_counts[0], denominator=0 if p10_counts is None else p10_counts[1], included_runs=len(assessable_rank_rows), excluded_missing_evidence=len(missing_evidence)),
        "recall_at_10": support_entry(numerator=None if r10_counts is None else r10_counts[0], denominator=0 if r10_counts is None else r10_counts[1], included_runs=len(assessable_rank_rows), excluded_missing_evidence=len(missing_evidence)),
        "ndcg_at_10": support_entry(numerator=None if ndcg10_support is None else ndcg10_support[0], denominator=0 if ndcg10_support is None else ndcg10_support[1], included_runs=len(assessable_rank_rows), excluded_missing_evidence=len(missing_evidence), note="numerator=DCG@10, denominator=ideal DCG@10; n/a when no assessable positives exist"),
        "ttae_ms": support_entry(numerator=ttae_ms, denominator=len(actionable), included_runs=len(actionable), excluded_missing_evidence=len(missing_evidence), note="relative ms; wall-clock epoch timestamps are discarded unless a run origin is known"),
        "ttoc_ms": support_entry(numerator=ttoc_ms, denominator=len(oracle_confirmed), included_runs=len(oracle_confirmed), excluded_missing_evidence=len(missing_evidence)),
        "wdpc_mean": support_entry(numerator=sum(wdpcs), denominator=len(wdpcs), included_runs=len(wdpcs), excluded_missing_evidence=len(missing_evidence)),
        "ttds_mean_events": support_entry(numerator=sum(ttds_values), denominator=len(ttds_values), included_runs=len(ttds_values), excluded_missing_evidence=len(missing_evidence)),
    }

    return {
        "total_runs": total,
        "total_records": len(rows),
        "campaign_records": len(campaign_rows),
        "unit_of_analysis": (
            "candidate"
            if candidate_rows and len(candidate_rows) == total
            else "mixed-or-run"
        ),
        "candidate_rows": len(candidate_rows),
        "unique_candidates": len(unique_candidate_keys),
        "truth_annotated_unique_candidates": len(unique_annotated_candidate_keys),
        "candidate_truth_coverage": div_or_none(len(unique_annotated_candidate_keys), len(unique_candidate_keys)),
        "campaigns_represented": len(campaign_ids),
        "truth_source_counts": dict(truth_source_counts),
        "evidence_supported_runs": len(evidence_rows),
        "missing_evidence_runs": len(missing_evidence),
        "independent_trace_runs": len(trace_rows),
        "reported_candidates": len(reported),
        "assessable_reported_candidates": len(reported_assessable),
        "unassessable_reported_candidates": len(unassessable_reported),
        "review_queue_candidates": len(review_queue),
        "assessable_review_queue_candidates": len(review_assessable),
        "unassessable_review_queue_candidates": len(review_unassessable),
        "meaningful_candidates": len(review_truth_positive),
        "meaningful_candidates_all_classified_diagnostic": len(reported_truth_positive),
        "label_meaningful_candidates_diagnostic": len(reported_label_meaningful),
        "mcp": div_or_none(len(review_truth_positive), len(review_assessable)),
        "mcp_all_classified_diagnostic": div_or_none(len(reported_truth_positive), len(reported_assessable)),
        "label_mcp_diagnostic": div_or_none(len(reported_label_meaningful), len(reported)),
        "panic_noise_false_positives": len(negative_truth_reviewed),
        "panic_noise_false_positives_all_classified_diagnostic": len(negative_truth_reported),
        "panic_noise_truth_cases": len(negative_truth_rows),
        "panic_noise_fpr": div_or_none(len(negative_truth_reviewed), len(negative_truth_rows)),
        "panic_noise_fpr_all_classified_diagnostic": div_or_none(len(negative_truth_reported), len(negative_truth_rows)),
        "oracle_confirmed_runs": len(oracle_confirmed),
        "oracle_confirmed_rate": div_or_none(len(oracle_confirmed), len(evidence_rows)),
        "oracle_confirmed_per_reported": div_or_none(len(oracle_confirmed), len(reported)),
        "oracle_confirmed_per_review_queue": div_or_none(len([r for r in review_queue if candidate_is_oracle_confirmed(r["classification"])]), len(review_queue)),
        "review_required_runs": len(review_required),
        "review_load": div_or_none(len(review_required), len(evidence_rows)),
        "expected_available": len(expected_available),
        "security_relevant_expected": len(security_relevant_expected),
        "review_queue_recall": div_or_none(len(security_relevant_reviewed), len(security_relevant_truth_rows)),
        "security_relevant_recall": div_or_none(len(security_relevant_reviewed), len(security_relevant_truth_rows)),
        "security_relevant_recall_all_classified_diagnostic": div_or_none(len(security_relevant_detected), len(security_relevant_truth_rows)),
        "replay_checked": len(replay_summaries),
        "reproducibility_rate": div_or_none(len(reproducible), len(replay_summaries)),
        "raw_panic_count": raw_panic_count,
        "raw_crash_count": raw_crash_count,
        "unsafe_hit_count": unsafe_hit_count,
        "harness_misuse_rejected": len(harness_misuse),
        "harness_misuse_rejection_rate": div_or_none(len(harness_misuse), len(evidence_rows)),
        "precision_at_1": precision1,
        "precision_at_3": precision3,
        "precision_at_5": precision5,
        "precision_at_10": precision10,
        "recall_at_10": recall10,
        "ndcg_at_10": ndcg10,
        "oracle_confirmed_at_1": oc1,
        "oracle_confirmed_at_5": oc5,
        "oracle_confirmed_at_10": oc10,
        "mrr": mrr,
        "reviews_to_first_confirmed": reviews_first,
        "reviews_per_confirmed": div_or_none(len(review_required), len(oracle_confirmed)),
        "actionable_candidates": len(actionable),
        "ttae_ms": ttae_ms,
        "ttoc_ms": ttoc_ms,
        "oracle_runs": oracle_runs_total,
        "oracle_cpu_seconds": oracle_cpu_total,
        "obe": div_or_none(len(oracle_confirmed), oracle_runs_total),
        "obe_per_cpu_minute": div_or_none(len(oracle_confirmed), oracle_cpu_total / 60.0),
        "duplicate_collapse_ratio": duplicate_collapse_ratio(observation_rows),
        "cpu_hours_observed": cpu_hours,
        "actionable_yield_per_cpu_hour": div_or_none(len(actionable), cpu_hours),
        "oracle_confirmed_yield_per_cpu_hour": div_or_none(len(oracle_confirmed), cpu_hours),
        "primary_label_counts": dict(label_counts),
        "relation_counts": dict(relation_counts),
        "oracle_counts": dict(oracle_counts),
        "harness_counts": dict(harness_counts),
        "support": support,
        "primary_label_confusion": confusion_counts(expected_available, "primary_label"),
        "relation_confusion": confusion_counts(expected_available, "relation"),
        "wdpc_mean": div_or_none(sum(wdpcs), len(wdpcs)),
        "ttds_mean_events": div_or_none(sum(ttds_values), len(ttds_values)),
        "ttds_observed_runs": len(ttds_values),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--candidate-truth",
        default=None,
        help="Adjudicated candidate-level truth CSV. Required for paper-facing MCP/FPR over fuzz artifacts.",
    )
    parser.add_argument(
        "--allow-case-truth-for-candidates",
        action="store_true",
        help="Legacy/debug only: apply one case-level expected.yaml label to every candidate artifact.",
    )
    parser.add_argument(
        "--run-index",
        action="append",
        type=int,
        default=[],
        help="Only aggregate these run indices. Repeatable. Omit only when the results directory contains one experiment.",
    )
    args = parser.parse_args()

    run_indices = set(args.run_index) if args.run_index else None
    candidate_truth_path = Path(args.candidate_truth).resolve() if args.candidate_truth else None
    candidate_truth_index = load_candidate_truth(candidate_truth_path)
    rows = iter_runs(
        args.suite,
        candidate_truth_index=candidate_truth_index,
        allow_case_truth_for_candidates=args.allow_case_truth_for_candidates,
        run_indices=run_indices,
    )
    rows.extend(iter_campaign_records(args.suite, run_indices=run_indices))
    by_tool_variant: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_tool_variant_mode: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_tool_variant[(row["tool"], row["variant"])].append(row)
        by_tool_variant_mode[(row["tool"], row["variant"], row.get("mode", "deterministic"))].append(row)

    result = {
        "schema_version": "0.3.0",
        "suite": args.suite,
        "run_index_filter": sorted(run_indices) if run_indices else None,
        "candidate_truth": {
            "path": candidate_truth_index.get("path"),
            "rows_loaded": candidate_truth_index.get("rows_loaded", 0),
            "rows_skipped_incomplete": candidate_truth_index.get("rows_skipped_incomplete", 0),
            "allow_case_truth_for_candidates": args.allow_case_truth_for_candidates,
        },
        "runs_dir": str(RUNS_DIR / args.suite),
        "total_records": len(rows),
        "total_runs": sum(1 for row in rows if row.get("unit_of_analysis") != "campaign"),
        "campaign_records": sum(1 for row in rows if row.get("unit_of_analysis") == "campaign"),
        "metric_semantics": {
            "mcp": "MAIN: truth-based precision over review_required candidates with expected.yaml or oracle truth; primary_label alone is not truth",
            "mcp_all_classified_diagnostic": "DIAGNOSTIC: truth-based precision over all non-noise/non-unknown classified outputs",
            "panic_noise_fpr": "MAIN: review-queue false positives over assessable truth-negative/noise cases; missing replay evidence is excluded",
            "panic_noise_fpr_all_classified_diagnostic": "DIAGNOSTIC: all-classified false positives over assessable truth-negative/noise cases",
            "review_queue_recall": "Security-relevant recall over the review queue",
            "missing_evidence_runs": "runs where RustDPR independent replay did not produce trace evidence; these are unsupported, not Noise",
            "candidate_truth_coverage": "unique candidate artifacts with adjudicated truth divided by all unique candidate artifacts",
            "truth_policy": "candidate rows use candidate-level adjudication; NoOracleFinding is unassessable, not negative truth",
            "cpu_hours_observed": "candidate rows are deduplicated by campaign_id so one fuzz budget is charged once per seed/run",
            "campaign_records": "zero-artifact campaigns are persisted separately and affect campaign/CPU-hour support, never candidate precision/FPR",
            "ttae_ms": "relative time-to-first-actionable evidence; epoch-like wall-clock timestamps are discarded if no origin is known",
        },
        "overall": compute_group_metrics(rows),
        "by_tool_variant": {
            f"{tool}/{variant}": compute_group_metrics(group)
            for (tool, variant), group in sorted(by_tool_variant.items())
        },
        "by_tool_variant_mode": {
            f"{tool}/{variant}/{mode}": compute_group_metrics(group)
            for (tool, variant, mode), group in sorted(by_tool_variant_mode.items())
        },
    }

    write_json(Path(args.out), result)
    print(f"[done] metrics written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
