from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from common import (
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


def load_expected(suite: str, case: str) -> dict[str, Any] | None:
    path = suite_case_expected_path(suite, case)
    if not path.exists():
        return None
    return normalize_expected_schema(load_yaml(path) or {})


def iter_runs(suite: str) -> list[dict[str, Any]]:
    rows = []
    suite_dir = RUNS_DIR / suite
    if not suite_dir.exists():
        return rows
    for classification_path in sorted(suite_dir.rglob("classification.json")):
        run_dir = classification_path.parent
        classification = read_json(classification_path)
        meta_path = run_dir / "run_meta.json"
        if not meta_path.exists():
            raise RuntimeError(f"run_meta.json not found for run: {run_dir}")
        meta = read_json(meta_path)
        case = meta["case"]
        expected = load_expected(suite, case)
        rows.append(
            {
                "suite": suite,
                "case": case,
                "run_dir": str(run_dir),
                "tool": meta["tool"],
                "variant": meta["variant"],
                "mode": meta.get("mode", "deterministic"),
                "seed": meta["seed"],
                "run_index": meta["run_index"],
                "classification": classification,
                "expected": expected,
                "meta": meta,
            }
        )
    return rows


def safe_div(num: float, den: float) -> float:
    return 0.0 if den == 0 else num / den


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


def confidence_rank(row: dict[str, Any]) -> float:
    classification = row["classification"]
    reached_count = len(classification.get("reached_dangerous_sites") or [])
    return candidate_score(
        classification,
        reached_count=reached_count,
        replay_stable=replay_stable_for_row(row),
        duplicate_ordinal=1,
    )


def is_true_candidate(row: dict[str, Any]) -> bool:
    expected = row.get("expected")
    classification = row["classification"]
    if classification.get("oracle_verdict") in CONFIRMED_ORACLES:
        return True
    if expected and expected.get("security_relevant"):
        return classification.get("primary_label") in MEANINGFUL_LABELS
    return False


def precision_at_k(rows: list[dict[str, Any]], k: int) -> float:
    ranked = sorted(rows, key=confidence_rank, reverse=True)[:k]
    return safe_div(sum(1 for row in ranked if is_true_candidate(row)), len(ranked))


def mean_reciprocal_rank(rows: list[dict[str, Any]]) -> float:
    ranked = sorted(rows, key=confidence_rank, reverse=True)
    for idx, row in enumerate(ranked, start=1):
        if is_true_candidate(row):
            return 1.0 / idx
    return 0.0


def reviews_to_first_confirmed(rows: list[dict[str, Any]]) -> int | None:
    ranked = sorted(rows, key=confidence_rank, reverse=True)
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
    return False


def truth_gain(row: dict[str, Any]) -> float:
    classification = row["classification"]
    if candidate_is_oracle_confirmed(classification):
        return 3.0
    if candidate_is_actionable(classification):
        return 2.0
    if is_true_candidate(row) or candidate_is_meaningful(classification):
        return 1.0
    return 0.0


def recall_at_k(rows: list[dict[str, Any]], k: int) -> float:
    positives = [row for row in rows if truth_gain(row) > 0.0]
    if not positives:
        return 0.0
    ranked = sorted(rows, key=confidence_rank, reverse=True)[:k]
    return safe_div(sum(1 for row in ranked if truth_gain(row) > 0.0), len(positives))


def oracle_confirmed_at_k(rows: list[dict[str, Any]], k: int) -> int:
    ranked = sorted(rows, key=confidence_rank, reverse=True)[:k]
    return sum(1 for row in ranked if candidate_is_oracle_confirmed(row["classification"]))


def dcg_at_k(gains: list[float], k: int) -> float:
    import math

    total = 0.0
    for idx, gain in enumerate(gains[:k], start=1):
        total += (2.0**gain - 1.0) / math.log2(idx + 1)
    return total


def ndcg_at_k(rows: list[dict[str, Any]], k: int) -> float:
    ranked_gains = [truth_gain(row) for row in sorted(rows, key=confidence_rank, reverse=True)]
    ideal_gains = sorted((truth_gain(row) for row in rows), reverse=True)
    ideal = dcg_at_k(ideal_gains, k)
    return safe_div(dcg_at_k(ranked_gains, k), ideal)


def dangerous_ids_for_row(row: dict[str, Any]) -> set[str]:
    site_map = load_run_artifact(row, "site_map.json")
    if not site_map:
        return set()
    return {str(site.get("site_id")) for site in site_map.get("dangerous_sites", []) if site.get("site_id") is not None}


def candidate_first_seen_ms(row: dict[str, Any]) -> int | None:
    classification = row["classification"]
    for key in ["first_seen_time_ms", "dangerous_hit_time_ms", "panic_time_ms"]:
        if classification.get(key) is not None:
            return safe_int(classification.get(key))
    trace = load_run_artifact(row, "trace_log.json")
    times = first_trace_times(trace, dangerous_ids_for_row(row))
    return times.get("dangerous_hit_time_ms") or times.get("panic_time_ms") or times.get("first_event_time_ms")


def time_to_first_actionable_ms(rows: list[dict[str, Any]]) -> int | None:
    values = [candidate_first_seen_ms(row) for row in rows if candidate_is_actionable(row["classification"])]
    values = [value for value in values if value is not None]
    return min(values) if values else None


def time_to_first_oracle_confirmed_ms(rows: list[dict[str, Any]]) -> int | None:
    values: list[int] = []
    for row in rows:
        if not candidate_is_oracle_confirmed(row["classification"]):
            continue
        queue = Path(row["run_dir"]) / "oracle_queue" / "oracle_queue_result.json"
        if queue.exists():
            data = read_json(queue)
            if data.get("oracle_end_time_ms") is not None:
                values.append(safe_int(data.get("oracle_end_time_ms")))
                continue
        meta = row.get("meta") or {}
        if meta.get("oracle_end_time_ms") is not None:
            values.append(safe_int(meta.get("oracle_end_time_ms")))
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
    if not rows:
        return 0.0
    keys = {candidate_duplicate_key(row["classification"], row.get("meta") or {}) for row in rows}
    return safe_div(len(rows), len(keys))


def cpu_hours_for_rows(rows: list[dict[str, Any]]) -> float:
    seconds = sum(safe_float((row.get("meta") or {}).get("budget_seconds"), 0.0) for row in rows)
    if seconds <= 0.0:
        seconds = sum(oracle_budget_for_row(row)[1] for row in rows)
    return seconds / 3600.0


def first_event_time_for_site(row: dict[str, Any], site_ids: set[str]) -> int | None:
    trace = load_run_artifact(row, "trace_log.json")
    if not trace:
        return None
    for idx, event in enumerate(trace.get("events", [])):
        if event.get("Hit", {}).get("site_id") in site_ids:
            return int(event.get("Hit", {}).get("ts_millis") or idx)
        if event.get("type") == "Hit" and event.get("site_id") in site_ids:
            return int(event.get("ts_millis") or idx)
        if event.get("site_id") in site_ids:
            return int(event.get("ts_millis") or idx)
    return None


def compute_group_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    reported = [r for r in rows if r["classification"].get("primary_label") not in {"Noise", "Unknown"}]
    meaningful = [r for r in reported if r["classification"].get("primary_label") in MEANINGFUL_LABELS]
    noise_reported = [r for r in reported if r["classification"].get("primary_label") in NOISE_LABELS]
    oracle_confirmed = [r for r in rows if r["classification"].get("oracle_verdict") in CONFIRMED_ORACLES]
    review_required = [r for r in rows if r["classification"].get("review_required")]

    label_counts = Counter(r["classification"].get("primary_label") for r in rows)
    relation_counts = Counter(r["classification"].get("relation") for r in rows)
    oracle_counts = Counter(r["classification"].get("oracle_verdict") for r in rows)
    harness_counts = Counter(r["classification"].get("harness_status") for r in rows)

    expected_available = [r for r in rows if r.get("expected")]
    security_relevant_expected = [r for r in expected_available if r["expected"].get("security_relevant")]
    true_meaningful = [r for r in security_relevant_expected if r["classification"].get("primary_label") in MEANINGFUL_LABELS]

    wdpcs = [compute_wdpc(r) for r in rows]
    ttds_values = [compute_ttds(r) for r in rows]
    ttds_values = [v for v in ttds_values if v is not None]

    replay_summaries = []
    for r in rows:
        summary = Path(r["run_dir"]) / "replay_summary.json"
        if summary.exists():
            replay_summaries.append(read_json(summary))
    reproducible = [x for x in replay_summaries if x.get("stable") or x.get("replay_stable")]

    raw_panic_count = sum(int((r.get("meta") or {}).get("raw_panic_count", 0) or 0) for r in rows)
    raw_crash_count = sum(int((r.get("meta") or {}).get("raw_crash_count", 0) or 0) for r in rows)
    unsafe_hit_count = sum(int((r.get("meta") or {}).get("unsafe_hit_count", 0) or 0) for r in rows)
    harness_misuse = [
        r
        for r in rows
        if r["classification"].get("harness_status") in {"LikelyMisuse", "Invalid"}
        or r["classification"].get("primary_label") == "HarnessMisuse"
    ]
    reviews_first = reviews_to_first_confirmed(rows)
    actionable = [r for r in rows if candidate_is_actionable(r["classification"])]
    oracle_budget_rows = [oracle_budget_for_row(r) for r in rows]
    oracle_runs_total = sum(x[0] for x in oracle_budget_rows)
    oracle_cpu_total = sum(x[1] for x in oracle_budget_rows)
    cpu_hours = cpu_hours_for_rows(rows)
    ttae_ms = time_to_first_actionable_ms(rows)
    ttoc_ms = time_to_first_oracle_confirmed_ms(rows)

    return {
        "total_runs": total,
        "reported_candidates": len(reported),
        "meaningful_candidates": len(meaningful),
        "mcp": safe_div(len(meaningful), len(reported)),
        "panic_noise_fpr": safe_div(len(noise_reported), len(reported)),
        "oracle_confirmed_runs": len(oracle_confirmed),
        "oracle_confirmed_rate": safe_div(len(oracle_confirmed), total),
        "oracle_confirmed_per_reported": safe_div(len(oracle_confirmed), len(reported)),
        "review_required_runs": len(review_required),
        "review_load": safe_div(len(review_required), total),
        "expected_available": len(expected_available),
        "security_relevant_expected": len(security_relevant_expected),
        "security_relevant_recall": safe_div(len(true_meaningful), len(security_relevant_expected)),
        "replay_checked": len(replay_summaries),
        "reproducibility_rate": safe_div(len(reproducible), len(replay_summaries)),
        "raw_panic_count": raw_panic_count,
        "raw_crash_count": raw_crash_count,
        "unsafe_hit_count": unsafe_hit_count,
        "harness_misuse_rejected": len(harness_misuse),
        "harness_misuse_rejection_rate": safe_div(len(harness_misuse), total),
        "precision_at_1": precision_at_k(rows, 1),
        "precision_at_3": precision_at_k(rows, 3),
        "precision_at_5": precision_at_k(rows, 5),
        "precision_at_10": precision_at_k(rows, 10),
        "recall_at_10": recall_at_k(rows, 10),
        "ndcg_at_10": ndcg_at_k(rows, 10),
        "oracle_confirmed_at_1": oracle_confirmed_at_k(rows, 1),
        "oracle_confirmed_at_5": oracle_confirmed_at_k(rows, 5),
        "oracle_confirmed_at_10": oracle_confirmed_at_k(rows, 10),
        "mrr": mean_reciprocal_rank(rows),
        "reviews_to_first_confirmed": reviews_first,
        "reviews_per_confirmed": safe_div(len(review_required), len(oracle_confirmed)),
        "actionable_candidates": len(actionable),
        "ttae_ms": ttae_ms,
        "ttoc_ms": ttoc_ms,
        "oracle_runs": oracle_runs_total,
        "oracle_cpu_seconds": oracle_cpu_total,
        "obe": safe_div(len(oracle_confirmed), oracle_runs_total),
        "obe_per_cpu_minute": safe_div(len(oracle_confirmed), oracle_cpu_total / 60.0),
        "duplicate_collapse_ratio": duplicate_collapse_ratio(rows),
        "cpu_hours_observed": cpu_hours,
        "actionable_yield_per_cpu_hour": safe_div(len(actionable), cpu_hours),
        "oracle_confirmed_yield_per_cpu_hour": safe_div(len(oracle_confirmed), cpu_hours),
        "primary_label_counts": dict(label_counts),
        "relation_counts": dict(relation_counts),
        "oracle_counts": dict(oracle_counts),
        "harness_counts": dict(harness_counts),
        "primary_label_confusion": confusion_counts(expected_available, "primary_label"),
        "relation_confusion": confusion_counts(expected_available, "relation"),
        "wdpc_mean": safe_div(sum(wdpcs), len(wdpcs)),
        "ttds_mean_events": safe_div(sum(ttds_values), len(ttds_values)),
        "ttds_observed_runs": len(ttds_values),
    }

def load_run_artifact(row: dict[str, Any], filename: str) -> dict[str, Any] | None:
    path = Path(row["run_dir"]) / filename
    if not path.exists():
        return None
    return read_json(path)

#Weighted Dangerous-Path Coverage
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

#Time-to-Dangerous-Site
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    rows = iter_runs(args.suite)
    by_tool_variant: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_tool_variant_mode: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_tool_variant[(row["tool"], row["variant"])].append(row)
        by_tool_variant_mode[(row["tool"], row["variant"], row.get("mode", "deterministic"))].append(row)

    result = {
        "suite": args.suite,
        "runs_dir": str(RUNS_DIR / args.suite),
        "total_runs": len(rows),
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
