from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from common import (
    RUNS_DIR,
    SUITES,
    load_yaml,
    normalize_expected_schema,
    read_json,
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
    score = float(classification.get("confidence") or 0.0)
    if classification.get("oracle_verdict") in CONFIRMED_ORACLES:
        score += 1.0
    if classification.get("primary_label") in MEANINGFUL_LABELS:
        score += 0.5
    if classification.get("review_required"):
        score += 0.1
    if classification.get("harness_status") in {"LikelyMisuse", "Invalid"}:
        score -= 1.0
    return score


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
        "mrr": mean_reciprocal_rank(rows),
        "reviews_to_first_confirmed": reviews_first,
        "reviews_per_confirmed": safe_div(len(review_required), len(oracle_confirmed)),
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
