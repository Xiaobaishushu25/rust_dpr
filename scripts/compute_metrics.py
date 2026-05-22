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
                "seed": meta["seed"],
                "run_index": meta["run_index"],
                "classification": classification,
                "expected": expected,
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

    replay_summaries = []
    for r in rows:
        summary = Path(r["run_dir"]) / "replay_summary.json"
        if summary.exists():
            replay_summaries.append(read_json(summary))
    reproducible = [x for x in replay_summaries if x.get("stable")]

    return {
        "total_runs": total,
        "reported_candidates": len(reported),
        "meaningful_candidates": len(meaningful),
        "mcp": safe_div(len(meaningful), len(reported)),
        "panic_noise_fpr": safe_div(len(noise_reported), len(reported)),
        "oracle_confirmed_runs": len(oracle_confirmed),
        "oracle_confirmed_rate": safe_div(len(oracle_confirmed), total),
        "review_required_runs": len(review_required),
        "review_load": safe_div(len(review_required), total),
        "expected_available": len(expected_available),
        "security_relevant_expected": len(security_relevant_expected),
        "security_relevant_recall": safe_div(len(true_meaningful), len(security_relevant_expected)),
        "replay_checked": len(replay_summaries),
        "reproducibility_rate": safe_div(len(reproducible), len(replay_summaries)),
        "primary_label_counts": dict(label_counts),
        "relation_counts": dict(relation_counts),
        "oracle_counts": dict(oracle_counts),
        "harness_counts": dict(harness_counts),
        "primary_label_confusion": confusion_counts(expected_available, "primary_label"),
        "relation_confusion": confusion_counts(expected_available, "relation"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    rows = iter_runs(args.suite)
    by_tool_variant: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_tool_variant[(row["tool"], row["variant"])].append(row)

    result = {
        "suite": args.suite,
        "runs_dir": str(RUNS_DIR / args.suite),
        "total_runs": len(rows),
        "overall": compute_group_metrics(rows),
        "by_tool_variant": {
            f"{tool}/{variant}": compute_group_metrics(group)
            for (tool, variant), group in sorted(by_tool_variant.items())
        },
    }

    write_json(Path(args.out), result)
    print(f"[done] metrics written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
