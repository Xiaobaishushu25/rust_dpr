from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Any

from common import read_json, safe_float, write_csv, write_json

# Metric direction: True means larger is better; False means smaller is better.
METRICS: list[tuple[str, bool, str]] = [
    ("mcp", True, "Meaningful Candidate Precision"),
    ("panic_noise_fpr", False, "Panic-noise false-positive rate"),
    ("oracle_confirmed_rate", True, "Oracle-confirmed rate over all runs"),
    ("oracle_confirmed_per_reported", True, "Oracle-confirmed rate over reported candidates"),
    ("review_load", False, "Manual review load per run"),
    ("reviews_to_first_confirmed", False, "Reviews needed to first confirmed candidate"),
    ("reviews_per_confirmed", False, "Reviews per oracle-confirmed candidate"),
    ("harness_misuse_rejection_rate", True, "Harness-misuse rejection rate"),
    ("security_relevant_recall", True, "Security-relevant recall against expected labels"),
    ("precision_at_1", True, "Precision@1 for ranked candidates"),
    ("precision_at_5", True, "Precision@5 for ranked candidates"),
    ("precision_at_10", True, "Precision@10 for ranked candidates"),
    ("recall_at_10", True, "Recall@10 for ranked candidates"),
    ("ndcg_at_10", True, "nDCG@10 for evidence ranking"),
    ("oracle_confirmed_at_1", True, "OracleConfirmed@1"),
    ("oracle_confirmed_at_5", True, "OracleConfirmed@5"),
    ("oracle_confirmed_at_10", True, "OracleConfirmed@10"),
    ("ttae_ms", False, "Time to first actionable evidence, ms"),
    ("ttoc_ms", False, "Time to first oracle-confirmed evidence, ms"),
    ("obe", True, "Oracle budget efficiency"),
    ("obe_per_cpu_minute", True, "Oracle-confirmed candidates per oracle CPU-minute"),
    ("duplicate_collapse_ratio", True, "Duplicate-collapse ratio"),
    ("actionable_yield_per_cpu_hour", True, "Actionable yield per CPU-hour"),
    ("oracle_confirmed_yield_per_cpu_hour", True, "Oracle-confirmed yield per CPU-hour"),
    ("wdpc_mean", True, "Mean weighted dangerous-path coverage"),
    ("ttds_mean_events", False, "Mean time-to-dangerous-site, events"),
]

FIELDNAMES = [
    "metric",
    "description",
    "higher_is_better",
    "baseline",
    "treatment",
    "absolute_delta",
    "relative_delta",
    "improvement",
    "relative_improvement",
    "directional_result",
]


def finite_number(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(out) or math.isinf(out):
        return None
    return out


def metric_group(metrics: dict[str, Any], key: str | None) -> dict[str, Any]:
    if key is None or key == "overall":
        return metrics.get("overall") or metrics
    groups = metrics.get("by_tool_variant") or {}
    if key in groups:
        return groups[key]
    mode_groups = metrics.get("by_tool_variant_mode") or {}
    if key in mode_groups:
        return mode_groups[key]
    available = sorted(list(groups.keys()) + list(mode_groups.keys()))
    raise SystemExit(
        f"metric group not found: {key}\n"
        f"available groups: {', '.join(available) if available else '(none)'}"
    )


def compare_metrics(baseline: dict[str, Any], treatment: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, higher_is_better, description in METRICS:
        b = finite_number(baseline.get(name))
        t = finite_number(treatment.get(name))
        if b is None and t is None:
            continue
        b = 0.0 if b is None else b
        t = 0.0 if t is None else t
        absolute_delta = t - b
        relative_delta = None if b == 0 else absolute_delta / abs(b)
        improvement = absolute_delta if higher_is_better else -absolute_delta
        relative_improvement = None if b == 0 else improvement / abs(b)
        if improvement > 0:
            directional_result = "improved"
        elif improvement < 0:
            directional_result = "regressed"
        else:
            directional_result = "unchanged"
        rows.append(
            {
                "metric": name,
                "description": description,
                "higher_is_better": higher_is_better,
                "baseline": b,
                "treatment": t,
                "absolute_delta": absolute_delta,
                "relative_delta": relative_delta,
                "improvement": improvement,
                "relative_improvement": relative_improvement,
                "directional_result": directional_result,
            }
        )
    return rows


def fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "yes" if value else "no"
    try:
        num = float(value)
    except (TypeError, ValueError):
        return str(value)
    if abs(num) >= 1000:
        return f"{num:,.0f}"
    return f"{num:.4f}"


def write_markdown(path: Path, rows: list[dict[str, Any]], *, baseline_name: str, treatment_name: str) -> None:
    improved = sum(1 for r in rows if r["directional_result"] == "improved")
    regressed = sum(1 for r in rows if r["directional_result"] == "regressed")
    lines = [
        "# Pipeline Comparison",
        "",
        f"Baseline: `{baseline_name}`",
        f"Treatment: `{treatment_name}`",
        "",
        f"Summary: {improved} metrics improved, {regressed} regressed, {len(rows) - improved - regressed} unchanged.",
        "",
        "| Metric | Direction | Baseline | Treatment | Improvement | Relative improvement | Result |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        direction = "↑" if row["higher_is_better"] else "↓"
        rel = row.get("relative_improvement")
        rel_s = "n/a" if rel is None else f"{float(rel) * 100:.2f}%"
        lines.append(
            "| {metric} | {direction} | {baseline} | {treatment} | {improvement} | {rel} | {result} |".format(
                metric=row["metric"],
                direction=direction,
                baseline=fmt(row["baseline"]),
                treatment=fmt(row["treatment"]),
                improvement=fmt(row["improvement"]),
                rel=rel_s,
                result=row["directional_result"],
            )
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare native harness/fuzzer output with a RustDPR-enhanced pipeline using compute_metrics.py JSON."
    )
    parser.add_argument("--metrics", required=True, help="metrics JSON generated by scripts/compute_metrics.py")
    parser.add_argument("--baseline", required=True, help="baseline group key, e.g. rulf/generated-harness or rulf/panic-only")
    parser.add_argument("--treatment", required=True, help="treatment group key, e.g. rulf/full or rustdpr/full")
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--out-md", required=True)
    args = parser.parse_args()

    metrics = read_json(Path(args.metrics))
    baseline = metric_group(metrics, args.baseline)
    treatment = metric_group(metrics, args.treatment)
    rows = compare_metrics(baseline, treatment)

    payload = {
        "metrics_path": args.metrics,
        "suite": metrics.get("suite"),
        "baseline": args.baseline,
        "treatment": args.treatment,
        "rows": rows,
    }
    write_json(Path(args.out_json), payload)
    write_csv(Path(args.out_csv), rows, FIELDNAMES)
    write_markdown(Path(args.out_md), rows, baseline_name=args.baseline, treatment_name=args.treatment)
    print(f"[done] compared {args.baseline} vs {args.treatment}")
    print(f"json: {args.out_json}")
    print(f"csv : {args.out_csv}")
    print(f"md  : {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
