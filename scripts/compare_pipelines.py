from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Any

from common import read_json, write_csv, write_json

# Metric direction: True means larger is better; False means smaller is better.
METRICS: list[tuple[str, bool, str]] = [
    ("candidate_truth_coverage", True, "Unique candidate artifacts with adjudicated truth"),
    ("mcp", True, "MAIN review-queue MCP, truth-based"),
    ("panic_noise_fpr", False, "MAIN review-queue panic-noise FPR"),
    ("review_queue_recall", True, "Review-queue recall against truth-positive cases"),
    ("review_load", False, "Manual review load per evidence-supported run"),
    ("reproducibility_rate", True, "Replay-stable candidate rate"),
    ("mcp_all_classified_diagnostic", True, "Diagnostic all-classified truth-based MCP"),
    ("panic_noise_fpr_all_classified_diagnostic", False, "Diagnostic all-classified panic-noise FPR"),
    ("label_mcp_diagnostic", True, "Diagnostic label-MCP, not a fair baseline truth metric"),
    ("oracle_confirmed_rate", True, "Oracle-confirmed rate over evidence-supported runs"),
    ("oracle_confirmed_per_reported", True, "Oracle-confirmed rate over reported candidates"),
    ("oracle_confirmed_per_review_queue", True, "Oracle-confirmed rate over review queue"),
    ("reviews_to_first_confirmed", False, "Reviews needed to first confirmed candidate"),
    ("reviews_per_confirmed", False, "Reviews per oracle-confirmed candidate"),
    ("harness_misuse_rejection_rate", True, "Harness-misuse rejection rate"),
    ("security_relevant_recall", True, "MAIN security-relevant recall through the review queue"),
    ("security_relevant_recall_all_classified_diagnostic", True, "Diagnostic all-classified security-relevant recall"),
    ("precision_at_1", True, "Precision@1 for ranked candidates"),
    ("precision_at_5", True, "Precision@5 for ranked candidates"),
    ("precision_at_10", True, "Precision@10 for ranked candidates"),
    ("recall_at_10", True, "Recall@10 for ranked candidates"),
    ("ndcg_at_10", True, "nDCG@10 for evidence ranking"),
    ("oracle_confirmed_at_1", True, "OracleConfirmed@1"),
    ("oracle_confirmed_at_5", True, "OracleConfirmed@5"),
    ("oracle_confirmed_at_10", True, "OracleConfirmed@10"),
    ("ttae_ms", False, "Time to first actionable evidence, relative ms"),
    ("ttoc_ms", False, "Time to first oracle-confirmed evidence, relative ms"),
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
    "comparability",
    "baseline_support",
    "treatment_support",
    "baseline_numerator",
    "baseline_denominator",
    "treatment_numerator",
    "treatment_denominator",
    "baseline_excluded_missing_evidence",
    "treatment_excluded_missing_evidence",
    "notes",
]


def finite_number(value: Any) -> float | None:
    if value in (None, "", "n/a", "NA"):
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


def support_for(group: dict[str, Any], metric: str) -> dict[str, Any]:
    support = group.get("support")
    if isinstance(support, dict) and isinstance(support.get(metric), dict):
        return support[metric]
    return {}


def support_string(support: dict[str, Any]) -> str:
    if not support:
        return "n/a"
    num = support.get("numerator")
    den = support.get("denominator")
    inc = support.get("included_runs")
    miss = support.get("excluded_missing_evidence")
    parts = []
    if num is not None or den is not None:
        parts.append(f"num={num},den={den}")
    if inc is not None:
        parts.append(f"n={inc}")
    if miss:
        parts.append(f"missing={miss}")
    return ";".join(parts) if parts else "n/a"


def support_denominator(support: dict[str, Any]) -> float | None:
    return finite_number(support.get("denominator"))


def compare_metrics(baseline: dict[str, Any], treatment: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, higher_is_better, description in METRICS:
        b = finite_number(baseline.get(name))
        t = finite_number(treatment.get(name))
        b_support = support_for(baseline, name)
        t_support = support_for(treatment, name)
        b_den = support_denominator(b_support)
        t_den = support_denominator(t_support)

        notes: list[str] = []
        if b is None:
            notes.append("baseline metric n/a")
        if t is None:
            notes.append("treatment metric n/a")
        if b_den == 0:
            notes.append("baseline support denominator is 0")
        if t_den == 0:
            notes.append("treatment support denominator is 0")
        if b_support.get("note"):
            notes.append(f"baseline: {b_support.get('note')}")
        if t_support.get("note") and t_support.get("note") != b_support.get("note"):
            notes.append(f"treatment: {t_support.get('note')}")

        if b is None or t is None:
            absolute_delta = None
            relative_delta = None
            improvement = None
            relative_improvement = None
            directional_result = "not_comparable"
            comparability = "not_comparable"
        else:
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
            comparability = "comparable"

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
                "comparability": comparability,
                "baseline_support": support_string(b_support),
                "treatment_support": support_string(t_support),
                "baseline_numerator": b_support.get("numerator"),
                "baseline_denominator": b_support.get("denominator"),
                "treatment_numerator": t_support.get("numerator"),
                "treatment_denominator": t_support.get("denominator"),
                "baseline_excluded_missing_evidence": b_support.get("excluded_missing_evidence"),
                "treatment_excluded_missing_evidence": t_support.get("excluded_missing_evidence"),
                "notes": " | ".join(notes),
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
    comparable = [r for r in rows if r["comparability"] == "comparable"]
    improved = sum(1 for r in comparable if r["directional_result"] == "improved")
    regressed = sum(1 for r in comparable if r["directional_result"] == "regressed")
    unchanged = sum(1 for r in comparable if r["directional_result"] == "unchanged")
    not_comparable = len(rows) - len(comparable)
    lines = [
        "# Pipeline Comparison",
        "",
        f"Baseline: `{baseline_name}`",
        f"Treatment: `{treatment_name}`",
        "",
        (
            f"Summary: {improved} comparable metrics improved, {regressed} regressed, "
            f"{unchanged} unchanged, {not_comparable} not comparable due to missing value/support."
        ),
        "",
        "> `mcp` and `panic_noise_fpr` are MAIN review-queue metrics: denominator is `review_required=true` for precision and truth-negative cases entering the review queue for FPR.",
        "> `mcp_all_classified_diagnostic` and `panic_noise_fpr_all_classified_diagnostic` keep the old all-classified view for debugging only.",
        "> `label_mcp_diagnostic` is included only for debugging old label-based behavior.",
        "",
        "| Metric | Direction | Baseline | Treatment | Improvement | Relative improvement | Result | Baseline support | Treatment support |",
        "|---|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for row in rows:
        direction = "↑" if row["higher_is_better"] else "↓"
        rel = row.get("relative_improvement")
        rel_s = "n/a" if rel is None else f"{float(rel) * 100:.2f}%"
        lines.append(
            "| {metric} | {direction} | {baseline} | {treatment} | {improvement} | {rel} | {result} | {bs} | {ts} |".format(
                metric=row["metric"],
                direction=direction,
                baseline=fmt(row["baseline"]),
                treatment=fmt(row["treatment"]),
                improvement=fmt(row["improvement"]),
                rel=rel_s,
                result=row["directional_result"],
                bs=row.get("baseline_support") or "n/a",
                ts=row.get("treatment_support") or "n/a",
            )
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare native harness/fuzzer output with a RustDPR-enhanced pipeline using compute_metrics.py JSON."
    )
    parser.add_argument("--metrics", required=True, help="metrics JSON generated by scripts/compute_metrics.py")
    parser.add_argument("--baseline", required=True, help="baseline group key, e.g. cargo-fuzz/crash-only")
    parser.add_argument("--treatment", required=True, help="treatment group key, e.g. cargo-fuzz/full")
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--out-md", required=True)
    args = parser.parse_args()

    metrics = read_json(Path(args.metrics))
    baseline = metric_group(metrics, args.baseline)
    treatment = metric_group(metrics, args.treatment)
    rows = compare_metrics(baseline, treatment)

    payload = {
        "schema_version": "0.2.0",
        "metrics_path": args.metrics,
        "suite": metrics.get("suite"),
        "baseline": args.baseline,
        "treatment": args.treatment,
        "metric_semantics": metrics.get("metric_semantics", {}),
        "baseline_group_summary": {
            "total_runs": baseline.get("total_runs"),
            "unit_of_analysis": baseline.get("unit_of_analysis"),
            "unique_candidates": baseline.get("unique_candidates"),
            "truth_annotated_unique_candidates": baseline.get("truth_annotated_unique_candidates"),
            "candidate_truth_coverage": baseline.get("candidate_truth_coverage"),
            "campaigns_represented": baseline.get("campaigns_represented"),
            "evidence_supported_runs": baseline.get("evidence_supported_runs"),
            "missing_evidence_runs": baseline.get("missing_evidence_runs"),
            "reported_candidates": baseline.get("reported_candidates"),
            "assessable_reported_candidates": baseline.get("assessable_reported_candidates"),
            "unassessable_reported_candidates": baseline.get("unassessable_reported_candidates"),
            "review_queue_candidates": baseline.get("review_queue_candidates"),
            "assessable_review_queue_candidates": baseline.get("assessable_review_queue_candidates"),
            "unassessable_review_queue_candidates": baseline.get("unassessable_review_queue_candidates"),
        },
        "treatment_group_summary": {
            "total_runs": treatment.get("total_runs"),
            "unit_of_analysis": treatment.get("unit_of_analysis"),
            "unique_candidates": treatment.get("unique_candidates"),
            "truth_annotated_unique_candidates": treatment.get("truth_annotated_unique_candidates"),
            "candidate_truth_coverage": treatment.get("candidate_truth_coverage"),
            "campaigns_represented": treatment.get("campaigns_represented"),
            "evidence_supported_runs": treatment.get("evidence_supported_runs"),
            "missing_evidence_runs": treatment.get("missing_evidence_runs"),
            "reported_candidates": treatment.get("reported_candidates"),
            "assessable_reported_candidates": treatment.get("assessable_reported_candidates"),
            "unassessable_reported_candidates": treatment.get("unassessable_reported_candidates"),
            "review_queue_candidates": treatment.get("review_queue_candidates"),
            "assessable_review_queue_candidates": treatment.get("assessable_review_queue_candidates"),
            "unassessable_review_queue_candidates": treatment.get("unassessable_review_queue_candidates"),
        },
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
