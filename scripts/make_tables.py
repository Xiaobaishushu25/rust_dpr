from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from common import BENCHMARKS_DIR, SUITES, discover_cases, load_yaml, normalize_expected_schema, read_json, write_csv


def benchmark_composition() -> list[dict]:
    rows = []
    for suite in SUITES:
        suite_dir = BENCHMARKS_DIR / suite
        if not suite_dir.exists():
            continue
        total = 0
        positive = 0
        oracle = 0
        negative = 0
        for case_dir in discover_cases(suite):
            expected_path = case_dir / "expected.yaml"
            if not expected_path.exists():
                continue
            expected = normalize_expected_schema(load_yaml(expected_path) or {})
            total += 1
            if expected.get("security_relevant"):
                positive += 1
            else:
                negative += 1
            if expected.get("oracle_confirmable"):
                oracle += 1
        rows.append(
            {
                "suite": suite,
                "cases": total,
                "security_relevant": positive,
                "negative": negative,
                "oracle_confirmable": oracle,
            }
        )
    return rows


def make_rq7_table(metrics: dict[str, Any]) -> str:
    groups = metrics.get("by_tool_variant") or {}
    lines = [
        "| Pipeline | MCP ↑ | Panic Noise FPR ↓ | Oracle/Reported ↑ | Replay Stable ↑ | Review Load ↓ | wDPC ↑ | P@5 ↑ | MRR ↑ | Reviews/Confirmed ↓ |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for pipeline, values in sorted(groups.items()):
        reviews_per_confirmed = values.get("reviews_per_confirmed")
        rpc = "n/a" if reviews_per_confirmed is None else f"{float(reviews_per_confirmed):.3f}"
        lines.append(
            f"| {pipeline} | "
            f"{float(values.get('mcp', 0.0)):.3f} | "
            f"{float(values.get('panic_noise_fpr', 0.0)):.3f} | "
            f"{float(values.get('oracle_confirmed_per_reported', 0.0)):.3f} | "
            f"{float(values.get('reproducibility_rate', 0.0)):.3f} | "
            f"{float(values.get('review_load', 0.0)):.3f} | "
            f"{float(values.get('wdpc_mean', 0.0)):.3f} | "
            f"{float(values.get('precision_at_5', 0.0)):.3f} | "
            f"{float(values.get('mrr', 0.0)):.3f} | "
            f"{rpc} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="reports/tables")
    parser.add_argument("--metrics", default=None, help="optional metrics JSON for RQ7/RQ8 table")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    rows = benchmark_composition()
    write_csv(
        out_dir / "benchmark_composition.csv",
        rows,
        ["suite", "cases", "security_relevant", "negative", "oracle_confirmable"],
    )
    print(f"[done] wrote {out_dir / 'benchmark_composition.csv'}")

    if args.metrics:
        metrics = read_json(Path(args.metrics))
        table = make_rq7_table(metrics)
        out_dir.mkdir(parents=True, exist_ok=True)
        table_path = out_dir / "rq7_rq8_integration_efficiency.md"
        table_path.write_text(table, encoding="utf-8")
        print(f"[done] wrote {table_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
