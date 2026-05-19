from __future__ import annotations

import argparse
from pathlib import Path

from common import BENCHMARKS_DIR, SUITES, discover_cases, load_yaml, normalize_expected_schema, write_csv


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="reports/tables")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    rows = benchmark_composition()
    write_csv(
        out_dir / "benchmark_composition.csv",
        rows,
        ["suite", "cases", "security_relevant", "negative", "oracle_confirmable"],
    )
    print(f"[done] wrote {out_dir / 'benchmark_composition.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
