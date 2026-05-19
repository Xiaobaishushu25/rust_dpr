from __future__ import annotations

import argparse

from common import BENCHMARKS_DIR, SUITES, discover_cases, load_yaml, normalize_expected_schema


def validate_suite(suite: str) -> list[dict]:
    rows = []
    for case_dir in discover_cases(suite):
        expected_path = case_dir / "expected.yaml"
        row = {"suite": suite, "case": case_dir.name, "status": "PASS", "errors": []}
        if not expected_path.exists():
            row["status"] = "ERROR"
            row["errors"].append("missing expected.yaml")
            rows.append(row)
            continue
        try:
            expected = normalize_expected_schema(load_yaml(expected_path) or {})
            if expected.get("case_id") and expected["case_id"] != case_dir.name:
                row["status"] = "ERROR"
                row["errors"].append("case_id does not match directory name")
        except Exception as e:
            row["status"] = "ERROR"
            row["errors"].append(str(e))
        rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=SUITES, default=None)
    args = parser.parse_args()

    suites = [args.suite] if args.suite else list(SUITES)
    all_rows = []
    for suite in suites:
        if not (BENCHMARKS_DIR / suite).exists():
            continue
        all_rows.extend(validate_suite(suite))

    errors = 0
    for row in all_rows:
        print(f"[{row['status']}] {row['suite']}/{row['case']}")
        for e in row["errors"]:
            print(f"  - {e}")
        if row["status"] != "PASS":
            errors += 1

    print(f"[summary] cases={len(all_rows)} errors={errors}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
