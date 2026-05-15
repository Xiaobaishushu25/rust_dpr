#!/usr/bin/env python3
from __future__ import annotations

import argparse

from common import BENCHMARKS_DIR, DATA_DIR, load_yaml, normalize_expected_schema, read_json


def check_suite(suite: str) -> bool:
    suite_dir = BENCHMARKS_DIR / suite
    data_suite_dir = DATA_DIR / suite
    if not suite_dir.exists():
        return False

    failed = False

    for case_dir in sorted([p for p in suite_dir.iterdir() if p.is_dir()]):
        case_name = case_dir.name
        expected_path = case_dir / "expected.yaml"
        result_path = data_suite_dir / case_name / "classification.json"

        if not expected_path.exists():
            print(f"[SKIP] {suite}/{case_name}: missing expected.yaml")
            continue
        if not result_path.exists():
            print(f"[SKIP] {suite}/{case_name}: missing classification.json")
            continue

        expected = normalize_expected_schema(load_yaml(expected_path))
        result = read_json(result_path)

        exp_class = expected.get("primary_label")
        exp_relation = expected.get("relation")
        exp_oracle = expected.get("oracle_verdict")
        exp_harness = expected.get("harness_status")
        exp_reached = expected.get("reached_count")

        got_class = result.get("primary_label")
        got_relation = result.get("relation")
        got_oracle = result.get("oracle_verdict")
        got_harness = result.get("harness_status")
        got_reached = len(result.get("reached_dangerous_sites", []))

        problems = []
        if exp_class is not None and exp_class != got_class:
            problems.append(f"class expected={exp_class} got={got_class}")
        if exp_relation is not None and exp_relation != got_relation:
            problems.append(f"relation expected={exp_relation} got={got_relation}")
        if exp_oracle is not None and exp_oracle != got_oracle:
            problems.append(f"oracle expected={exp_oracle} got={got_oracle}")
        if exp_harness is not None and exp_harness != got_harness:
            problems.append(f"harness expected={exp_harness} got={got_harness}")
        if exp_reached is not None and exp_reached != got_reached:
            problems.append(f"reached_count expected={exp_reached} got={got_reached}")

        if problems:
            failed = True
            print(f"[FAIL] {suite}/{case_name}")
            for p in problems:
                print(f"  - {p}")
        else:
            print(f"[PASS] {suite}/{case_name}")

    return failed


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate classification.json against expected.yaml")
    parser.add_argument(
        "--suite",
        choices=["micro", "oracle", "taxonomy"],
        default=None,
        help="check one suite only; default checks all",
    )
    args = parser.parse_args()

    suites = [args.suite] if args.suite else ["micro", "oracle", "taxonomy"]

    failed = False
    for suite in suites:
        suite_failed = check_suite(suite)
        failed = failed or suite_failed

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())