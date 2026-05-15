#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required. Install with: pip install pyyaml")
    sys.exit(1)

ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = ROOT_DIR / "benchmarks"
DATA_DIR = ROOT_DIR / "data"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def normalize_expected_schema(expected: dict) -> dict:
    # 新 schema（micro）
    if "expected_primary_label" in expected:
        return {
            "primary_label": expected.get("expected_primary_label"),
            "relation": expected.get("expected_relation"),
            "oracle_verdict": expected.get("expected_oracle"),
            "harness_status": expected.get("expected_harness_validity"),
            "reached_count": len(expected.get("expected_reached_dangerous_sites", [])),
        }

    # 旧 schema（oracle / taxonomy）
    old = expected.get("expected", {})
    return {
        "primary_label": old.get("class"),
        "relation": expected.get("expected_relation"),
        "oracle_verdict": None,
        "harness_status": None,
        "reached_count": 1 if old.get("reached_dangerous_site") else 0,
    }


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

        expected = normalize_expected_schema(read_yaml(expected_path))
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