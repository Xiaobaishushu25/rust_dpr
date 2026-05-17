from __future__ import annotations

import argparse
from pathlib import Path

from common import (
    BENCHMARKS_DIR,
    discover_cases,
    load_yaml,
    normalize_expected_schema,
    normalize_oracle_verdicts,
    normalize_primary_label,
    normalize_relation_label,
    read_json,
    summarize_classification,
    suite_case_data_dir,
    validate_result_schema,
    write_json,
)


def compare_case(suite: str, case_dir: Path) -> dict:
    case_name = case_dir.name
    expected_path = case_dir / "expected.yaml"
    classification_path = suite_case_data_dir(suite, case_name) / "classification.json"

    result = {
        "suite": suite,
        "case": case_name,
        "status": "PASS",
        "mismatches": [],
        "expected_path": str(expected_path),
        "classification_path": str(classification_path),
    }

    if not expected_path.exists():
        result["status"] = "ERROR"
        result["mismatches"].append("expected.yaml not found")
        return result

    if not classification_path.exists():
        result["status"] = "ERROR"
        result["mismatches"].append("classification.json not found")
        return result

    expected_raw = load_yaml(expected_path) or {}
    expected = normalize_expected_schema(expected_raw)

    classification = read_json(classification_path)
    validate_result_schema(
        classification,
        required=[
            "schema_version",
            "primary_label",
            "relation",
            "oracle_verdict",
            "harness_status",
            "confidence",
            "review_required",
        ],
        label=f"{suite}/{case_name}/classification",
    )

    actual_primary = normalize_primary_label(classification.get("primary_label"))
    actual_relation = normalize_relation_label(classification.get("relation"))
    actual_oracle = normalize_oracle_verdicts(classification.get("oracle_verdict"))
    actual_harness = classification.get("harness_status")
    actual_reached_count = len(classification.get("reached_dangerous_sites", []))

    checks = [
        ("primary_label", expected["primary_label"], actual_primary),
        ("relation", expected["relation"], actual_relation),
        ("oracle_verdict", expected["oracle_verdict"], actual_oracle),
        ("harness_status", expected["harness_status"], actual_harness),
        ("reached_count", expected["reached_count"], actual_reached_count),
    ]

    for field, exp, act in checks:
        if exp != act:
            result["status"] = "FAIL"
            result["mismatches"].append(f"{field}: expected={exp!r}, actual={act!r}")

    result["summary"] = summarize_classification(case_name, suite, classification)
    result["expected"] = expected
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Check expected labels against classification outputs")
    parser.add_argument("--suite", choices=["micro", "oracle", "taxonomy"], required=True)
    parser.add_argument("--case", default=None, help="check only one case")
    parser.add_argument("--strict", action="store_true", help="exit non-zero on FAIL or ERROR")
    parser.add_argument("--summary-json", default=None)
    args = parser.parse_args()

    if args.case:
        cases = [BENCHMARKS_DIR / args.suite / args.case]
        if not cases[0].exists():
            raise SystemExit(f"case not found: {cases[0]}")
    else:
        cases = discover_cases(args.suite)

    results = []
    pass_count = 0
    fail_count = 0
    error_count = 0

    for case_dir in cases:
        res = compare_case(args.suite, case_dir)
        results.append(res)

        status = res["status"]
        if status == "PASS":
            pass_count += 1
            print(f"[PASS] {res['suite']}/{res['case']}")
        elif status == "FAIL":
            fail_count += 1
            print(f"[FAIL] {res['suite']}/{res['case']}")
            for m in res["mismatches"]:
                print(f"  - {m}")
        else:
            error_count += 1
            print(f"[ERROR] {res['suite']}/{res['case']}")
            for m in res["mismatches"]:
                print(f"  - {m}")

    summary = {
        "suite": args.suite,
        "total": len(results),
        "pass": pass_count,
        "fail": fail_count,
        "error": error_count,
        "results": results,
    }

    if args.summary_json:
        write_json(Path(args.summary_json), summary)

    print("\n[summary]")
    print(f"suite : {args.suite}")
    print(f"total : {len(results)}")
    print(f"pass  : {pass_count}")
    print(f"fail  : {fail_count}")
    print(f"error : {error_count}")

    if args.strict and (fail_count > 0 or error_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())