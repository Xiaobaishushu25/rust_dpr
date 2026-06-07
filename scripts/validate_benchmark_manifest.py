from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from common import BENCHMARKS_DIR, SUITES, discover_cases, load_yaml, normalize_expected_schema

DEFAULT_MIN_CASES = {
    "micro": 30,
    "taxonomy": 20,
    "oracle": 10,
    "regression": 12,
    "realworld": 10,
    "generated_harness": 10,
}

REQUIRED_V2_KEYS = {
    "case_id",
    "suite",
    "category",
    "ground_truth",
    "dangerous_categories",
    "selection",
}

REQUIRED_GROUND_TRUTH_KEYS = {
    "primary_label",
    "relation",
    "oracle_verdict",
    "harness_status",
    "security_relevant",
    "oracle_confirmable",
    "expected_reached_count",
}


def _case_errors(suite: str, case_dir: Path, *, paper_strict: bool = False) -> list[str]:
    expected_path = case_dir / "expected.yaml"
    errors: list[str] = []
    if not expected_path.exists():
        return ["missing expected.yaml"]

    try:
        raw = load_yaml(expected_path) or {}
        # normalize_expected_schema validates canonical labels and legacy aliases.
        normalize_expected_schema(raw)
    except Exception as exc:  # noqa: BLE001 - validator should report all schema failures
        return [str(exc)]

    if raw.get("case_id") != case_dir.name:
        errors.append("case_id does not match directory name")
    if raw.get("suite") != suite:
        errors.append("suite does not match directory name")

    missing = sorted(REQUIRED_V2_KEYS - set(raw.keys()))
    if missing:
        errors.append(f"missing top-level v2 keys: {missing}")

    gt = raw.get("ground_truth") or {}
    missing_gt = sorted(REQUIRED_GROUND_TRUTH_KEYS - set(gt.keys()))
    if missing_gt:
        errors.append(f"missing ground_truth keys: {missing_gt}")

    selection = raw.get("selection") or {}
    if not selection.get("reason"):
        errors.append("selection.reason is required")
    if "negative_case" not in selection:
        errors.append("selection.negative_case is required")
    if "manually_labeled" not in selection:
        errors.append("selection.manually_labeled is required")

    source = raw.get("source") or {}
    if suite in {"regression", "realworld", "generated_harness"}:
        if not source:
            errors.append(f"{suite} cases must include source metadata")
        if suite == "regression":
            for key in ("crate_name", "advisory", "url"):
                if not source.get(key):
                    errors.append(f"regression source.{key} is required")
            if paper_strict and not (source.get("vulnerable_version") or source.get("version")):
                errors.append("paper-strict regression source.vulnerable_version is required")
        if suite == "realworld":
            for key in ("crate_name", "version"):
                if not source.get(key):
                    errors.append(f"realworld source.{key} is required")

    if paper_strict and suite == "regression":
        controls = raw.get("controls") or {}
        if "fixed_version_case" not in controls:
            errors.append("paper-strict regression controls.fixed_version_case is required, use null if unavailable")

    if not isinstance(raw.get("dangerous_categories", []), list):
        errors.append("dangerous_categories must be a list")

    return errors


def validate_suite(suite: str, *, paper_strict: bool = False) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_dir in discover_cases(suite):
        errors = _case_errors(suite, case_dir, paper_strict=paper_strict)
        rows.append(
            {
                "suite": suite,
                "case": case_dir.name,
                "status": "ERROR" if errors else "PASS",
                "errors": errors,
            }
        )
    return rows


def manifest_minima() -> dict[str, int]:
    manifest_path = BENCHMARKS_DIR / "manifest.yaml"
    if not manifest_path.exists():
        return dict(DEFAULT_MIN_CASES)
    manifest = load_yaml(manifest_path) or {}
    suites = manifest.get("suites") or {}
    minima = dict(DEFAULT_MIN_CASES)
    if isinstance(suites, dict):
        for name, row in suites.items():
            if isinstance(row, dict) and row.get("expected_cases_min") is not None:
                minima[name] = int(row["expected_cases_min"])
            elif isinstance(row, dict) and row.get("target_cases") is not None:
                minima[name] = int(row["target_cases"])
    elif isinstance(suites, list):
        for row in suites:
            if not isinstance(row, dict):
                continue
            name = row.get("name")
            if name in minima and row.get("target_cases") is not None:
                minima[name] = int(row["target_cases"])
            elif name in minima and row.get("expected_cases_min") is not None:
                minima[name] = int(row["expected_cases_min"])
    return minima


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate RustDPRBench expected.yaml files and suite composition.")
    parser.add_argument("--suite", choices=SUITES, default=None)
    parser.add_argument("--enforce-min", action="store_true", help="fail if suite case count is below manifest/default target")
    parser.add_argument("--min-cases", type=int, default=None, help="override minimum for the selected suite(s)")
    parser.add_argument("--paper-strict", action="store_true", help="enforce external snapshot/fixed-control metadata required for the paper artifact")
    args = parser.parse_args()

    suites = [args.suite] if args.suite else list(SUITES)
    minima = manifest_minima()
    all_rows: list[dict[str, Any]] = []
    count_errors = 0

    for suite in suites:
        suite_dir = BENCHMARKS_DIR / suite
        if not suite_dir.exists():
            if args.enforce_min:
                print(f"[ERROR] {suite}: missing suite directory")
                count_errors += 1
            continue
        rows = validate_suite(suite, paper_strict=args.paper_strict)
        all_rows.extend(rows)
        if args.enforce_min:
            minimum = args.min_cases if args.min_cases is not None else minima.get(suite, 0)
            if len(rows) < minimum:
                print(f"[ERROR] {suite}: cases={len(rows)} below required minimum={minimum}")
                count_errors += 1

    schema_errors = 0
    for row in all_rows:
        print(f"[{row['status']}] {row['suite']}/{row['case']}")
        for error in row["errors"]:
            print(f"  - {error}")
        if row["status"] != "PASS":
            schema_errors += 1

    print(f"[summary] cases={len(all_rows)} schema_errors={schema_errors} count_errors={count_errors}")
    return 1 if (schema_errors or count_errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
