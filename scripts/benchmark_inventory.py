#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:
    raise SystemExit("PyYAML is required. Install with: pip install pyyaml") from exc

ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS = ROOT / "benchmarks"
DEFAULT_SUITES = ("micro", "taxonomy", "oracle", "regression", "realworld", "generated-harness")


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


def discover_cases(suite: str) -> list[Path]:
    suite_dir = BENCHMARKS / suite
    if not suite_dir.exists():
        return []
    return sorted(p for p in suite_dir.iterdir() if p.is_dir())


def str_or_empty(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def row_for_case(suite: str, case_dir: Path) -> dict[str, Any]:
    expected_path = case_dir / "expected.yaml"
    if not expected_path.exists():
        return {
            "suite": suite,
            "case": case_dir.name,
            "category": "",
            "primary_label": "MISSING_EXPECTED",
            "relation": "",
            "oracle_verdict": "",
            "harness_status": "",
            "security_relevant": "",
            "oracle_confirmable": "",
            "expected_reached_count": "",
            "dangerous_categories": "",
            "negative_case": "",
            "source_crate": "",
            "source_version": "",
            "source_advisory": "",
            "fixed_version_case": "",
        }

    expected = load_yaml(expected_path)
    gt = expected.get("ground_truth") or {}
    source = expected.get("source") or {}
    selection = expected.get("selection") or {}
    controls = expected.get("controls") or {}
    return {
        "suite": suite,
        "case": case_dir.name,
        "category": str_or_empty(expected.get("category")),
        "primary_label": str_or_empty(gt.get("primary_label")),
        "relation": str_or_empty(gt.get("relation")),
        "oracle_verdict": str_or_empty(gt.get("oracle_verdict")),
        "harness_status": str_or_empty(gt.get("harness_status")),
        "security_relevant": str_or_empty(gt.get("security_relevant")),
        "oracle_confirmable": str_or_empty(gt.get("oracle_confirmable")),
        "expected_reached_count": str_or_empty(gt.get("expected_reached_count")),
        "dangerous_categories": ";".join(map(str, expected.get("dangerous_categories") or [])),
        "negative_case": str_or_empty(selection.get("negative_case")),
        "source_crate": str_or_empty(source.get("crate_name")),
        "source_version": str_or_empty(source.get("version") or source.get("vulnerable_version")),
        "source_advisory": str_or_empty(source.get("advisory")),
        "fixed_version_case": str_or_empty(controls.get("fixed_version_case")),
    }


def print_counter(title: str, counter: Counter[str]) -> None:
    print(f"\n[{title}]")
    if not counter:
        print("  <empty>")
        return
    for key, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {key}: {count}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize RustDPR benchmark composition.")
    parser.add_argument("--suite", action="append", choices=DEFAULT_SUITES, help="suite to include; may be repeated")
    parser.add_argument("--csv", type=Path, default=None, help="optional output CSV path")
    args = parser.parse_args()

    suites = tuple(args.suite) if args.suite else DEFAULT_SUITES
    rows: list[dict[str, Any]] = []
    for suite in suites:
        for case_dir in discover_cases(suite):
            rows.append(row_for_case(suite, case_dir))

    by_suite: Counter[str] = Counter(row["suite"] for row in rows)
    by_relation: Counter[str] = Counter(row["relation"] or "<empty>" for row in rows)
    by_primary: Counter[str] = Counter(row["primary_label"] or "<empty>" for row in rows)
    by_oracle: Counter[str] = Counter(row["oracle_verdict"] or "<empty>" for row in rows)
    by_harness: Counter[str] = Counter(row["harness_status"] or "<empty>" for row in rows)

    print(f"[summary] cases={len(rows)}")
    print_counter("by suite", by_suite)
    print_counter("by relation", by_relation)
    print_counter("by primary label", by_primary)
    print_counter("by oracle verdict", by_oracle)
    print_counter("by harness status", by_harness)

    per_suite_relation: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        per_suite_relation[row["suite"]][row["relation"] or "<empty>"] += 1
    for suite in sorted(per_suite_relation):
        print_counter(f"{suite}: relation distribution", per_suite_relation[suite])

    if args.csv:
        args.csv.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "suite",
            "case",
            "category",
            "primary_label",
            "relation",
            "oracle_verdict",
            "harness_status",
            "security_relevant",
            "oracle_confirmable",
            "expected_reached_count",
            "dangerous_categories",
            "negative_case",
            "source_crate",
            "source_version",
            "source_advisory",
            "fixed_version_case",
        ]
        with args.csv.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n[wrote] {args.csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
