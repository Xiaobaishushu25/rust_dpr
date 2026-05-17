from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from common import DATA_DIR, read_json, write_csv, write_json


def collect_suite_rows(suite: str) -> list[dict]:
    suite_dir = DATA_DIR / suite
    rows = []

    if not suite_dir.exists():
        return rows

    for case_dir in sorted(p for p in suite_dir.iterdir() if p.is_dir()):
        classification_path = case_dir / "classification.json"
        if not classification_path.exists():
            continue

        data = read_json(classification_path)
        rows.append(
            {
                "suite": suite,
                "case": case_dir.name,
                "primary_label": data.get("primary_label"),
                "relation": data.get("relation"),
                "oracle_verdict": data.get("oracle_verdict"),
                "harness_status": data.get("harness_status"),
                "distance_to_dangerous_site": data.get("distance_to_dangerous_site"),
                "reached_dangerous_sites": len(data.get("reached_dangerous_sites", [])),
                "review_required": data.get("review_required"),
                "confidence": data.get("confidence"),
                "schema_version": data.get("schema_version"),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect RustDPR classification results")
    parser.add_argument("--suite", choices=["micro", "oracle", "taxonomy"], required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    args = parser.parse_args()

    rows = collect_suite_rows(args.suite)

    label_counter = Counter(row["primary_label"] for row in rows)
    relation_counter = Counter(row["relation"] for row in rows)
    oracle_counter = Counter(row["oracle_verdict"] for row in rows)
    harness_counter = Counter(row["harness_status"] for row in rows)

    summary = {
        "suite": args.suite,
        "total_cases": len(rows),
        "primary_label_counts": dict(label_counter),
        "relation_counts": dict(relation_counter),
        "oracle_verdict_counts": dict(oracle_counter),
        "harness_status_counts": dict(harness_counter),
        "rows": rows,
    }

    write_json(Path(args.out_json), summary)

    fieldnames = [
        "suite",
        "case",
        "primary_label",
        "relation",
        "oracle_verdict",
        "harness_status",
        "distance_to_dangerous_site",
        "reached_dangerous_sites",
        "review_required",
        "confidence",
        "schema_version",
    ]
    write_csv(Path(args.out_csv), rows, fieldnames)

    print("[done]")
    print(f"suite       : {args.suite}")
    print(f"total cases : {len(rows)}")
    print(f"json        : {args.out_json}")
    print(f"csv         : {args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())