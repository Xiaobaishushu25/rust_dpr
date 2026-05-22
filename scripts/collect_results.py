from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from common import RUNS_DIR, SUITES, read_json, write_csv, write_json


def collect_run_rows(suite: str) -> list[dict]:
    rows = []
    suite_dir = RUNS_DIR / suite
    if not suite_dir.exists():
        return rows

    for classification_path in sorted(suite_dir.rglob("classification.json")):
        run_dir = classification_path.parent
        data = read_json(classification_path)
        meta_path = run_dir / "run_meta.json"
        if not meta_path.exists():
            raise RuntimeError(f"run_meta.json not found for run: {run_dir}")
        meta = read_json(meta_path)
        rows.append(
            {
                "suite": suite,
                "case": meta["case"],
                "tool": meta["tool"],
                "variant": meta["variant"],
                "seed": meta["seed"],
                "run_index": meta["run_index"],
                "mode": meta["mode"],
                "primary_label": data.get("primary_label"),
                "relation": data.get("relation"),
                "oracle_verdict": data.get("oracle_verdict"),
                "harness_status": data.get("harness_status"),
                "distance_to_dangerous_site": data.get("distance_to_dangerous_site"),
                "reached_dangerous_sites": len(data.get("reached_dangerous_sites", [])),
                "review_required": data.get("review_required"),
                "confidence": data.get("confidence"),
                "return_code": meta.get("return_code"),
                "schema_version": data.get("schema_version"),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect RustDPR classification results")
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    args = parser.parse_args()

    rows = collect_run_rows(args.suite)

    label_counter = Counter(row["primary_label"] for row in rows)
    relation_counter = Counter(row["relation"] for row in rows)
    oracle_counter = Counter(row["oracle_verdict"] for row in rows)
    harness_counter = Counter(row["harness_status"] for row in rows)

    summary = {
        "suite": args.suite,
        "total_runs": len(rows),
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
        "tool",
        "variant",
        "seed",
        "run_index",
        "mode",
        "primary_label",
        "relation",
        "oracle_verdict",
        "harness_status",
        "distance_to_dangerous_site",
        "reached_dangerous_sites",
        "review_required",
        "confidence",
        "return_code",
        "schema_version",
    ]
    write_csv(Path(args.out_csv), rows, fieldnames)

    print("[done]")
    print(f"suite      : {args.suite}")
    print(f"total runs : {len(rows)}")
    print(f"json       : {args.out_json}")
    print(f"csv        : {args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
