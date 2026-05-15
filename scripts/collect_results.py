from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def collect_suite_rows(suite: str) -> list[dict]:
    suite_dir = DATA_DIR / suite
    if not suite_dir.exists():
        return []

    rows: list[dict] = []
    for case_dir in sorted([p for p in suite_dir.iterdir() if p.is_dir()]):
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
                "confidence": data.get("confidence"),
                "oracle_verdict": data.get("oracle_verdict"),
                "harness_status": data.get("harness_status"),
                "distance_to_dangerous_site": data.get("distance_to_dangerous_site"),
                "reached_dangerous_sites": len(data.get("reached_dangerous_sites", [])),
                "review_required": data.get("review_required"),
                "notes_count": len(data.get("notes", {}).get("notes", [])),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect RustDPR classification results")
    parser.add_argument(
        "--suite",
        choices=["micro", "oracle", "taxonomy"],
        default=None,
        help="collect one suite only; default collects all",
    )
    parser.add_argument("--out-json", default=None, help="optional output JSON path")
    parser.add_argument("--out-csv", default=None, help="optional output CSV path")
    args = parser.parse_args()

    suites = [args.suite] if args.suite else ["micro", "oracle", "taxonomy"]

    rows: list[dict] = []
    for suite in suites:
        rows.extend(collect_suite_rows(suite))

    if args.out_json:
        out_json = Path(args.out_json)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.out_csv:
        import csv

        out_csv = Path(args.out_csv)
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "suite",
            "case",
            "primary_label",
            "relation",
            "confidence",
            "oracle_verdict",
            "harness_status",
            "distance_to_dangerous_site",
            "reached_dangerous_sites",
            "review_required",
            "notes_count",
        ]
        with out_csv.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())