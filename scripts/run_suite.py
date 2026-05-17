from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from common import (
    ROOT_DIR,
    discover_cases,
    read_json,
    summarize_classification,
    suite_case_data_dir,
    write_csv,
    write_json,
)


def run_case_subprocess(
    suite: str,
    case_name: str,
    *,
    asan_log: str | None = None,
    miri_log: str | None = None,
    skip_harness: bool = False,
) -> tuple[int, str]:
    cmd = [sys.executable, "scripts/run_case.py", case_name, "--suite", suite]

    if asan_log:
        cmd.extend(["--asan-log", asan_log])
    if miri_log:
        cmd.extend(["--miri-log", miri_log])
    if skip_harness:
        cmd.append("--skip-harness")

    print(f"[run] {' '.join(cmd)}")
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT_DIR),
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )

    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)

    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a whole RustDPR benchmark suite")
    parser.add_argument("--suite", choices=["micro", "oracle", "taxonomy"], required=True)
    parser.add_argument("--repeat", type=int, default=1, help="repeat each case N times")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--skip-harness", action="store_true")
    parser.add_argument("--summary-json", default=None)
    parser.add_argument("--summary-csv", default=None)
    args = parser.parse_args()

    cases = discover_cases(args.suite)
    all_rows = []
    failures = []

    for case_dir in cases:
        case_name = case_dir.name

        for run_idx in range(args.repeat):
            print(f"\n=== suite={args.suite} case={case_name} run={run_idx + 1}/{args.repeat} ===")
            rc, _ = run_case_subprocess(
                args.suite,
                case_name,
                skip_harness=args.skip_harness,
            )

            classification_path = suite_case_data_dir(args.suite, case_name) / "classification.json"
            if classification_path.exists():
                classification = read_json(classification_path)
                row = summarize_classification(case_name, args.suite, classification)
            else:
                row = {
                    "suite": args.suite,
                    "case": case_name,
                    "primary_label": None,
                    "relation": None,
                    "oracle_verdict": None,
                    "harness_status": None,
                    "distance_to_dangerous_site": None,
                    "reached_dangerous_sites": 0,
                    "notes_count": 0,
                    "review_required": None,
                    "schema_version": None,
                }

            row["return_code"] = rc
            row["run_index"] = run_idx + 1
            all_rows.append(row)

            if rc != 0:
                failures.append((case_name, run_idx + 1, rc))
                if args.fail_fast:
                    print("[fail-fast] stopping early")
                    break

        if args.fail_fast and failures:
            break

    summary = {
        "suite": args.suite,
        "repeat": args.repeat,
        "total_runs": len(all_rows),
        "failed_runs": len(failures),
        "failures": [
            {"case": case, "run_index": run_idx, "return_code": rc}
            for case, run_idx, rc in failures
        ],
        "rows": all_rows,
    }

    if args.summary_json:
        write_json(Path(args.summary_json), summary)

    if args.summary_csv:
        fieldnames = [
            "suite",
            "case",
            "run_index",
            "return_code",
            "primary_label",
            "relation",
            "oracle_verdict",
            "harness_status",
            "distance_to_dangerous_site",
            "reached_dangerous_sites",
            "notes_count",
            "review_required",
            "schema_version",
        ]
        write_csv(Path(args.summary_csv), all_rows, fieldnames)

    print("\n[summary]")
    print(f"suite       : {args.suite}")
    print(f"total runs  : {len(all_rows)}")
    print(f"failed runs : {len(failures)}")

    if failures:
        print("failures:")
        for case, run_idx, rc in failures:
            print(f"  - {case} run={run_idx} rc={rc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())