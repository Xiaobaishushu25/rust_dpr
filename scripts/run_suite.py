from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from common import (
    ROOT_DIR,
    SUITES,
    discover_cases,
    read_json,
    run_output_dir,
    summarize_run_classification,
    write_csv,
    write_json,
)


def run_case_subprocess(
    suite: str,
    case_name: str,
    *,
    tool: str,
    variant: str,
    seed: int | None,
    run_index: int,
    budget_seconds: int,
    asan_log: str | None = None,
    miri_log: str | None = None,
    skip_harness: bool = False,
) -> tuple[int, str]:
    cmd = [
        sys.executable,
        "scripts/run_case.py",
        case_name,
        "--suite",
        suite,
        "--tool",
        tool,
        "--variant",
        variant,
        "--run-index",
        str(run_index),
        "--budget-seconds",
        str(budget_seconds),
    ]

    if seed is not None:
        cmd.extend(["--seed", str(seed)])
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
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--repeat", type=int, default=1, help="repeat each case N times")
    parser.add_argument("--tool", default="rustdpr")
    parser.add_argument("--variant", default="full")
    parser.add_argument("--seeds", default="1,2,3,4,5")
    parser.add_argument("--budget-seconds", type=int, default=0)
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--skip-harness", action="store_true")
    parser.add_argument("--summary-json", default=None)
    parser.add_argument("--summary-csv", default=None)
    args = parser.parse_args()

    seeds = [int(x.strip()) for x in args.seeds.split(",") if x.strip()]
    if not seeds:
        seeds = [None]

    cases = discover_cases(args.suite)
    all_rows = []
    failures = []

    for case_dir in cases:
        case_name = case_dir.name
        for seed in seeds:
            for run_idx in range(args.repeat):
                print(f"=== suite={args.suite} case={case_name} seed={seed} run={run_idx + 1}/{args.repeat} ===")
                rc, _ = run_case_subprocess(
                    args.suite,
                    case_name,
                    tool=args.tool,
                    variant=args.variant,
                    seed=seed,
                    run_index=run_idx + 1,
                    budget_seconds=args.budget_seconds,
                    skip_harness=args.skip_harness,
                )

                out_dir = run_output_dir(
                    args.suite,
                    case_name,
                    tool=args.tool,
                    variant=args.variant,
                    seed=seed,
                    run_index=run_idx + 1,
                )
                classification_path = out_dir / "classification.json"
                meta_path = out_dir / "run_meta.json"
                if classification_path.exists():
                    classification = read_json(classification_path)
                    meta = read_json(meta_path) if meta_path.exists() else {}
                    row = summarize_run_classification(case_name, args.suite, classification, meta)
                else:
                    row = {
                        "suite": args.suite,
                        "case": case_name,
                        "tool": args.tool,
                        "variant": args.variant,
                        "seed": seed,
                        "run_index": run_idx + 1,
                        "budget_seconds": args.budget_seconds,
                        "return_code": rc,
                        "primary_label": None,
                        "relation": None,
                        "oracle_verdict": None,
                        "harness_status": None,
                        "distance_to_dangerous_site": None,
                        "reached_dangerous_sites": 0,
                        "notes_count": 0,
                        "review_required": None,
                        "confidence": None,
                        "schema_version": None,
                    }

                row["return_code"] = rc
                all_rows.append(row)

                if rc != 0:
                    failures.append((case_name, seed, run_idx + 1, rc))
                    if args.fail_fast:
                        print("[fail-fast] stopping early")
                        break

            if args.fail_fast and failures:
                break
        if args.fail_fast and failures:
            break

    summary = {
        "suite": args.suite,
        "tool": args.tool,
        "variant": args.variant,
        "repeat": args.repeat,
        "seeds": seeds,
        "total_runs": len(all_rows),
        "failed_runs": len(failures),
        "failures": [
            {"case": case, "seed": seed, "run_index": run_idx, "return_code": rc}
            for case, seed, run_idx, rc in failures
        ],
        "rows": all_rows,
    }

    if args.summary_json:
        write_json(Path(args.summary_json), summary)

    if args.summary_csv:
        fieldnames = [
            "suite",
            "case",
            "tool",
            "variant",
            "seed",
            "run_index",
            "budget_seconds",
            "return_code",
            "primary_label",
            "relation",
            "oracle_verdict",
            "harness_status",
            "distance_to_dangerous_site",
            "reached_dangerous_sites",
            "notes_count",
            "review_required",
            "confidence",
            "schema_version",
        ]
        write_csv(Path(args.summary_csv), all_rows, fieldnames)

    print("[summary]")
    print(f"suite       : {args.suite}")
    print(f"tool/variant: {args.tool}/{args.variant}")
    print(f"total runs  : {len(all_rows)}")
    print(f"failed runs : {len(failures)}")

    if failures:
        print("failures:")
        for case, seed, run_idx, rc in failures:
            print(f"  - {case} seed={seed} run={run_idx} rc={rc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
