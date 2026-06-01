# 清理 canonical run 目录
# → 对每个 oracle case 跑 ASan
# → 跑 Miri
# → 保存 asan.log / miri.log
# → 解析 oracle verdict
# → 生成 oracle_summary.json
# → 带 oracle log 重新执行 run_case.py
# → 重新 classify
# → 生成 classification.json
# → 自动调用 check_expected.py
# → 生成 suite summary
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common import (
    ROOT_DIR,
    SUITES,
    clean_case_output_dir,
    discover_cases,
    parse_oracle_log_file,
    read_json,
    run_output_dir,
    select_oracle_verdict,
    summarize_run_classification,
    write_csv,
    write_json,
)


SUMMARY_FIELDNAMES = [
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
    "selected_oracle_verdict",
    "asan_verdict",
    "miri_verdict",
    "harness_status",
    "distance_to_dangerous_site",
    "reached_dangerous_sites",
    "notes_count",
    "review_required",
    "confidence",
    "schema_version",
]


def enabled_oracles(value: str) -> list[str]:
    if value == "both":
        return ["asan", "miri"]
    return [value]


def run_one_oracle(
    *,
    oracle: str,
    suite: str,
    case_name: str,
    seed: int | None,
    run_index: int,
    oracle_dir: Path,
) -> dict:
    script = ROOT_DIR / "scripts" / ("run_asan.py" if oracle == "asan" else "run_miri.py")
    cmd = [
        sys.executable,
        str(script),
        case_name,
        "--suite",
        suite,
        "--run-index",
        str(run_index),
        "--out-dir",
        str(oracle_dir),
    ]
    if seed is not None:
        cmd.extend(["--seed", str(seed)])

    rc = 0
    try:
        from common import run_cmd

        rc = run_cmd(cmd, cwd=ROOT_DIR, check=False)
    except Exception as exc:  # keep suite automation moving; record failure in summary
        rc = 1
        oracle_dir.mkdir(parents=True, exist_ok=True)
        (oracle_dir / f"{oracle}.log").write_text(
            f"[run_oracle_suite] failed to execute {oracle}: {exc}\n",
            encoding="utf-8",
        )

    log_path = oracle_dir / f"{oracle}.log"
    verdict = parse_oracle_log_file(log_path, oracle)
    return {
        "oracle": oracle,
        "return_code": rc,
        "log": str(log_path),
        "verdict": verdict,
    }


def run_case_with_oracle_logs(
    *,
    suite: str,
    case_name: str,
    tool: str,
    variant: str,
    seed: int | None,
    run_index: int,
    budget_seconds: int,
    out_dir: Path,
    oracle_dir: Path,
    skip_harness: bool,
) -> int:
    cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "run_case.py"),
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
        "--out-dir",
        str(out_dir),
        "--no-clean",
    ]
    if seed is not None:
        cmd.extend(["--seed", str(seed)])

    asan_log = oracle_dir / "asan.log"
    miri_log = oracle_dir / "miri.log"
    if asan_log.exists():
        cmd.extend(["--asan-log", str(asan_log)])
    if miri_log.exists():
        cmd.extend(["--miri-log", str(miri_log)])
    if skip_harness:
        cmd.append("--skip-harness")

    from common import run_cmd

    return run_cmd(cmd, cwd=ROOT_DIR, check=False)


def run_expected_check(args) -> int:
    cmd = [
        sys.executable,
        str(ROOT_DIR / "scripts" / "check_expected.py"),
        "--suite",
        args.suite,
        "--tool",
        args.tool,
        "--variant",
        args.variant,
        "--run-index",
        str(args.run_index),
        "--summary-json",
        str(ROOT_DIR / "reports" / f"expected_{args.suite}_seed{args.seed}_run{args.run_index:03d}.json"),
    ]
    if args.seed is not None:
        cmd.extend(["--seed", str(args.seed)])
    if args.strict_expected:
        cmd.append("--strict")

    from common import run_cmd

    return run_cmd(cmd, cwd=ROOT_DIR, check=False)


def default_summary_json(args) -> Path:
    seed_part = "seed-none" if args.seed is None else f"seed-{args.seed}"
    return ROOT_DIR / "reports" / f"oracle_suite_{args.suite}_{seed_part}_run-{args.run_index:03d}.json"


def default_summary_csv(args) -> Path:
    seed_part = "seed-none" if args.seed is None else f"seed-{args.seed}"
    return ROOT_DIR / "reports" / f"oracle_suite_{args.suite}_{seed_part}_run-{args.run_index:03d}.csv"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the oracle suite end-to-end: ASan/Miri -> classify -> expected check"
    )
    parser.add_argument("--suite", choices=SUITES, default="oracle")
    parser.add_argument("--case", default=None, help="run only one case")
    parser.add_argument("--oracle", choices=["asan", "miri", "both"], default="both")
    parser.add_argument("--tool", default="rustdpr")
    parser.add_argument("--variant", default="full")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--run-index", type=int, default=1)
    parser.add_argument("--budget-seconds", type=int, default=0)
    parser.add_argument("--skip-harness", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--no-check-expected", action="store_true")
    parser.add_argument("--strict-expected", action="store_true")
    parser.add_argument("--summary-json", default=None)
    parser.add_argument("--summary-csv", default=None)
    args = parser.parse_args()

    if args.case:
        case_dir = ROOT_DIR / "benchmarks" / args.suite / args.case
        if not case_dir.exists():
            raise SystemExit(f"case not found: {case_dir}")
        cases = [case_dir]
    else:
        cases = discover_cases(args.suite)

    rows: list[dict] = []
    failures: list[dict] = []
    oracles = enabled_oracles(args.oracle)

    for case_dir in cases:
        case_name = case_dir.name
        print(f"=== oracle-suite suite={args.suite} case={case_name} seed={args.seed} run={args.run_index:03d} ===")
        out_dir = run_output_dir(
            args.suite,
            case_name,
            tool=args.tool,
            variant=args.variant,
            seed=args.seed,
            run_index=args.run_index,
        )
        clean_case_output_dir(out_dir)
        oracle_dir = out_dir / "oracle"
        oracle_dir.mkdir(parents=True, exist_ok=True)

        oracle_rows = [
            run_one_oracle(
                oracle=oracle,
                suite=args.suite,
                case_name=case_name,
                seed=args.seed,
                run_index=args.run_index,
                oracle_dir=oracle_dir,
            )
            for oracle in oracles
        ]
        selected_verdict = select_oracle_verdict(oracle_rows)
        write_json(
            oracle_dir / "oracle_summary.json",
            {
                "suite": args.suite,
                "case": case_name,
                "seed": args.seed,
                "run_index": args.run_index,
                "oracles": oracle_rows,
                "selected_oracle_verdict": selected_verdict,
            },
        )

        rc = run_case_with_oracle_logs(
            suite=args.suite,
            case_name=case_name,
            tool=args.tool,
            variant=args.variant,
            seed=args.seed,
            run_index=args.run_index,
            budget_seconds=args.budget_seconds,
            out_dir=out_dir,
            oracle_dir=oracle_dir,
            skip_harness=args.skip_harness,
        )

        classification_path = out_dir / "classification.json"
        meta_path = out_dir / "run_meta.json"
        if classification_path.exists() and meta_path.exists():
            classification = read_json(classification_path)
            meta = read_json(meta_path)
            row = summarize_run_classification(case_name, args.suite, classification, meta)
        else:
            row = {
                "suite": args.suite,
                "case": case_name,
                "tool": args.tool,
                "variant": args.variant,
                "seed": args.seed,
                "run_index": args.run_index,
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
        row["selected_oracle_verdict"] = selected_verdict
        row["asan_verdict"] = next((r["verdict"] for r in oracle_rows if r["oracle"] == "asan"), None)
        row["miri_verdict"] = next((r["verdict"] for r in oracle_rows if r["oracle"] == "miri"), None)
        rows.append(row)

        if rc != 0:
            failures.append({"case": case_name, "seed": args.seed, "run_index": args.run_index, "return_code": rc})
            if args.fail_fast:
                break

    expected_rc = 0
    if not args.no_check_expected:
        expected_rc = run_expected_check(args)
        if expected_rc != 0:
            failures.append({"case": "<check_expected>", "seed": args.seed, "run_index": args.run_index, "return_code": expected_rc})

    summary = {
        "suite": args.suite,
        "tool": args.tool,
        "variant": args.variant,
        "seed": args.seed,
        "run_index": args.run_index,
        "oracle": args.oracle,
        "total_runs": len(rows),
        "failed_runs": len(failures),
        "expected_check_return_code": expected_rc,
        "failures": failures,
        "rows": rows,
    }

    summary_json = Path(args.summary_json) if args.summary_json else default_summary_json(args)
    summary_csv = Path(args.summary_csv) if args.summary_csv else default_summary_csv(args)
    write_json(summary_json, summary)
    write_csv(summary_csv, rows, SUMMARY_FIELDNAMES)

    print("[summary]")
    print(f"suite       : {args.suite}")
    print(f"tool/variant: {args.tool}/{args.variant}")
    print(f"seed/run    : {args.seed}/run-{args.run_index:03d}")
    print(f"total runs  : {len(rows)}")
    print(f"failed runs : {len(failures)}")
    print(f"summary json: {summary_json}")
    print(f"summary csv : {summary_csv}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
