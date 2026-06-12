from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from common import (
    ROOT_DIR,
    SUITES,
    capture_version,
    clean_case_output_dir,
    find_trace_file,
    jsonl_trace_to_tracelog_json,
    read_json,
    resolve_case,
    load_yaml,
    run_cmd,
    run_output_dir,
    validate_result_schema,
    write_json,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a single RustDPR benchmark case")
    parser.add_argument("case", help="case name")
    parser.add_argument("--suite", choices=SUITES, default=None)
    parser.add_argument(
        "--mode",
        choices=["deterministic", "fuzz"],
        default="deterministic",
        help="execution mode",
    )
    parser.add_argument("--fuzz-target", default="fuzz_target_1")
    parser.add_argument("--fuzz-runs", type=int, default=64)
    parser.add_argument("--tool", default="rustdpr")
    parser.add_argument("--variant", default="full")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--run-index", type=int, default=1)
    parser.add_argument("--budget-seconds", type=int, default=0)
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--no-clean", action="store_true")
    parser.add_argument("--asan-log", default=None, help="optional ASan log file")
    parser.add_argument("--miri-log", default=None, help="optional Miri log file")
    parser.add_argument(
        "--skip-harness",
        action="store_true",
        help="skip validate-harness even if fuzz/ exists",
    )
    parser.add_argument("--panic-only", action="store_true")
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--no-trace", action="store_true")
    parser.add_argument("--no-dpg", action="store_true")
    parser.add_argument("--no-harness-validity", action="store_true")
    parser.add_argument("--no-oracle", action="store_true")
    parser.add_argument("--include-deps", action="store_true")
    parser.add_argument("--dep-crates", default="")
    args = parser.parse_args()

    suite, case_dir = resolve_case(args.case, args.suite)
    case_name = case_dir.name

    expected_path = case_dir / "expected.yaml"
    expected_cfg = load_yaml(expected_path) if expected_path.exists() else {}
    execution_cfg = expected_cfg.get("execution") or {}
    deterministic_test = execution_cfg.get("deterministic_test")
    run_ignored = bool(execution_cfg.get("run_ignored", False))

    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        out_dir = run_output_dir(
            suite,
            case_name,
            tool=args.tool,
            variant=args.variant,
            seed=args.seed,
            run_index=args.run_index,
            mode=args.mode,
        )

    if args.no_clean:
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        clean_case_output_dir(out_dir)

    seed_part = "none" if args.seed is None else str(args.seed)
    run_id = f"{suite}/{case_name}/{args.tool}/{args.variant}/seed-{seed_part}/run-{args.run_index:03d}/{args.mode}-{int(time.time())}"

    site_map = out_dir / "site_map.json"
    function_index = out_dir / "function_index.json"
    dpg = out_dir / "dpg.json"
    harness_json = out_dir / "harness_validity.json"
    classification_json = out_dir / "classification.json"
    run_meta_json = out_dir / "run_meta.json"
    trace_log_json = out_dir / "trace_log.json"
    report_md = out_dir / "report.md"
    test_log = out_dir / "cargo_test.log"

    print(f"[case] suite={suite} case={case_name}")
    print(f"[mode] {args.mode}")
    print(f"[tool] {args.tool}/{args.variant}")
    print(f"[out ] {out_dir}")

    analyze_cmd = [
        "cargo",
        "run",
        "-p",
        "rustdpr-cli",
        "--",
        "analyze-sites",
        "--crate-root",
        str(case_dir),
        "--out",
        str(site_map),
        "--function-out",
        str(function_index),
    ]
    if args.include_deps:
        analyze_cmd.append("--include-deps")
        if args.dep_crates:
            analyze_cmd.extend(["--dep-crates", args.dep_crates])

    run_cmd(analyze_cmd, cwd=ROOT_DIR)

    run_cmd(
        [
            "cargo",
            "run",
            "-p",
            "rustdpr-cli",
            "--",
            "build-dpg",
            "--site-map",
            str(site_map),
            "--function-index",
            str(function_index),
            "--out",
            str(dpg),
        ],
        cwd=ROOT_DIR,
    )

    fuzz_dir = case_dir / "fuzz"
    harness_used = False
    if fuzz_dir.exists() and not args.skip_harness:
        run_cmd(
            [
                "cargo",
                "run",
                "-p",
                "rustdpr-cli",
                "--",
                "validate-harness",
                "--harness",
                str(fuzz_dir),
                "--out",
                str(harness_json),
            ],
            cwd=ROOT_DIR,
        )
        harness_used = True

    if args.mode == "deterministic":
        trace_jsonl = out_dir / "trace.jsonl"
        if trace_jsonl.exists():
            trace_jsonl.unlink()

        cargo_test_cmd = [
            "cargo",
            "test",
            "--manifest-path",
            str(case_dir / "Cargo.toml"),
        ]

        if deterministic_test:
            cargo_test_cmd.append(deterministic_test)

        cargo_test_cmd.extend([
            "--",
            "--nocapture",
            "--test-threads=1",
        ])

        if run_ignored:
            cargo_test_cmd.append("--ignored")

        return_code = run_cmd(
            cargo_test_cmd,
            cwd=ROOT_DIR,
            env={
                "RUSTDPR_TRACE_PATH": str(trace_jsonl),
                "RUSTDPR_RUN_ID": run_id,
                "RUSTDPR_INPUT_ID": "deterministic",
            },
            log_path=test_log,
            check=False,
        )
        if not trace_jsonl.exists():
            trace_jsonl = find_trace_file(case_dir)
    else:
        fuzz_out_dir = out_dir / "fuzz"
        fuzz_seed = 1 if args.seed is None else args.seed
        return_code = run_cmd(
            [
                sys.executable,
                "scripts/run_fuzz.py",
                case_name,
                "--suite",
                suite,
                "--target",
                args.fuzz_target,
                "--seed",
                str(fuzz_seed),
                "--run-index",
                str(args.run_index),
                "--budget-seconds",
                str(args.budget_seconds),
                "--runs",
                str(args.fuzz_runs),
                "--out-dir",
                str(fuzz_out_dir),
                "--run-id",
                run_id,
            ],
            cwd=ROOT_DIR,
            check=False,
        )
        fuzz_meta = read_json(fuzz_out_dir / "fuzz_meta.json")
        trace_jsonl = Path(fuzz_meta["trace_jsonl"])
        if not trace_jsonl.exists():
            raise RuntimeError(f"cargo-fuzz did not produce a RustDPR trace: {trace_jsonl}")
    jsonl_trace_to_tracelog_json(
        trace_jsonl,
        trace_log_json,
        suite=suite,
        case_name=case_name,
        run_id=run_id,
    )

    classify_cmd = [
        "cargo",
        "run",
        "-p",
        "rustdpr-cli",
        "--",
        "classify",
        "--site-map",
        str(site_map),
        "--trace",
        str(trace_log_json),
        "--dpg",
        str(dpg),
        "--out",
        str(classification_json),
    ]

    if harness_used:
        classify_cmd.extend(["--harness", str(harness_json)])

    if args.asan_log:
        classify_cmd.extend(["--asan-log", str(args.asan_log)])

    if args.miri_log:
        classify_cmd.extend(["--miri-log", str(args.miri_log)])

    if args.panic_only:
        classify_cmd.append("--panic-only")
    if args.static_only:
        classify_cmd.append("--static-only")
    if args.no_trace:
        classify_cmd.append("--no-trace")
    if args.no_dpg:
        classify_cmd.append("--no-dpg")
    if args.no_harness_validity:
        classify_cmd.append("--no-harness-validity")
    if args.no_oracle:
        classify_cmd.append("--no-oracle")

    run_cmd(classify_cmd, cwd=ROOT_DIR)

    report_cmd = [
        "cargo",
        "run",
        "-p",
        "rustdpr-cli",
        "--",
        "report",
        "--site-map",
        str(site_map),
        "--trace",
        str(trace_log_json),
        "--dpg",
        str(dpg),
        "--classification",
        str(classification_json),
        "--out",
        str(report_md),
    ]
    if harness_used:
        report_cmd.extend(["--harness", str(harness_json)])

    run_cmd(report_cmd, cwd=ROOT_DIR)

    classification = read_json(classification_json)
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
        label="classification",
    )


    run_meta = {
        "run_id": run_id,
        "suite": suite,
        "case": case_name,
        "tool": args.tool,
        "variant": args.variant,
        "mode": args.mode,
        "seed": args.seed,
        "run_index": args.run_index,
        "budget_seconds": args.budget_seconds,
        "fuzz_target": args.fuzz_target if args.mode == "fuzz" else None,
        "fuzz_runs": args.fuzz_runs if args.mode == "fuzz" else None,
        "include_deps": args.include_deps,
        "dep_crates": args.dep_crates,
        "case_dir": str(case_dir),
        "out_dir": str(out_dir),
        "rustc_version": capture_version(["rustc", "--version", "--verbose"]),
        "cargo_version": capture_version(["cargo", "--version", "--verbose"]),
        "trace_jsonl": str(trace_jsonl),
        "trace_log_json": str(trace_log_json),
        "site_map": str(site_map),
        "function_index": str(function_index),
        "dpg": str(dpg),
        "harness_validity": str(harness_json) if harness_used else None,
        "classification_path": str(classification_json),
        "report_path": str(report_md),
        "return_code": return_code,
        "classification": classification,
    }
    write_json(run_meta_json, run_meta)

    print("[done]")
    print(f"trace jsonl     : {trace_jsonl}")
    print(f"trace log json  : {trace_log_json}")
    print(f"classification  : {classification_json}")
    print(f"report          : {report_md}")
    print(f"primary_label   : {classification.get('primary_label')}")
    print(f"relation        : {classification.get('relation')}")
    print(f"oracle_verdict  : {classification.get('oracle_verdict')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
