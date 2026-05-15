#python scripts/run_case.py mb_panic_before_unsafe --suite micro
from __future__ import annotations

import argparse

from common import (
    ROOT_DIR,
    find_trace_file,
    jsonl_trace_to_tracelog_json,
    read_json,
    resolve_case,
    run_cmd,
    suite_case_data_dir,
    write_json,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a single RustDPR benchmark case")
    parser.add_argument("case", help="case name")
    parser.add_argument("--suite", choices=["micro", "oracle", "taxonomy"], default=None)
    parser.add_argument(
        "--asan-log",
        default=None,
        help="path to ASan log file; passed through to rustdpr classify",
    )
    parser.add_argument(
        "--miri-log",
        default=None,
        help="path to Miri log file; passed through to rustdpr classify",
    )
    parser.add_argument(
        "--skip-harness",
        action="store_true",
        help="skip validate-harness even if fuzz/ exists",
    )
    args = parser.parse_args()

    suite, case_dir = resolve_case(args.case, args.suite)
    case_name = case_dir.name
    out_dir = suite_case_data_dir(suite, case_name)
    out_dir.mkdir(parents=True, exist_ok=True)

    site_map = out_dir / "site_map.json"
    function_index = out_dir / "function_index.json"
    dpg = out_dir / "dpg.json"
    harness_json = out_dir / "harness_validity.json"
    classification_json = out_dir / "classification.json"
    run_meta_json = out_dir / "run_meta.json"
    trace_log_json = out_dir / "trace_log.json"

    test_log = out_dir / "cargo_test.log"

    print(f"[case] suite={suite} case={case_name}")
    print(f"[out ] {out_dir}")

    # 1) analyze-sites
    run_cmd(
        [
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
        ],
        cwd=ROOT_DIR,
    )

    # 2) build-dpg
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

    # 3) validate-harness (optional)
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

    # 4) run tests
    run_cmd(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(case_dir / "Cargo.toml"),
            "--",
            "--nocapture",
        ],
        cwd=ROOT_DIR,
        log_path=test_log,
        check=False,
    )

    # 5) find trace and convert JSONL -> TraceLog JSON
    trace_jsonl = find_trace_file(case_dir)
    jsonl_trace_to_tracelog_json(trace_jsonl, trace_log_json)

    # 6) classify
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

    run_cmd(classify_cmd, cwd=ROOT_DIR)

    classification = read_json(classification_json)
    run_meta = {
        "suite": suite,
        "case": case_name,
        "case_dir": str(case_dir),
        "trace_jsonl": str(trace_jsonl),
        "trace_log_json": str(trace_log_json),
        "site_map": str(site_map),
        "function_index": str(function_index),
        "dpg": str(dpg),
        "harness_validity": str(harness_json) if harness_used else None,
        "classification": classification,
    }
    write_json(run_meta_json, run_meta)

    print("\n[done]")
    print(f"trace jsonl     : {trace_jsonl}")
    print(f"trace log json  : {trace_log_json}")
    print(f"classification  : {classification_json}")
    print(f"primary_label   : {classification.get('primary_label')}")
    print(f"relation        : {classification.get('relation')}")
    print(f"oracle_verdict  : {classification.get('oracle_verdict')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())