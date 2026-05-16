from __future__ import annotations

import argparse
import time

from common import (
    ROOT_DIR,
    clean_case_output_dir,
    find_trace_file,
    jsonl_trace_to_tracelog_json,
    read_json,
    resolve_case,
    run_cmd,
    suite_case_data_dir,
    suite_case_report_path,
    validate_result_schema,
    write_json,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a single RustDPR benchmark case")
    parser.add_argument("case", help="case name")
    parser.add_argument("--suite", choices=["micro", "oracle", "taxonomy"], default=None)
    parser.add_argument(
        "--mode",
        choices=["deterministic"],
        default="deterministic",
        help="execution mode; fuzz mode can be added later",
    )
    parser.add_argument("--asan-log", default=None, help="optional ASan log file")
    parser.add_argument("--miri-log", default=None, help="optional Miri log file")
    parser.add_argument(
        "--skip-harness",
        action="store_true",
        help="skip validate-harness even if fuzz/ exists",
    )
    args = parser.parse_args()

    suite, case_dir = resolve_case(args.case, args.suite)
    case_name = case_dir.name
    out_dir = suite_case_data_dir(suite, case_name)
    report_path = suite_case_report_path(suite, case_name)
    clean_case_output_dir(out_dir)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    run_id = f"{suite}-{case_name}-{int(time.time())}"

    site_map = out_dir / "site_map.json"
    function_index = out_dir / "function_index.json"
    dpg = out_dir / "dpg.json"
    harness_json = out_dir / "harness_validity.json"
    classification_json = out_dir / "classification.json"
    run_meta_json = out_dir / "run_meta.json"
    trace_log_json = out_dir / "trace_log.json"
    report_md = report_path

    test_log = out_dir / "cargo_test.log"

    print(f"[case] suite={suite} case={case_name}")
    print(f"[mode] {args.mode}")
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

    # 4) run tests (deterministic mode)
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

    # 5) locate and convert trace
    trace_jsonl = find_trace_file(case_dir)
    jsonl_trace_to_tracelog_json(
        trace_jsonl,
        trace_log_json,
        suite=suite,
        case_name=case_name,
        run_id=run_id,
    )

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

    # 7) report
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
        "mode": args.mode,
        "case_dir": str(case_dir),
        "trace_jsonl": str(trace_jsonl),
        "trace_log_json": str(trace_log_json),
        "site_map": str(site_map),
        "function_index": str(function_index),
        "dpg": str(dpg),
        "harness_validity": str(harness_json) if harness_used else None,
        "classification_path": str(classification_json),
        "report_path": str(report_md),
        "classification": classification,
    }
    write_json(run_meta_json, run_meta)

    print("\n[done]")
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