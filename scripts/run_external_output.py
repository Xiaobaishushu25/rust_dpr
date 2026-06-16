from __future__ import annotations

import argparse
import time
from pathlib import Path

from common import (
    ROOT_DIR,
    candidate_evidence_grade,
    candidate_id_for_run,
    candidate_is_actionable,
    candidate_is_meaningful,
    candidate_is_oracle_confirmed,
    candidate_score,
    candidate_score_components,
    first_trace_times,
    jsonl_trace_to_tracelog_json,
    read_json,
    run_cmd,
    validate_external_meta,
    write_json,
    write_jsonl,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate one upstream fuzzing output with RustDPR"
    )
    parser.add_argument("--meta", required=True, help="external run_meta.json")
    parser.add_argument("--crate-root", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--include-deps", action="store_true")
    parser.add_argument("--dep-crates", default="")
    parser.add_argument("--asan-log", default=None)
    parser.add_argument("--miri-log", default=None)
    parser.add_argument("--replay-summary", default=None)
    parser.add_argument("--tool-override", default=None, help="Override meta.tool in written run/candidate metadata")
    parser.add_argument("--variant-override", default=None, help="Override meta.variant in written run/candidate metadata, e.g. full")
    parser.add_argument(
        "--evidence-mode",
        choices=["rustdpr-replay", "trace-file", "empty-trace"],
        default="rustdpr-replay",
        help=(
            "How RustDPR obtains dynamic evidence. rustdpr-replay uses only traces produced by "
            "RustDPR-controlled replay; trace-file is for pre-existing RustDPR JSONL traces; "
            "empty-trace is a legacy/debug fallback. cargo-fuzz/libFuzzer logs are never parsed here."
        ),
    )
    parser.add_argument(
        "--allow-missing-independent-trace",
        action="store_true",
        help="Do not convert missing RustDPR replay trace evidence into an Unknown/unsupported classification.",
    )
    parser.add_argument("--panic-only", action="store_true")
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--no-trace", action="store_true")
    parser.add_argument("--no-dpg", action="store_true")
    parser.add_argument("--no-harness-validity", action="store_true")
    parser.add_argument("--no-oracle", action="store_true")
    args = parser.parse_args()

    meta = read_json(Path(args.meta))
    validate_external_meta(meta)
    effective_tool = args.tool_override or meta.get("tool")
    effective_variant = args.variant_override or meta.get("variant", "full")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    crate_root = Path(args.crate_root).resolve()
    if not crate_root.exists():
        print(f"[error] crate_root does not exist: {crate_root}")
        return 2
    if not crate_root.is_dir():
        print(f"[error] crate_root is not a directory: {crate_root}")
        return 2
    if not (crate_root / 'Cargo.toml').exists():
        print(f"[error] crate_root has no Cargo.toml: {crate_root}")
        return 2
    site_map = out_dir / "site_map.json"
    function_index = out_dir / "function_index.json"
    dpg = out_dir / "dpg.json"
    harness_json = out_dir / "harness_validity.json"
    trace_log_json = out_dir / "trace_log.json"
    classification_json = out_dir / "classification.json"
    report_md = out_dir / "report.md"
    run_meta_json = out_dir / "run_meta.json"

    analyze_cmd = [
        "cargo",
        "run",
        "-p",
        "rustdpr-cli",
        "--",
        "analyze-sites",
        "--crate-root",
        str(crate_root),
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

    harness_path = Path(meta["harness_path"])
    harness_used = False
    if harness_path.exists() and not args.no_harness_validity:
        run_cmd(
            [
                "cargo",
                "run",
                "-p",
                "rustdpr-cli",
                "--",
                "validate-harness",
                "--harness",
                str(harness_path),
                "--out",
                str(harness_json),
            ],
            cwd=ROOT_DIR,
        )
        harness_used = True

    evidence_source = {
        "mode": args.evidence_mode,
        "trace": None,
        "panic": "rustdpr_panic_hook_if_present",
        "dangerous_hit": "rustdpr_trace_hit_if_present",
        "oracle": "rustdpr_oracle_if_enabled",
        "external_log_used": False,
        "missing_independent_trace": False,
        "notes": [],
    }

    trace_path: str | None = None
    if args.evidence_mode == "rustdpr-replay":
        trace_path = meta.get("rustdpr_trace_path") or meta.get("trace_path")
        evidence_source["trace"] = "rustdpr_replay"
    elif args.evidence_mode == "trace-file":
        trace_path = meta.get("trace_path")
        evidence_source["trace"] = "provided_rustdpr_trace_file"
    else:
        trace_path = None
        evidence_source["trace"] = "empty_trace_debug_fallback"

    trace_missing = not (trace_path and Path(trace_path).exists())
    if not trace_missing:
        jsonl_trace_to_tracelog_json(
            Path(trace_path),
            trace_log_json,
            suite="generated_harness",
            case_name=meta.get("crate"),
            run_id=f"{effective_tool}/{effective_variant}/{meta.get('harness_id')}/{int(time.time())}",
        )
    else:
        evidence_source["missing_independent_trace"] = args.evidence_mode == "rustdpr-replay"
        evidence_source["notes"].append(
            "No RustDPR JSONL trace was available. This script does not parse cargo-fuzz/libFuzzer logs as evidence."
        )
        write_json(
            trace_log_json,
            {
                "schema_version": "0.2.0",
                "suite": "generated_harness",
                "case_name": meta.get("crate"),
                "run_id": meta.get("harness_id"),
                "events": [],
                "evidence_source": evidence_source,
            },
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
        "--dpg",
        str(dpg),
        "--trace",
        str(trace_log_json),
        "--out",
        str(classification_json),
    ]
    if harness_used:
        classify_cmd.extend(["--harness", str(harness_json)])
    if args.asan_log:
        classify_cmd.extend(["--asan-log", args.asan_log])
    if args.miri_log:
        classify_cmd.extend(["--miri-log", args.miri_log])
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
        "--dpg",
        str(dpg),
        "--trace",
        str(trace_log_json),
        "--classification",
        str(classification_json),
        "--out",
        str(report_md),
    ]
    if harness_used:
        report_cmd.extend(["--harness", str(harness_json)])
    run_cmd(report_cmd, cwd=ROOT_DIR)

    classification = read_json(classification_json)
    external_inputs_present = bool(
        meta.get("input_files")
        or meta.get("crash_inputs")
        or meta.get("corpus_inputs")
        or int(meta.get("raw_crash_count") or 0) > 0
        or int(meta.get("raw_replay_failure_count") or 0) > 0
    )
    if (
        args.evidence_mode == "rustdpr-replay"
        and trace_missing
        and external_inputs_present
        and not args.allow_missing_independent_trace
    ):
        notes = classification.get("notes") if isinstance(classification.get("notes"), dict) else {}
        note_list = list(notes.get("notes") or [])
        note_list.append(
            "RustDPR did not classify this external input as Noise because no independent RustDPR replay trace was produced. "
            "cargo-fuzz/libFuzzer logs were not parsed as classification evidence."
        )
        fired_rules = list(notes.get("fired_rules") or [])
        fired_rules.append("missing-rustdpr-independent-trace")
        evidence_summary = list(notes.get("evidence_summary") or [])
        evidence_summary.append(
            "Unsupported for RustDPR validation: external inputs exist, but RustDPR replay produced no trace."
        )
        decision_path = list(notes.get("decision_path") or [])
        decision_path.append(
            "evidence_mode=rustdpr-replay, external_log_used=false, trace_path_missing=true"
        )
        notes.update(
            {
                "notes": note_list,
                "fired_rules": fired_rules,
                "evidence_summary": evidence_summary,
                "decision_path": decision_path,
                "evidence_source": evidence_source,
            }
        )
        classification.update(
            {
                "primary_label": "Unknown",
                "relation": "Unknown",
                "reached_dangerous_sites": [],
                "nearest_dangerous_site": None,
                "distance_to_dangerous_site": None,
                "oracle_verdict": classification.get("oracle_verdict", "Unknown"),
                "oracle_evidence_strength": classification.get("oracle_evidence_strength", "Unknown"),
                "confidence": 0.0,
                "review_required": True,
                "notes": notes,
                "evidence_source": evidence_source,
            }
        )
        write_json(classification_json, classification)

    merged_meta = dict(meta)
    merged_meta.update(
        {
            "suite": "generated_harness",
            "case": crate_root.name,
            "tool": effective_tool,
            "variant": effective_variant,
            "mode": "external-output",
            "evidence_mode": args.evidence_mode,
            "evidence_source": evidence_source,
            "external_log_used_by_rustdpr": False,
            "seed": meta.get("seed"),
            "run_index": 1,
            "budget_seconds": meta.get("fuzz_budget_seconds", 0),
            "include_deps": args.include_deps,
            "dep_crates": args.dep_crates,
            "out_dir": str(out_dir),
            "site_map": str(site_map),
            "function_index": str(function_index),
            "dpg": str(dpg),
            "trace_log_json": str(trace_log_json),
            "harness_validity": str(harness_json) if harness_used else None,
            "classification_path": str(classification_json),
            "report_path": str(report_md),
            "replay_summary": args.replay_summary,
        }
    )
    classification = read_json(classification_json)
    site_map_data = read_json(site_map) if site_map.exists() else {}
    trace_data = read_json(trace_log_json) if trace_log_json.exists() else {}
    dangerous_ids = {
        str(site.get("site_id"))
        for site in site_map_data.get("dangerous_sites", [])
        if site.get("site_id") is not None
    }
    trace_times = first_trace_times(trace_data, dangerous_ids)
    reached = classification.get("reached_dangerous_sites") or []
    replay_stable = bool(classification.get("replay_stable", False))
    candidate_id = candidate_id_for_run(merged_meta, out_dir)
    score_breakdown = candidate_score_components(
        classification,
        reached_count=len(reached),
        replay_stable=replay_stable,
        duplicate_ordinal=1,
    )
    candidates_jsonl = out_dir / "candidates.jsonl"
    write_jsonl(
        candidates_jsonl,
        [
            {
                "schema_version": "0.1.0",
                "candidate_id": candidate_id,
                "suite": "generated_harness",
                "case": crate_root.name,
                "tool": effective_tool,
                "variant": effective_variant,
                "mode": "external-output",
                "seed": meta.get("seed"),
                "run_index": 1,
                "harness_id": meta.get("harness_id"),
                "input_id": meta.get("input_id"),
                "primary_label": classification.get("primary_label"),
                "relation": classification.get("relation"),
                "harness_status": classification.get("harness_status"),
                "oracle_verdict": classification.get("oracle_verdict"),
                "review_required": classification.get("review_required"),
                "confidence": classification.get("confidence"),
                "is_actionable": candidate_is_actionable(classification),
                "is_meaningful": candidate_is_meaningful(classification),
                "is_oracle_confirmed": candidate_is_oracle_confirmed(classification),
                "evidence_grade": candidate_evidence_grade(classification, replay_stable=replay_stable),
                "score": candidate_score(classification, reached_count=len(reached), replay_stable=replay_stable),
                "score_breakdown": score_breakdown,
                "reached_dangerous_sites": reached,
                "first_seen_time_ms": trace_times.get("dangerous_hit_time_ms") or trace_times.get("panic_time_ms") or trace_times.get("first_event_time_ms"),
                "dangerous_hit_time_ms": trace_times.get("dangerous_hit_time_ms"),
                "panic_time_ms": trace_times.get("panic_time_ms"),
                "run_dir": str(out_dir),
            }
        ],
    )
    merged_meta["candidates_path"] = str(candidates_jsonl)
    write_json(run_meta_json, merged_meta)
    print(f"[done] classification: {classification_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
