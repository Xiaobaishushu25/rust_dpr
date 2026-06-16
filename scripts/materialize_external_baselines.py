from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Any

from common import RUNS_DIR, read_json, write_json

CONFIRMED_ORACLES = {
    "AddressSanitizerDoubleFree",
    "AddressSanitizerUseAfterFree",
    "AddressSanitizerOutOfBounds",
    "AddressSanitizerInvalidFree",
    "AddressSanitizerLeak",
    "MiriUndefinedBehavior",
}


def raw_count(meta: dict[str, Any], key: str) -> int:
    value = meta.get(key, 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def has_crash_like_output(meta: dict[str, Any]) -> bool:
    return (
        raw_count(meta, "raw_crash_count") > 0
        or raw_count(meta, "raw_panic_count") > 0
        or bool(meta.get("crash_inputs"))
        or (meta.get("return_code") not in {None, 0, "0"})
    )


def baseline_classification(kind: str, source_cls: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    suite = meta.get("suite", "generated_harness")
    case = meta.get("case") or meta.get("crate")

    if kind == "crash-only":
        hit = has_crash_like_output(meta)
        return {
            "schema_version": source_cls.get("schema_version", "0.2.0"),
            "case_name": case,
            "suite": suite,
            "primary_label": "SuspiciousCandidate" if hit else "Noise",
            "relation": "Unknown" if hit else "NoneObserved",
            "reached_dangerous_sites": [],
            "nearest_dangerous_site": None,
            "distance_to_dangerous_site": None,
            "oracle_verdict": "Unknown",
            "oracle_evidence_strength": "Unknown",
            "target_api_misuse": False,
            "harness_status": "Unknown",
            "confidence": 0.55 if hit else 0.40,
            "review_required": bool(hit),
            "notes": {
                "notes": [],
                "fired_rules": ["external-crash-only-baseline"],
                "conflicting_evidence": [],
                "counters": {
                    "raw_crash_count": raw_count(meta, "raw_crash_count"),
                    "raw_panic_count": raw_count(meta, "raw_panic_count"),
                    "crash_inputs": len(meta.get("crash_inputs") or []),
                },
                "evidence_summary": [
                    "Native generated-harness baseline reports candidates using only raw panic/crash/output-artifact signals."
                ],
                "decision_path": [
                    f"raw_crash_count={raw_count(meta, 'raw_crash_count')}",
                    f"raw_panic_count={raw_count(meta, 'raw_panic_count')}",
                    f"return_code={meta.get('return_code')}",
                ],
            },
        }

    if kind == "panic-only":
        hit = raw_count(meta, "raw_panic_count") > 0 or has_crash_like_output(meta)
        return {
            "schema_version": source_cls.get("schema_version", "0.2.0"),
            "case_name": case,
            "suite": suite,
            "primary_label": "SuspiciousCandidate" if hit else "Noise",
            "relation": "Unknown" if hit else "NoneObserved",
            "reached_dangerous_sites": [],
            "nearest_dangerous_site": None,
            "distance_to_dangerous_site": None,
            "oracle_verdict": "Unknown",
            "oracle_evidence_strength": "Unknown",
            "target_api_misuse": False,
            "harness_status": "Unknown",
            "confidence": 0.50 if hit else 0.40,
            "review_required": bool(hit),
            "notes": {
                "notes": [],
                "fired_rules": ["external-panic-only-baseline"],
                "conflicting_evidence": [],
                "counters": {"raw_panic_count": raw_count(meta, "raw_panic_count")},
                "evidence_summary": ["Native panic-only baseline reports any panic-like output as a candidate."],
                "decision_path": [f"raw_panic_count={raw_count(meta, 'raw_panic_count')}"],
            },
        }

    if kind == "oracle-only":
        verdict = source_cls.get("oracle_verdict", "Unknown")
        confirmed = verdict in CONFIRMED_ORACLES
        return {
            "schema_version": source_cls.get("schema_version", "0.2.0"),
            "case_name": case,
            "suite": suite,
            "primary_label": "OracleConfirmedBug" if confirmed else "Noise",
            "relation": "Unknown" if confirmed else "NoneObserved",
            "reached_dangerous_sites": [],
            "nearest_dangerous_site": None,
            "distance_to_dangerous_site": None,
            "oracle_verdict": verdict,
            "oracle_evidence_strength": "Confirmed" if confirmed else "Unknown",
            "target_api_misuse": False,
            "harness_status": "Unknown",
            "confidence": 0.95 if confirmed else 0.45,
            "review_required": False if confirmed else bool(verdict in {"Unknown", "MiriUnsupported", "OracleTimeout", "OracleBuildFailure"}),
            "notes": {
                "notes": [],
                "fired_rules": ["external-oracle-only-baseline"],
                "conflicting_evidence": [],
                "counters": {},
                "evidence_summary": ["Oracle-only baseline ignores DPG, trace, and harness-validity evidence."],
                "decision_path": [f"oracle_verdict={verdict}"],
            },
        }

    raise ValueError(f"unsupported baseline: {kind}")


def iter_source_runs(suite: str, tool: str, variant: str | None) -> list[Path]:
    suite_dir = RUNS_DIR / suite
    if not suite_dir.exists():
        return []
    out: list[Path] = []
    for meta_path in sorted(suite_dir.rglob("run_meta.json")):
        meta = read_json(meta_path)
        if meta.get("tool") != tool:
            continue
        if variant and meta.get("variant") != variant:
            continue
        out.append(meta_path.parent)
    return out


def materialize(source_dir: Path, baseline: str, out_variant: str) -> Path:
    meta = read_json(source_dir / "run_meta.json")
    source_cls = read_json(source_dir / "classification.json")
    suite = meta.get("suite", "generated_harness")
    case = meta.get("case") or meta.get("crate") or source_dir.name
    tool = meta.get("tool", "rulf")
    seed = meta.get("seed", 0)
    run_index = meta.get("run_index", 1)
    out_dir = RUNS_DIR / suite / str(case) / str(tool) / out_variant / f"seed-{seed}" / f"run-{run_index}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Reuse artifacts that do not encode the classifier decision. Copying keeps compute_metrics features such as wDPC available.
    for name in ["site_map.json", "dpg.json", "trace_log.json", "trace.json", "harness_validity.json", "replay_summary.json"]:
        src = source_dir / name
        if src.exists():
            shutil.copy2(src, out_dir / name)

    new_meta = dict(meta)
    new_meta.update(
        {
            "tool": tool,
            "variant": out_variant,
            "mode": f"external-{baseline}-baseline",
            "source_run_dir": str(source_dir),
            "baseline_materialized_from": str(source_dir),
            "classification_path": str(out_dir / "classification.json"),
            "out_dir": str(out_dir),
        }
    )
    write_json(out_dir / "run_meta.json", new_meta)
    write_json(out_dir / "classification.json", baseline_classification(baseline, source_cls, meta))
    return out_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Create native external-tool baseline run groups from existing RustDPR external-output runs.")
    parser.add_argument("--suite", default="generated_harness")
    parser.add_argument("--source-tool", default="rulf")
    parser.add_argument("--source-variant", default=None, help="Filter source variant, e.g. full. Omit to use all variants for the tool.")
    parser.add_argument("--baseline", choices=["crash-only", "panic-only", "oracle-only"], default="crash-only")
    parser.add_argument("--out-variant", default=None, help="Metric variant name to create. Defaults to --baseline.")
    args = parser.parse_args()

    source_runs = iter_source_runs(args.suite, args.source_tool, args.source_variant)
    if not source_runs:
        print(
            "[error] no source runs found. Expected run_meta.json under "
            f"{RUNS_DIR / args.suite} with tool={args.source_tool!r}"
            + (f" and variant={args.source_variant!r}" if args.source_variant else "")
        )
        return 2

    out_variant = args.out_variant or args.baseline
    created = [materialize(run_dir, args.baseline, out_variant) for run_dir in source_runs]
    print(f"[done] created {len(created)} {args.source_tool}/{out_variant} baseline runs")
    for path in created[:10]:
        print(path)
    if len(created) > 10:
        print(f"... {len(created)-10} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
