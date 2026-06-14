from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from common import (
    RUNS_DIR,
    SUITES,
    as_list,
    candidate_duplicate_key,
    candidate_evidence_grade,
    candidate_id_for_run,
    candidate_is_actionable,
    candidate_is_meaningful,
    candidate_is_oracle_confirmed,
    candidate_score,
    candidate_score_components,
    first_trace_times,
    load_optional_json,
    read_json,
    safe_float,
    safe_int,
    write_csv,
    write_json,
    write_jsonl,
)

DEFAULT_FIELDNAMES = [
    "rank",
    "candidate_id",
    "score",
    "evidence_grade",
    "is_actionable",
    "is_meaningful",
    "is_oracle_confirmed",
    "replay_stable",
    "suite",
    "case",
    "tool",
    "variant",
    "mode",
    "seed",
    "run_index",
    "harness_id",
    "input_id",
    "run_dir",
    "primary_label",
    "relation",
    "harness_status",
    "oracle_verdict",
    "review_required",
    "confidence",
    "reached_dangerous_sites",
    "distance_to_dangerous_site",
    "first_seen_time_ms",
    "dangerous_hit_time_ms",
    "panic_time_ms",
    "oracle_start_time_ms",
    "oracle_end_time_ms",
    "oracle_wall_sec",
    "oracle_cpu_sec",
    "duplicate_key",
    "duplicate_ordinal",
    "duplicate_cluster_size",
    "score_breakdown",
]


def _run_dirs_for_suite(suite: str, runs_dir: Path) -> list[Path]:
    suite_dir = runs_dir / suite
    if not suite_dir.exists():
        return []
    return sorted(path.parent for path in suite_dir.rglob("classification.json"))


def _dangerous_site_ids(site_map: dict[str, Any] | None) -> set[str]:
    if not site_map:
        return set()
    ids: set[str] = set()
    for site in site_map.get("dangerous_sites") or []:
        site_id = site.get("site_id")
        if site_id is not None:
            ids.add(str(site_id))
    return ids


def _oracle_timing(run_dir: Path, meta: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        run_dir / "oracle_queue_result.json",
        run_dir / "oracle_summary.json",
        run_dir / "oracle" / "oracle_summary.json",
        run_dir / "external_oracle_summary.json",
    ]
    result: dict[str, Any] = {}
    for path in candidates:
        obj = load_optional_json(path)
        if not obj:
            continue
        result.update(obj)
    result.setdefault("oracle_start_time_ms", meta.get("oracle_start_time_ms"))
    result.setdefault("oracle_end_time_ms", meta.get("oracle_end_time_ms"))
    result.setdefault("oracle_wall_sec", meta.get("oracle_wall_sec"))
    result.setdefault("oracle_cpu_sec", meta.get("oracle_cpu_sec"))
    return result


def _replay_stable(run_dir: Path, classification: dict[str, Any]) -> bool:
    if "replay_stable" in classification:
        return bool(classification.get("replay_stable"))
    for name in ["replay_summary.json", "oracle_queue_result.json", "external_oracle_summary.json"]:
        obj = load_optional_json(run_dir / name)
        if obj and (obj.get("replay_stable") or obj.get("stable")):
            return True
    return False


def candidate_from_run_dir(run_dir: Path) -> dict[str, Any]:
    classification_path = run_dir / "classification.json"
    meta_path = run_dir / "run_meta.json"
    if not classification_path.exists() or not meta_path.exists():
        raise RuntimeError(f"run directory is missing classification/run_meta: {run_dir}")

    classification = read_json(classification_path)
    meta = read_json(meta_path)
    suite = str(meta.get("suite") or "unknown")
    case = str(meta.get("case") or meta.get("crate") or "unknown")

    site_map = load_optional_json(run_dir / "site_map.json")
    trace = load_optional_json(run_dir / "trace_log.json")
    dangerous_ids = _dangerous_site_ids(site_map)
    times = first_trace_times(trace, dangerous_ids)

    reached = as_list(classification.get("reached_dangerous_sites"))
    replay_stable = _replay_stable(run_dir, classification)
    oracle_timing = _oracle_timing(run_dir, meta)
    duplicate_key = candidate_duplicate_key(classification, meta)

    candidate_id = candidate_id_for_run(meta, run_dir)
    input_id = meta.get("input_id") or classification.get("input_id") or meta.get("replay_input")
    score_breakdown = candidate_score_components(
        classification,
        reached_count=len(reached),
        replay_stable=replay_stable,
        duplicate_ordinal=1,
    )

    return {
        "candidate_id": candidate_id,
        "score": sum(score_breakdown.values()),
        "evidence_grade": candidate_evidence_grade(classification, replay_stable=replay_stable),
        "is_actionable": candidate_is_actionable(classification),
        "is_meaningful": candidate_is_meaningful(classification),
        "is_oracle_confirmed": candidate_is_oracle_confirmed(classification),
        "replay_stable": replay_stable,
        "suite": suite,
        "case": case,
        "tool": meta.get("tool"),
        "variant": meta.get("variant"),
        "mode": meta.get("mode", "deterministic"),
        "seed": meta.get("seed"),
        "run_index": meta.get("run_index"),
        "harness_id": meta.get("harness_id"),
        "input_id": input_id,
        "run_dir": str(run_dir),
        "primary_label": classification.get("primary_label"),
        "relation": classification.get("relation"),
        "harness_status": classification.get("harness_status"),
        "oracle_verdict": classification.get("oracle_verdict"),
        "review_required": bool(classification.get("review_required")),
        "confidence": safe_float(classification.get("confidence"), 0.0),
        "reached_dangerous_sites": len(reached),
        "distance_to_dangerous_site": classification.get("distance_to_dangerous_site"),
        "first_seen_time_ms": times.get("dangerous_hit_time_ms") or times.get("panic_time_ms") or times.get("first_event_time_ms"),
        "dangerous_hit_time_ms": times.get("dangerous_hit_time_ms"),
        "panic_time_ms": times.get("panic_time_ms"),
        "oracle_start_time_ms": oracle_timing.get("oracle_start_time_ms"),
        "oracle_end_time_ms": oracle_timing.get("oracle_end_time_ms"),
        "oracle_wall_sec": safe_float(oracle_timing.get("oracle_wall_sec"), 0.0),
        "oracle_cpu_sec": safe_float(oracle_timing.get("oracle_cpu_sec"), 0.0),
        "duplicate_key": duplicate_key,
        "duplicate_ordinal": 1,
        "duplicate_cluster_size": 1,
        "score_breakdown": score_breakdown,
        "_classification": classification,
    }


def apply_duplicate_penalties(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cluster_size: dict[str, int] = defaultdict(int)
    for row in rows:
        cluster_size[row["duplicate_key"]] += 1

    ordinal: dict[str, int] = defaultdict(int)
    rows_by_time = sorted(
        rows,
        key=lambda r: (
            safe_int(r.get("first_seen_time_ms"), 10**18),
            str(r.get("candidate_id")),
        ),
    )
    by_candidate = {row["candidate_id"]: row for row in rows}
    for row in rows_by_time:
        key = row["duplicate_key"]
        ordinal[key] += 1
        target = by_candidate[row["candidate_id"]]
        target["duplicate_ordinal"] = ordinal[key]
        target["duplicate_cluster_size"] = cluster_size[key]
        classification = target.pop("_classification")
        breakdown = candidate_score_components(
            classification,
            reached_count=safe_int(target.get("reached_dangerous_sites")),
            replay_stable=bool(target.get("replay_stable")),
            duplicate_ordinal=ordinal[key],
        )
        target["score_breakdown"] = breakdown
        target["score"] = candidate_score(
            classification,
            reached_count=safe_int(target.get("reached_dangerous_sites")),
            replay_stable=bool(target.get("replay_stable")),
            duplicate_ordinal=ordinal[key],
        )
    return rows


def rank_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = apply_duplicate_penalties(rows)
    rows = sorted(
        rows,
        key=lambda r: (
            -safe_float(r.get("score")),
            safe_int(r.get("first_seen_time_ms"), 10**18),
            str(r.get("candidate_id")),
        ),
    )
    for idx, row in enumerate(rows, start=1):
        row["rank"] = idx
        if isinstance(row.get("score_breakdown"), dict):
            row["score_breakdown"] = json.dumps(row["score_breakdown"], sort_keys=True)
    return rows


def load_candidates(args: argparse.Namespace) -> list[dict[str, Any]]:
    suites = args.suite or list(SUITES)
    rows: list[dict[str, Any]] = []
    for suite in suites:
        for run_dir in _run_dirs_for_suite(suite, Path(args.runs_dir)):
            row = candidate_from_run_dir(run_dir)
            if args.exclude_noise and not (row["is_actionable"] or row["is_meaningful"] or row["is_oracle_confirmed"]):
                continue
            rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Rank RustDPR candidates for review/oracle scheduling")
    parser.add_argument("--suite", action="append", choices=SUITES, help="suite to scan; may be repeated; default scans all suites")
    parser.add_argument("--runs-dir", default=str(RUNS_DIR), help="root data/runs directory")
    parser.add_argument("--exclude-noise", action="store_true", help="drop obvious noise before ranking")
    parser.add_argument("--min-score", type=float, default=None)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--out-jsonl", default=None)
    parser.add_argument("--out-json", default=None)
    args = parser.parse_args()

    rows = rank_rows(load_candidates(args))
    if args.min_score is not None:
        rows = [row for row in rows if safe_float(row.get("score")) >= args.min_score]
        for idx, row in enumerate(rows, start=1):
            row["rank"] = idx

    serializable_rows = [{k: v for k, v in row.items() if not k.startswith("_")} for row in rows]
    write_csv(Path(args.out_csv), serializable_rows, DEFAULT_FIELDNAMES)
    if args.out_jsonl:
        write_jsonl(Path(args.out_jsonl), serializable_rows)
    if args.out_json:
        write_json(Path(args.out_json), {"total_candidates": len(serializable_rows), "rows": serializable_rows})

    confirmed_top10 = sum(1 for row in serializable_rows[:10] if row.get("is_oracle_confirmed"))
    actionable_top10 = sum(1 for row in serializable_rows[:10] if row.get("is_actionable"))
    print("[done] ranked candidates")
    print(f"total candidates     : {len(serializable_rows)}")
    print(f"top-10 actionable    : {actionable_top10}")
    print(f"top-10 oracle-confirmed: {confirmed_top10}")
    print(f"csv                  : {args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
