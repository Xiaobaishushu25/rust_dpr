from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path
from typing import Any

from common import (
    CONFIRMED_ORACLE_VERDICTS,
    parse_oracle_log_file,
    read_json,
    run_cmd,
    safe_float,
    safe_int,
    select_oracle_verdict,
    write_csv,
    write_json,
)

FIELDNAMES = [
    "queue_index",
    "rank",
    "candidate_id",
    "suite",
    "case",
    "tool",
    "variant",
    "run_dir",
    "executed",
    "skipped_reason",
    "oracles_run",
    "final_oracle_verdict",
    "oracle_confirmed",
    "oracle_wall_sec",
    "oracle_cpu_sec",
    "queue_elapsed_sec",
    "logs",
]


def _csv_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def load_ranked(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    return sorted(rows, key=lambda r: safe_int(r.get("rank"), 10**9))


def _run_meta_for_row(row: dict[str, Any]) -> dict[str, Any]:
    run_dir = Path(str(row.get("run_dir") or ""))
    meta_path = run_dir / "run_meta.json"
    if meta_path.exists():
        return read_json(meta_path)
    return {}


def oracle_cmd(row: dict[str, Any], oracle: str, log_path: Path) -> list[str]:
    meta = _run_meta_for_row(row)
    case_dir = meta.get("case_dir") or meta.get("crate_root")
    replay_input = row.get("input_id") or meta.get("replay_input")
    if case_dir and Path(case_dir).exists():
        cmd = [
            sys.executable,
            f"scripts/run_{oracle}.py",
            "--case-dir",
            str(case_dir),
            "--suite",
            str(row.get("suite") or meta.get("suite") or "generated_harness"),
            "--out-log",
            str(log_path),
        ]
    else:
        cmd = [
            sys.executable,
            f"scripts/run_{oracle}.py",
            str(row.get("case") or meta.get("case")),
            "--suite",
            str(row.get("suite") or meta.get("suite")),
            "--out-log",
            str(log_path),
        ]
    if replay_input:
        cmd.extend(["--replay-input", str(replay_input)])
    return cmd


def run_oracles_for_candidate(row: dict[str, Any], oracles: list[str], execute: bool) -> dict[str, Any]:
    run_dir = Path(str(row.get("run_dir") or "."))
    out_dir = run_dir / "oracle_queue"
    out_dir.mkdir(parents=True, exist_ok=True)

    oracle_rows = []
    start = time.monotonic()
    logs = []
    if not execute:
        existing_verdict = str(row.get("oracle_verdict") or "Unknown")
        return {
            "executed": False,
            "skipped_reason": "plan-only",
            "oracles_run": 0,
            "final_oracle_verdict": existing_verdict,
            "oracle_confirmed": existing_verdict in CONFIRMED_ORACLE_VERDICTS,
            "oracle_wall_sec": 0.0,
            "oracle_cpu_sec": safe_float(row.get("oracle_cpu_sec"), 0.0),
            "logs": [],
        }

    for oracle in oracles:
        log_path = out_dir / f"{oracle}.log"
        cmd = oracle_cmd(row, oracle, log_path)
        run_cmd(cmd, check=False)
        verdict = parse_oracle_log_file(log_path, oracle)
        oracle_rows.append({"oracle": oracle, "verdict": verdict, "log": str(log_path)})
        logs.append(str(log_path))

    wall = time.monotonic() - start
    final_verdict = select_oracle_verdict(oracle_rows)
    result = {
        "candidate_id": row.get("candidate_id"),
        "rank": safe_int(row.get("rank")),
        "oracle_rows": oracle_rows,
        "oracle_start_time_ms": int(start * 1000),
        "oracle_end_time_ms": int(time.monotonic() * 1000),
        "oracle_wall_sec": wall,
        "oracle_cpu_sec": wall,
        "final_oracle_verdict": final_verdict,
        "oracle_confirmed": final_verdict in CONFIRMED_ORACLE_VERDICTS,
    }
    write_json(out_dir / "oracle_queue_result.json", result)
    return {
        "executed": True,
        "skipped_reason": "",
        "oracles_run": len(oracles),
        "final_oracle_verdict": final_verdict,
        "oracle_confirmed": final_verdict in CONFIRMED_ORACLE_VERDICTS,
        "oracle_wall_sec": wall,
        "oracle_cpu_sec": wall,
        "logs": logs,
    }


def summarize(rows: list[dict[str, Any]], *, budget_minutes: float | None) -> dict[str, Any]:
    confirmed = [row for row in rows if row.get("oracle_confirmed")]
    oracle_runs = sum(safe_int(row.get("oracles_run")) for row in rows)
    cpu_sec = sum(safe_float(row.get("oracle_cpu_sec")) for row in rows)
    t_first_confirmed = None
    for row in rows:
        if row.get("oracle_confirmed"):
            t_first_confirmed = safe_float(row.get("queue_elapsed_sec"), 0.0)
            break
    def confirmed_at(k: int) -> int:
        return sum(1 for row in rows[:k] if row.get("oracle_confirmed"))
    return {
        "budget_minutes": budget_minutes,
        "queue_candidates": len(rows),
        "oracle_runs": oracle_runs,
        "oracle_confirmed": len(confirmed),
        "oracle_confirmed_at_1": confirmed_at(1),
        "oracle_confirmed_at_5": confirmed_at(5),
        "oracle_confirmed_at_10": confirmed_at(10),
        "ttoc_queue_sec": t_first_confirmed,
        "oracle_cpu_sec": cpu_sec,
        "obe": 0.0 if oracle_runs == 0 else len(confirmed) / oracle_runs,
        "obe_per_cpu_minute": 0.0 if cpu_sec <= 0 else len(confirmed) / (cpu_sec / 60.0),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run or plan an oracle queue using RustDPR candidate ranking")
    parser.add_argument("--ranked-csv", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--max-candidates", type=int, default=20)
    parser.add_argument("--budget-minutes", type=float, default=None)
    parser.add_argument("--oracle", choices=["asan", "miri", "both"], default="both")
    parser.add_argument("--execute", action="store_true", help="actually run ASan/Miri; default only writes a plan/evaluation over existing verdicts")
    parser.add_argument("--skip-confirmed", action="store_true", help="skip candidates that already have a confirmed oracle verdict")
    args = parser.parse_args()

    oracles = ["asan", "miri"] if args.oracle == "both" else [args.oracle]
    ranked = load_ranked(Path(args.ranked_csv))[: args.max_candidates]
    budget_sec = None if args.budget_minutes is None else args.budget_minutes * 60.0

    queue_rows: list[dict[str, Any]] = []
    queue_start = time.monotonic()
    for idx, row in enumerate(ranked, start=1):
        elapsed = time.monotonic() - queue_start
        if budget_sec is not None and elapsed >= budget_sec:
            break
        existing_confirmed = str(row.get("oracle_verdict") or "Unknown") in CONFIRMED_ORACLE_VERDICTS
        if args.skip_confirmed and existing_confirmed:
            outcome = {
                "executed": False,
                "skipped_reason": "already-confirmed",
                "oracles_run": 0,
                "final_oracle_verdict": row.get("oracle_verdict"),
                "oracle_confirmed": True,
                "oracle_wall_sec": 0.0,
                "oracle_cpu_sec": 0.0,
                "logs": [],
            }
        else:
            outcome = run_oracles_for_candidate(row, oracles, args.execute)
        queue_rows.append(
            {
                "queue_index": idx,
                "rank": safe_int(row.get("rank")),
                "candidate_id": row.get("candidate_id"),
                "suite": row.get("suite"),
                "case": row.get("case"),
                "tool": row.get("tool"),
                "variant": row.get("variant"),
                "run_dir": row.get("run_dir"),
                "executed": outcome["executed"],
                "skipped_reason": outcome["skipped_reason"],
                "oracles_run": outcome["oracles_run"],
                "final_oracle_verdict": outcome["final_oracle_verdict"],
                "oracle_confirmed": bool(outcome["oracle_confirmed"]),
                "oracle_wall_sec": outcome["oracle_wall_sec"],
                "oracle_cpu_sec": outcome["oracle_cpu_sec"],
                "queue_elapsed_sec": time.monotonic() - queue_start,
                "logs": ";".join(outcome["logs"]),
            }
        )

    summary = summarize(queue_rows, budget_minutes=args.budget_minutes)
    write_csv(Path(args.out_csv), queue_rows, FIELDNAMES)
    write_json(Path(args.out_json), {"summary": summary, "rows": queue_rows})
    print("[done] oracle queue")
    print(f"execute              : {args.execute}")
    print(f"queue candidates     : {summary['queue_candidates']}")
    print(f"oracle-confirmed@10  : {summary['oracle_confirmed_at_10']}")
    print(f"TTOC queue sec       : {summary['ttoc_queue_sec']}")
    print(f"OBE                  : {summary['obe']:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
