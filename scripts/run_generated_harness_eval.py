from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from common import RUNS_DIR, safe_float, write_json
from schedule_fuzz_budget import allocate
from score_harnesses import FIELDNAMES as SCORE_FIELDNAMES
from score_harnesses import discover_harnesses, index_runs, score_harness
from common import write_csv


def summarize_scores(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    compile_ok = [row for row in rows if str(row.get("compile_status")).lower() in {"ok", "success", "passed"}]
    valid = [row for row in rows if row.get("harness_status") in {"ConfirmedValid", "LikelyValid"}]
    misuse = [row for row in rows if row.get("harness_status") in {"LikelyMisuse", "Invalid"} or safe_float(row.get("short_run_harness_misuse_count")) > 0]
    dangerous_hits = [row for row in rows if safe_float(row.get("short_run_dangerous_hits")) > 0]
    oracle_confirmed = [row for row in rows if row.get("oracle_verdict") in {"AddressSanitizerDoubleFree", "AddressSanitizerUseAfterFree", "AddressSanitizerOutOfBounds", "AddressSanitizerInvalidFree", "AddressSanitizerLeak", "MiriUndefinedBehavior"}]
    return {
        "total_harnesses": total,
        "compile_ok": len(compile_ok),
        "compile_rate": 0.0 if total == 0 else len(compile_ok) / total,
        "valid_harnesses": len(valid),
        "valid_harness_rate": 0.0 if total == 0 else len(valid) / total,
        "misuse_harnesses": len(misuse),
        "harness_misuse_rate": 0.0 if total == 0 else len(misuse) / total,
        "dangerous_hit_harnesses": len(dangerous_hits),
        "dangerous_hit_rate": 0.0 if total == 0 else len(dangerous_hits) / total,
        "oracle_confirmed_harnesses": len(oracle_confirmed),
        "oracle_confirmed_rate": 0.0 if total == 0 else len(oracle_confirmed) / total,
        "mean_score": 0.0 if total == 0 else sum(safe_float(row.get("score")) for row in rows) / total,
    }


def write_summary_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Generated Harness Evaluation Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for key, value in summary.items():
        if isinstance(value, float):
            display = f"{value:.4f}"
        else:
            display = str(value)
        lines.append(f"| {key} | {display} |")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate generated-harness quality, ranking, and budget scheduling")
    parser.add_argument("--harness-dir", required=True)
    parser.add_argument("--runs-dir", default=str(RUNS_DIR))
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--strategy", choices=["uniform", "score-proportional", "top-k", "epsilon-greedy"], default="score-proportional")
    parser.add_argument("--total-budget-seconds", type=float, default=3600.0)
    parser.add_argument("--min-per-harness-seconds", type=float, default=0.0)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--epsilon", type=float, default=0.1)
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    harness_root = Path(args.harness_dir)
    root_for_ids = harness_root if harness_root.is_dir() else harness_root.parent
    run_index = index_runs(Path(args.runs_dir))
    harnesses = discover_harnesses(harness_root)
    scores = [score_harness(path, root_for_ids, run_index) for path in harnesses]
    scores.sort(key=lambda row: (-safe_float(row.get("score")), row["harness_id"]))
    for idx, row in enumerate(scores, start=1):
        row["rank"] = idx

    schedule = allocate(
        scores,
        total_budget_seconds=args.total_budget_seconds,
        min_per_harness_seconds=args.min_per_harness_seconds,
        strategy=args.strategy,
        top_k=args.top_k,
        epsilon=args.epsilon,
    )
    summary = summarize_scores(scores)
    summary.update(
        {
            "harness_dir": str(harness_root),
            "strategy": args.strategy,
            "total_budget_seconds": args.total_budget_seconds,
            "scheduled_harnesses": len(schedule),
            "allocated_seconds": sum(safe_float(row.get("allocation_seconds")) for row in schedule),
        }
    )

    write_csv(out_dir / "generated_harness_scores.csv", scores, SCORE_FIELDNAMES)
    write_json(out_dir / "generated_harness_scores.json", {"rows": scores})
    write_csv(
        out_dir / "generated_harness_schedule.csv",
        schedule,
        ["schedule_rank", "harness_id", "harness_path", "score", "strategy", "allocation_seconds", "allocation_fraction", "reason"],
    )
    write_json(out_dir / "generated_harness_eval_summary.json", summary)
    write_summary_markdown(out_dir / "generated_harness_eval_summary.md", summary)

    print("[done] generated harness eval")
    print(f"harnesses       : {len(scores)}")
    print(f"valid rate      : {summary['valid_harness_rate']:.4f}")
    print(f"misuse rate     : {summary['harness_misuse_rate']:.4f}")
    print(f"out dir         : {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
