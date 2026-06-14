from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any

from common import safe_float, write_csv, write_json

FIELDNAMES = [
    "schedule_rank",
    "harness_id",
    "harness_path",
    "score",
    "strategy",
    "allocation_seconds",
    "allocation_fraction",
    "reason",
]


def read_scores(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    rows.sort(key=lambda row: (-safe_float(row.get("score")), str(row.get("harness_id"))))
    return rows


def _allocate_by_weights(rows: list[dict[str, Any]], weights: list[float], remaining: float) -> list[float]:
    total_weight = sum(weights)
    if not rows or remaining <= 0:
        return [0.0 for _ in rows]
    if total_weight <= 0:
        return [remaining / len(rows) for _ in rows]
    return [remaining * weight / total_weight for weight in weights]


def allocate(rows: list[dict[str, Any]], *, total_budget_seconds: float, min_per_harness_seconds: float, strategy: str, top_k: int, epsilon: float) -> list[dict[str, Any]]:
    n = len(rows)
    if n == 0:
        return []
    base = min_per_harness_seconds if total_budget_seconds >= min_per_harness_seconds * n else 0.0
    allocations = [base for _ in rows]
    remaining = max(total_budget_seconds - base * n, 0.0)

    scores = [max(safe_float(row.get("score")), 0.0) for row in rows]
    reasons = [strategy for _ in rows]

    if strategy == "uniform":
        extra = [remaining / n for _ in rows]
    elif strategy == "score-proportional":
        extra = _allocate_by_weights(rows, [score + 0.001 for score in scores], remaining)
    elif strategy == "top-k":
        k = min(max(top_k, 1), n)
        weights = [1.0 if idx < k else 0.0 for idx in range(n)]
        extra = _allocate_by_weights(rows, weights, remaining)
        reasons = ["top-k-selected" if idx < k else "min-only" for idx in range(n)]
    elif strategy == "epsilon-greedy":
        uniform_budget = remaining * max(0.0, min(epsilon, 1.0))
        score_budget = remaining - uniform_budget
        uniform = [uniform_budget / n for _ in rows]
        weighted = _allocate_by_weights(rows, [score + 0.001 for score in scores], score_budget)
        extra = [a + b for a, b in zip(uniform, weighted)]
    else:
        raise ValueError(f"unsupported strategy: {strategy}")

    result = []
    for idx, (row, add, reason) in enumerate(zip(rows, extra, reasons), start=1):
        seconds = allocations[idx - 1] + add
        result.append(
            {
                "schedule_rank": idx,
                "harness_id": row.get("harness_id"),
                "harness_path": row.get("harness_path"),
                "score": safe_float(row.get("score")),
                "strategy": strategy,
                "allocation_seconds": round(seconds, 3),
                "allocation_fraction": 0.0 if total_budget_seconds <= 0 else round(seconds / total_budget_seconds, 6),
                "reason": reason,
            }
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Allocate fuzzing budget across RustDPR-scored harnesses")
    parser.add_argument("--scores-csv", required=True)
    parser.add_argument("--strategy", choices=["uniform", "score-proportional", "top-k", "epsilon-greedy"], default="score-proportional")
    parser.add_argument("--total-budget-seconds", type=float, required=True)
    parser.add_argument("--min-per-harness-seconds", type=float, default=0.0)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--epsilon", type=float, default=0.1)
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--out-json", required=True)
    args = parser.parse_args()

    rows = read_scores(Path(args.scores_csv))
    schedule = allocate(
        rows,
        total_budget_seconds=args.total_budget_seconds,
        min_per_harness_seconds=args.min_per_harness_seconds,
        strategy=args.strategy,
        top_k=args.top_k,
        epsilon=args.epsilon,
    )
    write_csv(Path(args.out_csv), schedule, FIELDNAMES)
    write_json(
        Path(args.out_json),
        {
            "strategy": args.strategy,
            "total_budget_seconds": args.total_budget_seconds,
            "scheduled_harnesses": len(schedule),
            "allocated_seconds": sum(safe_float(row.get("allocation_seconds")) for row in schedule),
            "rows": schedule,
        },
    )
    print("[done] fuzz budget schedule")
    print(f"strategy           : {args.strategy}")
    print(f"scheduled harnesses: {len(schedule)}")
    print(f"csv                : {args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
