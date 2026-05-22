from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common import RUNS_DIR, SUITES, read_json, run_cmd, write_json


def run_oracle_for_case(case: str, suite: str, oracle: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    log = out_dir / f"{oracle}.log"
    if oracle == "asan":
        cmd = [sys.executable, "scripts/run_asan.py", case, "--suite", suite, "--out-dir", str(out_dir)]
    elif oracle == "miri":
        cmd = [sys.executable, "scripts/run_miri.py", case, "--suite", suite, "--out-dir", str(out_dir)]
    else:
        raise ValueError(f"unknown oracle: {oracle}")
    run_cmd(cmd, check=False)
    return log


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--oracle", choices=["asan", "miri", "both"], default="both")
    parser.add_argument("--only-candidates", action="store_true")
    args = parser.parse_args()

    suite_dir = RUNS_DIR / args.suite
    if not suite_dir.exists():
        raise SystemExit(f"no runs found for suite: {args.suite}")

    oracles = ["asan", "miri"] if args.oracle == "both" else [args.oracle]
    rows = []

    for classification_path in sorted(suite_dir.rglob("classification.json")):
        run_dir = classification_path.parent
        classification = read_json(classification_path)
        meta_path = run_dir / "run_meta.json"
        if not meta_path.exists():
            raise RuntimeError(f"run_meta.json not found for run: {run_dir}")
        meta = read_json(meta_path)
        case = meta["case"]
        if args.only_candidates and classification.get("primary_label") in {"Noise", "ContractPanic", "BlockingPanic"}:
            continue

        oracle_dir = run_dir / "oracle"
        for oracle in oracles:
            log = run_oracle_for_case(case, args.suite, oracle, oracle_dir)
            rows.append({"case": case, "run_dir": str(run_dir), "oracle": oracle, "log": str(log)})

    write_json(Path("reports") / f"oracle_runs_{args.suite}.json", {"rows": rows})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
