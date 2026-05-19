from __future__ import annotations

import argparse
import sys

from common import SUITES, run_cmd

BASELINES = {
    "crash-only": {"tool": "cargo-fuzz", "variant": "crash-only"},
    "panic-only": {"tool": "rustdpr", "variant": "panic-only"},
    "static-only": {"tool": "rustdpr", "variant": "static-only"},
    "asan-only": {"tool": "asan-only", "variant": "oracle-only"},
    "miri-only": {"tool": "miri-only", "variant": "oracle-only"},
    "fourfuzz-approx": {"tool": "fourfuzz-approx", "variant": "unsafe-targeted"},
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", choices=BASELINES.keys())
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--run-index", type=int, default=1)
    parser.add_argument("--budget-seconds", type=int, default=0)
    args = parser.parse_args()

    spec = BASELINES[args.baseline]
    cmd = [
        sys.executable,
        "scripts/run_case.py",
        args.case,
        "--suite",
        args.suite,
        "--tool",
        spec["tool"],
        "--variant",
        spec["variant"],
        "--seed",
        str(args.seed),
        "--run-index",
        str(args.run_index),
        "--budget-seconds",
        str(args.budget_seconds),
    ]

    if args.baseline == "panic-only":
        cmd.append("--panic-only")
    elif args.baseline == "static-only":
        cmd.append("--static-only")
    elif args.baseline in {"asan-only", "miri-only"}:
        cmd.append("--no-oracle")

    return run_cmd(cmd, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
