from __future__ import annotations

import argparse
import sys

from common import SUITES, run_cmd

BASELINES = {
    "crash-only": {"tool": "cargo-fuzz", "variant": "crash-only"},
    "panic-only": {"tool": "rustdpr", "variant": "panic-only"},
    "static-only": {"tool": "rustdpr", "variant": "static-only"},
    "coverage-only": {"tool": "coverage-only", "variant": "coverage-only"},
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
    parser.add_argument("--mode", choices=["deterministic", "fuzz"], default=None)
    parser.add_argument("--fuzz-target", default="fuzz_target_1")
    parser.add_argument("--fuzz-runs", type=int, default=64)
    parser.add_argument("--include-deps", action="store_true")
    parser.add_argument("--dep-crates", default="")
    parser.add_argument("--instrument-deps", action="store_true")
    parser.add_argument("--coverage-threshold", type=float, default=1.0)
    args = parser.parse_args()

    spec = BASELINES[args.baseline]
    mode = args.mode or ("fuzz" if args.baseline == "crash-only" else "deterministic")
    cmd = [
        sys.executable,
        "scripts/run_case.py",
        args.case,
        "--suite",
        args.suite,
        "--mode",
        mode,
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
        "--fuzz-target",
        args.fuzz_target,
        "--fuzz-runs",
        str(args.fuzz_runs),
    ]

    if args.include_deps:
        cmd.append("--include-deps")
    if args.dep_crates:
        cmd.extend(["--dep-crates", args.dep_crates])
    if args.instrument_deps:
        cmd.append("--instrument-deps")

    if args.baseline == "panic-only":
        cmd.append("--panic-only")
    elif args.baseline == "static-only":
        cmd.append("--static-only")
    elif args.baseline == "crash-only":
        cmd.append("--crash-only")
    elif args.baseline == "coverage-only":
        cmd.extend(["--coverage-only", "--coverage-threshold", str(args.coverage_threshold)])
    elif args.baseline == "asan-only":
        cmd.extend(["--oracle-only", "asan"])
    elif args.baseline == "miri-only":
        cmd.extend(["--oracle-only", "miri"])

    return run_cmd(cmd, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
