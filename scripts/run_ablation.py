from __future__ import annotations

import argparse
import sys

from common import SUITES, discover_cases, run_cmd

ABLATIONS = {
    "full": [],
    "no-trace": ["--no-trace"],
    "no-dpg": ["--no-dpg"],
    "no-harness": ["--skip-harness", "--no-harness-validity"],
    "no-oracle": ["--no-oracle"],
    "panic-only": ["--panic-only"],
    "static-only": ["--static-only"],
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--seeds", default="1")
    parser.add_argument("--mode", choices=["deterministic", "fuzz"], default="deterministic")
    parser.add_argument("--budget-seconds", type=int, default=0)
    parser.add_argument("--fuzz-target", default="fuzz_target_1")
    parser.add_argument("--fuzz-runs", type=int, default=64)
    parser.add_argument("--variants", default=",".join(ABLATIONS.keys()))
    args = parser.parse_args()

    variants = [v.strip() for v in args.variants.split(",") if v.strip()]
    seeds = [int(x.strip()) for x in args.seeds.split(",") if x.strip()]

    failures = 0
    for variant in variants:
        if variant not in ABLATIONS:
            raise SystemExit(f"unknown ablation variant: {variant}")
        extra = ABLATIONS[variant]
        for case_dir in discover_cases(args.suite):
            for seed in seeds:
                for run_idx in range(args.repeat):
                    cmd = [
                        sys.executable,
                        "scripts/run_case.py",
                        case_dir.name,
                        "--suite",
                        args.suite,
                        "--tool",
                        "rustdpr",
                        "--variant",
                        variant,
                        "--mode",
                        args.mode,
                        "--budget-seconds",
                        str(args.budget_seconds),
                        "--fuzz-target",
                        args.fuzz_target,
                        "--fuzz-runs",
                        str(args.fuzz_runs),
                        "--seed",
                        str(seed),
                        "--run-index",
                        str(run_idx + 1),
                    ]
                    cmd.extend(extra)
                    rc = run_cmd(cmd, check=False)
                    if rc != 0:
                        failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
