from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = ROOT_DIR / "benchmarks"


def discover_cases(suite: str) -> list[Path]:
    suite_dir = BENCHMARKS_DIR / suite
    if not suite_dir.exists():
        raise FileNotFoundError(f"suite directory not found: {suite_dir}")
    return sorted([p for p in suite_dir.iterdir() if p.is_dir()])


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all cases in a benchmark suite")
    parser.add_argument("suite", choices=["micro", "oracle", "taxonomy"])
    parser.add_argument("--asan-log-dir", default=None, help="directory containing per-case ASan logs")
    parser.add_argument("--miri-log-dir", default=None, help="directory containing per-case Miri logs")
    parser.add_argument("--skip-harness", action="store_true")
    args = parser.parse_args()

    case_dirs = discover_cases(args.suite)
    failed: list[str] = []

    for case_dir in case_dirs:
        case_name = case_dir.name
        print("=" * 80)
        print(f"running suite={args.suite} case={case_name}")
        print("=" * 80)

        cmd = [
            sys.executable,
            str(ROOT_DIR / "scripts" / "run_case.py"),
            case_name,
            "--suite",
            args.suite,
        ]

        if args.skip_harness:
            cmd.append("--skip-harness")

        if args.asan_log_dir:
            asan_log = Path(args.asan_log_dir) / case_name / "asan.log"
            if asan_log.exists():
                cmd.extend(["--asan-log", str(asan_log)])

        if args.miri_log_dir:
            miri_log = Path(args.miri_log_dir) / case_name / "miri.log"
            if miri_log.exists():
                cmd.extend(["--miri-log", str(miri_log)])

        result = subprocess.run(cmd, cwd=str(ROOT_DIR))
        if result.returncode != 0:
            failed.append(case_name)

    if failed:
        print("\n[failed cases]")
        for name in failed:
            print(f" - {name}")
        return 1

    print("\n[ok] all cases completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())