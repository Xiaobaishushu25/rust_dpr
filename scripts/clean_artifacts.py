from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from common import BENCHMARKS_DIR, RUNS_DIR, SUITES


def remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
        print(f"removed dir: {path}")
    elif path.exists():
        path.unlink()
        print(f"removed file: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Clean RustDPR generated artifacts")
    parser.add_argument("--suite", choices=SUITES, default=None, help="clean only one suite")
    args = parser.parse_args()

    suites = [args.suite] if args.suite else list(SUITES)

    for suite in suites:
        runs_suite_dir = RUNS_DIR / suite
        if runs_suite_dir.exists():
            remove_path(runs_suite_dir)

        suite_dir = BENCHMARKS_DIR / suite
        if not suite_dir.exists():
            continue

        for case_dir in [p for p in suite_dir.iterdir() if p.is_dir()]:
            for candidate in [
                case_dir / "artifacts",
                case_dir / "trace.jsonl",
                case_dir / "asan.log",
                case_dir / "miri.log",
            ]:
                if candidate.exists():
                    remove_path(candidate)

    print("clean complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
