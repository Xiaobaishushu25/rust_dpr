from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
MICRO_DIR = ROOT_DIR / "benchmarks" / "micro"
RUN_CASE = ROOT_DIR / "scripts" / "run_case.py"


def main() -> int:
    if not MICRO_DIR.exists():
        print(f"micro benchmark dir not found: {MICRO_DIR}")
        return 1

    case_dirs = sorted([p for p in MICRO_DIR.iterdir() if p.is_dir()])
    if not case_dirs:
        print("no benchmark cases found")
        return 1

    failed = []

    for case_dir in case_dirs:
        case_name = case_dir.name
        print("=" * 40)
        print(f"running case: {case_name}")
        print("=" * 40)

        result = subprocess.run(
            [sys.executable, str(RUN_CASE), case_name],
            cwd=str(ROOT_DIR),
        )
        if result.returncode != 0:
            failed.append(case_name)

    if failed:
        print("\nfailed cases:")
        for name in failed:
            print(f"  - {name}")
        return 1

    print("\nall micro benchmarks completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())