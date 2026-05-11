from __future__ import annotations

import shutil
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
REPORTS_DIR = ROOT_DIR / "reports"
MICRO_DIR = ROOT_DIR / "benchmarks" / "micro"


def remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
        print(f"removed dir: {path}")
    elif path.exists():
        path.unlink()
        print(f"removed file: {path}")


def main() -> int:
    if DATA_DIR.exists():
        remove_path(DATA_DIR)

    if REPORTS_DIR.exists():
        remove_path(REPORTS_DIR)

    if MICRO_DIR.exists():
        for case_dir in MICRO_DIR.iterdir():
            if not case_dir.is_dir():
                continue
            artifacts_dir = case_dir / "artifacts"
            if artifacts_dir.exists():
                remove_path(artifacts_dir)

    print("cleaned data, reports, and benchmark artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())