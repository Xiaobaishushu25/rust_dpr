# scripts/run_miri.py
import subprocess
import sys
from pathlib import Path

def run_miri(case_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "miri.log"

    cmd = [
        "cargo", "+nightly", "miri", "test",
        "--manifest-path", str(case_dir / "Cargo.toml")
    ]

    print(f"Running Miri benchmark in {case_dir} ...")
    with log_file.open("w", encoding="utf-8") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=False)
    print(f"Miri output saved to {log_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python run_miri.py <case_dir> <out_dir>")
        sys.exit(1)

    case_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    run_miri(case_dir, out_dir)