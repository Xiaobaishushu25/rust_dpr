import os
import subprocess
import sys
from pathlib import Path


def run_asan(case_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "asan.log"

    env = dict(os.environ)
    env["RUSTFLAGS"] = "-Zsanitizer=address"
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=0:abort_on_error=0"

    cmd = [
        "cargo",
        "+nightly",
        "test",
        "--manifest-path",
        str(case_dir / "Cargo.toml"),
        "--",
        "--nocapture",
    ]

    print(f"Running ASan benchmark in {case_dir} ...")
    with log_file.open("w", encoding="utf-8") as f:
        subprocess.run(
            cmd,
            stdout=f,
            stderr=subprocess.STDOUT,
            env=env,
            check=False,
        )

    print(f"ASan output saved to {log_file}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scripts/run_asan.py <case_dir> <out_dir>")
        sys.exit(1)

    case_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    run_asan(case_dir, out_dir)