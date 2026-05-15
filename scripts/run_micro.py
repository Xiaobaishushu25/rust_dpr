import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "micro"
OUT.mkdir(parents=True, exist_ok=True)

MICRO_CASES = [
    "mb_unwrap_shallow",
    "mb_panic_before_unsafe",
    "mb_panic_after_unsafe",
]

def run(cmd):
    print(" ".join(map(str, cmd)))
    subprocess.run(cmd, check=True)

for case in MICRO_CASES:
    case_dir = ROOT / "benchmarks" / "micro" / case
    case_out = OUT / case
    case_out.mkdir(parents=True, exist_ok=True)

    site_map = case_out / "site_map.json"
    fn_idx = case_out / "function_index.json"
    dpg = case_out / "dpg.json"
    harness = case_out / "harness.json"

    run([
        "cargo", "run", "-p", "rustdpr-cli", "--",
        "analyze-sites",
        "--crate-root", str(case_dir),
        "--out", str(site_map),
        "--function-out", str(fn_idx),
    ])

    run([
        "cargo", "run", "-p", "rustdpr-cli", "--",
        "build-dpg",
        "--site-map", str(site_map),
        "--function-index", str(fn_idx),
        "--out", str(dpg),
    ])

    fuzz_dir = case_dir / "fuzz"
    if fuzz_dir.exists():
        run([
            "cargo", "run", "-p", "rustdpr-cli", "--",
            "validate-harness",
            "--harness", str(fuzz_dir),
            "--out", str(harness),
        ])