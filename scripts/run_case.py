from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
BENCH_DIR = ROOT_DIR / "benchmarks" / "micro"
DATA_DIR = ROOT_DIR / "data"
REPORTS_DIR = ROOT_DIR / "reports"


def run_cmd(cmd: list[str], cwd: Path | None = None, log_path: Path | None = None) -> None:
    print(f"[cmd] {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert process.stdout is not None

    log_file = None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = log_path.open("w", encoding="utf-8")

    try:
        for line in process.stdout:
            print(line, end="")
            if log_file is not None:
                log_file.write(line)
    finally:
        if log_file is not None:
            log_file.close()

    return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(return_code, cmd)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python scripts/run_case.py <case_name>")
        return 1

    case_name = sys.argv[1]
    case_dir = BENCH_DIR / case_name
    if not case_dir.exists():
        print(f"case not found: {case_dir}")
        return 1

    data_dir = DATA_DIR / case_name
    report_path = REPORTS_DIR / f"{case_name}.md"
    trace_path = case_dir / "artifacts" / "trace.jsonl"
    test_log_path = case_dir / "artifacts" / "test.stdout.log"

    data_dir.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    trace_path.parent.mkdir(parents=True, exist_ok=True)

    if trace_path.exists():
        trace_path.unlink()
    if test_log_path.exists():
        test_log_path.unlink()

    print(f"[1/5] collect metadata: {case_name}")
    run_cmd(
        [
            "cargo",
            "run",
            "-p",
            "rustdpr-cli",
            "--",
            "collect",
            "--crate-dir",
            str(case_dir),
            "--out",
            str(data_dir / "crate_meta.json"),
        ],
        cwd=ROOT_DIR,
    )

    print(f"[2/5] analyze sites: {case_name}")
    run_cmd(
        [
            "cargo",
            "run",
            "-p",
            "rustdpr-cli",
            "--",
            "analyze-sites",
            "--crate-dir",
            str(case_dir),
            "--out",
            str(data_dir / "site_map.json"),
        ],
        cwd=ROOT_DIR,
    )

    print(f"[3/5] run tests: {case_name}")
    run_cmd(
        ["cargo", "test", "--", "--nocapture"],
        cwd=case_dir,
        log_path=test_log_path,
    )

    if not trace_path.exists():
        print(f"trace file not found: {trace_path}")
        return 1

    print(f"[4/5] classify: {case_name}")
    run_cmd(
        [
            "cargo",
            "run",
            "-p",
            "rustdpr-cli",
            "--",
            "classify",
            "--trace",
            str(trace_path),
            "--site-map",
            str(data_dir / "site_map.json"),
            "--out",
            str(data_dir / "classification.json"),
        ],
        cwd=ROOT_DIR,
    )

    print(f"[5/5] render report: {case_name}")
    run_cmd(
        [
            "cargo",
            "run",
            "-p",
            "rustdpr-cli",
            "--",
            "report",
            "--trace",
            str(trace_path),
            "--site-map",
            str(data_dir / "site_map.json"),
            "--result",
            str(data_dir / "classification.json"),
            "--out",
            str(report_path),
        ],
        cwd=ROOT_DIR,
    )

    print(f"done: {case_name}")
    print(f"  trace:  {trace_path}")
    print(f"  class:  {data_dir / 'classification.json'}")
    print(f"  report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())