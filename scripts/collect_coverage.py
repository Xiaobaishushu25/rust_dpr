from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from common import ROOT_DIR, SUITES, capture_version, resolve_case, run_cmd, write_json


def parse_llvm_cov_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    totals = ((data.get("data") or [{}])[0].get("totals") or {})
    lines = totals.get("lines") or {}
    regions = totals.get("regions") or {}
    functions = totals.get("functions") or {}
    branches = totals.get("branches") or {}
    return {
        "lines_count": int(lines.get("count") or 0),
        "lines_covered": int(lines.get("covered") or 0),
        "line_coverage_percent": float(lines.get("percent") or 0.0),
        "regions_count": int(regions.get("count") or 0),
        "regions_covered": int(regions.get("covered") or 0),
        "region_coverage_percent": float(regions.get("percent") or 0.0),
        "functions_count": int(functions.get("count") or 0),
        "functions_covered": int(functions.get("covered") or 0),
        "function_coverage_percent": float(functions.get("percent") or 0.0),
        "branches_count": int(branches.get("count") or 0),
        "branches_covered": int(branches.get("covered") or 0),
        "branch_coverage_percent": float(branches.get("percent") or 0.0),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect line/region/function coverage for a benchmark crate")
    parser.add_argument("case", nargs="?", help="case name")
    parser.add_argument("--case-dir", default=None, help="direct crate root; used for instrumented working copies")
    parser.add_argument("--suite", choices=SUITES, default=None)
    parser.add_argument("--out", required=True, help="coverage.json output path")
    parser.add_argument("--raw-json", default=None, help="raw cargo-llvm-cov JSON path")
    parser.add_argument("--deterministic-test", default=None)
    parser.add_argument("--run-ignored", action="store_true")
    args = parser.parse_args()

    if args.case_dir:
        case_dir = Path(args.case_dir)
        suite = args.suite
        case_name = case_dir.name
    else:
        if not args.case:
            parser.error("case is required unless --case-dir is provided")
        suite, case_dir = resolve_case(args.case, args.suite)
        case_name = case_dir.name

    out = Path(args.out)
    raw_json = Path(args.raw_json) if args.raw_json else out.with_name("llvm_cov_raw.json")
    raw_json.parent.mkdir(parents=True, exist_ok=True)

    payload: dict[str, Any] = {
        "schema_version": "0.2.0",
        "suite": suite,
        "case": case_name,
        "case_dir": str(case_dir),
        "status": "unknown",
        "collector": "cargo-llvm-cov",
        "cargo_llvm_cov_version": capture_version(["cargo", "llvm-cov", "--version"]),
        "raw_json": str(raw_json),
    }

    if shutil.which("cargo") is None:
        payload.update({"status": "unavailable", "error": "cargo not found"})
        write_json(out, payload)
        return 0

    # cargo-llvm-cov is a cargo subcommand, so shutil.which("cargo-llvm-cov") is not reliable.
    probe = subprocess.run(
        ["cargo", "llvm-cov", "--version"],
        cwd=str(ROOT_DIR),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if probe.returncode != 0:
        payload.update(
            {
                "status": "unavailable",
                "error": "cargo-llvm-cov is not installed or not runnable",
                "probe_output": probe.stdout,
            }
        )
        write_json(out, payload)
        return 0

    cmd = [
        "cargo",
        "llvm-cov",
        "--manifest-path",
        str(case_dir / "Cargo.toml"),
        "--json",
        "--output-path",
        str(raw_json),
        "test",
    ]
    if args.deterministic_test:
        cmd.append(args.deterministic_test)
    cmd.extend(["--", "--nocapture", "--test-threads=1"])
    if args.run_ignored:
        cmd.append("--ignored")

    log_path = out.with_name("coverage.log")
    rc = run_cmd(cmd, cwd=ROOT_DIR, log_path=log_path, check=False)
    payload["return_code"] = rc
    payload["log_path"] = str(log_path)

    if rc != 0:
        payload.update({"status": "build_failure", "error": f"cargo llvm-cov exited with {rc}"})
        write_json(out, payload)
        return 0

    if not raw_json.exists():
        payload.update({"status": "missing_raw_json", "error": f"raw JSON not written: {raw_json}"})
        write_json(out, payload)
        return 0

    try:
        payload.update(parse_llvm_cov_json(raw_json))
        payload["status"] = "ok"
    except Exception as exc:  # noqa: BLE001 - report parser failure in coverage artifact.
        payload.update({"status": "parse_failure", "error": str(exc)})

    write_json(out, payload)
    print("[done]")
    print(f"coverage : {out}")
    print(f"status   : {payload.get('status')}")
    print(f"lines    : {payload.get('lines_covered', 0)}/{payload.get('lines_count', 0)}")
    print(f"percent  : {payload.get('line_coverage_percent', 0.0):.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
