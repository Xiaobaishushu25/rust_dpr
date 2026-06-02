from __future__ import annotations

import argparse
from pathlib import Path

from common import BENCHMARKS_DIR, SUITES, discover_cases, load_yaml, normalize_expected_schema, run_cmd, write_json

PLACEHOLDER_MARKERS = (
    "fuzzed code goes here",
    "TODO",
    "todo!",
)


def validate_case(suite: str, case_dir: Path, *, build: bool) -> dict:
    fuzz_dir = case_dir / "fuzz"
    target = fuzz_dir / "fuzz_targets" / "fuzz_target_1.rs"
    cargo_toml = fuzz_dir / "Cargo.toml"
    expected_path = case_dir / "expected.yaml"
    errors: list[str] = []
    warnings: list[str] = []

    if not fuzz_dir.exists():
        errors.append("missing fuzz/ directory")
    if not cargo_toml.exists():
        errors.append("missing fuzz/Cargo.toml")
    if not target.exists():
        errors.append("missing fuzz/fuzz_targets/fuzz_target_1.rs")
    else:
        text = target.read_text(encoding="utf-8", errors="replace")
        if any(marker in text for marker in PLACEHOLDER_MARKERS):
            errors.append("fuzz target still contains placeholder code")
        if "fuzz_target!" not in text:
            errors.append("fuzz target does not contain fuzz_target! macro")
        if "init_trace" not in text:
            warnings.append("fuzz target does not initialize RustDPR trace")
        if "install_panic_hook" not in text:
            warnings.append("fuzz target does not install RustDPR panic hook")

    if expected_path.exists():
        expected = normalize_expected_schema(load_yaml(expected_path) or {})
        harness_path = ((load_yaml(expected_path) or {}).get("harness") or {}).get("path")
        if harness_path and harness_path != "fuzz/fuzz_targets/fuzz_target_1.rs":
            warnings.append(f"expected.yaml harness.path is {harness_path!r}, not fuzz/fuzz_targets/fuzz_target_1.rs")
        if expected.get("case_id") != case_dir.name:
            errors.append("expected.yaml case_id does not match directory name")
    else:
        errors.append("missing expected.yaml")

    build_rc = None
    if build and not errors:
        build_rc = run_cmd(["cargo", "fuzz", "build", "fuzz_target_1"], cwd=fuzz_dir, check=False)
        if build_rc != 0:
            errors.append(f"cargo fuzz build failed with rc={build_rc}")

    return {
        "suite": suite,
        "case": case_dir.name,
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "warnings": warnings,
        "build_return_code": build_rc,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate that benchmark cargo-fuzz harnesses are present and non-placeholder")
    parser.add_argument("--suite", choices=SUITES, default=None)
    parser.add_argument("--case", default=None)
    parser.add_argument("--build", action="store_true", help="also run cargo fuzz build for each target")
    parser.add_argument("--summary-json", default=None)
    args = parser.parse_args()

    suites = [args.suite] if args.suite else [s for s in SUITES if (BENCHMARKS_DIR / s).exists()]
    rows = []
    for suite in suites:
        cases = [BENCHMARKS_DIR / suite / args.case] if args.case else discover_cases(suite)
        for case_dir in cases:
            row = validate_case(suite, case_dir, build=args.build)
            rows.append(row)
            print(f"[{row['status']}] {suite}/{case_dir.name}")
            for msg in row["errors"]:
                print(f"  - ERROR: {msg}")
            for msg in row["warnings"]:
                print(f"  - WARN : {msg}")

    summary = {
        "total": len(rows),
        "pass": sum(1 for r in rows if r["status"] == "PASS"),
        "fail": sum(1 for r in rows if r["status"] != "PASS"),
        "rows": rows,
    }
    if args.summary_json:
        write_json(Path(args.summary_json), summary)
    print(f"[summary] total={summary['total']} pass={summary['pass']} fail={summary['fail']}")
    return 1 if summary["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
