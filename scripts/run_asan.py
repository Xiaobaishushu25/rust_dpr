from __future__ import annotations

import argparse
from pathlib import Path

from common import ROOT_DIR, SUITES, parse_oracle_verdict_from_log_text, resolve_case, run_cmd, run_output_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ASan on a RustDPR benchmark case or external crate root")
    parser.add_argument("case", nargs="?", help="case name")
    parser.add_argument("--case-dir", default=None, help="direct crate root for external-output replay")
    parser.add_argument("--suite", choices=SUITES, default=None)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--run-index", type=int, default=1)
    parser.add_argument("--out-dir", default=None, help="output directory for asan.log")
    parser.add_argument("--out-log", default=None, help="direct output log path")
    parser.add_argument("--replay-input", default=None)
    args = parser.parse_args()

    if args.case_dir:
        case_dir = Path(args.case_dir)
        suite = args.suite or "generated_harness"
        case_name = case_dir.name
    else:
        if not args.case:
            parser.error("case is required unless --case-dir is provided")
        suite, case_dir = resolve_case(args.case, args.suite)
        case_name = case_dir.name

    if args.out_log:
        log_file = Path(args.out_log)
        log_file.parent.mkdir(parents=True, exist_ok=True)
    else:
        if args.out_dir:
            out_dir = Path(args.out_dir)
        else:
            out_dir = run_output_dir(
                suite,
                case_name,
                tool="asan-only",
                variant="oracle-only",
                seed=args.seed,
                run_index=args.run_index,
            ) / "oracle"
        out_dir.mkdir(parents=True, exist_ok=True)
        log_file = out_dir / "asan.log"

    env = {
        "RUSTFLAGS": "-Zsanitizer=address",
        "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=0:abort_on_error=0",
    }
    if args.replay_input:
        env["RUSTDPR_REPLAY_INPUT"] = args.replay_input

    run_cmd(
        [
            "cargo",
            "+nightly",
            "test",
            "--manifest-path",
            str(case_dir / "Cargo.toml"),
            "--",
            "--nocapture",
        ],
        cwd=ROOT_DIR,
        env=env,
        log_path=log_file,
        check=False,
    )

    content = log_file.read_text(encoding="utf-8", errors="replace")
    verdict = parse_oracle_verdict_from_log_text(content, "asan")
    print(f"[asan verdict] {verdict}")
    print(f"[log] {log_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
