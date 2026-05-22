from __future__ import annotations

import argparse
from pathlib import Path

from common import ROOT_DIR, SUITES, parse_oracle_verdict_from_log_text, resolve_case, run_cmd, run_output_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Miri on a RustDPR benchmark case")
    parser.add_argument("case", help="case name")
    parser.add_argument("--suite", choices=SUITES, default=None)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--run-index", type=int, default=1)
    parser.add_argument("--out-dir", default=None, help="output directory for miri.log")
    args = parser.parse_args()

    suite, case_dir = resolve_case(args.case, args.suite)
    if args.out_dir:
        out_dir = Path(args.out_dir)
    else:
        out_dir = run_output_dir(
            suite,
            case_dir.name,
            tool="miri-only",
            variant="oracle-only",
            seed=args.seed,
            run_index=args.run_index,
        ) / "oracle"
    out_dir.mkdir(parents=True, exist_ok=True)

    log_file = out_dir / "miri.log"

    run_cmd(
        [
            "cargo",
            "+nightly",
            "miri",
            "test",
            "--manifest-path",
            str(case_dir / "Cargo.toml"),
        ],
        cwd=ROOT_DIR,
        log_path=log_file,
        check=False,
    )

    content = log_file.read_text(encoding="utf-8", errors="replace")
    verdict = parse_oracle_verdict_from_log_text(content, "miri")
    print(f"[miri verdict] {verdict}")
    print(f"[log] {log_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
