from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common import parse_oracle_log_file, read_json, run_cmd, select_oracle_verdict, write_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay external crash input and attach oracle evidence")
    parser.add_argument("--meta", required=True)
    parser.add_argument("--crate-root", required=True)
    parser.add_argument("--repeat", type=int, default=10)
    parser.add_argument("--out", required=True)
    parser.add_argument("--skip-asan", action="store_true")
    parser.add_argument("--skip-miri", action="store_true")
    args = parser.parse_args()

    out = Path(args.out)
    work_dir = out.parent
    work_dir.mkdir(parents=True, exist_ok=True)

    replay_summary = work_dir / "replay_summary.json"
    run_cmd(
        [
            sys.executable,
            "scripts/replay_external_input.py",
            "--meta",
            args.meta,
            "--crate-root",
            args.crate_root,
            "--repeat",
            str(args.repeat),
            "--out",
            str(replay_summary),
        ],
        check=True,
    )

    meta = read_json(Path(args.meta))
    crash_inputs = meta.get("crash_inputs") or []
    replay_input = crash_inputs[0] if crash_inputs else None

    oracle_rows = []
    if replay_input and not args.skip_asan:
        asan_log = work_dir / "asan.log"
        run_cmd(
            [
                sys.executable,
                "scripts/run_asan.py",
                "--case-dir",
                args.crate_root,
                "--out-log",
                str(asan_log),
                "--replay-input",
                replay_input,
            ],
            check=False,
        )
        oracle_rows.append({"oracle": "asan", "verdict": parse_oracle_log_file(asan_log, "asan"), "log": str(asan_log)})

    if replay_input and not args.skip_miri:
        miri_log = work_dir / "miri.log"
        run_cmd(
            [
                sys.executable,
                "scripts/run_miri.py",
                "--case-dir",
                args.crate_root,
                "--out-log",
                str(miri_log),
                "--replay-input",
                replay_input,
            ],
            check=False,
        )
        oracle_rows.append({"oracle": "miri", "verdict": parse_oracle_log_file(miri_log, "miri"), "log": str(miri_log)})

    replay = read_json(replay_summary)
    best_verdict = select_oracle_verdict(oracle_rows)
    confirmed = best_verdict in {
        "AddressSanitizerDoubleFree",
        "AddressSanitizerUseAfterFree",
        "AddressSanitizerOutOfBounds",
        "AddressSanitizerInvalidFree",
        "AddressSanitizerLeak",
        "MiriUndefinedBehavior",
    }

    write_json(
        out,
        {
            "input_id": meta.get("harness_id"),
            "input": replay_input,
            "replay_runs": replay.get("replay_runs", 0),
            "replay_passes": replay.get("replay_passes", 0),
            "replay_failures": replay.get("replay_failures", 0),
            "replay_stable": replay.get("replay_stable", False),
            "stable": replay.get("stable", False),
            "stability": replay.get("stability", "Unsupported"),
            "oracle_rows": oracle_rows,
            "final_oracle_verdict": best_verdict,
            "final_confidence": "OracleConfirmed" if confirmed else "ReplayOnlyOrUnsupported",
            "replay_summary": str(replay_summary),
        },
    )
    print(f"[done] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
