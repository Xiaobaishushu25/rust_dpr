from __future__ import annotations

import argparse
from pathlib import Path

from common import read_json, run_cmd, write_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay an external fuzzing input N times")
    parser.add_argument("--meta", required=True)
    parser.add_argument("--crate-root", required=True)
    parser.add_argument("--repeat", type=int, default=10)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    meta = read_json(Path(args.meta))
    crate_root = Path(args.crate_root)
    crash_inputs = meta.get("crash_inputs") or []
    out = Path(args.out)

    if not crash_inputs:
        write_json(
            out,
            {
                "input_id": meta.get("harness_id"),
                "replay_runs": 0,
                "replay_passes": 0,
                "replay_failures": 0,
                "replay_stable": False,
                "stable": False,
                "stability": "Unsupported",
                "reason": "no crash inputs in metadata",
            },
        )
        return 0

    first_input = crash_inputs[0]
    rows = []
    replay_dir = out.parent / "replay"
    replay_dir.mkdir(parents=True, exist_ok=True)

    for i in range(args.repeat):
        log = replay_dir / f"replay-{i + 1:02d}.log"
        cmd = [
            "cargo",
            "test",
            "--manifest-path",
            str(crate_root / "Cargo.toml"),
            "--",
            "--nocapture",
            "--test-threads=1",
        ]
        env = {
            "RUSTDPR_REPLAY_INPUT": first_input,
            "RUSTDPR_INPUT_ID": f"replay-{i + 1:02d}",
        }
        rc = run_cmd(cmd, env=env, log_path=log, check=False)
        rows.append(
            {
                "replay_index": i + 1,
                "input": first_input,
                "return_code": rc,
                "log": str(log),
            }
        )

    return_codes = {row["return_code"] for row in rows}
    stable = len(return_codes) == 1
    passes = sum(1 for row in rows if row["return_code"] != 0)
    failures = args.repeat - passes

    write_json(
        out,
        {
            "input_id": meta.get("harness_id"),
            "input": first_input,
            "replay_runs": args.repeat,
            "replay_passes": passes,
            "replay_failures": failures,
            "replay_stable": stable,
            "stable": stable,
            "stability": "Stable" if stable else "Flaky",
            "rows": rows,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
