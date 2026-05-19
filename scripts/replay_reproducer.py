from __future__ import annotations

import argparse
from pathlib import Path

from common import read_json, run_cmd, write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--repeat", type=int, default=10)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    meta = read_json(run_dir / "run_meta.json")
    case_dir = Path(meta["case_dir"])

    rows = []
    for i in range(args.repeat):
        log = run_dir / "replay" / f"replay-{i + 1:02d}.log"
        rc = run_cmd(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(case_dir / "Cargo.toml"),
                "--",
                "--nocapture",
            ],
            log_path=log,
            check=False,
        )
        rows.append({"replay_index": i + 1, "return_code": rc, "log": str(log)})

    stable = len({row["return_code"] for row in rows}) == 1
    out = Path(args.out) if args.out else run_dir / "replay_summary.json"
    write_json(out, {"run_dir": str(run_dir), "repeat": args.repeat, "stable": stable, "rows": rows})
    print(f"[done] replay stable={stable} out={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
