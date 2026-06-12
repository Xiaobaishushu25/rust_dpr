from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from common import write_json  # noqa: E402


def files_under(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [str(p) for p in sorted(path.rglob("*")) if p.is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize RULF raw outputs for RustDPR")
    parser.add_argument("--crate", required=True)
    parser.add_argument("--crate-version", default=None)
    parser.add_argument("--harness-id", required=True)
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    harness_path = raw_dir / "fuzz_target.rs"
    trace_path = raw_dir / "trace.jsonl"
    crashes = raw_dir / "crashes"

    meta = {
        "schema_version": "0.2.0",
        "external_schema_version": "0.3.0",
        "tool": "rulf",
        "variant": "api-dependency-generated-harness",
        "crate": args.crate,
        "crate_version": args.crate_version,
        "harness_id": args.harness_id,
        "harness_path": str(harness_path),
        "engine": "AFL++-or-libFuzzer",
        "compile_status": "success" if harness_path.exists() else "missing_harness",
        "return_code": None,
        "fuzz_budget_seconds": None,
        "seed": None,
        "raw_panic_count": 0,
        "raw_crash_count": len(files_under(crashes)),
        "trace_path": str(trace_path) if trace_path.exists() else None,
        "coverage_path": str(raw_dir / "coverage.json") if (raw_dir / "coverage.json").exists() else None,
        "crash_inputs": files_under(crashes),
        "corpus_dir": str(raw_dir / "corpus") if (raw_dir / "corpus").exists() else None,
        "notes": "RULF generated harness normalized for RustDPR validation",
    }
    write_json(Path(args.out), meta)
    print(f"[done] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
