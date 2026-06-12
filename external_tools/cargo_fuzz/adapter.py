from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from common import read_json, write_json  # noqa: E402


def files_under(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [str(p) for p in sorted(path.rglob("*")) if p.is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize cargo-fuzz output for RustDPR")
    parser.add_argument("--crate", required=True)
    parser.add_argument("--crate-version", default=None)
    parser.add_argument("--harness-id", required=True)
    parser.add_argument("--harness-path", required=True)
    parser.add_argument("--fuzz-meta", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    fuzz_meta = read_json(Path(args.fuzz_meta))
    artifact_dir = Path(fuzz_meta.get("artifact_dir") or fuzz_meta.get("crashes_dir") or "")
    crash_inputs = files_under(artifact_dir)

    meta = {
        "schema_version": "0.2.0",
        "external_schema_version": "0.3.0",
        "tool": "cargo-fuzz",
        "variant": "libfuzzer",
        "crate": args.crate,
        "crate_version": args.crate_version,
        "harness_id": args.harness_id,
        "harness_path": args.harness_path,
        "engine": "libFuzzer",
        "compile_status": "success",
        "return_code": fuzz_meta.get("return_code"),
        "fuzz_budget_seconds": fuzz_meta.get("budget_seconds"),
        "seed": fuzz_meta.get("seed"),
        "raw_panic_count": 0,
        "raw_crash_count": len(crash_inputs),
        "trace_path": fuzz_meta.get("trace_jsonl"),
        "coverage_path": fuzz_meta.get("coverage_path"),
        "crash_inputs": crash_inputs,
        "corpus_dir": fuzz_meta.get("corpus_dir"),
        "notes": "normalized from cargo-fuzz/libFuzzer output",
    }
    write_json(Path(args.out), meta)
    print(f"[done] {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
