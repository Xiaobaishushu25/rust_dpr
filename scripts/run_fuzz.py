from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from common import ROOT_DIR, SUITES, capture_version, resolve_case, run_cmd, run_output_dir, write_json


def build_libfuzzer_args(*, budget_seconds: int, runs: int, seed: int, artifact_dir: Path) -> list[str]:
    args = [f"-seed={seed}", "-detect_leaks=0", f"-artifact_prefix={artifact_dir}/"]
    if budget_seconds > 0:
        args.append(f"-max_total_time={budget_seconds}")
    else:
        args.append(f"-runs={runs}")
    return args


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a cargo-fuzz target for one RustDPR benchmark case")
    parser.add_argument("case")
    parser.add_argument("--case-dir", default=None, help="direct benchmark crate root; used for instrumented working copies")
    parser.add_argument("--suite", choices=SUITES, default=None)
    parser.add_argument("--target", default="fuzz_target_1")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--run-index", type=int, default=1)
    parser.add_argument("--budget-seconds", type=int, default=0)
    parser.add_argument("--runs", type=int, default=64, help="libFuzzer -runs value when budget is 0")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--keep-corpus", action="store_true")
    args = parser.parse_args()

    if args.case_dir:
        suite = args.suite or "realworld"
        case_dir = Path(args.case_dir)
    else:
        suite, case_dir = resolve_case(args.case, args.suite)
    fuzz_dir = case_dir / "fuzz"
    if not fuzz_dir.exists():
        raise SystemExit(f"fuzz directory not found: {fuzz_dir}")

    out_dir = Path(args.out_dir) if args.out_dir else run_output_dir(
        suite,
        case_dir.name,
        tool="cargo-fuzz",
        variant="crash-only",
        seed=args.seed,
        run_index=args.run_index,
        mode="fuzz",
    ) / "fuzz"
    out_dir.mkdir(parents=True, exist_ok=True)

    trace_jsonl = out_dir / "fuzz_trace.jsonl"
    log_path = out_dir / "cargo_fuzz.log"
    artifact_dir = out_dir / "artifacts"
    corpus_dir = out_dir / "corpus" if args.keep_corpus else fuzz_dir / "corpus" / args.target
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if not args.keep_corpus:
        shutil.rmtree(corpus_dir, ignore_errors=True)
    corpus_dir.mkdir(parents=True, exist_ok=True)

    if trace_jsonl.exists():
        trace_jsonl.unlink()

    run_id = args.run_id or f"{suite}/{case_dir.name}/cargo-fuzz/seed-{args.seed}/run-{args.run_index:03d}"
    cmd = [
        "cargo",
        "fuzz",
        "run",
        args.target,
        str(corpus_dir),
        "--",
        *build_libfuzzer_args(
            budget_seconds=args.budget_seconds,
            runs=args.runs,
            seed=args.seed,
            artifact_dir=artifact_dir,
        ),
    ]

    env = {
        "RUST_BACKTRACE": "1",
        "RUSTDPR_TRACE_PATH": str(trace_jsonl),
        "RUSTDPR_RUN_ID": run_id,
        "RUSTDPR_INPUT_ID": f"seed-{args.seed}",
    }

    rc = run_cmd(cmd, cwd=fuzz_dir, env=env, log_path=log_path, check=False)

    meta = {
        "suite": suite,
        "case": case_dir.name,
        "target": args.target,
        "seed": args.seed,
        "run_index": args.run_index,
        "budget_seconds": args.budget_seconds,
        "runs": args.runs,
        "run_id": run_id,
        "fuzz_dir": str(fuzz_dir),
        "out_dir": str(out_dir),
        "corpus_dir": str(corpus_dir),
        "artifact_dir": str(artifact_dir),
        "trace_jsonl": str(trace_jsonl),
        "trace_exists": trace_jsonl.exists(),
        "log_path": str(log_path),
        "return_code": rc,
        "cargo_fuzz_version": capture_version(["cargo", "fuzz", "--version"]),
    }
    write_json(out_dir / "fuzz_meta.json", meta)

    print("[done]")
    print(f"return_code : {rc}")
    print(f"trace_jsonl : {trace_jsonl}")
    print(f"fuzz_meta   : {out_dir / 'fuzz_meta.json'}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
