from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from common import ROOT_DIR, write_json


def sanitize_id(value: str) -> str:
    value = value.strip().replace('\\', '/')
    value = value.rsplit('/', 1)[-1]
    value = re.sub(r'[^A-Za-z0-9_.-]+', '-', value)
    return value.strip('-') or 'target'


def files_under(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [str(p.resolve()) for p in sorted(path.rglob('*')) if p.is_file()]


def count_crashes(artifact_dir: Path) -> int:
    if not artifact_dir.exists():
        return 0
    ignored = {'.gitkeep', 'README', 'README.md'}
    return sum(1 for p in artifact_dir.rglob('*') if p.is_file() and p.name not in ignored)


def parse_log_for_return_code(log_path: Path | None) -> int | None:
    if not log_path or not log_path.exists():
        return None
    text = log_path.read_text(encoding='utf-8', errors='replace')
    # Optional marker produced by run_cargo_fuzz_pilot.py.
    m = re.search(r'RUSTDPR_CARGO_FUZZ_RETURN_CODE\s*=\s*(-?\d+)', text)
    if m:
        return int(m.group(1))
    return None


def infer_panic_count(log_path: Path | None) -> int:
    if not log_path or not log_path.exists():
        return 0
    text = log_path.read_text(encoding='utf-8', errors='replace')
    # cargo-fuzz/libFuzzer commonly prints Rust panic lines into stderr/stdout.
    return text.count("thread '") + text.count('panicked at')


def target_names(crate_root: Path, explicit: list[str]) -> list[str]:
    if explicit:
        return [sanitize_id(x) for x in explicit]
    fuzz_targets = crate_root / 'fuzz' / 'fuzz_targets'
    if not fuzz_targets.exists():
        return []
    return [p.stem for p in sorted(fuzz_targets.glob('*.rs'))]


def build_meta(
    *,
    crate: str,
    crate_version: str | None,
    crate_root: Path,
    target: str,
    seed: int,
    budget_seconds: int,
    run_index: int,
    log_path: Path | None,
    trace_path: Path | None,
    coverage_path: Path | None,
) -> dict[str, Any]:
    harness_path = crate_root / 'fuzz' / 'fuzz_targets' / f'{target}.rs'
    artifact_dir = crate_root / 'fuzz' / 'artifacts' / target
    corpus_dir = crate_root / 'fuzz' / 'corpus' / target
    crashes = files_under(artifact_dir)
    raw_crash_count = count_crashes(artifact_dir)
    return_code = parse_log_for_return_code(log_path)
    raw_panic_count = infer_panic_count(log_path)

    return {
        'schema_version': '0.2.0',
        'external_schema_version': '0.4.0',
        'tool': 'cargo-fuzz',
        'variant': 'libfuzzer',
        'crate': crate,
        'crate_version': crate_version,
        'crate_root': str(crate_root.resolve()),
        'harness_id': target,
        'harness_path': str(harness_path.resolve()),
        'engine': 'libFuzzer',
        'compile_status': 'success' if harness_path.exists() else 'missing-harness',
        'return_code': return_code,
        'fuzz_budget_seconds': budget_seconds,
        'seed': seed,
        'run_index': run_index,
        'raw_panic_count': raw_panic_count,
        'raw_crash_count': raw_crash_count,
        'trace_path': str(trace_path.resolve()) if trace_path and trace_path.exists() else None,
        'coverage_path': str(coverage_path.resolve()) if coverage_path and coverage_path.exists() else None,
        'crash_inputs': crashes,
        'artifact_dir': str(artifact_dir.resolve()),
        'corpus_dir': str(corpus_dir.resolve()),
        'log_path': str(log_path.resolve()) if log_path and log_path.exists() else None,
        'notes': 'normalized from official cargo-fuzz/libFuzzer project layout',
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Collect existing official cargo-fuzz outputs into RustDPR external-run metadata.'
    )
    parser.add_argument('--crate', required=True, help='Logical crate/case name used in reports, e.g. url')
    parser.add_argument('--crate-version', default=None)
    parser.add_argument('--crate-root', required=True, help='Path to the crate that contains fuzz/fuzz_targets/*.rs')
    parser.add_argument('--target', action='append', default=[], help='cargo-fuzz target name. May be repeated. Defaults to all fuzz_targets/*.rs')
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--run-index', type=int, default=1)
    parser.add_argument('--budget-seconds', type=int, default=300)
    parser.add_argument('--log-dir', default=None, help='Directory containing <target>.log produced by run_cargo_fuzz_pilot.py')
    parser.add_argument('--trace-dir', default=None, help='Optional directory containing <target>.trace.jsonl')
    parser.add_argument('--coverage-dir', default=None, help='Optional directory containing <target>.coverage.json')
    parser.add_argument('--out-root', default=str(ROOT_DIR / 'data' / 'external_runs' / 'cargo-fuzz'))
    args = parser.parse_args()

    crate_root = Path(args.crate_root).resolve()
    targets = target_names(crate_root, args.target)
    if not targets:
        print(f'[error] no cargo-fuzz targets found under {crate_root / "fuzz" / "fuzz_targets"}')
        return 2

    created: list[Path] = []
    for target in targets:
        log_path = Path(args.log_dir) / f'{target}.log' if args.log_dir else None
        trace_path = Path(args.trace_dir) / f'{target}.trace.jsonl' if args.trace_dir else None
        coverage_path = Path(args.coverage_dir) / f'{target}.coverage.json' if args.coverage_dir else None
        meta = build_meta(
            crate=args.crate,
            crate_version=args.crate_version,
            crate_root=crate_root,
            target=target,
            seed=args.seed,
            budget_seconds=args.budget_seconds,
            run_index=args.run_index,
            log_path=log_path,
            trace_path=trace_path,
            coverage_path=coverage_path,
        )
        out_path = (
            Path(args.out_root)
            / args.crate
            / target
            / f'seed-{args.seed}'
            / f'run-{args.run_index}'
            / 'run_meta.json'
        )
        write_json(out_path, meta)
        created.append(out_path)

    print(f'[done] collected {len(created)} cargo-fuzz target(s)')
    for path in created[:20]:
        print(path)
    if len(created) > 20:
        print(f'... {len(created) - 20} more')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
