from __future__ import annotations

import argparse
import hashlib
import re
import shutil
from pathlib import Path
from typing import Any

from common import ROOT_DIR, SUITES, read_json, write_json


def sanitize_id(value: str) -> str:
    value = value.strip().replace('\\', '/')
    value = value.rsplit('/', 1)[-1]
    value = re.sub(r'[^A-Za-z0-9_.-]+', '-', value)
    return value.strip('-') or 'target'


def target_names(crate_root: Path, explicit: list[str]) -> list[str]:
    if explicit:
        return [sanitize_id(x) for x in explicit]
    fuzz_targets = crate_root / 'fuzz' / 'fuzz_targets'
    if not fuzz_targets.exists():
        return []
    return [p.stem for p in sorted(fuzz_targets.glob('*.rs'))]


def files_under(path: Path) -> list[Path]:
    if not path.exists():
        return []
    ignored = {'.gitkeep', 'README', 'README.md'}
    return [p for p in sorted(path.rglob('*')) if p.is_file() and p.name not in ignored]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def stable_input_id(path: Path, *, prefix: str) -> tuple[str, str]:
    """Return a path-independent candidate id and its full content digest."""
    digest = sha256_file(path)
    return f'{prefix}-{digest[:20]}', digest


def copy_inputs(paths: list[Path], out_dir: Path, *, kind: str) -> list[dict[str, Any]]:
    rows_by_id: dict[str, dict[str, Any]] = {}
    dest_dir = out_dir / kind
    dest_dir.mkdir(parents=True, exist_ok=True)
    for src in paths:
        input_id, digest = stable_input_id(src, prefix=kind[:-1] if kind.endswith('s') else kind)
        existing = rows_by_id.get(input_id)
        if existing is not None:
            existing.setdefault('original_paths', []).append(str(src.resolve()))
            continue
        dest = dest_dir / input_id
        if src.resolve() != dest.resolve():
            shutil.copy2(src, dest)
        rows_by_id[input_id] = {
            'input_id': input_id,
            'kind': kind,
            'sha256': digest,
            'original_path': str(src.resolve()),
            'original_paths': [str(src.resolve())],
            'path': str(dest.resolve()),
            'size_bytes': dest.stat().st_size if dest.exists() else None,
        }
    return list(rows_by_id.values())


def target_run_row(run_summary: dict[str, Any] | None, target: str) -> dict[str, Any] | None:
    if not run_summary:
        return None
    for row in run_summary.get('targets') or []:
        if str(row.get('target')) == target:
            return row
    return None


def build_manifest(
    *,
    suite: str,
    crate: str,
    crate_version: str | None,
    crate_root: Path,
    target: str,
    seed: int,
    run_index: int,
    budget_seconds: int,
    out_input_dir: Path,
    artifact_dir: Path,
    corpus_dir: Path,
    campaign_id: str | None,
    run_summary_path: Path | None,
    producer_run: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    harness_path = crate_root / 'fuzz' / 'fuzz_targets' / f'{target}.rs'

    artifact_rows = copy_inputs(files_under(artifact_dir), out_input_dir, kind='artifacts')
    corpus_rows = copy_inputs(files_under(corpus_dir), out_input_dir, kind='corpus')
    all_rows = artifact_rows + corpus_rows

    producer_return_code = (producer_run or {}).get('return_code')
    producer_status = (producer_run or {}).get('status')
    if not producer_status and producer_return_code is not None:
        producer_status = (
            'completed-with-artifact'
            if artifact_rows
            else ('completed-no-artifact' if int(producer_return_code) == 0 else 'unknown-nonzero-no-artifact')
        )
    producer_ok = (producer_run or {}).get('ok')
    if producer_ok is None and producer_status:
        producer_ok = producer_status != 'failed-no-artifact'
    producer_info = {
        'status': producer_status,
        'ok': producer_ok,
        'return_code': producer_return_code,
        'elapsed_seconds': (producer_run or {}).get('elapsed_seconds'),
        'log_path': (producer_run or {}).get('log_path'),
        'reported_artifact_count': (producer_run or {}).get('artifact_count'),
        'reported_corpus_count': (producer_run or {}).get('corpus_count'),
        'collected_artifact_count': len(artifact_rows),
        'collected_corpus_count': len(corpus_rows),
    }

    manifest = {
        'schema_version': '0.2.0',
        'producer': 'cargo-fuzz/libFuzzer',
        'consumer_policy': 'inputs-only-no-external-log-evidence',
        'tool': 'cargo-fuzz',
        'suite': suite,
        'case': crate,
        'crate': crate,
        'crate_version': crate_version,
        'crate_root': str(crate_root.resolve()),
        'harness_id': target,
        'harness_path': str(harness_path.resolve()),
        'seed': seed,
        'run_index': run_index,
        'budget_seconds': budget_seconds,
        'campaign_id': campaign_id,
        'run_summary_path': str(run_summary_path.resolve()) if run_summary_path else None,
        'producer_run': producer_info,
        'artifact_dir': str(artifact_dir.resolve()),
        'corpus_dir': str(corpus_dir.resolve()),
        'artifact_inputs': artifact_rows,
        'corpus_inputs': corpus_rows,
        'input_files': all_rows,
        'counts': {
            'artifact_inputs': len(artifact_rows),
            'corpus_inputs': len(corpus_rows),
            'total_inputs': len(all_rows),
        },
        'evidence_policy': {
            'external_log_used_by_rustdpr': False,
            'external_log_used_by_native_baseline': False,
            'rustdpr_validation_requires_independent_replay': True,
            'notes': [
                'cargo-fuzz is used only as an input/artifact producer.',
                'RustDPR must replay these inputs under its own trace/oracle pipeline before classification.',
            ],
        },
    }

    meta = {
        'schema_version': '0.2.0',
        'external_schema_version': '0.5.0',
        'tool': 'cargo-fuzz',
        'variant': 'input-producer',
        'suite': suite,
        'case': crate,
        'crate': crate,
        'crate_version': crate_version,
        'crate_root': str(crate_root.resolve()),
        'harness_id': target,
        'harness_path': str(harness_path.resolve()),
        'engine': 'libFuzzer',
        'compile_status': 'success' if harness_path.exists() else 'missing-harness',
        'fuzz_budget_seconds': budget_seconds,
        'campaign_budget_seconds': budget_seconds,
        'campaign_id': campaign_id,
        'run_summary_path': str(run_summary_path.resolve()) if run_summary_path else None,
        'producer_status': producer_status,
        'producer_ok': producer_ok,
        'producer_return_code': producer_return_code,
        'producer_elapsed_seconds': (producer_run or {}).get('elapsed_seconds'),
        'producer_log_path': (producer_run or {}).get('log_path'),
        'seed': seed,
        'run_index': run_index,
        'raw_crash_count': len(artifact_rows),
        # Deliberately do not infer panic_count from cargo-fuzz logs in the RustDPR evidence path.
        'raw_panic_count': 0,
        'crash_inputs': [row['path'] for row in artifact_rows],
        'corpus_inputs': [row['path'] for row in corpus_rows],
        'input_files': [row['path'] for row in all_rows],
        'input_manifest_path': None,  # filled by main after manifest path is known
        'trace_path': None,
        'artifact_dir': str(artifact_dir.resolve()),
        'corpus_dir': str(corpus_dir.resolve()),
        'evidence_policy': manifest['evidence_policy'],
        'notes': 'cargo-fuzz outputs collected as inputs only; RustDPR classification must use independent replay evidence.',
    }
    return manifest, meta



def infer_suite_from_crate_root(crate_root: Path) -> str:
    parts = str(crate_root).replace('\\', '/').split('/')
    for idx, part in enumerate(parts[:-1]):
        if part == 'benchmarks' and parts[idx + 1] in SUITES:
            return parts[idx + 1]
    return 'generated_harness'

def main() -> int:
    parser = argparse.ArgumentParser(
        description='Collect cargo-fuzz corpus/artifacts as input files only, without using cargo-fuzz logs as RustDPR evidence.'
    )
    parser.add_argument('--crate', required=True, help='Logical crate/case name used in reports, e.g. url')
    parser.add_argument('--crate-version', default=None)
    parser.add_argument('--crate-root', required=True, help='Path to the crate that contains fuzz/fuzz_targets/*.rs')
    parser.add_argument('--suite', choices=SUITES, default=None, help='Benchmark suite carried into downstream RustDPR metrics. Defaults to inferred benchmarks/<suite>/... or generated_harness.')
    parser.add_argument('--target', action='append', default=[], help='cargo-fuzz target name. May be repeated. Defaults to all fuzz_targets/*.rs')
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--run-index', type=int, default=1)
    parser.add_argument('--budget-seconds', type=int, default=300)
    parser.add_argument(
        '--run-summary',
        default=None,
        help=(
            'Summary emitted by run_cargo_fuzz_pilot.py. When provided, collection uses the '
            'exact isolated artifact/corpus directories recorded for this seed/run.'
        ),
    )
    parser.add_argument('--input-root', default=str(ROOT_DIR / 'data' / 'external_inputs' / 'cargo-fuzz'))
    parser.add_argument('--out-root', default=str(ROOT_DIR / 'data' / 'external_runs' / 'cargo-fuzz'))
    args = parser.parse_args()

    crate_root = Path(args.crate_root).resolve()
    if not crate_root.exists():
        print(f'[error] crate_root does not exist: {crate_root}')
        return 2
    if not crate_root.is_dir():
        print(f'[error] crate_root is not a directory: {crate_root}')
        return 2
    if not (crate_root / 'Cargo.toml').exists():
        print(f'[error] crate_root has no Cargo.toml: {crate_root}')
        return 2
    suite = args.suite or infer_suite_from_crate_root(crate_root)
    run_summary_path = Path(args.run_summary).resolve() if args.run_summary else None
    run_summary = read_json(run_summary_path) if run_summary_path and run_summary_path.exists() else None
    if args.run_summary and run_summary is None:
        print(f'[error] run summary does not exist: {run_summary_path}')
        return 2
    targets = target_names(crate_root, args.target)
    if not targets:
        print(f'[error] no cargo-fuzz targets found under {crate_root / "fuzz" / "fuzz_targets"}')
        return 2

    created: list[Path] = []
    for target in targets:
        run_row = target_run_row(run_summary, target)
        if run_summary is not None and run_row is None:
            print(f'[error] target {target!r} was not found in run summary: {run_summary_path}')
            return 2
        artifact_dir = (
            Path(str(run_row['artifact_dir'])).resolve()
            if run_row is not None
            else (crate_root / 'fuzz' / 'artifacts' / target).resolve()
        )
        corpus_dir = (
            Path(str(run_row['corpus_dir'])).resolve()
            if run_row is not None
            else (crate_root / 'fuzz' / 'corpus' / target).resolve()
        )
        campaign_id = str(run_row.get('campaign_id')) if run_row and run_row.get('campaign_id') else None
        if run_row is not None and (run_row.get('ok') is False or run_row.get('status') == 'failed-no-artifact'):
            print(
                f"[error] refusing to collect failed cargo-fuzz campaign: target={target} "
                f"status={run_row.get('status')} rc={run_row.get('return_code')} "
                f"log={run_row.get('log_path')}"
            )
            return 2
        input_dir = (
            Path(args.input_root)
            / args.crate
            / target
            / f'seed-{args.seed}'
            / f'run-{args.run_index}'
        )
        if input_dir.exists():
            shutil.rmtree(input_dir)
        manifest, meta = build_manifest(
            suite=suite,
            crate=args.crate,
            crate_version=args.crate_version,
            crate_root=crate_root,
            target=target,
            seed=args.seed,
            run_index=args.run_index,
            budget_seconds=args.budget_seconds,
            out_input_dir=input_dir,
            artifact_dir=artifact_dir,
            corpus_dir=corpus_dir,
            campaign_id=campaign_id,
            run_summary_path=run_summary_path,
            producer_run=run_row,
        )
        manifest_path = input_dir / 'input_manifest.json'
        write_json(manifest_path, manifest)
        meta['input_manifest_path'] = str(manifest_path.resolve())

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

    print(f'[done] collected cargo-fuzz inputs for {len(created)} target(s)')
    for path in created[:20]:
        print(path)
    if len(created) > 20:
        print(f'... {len(created) - 20} more')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
