from __future__ import annotations

import argparse
import hashlib
import re
import shutil
from pathlib import Path
from typing import Any

from common import ROOT_DIR, SUITES, write_json


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


def stable_input_id(path: Path, *, prefix: str) -> str:
    h = hashlib.sha1()
    h.update(str(path.resolve()).encode('utf-8', errors='replace'))
    try:
        h.update(path.read_bytes()[:4096])
    except OSError:
        pass
    stem = sanitize_id(path.name)[:80]
    return f'{prefix}-{stem}-{h.hexdigest()[:12]}'


def copy_inputs(paths: list[Path], out_dir: Path, *, kind: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    dest_dir = out_dir / kind
    dest_dir.mkdir(parents=True, exist_ok=True)
    for src in paths:
        input_id = stable_input_id(src, prefix=kind[:-1] if kind.endswith('s') else kind)
        dest = dest_dir / input_id
        if src.resolve() != dest.resolve():
            shutil.copy2(src, dest)
        rows.append(
            {
                'input_id': input_id,
                'kind': kind,
                'original_path': str(src.resolve()),
                'path': str(dest.resolve()),
                'size_bytes': dest.stat().st_size if dest.exists() else None,
            }
        )
    return rows


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
) -> tuple[dict[str, Any], dict[str, Any]]:
    harness_path = crate_root / 'fuzz' / 'fuzz_targets' / f'{target}.rs'
    artifact_dir = crate_root / 'fuzz' / 'artifacts' / target
    corpus_dir = crate_root / 'fuzz' / 'corpus' / target

    artifact_rows = copy_inputs(files_under(artifact_dir), out_input_dir, kind='artifacts')
    corpus_rows = copy_inputs(files_under(corpus_dir), out_input_dir, kind='corpus')
    all_rows = artifact_rows + corpus_rows

    manifest = {
        'schema_version': '0.1.0',
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
    targets = target_names(crate_root, args.target)
    if not targets:
        print(f'[error] no cargo-fuzz targets found under {crate_root / "fuzz" / "fuzz_targets"}')
        return 2

    created: list[Path] = []
    for target in targets:
        input_dir = (
            Path(args.input_root)
            / args.crate
            / target
            / f'seed-{args.seed}'
            / f'run-{args.run_index}'
        )
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
