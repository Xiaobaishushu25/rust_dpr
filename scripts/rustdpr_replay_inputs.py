from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from common import ROOT_DIR, read_json, run_cmd, write_json


def select_inputs(meta: dict[str, Any], kind: str) -> list[str]:
    artifacts = list(meta.get('crash_inputs') or [])
    corpus = list(meta.get('corpus_inputs') or [])
    all_inputs = list(meta.get('input_files') or [])

    if kind == 'artifacts':
        return artifacts
    if kind == 'corpus':
        return corpus
    if kind == 'all':
        if all_inputs:
            return all_inputs
        # Backward compatibility with old external-run metadata.
        return artifacts + [p for p in corpus if p not in artifacts]
    raise ValueError(f'unsupported input kind: {kind}')


def trace_event_count(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def append_trace(src: Path, dst: Path) -> int:
    if not src.exists():
        return 0
    n = 0
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open('r', encoding='utf-8', errors='replace') as fin, dst.open('a', encoding='utf-8') as fout:
        for line in fin:
            if line.strip():
                fout.write(line)
                if not line.endswith('\n'):
                    fout.write('\n')
                n += 1
    return n


def run_replay(
    *,
    crate_root: Path,
    target: str,
    input_path: Path,
    input_id: str,
    run_id: str,
    trace_path: Path,
    log_path: Path,
    toolchain: str,
    extra_libfuzzer_args: list[str],
) -> dict[str, Any]:
    cmd = [
        'cargo',
        f'+{toolchain}',
        'fuzz',
        'run',
        target,
        str(input_path),
        '--',
        '-runs=1',
        *extra_libfuzzer_args,
    ]
    env = dict(os.environ)
    env.update(
        {
            'RUSTDPR_TRACE_PATH': str(trace_path),
            'RUSTDPR_RUN_ID': run_id,
            'RUSTDPR_INPUT_ID': input_id,
            # Some targets call init_trace("..."); the crate-level implementation honors this env override.
            'RUSTDPR_DISABLE_TRACE': env.get('RUSTDPR_DISABLE_TRACE', '0'),
        }
    )
    rc = run_cmd(cmd, cwd=crate_root, env=env, log_path=log_path, check=False)
    return {
        'input_id': input_id,
        'input_path': str(input_path.resolve()),
        'return_code': rc,
        'trace_path': str(trace_path.resolve()),
        'trace_events': trace_event_count(trace_path),
        'log_path': str(log_path.resolve()),
        'command': cmd,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Replay cargo-fuzz-produced inputs under RustDPR-controlled tracing, without parsing cargo-fuzz/libFuzzer logs as evidence.'
    )
    parser.add_argument('--meta', required=True, help='cargo-fuzz input-producer run_meta.json')
    parser.add_argument('--crate-root', required=True)
    parser.add_argument('--out-dir', required=True)
    parser.add_argument('--input-kind', choices=['artifacts', 'corpus', 'all'], default='artifacts')
    parser.add_argument('--limit', type=int, default=None)
    parser.add_argument('--toolchain', default='nightly')
    parser.add_argument('--continue-on-error', action='store_true', default=True)
    parser.add_argument('libfuzzer_args', nargs='*', help='Extra libFuzzer args after a literal --, e.g. -- -rss_limit_mb=4096')
    args = parser.parse_args()

    meta_path = Path(args.meta)
    meta = read_json(meta_path)
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
    target = str(meta.get('harness_id') or '')
    if not target:
        print('[error] metadata has no harness_id/cargo-fuzz target')
        return 2

    extra = list(args.libfuzzer_args)
    if extra and extra[0] == '--':
        extra = extra[1:]

    inputs = select_inputs(meta, args.input_kind)
    if args.limit is not None:
        inputs = inputs[: args.limit]

    out_dir = Path(args.out_dir).resolve()
    traces_dir = out_dir / 'per_input_traces'
    logs_dir = out_dir / 'logs'
    combined_trace = out_dir / 'trace.jsonl'
    replay_summary = out_dir / 'replay_summary.json'
    replay_meta = out_dir / 'run_meta.json'
    out_dir.mkdir(parents=True, exist_ok=True)
    if combined_trace.exists():
        combined_trace.unlink()

    rows: list[dict[str, Any]] = []
    if not inputs:
        summary = {
            'schema_version': '0.1.0',
            'evidence_source': 'rustdpr_replay',
            'external_log_used': False,
            'crate': meta.get('crate'),
            'harness_id': target,
            'input_kind': args.input_kind,
            'total_inputs': 0,
            'replayed_inputs': 0,
            'nonzero_return_codes': 0,
            'combined_trace_events': 0,
            'status': 'no-inputs',
            'rows': [],
        }
        write_json(replay_summary, summary)
        new_meta = dict(meta)
        new_meta.update(
            {
                'trace_path': None,
                'rustdpr_replay_summary_path': str(replay_summary),
                'rustdpr_replay_meta_path': str(replay_meta),
                'evidence_source': 'rustdpr_replay',
                'external_log_used_by_rustdpr': False,
                'raw_replay_failure_count': 0,
                'notes': 'No cargo-fuzz inputs were available for independent RustDPR replay.',
            }
        )
        write_json(replay_meta, new_meta)
        print('[done] no inputs to replay')
        return 0

    for idx, raw_input in enumerate(inputs, start=1):
        input_path = Path(raw_input).resolve()
        input_id = f'{args.input_kind}-{idx:04d}-{input_path.name}'
        run_id = f"cargo-fuzz/{meta.get('crate')}/{target}/seed-{meta.get('seed')}/run-{meta.get('run_index')}/{input_id}"
        trace_path = traces_dir / f'{input_id}.jsonl'
        log_path = logs_dir / f'{input_id}.log'
        row = run_replay(
            crate_root=crate_root,
            target=target,
            input_path=input_path,
            input_id=input_id,
            run_id=run_id,
            trace_path=trace_path,
            log_path=log_path,
            toolchain=args.toolchain,
            extra_libfuzzer_args=extra,
        )
        row['combined_trace_events_before_append'] = trace_event_count(combined_trace)
        appended = append_trace(trace_path, combined_trace)
        row['appended_trace_events'] = appended
        rows.append(row)
        if row['return_code'] != 0 and not args.continue_on_error:
            break

    combined_events = trace_event_count(combined_trace)
    nonzero = sum(1 for row in rows if int(row.get('return_code') or 0) != 0)
    traced = sum(1 for row in rows if int(row.get('trace_events') or 0) > 0)
    summary = {
        'schema_version': '0.1.0',
        'evidence_source': 'rustdpr_replay',
        'external_log_used': False,
        'crate': meta.get('crate'),
        'crate_root': str(crate_root),
        'harness_id': target,
        'input_kind': args.input_kind,
        'toolchain': args.toolchain,
        'total_inputs': len(inputs),
        'replayed_inputs': len(rows),
        'inputs_with_trace': traced,
        'nonzero_return_codes': nonzero,
        'combined_trace_path': str(combined_trace),
        'combined_trace_events': combined_events,
        'status': 'ok' if combined_events > 0 else 'missing-rustdpr-trace',
        'rows': rows,
        'notes': [
            'Replay logs are retained for provenance/debugging only.',
            'RustDPR classification must use combined_trace_path and must not parse cargo-fuzz/libFuzzer logs as evidence.',
        ],
    }
    write_json(replay_summary, summary)

    new_meta = dict(meta)
    new_meta.update(
        {
            'trace_path': str(combined_trace) if combined_trace.exists() and combined_events > 0 else None,
            'rustdpr_trace_path': str(combined_trace) if combined_trace.exists() and combined_events > 0 else None,
            'rustdpr_replay_summary_path': str(replay_summary),
            'rustdpr_replay_meta_path': str(replay_meta),
            'evidence_source': 'rustdpr_replay',
            'external_log_used_by_rustdpr': False,
            'raw_replay_failure_count': nonzero,
            'replay_inputs_with_trace': traced,
            'replay_combined_trace_events': combined_events,
            'replay_status': summary['status'],
            'notes': 'RustDPR replay metadata generated from cargo-fuzz inputs; no cargo-fuzz/libFuzzer log evidence used for classification.',
        }
    )
    write_json(replay_meta, new_meta)
    print(f'[done] replayed {len(rows)} input(s); trace_events={combined_events}; meta={replay_meta}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
