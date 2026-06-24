from __future__ import annotations

import argparse
import hashlib
import os
import re
from pathlib import Path
from typing import Any

from common import ROOT_DIR, read_json, run_cmd, write_json


def sanitize_id(value: str) -> str:
    value = value.strip().replace('\\', '/')
    value = value.rsplit('/', 1)[-1]
    value = re.sub(r'[^A-Za-z0-9_.-]+', '-', value)
    return value.strip('-') or 'input'


def content_input_id(path: Path, kind: str) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    prefix = kind[:-1] if kind.endswith('s') else kind
    return f'{prefix}-{h.hexdigest()[:20]}'


def manifest_input_records(meta: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    manifest_path = meta.get('input_manifest_path')
    if not manifest_path:
        return []
    path = Path(str(manifest_path))
    if not path.exists():
        return []
    manifest = read_json(path)
    artifacts = list(manifest.get('artifact_inputs') or [])
    corpus = list(manifest.get('corpus_inputs') or [])
    if kind == 'artifacts':
        return artifacts
    if kind == 'corpus':
        return corpus
    if kind == 'all':
        return list(manifest.get('input_files') or (artifacts + corpus))
    raise ValueError(f'unsupported input kind: {kind}')


def select_input_records(meta: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    records = manifest_input_records(meta, kind)
    if records:
        return records

    artifacts = list(meta.get('crash_inputs') or [])
    corpus = list(meta.get('corpus_inputs') or [])
    all_inputs = list(meta.get('input_files') or [])
    if kind == 'artifacts':
        raw = [('artifacts', path) for path in artifacts]
    elif kind == 'corpus':
        raw = [('corpus', path) for path in corpus]
    elif kind == 'all':
        paths = all_inputs or (artifacts + [path for path in corpus if path not in artifacts])
        artifact_set = set(artifacts)
        raw = [('artifacts' if path in artifact_set else 'corpus', path) for path in paths]
    else:
        raise ValueError(f'unsupported input kind: {kind}')

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for record_kind, raw_path in raw:
        path = Path(raw_path).resolve()
        if not path.exists() or not path.is_file():
            continue
        input_id = content_input_id(path, record_kind)
        key = (record_kind, input_id)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                'input_id': input_id,
                'kind': record_kind,
                'path': str(path),
                'size_bytes': path.stat().st_size,
            }
        )
    return rows


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
    """Append a per-input trace to a debug-only aggregate trace."""
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
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_dir = log_path.parent / 'artifacts'
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if trace_path.exists():
        trace_path.unlink()
    if any(arg.startswith('-artifact_prefix=') for arg in extra_libfuzzer_args):
        raise ValueError(
            'do not pass -artifact_prefix to rustdpr_replay_inputs.py; '
            'each replay attempt uses an isolated artifact directory'
        )
    cmd = [
        'cargo',
        f'+{toolchain}',
        'fuzz',
        'run',
        target,
        str(input_path),
        '--',
        '-runs=1',
        f'-artifact_prefix={artifact_dir}{os.sep}',
        *extra_libfuzzer_args,
    ]
    env = dict(os.environ)
    env.update(
        {
            'RUSTDPR_TRACE_PATH': str(trace_path),
            'RUSTDPR_RUN_ID': run_id,
            'RUSTDPR_INPUT_ID': input_id,
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
        'artifact_dir': str(artifact_dir.resolve()),
        'command': cmd,
    }


def per_input_meta(
    *,
    source_meta: dict[str, Any],
    record: dict[str, Any],
    row: dict[str, Any],
    replay_summary_path: Path,
) -> dict[str, Any]:
    input_id = str(record['input_id'])
    input_path = str(Path(str(record['path'])).resolve())
    input_kind = str(record.get('kind') or 'artifacts')
    trace_events = int(row.get('trace_events') or 0)
    return_code = int(row.get('return_code') or 0)
    campaign_id = source_meta.get('campaign_id') or (
        f"cargo-fuzz/{source_meta.get('crate')}/{source_meta.get('harness_id')}/"
        f"seed-{source_meta.get('seed')}/run-{source_meta.get('run_index')}"
    )
    candidate_id = f'{campaign_id}/{input_id}'

    meta = dict(source_meta)
    meta.update(
        {
            'schema_version': '0.3.0',
            'unit_of_analysis': 'candidate',
            'campaign_id': campaign_id,
            'campaign_budget_seconds': source_meta.get(
                'campaign_budget_seconds', source_meta.get('fuzz_budget_seconds', 0)
            ),
            'candidate_id': candidate_id,
            'input_id': input_id,
            'input_kind': input_kind,
            'input_sha256': record.get('sha256'),
            'input_path': input_path,
            'input_files': [input_path],
            'crash_inputs': [input_path] if input_kind == 'artifacts' else [],
            'corpus_inputs': [input_path] if input_kind == 'corpus' else [],
            'raw_crash_count': 1 if input_kind == 'artifacts' else 0,
            'raw_replay_failure_count': int(row.get('replay_passes') or (1 if return_code != 0 else 0)),
            'return_code': return_code,
            'trace_path': row.get('trace_path') if trace_events > 0 else None,
            'rustdpr_trace_path': row.get('trace_path') if trace_events > 0 else None,
            'rustdpr_replay_summary_path': str(replay_summary_path.resolve()),
            'evidence_source': 'rustdpr_replay_per_input',
            'external_log_used_by_rustdpr': False,
            'replay_trace_events': trace_events,
            'replay_runs': int(row.get('replay_runs') or 1),
            'replay_passes': int(row.get('replay_passes') or 0),
            'replay_failures': int(row.get('replay_failures') or 0),
            'replay_stable': bool(row.get('replay_stable')),
            'return_code_stable': bool(row.get('return_code_stable')),
            'trace_attempts': int(row.get('trace_attempts') or 0),
            'traced_reproduced_attempts': int(row.get('traced_reproduced_attempts') or 0),
            'replay_outcome': row.get('replay_outcome'),
            'replay_status': 'ok' if trace_events > 0 else 'missing-rustdpr-trace',
            'replay_log_path': row.get('log_path'),
            'replay_log_paths': [attempt.get('log_path') for attempt in (row.get('attempts') or [])],
            'notes': (
                'Candidate-level RustDPR replay metadata. Classification must use only this input trace; '
                'the debug aggregate trace is forbidden as classification evidence.'
            ),
        }
    )
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            'Replay cargo-fuzz-produced inputs under RustDPR-controlled tracing. '
            'Each input receives a separate trace and candidate metadata file.'
        )
    )
    parser.add_argument('--meta', required=True, help='cargo-fuzz input-producer run_meta.json')
    parser.add_argument('--crate-root', required=True)
    parser.add_argument('--out-dir', required=True)
    parser.add_argument('--input-kind', choices=['artifacts', 'corpus', 'all'], default='artifacts')
    parser.add_argument('--limit', type=int, default=None)
    parser.add_argument(
        '--repeat',
        type=int,
        default=1,
        help=(
            'Replay each candidate this many times. Paper runs should use 10. '
            'Classification uses one canonical per-input trace; stability uses all attempts.'
        ),
    )
    parser.add_argument('--toolchain', default='nightly')
    parser.add_argument('--stop-after-first-nonzero', action='store_true', help='Debug only: stop after the first reproduced non-zero return code.')
    parser.add_argument('libfuzzer_args', nargs='*', help='Extra libFuzzer args after a literal --, e.g. -- -rss_limit_mb=4096')
    args = parser.parse_args()

    if args.repeat < 1:
        parser.error('--repeat must be >= 1')

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
    if any(arg.startswith('-artifact_prefix=') for arg in extra):
        print(
            '[error] do not pass -artifact_prefix; each replay attempt uses an isolated artifact directory'
        )
        return 2

    records = select_input_records(meta, args.input_kind)
    if args.limit is not None:
        records = records[: args.limit]

    out_dir = Path(args.out_dir).resolve()
    traces_dir = out_dir / 'per_input_traces'
    logs_dir = out_dir / 'logs'
    per_input_meta_dir = out_dir / 'per_input_meta'
    per_input_summary_dir = out_dir / 'per_input_replay'
    debug_combined_trace = out_dir / 'debug_combined_trace.jsonl'
    replay_summary = out_dir / 'replay_summary.json'
    replay_meta = out_dir / 'run_meta.json'
    out_dir.mkdir(parents=True, exist_ok=True)
    if debug_combined_trace.exists():
        debug_combined_trace.unlink()

    rows: list[dict[str, Any]] = []
    per_input_meta_paths: list[str] = []
    if not records:
        summary = {
            'schema_version': '0.2.0',
            'evidence_source': 'rustdpr_replay_per_input',
            'external_log_used': False,
            'crate': meta.get('crate'),
            'harness_id': target,
            'input_kind': args.input_kind,
            'repeat_per_input': args.repeat,
            'total_inputs': 0,
            'replayed_inputs': 0,
            'nonzero_return_codes': 0,
            'per_input_meta_paths': [],
            'status': 'no-inputs',
            'rows': [],
        }
        write_json(replay_summary, summary)
        new_meta = dict(meta)
        new_meta.update(
            {
                'trace_path': None,
                'rustdpr_trace_path': None,
                'rustdpr_replay_summary_path': str(replay_summary),
                'rustdpr_replay_meta_path': str(replay_meta),
                'evidence_source': 'rustdpr_replay_per_input',
                'external_log_used_by_rustdpr': False,
                'raw_replay_failure_count': 0,
                'classification_forbidden': True,
                'notes': 'No cargo-fuzz inputs were available for candidate-level RustDPR replay.',
            }
        )
        write_json(replay_meta, new_meta)
        print('[done] no inputs to replay')
        return 0

    for record in records:
        input_path = Path(str(record['path'])).resolve()
        input_id = sanitize_id(str(record.get('input_id') or content_input_id(input_path, str(record.get('kind') or args.input_kind))))
        attempts: list[dict[str, Any]] = []
        for repeat_index in range(1, args.repeat + 1):
            run_id = (
                f"cargo-fuzz/{meta.get('crate')}/{target}/seed-{meta.get('seed')}/"
                f"run-{meta.get('run_index')}/{input_id}/replay-{repeat_index}"
            )
            trace_path = traces_dir / input_id / f'replay-{repeat_index:02d}.jsonl'
            log_path = logs_dir / input_id / f'replay-{repeat_index:02d}.log'
            attempt = run_replay(
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
            attempt['replay_index'] = repeat_index
            attempts.append(attempt)

        canonical = next(
            (
                attempt
                for attempt in attempts
                if int(attempt.get('return_code') or 0) != 0
                and int(attempt.get('trace_events') or 0) > 0
            ),
            next(
                (attempt for attempt in attempts if int(attempt.get('trace_events') or 0) > 0),
                attempts[0],
            ),
        )
        return_codes = [int(attempt.get('return_code') or 0) for attempt in attempts]
        reproduced = sum(1 for code in return_codes if code != 0)
        trace_attempts = sum(1 for attempt in attempts if int(attempt.get('trace_events') or 0) > 0)
        traced_reproduced = sum(
            1
            for attempt in attempts
            if int(attempt.get('return_code') or 0) != 0
            and int(attempt.get('trace_events') or 0) > 0
        )
        return_code_stable = len(set(return_codes)) == 1
        stable_reproduced = (
            reproduced == args.repeat
            and traced_reproduced == args.repeat
            and return_code_stable
        )
        replay_outcome = (
            'StableReproduced'
            if stable_reproduced
            else (
                'NotReproduced'
                if reproduced == 0
                else ('MissingTraceEvidence' if trace_attempts < args.repeat else 'Flaky')
            )
        )
        row = {
            **canonical,
            'kind': record.get('kind'),
            'sha256': record.get('sha256'),
            'replay_runs': args.repeat,
            'replay_passes': reproduced,
            'replay_failures': args.repeat - reproduced,
            'replay_stable': stable_reproduced,
            'return_code_stable': return_code_stable,
            'return_codes': return_codes,
            'trace_attempts': trace_attempts,
            'traced_reproduced_attempts': traced_reproduced,
            'replay_outcome': replay_outcome,
            'attempts': attempts,
        }
        canonical_trace_path = Path(str(canonical['trace_path']))
        row['debug_aggregate_events_before_append'] = trace_event_count(debug_combined_trace)
        row['debug_aggregate_appended_events'] = append_trace(canonical_trace_path, debug_combined_trace)

        individual_summary_path = per_input_summary_dir / f'{input_id}.json'
        individual_summary = {
            'schema_version': '0.2.0',
            'input_id': input_id,
            'input': str(input_path),
            'input_kind': record.get('kind'),
            'replay_runs': args.repeat,
            'replay_passes': reproduced,
            'replay_failures': args.repeat - reproduced,
            'replay_stable': stable_reproduced,
            'stable': stable_reproduced,
            'return_code_stable': return_code_stable,
            'return_codes': return_codes,
            'trace_attempts': trace_attempts,
            'traced_reproduced_attempts': traced_reproduced,
            'stability': replay_outcome,
            'trace_events': int(row.get('trace_events') or 0),
            'return_code': int(row.get('return_code') or 0),
            'log_path': row.get('log_path'),
            'canonical_trace_path': row.get('trace_path'),
            'attempts': attempts,
            'notes': (
                'replay_passes counts non-zero cargo-fuzz replays. replay_stable is true only '
                'when every attempt is non-zero, emits RustDPR trace evidence, and returns the '
                'same process exit code.'
            ),
        }
        write_json(individual_summary_path, individual_summary)

        candidate_meta = per_input_meta(
            source_meta=meta,
            record={**record, 'input_id': input_id, 'path': str(input_path)},
            row=row,
            replay_summary_path=individual_summary_path,
        )
        candidate_meta_path = per_input_meta_dir / f'{input_id}.json'
        write_json(candidate_meta_path, candidate_meta)
        row['candidate_meta_path'] = str(candidate_meta_path.resolve())
        row['candidate_replay_summary_path'] = str(individual_summary_path.resolve())
        rows.append(row)
        per_input_meta_paths.append(str(candidate_meta_path.resolve()))
        if reproduced > 0 and args.stop_after_first_nonzero:
            break

    debug_events = trace_event_count(debug_combined_trace)
    nonzero = sum(int(row.get('replay_passes') or 0) for row in rows)
    reproduced_candidates = sum(1 for row in rows if int(row.get('replay_passes') or 0) > 0)
    stable_candidates = sum(1 for row in rows if bool(row.get('replay_stable')))
    traced = sum(1 for row in rows if int(row.get('trace_events') or 0) > 0)
    summary = {
        'schema_version': '0.2.0',
        'evidence_source': 'rustdpr_replay_per_input',
        'external_log_used': False,
        'crate': meta.get('crate'),
        'crate_root': str(crate_root),
        'harness_id': target,
        'input_kind': args.input_kind,
        'toolchain': args.toolchain,
        'repeat_per_input': args.repeat,
        'total_inputs': len(records),
        'replayed_inputs': len(rows),
        'inputs_with_trace': traced,
        'nonzero_return_codes': nonzero,
        'reproduced_candidates': reproduced_candidates,
        'stable_reproduced_candidates': stable_candidates,
        'per_input_meta_paths': per_input_meta_paths,
        'debug_combined_trace_path': str(debug_combined_trace),
        'debug_combined_trace_events': debug_events,
        'status': 'ok' if traced > 0 else 'missing-rustdpr-trace',
        'rows': rows,
        'notes': [
            'Each candidate is classified from its own trace; cross-input trace concatenation is forbidden.',
            'debug_combined_trace_path is retained only for debugging and aggregate provenance.',
            'Replay logs are retained for provenance and optional ASan parsing; cargo-fuzz generation logs are not classification evidence.',
        ],
    }
    write_json(replay_summary, summary)

    aggregate_meta = dict(meta)
    aggregate_meta.update(
        {
            'trace_path': None,
            'rustdpr_trace_path': None,
            'rustdpr_replay_summary_path': str(replay_summary),
            'rustdpr_replay_meta_path': str(replay_meta),
            'evidence_source': 'rustdpr_replay_per_input',
            'external_log_used_by_rustdpr': False,
            'raw_replay_failure_count': nonzero,
            'replay_inputs_with_trace': traced,
            'replay_status': summary['status'],
            'per_input_meta_paths': per_input_meta_paths,
            'classification_forbidden': True,
            'classification_forbidden_reason': (
                'This aggregate metadata spans multiple inputs. Use per_input_meta_paths; '
                'never classify a concatenated trace.'
            ),
            'debug_combined_trace_path': str(debug_combined_trace),
            'notes': 'Aggregate replay metadata; not a candidate and not valid classification input.',
        }
    )
    write_json(replay_meta, aggregate_meta)
    print(f'[done] replayed {len(rows)} candidate input(s); per-input traces={traced}; meta={replay_meta}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
