from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from common import ROOT_DIR, SUITES, read_json, write_json


def sanitize_path_component(value: str) -> str:
    value = value.strip().replace('\\', '/')
    value = value.rsplit('/', 1)[-1]
    value = re.sub(r'[^A-Za-z0-9_.-]+', '-', value)
    return value.strip('-') or 'candidate'


def iter_meta(
    external_root: Path,
    crate: str | None,
    seed: int | None,
    run_index: int | None,
    targets: set[str],
    suite: str | None,
) -> list[Path]:
    paths = sorted(external_root.rglob('run_meta.json'))
    out: list[Path] = []
    for path in paths:
        meta = read_json(path)
        if meta.get('tool') != 'cargo-fuzz':
            continue
        if crate and meta.get('crate') != crate:
            continue
        if seed is not None and int(meta.get('seed') or -1) != seed:
            continue
        if run_index is not None and int(meta.get('run_index') or -1) != run_index:
            continue
        if targets and str(meta.get('harness_id') or '') not in targets:
            continue
        if suite and str(meta.get('suite') or '') != suite:
            continue
        out.append(path)
    return out


def run_replay_for_meta(
    *,
    meta_path: Path,
    meta: dict[str, Any],
    crate_root: Path,
    input_kind: str,
    replay_limit: int | None,
    replay_repeat: int,
    toolchain: str,
    keep_existing_replay: bool,
) -> Path:
    crate = str(meta.get('crate') or crate_root.name)
    harness_id = str(meta.get('harness_id') or 'target')
    seed = int(meta.get('seed') or 0)
    run_index = int(meta.get('run_index') or 1)
    replay_dir = (
        ROOT_DIR
        / 'data'
        / 'external_replays'
        / 'cargo-fuzz'
        / crate
        / harness_id
        / f'seed-{seed}'
        / f'run-{run_index}'
    )
    if replay_dir.exists() and not keep_existing_replay:
        shutil.rmtree(replay_dir)
    cmd = [
        sys.executable,
        'scripts/rustdpr_replay_inputs.py',
        '--meta',
        str(meta_path),
        '--crate-root',
        str(crate_root),
        '--out-dir',
        str(replay_dir),
        '--input-kind',
        input_kind,
        '--repeat',
        str(replay_repeat),
        '--toolchain',
        toolchain,
    ]
    if replay_limit is not None:
        cmd.extend(['--limit', str(replay_limit)])
    print('$ ' + ' '.join(cmd))
    subprocess.run(cmd, cwd=ROOT_DIR, check=True)
    return replay_dir / 'run_meta.json'


def campaign_output_root(
    *,
    suite: str,
    variant: str,
    meta: dict[str, Any],
    crate_root: Path,
    ordinal: int,
) -> Path:
    crate = str(meta.get('crate') or crate_root.name)
    harness_id = sanitize_path_component(str(meta.get('harness_id') or f'target-{ordinal}'))
    seed = int(meta.get('seed') or 0)
    run_index = int(meta.get('run_index') or ordinal)
    return (
        ROOT_DIR
        / 'data'
        / 'runs'
        / suite
        / crate
        / 'cargo-fuzz'
        / variant
        / harness_id
        / f'seed-{seed}'
        / f'run-{run_index}'
    )


def write_campaign_record(
    *,
    campaign_out_root: Path,
    meta_path: Path,
    meta: dict[str, Any],
    suite: str,
    variant: str,
    candidate_count: int,
) -> Path:
    """Persist one campaign observation even when libFuzzer produced no artifact.

    Candidate-level rows alone cannot represent zero-artifact campaigns. Without
    this record, CPU-hour/yield denominators silently omit unsuccessful seeds.
    """
    campaign_out_root.mkdir(parents=True, exist_ok=True)
    record_path = campaign_out_root / 'campaign_record.json'
    write_json(
        record_path,
        {
            'schema_version': '0.1.0',
            'unit_of_analysis': 'campaign',
            'suite': suite,
            'case': meta.get('case') or meta.get('crate'),
            'crate': meta.get('crate'),
            'tool': 'cargo-fuzz',
            'variant': variant,
            'mode': 'external-output-campaign',
            'harness_id': meta.get('harness_id'),
            'seed': int(meta.get('seed') or 0),
            'run_index': int(meta.get('run_index') or 1),
            'campaign_id': meta.get('campaign_id'),
            'campaign_budget_seconds': meta.get(
                'campaign_budget_seconds', meta.get('fuzz_budget_seconds', 0)
            ),
            'raw_crash_count': int(meta.get('raw_crash_count') or 0),
            'raw_panic_count': int(meta.get('raw_panic_count') or 0),
            'candidate_count': candidate_count,
            'producer_status': meta.get('producer_status'),
            'producer_ok': meta.get('producer_ok'),
            'producer_return_code': meta.get('producer_return_code'),
            'producer_elapsed_seconds': meta.get('producer_elapsed_seconds'),
            'producer_log_path': meta.get('producer_log_path'),
            'collected_corpus_count': len(meta.get('corpus_inputs') or []),
            'source_meta_path': str(meta_path.resolve()),
            'artifact_dir': meta.get('artifact_dir'),
            'corpus_dir': meta.get('corpus_dir'),
        },
    )
    return record_path


def candidate_meta_paths(replay_meta_path: Path, *, evidence_mode: str) -> list[Path]:
    if evidence_mode != 'rustdpr-replay':
        return [replay_meta_path]

    replay_meta = read_json(replay_meta_path)
    if not replay_meta.get('classification_forbidden'):
        raise RuntimeError(
            'candidate-level replay metadata was expected, but the aggregate replay meta was not '
            'marked classification_forbidden. Refusing to risk cross-input trace contamination.'
        )
    paths = [Path(str(path)).resolve() for path in (replay_meta.get('per_input_meta_paths') or [])]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise RuntimeError('candidate replay metadata is missing: ' + ', '.join(missing))
    return paths


def validate_candidate_meta(meta: dict[str, Any], path: Path) -> None:
    if meta.get('classification_forbidden'):
        raise RuntimeError(f'aggregate metadata must not be classified: {path}')
    if meta.get('unit_of_analysis') != 'candidate':
        raise RuntimeError(f'candidate metadata is missing unit_of_analysis=candidate: {path}')
    input_files = list(meta.get('input_files') or [])
    if len(input_files) != 1:
        raise RuntimeError(f'candidate metadata must contain exactly one input file: {path}')
    if not meta.get('input_id'):
        raise RuntimeError(f'candidate metadata is missing input_id: {path}')


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            'Batch-run RustDPR validation on collected cargo-fuzz artifacts. In rustdpr-replay '
            'mode, each artifact is classified independently from its own trace.'
        )
    )
    parser.add_argument('--crate', default=None)
    parser.add_argument('--crate-root', required=True)
    parser.add_argument('--suite', choices=SUITES, default='generated_harness', help='Benchmark suite for data/runs output and classification metadata.')
    parser.add_argument('--seed', type=int, default=None)
    parser.add_argument('--run-index', type=int, default=None)
    parser.add_argument('--target', action='append', default=[], help='Only validate selected cargo-fuzz target(s). Repeatable.')
    parser.add_argument('--variant', default='full')
    parser.add_argument('--limit', type=int, default=None, help='Limit collected campaign metadata files, not candidate inputs.')
    parser.add_argument('--external-root', default=str(ROOT_DIR / 'data' / 'external_runs' / 'cargo-fuzz'))
    parser.add_argument('--include-deps', action='store_true')
    parser.add_argument('--dep-crates', default='')
    parser.add_argument(
        '--evidence-mode',
        choices=['rustdpr-replay', 'trace-file', 'empty-trace'],
        default='rustdpr-replay',
        help='Default rustdpr-replay re-executes cargo-fuzz inputs and uses only RustDPR trace evidence.',
    )
    parser.add_argument('--input-kind', choices=['artifacts', 'corpus', 'all'], default='artifacts')
    parser.add_argument('--replay-limit', type=int, default=None)
    parser.add_argument('--replay-repeat', type=int, default=1, help='Replay each candidate N times; use 10 for final reproducibility results.')
    parser.add_argument('--toolchain', default='nightly')
    parser.add_argument('--allow-missing-independent-trace', action='store_true')
    parser.add_argument(
        '--asan-from-replay-log',
        action='store_true',
        help=(
            'Pass each cargo-fuzz replay log to the ASan parser. Positive sanitizer findings become '
            'oracle evidence; absence of a finding is never used as negative ground truth.'
        ),
    )
    parser.add_argument(
        '--keep-existing-output',
        action='store_true',
        help='Do not clean existing replay and campaign output directories before classification.',
    )
    args = parser.parse_args()

    if args.replay_repeat < 1:
        parser.error('--replay-repeat must be >= 1')

    if args.evidence_mode == 'rustdpr-replay' and args.input_kind != 'artifacts':
        print(
            '[error] paper-facing cargo-fuzz triage must classify the same reported artifact set as '
            'the crash-only baseline. Use --input-kind artifacts. Corpus analysis is a separate search-state experiment.'
        )
        return 2

    metas = iter_meta(
        Path(args.external_root),
        args.crate,
        args.seed,
        args.run_index,
        {str(x) for x in args.target},
        args.suite,
    )
    if args.limit is not None:
        metas = metas[: args.limit]
    if not metas:
        print('[error] no collected cargo-fuzz run_meta.json found. Run collect_cargo_fuzz_inputs.py first.')
        return 2

    crate_root = Path(args.crate_root).resolve()
    validated_candidates = 0
    campaigns_without_candidates = 0

    for idx, meta_path in enumerate(metas, start=1):
        original_meta = read_json(meta_path)
        if original_meta.get('producer_ok') is False or original_meta.get('producer_status') == 'failed-no-artifact':
            print(
                f"[error] refusing to validate failed cargo-fuzz campaign: "
                f"{original_meta.get('crate')} / {original_meta.get('harness_id')} / "
                f"seed={original_meta.get('seed')} status={original_meta.get('producer_status')} "
                f"rc={original_meta.get('producer_return_code')} log={original_meta.get('producer_log_path')}"
            )
            return 2
        campaign_out_root = campaign_output_root(
            suite=args.suite,
            variant=args.variant,
            meta=original_meta,
            crate_root=crate_root,
            ordinal=idx,
        )
        if campaign_out_root.exists() and not args.keep_existing_output:
            shutil.rmtree(campaign_out_root)

        replay_meta_path = meta_path
        if args.evidence_mode == 'rustdpr-replay':
            replay_meta_path = run_replay_for_meta(
                meta_path=meta_path,
                meta=original_meta,
                crate_root=crate_root,
                input_kind=args.input_kind,
                replay_limit=args.replay_limit,
                replay_repeat=args.replay_repeat,
                toolchain=args.toolchain,
                keep_existing_replay=args.keep_existing_output,
            )

        paths = candidate_meta_paths(replay_meta_path, evidence_mode=args.evidence_mode)
        write_campaign_record(
            campaign_out_root=campaign_out_root,
            meta_path=meta_path,
            meta=original_meta,
            suite=args.suite,
            variant=args.variant,
            candidate_count=len(paths),
        )
        if not paths:
            campaigns_without_candidates += 1
            print(
                f"[info] zero-artifact campaign (valid for artifact-only triage): "
                f"{original_meta.get('crate')} / {original_meta.get('harness_id')} / "
                f"seed={original_meta.get('seed')} producer_status={original_meta.get('producer_status') or 'legacy-unknown'} "
                f"producer_rc={original_meta.get('producer_return_code')} "
                f"corpus_inputs={len(original_meta.get('corpus_inputs') or [])}"
            )
            continue

        for candidate_meta_path in paths:
            candidate_meta = read_json(candidate_meta_path)
            if args.evidence_mode == 'rustdpr-replay':
                validate_candidate_meta(candidate_meta, candidate_meta_path)
            input_id = sanitize_path_component(str(candidate_meta.get('input_id') or candidate_meta_path.stem))
            out_dir = campaign_out_root / input_id
            cmd = [
                sys.executable,
                'scripts/run_external_output.py',
                '--meta',
                str(candidate_meta_path),
                '--crate-root',
                str(crate_root),
                '--out-dir',
                str(out_dir),
                '--suite',
                args.suite,
                '--tool-override',
                'cargo-fuzz',
                '--variant-override',
                args.variant,
                '--evidence-mode',
                args.evidence_mode,
            ]
            if args.allow_missing_independent_trace:
                cmd.append('--allow-missing-independent-trace')
            replay_summary = candidate_meta.get('rustdpr_replay_summary_path')
            if replay_summary:
                cmd.extend(['--replay-summary', str(replay_summary)])
            if args.asan_from_replay_log and candidate_meta.get('replay_log_path'):
                cmd.extend(['--asan-log', str(candidate_meta['replay_log_path'])])
            if args.include_deps:
                cmd.append('--include-deps')
                if args.dep_crates:
                    cmd.extend(['--dep-crates', args.dep_crates])
            print('$ ' + ' '.join(cmd))
            subprocess.run(cmd, cwd=ROOT_DIR, check=True)
            validated_candidates += 1

    print(
        f'[done] validated {validated_candidates} cargo-fuzz candidate artifact(s) from {len(metas)} campaign(s); '
        f'campaigns_without_candidates={campaigns_without_candidates}; evidence_mode={args.evidence_mode}'
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
