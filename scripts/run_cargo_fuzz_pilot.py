from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from common import ROOT_DIR, write_json


def sanitize_id(value: str) -> str:
    value = value.strip().replace('\\', '/')
    value = value.rsplit('/', 1)[-1]
    value = re.sub(r'[^A-Za-z0-9_.-]+', '-', value)
    return value.strip('-') or 'target'


def discover_targets(crate_root: Path, explicit: list[str]) -> list[str]:
    if explicit:
        return [sanitize_id(x) for x in explicit]
    fuzz_targets = crate_root / 'fuzz' / 'fuzz_targets'
    return [p.stem for p in sorted(fuzz_targets.glob('*.rs'))]


def file_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for candidate in path.rglob('*') if candidate.is_file())


def producer_status(*, return_code: int, artifact_count: int) -> tuple[str, bool]:
    """Classify cargo-fuzz completion without treating a discovered crash as a wrapper failure.

    libFuzzer normally exits non-zero after saving a crash artifact. That is a
    successful fuzzing outcome for this producer stage. A non-zero exit with no
    freshly-created artifact, however, usually indicates build/tool/runtime failure
    and must not be silently converted into a zero-candidate campaign.
    """
    if artifact_count > 0:
        return 'completed-with-artifact', True
    if return_code == 0:
        return 'completed-no-artifact', True
    return 'failed-no-artifact', False


def copy_seed_corpus(seed_root: Path | None, target: str, corpus_dir: Path) -> int:
    """Copy a read-only seed snapshot into one isolated campaign corpus.

    The normal ``fuzz/corpus/<target>`` directory is deliberately *not* used as
    an implicit seed source because cargo-fuzz writes newly discovered inputs
    back to the first corpus directory. Reusing that directory across seeds
    makes later seeds inherit earlier discoveries and breaks independence.
    """
    if seed_root is None:
        return 0

    candidates = [seed_root / target, seed_root]
    source = next((path for path in candidates if path.exists() and path.is_dir()), None)
    if source is None:
        return 0

    copied = 0
    for src in sorted(source.rglob('*')):
        if not src.is_file():
            continue
        rel = src.relative_to(source)
        dst = corpus_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied += 1
    return copied


def run_one(
    crate_root: Path,
    target: str,
    budget_seconds: int,
    seed: int,
    run_index: int,
    log_dir: Path,
    campaign_root: Path,
    seed_corpus_root: Path | None,
    keep_campaign: bool,
    extra_args: list[str],
) -> dict[str, object]:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f'{target}.log'

    campaign_dir = campaign_root / target / f'seed-{seed}' / f'run-{run_index}'
    if campaign_dir.exists() and not keep_campaign:
        shutil.rmtree(campaign_dir)
    corpus_dir = campaign_dir / 'corpus'
    artifact_dir = campaign_dir / 'artifacts'
    corpus_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    initial_corpus_files = copy_seed_corpus(seed_corpus_root, target, corpus_dir)

    # The experiment owns the artifact prefix. Allowing a second user-provided
    # prefix would silently split outputs and make collection incomplete.
    conflicting = [arg for arg in extra_args if arg.startswith('-artifact_prefix=')]
    if conflicting:
        raise ValueError(
            'do not pass -artifact_prefix through libfuzzer_args; '
            'run_cargo_fuzz_pilot.py assigns an isolated prefix per seed/run'
        )

    cmd = [
        'cargo',
        '+nightly',
        'fuzz',
        'run',
        target,
        str(corpus_dir),
        '--',
        f'-max_total_time={budget_seconds}',
        f'-seed={seed}',
        f'-artifact_prefix={artifact_dir}{os.sep}',
        '-print_final_stats=1',
        *extra_args,
    ]
    start = time.time()
    env = dict(os.environ)
    with log_path.open('w', encoding='utf-8', errors='replace') as log:
        log.write('$ ' + ' '.join(cmd) + '\n')
        log.flush()
        proc = subprocess.run(cmd, cwd=crate_root, stdout=log, stderr=subprocess.STDOUT, env=env)
        log.write(f'\nRUSTDPR_CARGO_FUZZ_RETURN_CODE={proc.returncode}\n')
    finished = time.time()
    elapsed = finished - start
    artifact_count = file_count(artifact_dir)
    corpus_count = file_count(corpus_dir)
    status, ok = producer_status(return_code=proc.returncode, artifact_count=artifact_count)
    return {
        'campaign_id': f'{sanitize_id(crate_root.name)}/{target}/seed-{seed}/run-{run_index}',
        'started_at_unix': start,
        'finished_at_unix': finished,
        'campaign_dir': str(campaign_dir.resolve()),
        'target': target,
        'command': cmd,
        'return_code': proc.returncode,
        'status': status,
        'ok': ok,
        'elapsed_seconds': elapsed,
        'log_path': str(log_path),
        'artifact_dir': str(artifact_dir.resolve()),
        'corpus_dir': str(corpus_dir.resolve()),
        'initial_corpus_files': initial_corpus_files,
        'artifact_count': artifact_count,
        'corpus_count': corpus_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Run official cargo-fuzz/libFuzzer targets for a short pilot and keep logs for RustDPR collection.'
    )
    parser.add_argument('--crate-root', required=True)
    parser.add_argument('--target', action='append', default=[], help='Fuzz target name. May be repeated. Defaults to all fuzz_targets/*.rs')
    parser.add_argument('--budget-seconds', type=int, default=300)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--run-index', type=int, default=1)
    parser.add_argument('--log-dir', default=str(ROOT_DIR / 'reports' / 'cargo_fuzz_logs'))
    parser.add_argument('--summary-json', default=str(ROOT_DIR / 'reports' / 'cargo_fuzz_run_summary.json'))
    parser.add_argument(
        '--campaign-root',
        default=None,
        help=(
            'Root for isolated corpus/artifact state. Defaults to '
            'data/cargo_fuzz_campaigns/<crate-name>. Each target/seed/run gets a clean directory.'
        ),
    )
    parser.add_argument(
        '--seed-corpus-root',
        default=None,
        help=(
            'Optional immutable seed snapshot. The script first looks for <root>/<target>, '
            'then <root>. It never implicitly reuses fuzz/corpus/<target>.'
        ),
    )
    parser.add_argument(
        '--keep-campaign',
        action='store_true',
        help='Reuse an existing isolated campaign directory. Off by default for independent paper runs.',
    )
    parser.add_argument('libfuzzer_args', nargs='*', help='Extra libFuzzer args after a literal --, e.g. -- -rss_limit_mb=4096')
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
    targets = discover_targets(crate_root, args.target)
    if not targets:
        print(f'[error] no cargo-fuzz targets found under {crate_root / "fuzz" / "fuzz_targets"}')
        return 2

    extra = list(args.libfuzzer_args)
    if extra and extra[0] == '--':
        extra = extra[1:]

    campaign_root = (
        Path(args.campaign_root).resolve()
        if args.campaign_root
        else (ROOT_DIR / 'data' / 'cargo_fuzz_campaigns' / sanitize_id(crate_root.name)).resolve()
    )
    seed_corpus_root = Path(args.seed_corpus_root).resolve() if args.seed_corpus_root else None

    try:
        rows = [
            run_one(
                crate_root,
                target,
                args.budget_seconds,
                args.seed,
                args.run_index,
                Path(args.log_dir),
                campaign_root,
                seed_corpus_root,
                args.keep_campaign,
                extra,
            )
            for target in targets
        ]
    except ValueError as exc:
        print(f'[error] {exc}')
        return 2
    failed_rows = [row for row in rows if not bool(row.get('ok'))]
    payload = {
        'schema_version': '0.2.0',
        'crate_root': str(crate_root),
        'budget_seconds': args.budget_seconds,
        'seed': args.seed,
        'run_index': args.run_index,
        'campaign_root': str(campaign_root),
        'seed_corpus_root': str(seed_corpus_root) if seed_corpus_root else None,
        'campaign_isolation': True,
        'ok': not failed_rows,
        'failed_targets': [str(row.get('target')) for row in failed_rows],
        'targets': rows,
    }
    write_json(Path(args.summary_json), payload)
    for row in rows:
        print(
            f"[campaign] target={row.get('target')} status={row.get('status')} "
            f"rc={row.get('return_code')} artifacts={row.get('artifact_count')} "
            f"corpus={row.get('corpus_count')}"
        )
    print(f'[done] ran {len(rows)} cargo-fuzz target(s); failed={len(failed_rows)}')
    print(f'summary: {args.summary_json}')
    return 1 if failed_rows else 0


if __name__ == '__main__':
    raise SystemExit(main())
