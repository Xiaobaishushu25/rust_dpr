from __future__ import annotations

import argparse
import os
import re
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


def run_one(crate_root: Path, target: str, budget_seconds: int, seed: int, log_dir: Path, extra_args: list[str]) -> dict[str, object]:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f'{target}.log'
    cmd = [
        'cargo',
        '+nightly',
        'fuzz',
        'run',
        target,
        '--',
        f'-max_total_time={budget_seconds}',
        f'-seed={seed}',
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
    elapsed = time.time() - start
    return {
        'target': target,
        'command': cmd,
        'return_code': proc.returncode,
        'elapsed_seconds': elapsed,
        'log_path': str(log_path),
        'artifact_dir': str(crate_root / 'fuzz' / 'artifacts' / target),
        'corpus_dir': str(crate_root / 'fuzz' / 'corpus' / target),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Run official cargo-fuzz/libFuzzer targets for a short pilot and keep logs for RustDPR collection.'
    )
    parser.add_argument('--crate-root', required=True)
    parser.add_argument('--target', action='append', default=[], help='Fuzz target name. May be repeated. Defaults to all fuzz_targets/*.rs')
    parser.add_argument('--budget-seconds', type=int, default=300)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--log-dir', default=str(ROOT_DIR / 'reports' / 'cargo_fuzz_logs'))
    parser.add_argument('--summary-json', default=str(ROOT_DIR / 'reports' / 'cargo_fuzz_run_summary.json'))
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

    rows = [run_one(crate_root, t, args.budget_seconds, args.seed, Path(args.log_dir), extra) for t in targets]
    payload = {
        'schema_version': '0.1.0',
        'crate_root': str(crate_root),
        'budget_seconds': args.budget_seconds,
        'seed': args.seed,
        'targets': rows,
    }
    write_json(Path(args.summary_json), payload)
    print(f'[done] ran {len(rows)} cargo-fuzz target(s)')
    print(f'summary: {args.summary_json}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
