from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from common import ROOT_DIR, read_json


def iter_meta(external_root: Path, crate: str | None, seed: int | None) -> list[Path]:
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
        out.append(path)
    return out


def run_replay_for_meta(
    *,
    meta_path: Path,
    meta: dict,
    crate_root: Path,
    input_kind: str,
    replay_limit: int | None,
    toolchain: str,
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
    cmd = [
        'python3',
        'scripts/rustdpr_replay_inputs.py',
        '--meta',
        str(meta_path),
        '--crate-root',
        str(crate_root),
        '--out-dir',
        str(replay_dir),
        '--input-kind',
        input_kind,
        '--toolchain',
        toolchain,
    ]
    if replay_limit is not None:
        cmd.extend(['--limit', str(replay_limit)])
    print('$ ' + ' '.join(cmd))
    subprocess.run(cmd, cwd=ROOT_DIR, check=True)
    return replay_dir / 'run_meta.json'


def main() -> int:
    parser = argparse.ArgumentParser(description='Batch-run RustDPR validation on collected cargo-fuzz inputs using independent replay evidence by default.')
    parser.add_argument('--crate', default=None)
    parser.add_argument('--crate-root', required=True)
    parser.add_argument('--seed', type=int, default=None)
    parser.add_argument('--variant', default='full')
    parser.add_argument('--limit', type=int, default=None)
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
    parser.add_argument('--toolchain', default='nightly')
    parser.add_argument('--allow-missing-independent-trace', action='store_true')
    args = parser.parse_args()

    metas = iter_meta(Path(args.external_root), args.crate, args.seed)
    if args.limit is not None:
        metas = metas[: args.limit]
    if not metas:
        print('[error] no collected cargo-fuzz run_meta.json found. Run collect_cargo_fuzz_inputs.py first.')
        return 2

    crate_root = Path(args.crate_root).resolve()
    for idx, meta_path in enumerate(metas, start=1):
        original_meta = read_json(meta_path)
        meta_for_validation = meta_path
        if args.evidence_mode == 'rustdpr-replay':
            meta_for_validation = run_replay_for_meta(
                meta_path=meta_path,
                meta=original_meta,
                crate_root=crate_root,
                input_kind=args.input_kind,
                replay_limit=args.replay_limit,
                toolchain=args.toolchain,
            )

        meta = read_json(meta_for_validation)
        crate = str(meta.get('crate') or crate_root.name)
        harness_id = str(meta.get('harness_id') or f'target-{idx}')
        seed = int(meta.get('seed') or 0)
        run_index = int(meta.get('run_index') or idx)
        out_dir = ROOT_DIR / 'data' / 'runs' / 'generated_harness' / crate / 'cargo-fuzz' / args.variant / f'seed-{seed}' / f'run-{run_index}-{harness_id}'
        cmd = [
            'python3',
            'scripts/run_external_output.py',
            '--meta',
            str(meta_for_validation),
            '--crate-root',
            str(crate_root),
            '--out-dir',
            str(out_dir),
            '--tool-override',
            'cargo-fuzz',
            '--variant-override',
            args.variant,
            '--evidence-mode',
            args.evidence_mode,
        ]
        if args.allow_missing_independent_trace:
            cmd.append('--allow-missing-independent-trace')
        if meta.get('rustdpr_replay_summary_path'):
            cmd.extend(['--replay-summary', str(meta.get('rustdpr_replay_summary_path'))])
        if args.include_deps:
            cmd.append('--include-deps')
            if args.dep_crates:
                cmd.extend(['--dep-crates', args.dep_crates])
        print('$ ' + ' '.join(cmd))
        subprocess.run(cmd, cwd=ROOT_DIR, check=True)

    print(f'[done] validated {len(metas)} cargo-fuzz run(s) with RustDPR evidence_mode={args.evidence_mode}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
