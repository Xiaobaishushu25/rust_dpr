from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from common import ROOT_DIR


def run(cmd: list[str]) -> None:
    print('$ ' + ' '.join(map(str, cmd)))
    subprocess.run(cmd, cwd=ROOT_DIR, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description='End-to-end cargo-fuzz baseline comparison using RustDPR independent replay evidence, not cargo-fuzz logs.'
    )
    parser.add_argument('--crate', required=True)
    parser.add_argument('--crate-version', default='unknown')
    parser.add_argument('--crate-root', required=True)
    parser.add_argument('--target', action='append', default=[], help='cargo-fuzz target; repeatable. Defaults to all targets')
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--run-index', type=int, default=1)
    parser.add_argument('--budget-seconds', type=int, default=300)
    parser.add_argument('--variant', default='full')
    parser.add_argument('--input-kind', choices=['artifacts', 'corpus', 'all'], default='artifacts')
    parser.add_argument('--replay-limit', type=int, default=None)
    parser.add_argument('--toolchain', default='nightly')
    parser.add_argument('--include-deps', action='store_true')
    parser.add_argument('--dep-crates', default='')
    parser.add_argument('--skip-run-cargo-fuzz', action='store_true', help='Use existing fuzz/artifacts and fuzz/corpus directories')
    args = parser.parse_args()

    targets: list[str] = args.target

    if not args.skip_run_cargo_fuzz:
        cmd = [
            'python3',
            'scripts/run_cargo_fuzz_pilot.py',
            '--crate-root',
            args.crate_root,
            '--budget-seconds',
            str(args.budget_seconds),
            '--seed',
            str(args.seed),
        ]
        for target in targets:
            cmd.extend(['--target', target])
        run(cmd)

    collect_cmd = [
        'python3',
        'scripts/collect_cargo_fuzz_inputs.py',
        '--crate',
        args.crate,
        '--crate-version',
        args.crate_version,
        '--crate-root',
        args.crate_root,
        '--seed',
        str(args.seed),
        '--run-index',
        str(args.run_index),
        '--budget-seconds',
        str(args.budget_seconds),
    ]
    for target in targets:
        collect_cmd.extend(['--target', target])
    run(collect_cmd)

    batch_cmd = [
        'python3',
        'scripts/run_cargo_fuzz_rustdpr_batch.py',
        '--crate',
        args.crate,
        '--crate-root',
        args.crate_root,
        '--seed',
        str(args.seed),
        '--variant',
        args.variant,
        '--evidence-mode',
        'rustdpr-replay',
        '--input-kind',
        args.input_kind,
        '--toolchain',
        args.toolchain,
    ]
    if args.replay_limit is not None:
        batch_cmd.extend(['--replay-limit', str(args.replay_limit)])
    if args.include_deps:
        batch_cmd.append('--include-deps')
        if args.dep_crates:
            batch_cmd.extend(['--dep-crates', args.dep_crates])
    run(batch_cmd)

    run(
        [
            'python3',
            'scripts/materialize_external_baselines.py',
            '--suite',
            'generated_harness',
            '--source-tool',
            'cargo-fuzz',
            '--source-variant',
            args.variant,
            '--baseline',
            'crash-only',
            '--out-variant',
            'crash-only',
        ]
    )
    run(['python3', 'scripts/compute_metrics.py', '--suite', 'generated_harness', '--out', 'reports/metrics_generated_harness.json'])
    run(
        [
            'python3',
            'scripts/compare_pipelines.py',
            '--metrics',
            'reports/metrics_generated_harness.json',
            '--baseline',
            'cargo-fuzz/crash-only',
            '--treatment',
            f'cargo-fuzz/{args.variant}',
            '--out-json',
            'reports/cargo_fuzz_vs_rustdpr_delta.json',
            '--out-csv',
            'reports/cargo_fuzz_vs_rustdpr_delta.csv',
            '--out-md',
            'reports/cargo_fuzz_vs_rustdpr_delta.md',
        ]
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
