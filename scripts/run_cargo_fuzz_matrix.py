from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from common import ROOT_DIR, SUITES, ensure_pyyaml, read_json, write_json

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - handled at runtime
    yaml = None


@dataclass
class CaseSpec:
    crate: str
    crate_root: str
    crate_version: str = 'unknown'
    targets: list[str] = field(default_factory=list)
    seeds: list[int] = field(default_factory=lambda: [1])
    budget_seconds: int | None = None
    replay_limit: int | None = None
    replay_repeat: int | None = None
    input_kind: str | None = None
    include_deps: bool = False
    dep_crates: str = ''
    skip_run_cargo_fuzz: bool = False
    seed_corpus_root: str | None = None
    run_index: int = 1
    enabled: bool = True


def load_manifest(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    if path.suffix.lower() == '.json':
        return read_json(path)
    ensure_pyyaml()
    assert yaml is not None
    with path.open('r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f'manifest must be a mapping: {path}')
    return data


def as_list_of_int(value: Any, default: list[int]) -> list[int]:
    if value is None:
        return list(default)
    if isinstance(value, int):
        return [value]
    if isinstance(value, list):
        return [int(x) for x in value]
    raise ValueError(f'expected int or list[int], got {value!r}')


def as_list_of_str(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(x) for x in value]
    raise ValueError(f'expected str or list[str], got {value!r}')


def parse_cases(manifest: dict[str, Any]) -> tuple[dict[str, Any], list[CaseSpec]]:
    defaults = dict(manifest.get('defaults') or {})
    raw_cases = manifest.get('cases')
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError('manifest must contain a non-empty cases: [...] list')

    cases: list[CaseSpec] = []
    for idx, raw in enumerate(raw_cases, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f'case #{idx} must be a mapping')
        merged = {**defaults, **raw}
        crate = str(merged.get('crate') or merged.get('case') or '').strip()
        crate_root = str(merged.get('crate_root') or '').strip()
        if not crate:
            raise ValueError(f'case #{idx} is missing crate')
        if not crate_root:
            raise ValueError(f'case {crate!r} is missing crate_root')
        cases.append(
            CaseSpec(
                crate=crate,
                crate_root=crate_root,
                crate_version=str(merged.get('crate_version') or 'unknown'),
                targets=as_list_of_str(merged.get('targets') or merged.get('target')),
                seeds=as_list_of_int(merged.get('seeds') or merged.get('seed'), [int(defaults.get('seed', 1) or 1)]),
                budget_seconds=int(merged.get('budget_seconds')) if merged.get('budget_seconds') is not None else None,
                replay_limit=int(merged.get('replay_limit')) if merged.get('replay_limit') is not None else None,
                replay_repeat=int(merged.get('replay_repeat')) if merged.get('replay_repeat') is not None else None,
                input_kind=str(merged.get('input_kind')) if merged.get('input_kind') is not None else None,
                include_deps=bool(merged.get('include_deps', False)),
                dep_crates=str(merged.get('dep_crates') or ''),
                skip_run_cargo_fuzz=bool(merged.get('skip_run_cargo_fuzz', False)),
                seed_corpus_root=str(merged.get('seed_corpus_root')) if merged.get('seed_corpus_root') else None,
                run_index=int(merged.get('run_index', 1) or 1),
                enabled=bool(merged.get('enabled', True)),
            )
        )
    return defaults, cases



def suite_from_crate_root(crate_root: str) -> str | None:
    parts = crate_root.replace('\\', '/').split('/')
    for idx, part in enumerate(parts[:-1]):
        if part == 'benchmarks' and parts[idx + 1] in SUITES:
            return parts[idx + 1]
    return None


def infer_suite(manifest: dict[str, Any], cases: list[CaseSpec], explicit: str | None) -> str:
    if explicit:
        return explicit
    for value in (manifest.get('suite'), (manifest.get('defaults') or {}).get('suite')):
        if value:
            suite = str(value)
            if suite not in SUITES:
                raise ValueError(f'unsupported suite in manifest: {suite!r}; choices={SUITES}')
            return suite
    discovered = {suite_from_crate_root(c.crate_root) for c in cases}
    discovered.discard(None)
    if len(discovered) == 1:
        return discovered.pop()  # type: ignore[return-value]
    return 'generated_harness'

def py() -> str:
    return sys.executable or 'python3'


def rel_or_abs(path: str) -> str:
    p = Path(path)
    return str(p if p.is_absolute() else ROOT_DIR / p)


def add_targets(cmd: list[str], targets: list[str]) -> None:
    for target in targets:
        cmd.extend(['--target', target])


def run_cmd(cmd: list[str], *, dry_run: bool, continue_on_error: bool) -> tuple[bool, int, float]:
    print('$ ' + ' '.join(map(str, cmd)))
    if dry_run:
        return True, 0, 0.0
    start = time.time()
    proc = subprocess.run(cmd, cwd=ROOT_DIR)
    elapsed = time.time() - start
    ok = proc.returncode == 0
    if not ok and not continue_on_error:
        raise subprocess.CalledProcessError(proc.returncode, cmd)
    return ok, proc.returncode, elapsed


def run_logged_cmd(
    cmd: list[str],
    *,
    cwd: Path,
    log_path: Path,
    dry_run: bool,
    continue_on_error: bool,
) -> tuple[bool, int, float]:
    """Run a command with stdout/stderr captured in a stable per-case log.

    This is used by the build gate.  A structural preflight can succeed even
    when a historical crate version no longer resolves or compiles under the
    selected toolchain, so paper runs need a real cargo-fuzz build before any
    multi-hour campaign is scheduled.
    """
    print('$ ' + ' '.join(map(str, cmd)))
    print(f'  log: {log_path}')
    if dry_run:
        return True, 0, 0.0
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.time()
    with log_path.open('w', encoding='utf-8', errors='replace') as log:
        log.write('$ ' + ' '.join(map(str, cmd)) + '\n')
        log.write(f'cwd={cwd}\n\n')
        log.flush()
        proc = subprocess.run(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        log.write(f'\nRUSTDPR_BUILD_CHECK_RETURN_CODE={proc.returncode}\n')
    elapsed = time.time() - start
    ok = proc.returncode == 0
    if not ok and not continue_on_error:
        raise subprocess.CalledProcessError(proc.returncode, cmd)
    return ok, proc.returncode, elapsed


def record(
    summary: list[dict[str, Any]],
    *,
    case: CaseSpec | None,
    seed: int | None,
    phase: str,
    cmd: list[str] | None,
    ok: bool,
    return_code: int,
    elapsed: float,
    skipped: bool = False,
    reason: str | None = None,
) -> None:
    summary.append(
        {
            'case': case.crate if case else None,
            'crate_root': case.crate_root if case else None,
            'seed': seed,
            'phase': phase,
            'ok': ok,
            'return_code': return_code,
            'elapsed_seconds': elapsed,
            'skipped': skipped,
            'reason': reason,
            'command': cmd or [],
        }
    )


def case_root(case: CaseSpec) -> Path:
    return Path(rel_or_abs(case.crate_root)).resolve()


def fuzz_targets_dir(root: Path) -> Path:
    return root / 'fuzz' / 'fuzz_targets'


def discover_target_names(root: Path) -> list[str]:
    d = fuzz_targets_dir(root)
    if not d.exists():
        return []
    return [p.stem for p in sorted(d.glob('*.rs'))]


def preflight_case(case: CaseSpec, args: argparse.Namespace, summary: list[dict[str, Any]]) -> bool:
    root = case_root(case)
    reasons: list[str] = []
    if not root.exists():
        reasons.append(f'crate_root does not exist: {root}')
    elif not root.is_dir():
        reasons.append(f'crate_root is not a directory: {root}')
    else:
        if not (root / 'Cargo.toml').exists():
            reasons.append(f'crate_root has no Cargo.toml: {root}')
        d = fuzz_targets_dir(root)
        if not d.exists():
            reasons.append(f'no fuzz/fuzz_targets directory: {d}')
        else:
            available = discover_target_names(root)
            if case.targets:
                missing = [t for t in case.targets if t not in available]
                if missing:
                    reasons.append(f'missing target(s) {missing}; available={available}')
            elif not available:
                reasons.append(f'no fuzz target .rs files under {d}')
    ok = not reasons
    reason = '; '.join(reasons) if reasons else 'ok'
    record(summary, case=case, seed=None, phase='preflight', cmd=None, ok=ok, return_code=0 if ok else 2, elapsed=0.0, reason=reason)
    if ok:
        return True
    print(f'[preflight:error] {case.crate}: {reason}')
    if not args.continue_on_error:
        raise SystemExit(2)
    return False


def build_check_case(case: CaseSpec, args: argparse.Namespace, summary: list[dict[str, Any]]) -> bool:
    """Compile every selected fuzz target in its own fuzz workspace.

    The benchmark discovery manifest, not the repository's top-level Cargo
    workspace, is the source of truth for regression experiments.  Building
    from ``crate_root`` makes cargo-fuzz use ``fuzz/Cargo.toml`` and therefore
    keeps vulnerable/fixed dependency graphs isolated from one another.
    """
    root = case_root(case)
    targets = case.targets or discover_target_names(root)
    all_ok = True
    for target in targets:
        log_path = Path(args.build_check_log_root).resolve() / case.crate / f'{target}.log'
        cmd = ['cargo', f'+{args.toolchain}', 'fuzz', 'build', target]
        ok, rc, elapsed = run_logged_cmd(
            cmd,
            cwd=root,
            log_path=log_path,
            dry_run=args.dry_run,
            continue_on_error=args.continue_on_error,
        )
        record(
            summary,
            case=case,
            seed=None,
            phase='build-check',
            cmd=cmd,
            ok=ok,
            return_code=rc,
            elapsed=elapsed,
            reason=f'target={target}; log={log_path}',
        )
        if not ok:
            all_ok = False
            print(f'[build-check:error] {case.crate}/{target}: rc={rc}; log={log_path}')
    return all_ok


def campaign_log_dir(case: CaseSpec, seed: int) -> Path:
    return ROOT_DIR / 'reports' / 'cargo_fuzz_logs' / case.crate / f'seed-{seed}' / f'run-{case.run_index}'


def campaign_summary_path(case: CaseSpec, seed: int) -> Path:
    return campaign_log_dir(case, seed) / 'summary.json'


def campaign_root_for_case(case: CaseSpec, args: argparse.Namespace) -> Path:
    return Path(args.campaign_root).resolve() / case.crate


def seed_corpus_for_case(case: CaseSpec, args: argparse.Namespace) -> Path | None:
    raw = case.seed_corpus_root or args.seed_corpus_root
    if not raw:
        return None
    base = Path(rel_or_abs(raw)).resolve()
    case_specific = base / case.crate
    return case_specific if case_specific.exists() else base


def maybe_run_cargo_fuzz(case: CaseSpec, seed: int, args: argparse.Namespace, summary: list[dict[str, Any]]) -> bool:
    if args.skip_run_cargo_fuzz or case.skip_run_cargo_fuzz:
        print(f'[skip] cargo-fuzz run for {case.crate} seed={seed}; expecting an existing isolated run summary')
        record(summary, case=case, seed=seed, phase='run-cargo-fuzz', cmd=None, ok=True, return_code=0, elapsed=0.0, skipped=True, reason='skip_run_cargo_fuzz')
        return True
    budget = case.budget_seconds if case.budget_seconds is not None else args.budget_seconds
    cmd = [
        py(),
        'scripts/run_cargo_fuzz_pilot.py',
        '--crate-root',
        str(case_root(case)),
        '--budget-seconds',
        str(budget),
        '--seed',
        str(seed),
        '--run-index',
        str(case.run_index),
        '--campaign-root',
        str(campaign_root_for_case(case, args)),
        '--log-dir',
        str(campaign_log_dir(case, seed)),
        '--summary-json',
        str(campaign_summary_path(case, seed)),
    ]
    seed_corpus_root = seed_corpus_for_case(case, args)
    if seed_corpus_root is not None:
        cmd.extend(['--seed-corpus-root', str(seed_corpus_root)])
    add_targets(cmd, case.targets)
    ok, rc, elapsed = run_cmd(cmd, dry_run=args.dry_run, continue_on_error=args.continue_on_error)
    record(summary, case=case, seed=seed, phase='run-cargo-fuzz', cmd=cmd, ok=ok, return_code=rc, elapsed=elapsed)
    return ok


def collect_inputs(case: CaseSpec, seed: int, args: argparse.Namespace, summary: list[dict[str, Any]]) -> bool:
    budget = case.budget_seconds if case.budget_seconds is not None else args.budget_seconds
    run_summary = campaign_summary_path(case, seed)
    if not run_summary.exists() and not args.dry_run and not args.allow_legacy_shared_state:
        reason = (
            f'isolated run summary not found: {run_summary}. Re-run the fuzz phase, or use '
            '--allow-legacy-shared-state only for non-paper debugging.'
        )
        print(f'[error] {reason}')
        record(summary, case=case, seed=seed, phase='collect-inputs', cmd=None, ok=False, return_code=2, elapsed=0.0, reason=reason)
        return False
    cmd = [
        py(),
        'scripts/collect_cargo_fuzz_inputs.py',
        '--crate',
        case.crate,
        '--crate-version',
        case.crate_version,
        '--crate-root',
        str(case_root(case)),
        '--seed',
        str(seed),
        '--run-index',
        str(case.run_index),
        '--budget-seconds',
        str(budget),
        '--suite',
        args.suite,
    ]
    if run_summary.exists() or args.dry_run:
        cmd.extend(['--run-summary', str(run_summary)])
    add_targets(cmd, case.targets)
    ok, rc, elapsed = run_cmd(cmd, dry_run=args.dry_run, continue_on_error=args.continue_on_error)
    record(summary, case=case, seed=seed, phase='collect-inputs', cmd=cmd, ok=ok, return_code=rc, elapsed=elapsed)
    return ok


def validate_case(case: CaseSpec, seed: int, args: argparse.Namespace, summary: list[dict[str, Any]]) -> bool:
    input_kind = case.input_kind or args.input_kind
    replay_limit = case.replay_limit if case.replay_limit is not None else args.replay_limit
    replay_repeat = case.replay_repeat if case.replay_repeat is not None else args.replay_repeat
    cmd = [
        py(),
        'scripts/run_cargo_fuzz_rustdpr_batch.py',
        '--crate',
        case.crate,
        '--crate-root',
        str(case_root(case)),
        '--seed',
        str(seed),
        '--run-index',
        str(case.run_index),
        '--suite',
        args.suite,
        '--variant',
        args.variant,
        '--evidence-mode',
        args.evidence_mode,
        '--input-kind',
        input_kind,
        '--replay-repeat',
        str(replay_repeat),
        '--toolchain',
        args.toolchain,
    ]
    add_targets(cmd, case.targets)
    if replay_limit is not None:
        cmd.extend(['--replay-limit', str(replay_limit)])
    if case.include_deps or args.include_deps:
        cmd.append('--include-deps')
        dep_crates = case.dep_crates or args.dep_crates
        if dep_crates:
            cmd.extend(['--dep-crates', dep_crates])
    if args.allow_missing_independent_trace:
        cmd.append('--allow-missing-independent-trace')
    if args.asan_from_replay_log:
        cmd.append('--asan-from-replay-log')
    ok, rc, elapsed = run_cmd(cmd, dry_run=args.dry_run, continue_on_error=args.continue_on_error)
    record(summary, case=case, seed=seed, phase='rustdpr-validate', cmd=cmd, ok=ok, return_code=rc, elapsed=elapsed)
    return ok


def add_result_run_indices(cmd: list[str], args: argparse.Namespace) -> None:
    """Restrict post-processing to the run indices selected by this manifest."""
    for run_index in args.result_run_indices:
        cmd.extend(['--run-index', str(run_index)])


def materialize_baseline(args: argparse.Namespace, summary: list[dict[str, Any]]) -> bool:
    cmd = [
        py(),
        'scripts/materialize_external_baselines.py',
        '--suite',
        args.suite,
        '--source-tool',
        'cargo-fuzz',
        '--source-variant',
        args.variant,
        '--baseline',
        args.baseline,
        '--out-variant',
        args.baseline_variant,
    ]
    add_result_run_indices(cmd, args)
    ok, rc, elapsed = run_cmd(cmd, dry_run=args.dry_run, continue_on_error=args.continue_on_error)
    record(summary, case=None, seed=None, phase='materialize-baseline', cmd=cmd, ok=ok, return_code=rc, elapsed=elapsed)
    return ok


def compute_metrics(args: argparse.Namespace, summary: list[dict[str, Any]]) -> bool:
    cmd = [py(), 'scripts/compute_metrics.py', '--suite', args.suite, '--out', args.metrics_out]
    add_result_run_indices(cmd, args)
    if args.candidate_truth:
        cmd.extend(['--candidate-truth', args.candidate_truth])
    if args.allow_case_truth_for_candidates:
        cmd.append('--allow-case-truth-for-candidates')
    ok, rc, elapsed = run_cmd(cmd, dry_run=args.dry_run, continue_on_error=args.continue_on_error)
    record(summary, case=None, seed=None, phase='compute-metrics', cmd=cmd, ok=ok, return_code=rc, elapsed=elapsed)
    return ok


def compare(args: argparse.Namespace, summary: list[dict[str, Any]]) -> bool:
    cmd = [
        py(),
        'scripts/compare_pipelines.py',
        '--metrics',
        args.metrics_out,
        '--baseline',
        f'cargo-fuzz/{args.baseline_variant}',
        '--treatment',
        f'cargo-fuzz/{args.variant}',
        '--out-json',
        args.compare_json,
        '--out-csv',
        args.compare_csv,
        '--out-md',
        args.compare_md,
    ]
    ok, rc, elapsed = run_cmd(cmd, dry_run=args.dry_run, continue_on_error=args.continue_on_error)
    record(summary, case=None, seed=None, phase='compare', cmd=cmd, ok=ok, return_code=rc, elapsed=elapsed)
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description='Run a multi-case cargo-fuzz + RustDPR independent-replay experiment from a manifest.')
    parser.add_argument('--manifest', required=True, help='YAML/JSON file with defaults and cases')
    parser.add_argument('--suite', choices=SUITES, default=None, help='Benchmark suite for data/runs and metrics. Defaults to manifest.suite, defaults.suite, or inferred from benchmarks/<suite>/... crate_root.')
    parser.add_argument('--phase', choices=['all', 'preflight', 'build-check', 'run-fuzz', 'collect', 'validate', 'baseline', 'metrics', 'compare', 'postprocess'], default='all', help='build-check compiles every fuzz target independently; postprocess = baseline + metrics + compare')
    parser.add_argument('--variant', default='full')
    parser.add_argument('--baseline', default='crash-only')
    parser.add_argument('--baseline-variant', default='crash-only')
    parser.add_argument('--budget-seconds', type=int, default=300)
    parser.add_argument('--replay-limit', type=int, default=None)
    parser.add_argument('--replay-repeat', type=int, default=1, help='Replay each candidate N times; set 10 for final reproducibility results.')
    parser.add_argument('--input-kind', choices=['artifacts', 'corpus', 'all'], default='artifacts')
    parser.add_argument('--evidence-mode', choices=['rustdpr-replay', 'trace-file', 'empty-trace'], default='rustdpr-replay')
    parser.add_argument('--toolchain', default='nightly')
    parser.add_argument('--build-check-log-root', default=str(ROOT_DIR / 'reports' / 'cargo_fuzz_build_check'))
    parser.add_argument('--include-deps', action='store_true')
    parser.add_argument('--dep-crates', default='')
    parser.add_argument('--skip-run-cargo-fuzz', action='store_true')
    parser.add_argument('--campaign-root', default=str(ROOT_DIR / 'data' / 'cargo_fuzz_campaigns'))
    parser.add_argument('--seed-corpus-root', default=None, help='Optional immutable seed-corpus snapshot root; a <root>/<case> subdirectory is preferred when present.')
    parser.add_argument('--allow-legacy-shared-state', action='store_true', help='Allow collection from fuzz/artifacts and fuzz/corpus without an isolated run summary. Never use for paper results.')
    parser.add_argument('--allow-corpus-candidates', action='store_true', help='Allow corpus/all as the candidate universe. Off by default because crash-only and RustDPR must receive the same reported artifacts.')
    parser.add_argument('--asan-from-replay-log', action='store_true', help='Parse positive ASan findings from each cargo-fuzz replay log.')
    parser.add_argument('--candidate-truth', default=None, help='Candidate-level adjudicated truth CSV used by compute_metrics.py.')
    parser.add_argument('--allow-case-truth-for-candidates', action='store_true', help='Legacy/debug only: apply case-level expected.yaml truth to every candidate artifact.')
    parser.add_argument('--allow-missing-independent-trace', action='store_true')
    parser.add_argument('--collect-after-failed-fuzz', action='store_true', help='Collect/validate even when run-cargo-fuzz failed. Off by default to avoid cascaded path/env errors.')
    parser.add_argument('--limit-cases', type=int, default=None)
    parser.add_argument('--case', action='append', default=[], help='Only run selected crate/case names; repeatable')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--continue-on-error', action='store_true')
    parser.add_argument('--summary-out', default=None)
    parser.add_argument('--metrics-out', default=None)
    parser.add_argument('--compare-json', default=None)
    parser.add_argument('--compare-csv', default=None)
    parser.add_argument('--compare-md', default=None)
    args = parser.parse_args()

    if args.replay_repeat < 1:
        parser.error('--replay-repeat must be >= 1')

    manifest = load_manifest(Path(args.manifest))
    _, cases = parse_cases(manifest)
    args.suite = infer_suite(manifest, cases, args.suite)
    args.summary_out = args.summary_out or str(ROOT_DIR / 'reports' / f'cargo_fuzz_matrix_{args.suite}_summary.json')
    args.metrics_out = args.metrics_out or str(ROOT_DIR / 'reports' / f'metrics_{args.suite}_cargo_fuzz.json')
    args.compare_json = args.compare_json or str(ROOT_DIR / 'reports' / f'{args.suite}_cargo_fuzz_vs_rustdpr_delta.json')
    args.compare_csv = args.compare_csv or str(ROOT_DIR / 'reports' / f'{args.suite}_cargo_fuzz_vs_rustdpr_delta.csv')
    args.compare_md = args.compare_md or str(ROOT_DIR / 'reports' / f'{args.suite}_cargo_fuzz_vs_rustdpr_delta.md')
    cases = [c for c in cases if c.enabled]
    if args.case:
        wanted = set(args.case)
        cases = [c for c in cases if c.crate in wanted]
    if args.limit_cases is not None:
        cases = cases[: args.limit_cases]
    args.result_run_indices = sorted({case.run_index for case in cases})
    if not cases and args.phase not in {'baseline', 'metrics', 'compare', 'postprocess'}:
        print('[error] no enabled cases selected')
        return 2
    if not args.allow_corpus_candidates:
        invalid = [c.crate for c in cases if (c.input_kind or args.input_kind) != 'artifacts']
        if invalid:
            print(
                '[error] paper-facing cargo-fuzz comparison requires input_kind=artifacts so both '
                f'pipelines receive the same candidate universe. Invalid cases: {invalid}'
            )
            return 2

    summary: list[dict[str, Any]] = []
    selected = {
        'manifest': str(Path(args.manifest).resolve()),
        'phase': args.phase,
        'variant': args.variant,
        'baseline_variant': args.baseline_variant,
        'suite': args.suite,
        'campaign_root': str(Path(args.campaign_root).resolve()),
        'candidate_truth': args.candidate_truth,
        'candidate_universe': args.input_kind,
        'result_run_indices': args.result_run_indices,
        'cases': [c.__dict__ for c in cases],
        'started_at_unix': time.time(),
    }
    print(f'[matrix] result run-index filter: {args.result_run_indices or "<none>"}')
    print('[matrix] selected cases:')
    for c in cases:
        print(f'  - {c.crate}: root={c.crate_root}, targets={c.targets or "<discover>"}, seeds={c.seeds}')

    preflight_ok: dict[str, bool] = {}
    if args.phase not in {'baseline', 'metrics', 'compare', 'postprocess'}:
        for case in cases:
            preflight_ok[case.crate] = preflight_case(case, args, summary)
        if args.phase == 'preflight':
            payload = {'schema_version': '0.2.0', 'selection': selected, 'finished_at_unix': time.time(), 'ok': all(preflight_ok.values()), 'steps': summary}
            write_json(Path(args.summary_out), payload)
            failed = [row for row in summary if not row['ok']]
            print(f'[done] preflight cases={len(cases)} failed={len(failed)} summary={args.summary_out}')
            return 1 if failed else 0
        if args.phase == 'build-check':
            build_ok: dict[str, bool] = {}
            for case in cases:
                if not preflight_ok.get(case.crate, False):
                    build_ok[case.crate] = False
                    continue
                build_ok[case.crate] = build_check_case(case, args, summary)
            payload = {
                'schema_version': '0.2.0',
                'selection': selected,
                'finished_at_unix': time.time(),
                'ok': all(preflight_ok.values()) and all(build_ok.values()),
                'steps': summary,
            }
            write_json(Path(args.summary_out), payload)
            failed = [row for row in summary if not row['ok']]
            print(f'[done] build-check cases={len(cases)} failed_steps={len(failed)} summary={args.summary_out}')
            return 1 if failed else 0

    for case in cases:
        if preflight_ok and not preflight_ok.get(case.crate, True):
            print(f'[skip] {case.crate}: failed preflight')
            continue
        for seed in case.seeds:
            run_ok = True
            collect_ok = True
            if args.phase in {'all', 'run-fuzz'}:
                run_ok = maybe_run_cargo_fuzz(case, seed, args, summary)
            if args.phase in {'all', 'collect'}:
                if run_ok or args.collect_after_failed_fuzz or args.skip_run_cargo_fuzz or case.skip_run_cargo_fuzz:
                    collect_ok = collect_inputs(case, seed, args, summary)
                else:
                    record(summary, case=case, seed=seed, phase='collect-inputs', cmd=None, ok=True, return_code=0, elapsed=0.0, skipped=True, reason='skipped because run-cargo-fuzz failed')
                    collect_ok = False
            if args.phase in {'all', 'validate'}:
                if collect_ok:
                    validate_case(case, seed, args, summary)
                else:
                    record(summary, case=case, seed=seed, phase='rustdpr-validate', cmd=None, ok=True, return_code=0, elapsed=0.0, skipped=True, reason='skipped because collect-inputs did not run or failed')

    if args.phase in {'all', 'baseline', 'postprocess'}:
        materialize_baseline(args, summary)
    if args.phase in {'all', 'metrics', 'postprocess'}:
        compute_metrics(args, summary)
    if args.phase in {'all', 'compare', 'postprocess'}:
        compare(args, summary)

    payload = {'schema_version': '0.2.0', 'selection': selected, 'finished_at_unix': time.time(), 'ok': all(row['ok'] for row in summary), 'steps': summary}
    write_json(Path(args.summary_out), payload)
    failed = [row for row in summary if not row['ok']]
    print(f'[done] matrix steps={len(summary)} failed={len(failed)} summary={args.summary_out}')
    if failed:
        print('[failed steps]')
        for row in failed:
            print(f"  - case={row['case']} seed={row['seed']} phase={row['phase']} rc={row['return_code']} reason={row.get('reason') or ''}")
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
