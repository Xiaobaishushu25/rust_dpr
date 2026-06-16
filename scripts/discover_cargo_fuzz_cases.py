from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from common import ROOT_DIR, ensure_pyyaml, write_json

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None


def find_cases(search_roots: list[Path]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for root in search_roots:
        if not root.exists():
            continue
        for fuzz_targets in sorted(root.rglob('fuzz/fuzz_targets')):
            crate_root = fuzz_targets.parent.parent
            if crate_root in seen:
                continue
            seen.add(crate_root)
            if not (crate_root / 'Cargo.toml').exists():
                continue
            targets = [p.stem for p in sorted(fuzz_targets.glob('*.rs'))]
            if not targets:
                continue
            try:
                rel = crate_root.relative_to(ROOT_DIR)
                crate_root_str = str(rel).replace('\\', '/')
            except ValueError:
                crate_root_str = str(crate_root.resolve())
            cases.append({'crate': crate_root.name, 'crate_root': crate_root_str, 'targets': targets})
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description='Discover existing cargo-fuzz crates and write a matrix manifest.')
    parser.add_argument('--search-root', action='append', default=[], help='Directory to scan. Repeatable. Defaults to benchmarks/.')
    parser.add_argument('--out', default=str(ROOT_DIR / 'scripts' / 'cargo_fuzz_matrix.generated.yaml'))
    parser.add_argument('--seeds', default='1,2,3')
    parser.add_argument('--budget-seconds', type=int, default=60)
    parser.add_argument('--replay-limit', type=int, default=20)
    parser.add_argument('--input-kind', choices=['artifacts', 'corpus', 'all'], default='all')
    args = parser.parse_args()

    roots = [Path(x).resolve() if Path(x).is_absolute() else (ROOT_DIR / x).resolve() for x in args.search_root]
    if not roots:
        roots = [(ROOT_DIR / 'benchmarks').resolve()]
    cases = find_cases(roots)
    payload = {
        'defaults': {
            'crate_version': '0.1.0',
            'seeds': [int(x.strip()) for x in args.seeds.split(',') if x.strip()],
            'budget_seconds': args.budget_seconds,
            'replay_limit': args.replay_limit,
            'input_kind': args.input_kind,
            'include_deps': False,
            'skip_run_cargo_fuzz': False,
        },
        'cases': cases,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix.lower() == '.json':
        write_json(out, payload)
    else:
        ensure_pyyaml()
        assert yaml is not None
        with out.open('w', encoding='utf-8') as f:
            yaml.safe_dump(payload, f, sort_keys=False, allow_unicode=True)
    print(f'[done] discovered {len(cases)} cargo-fuzz case(s)')
    print(out)
    return 0 if cases else 1


if __name__ == '__main__':
    raise SystemExit(main())
