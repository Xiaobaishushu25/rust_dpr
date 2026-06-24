from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any

from common import read_json


COLUMNS = [
    'suite',
    'pipeline',
    'campaigns',
    'unique_candidates',
    'truth_coverage',
    'mcp',
    'panic_noise_fpr',
    'review_load',
    'review_queue_recall',
    'oracle_confirmed_per_review_queue',
    'reproducibility_rate',
    'wdpc_mean',
    'missing_evidence',
]


def parse_metric_arg(value: str) -> tuple[str, Path]:
    if '=' not in value:
        raise argparse.ArgumentTypeError('expected SUITE=PATH')
    suite, raw_path = value.split('=', 1)
    suite = suite.strip()
    path = Path(raw_path).resolve()
    if not suite or not path.exists():
        raise argparse.ArgumentTypeError(f'invalid metrics argument: {value!r}')
    return suite, path


def group(metrics: dict[str, Any], key: str) -> dict[str, Any]:
    groups = metrics.get('by_tool_variant') or {}
    if key not in groups:
        raise RuntimeError(f'metric group {key!r} not found; available={sorted(groups)}')
    return groups[key]


def ratio_cell(values: dict[str, Any], metric: str) -> str:
    value = values.get(metric)
    support = (values.get('support') or {}).get(metric) or {}
    num = support.get('numerator')
    den = support.get('denominator')
    if value is None:
        return 'n/a'
    if num is not None and den is not None:
        return f'{float(value):.3f} ({num}/{den})'
    return f'{float(value):.3f}'


def build_row(suite: str, pipeline: str, values: dict[str, Any]) -> dict[str, Any]:
    coverage = values.get('candidate_truth_coverage')
    wdpc = values.get('wdpc_mean') if suite in {'regression', 'realworld', 'generated_harness'} else None
    return {
        'suite': suite,
        'pipeline': pipeline,
        'campaigns': values.get('campaigns_represented', 0),
        'unique_candidates': values.get('unique_candidates', values.get('total_runs', 0)),
        'truth_coverage': 'n/a' if coverage is None else ratio_cell(values, 'candidate_truth_coverage'),
        'mcp': ratio_cell(values, 'mcp'),
        'panic_noise_fpr': ratio_cell(values, 'panic_noise_fpr'),
        'review_load': ratio_cell(values, 'review_load'),
        'review_queue_recall': ratio_cell(values, 'review_queue_recall'),
        'oracle_confirmed_per_review_queue': ratio_cell(values, 'oracle_confirmed_per_review_queue'),
        'reproducibility_rate': ratio_cell(values, 'reproducibility_rate'),
        'wdpc_mean': '—' if wdpc is None else f'{float(wdpc):.3f}',
        'missing_evidence': values.get('missing_evidence_runs', 0),
    }


def markdown(rows: list[dict[str, Any]]) -> str:
    headers = [
        'Suite', 'Pipeline', '#Campaigns', '#Unique', 'Truth Cov.', 'MCP ↑', 'Noise FPR ↓',
        'Review Load ↓', 'Recall ↑', 'Oracle/Review ↑', 'Replay Stable ↑', 'wDPC ↑', 'Missing',
    ]
    lines = [
        '| ' + ' | '.join(headers) + ' |',
        '|' + '|'.join(['---'] * len(headers)) + '|',
    ]
    for row in rows:
        lines.append('| ' + ' | '.join(str(row[key]) for key in COLUMNS) + ' |')
    return '\n'.join(lines) + '\n'


def latex_escape(value: Any) -> str:
    text = str(value)
    return (
        text.replace('\\', r'\textbackslash{}')
        .replace('&', r'\&')
        .replace('%', r'\%')
        .replace('_', r'\_')
        .replace('#', r'\#')
    )


def latex(rows: list[dict[str, Any]]) -> str:
    lines = [
        r'\begin{tabular}{llrrrrrrrrrrr}',
        r'\toprule',
        r'Suite & Pipeline & \#Campaigns & \#Unique & Truth Cov. & MCP $\uparrow$ & FPR $\downarrow$ & Review $\downarrow$ & Recall $\uparrow$ & Oracle/Review $\uparrow$ & Stable $\uparrow$ & wDPC $\uparrow$ & Missing \\',
        r'\midrule',
    ]
    for row in rows:
        lines.append(' & '.join(latex_escape(row[key]) for key in COLUMNS) + r' \\')
    lines.extend([r'\bottomrule', r'\end{tabular}'])
    return '\n'.join(lines) + '\n'


def main() -> int:
    parser = argparse.ArgumentParser(description='Generate paper-ready cargo-fuzz vs RustDPR tables from metrics JSON files.')
    parser.add_argument('--metrics', action='append', required=True, type=parse_metric_arg, help='Repeatable SUITE=PATH, e.g. regression=reports/metrics_regression.json')
    parser.add_argument('--baseline', default='cargo-fuzz/crash-only')
    parser.add_argument('--treatment', default='cargo-fuzz/full')
    parser.add_argument('--out-prefix', required=True)
    args = parser.parse_args()

    rows: list[dict[str, Any]] = []
    for suite, path in args.metrics:
        metrics = read_json(path)
        rows.append(build_row(suite, args.baseline, group(metrics, args.baseline)))
        rows.append(build_row(suite, args.treatment, group(metrics, args.treatment)))

    prefix = Path(args.out_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with prefix.with_suffix('.csv').open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    prefix.with_suffix('.md').write_text(markdown(rows), encoding='utf-8')
    prefix.with_suffix('.tex').write_text(latex(rows), encoding='utf-8')
    print(f'[done] wrote {prefix.with_suffix(".csv")}, {prefix.with_suffix(".md")}, {prefix.with_suffix(".tex")}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
