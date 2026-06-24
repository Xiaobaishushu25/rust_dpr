from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Any

from common import RUNS_DIR, SUITES, read_json


FIELDNAMES = [
    'suite',
    'case',
    'input_sha256',
    'candidate_id',
    'candidate_ids',
    'occurrences',
    'campaign_count',
    'input_path',
    'replay_log_path',
    'security_relevant',
    'primary_label',
    'relation',
    'harness_status',
    'oracle_verdict',
    'truth_source',
    'annotator_1',
    'annotator_2',
    'adjudicated',
    'rationale',
]


def candidate_rows(
    suite: str,
    tool: str,
    variant: str,
    run_indices: set[int] | None = None,
) -> list[dict[str, Any]]:
    root = RUNS_DIR / suite
    rows: list[dict[str, Any]] = []
    if not root.exists():
        return rows
    for meta_path in sorted(root.rglob('run_meta.json')):
        meta = read_json(meta_path)
        if meta.get('tool') != tool or meta.get('variant') != variant:
            continue
        run_index = int(meta.get('run_index', 1) or 1)
        if run_indices and run_index not in run_indices:
            continue
        if meta.get('unit_of_analysis') != 'candidate':
            continue
        digest = str(meta.get('input_sha256') or '').strip().lower()
        case = str(meta.get('case') or meta.get('crate') or '').strip()
        if not case or not digest:
            continue
        rows.append(
            {
                'suite': suite,
                'case': case,
                'input_sha256': digest,
                'candidate_id': str(meta.get('candidate_id') or ''),
                'campaign_id': str(meta.get('campaign_id') or ''),
                'input_path': str(meta.get('input_path') or ((meta.get('input_files') or [''])[0])),
                'replay_log_path': str(meta.get('replay_log_path') or ''),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            'Export a deduplicated, prediction-blind candidate truth template. '
            'Rows are keyed by case + full input SHA-256 so baseline/treatment and repeated seeds share one annotation.'
        )
    )
    parser.add_argument('--suite', choices=SUITES, required=True)
    parser.add_argument('--tool', default='cargo-fuzz')
    parser.add_argument('--variant', default='full')
    parser.add_argument('--out', required=True)
    parser.add_argument(
        '--run-index',
        action='append',
        type=int,
        default=[],
        help='Only export candidates from these run indices. Repeatable.',
    )
    args = parser.parse_args()

    run_indices = set(args.run_index) if args.run_index else None
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in candidate_rows(args.suite, args.tool, args.variant, run_indices):
        grouped[(row['case'], row['input_sha256'])].append(row)

    out_rows: list[dict[str, Any]] = []
    for (case, digest), occurrences in sorted(grouped.items()):
        first = occurrences[0]
        candidate_ids = sorted({row['candidate_id'] for row in occurrences if row['candidate_id']})
        campaigns = sorted({row['campaign_id'] for row in occurrences if row['campaign_id']})
        out_rows.append(
            {
                'suite': args.suite,
                'case': case,
                'input_sha256': digest,
                'candidate_id': candidate_ids[0] if candidate_ids else '',
                'candidate_ids': ';'.join(candidate_ids),
                'occurrences': len(occurrences),
                'campaign_count': len(campaigns),
                'input_path': first['input_path'],
                'replay_log_path': first['replay_log_path'],
                'security_relevant': '',
                'primary_label': '',
                'relation': '',
                'harness_status': '',
                'oracle_verdict': '',
                'truth_source': 'two-annotator-adjudication',
                'annotator_1': '',
                'annotator_2': '',
                'adjudicated': '',
                'rationale': '',
            }
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(out_rows)

    print(f'[done] unique candidate artifacts={len(out_rows)} template={out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
