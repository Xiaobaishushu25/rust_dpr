# scripts/find_mismatches.py
from __future__ import annotations

from pathlib import Path

from common import RUNS_DIR, load_yaml, normalize_expected_schema, read_json, suite_case_expected_path


def main() -> int:
    suite = "micro"
    root = RUNS_DIR / suite

    rows = []

    for cls_path in root.rglob("classification.json"):
        run_dir = cls_path.parent
        cls = read_json(cls_path)

        meta_path = run_dir / "run_meta.json"
        meta = read_json(meta_path) if meta_path.exists() else {}

        case = cls.get("case_name") or meta.get("case")
        if not case:
            continue

        expected_path = suite_case_expected_path(suite, case)
        if not expected_path.exists():
            continue

        expected = normalize_expected_schema(load_yaml(expected_path) or {})

        exp_label = expected.get("primary_label")
        act_label = cls.get("primary_label")
        exp_relation = expected.get("relation")
        act_relation = cls.get("relation")

        if exp_label != act_label or exp_relation != act_relation:
            rows.append(
                {
                    "case": case,
                    "mode": meta.get("mode"),
                    "seed": meta.get("seed"),
                    "run_index": meta.get("run_index"),
                    "expected_label": exp_label,
                    "actual_label": act_label,
                    "expected_relation": exp_relation,
                    "actual_relation": act_relation,
                    "run_dir": str(run_dir),
                }
            )

    for r in rows:
        print(
            f"{r['case']} mode={r['mode']} seed={r['seed']} run={r['run_index']} "
            f"label {r['expected_label']} -> {r['actual_label']} | "
            f"relation {r['expected_relation']} -> {r['actual_relation']}"
        )
        print(f"  {r['run_dir']}")

    print(f"\n[summary] mismatches={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())