from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def cohen_kappa(pairs: list[tuple[str, str]]) -> float:
    if not pairs:
        return 0.0
    labels = sorted(set(x for p in pairs for x in p))
    n = len(pairs)
    observed = sum(1 for a, b in pairs if a == b) / n
    left = Counter(a for a, _ in pairs)
    right = Counter(b for _, b in pairs)
    expected = sum((left[l] / n) * (right[l] / n) for l in labels)
    if expected == 1.0:
        return 1.0
    return (observed - expected) / (1 - expected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--a", required=True)
    parser.add_argument("--b", required=True)
    parser.add_argument("--fields", default="primary_label,relation,harness_status,oracle_verdict")
    args = parser.parse_args()

    rows_a = read_rows(Path(args.a))
    rows_b = read_rows(Path(args.b))
    key = lambda r: (r["suite"], r["case"])
    map_a = {key(r): r for r in rows_a}
    map_b = {key(r): r for r in rows_b}
    common = sorted(set(map_a) & set(map_b))

    fields = [f.strip() for f in args.fields.split(",") if f.strip()]
    print(f"common_cases,{len(common)}")
    for field in fields:
        pairs = [(map_a[k][field], map_b[k][field]) for k in common]
        print(f"{field},kappa,{cohen_kappa(pairs):.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
