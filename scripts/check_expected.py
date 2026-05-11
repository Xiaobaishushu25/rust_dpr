#!/usr/bin/env python3
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is required. Install with: pip install pyyaml")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
MICRO_DIR = ROOT / "benchmarks" / "micro"
DATA_DIR = ROOT / "data"

failed = False

for case_dir in sorted(MICRO_DIR.iterdir()):
    if not case_dir.is_dir():
        continue

    case_name = case_dir.name
    expected_path = case_dir / "expected.yaml"
    result_path = DATA_DIR / case_name / "classification.json"

    if not expected_path.exists():
        print(f"[SKIP] {case_name}: missing expected.yaml")
        continue

    if not result_path.exists():
        print(f"[SKIP] {case_name}: missing classification.json")
        continue

    expected = yaml.safe_load(expected_path.read_text())
    result = json.loads(result_path.read_text())

    exp_class = expected.get("expected_class")
    exp_relation = expected.get("expected_relation")
    exp_reached = expected.get("expected_reached_sites")

    got_class = result.get("class")
    got_relation = result.get("relation")
    got_reached = len(result.get("reached_site_ids", []))

    ok = (
        exp_class == got_class and
        exp_relation == got_relation and
        exp_reached == got_reached
    )

    status = "PASS" if ok else "FAIL"
    print(
        f"[{status}] {case_name} | "
        f"class: expected={exp_class} got={got_class} | "
        f"relation: expected={exp_relation} got={got_relation} | "
        f"reached: expected={exp_reached} got={got_reached}"
    )

    if not ok:
        failed = True

if failed:
    sys.exit(1)