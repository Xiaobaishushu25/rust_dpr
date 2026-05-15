import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "micro"

rows = []

for case_dir in RESULTS.iterdir():
    if not case_dir.is_dir():
        continue

    cls = case_dir / "classification.json"
    if not cls.exists():
        continue

    data = json.loads(cls.read_text())
    rows.append({
        "case": case_dir.name,
        "label": data["primary_label"],
        "relation": data["relation"],
        "confidence": data["confidence"],
        "oracle": data["oracle_verdict"],
        "distance": data["distance_to_dangerous_site"],
    })

print(json.dumps(rows, indent=2))