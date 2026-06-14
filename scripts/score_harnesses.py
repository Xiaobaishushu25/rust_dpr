from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from common import (
    RUNS_DIR,
    candidate_is_oracle_confirmed,
    load_optional_json,
    read_json,
    safe_float,
    write_csv,
    write_json,
)

FIELDNAMES = [
    "rank",
    "harness_id",
    "harness_path",
    "crate",
    "tool",
    "compile_status",
    "harness_status",
    "misuse_findings",
    "static_dangerous_sites",
    "high_risk_categories",
    "short_run_primary_label",
    "short_run_relation",
    "short_run_panic_count",
    "short_run_harness_misuse_count",
    "short_run_dangerous_hits",
    "oracle_verdict",
    "score",
    "score_breakdown",
    "source_run_dir",
]

MISUSE_PATTERNS = {
    "NullPointer": re.compile(r"std::ptr::null(?:_mut)?\s*\(|core::ptr::null(?:_mut)?\s*\(|ptr::null(?:_mut)?\s*\("),
    "FromRawParts": re.compile(r"(?:Vec|slice|std::slice)::from_raw_parts(?:_mut)?\s*\(|from_raw_parts(?:_mut)?\s*\("),
    "BoxFromRaw": re.compile(r"Box::from_raw\s*\("),
    "CStrFromPtr": re.compile(r"CStr::from_ptr\s*\("),
    "AssumeInit": re.compile(r"\.assume_init\s*\("),
    "Transmute": re.compile(r"transmute(?:::<[^>]+>)?\s*\("),
    "SetLen": re.compile(r"\.set_len\s*\("),
}

HIGH_RISK_CATEGORIES = {
    "FfiBoundary",
    "RawPointer",
    "AllocationOwnership",
    "ManualLengthCapacity",
    "MaybeUninit",
    "Transmute",
    "DropInvariant",
}


def harness_id_for_path(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path.name
    return str(rel).replace("/", "__").replace("\\\\", "__").replace(".rs", "")


def scan_harness_source(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = sorted(kind for kind, pattern in MISUSE_PATTERNS.items() if pattern.search(text))
    has_fuzz_target = "fuzz_target!" in text or "libfuzzer_sys" in text or "arbitrary" in text
    if len(findings) >= 2:
        status = "LikelyMisuse"
    elif findings:
        status = "Unknown"
    elif has_fuzz_target:
        status = "LikelyValid"
    else:
        status = "Unknown"
    return {
        "static_harness_status": status,
        "misuse_findings": findings,
        "has_fuzz_target": has_fuzz_target,
    }


def index_runs(runs_dir: Path) -> dict[str, list[Path]]:
    index: dict[str, list[Path]] = defaultdict(list)
    if not runs_dir.exists():
        return index
    for meta_path in runs_dir.rglob("run_meta.json"):
        meta = load_optional_json(meta_path) or {}
        run_dir = meta_path.parent
        keys = [meta.get("harness_id"), meta.get("harness_path")]
        for key in keys:
            if key:
                index[str(key)].append(run_dir)
                try:
                    index[str(Path(key).resolve())].append(run_dir)
                except OSError:
                    pass
    return index


def best_run_for_harness(path: Path, harness_id: str, run_index: dict[str, list[Path]]) -> Path | None:
    keys = [harness_id, str(path), str(path.resolve())]
    candidates: list[Path] = []
    seen = set()
    for key in keys:
        for run_dir in run_index.get(key, []):
            if run_dir not in seen:
                seen.add(run_dir)
                candidates.append(run_dir)
    if not candidates:
        return None
    def score_run(run_dir: Path) -> tuple[float, str]:
        classification = load_optional_json(run_dir / "classification.json") or {}
        reached = classification.get("reached_dangerous_sites") or []
        return (float(len(reached)), str(run_dir))
    return sorted(candidates, key=score_run, reverse=True)[0]


def high_risk_categories(site_map: dict[str, Any] | None) -> list[str]:
    categories = set()
    if not site_map:
        return []
    for site in site_map.get("dangerous_sites") or []:
        for key in ["category", "dangerous_category", "kind", "kind_name"]:
            value = site.get(key)
            if value:
                categories.add(str(value))
    return sorted(cat for cat in categories if cat in HIGH_RISK_CATEGORIES or any(hr in cat for hr in HIGH_RISK_CATEGORIES))


def score_harness(path: Path, root: Path, run_index: dict[str, list[Path]]) -> dict[str, Any]:
    harness_id = harness_id_for_path(path, root)
    source_scan = scan_harness_source(path)
    run_dir = best_run_for_harness(path, harness_id, run_index)
    meta: dict[str, Any] = {}
    classification: dict[str, Any] = {}
    harness_validity: dict[str, Any] = {}
    site_map: dict[str, Any] = {}
    if run_dir:
        meta = load_optional_json(run_dir / "run_meta.json") or {}
        classification = load_optional_json(run_dir / "classification.json") or {}
        harness_validity = load_optional_json(run_dir / "harness_validity.json") or {}
        site_map = load_optional_json(run_dir / "site_map.json") or {}

    compile_status = str(meta.get("compile_status") or "unknown")
    harness_status = str(
        classification.get("harness_status")
        or harness_validity.get("status")
        or source_scan["static_harness_status"]
        or "Unknown"
    )
    dangerous_sites = len(site_map.get("dangerous_sites") or []) if site_map else 0
    categories = high_risk_categories(site_map)
    reached = classification.get("reached_dangerous_sites") or []
    primary = str(classification.get("primary_label") or "Unknown")
    relation = str(classification.get("relation") or "Unknown")
    oracle_verdict = str(classification.get("oracle_verdict") or "Unknown")

    breakdown = {
        "compile": 2.0 if compile_status in {"ok", "success", "passed"} else (-5.0 if compile_status in {"failed", "fail", "error"} else 0.0),
        "harness_status": {"ConfirmedValid": 2.5, "LikelyValid": 1.5, "Unknown": 0.0, "LikelyMisuse": -3.0, "Invalid": -5.0}.get(harness_status, 0.0),
        "static_pattern_penalty": -min(len(source_scan["misuse_findings"]), 4) * 0.75,
        "static_dangerous_sites": min(dangerous_sites, 10) * 0.2,
        "high_risk_categories": min(len(categories), 5) * 0.5,
        "short_run_dangerous_hits": min(len(reached), 6) * 0.6,
        "short_run_actionable": 2.0 if primary in {"PanicAfterUnsafe", "InsideUnsafePanic", "DangerousPathReached", "SuspiciousCandidate"} else 0.0,
        "short_run_harness_misuse": -3.0 if primary == "HarnessMisuse" or harness_status in {"LikelyMisuse", "Invalid"} else 0.0,
        "oracle_confirmed": 4.0 if candidate_is_oracle_confirmed(classification) else 0.0,
    }
    score = sum(breakdown.values())

    return {
        "rank": 0,
        "harness_id": harness_id,
        "harness_path": str(path),
        "crate": meta.get("crate") or meta.get("case") or root.name,
        "tool": meta.get("tool") or "unknown",
        "compile_status": compile_status,
        "harness_status": harness_status,
        "misuse_findings": ";".join(source_scan["misuse_findings"]),
        "static_dangerous_sites": dangerous_sites,
        "high_risk_categories": ";".join(categories),
        "short_run_primary_label": primary,
        "short_run_relation": relation,
        "short_run_panic_count": int(meta.get("raw_panic_count", 0) or 0),
        "short_run_harness_misuse_count": 1 if primary == "HarnessMisuse" or harness_status in {"LikelyMisuse", "Invalid"} else 0,
        "short_run_dangerous_hits": len(reached),
        "oracle_verdict": oracle_verdict,
        "score": score,
        "score_breakdown": json.dumps(breakdown, sort_keys=True),
        "source_run_dir": str(run_dir) if run_dir else "",
    }


def discover_harnesses(harness_dir: Path) -> list[Path]:
    if harness_dir.is_file() and harness_dir.suffix == ".rs":
        return [harness_dir]
    return sorted(path for path in harness_dir.rglob("*.rs") if path.is_file())


def main() -> int:
    parser = argparse.ArgumentParser(description="Score generated fuzz harnesses for RustDPR-assisted gate/ranking")
    parser.add_argument("--harness-dir", required=True)
    parser.add_argument("--runs-dir", default=str(RUNS_DIR))
    parser.add_argument("--out-csv", required=True)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--min-score", type=float, default=None)
    args = parser.parse_args()

    root = Path(args.harness_dir)
    harnesses = discover_harnesses(root)
    run_index = index_runs(Path(args.runs_dir))
    rows = [score_harness(path, root if root.is_dir() else root.parent, run_index) for path in harnesses]
    rows.sort(key=lambda row: (-safe_float(row.get("score")), row["harness_id"]))
    if args.min_score is not None:
        rows = [row for row in rows if safe_float(row.get("score")) >= args.min_score]
    for idx, row in enumerate(rows, start=1):
        row["rank"] = idx

    write_csv(Path(args.out_csv), rows, FIELDNAMES)
    write_json(Path(args.out_json), {"harness_dir": str(root), "total_harnesses": len(rows), "rows": rows})
    print("[done] scored harnesses")
    print(f"total harnesses : {len(rows)}")
    print(f"csv             : {args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
