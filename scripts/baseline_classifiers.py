from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from common import parse_oracle_verdict_from_log_text, read_json

RUSTDPR_SCHEMA_VERSION = "0.2.0"
CONFIRMED_ORACLES = {
    "AddressSanitizerDoubleFree",
    "AddressSanitizerUseAfterFree",
    "AddressSanitizerOutOfBounds",
    "AddressSanitizerInvalidFree",
    "AddressSanitizerLeak",
    "MiriUndefinedBehavior",
}


def _notes(*, rule: str, counters: dict[str, int] | None = None, summary: list[str] | None = None, decision: list[str] | None = None) -> dict[str, Any]:
    return {
        "notes": [],
        "counters": counters or {},
        "fired_rules": [rule],
        "conflicting_evidence": [],
        "evidence_summary": summary or [],
        "decision_path": decision or [],
    }


def _classification(
    *,
    suite: str | None,
    case_name: str | None,
    primary_label: str,
    relation: str = "Unknown",
    oracle_verdict: str = "Unknown",
    harness_status: str = "Unknown",
    confidence: float = 0.5,
    review_required: bool = True,
    nearest_dangerous_site: str | None = None,
    distance_to_dangerous_site: int | None = None,
    reached_dangerous_sites: list[str] | None = None,
    oracle_evidence_strength: str = "Unknown",
    target_api_misuse: bool = False,
    notes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": RUSTDPR_SCHEMA_VERSION,
        "case_name": case_name,
        "suite": suite,
        "primary_label": primary_label,
        "relation": relation,
        "reached_dangerous_sites": reached_dangerous_sites or [],
        "nearest_dangerous_site": nearest_dangerous_site,
        "distance_to_dangerous_site": distance_to_dangerous_site,
        "oracle_verdict": oracle_verdict,
        "oracle_evidence_strength": oracle_evidence_strength,
        "target_api_misuse": target_api_misuse,
        "harness_status": harness_status,
        "confidence": confidence,
        "review_required": review_required,
        "notes": notes or _notes(rule="baseline"),
    }


def count_trace_events(trace_log_json: Path | None) -> dict[str, int]:
    counters = {
        "trace_events": 0,
        "function_enter": 0,
        "function_exit": 0,
        "dangerous_hits": 0,
        "panic_count": 0,
        "oracle_markers": 0,
    }
    if trace_log_json is None or not trace_log_json.exists():
        return counters
    trace = read_json(trace_log_json)
    events = trace.get("events") or []
    counters["trace_events"] = len(events)
    for event in events:
        if "EnterFunction" in event:
            counters["function_enter"] += 1
        elif "ExitFunction" in event:
            counters["function_exit"] += 1
        elif "Hit" in event:
            counters["dangerous_hits"] += 1
        elif "Panic" in event:
            counters["panic_count"] += 1
        elif "OracleMarker" in event:
            counters["oracle_markers"] += 1
    return counters


def fuzz_artifact_count(fuzz_meta: dict[str, Any] | None) -> int:
    if not fuzz_meta:
        return 0
    artifact_dir = Path(str(fuzz_meta.get("artifact_dir") or ""))
    if not artifact_dir.exists():
        return 0
    ignored = {"README.md", ".gitignore"}
    return len([p for p in artifact_dir.iterdir() if p.is_file() and p.name not in ignored])


def cargo_fuzz_log_has_crash(log_path: Path | None) -> bool:
    if log_path is None or not log_path.exists():
        return False
    text = log_path.read_text(encoding="utf-8", errors="replace")
    patterns = [
        r"ERROR:\s*libFuzzer",
        r"Test unit written to",
        r"artifact_prefix",
        r"thread .* panicked at",
        r"AddressSanitizer",
        r"UndefinedBehaviorSanitizer",
        r"==\d+==ERROR",
        r"crash-",
        r"panic",
    ]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def classify_crash_only(
    *,
    suite: str,
    case_name: str,
    return_code: int,
    mode: str,
    trace_log_json: Path | None,
    fuzz_meta: dict[str, Any] | None = None,
    harness_status: str = "Unknown",
) -> dict[str, Any]:
    counters = count_trace_events(trace_log_json)
    artifacts = fuzz_artifact_count(fuzz_meta)
    counters["fuzz_artifacts"] = artifacts
    counters["return_code"] = return_code
    log_path = Path(fuzz_meta["log_path"]) if fuzz_meta and fuzz_meta.get("log_path") else None
    log_crash = cargo_fuzz_log_has_crash(log_path)
    crashed = return_code != 0 or artifacts > 0 or log_crash

    if crashed:
        label = "SuspiciousCandidate"
        confidence = 0.55
        review = True
        summary = [
            "crash-only baseline reported a candidate because the execution returned non-zero, produced a fuzz artifact, or the cargo-fuzz log contained crash-like text"
        ]
    else:
        label = "Noise"
        confidence = 0.45
        review = False
        summary = ["crash-only baseline observed no crash artifact and a zero return code"]

    return _classification(
        suite=suite,
        case_name=case_name,
        primary_label=label,
        relation="Unknown" if crashed else "NoneObserved",
        oracle_verdict="Unknown",
        harness_status=harness_status,
        confidence=confidence,
        review_required=review,
        notes=_notes(
            rule="crash-only-baseline",
            counters=counters,
            summary=summary,
            decision=[
                f"mode={mode}",
                f"return_code={return_code}",
                f"fuzz_artifacts={artifacts}",
                f"log_crash={log_crash}",
            ],
        ),
    )


def oracle_strength(verdict: str) -> str:
    if verdict in CONFIRMED_ORACLES:
        return "Confirmed"
    if verdict == "MiriUnsupported":
        return "Unsupported"
    if verdict in {"OracleTimeout", "OracleBuildFailure"}:
        return "WeakHeuristic"
    return "Unknown"


def classify_oracle_only(
    *,
    suite: str,
    case_name: str,
    oracle: str,
    log_path: Path,
    trace_log_json: Path | None,
    harness_status: str = "Unknown",
) -> dict[str, Any]:
    content = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    verdict = parse_oracle_verdict_from_log_text(content, oracle)
    counters = count_trace_events(trace_log_json)
    counters["oracle_log_bytes"] = len(content.encode("utf-8", errors="replace"))

    if verdict in CONFIRMED_ORACLES:
        label = "OracleConfirmedBug"
        relation = "Unknown"
        confidence = 0.99
        review = False
    elif verdict == "NoOracleFinding":
        label = "Noise"
        relation = "NoneObserved"
        confidence = 0.60
        review = False
    elif verdict in {"MiriUnsupported", "OracleTimeout", "OracleBuildFailure"}:
        label = "SuspiciousCandidate"
        relation = "UnsupportedOracle"
        confidence = 0.40
        review = True
    else:
        label = "Unknown"
        relation = "Unknown"
        confidence = 0.30
        review = True

    return _classification(
        suite=suite,
        case_name=case_name,
        primary_label=label,
        relation=relation,
        oracle_verdict=verdict,
        oracle_evidence_strength=oracle_strength(verdict),
        harness_status=harness_status,
        confidence=confidence,
        review_required=review,
        notes=_notes(
            rule=f"{oracle}-only-baseline",
            counters=counters,
            summary=[f"{oracle}-only baseline classified the run using only {log_path.name}: {verdict}"],
            decision=[f"oracle={oracle}", f"verdict={verdict}", f"log_path={log_path}"],
        ),
    )


def classify_coverage_only(
    *,
    suite: str,
    case_name: str,
    coverage_json: Path,
    threshold_percent: float,
    trace_log_json: Path | None,
    harness_status: str = "Unknown",
) -> dict[str, Any]:
    coverage = read_json(coverage_json) if coverage_json.exists() else {"status": "missing"}
    counters = count_trace_events(trace_log_json)
    line_percent = float(coverage.get("line_coverage_percent") or 0.0)
    lines_covered = int(coverage.get("lines_covered") or 0)
    lines_count = int(coverage.get("lines_count") or 0)
    counters.update(
        {
            "coverage_lines_covered": lines_covered,
            "coverage_lines_count": lines_count,
            "coverage_line_percent_x100": int(round(line_percent * 100)),
        }
    )
    status = str(coverage.get("status") or "unknown")
    covered = status == "ok" and line_percent >= threshold_percent and lines_covered > 0

    if covered:
        label = "SuspiciousCandidate"
        relation = "Unknown"
        confidence = 0.45
        review = True
        summary = [
            f"coverage-only baseline reported a candidate because line coverage {line_percent:.2f}% met threshold {threshold_percent:.2f}%"
        ]
    elif status != "ok":
        label = "Unknown"
        relation = "Unknown"
        confidence = 0.25
        review = True
        summary = [f"coverage collection did not complete successfully: status={status}"]
    else:
        label = "Noise"
        relation = "NoneObserved"
        confidence = 0.35
        review = False
        summary = [
            f"coverage-only baseline did not report a candidate because line coverage {line_percent:.2f}% was below threshold {threshold_percent:.2f}%"
        ]

    return _classification(
        suite=suite,
        case_name=case_name,
        primary_label=label,
        relation=relation,
        oracle_verdict="Unknown",
        harness_status=harness_status,
        confidence=confidence,
        review_required=review,
        notes=_notes(
            rule="coverage-only-baseline",
            counters=counters,
            summary=summary,
            decision=[
                f"coverage_status={status}",
                f"line_coverage_percent={line_percent:.2f}",
                f"threshold_percent={threshold_percent:.2f}",
            ],
        ),
    )
