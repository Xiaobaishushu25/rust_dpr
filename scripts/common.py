from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None


ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = ROOT_DIR / "benchmarks"
DATA_DIR = ROOT_DIR / "data"
REPORTS_DIR = ROOT_DIR / "reports"
RUNS_DIR = DATA_DIR / "runs"
EXTERNAL_TOOLS_DIR = ROOT_DIR / "external_tools"
GENERATED_HARNESSES_DIR = ROOT_DIR / "generated_harnesses"
EXTERNAL_RUNS_DIR = DATA_DIR / "external_runs"

SUITES = ("micro", "taxonomy", "oracle", "regression", "realworld", "generated_harness")

TOOLS = (
    "rustdpr",
    "cargo-fuzz",
    "coverage-only",
    "static-only",
    "asan-only",
    "miri-only",
    "fourfuzz-approx",
    "fourfuzz-style",
    "deepsurf-approx",
    "deepsurf-style",
    "rpg-approx",
    "rpg",
    "rulf-approx",
    "rulf",
)

VARIANTS = (
    "full",
    "no-trace",
    "no-dpg",
    "no-harness",
    "no-oracle",
    "panic-only",
    "panic-message-only",
    "static-only",
    "coverage-only",
    "unweighted",
    "crash-only",
    "oracle-only",
    "unsafe-targeted",
    "generated-harness",
    "llm-generated-harness",
)


def ensure_pyyaml() -> None:
    if yaml is None:
        print("PyYAML is required. Install with: pip install pyyaml")
        raise SystemExit(1)


def add_suite_arg(parser, *, required: bool = False, default: str | None = None):
    return parser.add_argument(
        "--suite",
        choices=SUITES,
        required=required,
        default=default,
    )


def run_cmd(
    cmd: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    log_path: Path | None = None,
    check: bool = True,
) -> int:
    print(f"[cmd] {' '.join(map(str, cmd))}")
    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)

    process = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=merged_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    assert process.stdout is not None
    log_file = None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_file = log_path.open("w", encoding="utf-8")

    try:
        for line in process.stdout:
            print(line, end="")
            if log_file is not None:
                log_file.write(line)
    finally:
        if log_file is not None:
            log_file.close()

    return_code = process.wait()
    if check and return_code != 0:
        raise subprocess.CalledProcessError(return_code, cmd)
    return return_code


def capture_version(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return (proc.stdout or proc.stderr or "").strip()
    except OSError as e:
        return f"unavailable: {e}"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise RuntimeError(f"invalid JSONL object at {path}:{line_no}")
            rows.append(obj)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def safe_int(value: Any, default: int = 0) -> int:
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    if value in (None, ""):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def load_optional_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return read_json(path)


def load_yaml(path: Path) -> Any:
    ensure_pyyaml()
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def discover_cases(suite: str) -> list[Path]:
    suite_dir = BENCHMARKS_DIR / suite
    if not suite_dir.exists():
        raise FileNotFoundError(f"suite directory not found: {suite_dir}")
    return sorted([p for p in suite_dir.iterdir() if p.is_dir()])


def resolve_case(case: str, suite: str | None = None) -> tuple[str, Path]:
    if suite:
        case_dir = BENCHMARKS_DIR / suite / case
        if not case_dir.exists():
            raise FileNotFoundError(f"case not found: {case_dir}")
        return suite, case_dir

    matches: list[tuple[str, Path]] = []
    for suite_dir in BENCHMARKS_DIR.iterdir():
        if not suite_dir.is_dir():
            continue
        candidate = suite_dir / case
        if candidate.exists():
            matches.append((suite_dir.name, candidate))

    if not matches:
        raise FileNotFoundError(f"case not found under benchmarks/*/: {case}")

    if len(matches) > 1:
        suites = ", ".join(s for s, _ in matches)
        raise RuntimeError(f"ambiguous case {case!r}; found in suites: {suites}")

    return matches[0]


def run_output_dir(
    suite: str,
    case_name: str,
    *,
    tool: str,
    variant: str,
    seed: int | None,
    run_index: int,
    mode: str | None = None,
) -> Path:
    seed_part = "seed-none" if seed is None else f"seed-{seed}"
    base = RUNS_DIR / suite / case_name / tool / variant
    if mode and mode != "deterministic":
        base = base / mode
    return base / seed_part / f"run-{run_index:03d}"


def external_run_output_dir(
    suite: str,
    case_name: str,
    *,
    upstream_tool: str,
    harness_id: str,
    seed: int | None,
    run_index: int,
    variant: str = "full",
) -> Path:
    seed_part = "seed-none" if seed is None else f"seed-{seed}"
    return (
        RUNS_DIR
        / suite
        / case_name
        / upstream_tool
        / variant
        / harness_id
        / seed_part
        / f"run-{run_index:03d}"
    )


REQUIRED_EXTERNAL_META_FIELDS = {
    "tool",
    "crate",
    "harness_id",
    "harness_path",
    "compile_status",
}


def validate_external_meta(meta: dict[str, Any]) -> None:
    missing = sorted(REQUIRED_EXTERNAL_META_FIELDS - set(meta))
    if missing:
        raise RuntimeError(f"external run metadata missing fields: {missing}")


def suite_case_expected_path(suite: str, case_name: str) -> Path:
    return BENCHMARKS_DIR / suite / case_name / "expected.yaml"


def benchmark_manifest_path() -> Path:
    return BENCHMARKS_DIR / "manifest.yaml"


def clean_case_output_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def possible_trace_paths(case_dir: Path) -> list[Path]:
    return [
        case_dir / "artifacts" / "trace.jsonl",
        case_dir / "trace.jsonl",
        case_dir / "target" / "trace.jsonl",
    ]


def find_trace_file(case_dir: Path) -> Path:
    candidates: list[Path] = []
    for p in possible_trace_paths(case_dir):
        if p.exists():
            candidates.append(p)

    candidates.extend(case_dir.rglob("trace.jsonl"))

    unique = []
    seen = set()
    for p in candidates:
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp)
            unique.append(p)

    if len(unique) == 1:
        return unique[0]

    if len(unique) > 1:
        raise RuntimeError(
            "multiple trace.jsonl files found; clean stale benchmark artifacts first: "
            + ", ".join(str(p) for p in unique)
        )
    raise FileNotFoundError(f"trace.jsonl not found under {case_dir}")


def jsonl_trace_to_tracelog_json(
    trace_jsonl: Path,
    out_json: Path,
    *,
    suite: str | None = None,
    case_name: str | None = None,
    run_id: str | None = None,
) -> Path:
    events: list[dict[str, Any]] = []

    with trace_jsonl.open("r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"invalid JSONL trace at {trace_jsonl}, line {idx}: {e}"
                ) from e
            if not isinstance(obj, dict):
                raise RuntimeError(
                    f"invalid JSONL trace at {trace_jsonl}, line {idx}: expected object"
                )
            events.append(obj)

    payload = {
        "schema_version": "0.2.0",
        "suite": suite,
        "case_name": case_name,
        "run_id": run_id,
        "events": events,
    }
    write_json(out_json, payload)
    return out_json


def validate_result_schema(data: dict[str, Any], required: list[str], label: str) -> None:
    missing = [k for k in required if k not in data]
    if missing:
        raise RuntimeError(f"{label} missing required fields: {missing}")


RELATION_LABEL_MAP = {
    "NoneObserved": "NoneObserved",
    "NoDangerousSiteReached": "NoneObserved",
    "BeforeUnsafe": "BeforeUnsafe",
    "AfterUnsafe": "AfterUnsafe",
    "InsideUnsafe": "InsideUnsafe",
    # AdjacentToUnsafe is kept for backward compatibility with earlier RustDPRBench
    # annotations. New paper-facing labels should prefer Before/After/Inside/FfiBoundary.
    "AdjacentToUnsafe": "AdjacentToUnsafe",
    "FfiBoundary": "FfiBoundary",
    "HarnessMisuse": "HarnessMisuse",
    "UnsupportedOracle": "UnsupportedOracle",
    "Unknown": "Unknown",
}

VALID_PRIMARY_LABELS = {
    "Noise",
    "ContractPanic",
    "HarnessMisuse",
    "BlockingPanic",
    "PanicAfterUnsafe",
    "InsideUnsafePanic",
    "DangerousPathReached",
    "OracleConfirmedBug",
    "SuspiciousCandidate",
    "Unknown",
}

VALID_RELATION_LABELS = {
    "NoneObserved",
    "BeforeUnsafe",
    "AfterUnsafe",
    "InsideUnsafe",
    "AdjacentToUnsafe",
    "FfiBoundary",
    "HarnessMisuse",
    "UnsupportedOracle",
    "Unknown",
}

VALID_ORACLE_VERDICTS = {
    "Unknown",
    "NoOracleFinding",
    "AddressSanitizerDoubleFree",
    "AddressSanitizerUseAfterFree",
    "AddressSanitizerOutOfBounds",
    "AddressSanitizerInvalidFree",
    "AddressSanitizerLeak",
    "MiriUndefinedBehavior",
    "MiriUnsupported",
    "OracleTimeout",
    "OracleBuildFailure",
}

VALID_HARNESS_STATUS = {
    "ConfirmedValid",
    "LikelyValid",
    "LikelyMisuse",
    "Invalid",
    "Unknown",
}

CONFIRMED_ORACLE_VERDICTS = {
    "AddressSanitizerDoubleFree",
    "AddressSanitizerUseAfterFree",
    "AddressSanitizerOutOfBounds",
    "AddressSanitizerInvalidFree",
    "AddressSanitizerLeak",
    "MiriUndefinedBehavior",
}

PAPER_MEANINGFUL_LABELS = {
    "PanicAfterUnsafe",
    "InsideUnsafePanic",
    "DangerousPathReached",
    "OracleConfirmedBug",
    "SuspiciousCandidate",
}

PAPER_NOISE_LABELS = {
    "Noise",
    "ContractPanic",
    "BlockingPanic",
    "HarnessMisuse",
}

PAPER_ACTIONABLE_RELATIONS = {"AfterUnsafe", "InsideUnsafe", "FfiBoundary", "AdjacentToUnsafe"}
PAPER_BAD_HARNESS_STATUS = {"LikelyMisuse", "Invalid"}
PAPER_GOOD_HARNESS_STATUS = {"ConfirmedValid", "LikelyValid"}
PAPER_UNSUPPORTED_ORACLES = {"MiriUnsupported", "OracleTimeout", "OracleBuildFailure"}

RELATION_SCORE = {
    "InsideUnsafe": 5.0,
    "AfterUnsafe": 4.0,
    "FfiBoundary": 4.0,
    "AdjacentToUnsafe": 2.5,
    "BeforeUnsafe": -2.0,
    "NoneObserved": -1.0,
    "HarnessMisuse": -4.0,
    "UnsupportedOracle": -2.0,
    "Unknown": 0.0,
}

PRIMARY_LABEL_SCORE = {
    "OracleConfirmedBug": 6.0,
    "DangerousPathReached": 4.0,
    "InsideUnsafePanic": 4.0,
    "PanicAfterUnsafe": 3.0,
    "SuspiciousCandidate": 2.0,
    "BlockingPanic": -3.0,
    "ContractPanic": -3.0,
    "HarnessMisuse": -5.0,
    "Noise": -4.0,
    "Unknown": 0.0,
}

HARNESS_STATUS_SCORE = {
    "ConfirmedValid": 2.0,
    "LikelyValid": 1.0,
    "Unknown": 0.0,
    "LikelyMisuse": -3.0,
    "Invalid": -5.0,
}

ORACLE_VERDICT_SCORE = {
    "AddressSanitizerDoubleFree": 6.0,
    "AddressSanitizerUseAfterFree": 6.0,
    "AddressSanitizerOutOfBounds": 6.0,
    "AddressSanitizerInvalidFree": 6.0,
    "AddressSanitizerLeak": 4.0,
    "MiriUndefinedBehavior": 6.0,
    "NoOracleFinding": 0.0,
    "MiriUnsupported": -1.0,
    "OracleTimeout": -1.0,
    "OracleBuildFailure": -2.0,
    "Unknown": 0.0,
}


def candidate_id_for_run(meta: dict[str, Any], run_dir: Path | None = None) -> str:
    explicit = meta.get("candidate_id") or meta.get("run_id")
    if explicit:
        return str(explicit).replace("/", "__")
    parts = [
        meta.get("suite", "unknown"),
        meta.get("case", meta.get("crate", "unknown")),
        meta.get("tool", "unknown"),
        meta.get("variant", "unknown"),
        f"seed-{meta.get('seed', 'none')}",
        f"run-{meta.get('run_index', 1)}",
    ]
    if meta.get("harness_id"):
        parts.insert(4, str(meta.get("harness_id")))
    if run_dir is not None:
        parts.append(hashlib.sha1(str(run_dir).encode("utf-8")).hexdigest()[:10])
    return "__".join(str(x).replace("/", "_") for x in parts)


def candidate_is_meaningful(classification: dict[str, Any]) -> bool:
    return str(classification.get("primary_label") or "Unknown") in PAPER_MEANINGFUL_LABELS


def candidate_is_actionable(classification: dict[str, Any]) -> bool:
    primary = str(classification.get("primary_label") or "Unknown")
    relation = str(classification.get("relation") or "Unknown")
    harness = str(classification.get("harness_status") or "Unknown")
    return (
        primary in PAPER_MEANINGFUL_LABELS
        and relation in PAPER_ACTIONABLE_RELATIONS
        and harness not in PAPER_BAD_HARNESS_STATUS
    )


def candidate_is_oracle_confirmed(classification: dict[str, Any]) -> bool:
    return str(classification.get("oracle_verdict") or "Unknown") in CONFIRMED_ORACLE_VERDICTS


def candidate_evidence_grade(classification: dict[str, Any], *, replay_stable: bool = False) -> str:
    if candidate_is_oracle_confirmed(classification) and replay_stable:
        return "oracle-confirmed-replay-stable"
    if candidate_is_oracle_confirmed(classification):
        return "oracle-confirmed"
    if candidate_is_actionable(classification):
        return "actionable"
    if candidate_is_meaningful(classification):
        return "suspicious"
    return "noise-or-unsupported"


def candidate_score_components(
    classification: dict[str, Any],
    *,
    reached_count: int = 0,
    replay_stable: bool = False,
    duplicate_ordinal: int = 1,
) -> dict[str, float]:
    primary = str(classification.get("primary_label") or "Unknown")
    relation = str(classification.get("relation") or "Unknown")
    harness = str(classification.get("harness_status") or "Unknown")
    oracle = str(classification.get("oracle_verdict") or "Unknown")
    distance = safe_float(classification.get("distance_to_dangerous_site"), 0.0)
    confidence = safe_float(classification.get("confidence"), 0.0)
    duplicate_penalty = -0.5 * max(0, duplicate_ordinal - 1)
    distance_penalty = -min(max(distance, 0.0) * 0.25, 3.0)
    return {
        "primary_label": PRIMARY_LABEL_SCORE.get(primary, 0.0),
        "relation": RELATION_SCORE.get(relation, 0.0),
        "harness_status": HARNESS_STATUS_SCORE.get(harness, 0.0),
        "oracle_verdict": ORACLE_VERDICT_SCORE.get(oracle, 0.0),
        "model_confidence": max(0.0, min(confidence, 1.0)) * 2.0,
        "dangerous_reach": min(max(reached_count, 0), 6) * 0.5,
        "review_required": 0.25 if classification.get("review_required") else 0.0,
        "replay_stable": 2.0 if replay_stable else 0.0,
        "distance_penalty": distance_penalty,
        "duplicate_penalty": duplicate_penalty,
    }


def candidate_score(
    classification: dict[str, Any],
    *,
    reached_count: int = 0,
    replay_stable: bool = False,
    duplicate_ordinal: int = 1,
) -> float:
    return sum(
        candidate_score_components(
            classification,
            reached_count=reached_count,
            replay_stable=replay_stable,
            duplicate_ordinal=duplicate_ordinal,
        ).values()
    )


def candidate_duplicate_key(classification: dict[str, Any], meta: dict[str, Any]) -> str:
    panic_location = classification.get("panic_location") or classification.get("panic_site")
    if isinstance(panic_location, dict):
        panic_location = f"{panic_location.get('file')}:{panic_location.get('line')}"
    reached = classification.get("reached_dangerous_sites") or []
    first_reached = reached[0] if isinstance(reached, list) and reached else "none"
    backtrace_hash = classification.get("backtrace_hash") or classification.get("stack_hash") or "no-bt"
    return "|".join(
        [
            str(meta.get("case") or meta.get("crate") or "unknown"),
            str(classification.get("primary_label") or "Unknown"),
            str(classification.get("relation") or "Unknown"),
            str(classification.get("oracle_verdict") or "Unknown"),
            str(first_reached),
            str(panic_location or backtrace_hash),
        ]
    )


def trace_event_kind(event: dict[str, Any]) -> str:
    if "Hit" in event:
        return "Hit"
    if "Panic" in event:
        return "Panic"
    return str(event.get("type") or event.get("kind") or "Unknown")


def trace_event_payload(event: dict[str, Any]) -> dict[str, Any]:
    kind = trace_event_kind(event)
    payload = event.get(kind)
    return payload if isinstance(payload, dict) else event


def trace_event_ts_millis(event: dict[str, Any], fallback: int) -> int:
    payload = trace_event_payload(event)
    return safe_int(payload.get("ts_millis") or payload.get("time_millis") or payload.get("timestamp_ms"), fallback)


def trace_event_site_id(event: dict[str, Any]) -> str | None:
    payload = trace_event_payload(event)
    value = payload.get("site_id") or event.get("site_id")
    return None if value is None else str(value)


def first_trace_times(trace: dict[str, Any] | None, dangerous_ids: set[str] | None = None) -> dict[str, int | None]:
    result: dict[str, int | None] = {
        "first_event_time_ms": None,
        "dangerous_hit_time_ms": None,
        "panic_time_ms": None,
    }
    if not trace:
        return result
    dangerous_ids = dangerous_ids or set()
    for idx, event in enumerate(trace.get("events", []) or []):
        ts = trace_event_ts_millis(event, idx)
        if result["first_event_time_ms"] is None:
            result["first_event_time_ms"] = ts
        kind = trace_event_kind(event)
        site_id = trace_event_site_id(event)
        if kind == "Hit" and site_id in dangerous_ids and result["dangerous_hit_time_ms"] is None:
            result["dangerous_hit_time_ms"] = ts
        if kind == "Panic" and result["panic_time_ms"] is None:
            result["panic_time_ms"] = ts
    return result


def is_confirmed_oracle_verdict(verdict: str) -> bool:
    return verdict in CONFIRMED_ORACLE_VERDICTS


def oracle_verdict_priority(verdict: str) -> int:
    """Priority used when ASan and Miri logs are both available.

    ASan gives a more specific memory-safety class for heap/double-free/OOB cases,
    while Miri is the fallback for UB cases that ASan does not classify.
    """
    if verdict in {
        "AddressSanitizerDoubleFree",
        "AddressSanitizerUseAfterFree",
        "AddressSanitizerOutOfBounds",
        "AddressSanitizerInvalidFree",
        "AddressSanitizerLeak",
    }:
        return 100
    if verdict == "MiriUndefinedBehavior":
        return 90
    if verdict == "OracleTimeout":
        return 20
    if verdict == "MiriUnsupported":
        return 10
    return 0


def parse_oracle_log_file(path: Path, oracle: str) -> str:
    if not path.exists():
        return "Unknown"
    return parse_oracle_verdict_from_log_text(
        path.read_text(encoding="utf-8", errors="replace"),
        oracle,
    )


def select_oracle_verdict(rows: list[dict[str, Any]]) -> str:
    """Select the best canonical verdict from parsed oracle rows."""
    best = "Unknown"
    best_priority = -1
    for row in rows:
        verdict = str(row.get("verdict") or "Unknown")
        priority = oracle_verdict_priority(verdict)
        if priority > best_priority:
            best = verdict
            best_priority = priority
    return best



def normalize_primary_label(value: Any) -> str:
    if value is None:
        raise RuntimeError("primary_label must not be null")
    value = str(value)
    if value not in VALID_PRIMARY_LABELS:
        raise RuntimeError(f"invalid primary_label: {value!r}")
    return value


def normalize_relation_label(value: Any) -> str:
    if value is None:
        raise RuntimeError("relation must not be null")
    value = RELATION_LABEL_MAP.get(str(value), str(value))
    if value not in VALID_RELATION_LABELS:
        raise RuntimeError(f"invalid relation: {value!r}")
    return value


def normalize_oracle_verdicts(value: Any) -> str:
    if value is None:
        raise RuntimeError("oracle_verdict must not be null")
    value = str(value)
    if value not in VALID_ORACLE_VERDICTS:
        raise RuntimeError(f"invalid oracle_verdict: {value!r}")
    return value


def normalize_harness_status(value: Any) -> str:
    if value is None:
        raise RuntimeError("harness_status must not be null")
    value = str(value)
    if value not in VALID_HARNESS_STATUS:
        raise RuntimeError(f"invalid harness_status: {value!r}")
    return value


def normalize_expected_schema(expected: dict[str, Any]) -> dict[str, Any]:
    required_top_level = ["case_id", "suite", "category", "ground_truth"]
    missing_top_level = [k for k in required_top_level if k not in expected]
    if missing_top_level:
        raise RuntimeError(f"expected.yaml missing required fields: {missing_top_level}")

    gt = expected.get("ground_truth") or {}
    required_ground_truth = [
        "primary_label",
        "relation",
        "oracle_verdict",
        "harness_status",
        "security_relevant",
        "oracle_confirmable",
        "expected_reached_count",
    ]
    missing_ground_truth = [k for k in required_ground_truth if k not in gt]
    if missing_ground_truth:
        raise RuntimeError(f"expected.yaml ground_truth missing required fields: {missing_ground_truth}")

    return {
        "case_id": expected["case_id"],
        "suite": expected["suite"],
        "category": expected["category"],
        "primary_label": normalize_primary_label(gt["primary_label"]),
        "relation": normalize_relation_label(gt["relation"]),
        "oracle_verdict": normalize_oracle_verdicts(gt["oracle_verdict"]),
        "harness_status": normalize_harness_status(gt["harness_status"]),
        "reached_count": int(gt["expected_reached_count"]),
        "security_relevant": bool(gt["security_relevant"]),
        "oracle_confirmable": bool(gt["oracle_confirmable"]),
        "dangerous_categories": expected.get("dangerous_categories", []),
        "panic_kinds": expected.get("panic_kinds", []),
        "notes": expected.get("notes"),
    }


def summarize_classification(case_name: str, suite: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "suite": suite,
        "case": case_name,
        "primary_label": data.get("primary_label"),
        "relation": data.get("relation"),
        "oracle_verdict": data.get("oracle_verdict"),
        "harness_status": data.get("harness_status"),
        "distance_to_dangerous_site": data.get("distance_to_dangerous_site"),
        "reached_dangerous_sites": len(data.get("reached_dangerous_sites", [])),
        "notes_count": len((data.get("notes") or {}).get("notes", [])),
        "review_required": data.get("review_required"),
        "confidence": data.get("confidence"),
        "schema_version": data.get("schema_version"),
    }


def summarize_run_classification(
    case_name: str,
    suite: str,
    classification: dict[str, Any],
    meta: dict[str, Any],
) -> dict[str, Any]:
    required_meta = ["tool", "variant", "mode", "seed", "run_index", "budget_seconds", "return_code"]
    missing_meta = [k for k in required_meta if k not in meta]
    if missing_meta:
        raise RuntimeError(f"run_meta.json missing required fields: {missing_meta}")

    row = summarize_classification(case_name, suite, classification)
    row.update(
        {
            "tool": meta["tool"],
            "variant": meta["variant"],
            "mode": meta["mode"],
            "seed": meta["seed"],
            "run_index": meta["run_index"],
            "budget_seconds": meta["budget_seconds"],
            "return_code": meta["return_code"],
        }
    )
    return row

def _classify_asan_issue_text(text: str) -> str | None:
    """Classify an ASan ERROR/SUMMARY line into RustDPR's canonical verdict.

    ASan logs contain many explanatory lines. Parsing only the canonical
    ERROR/SUMMARY text first avoids false matches from shadow-byte legends or
    secondary diagnostics.
    """
    text = text.lower()
    if "double-free" in text or "attempting double-free" in text:
        return "AddressSanitizerDoubleFree"
    if any(token in text for token in [
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "global-buffer-overflow",
        "container-overflow",
        "out-of-bounds",
    ]):
        return "AddressSanitizerOutOfBounds"
    if any(token in text for token in [
        "heap-use-after-free",
        "stack-use-after-return",
        "use-after-free",
    ]):
        return "AddressSanitizerUseAfterFree"
    if any(token in text for token in [
        "attempting free on address which was not malloc",
        "bad-free",
        "invalid-free",
        "alloc-dealloc-mismatch",
    ]):
        return "AddressSanitizerInvalidFree"
    if any(token in text for token in [
        "leaksanitizer",
        "detected memory leaks",
        "direct leak of",
        "indirect leak of",
    ]):
        return "AddressSanitizerLeak"
    return None


def parse_oracle_verdict_from_log_text(content: str, oracle: str) -> str:
    """Parse ASan/Miri output into RustDPR's canonical OracleVerdict string."""
    oracle = oracle.lower().strip()
    lower = content.lower()

    def contains_any(needles: list[str]) -> bool:
        return any(needle in lower for needle in needles)

    if oracle == "asan":
        # Prefer the canonical ASan header/summary line over broad substring
        # matching, because non-primary diagnostic text may mention other bug
        # classes.
        for line in lower.splitlines():
            if "error: addresssanitizer:" in line or "summary: addresssanitizer:" in line:
                verdict = _classify_asan_issue_text(line)
                if verdict is not None:
                    return verdict

        fallback = _classify_asan_issue_text(lower)
        if fallback is not None:
            return fallback
        if contains_any(["timeout", "alarm", "max_total_time"]):
            return "OracleTimeout"
        if contains_any(["build failed", "could not compile", "error: aborting due to", "linking with"]):
            return "OracleBuildFailure"
        return "NoOracleFinding"

    if oracle == "miri":
        # UB evidence should win over unsupported-environment notes. This is
        # important when Miri is run with -Zmiri-disable-isolation, where the
        # log can contain an isolation warning before the concrete UB report.
        if contains_any([
            "error: undefined behavior",
            "undefined behavior:",
            "miri: undefined behavior",
            "out-of-bounds pointer arithmetic",
            "dangling pointer",
            "pointer to unallocated allocation",
            "attempting a read access using",
            "attempting a write access using",
            "deallocating while item is protected",
            "data race",
            "uninitialized",
            "invalid enum discriminant",
            "violated precondition",

            # Extra Miri UB diagnostics seen in validity and alignment cases.
            "constructing invalid value",
            "invalid value",
            "expected a boolean",
            "encountered 0x",
            "not a valid",
            "validity invariant",
            "misaligned pointer dereference",
            "memory access failed",
            "not dereferenceable",
        ]):
            return "MiriUndefinedBehavior"

        if contains_any([
            "unsupported operation",
            "miri does not support",
            "can't call foreign function",
            "can't call extern function",
            "is not supported by miri",
            "operation is not available under isolation",
            "operation not available under isolation",
            "isolation error",
        ]):
            return "MiriUnsupported"
        if contains_any(["build failed", "could not compile", "error: aborting due to", "linking with"]):
            return "OracleBuildFailure"
        return "NoOracleFinding"

    raise ValueError(f"unknown oracle: {oracle!r}")