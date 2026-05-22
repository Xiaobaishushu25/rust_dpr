from __future__ import annotations

import csv
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

SUITES = ("micro", "oracle", "taxonomy", "regression", "realworld")

TOOLS = (
    "rustdpr",
    "cargo-fuzz",
    "coverage-only",
    "static-only",
    "asan-only",
    "miri-only",
    "fourfuzz-approx",
    "deepsurf-approx",
)

VARIANTS = (
    "full",
    "no-trace",
    "no-dpg",
    "no-harness",
    "no-oracle",
    "panic-only",
    "static-only",
    "unweighted",
    "crash-only",
    "oracle-only",
    "unsafe-targeted",
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
) -> Path:
    seed_part = "seed-none" if seed is None else f"seed-{seed}"
    return RUNS_DIR / suite / case_name / tool / variant / seed_part / f"run-{run_index:03d}"


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
    "AdjacentToUnsafe": "AdjacentToUnsafe",
    "FfiBoundary": "FfiBoundary",
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
    "Unknown",
}

VALID_ORACLE_VERDICTS = {
    "Unknown",
    "AddressSanitizerDoubleFree",
    "AddressSanitizerUseAfterFree",
    "AddressSanitizerOutOfBounds",
    "AddressSanitizerInvalidFree",
    "AddressSanitizerLeak",
    "MiriUndefinedBehavior",
    "MiriUnsupported",
    "OracleTimeout",
}

VALID_HARNESS_STATUS = {
    "ConfirmedValid",
    "LikelyValid",
    "LikelyMisuse",
    "Invalid",
    "Unknown",
}


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
    required_meta = ["tool", "variant", "seed", "run_index", "budget_seconds", "return_code"]
    missing_meta = [k for k in required_meta if k not in meta]
    if missing_meta:
        raise RuntimeError(f"run_meta.json missing required fields: {missing_meta}")

    row = summarize_classification(case_name, suite, classification)
    row.update(
        {
            "tool": meta["tool"],
            "variant": meta["variant"],
            "seed": meta["seed"],
            "run_index": meta["run_index"],
            "budget_seconds": meta["budget_seconds"],
            "return_code": meta["return_code"],
        }
    )
    return row
