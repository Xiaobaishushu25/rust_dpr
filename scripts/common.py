from __future__ import annotations

import csv
import json
import os
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


def ensure_pyyaml() -> None:
    if yaml is None:
        print("PyYAML is required. Install with: pip install pyyaml")
        raise SystemExit(1)


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


def suite_case_data_dir(suite: str, case_name: str) -> Path:
    return DATA_DIR / suite / case_name


def possible_trace_paths(case_dir: Path) -> list[Path]:
    return [
        case_dir / "artifacts" / "trace.jsonl",
        case_dir / "trace.jsonl",
        case_dir / "target" / "trace.jsonl",
    ]


def find_trace_file(case_dir: Path) -> Path:
    for p in possible_trace_paths(case_dir):
        if p.exists():
            return p

    found = list(case_dir.rglob("trace.jsonl"))
    if found:
        return found[0]

    raise FileNotFoundError(f"trace.jsonl not found under {case_dir}")


def jsonl_trace_to_tracelog_json(trace_jsonl: Path, out_json: Path) -> Path:
    events: list[dict[str, Any]] = []

    with trace_jsonl.open("r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"invalid JSONL trace at {trace_jsonl}, line {idx}: {e}"
                ) from e

    write_json(out_json, {"events": events})
    return out_json


def parse_oracle_verdict_from_log_text(content: str, source: str) -> str:
    lower = content.lower()

    if source == "asan":
        if "double-free" in lower:
            return "AddressSanitizerDoubleFree"
        if "use-after-free" in lower:
            return "AddressSanitizerUseAfterFree"
        if "out-of-bounds" in lower or "heap-buffer-overflow" in lower:
            return "AddressSanitizerOutOfBounds"
        return "Unknown"

    if source == "miri":
        if "undefined behavior" in lower or "ub" in lower:
            return "MiriUndefinedBehavior"
        return "Unknown"

    raise ValueError(f"unknown oracle source: {source}")


PRIMARY_LABEL_MAP = {
    "Noise": "Noise",
    "NormalContractPanic": "ContractPanic",
    "ContractPanic": "ContractPanic",
    "HarnessMisuse": "HarnessMisuse",
    "BlockingPanic": "BlockingPanic",
    "PanicAfterUnsafe": "PanicAfterUnsafe",
    "InsideUnsafePanic": "InsideUnsafePanic",
    "DangerousPathReached": "DangerousPathReached",
    "OracleConfirmedBug": "OracleConfirmedBug",
    "OracleConfirmedDoubleFree": "OracleConfirmedBug",
    "OracleConfirmedUseAfterFree": "OracleConfirmedBug",
    "OracleConfirmedOutOfBounds": "OracleConfirmedBug",
    "SuspiciousCandidate": "SuspiciousCandidate",
    "Unknown": "Unknown",
}

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


def normalize_primary_label(value: Any) -> Any:
    if value is None:
        return None
    return PRIMARY_LABEL_MAP.get(str(value), str(value))


def normalize_relation_label(value: Any) -> Any:
    if value is None:
        return None
    return RELATION_LABEL_MAP.get(str(value), str(value))


def normalize_oracle_verdicts(values: Any) -> Any:
    if values is None:
        return None

    if isinstance(values, list) and values:
        first = str(values[0])
    else:
        first = str(values)

    mapping = {
        "Unknown": "Unknown",
        "DoubleFree": "AddressSanitizerDoubleFree",
        "UseAfterFree": "AddressSanitizerUseAfterFree",
        "OutOfBounds": "AddressSanitizerOutOfBounds",
        "UndefinedBehavior": "MiriUndefinedBehavior",
        "AddressSanitizerDoubleFree": "AddressSanitizerDoubleFree",
        "AddressSanitizerUseAfterFree": "AddressSanitizerUseAfterFree",
        "AddressSanitizerOutOfBounds": "AddressSanitizerOutOfBounds",
        "MiriUndefinedBehavior": "MiriUndefinedBehavior",
    }
    return mapping.get(first, first)


def normalize_expected_schema(expected: dict[str, Any]) -> dict[str, Any]:
    # 新 schema
    if "expected_primary_label" in expected:
        return {
            "primary_label": normalize_primary_label(expected.get("expected_primary_label")),
            "relation": normalize_relation_label(expected.get("expected_relation")),
            "oracle_verdict": normalize_oracle_verdicts(expected.get("expected_oracle")),
            "harness_status": expected.get("expected_harness_validity"),
            "reached_count": len(expected.get("expected_reached_dangerous_sites", [])),
        }

    # 中间 schema：expected_class / expected_relation / expected_reached_sites
    if "expected_class" in expected:
        return {
            "primary_label": normalize_primary_label(expected.get("expected_class")),
            "relation": normalize_relation_label(expected.get("expected_relation")),
            "oracle_verdict": normalize_oracle_verdicts(expected.get("expected_oracle")),
            "harness_status": expected.get("expected_harness_validity"),
            "reached_count": int(expected.get("expected_reached_sites", 0) or 0),
        }

    # 旧嵌套 schema：expected: { ... }
    old = expected.get("expected", {})
    oracle_verdict = normalize_oracle_verdicts(old.get("oracle_verdicts"))

    relation = expected.get("expected_relation")
    if relation is None:
        panic_observed = old.get("panic_observed")
        reached = old.get("reached_dangerous_site")
        if reached and panic_observed:
            relation = "AfterUnsafe"
        elif reached and not panic_observed:
            relation = "NoneObserved"
        elif (not reached) and panic_observed:
            relation = "BeforeUnsafe"
        else:
            relation = None

    return {
        "primary_label": normalize_primary_label(old.get("class")),
        "relation": normalize_relation_label(relation),
        "oracle_verdict": oracle_verdict,
        "harness_status": None,
        "reached_count": 1 if old.get("reached_dangerous_site") else 0,
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
        "notes_count": len(data.get("notes", {}).get("notes", [])),
    }