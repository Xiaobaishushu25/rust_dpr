from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

from common import ROOT_DIR, SUITES, read_json, resolve_case, run_cmd, write_json

MARKER_BEGIN = "# BEGIN RUSTDPR INSTRUMENTED DEPENDENCY PATCH"
MARKER_END = "# END RUSTDPR INSTRUMENTED DEPENDENCY PATCH"


def copytree_clean(src: Path, dst: Path) -> None:
    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {
            name
            for name in names
            if name in {"target", ".git", "artifacts", "data"}
            or name.endswith(".profraw")
            or name.endswith(".profdata")
        }

    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=ignore)


def run_metadata(case_dir: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--manifest-path", str(case_dir / "Cargo.toml")],
        cwd=str(ROOT_DIR),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or "cargo metadata failed")
    return json.loads(proc.stdout)


def select_dependency_packages(metadata: dict[str, Any], dep_crates: list[str]) -> list[dict[str, Any]]:
    root_id = metadata.get("resolve", {}).get("root")
    requested = {d.strip() for d in dep_crates if d.strip()}
    packages = []
    for pkg in metadata.get("packages", []):
        if pkg.get("id") == root_id:
            continue
        name = str(pkg.get("name") or "")
        if requested and name not in requested:
            continue
        manifest = Path(pkg["manifest_path"])
        if not manifest.exists():
            continue
        packages.append(pkg)
    packages.sort(key=lambda p: (str(p.get("name")), str(p.get("version"))))
    return packages


def sanitize_path_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def rel_path_for_toml(from_dir: Path, to_dir: Path) -> str:
    return Path(to_dir).resolve().relative_to(from_dir.resolve()).as_posix() if False else Path(
        __import__("os").path.relpath(str(to_dir.resolve()), str(from_dir.resolve()))
    ).as_posix()


def append_patch_table(manifest: Path, patch_entries: dict[str, Path], *, base_dir: Path) -> bool:
    text = manifest.read_text(encoding="utf-8", errors="replace") if manifest.exists() else ""
    if MARKER_BEGIN in text:
        text = re.sub(
            rf"\n?{re.escape(MARKER_BEGIN)}.*?{re.escape(MARKER_END)}\n?",
            "\n",
            text,
            flags=re.DOTALL,
        ).rstrip() + "\n"

    lines = ["", MARKER_BEGIN, "[patch.crates-io]"]
    for name, dep_dir in sorted(patch_entries.items()):
        rel = rel_path_for_toml(base_dir, dep_dir)
        lines.append(f'{name} = {{ path = "{rel}" }}')
    lines.append(MARKER_END)
    lines.append("")
    manifest.write_text(text.rstrip() + "\n" + "\n".join(lines), encoding="utf-8")
    return True


def append_trace_dependency(dep_manifest: Path) -> None:
    text = dep_manifest.read_text(encoding="utf-8", errors="replace")
    if "[dependencies.rustdpr-trace]" in text or "rustdpr-trace" in text:
        return
    trace_path = (ROOT_DIR / "crates" / "rustdpr-trace").resolve().as_posix()
    block = f'\n# Added by RustDPR dependency instrumentation.\n[dependencies.rustdpr-trace]\npath = "{trace_path}"\n'
    dep_manifest.write_text(text.rstrip() + "\n" + block, encoding="utf-8")


def find_function_body_insert_line(lines: list[str], line_start: int, line_end: int) -> int | None:
    start = max(line_start - 1, 0)
    end = min(max(line_end, line_start), len(lines))
    for idx in range(start, end):
        if "{" in lines[idx]:
            return idx + 1
    return None


def indent_after_open_brace(line: str) -> str:
    prefix = re.match(r"\s*", line).group(0) if re.match(r"\s*", line) else ""
    return prefix + "    "


def load_functions_by_id(function_index: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fn in function_index.get("functions", []):
        by_id[str(fn.get("function_id"))].append(fn)
    return by_id


def instrument_sites(
    *,
    site_map: dict[str, Any],
    function_index: dict[str, Any],
    source_to_vendored_root: dict[str, Path],
) -> dict[str, Any]:
    functions_by_id = load_functions_by_id(function_index)
    sites_by_file_and_insert: dict[tuple[Path, int], list[str]] = defaultdict(list)
    skipped: list[dict[str, Any]] = []

    for site in site_map.get("dangerous_sites", []):
        if site.get("source_origin") != "dependency":
            continue
        source_root = str(Path(str(site.get("source_root") or "")).resolve())
        vendored_root = source_to_vendored_root.get(source_root)
        if vendored_root is None:
            skipped.append({"site_id": site.get("site_id"), "reason": "dependency root was not vendored"})
            continue
        span = site.get("span") or {}
        rel_file = str(span.get("file") or "")
        if not rel_file:
            skipped.append({"site_id": site.get("site_id"), "reason": "missing span file"})
            continue
        target_file = vendored_root / rel_file
        if not target_file.exists():
            skipped.append({"site_id": site.get("site_id"), "reason": f"source file not found after vendoring: {rel_file}"})
            continue

        fn_candidates = functions_by_id.get(str(site.get("enclosing_fn") or ""), [])
        fn_match = None
        for fn in fn_candidates:
            if fn.get("file") == rel_file:
                fn_match = fn
                break
        if fn_match is None:
            skipped.append({"site_id": site.get("site_id"), "reason": "enclosing function not found in function_index"})
            continue

        lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines()
        insert_line = find_function_body_insert_line(
            lines,
            int(fn_match.get("line_start") or span.get("line_start") or 1),
            int(fn_match.get("line_end") or span.get("line_end") or span.get("line_start") or 1),
        )
        if insert_line is None:
            skipped.append({"site_id": site.get("site_id"), "reason": "could not find function body opening brace"})
            continue
        sites_by_file_and_insert[(target_file, insert_line)].append(str(site["site_id"]))

    instrumented_count = 0
    for (target_file, insert_line), site_ids in sorted(sites_by_file_and_insert.items(), key=lambda item: (str(item[0][0]), -item[0][1])):
        lines = target_file.read_text(encoding="utf-8", errors="replace").splitlines()
        open_brace_line = max(insert_line - 1, 0)
        indent = indent_after_open_brace(lines[open_brace_line] if open_brace_line < len(lines) else "")
        hit_lines = [f'{indent}rustdpr_trace::dpr_hit!("{site_id}");' for site_id in sorted(set(site_ids))]
        lines[insert_line:insert_line] = hit_lines
        target_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        instrumented_count += len(set(site_ids))

    return {"instrumented_sites": instrumented_count, "skipped_sites": skipped}


def main() -> int:
    parser = argparse.ArgumentParser(description="Vendor and instrument dependency dangerous sites for dynamic RustDPR tracing")
    parser.add_argument("case", help="case name")
    parser.add_argument("--suite", choices=SUITES, required=True)
    parser.add_argument("--dep-crates", default="", help="comma-separated dependency crates to vendor/instrument")
    parser.add_argument("--work-dir", required=True, help="fresh working copy of the benchmark case")
    parser.add_argument("--out-dir", required=True, help="instrumentation metadata directory")
    args = parser.parse_args()

    suite, original_case_dir = resolve_case(args.case, args.suite)
    work_dir = Path(args.work_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    copytree_clean(original_case_dir, work_dir)

    dep_crates = [d.strip() for d in args.dep_crates.split(",") if d.strip()]
    metadata = run_metadata(work_dir)
    packages = select_dependency_packages(metadata, dep_crates)
    if not packages:
        raise SystemExit(f"no dependency packages selected for instrumentation: dep_crates={dep_crates}")

    pre_site_map = out_dir / "site_map.pre_instrumentation.json"
    pre_function_index = out_dir / "function_index.pre_instrumentation.json"
    analyze_cmd = [
        "cargo",
        "run",
        "-p",
        "rustdpr-cli",
        "--",
        "analyze-sites",
        "--crate-root",
        str(work_dir),
        "--out",
        str(pre_site_map),
        "--function-out",
        str(pre_function_index),
        "--include-deps",
    ]
    if dep_crates:
        analyze_cmd.extend(["--dep-crates", ",".join(dep_crates)])
    run_cmd(analyze_cmd, cwd=ROOT_DIR)

    site_map = read_json(pre_site_map)
    function_index = read_json(pre_function_index)

    vendor_root = work_dir / "vendor" / "rustdpr-instrumented"
    patch_entries: dict[str, Path] = {}
    source_to_vendored_root: dict[str, Path] = {}
    vendored = []

    for pkg in packages:
        name = str(pkg["name"])
        version = str(pkg.get("version") or "unknown")
        source_root = Path(pkg["manifest_path"]).parent.resolve()
        vendored_dir = vendor_root / f"{sanitize_path_component(name)}-{sanitize_path_component(version)}"
        copytree_clean(source_root, vendored_dir)
        append_trace_dependency(vendored_dir / "Cargo.toml")
        patch_entries[name] = vendored_dir
        source_to_vendored_root[str(source_root)] = vendored_dir
        vendored.append(
            {
                "name": name,
                "version": version,
                "source_root": str(source_root),
                "vendored_root": str(vendored_dir),
                "manifest": str(vendored_dir / "Cargo.toml"),
            }
        )

    append_patch_table(work_dir / "Cargo.toml", patch_entries, base_dir=work_dir)
    fuzz_manifest = work_dir / "fuzz" / "Cargo.toml"
    if fuzz_manifest.exists():
        append_patch_table(fuzz_manifest, patch_entries, base_dir=fuzz_manifest.parent)

    inst = instrument_sites(
        site_map=site_map,
        function_index=function_index,
        source_to_vendored_root=source_to_vendored_root,
    )

    manifest = {
        "schema_version": "0.2.0",
        "suite": suite,
        "case": args.case,
        "original_case_dir": str(original_case_dir),
        "work_case_dir": str(work_dir),
        "dep_crates": dep_crates,
        "vendored": vendored,
        "site_map": str(pre_site_map),
        "function_index": str(pre_function_index),
        "instrumented_sites": inst["instrumented_sites"],
        "skipped_sites": inst["skipped_sites"],
        "patch_manifests": [str(work_dir / "Cargo.toml")] + ([str(fuzz_manifest)] if fuzz_manifest.exists() else []),
        "instrumentation_granularity": "function-entry proxy hits for dependency dangerous sites",
    }
    write_json(out_dir / "instrumentation_manifest.json", manifest)
    print("[done]")
    print(f"work case          : {work_dir}")
    print(f"vendored deps      : {len(vendored)}")
    print(f"instrumented sites : {manifest['instrumented_sites']}")
    print(f"manifest           : {out_dir / 'instrumentation_manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
