# RULF vs RULF+RustDPR: Quantitative-Advantage Protocol

This document is the next-step experiment protocol for turning RustDPR from a post-hoc static triage layer into a paper-facing evidence-optimization layer over RULF/RPG-style generated harnesses.

## Core claim

Do **not** claim that RustDPR is a stronger fuzz engine than RULF. The fair and stronger claim is:

> Given the same RULF-generated harnesses, seeds, fuzzing budget, and crash/panic output stream, RustDPR improves the precision, evidence quality, review efficiency, and oracle budget efficiency of security-relevant candidate validation. In assist mode, RustDPR further uses dangerous-path and harness-validity evidence to rank harnesses, allocate fuzzing/oracle budget, and shorten time-to-actionable evidence.

This makes RustDPR a validation-and-evidence optimizer, not a static afterthought.

## Experimental settings

### A. Passive validation comparison

Use the exact same RULF outputs for both sides.

| Pipeline | Input | Decision rule | Purpose |
|---|---|---|---|
| Native RULF | RULF harnesses + fuzz logs + crashes/panics | report crash/panic as candidate | Baseline review burden and noise |
| RULF+RustDPR passive | same outputs | RustDPR DPG + trace + harness validity + ASan/Miri + replay | Quantify better candidate evidence |

Metrics:

- MCP: meaningful candidates / reported candidates.
- Panic Noise FPR: noise reported as high-value / reported candidates.
- Review Load: candidates requiring manual review per crate/run.
- Oracle-confirmed rate and OracleConfirmed@k.
- Reviews-to-first-confirmed and reviews-per-confirmed.
- Duplicate-collapse ratio.
- wDPC and TTDS, when trace and site map are available.

### B. Assist-mode comparison

Use RULF as the harness generator, but let RustDPR decide which harnesses and candidates deserve budget.

| Pipeline | Input | Feedback used | Purpose |
|---|---|---|---|
| Native RULF schedule | RULF harnesses | RULF/API coverage or uniform budget | Conventional harness execution |
| RULF+RustDPR assist | same harnesses | harness validity, dangerous-site inventory, short-run trace, wDPC, candidate rank | Evidence-guided budget allocation |

Metrics:

- Valid harness rate among selected top-k harnesses.
- Harness misuse rate among selected top-k harnesses.
- Actionable yield per CPU-hour.
- Oracle-confirmed yield per CPU-hour.
- Time-to-first-actionable evidence (TTAE).
- Time-to-first-oracle-confirmed evidence (TTOC).
- Oracle budget efficiency (OBE = confirmed candidates / oracle runs).

## Required fairness rules

1. Same crate version, features, toolchain, seed schedule, and total fuzzing budget.
2. Native RULF and RULF+RustDPR passive must consume the same RULF raw outputs.
3. Assist mode may reallocate budget, but total budget must remain identical.
4. Build failures, unsupported oracle results, timeouts, and missing harnesses must be counted.
5. If original RULF is not fully reproducible, label the pipeline as `rulf-approx` and explicitly report what was approximated.
6. RustDPR must not be credited for new input mutation unless an actual feedback loop is implemented and evaluated separately.

## How to run the comparison

### 1. Normalize RULF outputs

Expected raw directory shape:

```text
rulf_outputs/<crate>/<harness_id>/
  fuzz_target.rs
  trace.jsonl              # optional but strongly recommended
  crashes/                 # optional
  coverage.json            # optional
  corpus/                  # optional
```

Normalize one raw harness output:

```bash
python3 external_tools/rulf/adapter.py \
  --crate <crate> \
  --crate-version <version> \
  --harness-id <harness_id> \
  --raw-dir rulf_outputs/<crate>/<harness_id> \
  --out data/external_runs/rulf/<crate>/<harness_id>/external_meta.json
```

### 2. Run RustDPR over the same outputs

Use `scripts/run_external_output.py` or the existing run-level pipeline to produce:

```text
data/runs/generated_harness/<case>/rulf/full/seed-<seed>/run-<idx>/
  run_meta.json
  site_map.json
  dpg.json
  trace_log.json
  harness_validity.json
  classification.json
  replay_summary.json      # if replay was executed
  oracle_summary.json      # if ASan/Miri was executed
```

For native RULF triage, create a `rulf/panic-only` or `rulf/crash-only` baseline classification over the same run directory. For RustDPR passive, use `rulf/full`.

### 3. Compute metrics

```bash
python3 scripts/compute_metrics.py \
  --suite generated_harness \
  --out reports/metrics_generated_harness.json
```

### 4. Compare native RULF against RULF+RustDPR

```bash
python3 scripts/compare_pipelines.py \
  --metrics reports/metrics_generated_harness.json \
  --baseline rulf/crash-only \
  --treatment rulf/full \
  --out-json reports/rulf_vs_rustdpr_delta.json \
  --out-csv reports/rulf_vs_rustdpr_delta.csv \
  --out-md reports/rulf_vs_rustdpr_delta.md
```

If native RULF baseline is encoded as `rulf/generated-harness`, replace the baseline key accordingly.

## Paper table template

| Method | MCP ↑ | Panic Noise FPR ↓ | OracleConfirmed@5 ↑ | Review Load ↓ | Reviews/Confirmed ↓ | OBE ↑ | TTAE ↓ | wDPC ↑ |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Native RULF | | | | | | | | |
| RULF+RustDPR passive | | | | | | | | |
| RULF+RustDPR assist | | | | | | | | |

## Strong novelty framing

The novelty should be written as **evidence-guided validation and budget optimization**:

1. RULF/RPG solve **which API sequence or harness to generate**.
2. FourFuzz-style tools solve **how to bias fuzzing toward unsafe code coverage**.
3. RustDPR solves **whether the resulting panic/crash is security-relevant, reproducible, and worth oracle/reviewer budget**.
4. RustDPR assist mode closes the loop by feeding validation evidence back into harness ranking, fuzz-budget allocation, and oracle scheduling.

A concise formulation:

> RustDPR turns generated-harness fuzzing from output enumeration into evidence-aware candidate optimization: it separates contract panic and harness misuse from dangerous-path evidence, ranks candidates by dynamic panic-danger relation and oracle support, and schedules scarce fuzzing/oracle/reviewer budget toward candidates with the highest expected security value.

## Minimum acceptance bar for the next experiment round

- At least 5 crates with RULF or RULF-approx harnesses.
- At least 3 seeds per crate for the first pilot; 5–10 seeds for the paper table.
- Both native RULF and RULF+RustDPR passive over exactly the same raw outputs.
- Assist mode only after passive comparison is stable.
- Report unsupported/build-failure/timeout explicitly.
