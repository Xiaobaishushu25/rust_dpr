# cargo-fuzz Baseline Protocol for RustDPR

This protocol provides the first practical generated-harness baseline for RustDPR before the more difficult RULF reproduction is complete.

## Why cargo-fuzz first?

`cargo-fuzz` is the standard Cargo subcommand for Rust fuzzing with libFuzzer. It is widely documented, installable with `cargo install cargo-fuzz`, and uses the normal `fuzz/fuzz_targets/*.rs` project layout. This makes it a better near-term baseline than RULF, whose artifact requires a custom rustdoc/fuzz-target-generator workflow.

The comparison should not claim that RustDPR generates better fuzz targets. The fair claim is:

> Given the same official cargo-fuzz targets and the same libFuzzer outputs, RustDPR improves the validation and triage of panic/crash candidates by adding dangerous-site evidence, dynamic traces when available, harness-validity analysis, and oracle/replay evidence.

## Experimental groups

| Group | Meaning | Candidate decision |
|---|---|---|
| `cargo-fuzz/crash-only` | Native cargo-fuzz/libFuzzer triage | any crash/artifact/non-zero run is reported |
| `cargo-fuzz/full` | cargo-fuzz + RustDPR | DPG + trace + harness validity + optional ASan/Miri/replay |

Both groups must use the same fuzz target, crate version, seed, budget, and libFuzzer output directory.

## Setup

Use Linux or WSL2. `cargo-fuzz` requires libFuzzer/LLVM sanitizer support and nightly Rust.

```bash
rustup toolchain install nightly
rustup +nightly component add rust-src llvm-tools-preview
cargo install cargo-fuzz
```

Inside the target crate:

```bash
cargo +nightly fuzz init
# edit fuzz/fuzz_targets/<target>.rs if needed
cargo +nightly fuzz list
```

## One-target pilot

```bash
# 1. Run official cargo-fuzz/libFuzzer.
python3 scripts/run_cargo_fuzz_pilot.py \
  --crate-root /path/to/crate \
  --target fuzz_target_1 \
  --budget-seconds 300 \
  --seed 1

# 2. Collect its official project-layout outputs.
python3 scripts/collect_cargo_fuzz_outputs.py \
  --crate mycrate \
  --crate-version 0.1.0 \
  --crate-root /path/to/crate \
  --target fuzz_target_1 \
  --seed 1 \
  --budget-seconds 300 \
  --log-dir reports/cargo_fuzz_logs

# 3. Run RustDPR validation on the same cargo-fuzz output.
python3 scripts/run_cargo_fuzz_rustdpr_batch.py \
  --crate mycrate \
  --crate-root /path/to/crate \
  --variant full \
  --limit 1

# 4. Materialize the native cargo-fuzz baseline.
python3 scripts/materialize_external_baselines.py \
  --suite generated_harness \
  --source-tool cargo-fuzz \
  --source-variant full \
  --baseline crash-only \
  --out-variant crash-only

# 5. Compute and compare.
python3 scripts/compute_metrics.py \
  --suite generated_harness \
  --out reports/metrics_generated_harness.json

python3 scripts/compare_pipelines.py \
  --metrics reports/metrics_generated_harness.json \
  --baseline cargo-fuzz/crash-only \
  --treatment cargo-fuzz/full \
  --out-json reports/cargo_fuzz_vs_rustdpr_delta.json \
  --out-csv reports/cargo_fuzz_vs_rustdpr_delta.csv \
  --out-md reports/cargo_fuzz_vs_rustdpr_delta.md
```

## Makefile shortcut

```bash
make cargo-fuzz-pilot-compare \
  CRATE=mycrate \
  CRATE_VERSION=0.1.0 \
  CRATE_ROOT=/path/to/crate \
  CARGO_FUZZ_TARGET=fuzz_target_1 \
  FUZZ_BUDGET_SECONDS=300 \
  LIMIT=1
```

## Notes for paper writing

- `cargo-fuzz` is a wrapper around libFuzzer, not a harness generator. Therefore the paper should call this comparison an **official Rust fuzzing pipeline baseline**, not a generated-harness baseline.
- For crates with manually written cargo-fuzz targets, the fairness condition is strong: both groups consume exactly the same target and output.
- For crates without existing targets, the target construction policy must be documented separately. Do not mix manual target quality with RustDPR's triage value.
- If no `trace.jsonl` is available, RustDPR still evaluates static dangerous-site evidence and harness validity, but relation evidence is weaker. Report this as an ablation/limitation rather than hiding it.
