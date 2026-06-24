SUITE ?= regression
HARNESS_DIR ?= generated_harnesses
ORACLE_BUDGET_MINUTES ?= 30
ORACLE_MAX_CANDIDATES ?= 20
FUZZ_BUDGET_SECONDS ?= 3600

validate-manifest:
	python3 scripts/validate_benchmark_manifest.py --enforce-min

validate-realworld:
	python3 scripts/validate_benchmark_manifest.py --suite realworld --enforce-min --min-cases 1

fuzz-realworld:
	python3 scripts/validate_fuzz_harnesses.py --suite realworld --summary-json reports/fuzz_harnesses_realworld.json
	python3 scripts/run_suite.py --suite realworld --mode fuzz --repeat 1 --seeds 1 --budget-seconds 30 --summary-json reports/fuzz_realworld_summary.json --summary-csv reports/fuzz_realworld_summary.csv
	python3 scripts/compute_metrics.py --suite realworld --out reports/metrics_realworld_fuzz.json

smoke:
	python3 scripts/validate_benchmark_manifest.py --suite micro --enforce-min --min-cases 1
	python3 scripts/run_suite.py --suite micro --repeat 1 --seeds 1 --summary-json reports/smoke_micro.json --summary-csv reports/smoke_micro.csv
	python3 scripts/check_expected.py --suite micro --strict
	python3 scripts/compute_metrics.py --suite micro --out reports/metrics_micro.json

smoke-realworld:
	python3 scripts/validate_benchmark_manifest.py --suite realworld --enforce-min --min-cases 1
	python3 scripts/validate_fuzz_harnesses.py --suite realworld --summary-json reports/fuzz_harnesses_realworld.json
	python3 scripts/run_suite.py --suite realworld --mode fuzz --repeat 1 --seeds 1 --budget-seconds 30 --summary-json reports/smoke_realworld.json --summary-csv reports/smoke_realworld.csv
	python3 scripts/compute_metrics.py --suite realworld --out reports/metrics_realworld.json

rank-candidates:
	python3 scripts/rank_candidates.py --suite $(SUITE) --out-csv reports/candidates_ranked_$(SUITE).csv --out-jsonl reports/candidates_ranked_$(SUITE).jsonl --out-json reports/candidates_ranked_$(SUITE).json

oracle-queue-plan: rank-candidates
	python3 scripts/run_oracle_queue.py --ranked-csv reports/candidates_ranked_$(SUITE).csv --out-json reports/oracle_queue_$(SUITE).json --out-csv reports/oracle_queue_$(SUITE).csv --max-candidates $(ORACLE_MAX_CANDIDATES) --budget-minutes $(ORACLE_BUDGET_MINUTES)

paper-efficiency: oracle-queue-plan
	python3 scripts/compute_metrics.py --suite $(SUITE) --out reports/metrics_$(SUITE)_efficiency.json
	python3 scripts/make_tables.py --metrics reports/metrics_$(SUITE)_efficiency.json --out-dir reports/tables

assist-generated:
	mkdir -p $(HARNESS_DIR) reports/generated_harness
	python3 scripts/run_generated_harness_eval.py --harness-dir $(HARNESS_DIR) --out-dir reports/generated_harness --total-budget-seconds $(FUZZ_BUDGET_SECONDS)

compare-rulf-rustdpr:
	python3 scripts/compute_metrics.py --suite generated_harness --out reports/metrics_generated_harness.json
	python3 scripts/compare_pipelines.py --metrics reports/metrics_generated_harness.json --baseline rulf/crash-only --treatment rulf/full --out-json reports/rulf_vs_rustdpr_delta.json --out-csv reports/rulf_vs_rustdpr_delta.csv --out-md reports/rulf_vs_rustdpr_delta.md




# ---- cargo-fuzz official baseline integration helpers ----
# Example:
#   make cargo-fuzz-pilot-compare CRATE=url CRATE_VERSION=2.5.0 CRATE_ROOT=/path/to/rust-url CARGO_FUZZ_TARGET=parse FUZZ_BUDGET_SECONDS=300 LIMIT=1
CRATE_ROOT ?=
CARGO_FUZZ_TARGET ?=
CARGO_FUZZ_LOG_DIR ?= reports/cargo_fuzz_logs
CARGO_FUZZ_SEED ?= 1
CARGO_FUZZ_RUN_INDEX ?= 1
CARGO_FUZZ_REPLAY_REPEAT ?= 1
CARGO_FUZZ_CAMPAIGN_ROOT ?= data/cargo_fuzz_campaigns/$(CRATE)
CARGO_FUZZ_RUN_SUMMARY ?= $(CARGO_FUZZ_LOG_DIR)/summary.json
CANDIDATE_TRUTH ?=

run-cargo-fuzz:
	python3 scripts/run_cargo_fuzz_pilot.py --crate-root $(CRATE_ROOT) $(if $(CARGO_FUZZ_TARGET),--target $(CARGO_FUZZ_TARGET),) --budget-seconds $(FUZZ_BUDGET_SECONDS) --seed $(CARGO_FUZZ_SEED) --run-index $(CARGO_FUZZ_RUN_INDEX) --campaign-root $(CARGO_FUZZ_CAMPAIGN_ROOT) --log-dir $(CARGO_FUZZ_LOG_DIR) --summary-json $(CARGO_FUZZ_RUN_SUMMARY)

collect-cargo-fuzz:
	python3 scripts/collect_cargo_fuzz_inputs.py --crate $(CRATE) --crate-version "$(CRATE_VERSION)" --crate-root $(CRATE_ROOT) $(if $(CARGO_FUZZ_TARGET),--target $(CARGO_FUZZ_TARGET),) --suite $(SUITE) --seed $(CARGO_FUZZ_SEED) --run-index $(CARGO_FUZZ_RUN_INDEX) --budget-seconds $(FUZZ_BUDGET_SECONDS) --run-summary $(CARGO_FUZZ_RUN_SUMMARY)

run-cargo-fuzz-rustdpr:
	python3 scripts/run_cargo_fuzz_rustdpr_batch.py --crate $(CRATE) --crate-root $(CRATE_ROOT) --suite $(SUITE) --seed $(CARGO_FUZZ_SEED) --run-index $(CARGO_FUZZ_RUN_INDEX) $(if $(CARGO_FUZZ_TARGET),--target $(CARGO_FUZZ_TARGET),) --variant full --input-kind artifacts --replay-repeat $(CARGO_FUZZ_REPLAY_REPEAT) $(if $(LIMIT),--limit $(LIMIT),)

materialize-cargo-fuzz-baselines:
	python3 scripts/materialize_external_baselines.py --suite $(SUITE) --source-tool cargo-fuzz --source-variant full --baseline crash-only --out-variant crash-only

compare-cargo-fuzz-rustdpr: materialize-cargo-fuzz-baselines
	python3 scripts/compute_metrics.py --suite $(SUITE) --out reports/metrics_$(SUITE)_cargo_fuzz.json $(if $(CANDIDATE_TRUTH),--candidate-truth $(CANDIDATE_TRUTH),)
	python3 scripts/compare_pipelines.py --metrics reports/metrics_$(SUITE)_cargo_fuzz.json --baseline cargo-fuzz/crash-only --treatment cargo-fuzz/full --out-json reports/cargo_fuzz_vs_rustdpr_delta.json --out-csv reports/cargo_fuzz_vs_rustdpr_delta.csv --out-md reports/cargo_fuzz_vs_rustdpr_delta.md

cargo-fuzz-pilot-compare: run-cargo-fuzz collect-cargo-fuzz run-cargo-fuzz-rustdpr compare-cargo-fuzz-rustdpr
