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
