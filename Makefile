analyze:
	cargo run -p rustdpr-cli -- analyze-sites \
		--crate-root . \
		--out data/site_map.json \
		--function-out data/function_index.json

dpg:
	cargo run -p rustdpr-cli -- build-dpg \
		--site-map data/site_map.json \
		--function-index data/function_index.json \
		--out data/dpg.json

micro:
	python3 scripts/run_suite.py --suite micro --summary-json reports/micro_summary.json --summary-csv reports/micro_summary.csv

oracle:
	python3 scripts/run_suite.py --suite oracle --summary-json reports/oracle_summary.json --summary-csv reports/oracle_summary.csv

taxonomy:
	python3 scripts/run_suite.py --suite taxonomy --summary-json reports/taxonomy_summary.json --summary-csv reports/taxonomy_summary.csv

check-micro:
	python3 scripts/check_expected.py --suite micro --strict

check-oracle:
	python3 scripts/check_expected.py --suite oracle --strict

check-taxonomy:
	python3 scripts/check_expected.py --suite taxonomy --strict

fmt:
	cargo fmt --all

fuzz-validate:
	python3 scripts/validate_fuzz_harnesses.py --summary-json reports/fuzz_harnesses.json

fuzz-validate-build:
	python3 scripts/validate_fuzz_harnesses.py --build --summary-json reports/fuzz_harnesses_build.json

fuzz-smoke:
	python3 scripts/run_case.py mb_panic_after_unsafe --suite micro --mode fuzz --seed 1 --run-index 1 --budget-seconds 5

fuzz-micro:
	python3 scripts/validate_fuzz_harnesses.py --suite micro --summary-json reports/fuzz_harnesses_micro.json
	python3 scripts/run_suite.py --suite micro --mode fuzz --repeat 3 --seeds 1,2,3 --budget-seconds 30 --summary-json reports/fuzz_micro_summary.json --summary-csv reports/fuzz_micro_summary.csv
	python3 scripts/compute_metrics.py --suite micro --out reports/metrics_micro_fuzz.json

fuzz-oracle:
	python3 scripts/validate_fuzz_harnesses.py --suite oracle --summary-json reports/fuzz_harnesses_oracle.json
	python3 scripts/run_suite.py --suite oracle --mode fuzz --repeat 3 --seeds 1,2,3 --budget-seconds 30 --summary-json reports/fuzz_oracle_summary.json --summary-csv reports/fuzz_oracle_summary.csv
	python3 scripts/run_oracle_suite.py --suite oracle --mode fuzz --oracle both --budget-seconds 30 --strict-expected --summary-json reports/oracle_suite_fuzz_ready.json --summary-csv reports/oracle_suite_fuzz_ready.csv
	python3 scripts/compute_metrics.py --suite oracle --out reports/metrics_oracle_fuzz.json

fuzz-taxonomy:
	python3 scripts/validate_fuzz_harnesses.py --suite taxonomy --summary-json reports/fuzz_harnesses_taxonomy.json
	python3 scripts/run_suite.py --suite taxonomy --mode fuzz --repeat 3 --seeds 1,2,3 --budget-seconds 30 --summary-json reports/fuzz_taxonomy_summary.json --summary-csv reports/fuzz_taxonomy_summary.csv
	python3 scripts/compute_metrics.py --suite taxonomy --out reports/metrics_taxonomy_fuzz.json

fuzz-validate:
	python3 scripts/validate_fuzz_harnesses.py --summary-json reports/fuzz_harnesses.json

fuzz-validate-build:
	python3 scripts/validate_fuzz_harnesses.py --build --summary-json reports/fuzz_harnesses_build.json

fuzz-smoke:
	python3 scripts/run_case.py mb_panic_after_unsafe --suite micro --mode fuzz --seed 1 --run-index 1 --budget-seconds 5

fuzz-micro:
	python3 scripts/validate_fuzz_harnesses.py --suite micro --summary-json reports/fuzz_harnesses_micro.json
	python3 scripts/run_suite.py --suite micro --mode fuzz --repeat 3 --seeds 1,2,3 --budget-seconds 30 --summary-json reports/fuzz_micro_summary.json --summary-csv reports/fuzz_micro_summary.csv
	python3 scripts/compute_metrics.py --suite micro --out reports/metrics_micro_fuzz.json

fuzz-oracle:
	python3 scripts/validate_fuzz_harnesses.py --suite oracle --summary-json reports/fuzz_harnesses_oracle.json
	python3 scripts/run_suite.py --suite oracle --mode fuzz --repeat 3 --seeds 1,2,3 --budget-seconds 30 --summary-json reports/fuzz_oracle_summary.json --summary-csv reports/fuzz_oracle_summary.csv
	python3 scripts/run_oracle_suite.py --suite oracle --mode fuzz --oracle both --budget-seconds 30 --strict-expected --summary-json reports/oracle_suite_fuzz_ready.json --summary-csv reports/oracle_suite_fuzz_ready.csv
	python3 scripts/compute_metrics.py --suite oracle --out reports/metrics_oracle_fuzz.json

fuzz-taxonomy:
	python3 scripts/validate_fuzz_harnesses.py --suite taxonomy --summary-json reports/fuzz_harnesses_taxonomy.json
	python3 scripts/run_suite.py --suite taxonomy --mode fuzz --repeat 3 --seeds 1,2,3 --budget-seconds 30 --summary-json reports/fuzz_taxonomy_summary.json --summary-csv reports/fuzz_taxonomy_summary.csv
	python3 scripts/compute_metrics.py --suite taxonomy --out reports/metrics_taxonomy_fuzz.json

fuzz-validate:
	python3 scripts/validate_fuzz_harnesses.py --summary-json reports/fuzz_harnesses.json

fuzz-validate-build:
	python3 scripts/validate_fuzz_harnesses.py --build --summary-json reports/fuzz_harnesses_build.json

fuzz-smoke:
	python3 scripts/run_case.py mb_panic_after_unsafe --suite micro --mode fuzz --seed 1 --run-index 1 --budget-seconds 5

fuzz-micro:
	python3 scripts/validate_fuzz_harnesses.py --suite micro --summary-json reports/fuzz_harnesses_micro.json
	python3 scripts/run_suite.py --suite micro --mode fuzz --repeat 3 --seeds 1,2,3 --budget-seconds 30 --summary-json reports/fuzz_micro_summary.json --summary-csv reports/fuzz_micro_summary.csv
	python3 scripts/compute_metrics.py --suite micro --out reports/metrics_micro_fuzz.json

fuzz-oracle:
	python3 scripts/validate_fuzz_harnesses.py --suite oracle --summary-json reports/fuzz_harnesses_oracle.json
	python3 scripts/run_suite.py --suite oracle --mode fuzz --repeat 3 --seeds 1,2,3 --budget-seconds 30 --summary-json reports/fuzz_oracle_summary.json --summary-csv reports/fuzz_oracle_summary.csv
	python3 scripts/run_oracle_suite.py --suite oracle --mode fuzz --oracle both --budget-seconds 30 --strict-expected --summary-json reports/oracle_suite_fuzz_ready.json --summary-csv reports/oracle_suite_fuzz_ready.csv
	python3 scripts/compute_metrics.py --suite oracle --out reports/metrics_oracle_fuzz.json

fuzz-taxonomy:
	python3 scripts/validate_fuzz_harnesses.py --suite taxonomy --summary-json reports/fuzz_harnesses_taxonomy.json
	python3 scripts/run_suite.py --suite taxonomy --mode fuzz --repeat 3 --seeds 1,2,3 --budget-seconds 30 --summary-json reports/fuzz_taxonomy_summary.json --summary-csv reports/fuzz_taxonomy_summary.csv
	python3 scripts/compute_metrics.py --suite taxonomy --out reports/metrics_taxonomy_fuzz.json
