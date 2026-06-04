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