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