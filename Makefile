analyze:
	cargo run -p rustdpr-cli -- analyze-sites --crate . --out data/site_map.json

dpg:
	cargo run -p rustdpr-cli -- build-dpg --site-map data/site_map.json --out data/dpg.json

micro:
	python3 scripts/run_micro.py

summary:
	python3 scripts/collect_results.py

fmt:
	cargo fmt --all