# Pipeline Comparison

Baseline: `cargo-fuzz/crash-only`
Treatment: `cargo-fuzz/full`

Summary: 5 metrics improved, 3 regressed, 16 unchanged.

| Metric | Direction | Baseline | Treatment | Improvement | Relative improvement | Result |
|---|---:|---:|---:|---:|---:|---|
| mcp | ↑ | 1.0000 | 0.6552 | -0.3448 | -34.48% | regressed |
| panic_noise_fpr | ↓ | 0.0000 | 0.3448 | -0.3448 | n/a | regressed |
| oracle_confirmed_rate | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| oracle_confirmed_per_reported | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| review_load | ↓ | 0.9000 | 0.2333 | 0.6667 | 74.07% | improved |
| reviews_per_confirmed | ↓ | 0.0000 | 0.0000 | -0.0000 | n/a | unchanged |
| harness_misuse_rejection_rate | ↑ | 0.0000 | 0.1333 | 0.1333 | n/a | improved |
| security_relevant_recall | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| precision_at_1 | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| precision_at_5 | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| precision_at_10 | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| recall_at_10 | ↑ | 0.1235 | 0.1754 | 0.0520 | 42.11% | improved |
| ndcg_at_10 | ↑ | 1.0000 | 1.0000 | 0.0000 | 0.00% | unchanged |
| oracle_confirmed_at_1 | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| oracle_confirmed_at_5 | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| oracle_confirmed_at_10 | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| ttae_ms | ↓ | 0.0000 | 1,781,617,626,213 | -1,781,617,626,213 | n/a | regressed |
| obe | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| obe_per_cpu_minute | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| duplicate_collapse_ratio | ↑ | 3.0000 | 3.0000 | 0.0000 | 0.00% | unchanged |
| actionable_yield_per_cpu_hour | ↑ | 0.0000 | 38.0000 | 38.0000 | n/a | improved |
| oracle_confirmed_yield_per_cpu_hour | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged |
| wdpc_mean | ↑ | 0.0000 | 0.1969 | 0.1969 | n/a | improved |
| ttds_mean_events | ↓ | 1.0000 | 1.0000 | -0.0000 | -0.00% | unchanged |
