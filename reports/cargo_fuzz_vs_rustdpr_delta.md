# Pipeline Comparison

Baseline: `cargo-fuzz/crash-only`
Treatment: `cargo-fuzz/full`

Summary: 10 comparable metrics improved, 3 regressed, 14 unchanged, 5 not comparable due to missing value/support.

> `mcp` and `panic_noise_fpr` are MAIN review-queue metrics: denominator is `review_required=true` for precision and truth-negative cases entering the review queue for FPR.
> `mcp_all_classified_diagnostic` and `panic_noise_fpr_all_classified_diagnostic` keep the old all-classified view for debugging only.
> `label_mcp_diagnostic` is included only for debugging old label-based behavior.

| Metric | Direction | Baseline | Treatment | Improvement | Relative improvement | Result | Baseline support | Treatment support |
|---|---:|---:|---:|---:|---:|---|---|---|
| mcp | ↑ | 0.7037 | 1.0000 | 0.2963 | 42.11% | improved | num=57,den=81;n=81;missing=6 | num=57,den=57;n=57;missing=6 |
| panic_noise_fpr | ↓ | 0.8889 | 0.0000 | 0.8889 | 100.00% | improved | num=24,den=27;n=27;missing=6 | num=0,den=27;n=27;missing=6 |
| review_queue_recall | ↑ | 1.0000 | 1.0000 | 0.0000 | 0.00% | unchanged | num=57,den=57;n=57;missing=6 | num=57,den=57;n=57;missing=6 |
| review_load | ↓ | 0.9643 | 0.6786 | 0.2857 | 29.63% | improved | num=81,den=84;n=84;missing=6 | num=57,den=84;n=84;missing=6 |
| mcp_all_classified_diagnostic | ↑ | 0.7037 | 0.6786 | -0.0251 | -3.57% | regressed | num=57,den=81;n=81;missing=6 | num=57,den=84;n=84;missing=6 |
| panic_noise_fpr_all_classified_diagnostic | ↓ | 0.8889 | 1.0000 | -0.1111 | -12.50% | regressed | num=24,den=27;n=27;missing=6 | num=27,den=27;n=27;missing=6 |
| label_mcp_diagnostic | ↑ | 1.0000 | 0.6786 | -0.3214 | -32.14% | regressed | num=81,den=81;n=81;missing=6 | num=57,den=84;n=84;missing=6 |
| oracle_confirmed_rate | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged | num=0,den=84;n=84;missing=6 | num=0,den=84;n=84;missing=6 |
| oracle_confirmed_per_reported | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged | num=0,den=81;n=81;missing=6 | num=0,den=84;n=84;missing=6 |
| oracle_confirmed_per_review_queue | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged | num=0,den=81;n=81;missing=6 | num=0,den=57;n=57;missing=6 |
| reviews_to_first_confirmed | ↓ | 1.0000 | 1.0000 | -0.0000 | -0.00% | unchanged | n/a | n/a |
| reviews_per_confirmed | ↓ | n/a | n/a | n/a | n/a | not_comparable | n/a | n/a |
| harness_misuse_rejection_rate | ↑ | 0.0000 | 0.1071 | 0.1071 | n/a | improved | num=0,den=84;n=84;missing=6 | num=9,den=84;n=84;missing=6 |
| security_relevant_recall | ↑ | 1.0000 | 1.0000 | 0.0000 | 0.00% | unchanged | num=57,den=57;n=57;missing=6 | num=57,den=57;n=57;missing=6 |
| security_relevant_recall_all_classified_diagnostic | ↑ | 1.0000 | 1.0000 | 0.0000 | 0.00% | unchanged | num=57,den=57;n=57;missing=6 | num=57,den=57;n=57;missing=6 |
| precision_at_1 | ↑ | 1.0000 | 1.0000 | 0.0000 | 0.00% | unchanged | num=1,den=1;n=84;missing=6 | num=1,den=1;n=84;missing=6 |
| precision_at_5 | ↑ | 0.6000 | 1.0000 | 0.4000 | 66.67% | improved | num=3,den=5;n=84;missing=6 | num=5,den=5;n=84;missing=6 |
| precision_at_10 | ↑ | 0.3000 | 1.0000 | 0.7000 | 233.33% | improved | num=3,den=10;n=84;missing=6 | num=10,den=10;n=84;missing=6 |
| recall_at_10 | ↑ | 0.0526 | 0.1754 | 0.1228 | 233.33% | improved | num=3,den=57;n=84;missing=6 | num=10,den=57;n=84;missing=6 |
| ndcg_at_10 | ↑ | 0.4690 | 1.0000 | 0.5310 | 113.22% | improved | num=2.1309297535714578,den=4.543559338088346;n=84;missing=6 | num=13.630678014265039,den=13.630678014265039;n=84;missing=6 |
| oracle_confirmed_at_1 | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged | n/a | n/a |
| oracle_confirmed_at_5 | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged | n/a | n/a |
| oracle_confirmed_at_10 | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged | n/a | n/a |
| ttae_ms | ↓ | n/a | n/a | n/a | n/a | not_comparable | num=None,den=0;n=0;missing=6 | num=None,den=57;n=57;missing=6 |
| ttoc_ms | ↓ | n/a | n/a | n/a | n/a | not_comparable | num=None,den=0;n=0;missing=6 | num=None,den=0;n=0;missing=6 |
| obe | ↑ | n/a | n/a | n/a | n/a | not_comparable | n/a | n/a |
| obe_per_cpu_minute | ↑ | n/a | n/a | n/a | n/a | not_comparable | n/a | n/a |
| duplicate_collapse_ratio | ↑ | 3.0000 | 3.0000 | 0.0000 | 0.00% | unchanged | n/a | n/a |
| actionable_yield_per_cpu_hour | ↑ | 0.0000 | 40.7143 | 40.7143 | n/a | improved | n/a | n/a |
| oracle_confirmed_yield_per_cpu_hour | ↑ | 0.0000 | 0.0000 | 0.0000 | n/a | unchanged | n/a | n/a |
| wdpc_mean | ↑ | 0.0000 | 0.2110 | 0.2110 | n/a | improved | num=0.0,den=84;n=84;missing=6 | num=17.72463054187192,den=84;n=84;missing=6 |
| ttds_mean_events | ↓ | 1.0000 | 1.0000 | -0.0000 | -0.00% | unchanged | num=60,den=60;n=60;missing=6 | num=60,den=60;n=60;missing=6 |
