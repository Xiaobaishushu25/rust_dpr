# Metrics support counts and comparison semantics

This document describes the metrics used by `scripts/compute_metrics.py` and `scripts/compare_pipelines.py` for cargo-fuzz/RULF-style input-generation baselines combined with RustDPR validation.

## Key changes in this version

1. `mcp` is now the **main review-queue precision** metric. Its denominator is candidates with `review_required=true` and available truth from benchmark `expected.yaml` or oracle verdicts. A pipeline's own `primary_label` is not used as truth.
2. `panic_noise_fpr` is now the **main review-queue false-positive rate**. It counts truth-negative/noise cases that entered the review queue, not every classification RustDPR produced.
3. `review_queue_recall` and `security_relevant_recall` measure how many truth-positive evidence-supported runs are retained in the review queue.
4. `mcp_all_classified_diagnostic` and `panic_noise_fpr_all_classified_diagnostic` preserve the old all-classified-output view for debugging. They should not be used as the main triage precision/FPR.
5. `label_mcp_diagnostic` preserves the old label-based behavior for debugging only. Do not use it as a fairness claim against crash-only baselines.
6. Missing independent replay evidence is not counted as `Noise`. It is tracked through `missing_evidence_runs` and excluded from MCP/FPR denominators.
7. `ttae_ms` and `ttoc_ms` are relative durations. Epoch-like wall-clock timestamps are discarded unless a run origin is available for subtraction.
8. Ranking metrics return `null`/`n/a` when there is no assessable ground-truth positive. Their support entries now include real numerators and denominators where applicable.
9. Each major metric has a `support` entry with numerator, denominator, included run count, missing-evidence exclusions, and notes.

## Why review queue is the main denominator

RustDPR emits a classification for every replayed input. Those classifications include `Noise`, `HarnessMisuse`, `Unknown`, and other non-actionable explanations. Treating every classification as a reported candidate incorrectly penalizes RustDPR for explaining inputs that it intentionally does **not** send to reviewers.

Therefore, paper-facing precision/FPR should be computed over the candidate queue that RustDPR actually reports:

```text
review_queue = evidence-supported runs where classification.review_required == true
```

The old all-classified view is still useful for debugging, but it is not the main triage metric.

## Important output fields

`compute_metrics.py` emits these group fields:

- `total_runs`: all classification runs found.
- `evidence_supported_runs`: runs not blocked by missing RustDPR independent replay evidence.
- `missing_evidence_runs`: runs where RustDPR independent replay did not produce trace evidence.
- `reported_candidates`: non-noise/non-unknown classified outputs after excluding missing replay evidence. Diagnostic only.
- `assessable_reported_candidates`: reported candidates with expected.yaml or oracle truth. Diagnostic only.
- `review_queue_candidates`: candidates with `review_required=true` after excluding missing replay evidence. Main paper queue.
- `assessable_review_queue_candidates`: review-queue candidates with expected.yaml or oracle truth.
- `unassessable_review_queue_candidates`: review-queue candidates lacking truth support.
- `support`: per-metric numerator/denominator and exclusion counts.

## Recommended interpretation

For paper claims, prefer:

- `mcp`, now review-queue truth-based precision,
- `panic_noise_fpr`, now review-queue false-positive rate,
- `review_queue_recall` / `security_relevant_recall`,
- `review_load`,
- `harness_misuse_rejection_rate`,
- `wdpc_mean`,
- oracle metrics only after ASan/Miri/replay oracle is connected.

Use only as diagnostics:

- `mcp_all_classified_diagnostic`,
- `panic_noise_fpr_all_classified_diagnostic`,
- `label_mcp_diagnostic`.

Do not over-interpret:

- metrics whose support denominator is 0,
- TTAE/TTOC values from pre-patch runs that contained epoch timestamps,
- oracle metrics before oracle verdicts are actually written back into classification or oracle-queue outputs.
