# RustDPR Passive/Assist Experiment Pipeline

This note documents the next-step implementation added for paper-facing evidence-efficiency experiments.

## Why this pipeline exists

RustDPR should not claim that it mutates inputs or improves the fuzz engine directly. The paper-facing speed claim should instead be:

- Passive mode reduces the time and review/oracle budget needed to identify actionable or confirmed evidence from a fixed fuzzing output stream.
- Assist mode feeds RustDPR evidence back into harness filtering, harness ranking, fuzz-budget allocation, and oracle scheduling.

## New outputs

### Candidate ranking

```bash
python3 scripts/rank_candidates.py \
  --suite regression \
  --out-csv reports/candidates_ranked_regression.csv \
  --out-jsonl reports/candidates_ranked_regression.jsonl \
  --out-json reports/candidates_ranked_regression.json
```

The ranked candidate table contains:

- `score`: RustDPR evidence score;
- `evidence_grade`: `oracle-confirmed-replay-stable`, `oracle-confirmed`, `actionable`, `suspicious`, or `noise-or-unsupported`;
- relation, primary label, harness status, oracle verdict, replay stability;
- first-seen, dangerous-hit, panic, and oracle timing fields when available;
- duplicate cluster key and duplicate ordinal.

### Oracle queue planning / execution

Plan only, using existing oracle verdicts:

```bash
python3 scripts/run_oracle_queue.py \
  --ranked-csv reports/candidates_ranked_regression.csv \
  --out-json reports/oracle_queue_regression.json \
  --out-csv reports/oracle_queue_regression.csv \
  --max-candidates 20 \
  --budget-minutes 30
```

Execute ASan and Miri in RustDPR ranking order:

```bash
python3 scripts/run_oracle_queue.py \
  --ranked-csv reports/candidates_ranked_regression.csv \
  --out-json reports/oracle_queue_regression.json \
  --out-csv reports/oracle_queue_regression.csv \
  --max-candidates 20 \
  --budget-minutes 30 \
  --execute
```

The queue summary reports `OracleConfirmed@1/@5/@10`, TTOC, OBE, and OBE per CPU-minute.

### Generated harness scoring and scheduling

```bash
python3 scripts/run_generated_harness_eval.py \
  --harness-dir generated_harnesses \
  --out-dir reports/generated_harness \
  --strategy score-proportional \
  --total-budget-seconds 3600
```

This creates:

- `generated_harness_scores.csv/json`;
- `generated_harness_schedule.csv`;
- `generated_harness_eval_summary.json/md`.

The score combines compile metadata, harness validity, static misuse patterns, dangerous-site inventory, short-run dangerous hits, and oracle evidence when available.

## Make targets

```bash
make rank-candidates SUITE=regression
make oracle-queue-plan SUITE=regression
make paper-efficiency SUITE=regression
make assist-generated HARNESS_DIR=generated_harnesses FUZZ_BUDGET_SECONDS=3600
```

## Metrics added to `compute_metrics.py`

The metrics JSON now includes:

- `recall_at_10`;
- `ndcg_at_10`;
- `oracle_confirmed_at_1`, `oracle_confirmed_at_5`, `oracle_confirmed_at_10`;
- `ttae_ms` and `ttoc_ms`;
- `oracle_runs`, `oracle_cpu_seconds`, `obe`, and `obe_per_cpu_minute`;
- `duplicate_collapse_ratio`;
- `actionable_yield_per_cpu_hour`;
- `oracle_confirmed_yield_per_cpu_hour`.

These metrics should be used to support the validation-speed and evidence-yield claims, not a claim that RustDPR itself is a new fuzzer.
