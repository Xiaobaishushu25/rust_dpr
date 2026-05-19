# RustDPR Artifact Evaluation

## Environment

- Rust toolchain: pinned by `rust-toolchain.toml`
- Python: 3.10+
- Optional: nightly + Miri + ASan support

## Smoke Test

```bash
make smoke
```

Expected:

- micro suite runs successfully;
- expected labels pass;
- metrics JSON generated.

## Main Evaluation

```bash
make eval-micro
make eval-oracle
make eval-taxonomy
```

## Outputs

- `data/runs/`: per-run artifacts
- `reports/metrics_*.json`: metrics
- `reports/tables/*.csv`: paper tables
- `reports/figures/*.pdf`: plots
