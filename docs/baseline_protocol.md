# Baseline Protocol

## Validation Baselines

- crash-only: every panic/crash is treated as a candidate.
- panic-only: uses panic presence/location, but not DPG or dangerous-site trace.
- static-only: uses static dangerous site count/reachability, but not dynamic trace.
- ASan-only: uses ASan verdicts on reproducers, not fuzzing guidance.
- Miri-only: uses Miri verdicts on reproducers, not fuzzing guidance.

## Approximation Baselines

- fourfuzz-approx: unsafe-site targeted evaluation using RustDPR dangerous-site map and coverage/hit evidence.
- deepsurf-approx: generated or manually supplied unsafe-focused harnesses are validated by RustDPR.

## Fairness

All validation baselines consume the same executions and traces where applicable.
End-to-end harness generation baselines are reported separately.
