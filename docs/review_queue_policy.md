# RustDPR review queue policy

RustDPR emits a classification for every evidence-supported replayed input, but not every
classification should enter the main human review queue. The review queue is the denominator for
main triage precision/FPR metrics.

## Main policy

The main review queue should include actionable security-relevant evidence:

- `OracleConfirmedBug`: confirmed by ASan/Miri/replay oracle.
- `InsideUnsafePanic`: panic/crash occurred inside a dangerous unsafe/FFI region.
- `PanicAfterUnsafe`: panic/crash occurred after an actionable dangerous site was reached.
- `SuspiciousCandidate`: weaker dangerous-path evidence that still needs human review.
- `UnsupportedOracle`: the candidate cannot be confirmed automatically but remains suspicious.

The main review queue should exclude outputs that are useful diagnostics but should not be reported
as vulnerability candidates:

- `BlockingPanic` / `BeforeUnsafe`: panic blocks the dangerous path.
- `ContractPanic` / `NoneObserved`: panic has no observed dangerous-path relation.
- `HarnessMisuse`: invalid harness artifact, counted for rejection statistics instead.
- `Noise` / `Unknown`: no actionable evidence.
- `DangerousPathReached` without panic: useful for wDPC/TTDS evidence, but not a panic/crash candidate.

## Why this changed

The earlier policy accidentally sent `SuspiciousCandidate` and some `ContractPanic` outputs to the
review queue, while excluding high-confidence `PanicAfterUnsafe`, `InsideUnsafePanic`, and
`FfiBoundary` cases. This made review-queue recall artificially low even when relation
classification and ranking were correct.

## Expected metric effect

After this change, review load will increase compared with the overly conservative gate, but
review-queue recall should recover. The intended evaluation trade-off is:

- main `mcp`: precision among `review_required=true` candidates;
- main `panic_noise_fpr`: truth-negative cases that enter the review queue;
- `review_queue_recall`: truth-positive cases retained by the review queue;
- `review_load`: review queue size per evidence-supported run;
- ranking metrics still evaluate budgeted top-k ordering separately.
