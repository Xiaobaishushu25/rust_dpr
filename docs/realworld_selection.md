# Real-world Benchmark Selection

## Purpose

The real-world suite evaluates whether RustDPR can validate and triage panic-adjacent dangerous paths in non-toy Rust code. Smoke-only cases are used for pipeline testing and are excluded from paper-level real-world results.

## Inclusion Criteria

A real-world case must satisfy:

1. The crate snapshot or minimized reproducer is pinned.
2. The code contains unsafe Rust, raw pointer operations, FFI, manual allocation, initialization-sensitive code, or drop-sensitive invariants.
3. The case has a deterministic test or fuzz harness.
4. The case has an expected.yaml label with selection rationale.
5. The harness must not fabricate undefined behavior by directly constructing invalid pointers unless the case is explicitly labeled as harness misuse.

## Exclusion Criteria

1. Build cannot be reproduced under the pinned toolchain.
2. The case requires network, system-specific devices, or unstable external services.
3. The finding is only an ordinary API contract panic with no dangerous-path evidence.

## Reporting

For each case, report:

- crate name and version
- source URL or local snapshot hash
- dangerous category
- fuzz/deterministic mode
- expected label
- RustDPR label
- oracle status
- harness validity
- whether the result is included in the main paper table