# Regression benchmark expansion: real external crate versions

This update intentionally replaces the earlier minimized-advisory-model direction with
regression cases that call real historical external crates, matching the existing
`benchmarks/regression` style.

## Added crate-version pairs

| Case pair | Real crate versions | Advisory | Public trigger |
|---|---|---|---|
| `rsec_scratchpad_2021_0030_{vuln,fixed}` | `scratchpad = 1.3.0` / `1.3.1` | RUSTSEC-2021-0030 | `SliceMoveSource::move_elements` with a panicking closure |
| `rsec_stack_dst_2021_0033_{vuln,fixed}` | `stack_dst = 0.6.0` / `0.6.1` | RUSTSEC-2021-0033 | `StackA::push_cloned` with a panicking `Clone` implementation |
| `rsec_qwutils_2021_0018_{vuln,fixed}` | `qwutils = 0.3.0` / `0.3.1` | RUSTSEC-2021-0018 | `VecExt::insert_slice_clone` with a panicking `Clone` implementation |

Each vulnerable case uses child-process replay, because historical double-free and
uninitialized-drop bugs can terminate by ordinary panic, allocator diagnostics, abort,
or platform-specific abnormal exit. Each fixed case preserves the same public API shape
and adversarial user callback/trait implementation, but asserts that the panic is a
contract panic without abnormal drop evidence.

## Important reproducibility note

These cases are pinned as crates.io dependencies rather than simplified local models. If a
historical vulnerable release is yanked by crates.io, artifact reproduction should either
vendor that exact upstream source under `vendor/` and add a `[patch.crates-io]` entry, or
commit a Cargo.lock generated in an environment that already resolved the yanked version.
This mirrors the repository's existing approach for yanked external regression crates.

## Why these cases fit RustDPR

All three cases exercise the same evaluation question as the current regression suite:
user-code panic occurs through a safe public API after an unsafe ownership/length/pointer
state transition inside an external crate. They are therefore suitable for evaluating
panic-danger ordering, fixed-version controls, and candidate replay evidence.

## Additional real external regression cases

This second expansion keeps the same quality bar: direct calls into historical
external crate versions through public APIs, public advisory metadata in
`expected.yaml`, and fixed controls where an official fixed version exists.

| Case pair / case | Real crate versions | Advisory | Public trigger |
|---|---|---|---|
| `rsec_ms3d_2021_0016_{vuln,fixed}` | `ms3d = 0.1.2` / `0.1.3` | RUSTSEC-2021-0016 | `Model::from_reader` with a safe custom `Read` that observes the supplied buffer before writing |
| `rsec_endian_trait_2021_0039_vuln` | `endian_trait = 0.6.0` | RUSTSEC-2021-0039 | `<&mut [T] as Endian>::to_be` with a panicking user `Endian` implementation |

The ms3d pair is an oracle-oriented regression: the vulnerable crate passes an
uninitialized internal buffer to user `Read`, while the fixed version
zero-initializes that buffer. The endian_trait case has no official patched
version in RustSec, so it is deliberately recorded as an unpaired vulnerable
historical case rather than a fixed-version control.
