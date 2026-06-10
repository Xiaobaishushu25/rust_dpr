# Regression expansion round 2: real external RustSec crates

This round continues the paper-grade regression benchmark policy: every added
case invokes a historical vulnerable external crate version through a real public
API, and every case with an official fixed release includes a paired fixed-version
control using the same harness shape.

## Added pairs

| Advisory | Crate | Vulnerable case | Fixed control | Public API path | Expected evidence |
|---|---|---|---|---|---|
| RUSTSEC-2021-0014 | `marc` | `rsec_marc_2021_0014_vuln` (`=1.0.0`) | `rsec_marc_2021_0014_fixed` (`=2.0.0`) | `marc::Record::read` | Miri UB in vulnerable only |
| RUSTSEC-2021-0012 | `cdr` | `rsec_cdr_2021_0012_vuln` (`=0.2.3`) | `rsec_cdr_2021_0012_fixed` (`=0.2.4`) | `cdr::deserialize_from` / `Deserializer::read_vec` | Miri UB in vulnerable only |
| RUSTSEC-2021-0008 | `bra` | `rsec_bra_2021_0008_vuln` (`=0.1.0`) | `rsec_bra_2021_0008_fixed` (`=0.1.1`) | `bra::GreedyBufReader` (0.1.0) / `GreedyAccessReader` (0.1.1) / `BufRead::fill_buf` | Miri UB in vulnerable only |

## Why these cases fit RustDPR

All three advisories share a strong validation-layer pattern: safe user-provided
`Read` implementations receive a buffer from the library. In the vulnerable
version, the library-created buffer is uninitialized; in the fixed version, the
library zero-initializes it before handing it to user code. This makes each pair
useful for separating genuine dangerous-path/oracle evidence from coarse signals
such as API coverage or the mere presence of unsafe code.

The harnesses intentionally observe the buffer before writing to it. That action
is valid for arbitrary `Read` implementations; the invalid state is introduced by
the vulnerable crate, not by the harness.

## Reproducibility note

The sandbox used to generate this patch does not include `cargo`/`rustc`, so this
round was validated with RustDPR's Python benchmark schema/inventory tooling and
`git apply --check`. On a Rust toolchain, the next validation step should be:

```bash
python3 scripts/validate_benchmark_manifest.py --suite regression --paper-strict --enforce-min
python3 scripts/benchmark_inventory.py --suite regression
cargo test -p rsec_marc_2021_0014_vuln -p rsec_marc_2021_0014_fixed   -p rsec_cdr_2021_0012_vuln -p rsec_cdr_2021_0012_fixed   -p rsec_bra_2021_0008_vuln -p rsec_bra_2021_0008_fixed
```

If a historical crate version is yanked by crates.io resolution, vendor the
corresponding `.crate` snapshot under `vendor/` and add a `[patch.crates-io]`
entry, following the existing `direct_ring_buffer`/`through` pattern.
