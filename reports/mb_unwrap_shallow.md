# RustDPR Report: mb_unwrap_shallow

## Dangerous Sites
- none

## Panic Sites
- P0001 UnwrapCall H:\WorkSpace2\Rust\RustRover\rust-dpr\benchmarks\micro\mb_unwrap_shallow\src\lib.rs:5-5
- P0002 UnwrapCall H:\WorkSpace2\Rust\RustRover\rust-dpr\benchmarks\micro\mb_unwrap_shallow\src\lib.rs:18-18
- P0003 UnwrapCall H:\WorkSpace2\Rust\RustRover\rust-dpr\benchmarks\micro\mb_unwrap_shallow\src\lib.rs:24-24

## Trace Events
- Panic { message: Some("called `Option::unwrap()` on a `None` value"), file: Some("benchmarks\\micro\\mb_unwrap_shallow\\src\\lib.rs"), line: Some(5), ts_millis: 1778507180734 }

## Classification
- Relation: NoDangerousSiteReached
- Class: NormalContractPanic
- Reached Sites: []
- Panic Message: Some("called `Option::unwrap()` on a `None` value")
- Panic File: Some("benchmarks\\micro\\mb_unwrap_shallow\\src\\lib.rs")
- Panic Line: Some(5)

## Notes
- panic observed and crate has no dangerous site
