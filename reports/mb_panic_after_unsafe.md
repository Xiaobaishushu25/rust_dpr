# RustDPR Report: mb_panic_after_unsafe

## Dangerous Sites
- S0001 UnsafeBlock ./benchmarks/micro/mb_panic_after_unsafe\src\lib.rs:8-8

## Panic Sites
- P0001 UnwrapCall ./benchmarks/micro/mb_panic_after_unsafe\src\lib.rs:29-29

## Trace Events
- Hit { site_id: "S0001", ts_millis: 1778502028883 }
- Panic { message: Some("out must not be zero after unsafe write"), file: Some("benchmarks\\micro\\mb_panic_after_unsafe\\src\\lib.rs"), line: Some(16), ts_millis: 1778502028883 }

## Classification
- Relation: AfterUnsafe
- Class: PanicAfterUnsafe
- Reached Sites: ["S0001"]

## Notes
- dangerous site reached before panic
