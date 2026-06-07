#![no_main]
use libfuzzer_sys::fuzz_target;
use mb_drop_invariant_after_panic::duplicate_then_panic;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let flag = data.first().copied().unwrap_or(0) == 0xAA;
    let _ = std::panic::catch_unwind(|| duplicate_then_panic(flag));
});
