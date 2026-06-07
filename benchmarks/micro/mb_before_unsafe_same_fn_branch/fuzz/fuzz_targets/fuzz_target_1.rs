#![no_main]
use libfuzzer_sys::fuzz_target;
use mb_before_unsafe_same_fn_branch::process;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let _ = std::panic::catch_unwind(|| {
        let _ = process(data);
    });
});
