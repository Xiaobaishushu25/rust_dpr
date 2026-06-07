#![no_main]
use libfuzzer_sys::fuzz_target;
use mb_none_static_unsafe_unreached::process;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let _ = std::panic::catch_unwind(|| {
        let _ = process(data);
    });
});
