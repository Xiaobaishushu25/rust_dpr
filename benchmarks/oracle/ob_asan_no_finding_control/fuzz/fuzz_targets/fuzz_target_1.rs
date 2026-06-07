#![no_main]
use libfuzzer_sys::fuzz_target;
use ob_asan_no_finding_control::process;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let _ = process(data);
});
