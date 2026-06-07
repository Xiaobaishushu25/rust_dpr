#![no_main]
use libfuzzer_sys::fuzz_target;
use rsec_slice_deque_2021_0047_vuln::reproduce_slice_deque_2021_0047;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let trigger = data.first().map(|b| b & 1 == 1).unwrap_or(true);
    let _ = std::panic::catch_unwind(|| {
        let _ = reproduce_slice_deque_2021_0047(trigger);
    });
});
