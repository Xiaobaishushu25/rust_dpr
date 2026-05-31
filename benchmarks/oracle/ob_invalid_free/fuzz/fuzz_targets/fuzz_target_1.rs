#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};
use ob_invalid_free as benchmark;

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    
    // Convert the input data to a boolean to control the invalid free
    let do_invalid_free = if !data.is_empty() { data[0] != 0 } else { false };
    
    let _ = std::panic::catch_unwind(|| {
        benchmark::trigger(do_invalid_free);
    });
});
