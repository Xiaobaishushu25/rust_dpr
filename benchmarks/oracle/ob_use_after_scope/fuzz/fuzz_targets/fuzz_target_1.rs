#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};
use ob_use_after_scope as benchmark;

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    
    // Convert the input data to a boolean to control reading after scope
    let read_after_scope = if !data.is_empty() { data[0] != 0 } else { false };
    
    let _ = std::panic::catch_unwind(|| {
        let _result = benchmark::trigger(read_after_scope);
    });
});
