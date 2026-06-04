#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 {
        return;
    }
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();

    let idx = (data[0] as usize) + 8; let _ = ob_stack_oob_read::trigger(idx);
});
