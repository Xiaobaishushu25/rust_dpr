#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};
use tb_inside_unsafe_panic as benchmark;

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    
    let _ = std::panic::catch_unwind(|| {
        benchmark::trigger(data);
    });
});
