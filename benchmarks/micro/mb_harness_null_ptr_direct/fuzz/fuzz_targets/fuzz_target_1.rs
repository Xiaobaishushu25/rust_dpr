#![no_main]
use libfuzzer_sys::fuzz_target;
use mb_harness_null_ptr_direct::unsafe_read_first;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    if data.first().copied().unwrap_or(0) == 0 {
        let _ = std::panic::catch_unwind(|| unsafe {
            let _ = unsafe_read_first(std::ptr::null());
        });
    }
});
