#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};
use tb_harness_misuse_invalid_input as benchmark;
use std::ptr;

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    
    // Create a pointer based on input data - may be null if data is empty
    let ptr = if data.is_empty() {
        ptr::null() // This will cause the assertion to fail
    } else {
        data.as_ptr()
    };
    
    let _ = std::panic::catch_unwind(|| {
        unsafe {
            let _result = benchmark::read_non_null(ptr);
        }
    });
});
