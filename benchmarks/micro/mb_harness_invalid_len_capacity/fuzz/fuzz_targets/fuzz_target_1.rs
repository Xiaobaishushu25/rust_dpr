#![no_main]
use libfuzzer_sys::fuzz_target;
use mb_harness_invalid_len_capacity::sum_raw_parts;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let len = data.first().copied().unwrap_or(0) as usize;
    let ptr = if data.len() > 1 { data[1..].as_ptr() } else { std::ptr::null() };
    let _ = std::panic::catch_unwind(|| unsafe {
        let _ = sum_raw_parts(ptr, len);
    });
});
