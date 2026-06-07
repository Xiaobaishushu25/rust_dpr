#![no_main]
use libfuzzer_sys::fuzz_target;
use mb_harness_aliasing_raw_mut::write_unique_raw;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    if data.len() < 2 {
        return;
    }
    let mut byte = data[0];
    let p1 = &mut byte as *mut u8;
    let p2 = &mut byte as *mut u8;
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let _ = write_unique_raw(p1, data[1]);
        let _ = write_unique_raw(p2, data[0]);
    }));
});
