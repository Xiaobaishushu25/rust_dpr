#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();

    let _ = std::panic::catch_unwind(|| {
        use rw_image_stride_copy::*; let _ = copy_row(data, data.len().min(8), 1);
    });
});
