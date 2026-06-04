#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 {
        return;
    }
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();

    let _ = std::panic::catch_unwind(|| {
        let _ = rsec_borrowck_any_as_u8_slice::any_as_u8_slice_like(&rsec_borrowck_any_as_u8_slice::Padded { a: 1, b: 2 }, true);
    });
});
