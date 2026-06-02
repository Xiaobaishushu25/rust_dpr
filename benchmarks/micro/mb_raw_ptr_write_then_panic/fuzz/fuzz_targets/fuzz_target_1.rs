#![no_main]

use libfuzzer_sys::fuzz_target;
use mb_raw_ptr_write_then_panic::write_then_check;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("artifacts/fuzz_trace.jsonl");
    install_panic_hook();

    let value = data.first().copied().unwrap_or(0);
    let reject = data.get(1).map(|b| b % 2 == 1).unwrap_or(false);

    let _ = std::panic::catch_unwind(|| {
        let _ = write_then_check(value, reject);
    });
});
