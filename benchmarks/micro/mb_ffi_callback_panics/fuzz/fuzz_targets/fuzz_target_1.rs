#![no_main]
use libfuzzer_sys::fuzz_target;
use mb_ffi_callback_panics::call_callback;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let _ = std::panic::catch_unwind(|| {
        let _ = call_callback(data);
    });
});
