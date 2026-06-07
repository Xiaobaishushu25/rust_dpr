#![no_main]
use libfuzzer_sys::fuzz_target;
use mb_maybeuninit_assume_init_after_panic::build_then_validate;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let _ = std::panic::catch_unwind(|| {
        let _ = build_then_validate(data);
    });
});
