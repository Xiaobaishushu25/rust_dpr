#![no_main]
use libfuzzer_sys::fuzz_target;
use tb_inside_unsafe_assert_macro::check_inside_unsafe;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let _ = std::panic::catch_unwind(|| {
        let _ = check_inside_unsafe(data);
    });
});
