#![no_main]
use libfuzzer_sys::fuzz_target;
use ob_asan_oob_write_control::write_one_past_end;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    let trigger = data.first().copied().unwrap_or(0) == 0xA5;
    write_one_past_end(trigger);
});
