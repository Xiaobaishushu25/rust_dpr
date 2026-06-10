#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rustdpr_trace::init_trace("fuzz_trace.jsonl");
    rustdpr_trace::install_panic_hook();
    let _ = rw_bytes_buf_ops::run_input(data);
});
