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
        use rw_arena_nonnull_handle::*; let buf = [0xfeu8, data[0]]; let _ = allocate_handle(&buf);
    });
});
