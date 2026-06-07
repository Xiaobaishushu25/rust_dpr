#![no_main]
use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};
use tb_harness_direct_unsafe_precondition::unsafe_sum_raw_parts;

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    if data.first().copied().unwrap_or(0) == 0xFF {
        let bogus_len = usize::MAX / 4;
        let _ = std::panic::catch_unwind(|| unsafe {
            let _ = unsafe_sum_raw_parts(data.as_ptr(), bogus_len);
        });
    }
});
