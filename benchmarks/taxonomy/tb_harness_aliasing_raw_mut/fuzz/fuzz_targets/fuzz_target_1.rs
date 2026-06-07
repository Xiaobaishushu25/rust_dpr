#![no_main]
use libfuzzer_sys::fuzz_target;
use tb_harness_aliasing_raw_mut::mutate_unique;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    if data.len() < 4 {
        return;
    }
    let mut slot = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let p1 = &mut slot as *mut u32;
    let p2 = &mut slot as *mut u32;
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let _ = mutate_unique(p1, 1);
        let _ = mutate_unique(p2, 2);
    }));
});
