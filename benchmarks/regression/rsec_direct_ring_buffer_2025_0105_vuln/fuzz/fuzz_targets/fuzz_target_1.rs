#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    if data.first().copied() == Some(b'G') {
        let _ = rsec_direct_ring_buffer_2025_0105_vuln::run_public_api_miri_poc();
    }
});
