#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    if data.first().copied() == Some(b'G') {
        rsec_qwutils_2021_0018_fixed::run_fixed_public_api_contract_panic();
    }
});
