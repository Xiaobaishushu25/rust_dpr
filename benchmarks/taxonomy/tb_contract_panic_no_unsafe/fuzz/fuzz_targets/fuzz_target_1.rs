#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};
use tb_contract_panic_no_unsafe as benchmark;

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    
    let _ = std::panic::catch_unwind(|| {
        let _result = benchmark::parse_header(data);
    });
});
