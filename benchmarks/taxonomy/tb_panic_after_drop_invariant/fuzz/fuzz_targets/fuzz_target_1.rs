#![no_main]

use libfuzzer_sys::fuzz_target;
use rustdpr_trace::{init_trace, install_panic_hook};
use tb_panic_after_drop_invariant as benchmark;

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("artifacts/trace.jsonl");
    install_panic_hook();
    
    // Convert the input data to a boolean to control the panic
    let trigger_panic = if !data.is_empty() { data[0] != 0 } else { false };
    
    let _ = std::panic::catch_unwind(|| {
        let _result = benchmark::trigger(trigger_panic);
    });
});
