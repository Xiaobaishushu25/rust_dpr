#![no_main]

use libfuzzer_sys::fuzz_target;
use tb_before_dangerous_site_blocking::trigger;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("artifacts/fuzz_trace.jsonl");
    install_panic_hook();
    
    // 使用输入数据确定是否应该触发panic
    let should_block = if data.is_empty() {
        false
    } else {
        data[0] % 2 == 1  // 如果第一个字节是奇数，则触发panic
    };
    
    let _ = std::panic::catch_unwind(|| {
        let _ = trigger(should_block);
    });
});
