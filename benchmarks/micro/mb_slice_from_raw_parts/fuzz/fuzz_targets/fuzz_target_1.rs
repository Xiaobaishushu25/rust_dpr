#![no_main]

use libfuzzer_sys::fuzz_target;
use mb_slice_from_raw_parts::view_then_check;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("artifacts/fuzz_trace.jsonl");
    install_panic_hook();
    
    // 使用输入数据确定是否应该触发panic
    let should_panic = if data.is_empty() {
        false
    } else {
        data[0] % 2 == 1  // 如果第一个字节是奇数，则触发panic
    };
    
    let _ = std::panic::catch_unwind(|| {
        let _ = view_then_check(should_panic);
    });
});
