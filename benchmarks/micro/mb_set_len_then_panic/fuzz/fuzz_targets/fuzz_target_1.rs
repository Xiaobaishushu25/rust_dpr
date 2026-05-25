#![no_main]

use libfuzzer_sys::fuzz_target;
use mb_set_len_then_panic::build_vec;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    // 初始化追踪系统
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    // 输入验证：至少需要 1 个字节来决定是否触发 panic
    if data.is_empty() {
        return;
    }
    // 根据第一个字节决定是否触发 panic
    // 当 data[0] > 127 时 (约 50% 概率) 触发 panic
    let trigger = data[0] > 127;
    // 捕获可能的 panic（当 trigger 为 true 时会 panic）
    let _ = std::panic::catch_unwind(|| {
        build_vec(trigger);
    });
});
