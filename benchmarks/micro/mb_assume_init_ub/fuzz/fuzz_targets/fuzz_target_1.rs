#![no_main]

use libfuzzer_sys::fuzz_target;
use mb_assume_init_ub::materialize;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
        // 初始化追踪系统
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
    // 输入验证
    if data.is_empty() {
        return;
    }
    // 将字节转换为布尔参数
    let trigger = data[0] > 127;  // 50% 概率为 true
    // 捕获 panic（因为 assert! 会 panic）
    let _ = std::panic::catch_unwind(|| {
        let _ = materialize(trigger);
    });
});
