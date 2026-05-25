#![no_main]

use libfuzzer_sys::fuzz_target;
use mb_transmute_contract::convert_len;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    // 初始化追踪系统
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();

    // 输入验证：至少需要4个字节来构造 [u8; 4] 数组
    if data.len() < 4 {
        return;
    }

    // 从输入数据中提取前4个字节作为转换的输入
    let bytes: [u8; 4] = [data[0], data[1], data[2], data[3]];

    // 根据输入的第5个字节（如果存在）或默认值决定是否允许零值
    let allow_zero = if data.len() > 4 {
        data[4] > 127  // 约50%概率
    } else {
        false  // 默认不允许零值，增加触发panic的机会
    };

    // 捕获可能的 panic（当 bytes 为 [0,0,0,0] 且 allow_zero 为 false 时会 panic）
    let _ = std::panic::catch_unwind(|| {
        let _ = convert_len(bytes, allow_zero);
    });
});
