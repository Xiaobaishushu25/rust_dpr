#![no_main]

use libfuzzer_sys::fuzz_target;
use ob_oob_raw::trigger;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    // 初始化追踪系统
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();

    // 输入验证：至少需要8个字节来构造 usize 索引
    if data.len() < std::mem::size_of::<usize>() {
        return;
    }

    // 从输入数据中构造索引值
    // 使用前8个字节构造一个 usize 值作为索引
    let mut idx_bytes = [0u8; std::mem::size_of::<usize>()];
    idx_bytes.copy_from_slice(&data[..std::mem::size_of::<usize>()]);
    let idx = usize::from_le_bytes(idx_bytes);

    // 捕获可能的 panic 或程序崩溃（当索引导致越界访问时）
    let _ = std::panic::catch_unwind(|| {
        let _ = trigger(idx);
    });
});
