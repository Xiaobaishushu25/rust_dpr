#![no_main]

use libfuzzer_sys::fuzz_target;
use ob_heap_uaf::trigger;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    // 初始化追踪系统
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();

    // 输入验证：至少需要1个字节来决定是否触发 UAF
    if data.is_empty() {
        return;
    }

    // 根据第一个字节的值决定是否触发 use-after-free
    // 当 data[0] > 127 时（约50%概率）触发 UAF
    let flag = data[0] > 127;

    // 捕获可能的 panic 或程序崩溃
    let _ = std::panic::catch_unwind(|| {
        let _ = trigger(flag);
    });
});
