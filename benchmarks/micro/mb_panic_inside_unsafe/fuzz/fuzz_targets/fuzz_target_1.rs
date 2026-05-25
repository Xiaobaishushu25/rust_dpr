#![no_main]

use libfuzzer_sys::fuzz_target;
use mb_panic_inside_unsafe::process;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
        // 初始化追踪系统
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();

    // 捕获 panic（因为当 data[0] == 0xff 时会 panic）
    let _ = std::panic::catch_unwind(|| {
        process(data);
    });
});
