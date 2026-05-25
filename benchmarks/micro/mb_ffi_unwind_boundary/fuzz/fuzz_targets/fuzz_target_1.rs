#![no_main]

use libfuzzer_sys::fuzz_target;
use mb_ffi_unwind_boundary::invoke_callback;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();
       if data.is_empty() {
        return; // 处理空输入
    }
    let byte_value = data[0]; // 获取第一个字节作为 u8
    let _ = std::panic::catch_unwind(|| {
        let _ = invoke_callback(byte_value); // 或直接使用 byte_value
    });
});
