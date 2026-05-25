#![no_main]

use libfuzzer_sys::fuzz_target;
use mb_harness_misuse_null::deref_non_null;
use rustdpr_trace::{init_trace, install_panic_hook};

fuzz_target!(|data: &[u8]| {
    // 初始化追踪系统
    let _ = init_trace("fuzz_trace.jsonl");
    install_panic_hook();

    // 输入验证：至少需要 1 个字节来决定指针类型
    if data.is_empty() {
        return;
    }
    // 根据输入字节构造指针
    // data[0] == 0 时构造空指针，否则构造非空但可能无效的指针
    let ptr = if data[0] == 0 {
        std::ptr::null::<u8>()
    } else {
        // 构造一个非空但可能无效的指针地址
        // 使用 data 的其他字节作为地址的低 8 位
        let addr = if data.len() >= 2 {
            data[1] as usize
        } else {
            0x1000 // 固定的小地址（通常是无效的）
        };
        addr as *const u8
    };
    // 捕获 panic（因为空指针会触发 assert!）
    let _ = std::panic::catch_unwind(|| {
        unsafe {
            let _ = deref_non_null(ptr);
        }
    });
});
