#![no_main]

use libfuzzer_sys::fuzz_target;
use ob_oob_raw::trigger;
use rustdpr_trace::{init_trace, install_panic_hook};
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| {
        let _ = init_trace("fuzz_trace.jsonl");
        install_panic_hook();
    });

    // oracle harness 里，fuzzer 输入只负责决定是否触发漏洞，
    // 不负责生成任意 usize 索引。否则 idx 过大时可能被 ASan 报成 UAF。
    if data.is_empty() {
        return;
    }

    // 约 50% 概率触发漏洞，保持和其他 oracle harness 风格一致。
    if data[0] <= 127 {
        return;
    }

    // Vec 长度是 3，合法索引是 0、1、2。
    // idx = 3 是第一个越界位置，也就是 one-past-the-end。
    // 这样最稳定地触发 ASan 的 heap-buffer-overflow / OOB。
    let _ = trigger(3);
});