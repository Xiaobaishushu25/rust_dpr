use rustdpr_trace::hit;

// 公开函数：接收一个索引 idx，返回一个 u8 类型的值
pub fn trigger(idx: usize) -> u8 {
    // 1. 创建一个长度为 3 的 Vec<u8>，分配在堆内存上
    // 合法元素：索引0=1，1=2，2=3，**索引≥3 都是非法越界**
    let v = vec![1u8, 2, 3];

    // 2. 获取 Vec 的裸指针（raw pointer）*const u8
    // 关键：Rust 对【裸指针】不做任何安全检查（无边界、无生命周期）
    let p = v.as_ptr();

    // 3. 不安全代码块：操作裸指针、解引用 属于 Rust 未定义行为范畴，必须用 unsafe 包裹
    unsafe {
        // 测试用例标记：项目自定义函数，给这个错误用例打标签 S00001（对应 OOB 裸指针错误）
        // 作用：让你的 MVP parser 能识别这是哪个测试用例
        hit("S00001");

        // 4. 核心：裸指针偏移 + 解引用（触发越界的关键代码）
        // p.add(idx)：指针向后偏移 idx 个元素（无任何边界检查！）
        // *p：解引用指针，读取内存值
        *p.add(idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::{init_trace, install_panic_hook};

    #[test]
    fn trigger_oob_raw() {
        init_trace("trace.jsonl").unwrap();
        install_panic_hook();
        let _ = trigger(4);
    }
}