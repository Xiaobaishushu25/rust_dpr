use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_TRANSMUTE: &str = "S00001";
pub const FN_CONVERT: &str = "crate::convert_len";

/// 将4字节数组转换为 usize 值，并根据合约要求检查零值
///
/// # 参数
/// * `bytes`: 包含要转换的4字节数据的数组
/// * `allow_zero`: 是否允许返回零值；如果为false且转换结果为0，则触发断言失败
///
/// # 返回值
/// 转换后的 usize 值
///
/// # 安全性
/// 该函数使用 unsafe 代码块执行 transmute 操作，这可能引入未定义行为
/// 如果不允许零值但输入为零，则会触发合约断言
pub fn convert_len(bytes: [u8; 4], allow_zero: bool) -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_CONVERT);

    let value: u32 = unsafe {
        dpr_hit!(SITE_TRANSMUTE);
        std::mem::transmute(bytes)
    };
    assert!(allow_zero || value != 0, "zero value rejected by contract");
    value as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn contract_panic_after_transmute() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = convert_len([0, 0, 0, 0], false);
    }
}
