use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_TRANSMUTE: &str = "S00001";
pub const FN_CONVERT: &str = "crate::convert_len";

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
