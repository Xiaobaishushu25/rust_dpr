use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_VALID_RAW_READ: &str = "S00001";
pub const FN_PROCESS: &str = "crate::valid_raw_read";

pub fn valid_raw_read(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    let value = input.first().copied().unwrap_or(0);
    let ptr = &value as *const u8;
    unsafe {
        dpr_hit!(SITE_VALID_RAW_READ);
        *ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn valid_raw_read_has_no_oracle_finding() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(valid_raw_read(&[3]), 3);
    }
}
