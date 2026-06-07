use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_SAFE_RAW_READ: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    let value = input.first().copied().unwrap_or(0);
    let ptr = &value as *const u8;

    unsafe {
        dpr_hit!(SITE_SAFE_RAW_READ);
        *ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn safe_raw_read_has_no_oracle_finding() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(process(&[42]), 42);
        assert_eq!(process(&[]), 0);
    }
}
