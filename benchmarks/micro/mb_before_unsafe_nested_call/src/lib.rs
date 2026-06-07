use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_READ: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";
pub const FN_INNER: &str = "crate::inner_raw_read";

fn validate(input: &[u8]) {
    assert!(
        !input.is_empty(),
        "input must not be empty before unsafe helper"
    );
    assert!(input[0] != 0, "zero is rejected before unsafe helper");
}

fn inner_raw_read(input: &[u8]) -> u8 {
    let _guard = dpr_function!(FN_INNER);
    unsafe {
        dpr_hit!(SITE_RAW_READ);
        *input.as_ptr()
    }
}

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    validate(input);
    inner_raw_read(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn empty_panics_before_nested_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[]);
    }

    #[test]
    #[should_panic]
    fn zero_panics_before_nested_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[0]);
    }

    #[test]
    fn nonzero_reaches_nested_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(process(&[7]), 7);
    }
}
