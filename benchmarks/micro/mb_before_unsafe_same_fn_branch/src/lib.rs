use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_READ: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);

    if input.first().copied().unwrap_or(0) == 0 {
        panic!("guard rejected input before same-function unsafe block");
    }

    unsafe {
        dpr_hit!(SITE_RAW_READ);
        *input.as_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn zero_panics_before_unsafe_in_same_function() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[0]);
    }

    #[test]
    fn nonzero_reaches_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(process(&[9]), 9);
    }
}
