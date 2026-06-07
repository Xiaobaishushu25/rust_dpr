use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNSAFE_REGION: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    let mut out = 0u8;

    unsafe {
        dpr_hit!(SITE_UNSAFE_REGION);
        assert!(!input.is_empty(), "panic occurs inside unsafe region");
        let ptr = &mut out as *mut u8;
        *ptr = *input.as_ptr();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn empty_panics_inside_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[]);
    }

    #[test]
    fn non_empty_ok() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(process(&[9]), 9);
    }
}
