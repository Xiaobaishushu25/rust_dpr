use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNSAFE_WRITE: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);

    let mut out = 0u8;

    unsafe {
        dpr_hit!(SITE_UNSAFE_WRITE);
        let ptr = &mut out as *mut u8;
        if let Some(first) = input.first() {
            *ptr = *first;
        }
    }

    assert!(out != 0, "out must not be zero after unsafe write");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn empty_panics_after_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[]);
    }

    #[test]
    fn non_empty_ok() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(process(&[3]), 3);
    }
}
