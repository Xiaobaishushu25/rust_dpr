use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNSAFE_REGION: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);

    unsafe {
        dpr_hit!(SITE_UNSAFE_REGION);
        let byte = input.get(1).copied().unwrap();
        let out = &byte as *const u8;
        *out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn short_input_panics_inside_unsafe_region() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[1]);
    }

    #[test]
    fn two_bytes_ok() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(process(&[1, 7]), 7);
    }
}
