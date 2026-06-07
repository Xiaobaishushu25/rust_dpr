use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_FFI_BOUNDARY: &str = "S00001";
pub const FN_PROCESS: &str = "crate::process";
pub const FN_CALLBACK: &str = "crate::ffi_like_callback";

extern "C-unwind" fn ffi_like_callback(flag: u8) -> u8 {
    let _guard = dpr_function!(FN_CALLBACK);
    if flag == 0 {
        panic!("panic crosses an extern C-unwind style boundary");
    }
    flag
}

pub fn process(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    let flag = input.first().copied().unwrap_or(0);
    unsafe {
        dpr_hit!(SITE_FFI_BOUNDARY);
        ffi_like_callback(flag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn zero_panics_across_boundary() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = process(&[0]);
    }

    #[test]
    fn nonzero_ok() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(process(&[4]), 4);
    }
}
