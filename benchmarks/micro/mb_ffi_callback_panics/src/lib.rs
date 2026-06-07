use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_FFI_CALLBACK: &str = "S00001";
pub const FN_CALL_CALLBACK: &str = "crate::call_callback";

pub type Callback = extern "C-unwind" fn(u8) -> u8;

extern "C-unwind" fn panicking_callback(x: u8) -> u8 {
    assert!(x != 0, "callback panic crosses C-unwind ABI boundary");
    x
}

pub fn call_callback(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_CALL_CALLBACK);
    let cb: Callback = panicking_callback;
    let x = input.first().copied().unwrap_or(0);

    unsafe {
        dpr_hit!(SITE_FFI_CALLBACK);
        cb(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn zero_panics_at_ffi_boundary() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = call_callback(&[0]);
    }

    #[test]
    fn nonzero_ok() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(call_callback(&[5]), 5);
    }
}
