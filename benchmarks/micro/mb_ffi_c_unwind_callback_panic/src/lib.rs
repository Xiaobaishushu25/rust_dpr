use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_FFI_CALLBACK: &str = "S00001";
pub const FN_CALL_CALLBACK: &str = "crate::call_callback_boundary";

pub type Callback = extern "C-unwind" fn(u8) -> u8;

extern "C-unwind" fn panicking_callback(byte: u8) -> u8 {
    if byte == 0 {
        panic!("callback panic across C-unwind boundary");
    }
    byte
}

pub fn call_callback_boundary(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_CALL_CALLBACK);
    let byte = input.first().copied().unwrap_or(0);
    unsafe {
        dpr_hit!(SITE_FFI_CALLBACK);
        let cb: Callback = panicking_callback;
        cb(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn callback_panics_at_ffi_boundary() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = call_callback_boundary(&[0]);
    }

    #[test]
    fn callback_nonzero_returns() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(call_callback_boundary(&[9]), 9);
    }
}
