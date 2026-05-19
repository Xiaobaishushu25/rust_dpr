use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_FFI_BOUNDARY: &str = "S00001";
pub const FN_INVOKE: &str = "crate::invoke_callback";

extern "C" fn c_style_callback(flag: u8) {
    if flag == 0xff {
        panic!("callback panic across ffi-like boundary");
    }
}

pub fn invoke_callback(flag: u8) {
    install_panic_hook();
    let _guard = dpr_function!(FN_INVOKE);
    unsafe {
        dpr_hit!(SITE_FFI_BOUNDARY);
        c_style_callback(flag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_ffi_boundary() {
        init_trace("artifacts/trace.jsonl").unwrap();
        invoke_callback(0xff);
    }
}
