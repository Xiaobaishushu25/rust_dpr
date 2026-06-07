use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_FFI: &str = "S00001";
pub const FN_ENTRY: &str = "crate::entry";
pub const FN_BOUNDARY: &str = "crate::rust_callback_with_c_unwind_abi";

extern "C-unwind" fn rust_callback_with_c_unwind_abi(v: u8) -> u8 {
    let _guard = dpr_function!(FN_BOUNDARY);
    assert!(v != 0, "callback contract panic at FFI boundary");
    v
}

pub fn entry(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_ENTRY);
    let value = input.first().copied().unwrap_or(0);
    unsafe {
        dpr_hit!(SITE_FFI);
        rust_callback_with_c_unwind_abi(value)
    }
}
