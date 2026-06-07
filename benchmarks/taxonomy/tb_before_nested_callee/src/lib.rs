use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_NESTED_UNSAFE: &str = "S00001";
pub const FN_ENTRY: &str = "crate::entry";
pub const FN_HELPER: &str = "crate::helper_with_unsafe";

fn helper_with_unsafe(input: &[u8]) -> u8 {
    let _guard = dpr_function!(FN_HELPER);
    unsafe {
        dpr_hit!(SITE_NESTED_UNSAFE);
        *input.as_ptr()
    }
}

pub fn entry(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_ENTRY);
    if input.len() < 2 {
        panic!("entry rejects input before nested unsafe callee");
    }
    helper_with_unsafe(input)
}
