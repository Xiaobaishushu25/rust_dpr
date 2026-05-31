use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_DEREF: &str = "S00001";
pub const FN_READ: &str = "crate::read_non_null";

/// Reads a byte through a raw pointer.
///
/// # Safety
/// The caller must provide a non-null pointer that is valid for one byte.
pub unsafe fn read_non_null(ptr: *const u8) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_READ);

    assert!(!ptr.is_null(), "caller must provide a non-null pointer");
    unsafe {
        dpr_hit!(SITE_RAW_DEREF);
        *ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn invalid_null_pointer_input() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let ptr = std::ptr::null();
        unsafe {
            let _ = read_non_null(ptr);
        }
    }
}
