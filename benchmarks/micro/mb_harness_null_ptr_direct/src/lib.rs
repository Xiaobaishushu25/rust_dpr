use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_DEREF_RAW: &str = "S00001";
pub const FN_UNSAFE_API: &str = "crate::unsafe_read_first";

/// # Safety
/// `ptr` must be non-null and valid for reads of one byte.
pub unsafe fn unsafe_read_first(ptr: *const u8) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_UNSAFE_API);
    dpr_hit!(SITE_DEREF_RAW);
    unsafe { *ptr }
}

pub fn safe_wrapper(input: &[u8]) -> Option<u8> {
    install_panic_hook();
    let first = input.first()?;
    Some(unsafe { unsafe_read_first(first as *const u8) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn safe_wrapper_empty_is_not_bug() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(safe_wrapper(&[]), None);
    }

    #[test]
    fn safe_wrapper_nonempty_ok() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(safe_wrapper(&[5]), Some(5));
    }
}
