use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_FROM_RAW_PARTS: &str = "S00001";
pub const FN_VIEW_RAW: &str = "crate::view_raw_parts";

/// Returns the first byte of a raw slice.
///
/// # Safety
/// The caller must provide a non-null pointer valid for `len` bytes.
pub unsafe fn view_raw_parts(ptr: *const u8, len: usize) -> Option<u8> {
    install_panic_hook();
    let _guard = dpr_function!(FN_VIEW_RAW);

    assert!(!ptr.is_null(), "null raw pointer supplied by harness");
    assert!(len <= 8, "oversized length supplied by harness");

    unsafe {
        dpr_hit!(SITE_FROM_RAW_PARTS);
        std::slice::from_raw_parts(ptr, len).first().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn null_pointer_is_harness_misuse() {
        init_trace("artifacts/trace.jsonl").unwrap();
        unsafe {
            let _ = view_raw_parts(std::ptr::null(), 4);
        }
    }

    #[test]
    #[should_panic]
    fn bad_length_is_harness_misuse() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let data = [1u8, 2, 3, 4];
        unsafe {
            let _ = view_raw_parts(data.as_ptr(), 128);
        }
    }

    #[test]
    fn valid_raw_parts() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let data = [11u8, 12, 13, 14];
        let got = unsafe { view_raw_parts(data.as_ptr(), data.len()) };
        assert_eq!(got, Some(11));
    }
}
