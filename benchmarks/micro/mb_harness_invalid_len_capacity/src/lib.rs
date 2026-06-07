use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_PARTS_READ: &str = "S00001";
pub const FN_SUM_RAW_PARTS: &str = "crate::sum_raw_parts";

/// Sums a raw byte slice.
///
/// # Safety
/// `ptr` must be non-null and valid for `len` initialized bytes.
pub unsafe fn sum_raw_parts(ptr: *const u8, len: usize) -> u32 {
    install_panic_hook();
    let _guard = dpr_function!(FN_SUM_RAW_PARTS);

    assert!(!ptr.is_null(), "harness supplied a null pointer");
    assert!(
        len <= 16,
        "harness supplied an unrealistic raw slice length"
    );

    unsafe {
        dpr_hit!(SITE_RAW_PARTS_READ);
        std::slice::from_raw_parts(ptr, len)
            .iter()
            .map(|b| *b as u32)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn invalid_harness_null_pointer() {
        init_trace("artifacts/trace.jsonl").unwrap();
        unsafe {
            let _ = sum_raw_parts(std::ptr::null(), 8);
        }
    }

    #[test]
    #[should_panic]
    fn invalid_harness_length_capacity() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let data = [1u8, 2, 3, 4];
        unsafe {
            let _ = sum_raw_parts(data.as_ptr(), 64);
        }
    }

    #[test]
    fn valid_harness_input() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let data = [1u8, 2, 3, 4];
        let sum = unsafe { sum_raw_parts(data.as_ptr(), data.len()) };
        assert_eq!(sum, 10);
    }
}
