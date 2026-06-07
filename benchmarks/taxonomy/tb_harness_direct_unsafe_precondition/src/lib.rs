use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::slice;

pub const SITE_FROM_RAW_PARTS: &str = "S00001";
pub const FN_UNSAFE_API: &str = "crate::unsafe_sum_raw_parts";

/// # Safety
/// `ptr` must be valid for `len` bytes and must point to initialized memory.
pub unsafe fn unsafe_sum_raw_parts(ptr: *const u8, len: usize) -> u64 {
    install_panic_hook();
    let _guard = dpr_function!(FN_UNSAFE_API);
    dpr_hit!(SITE_FROM_RAW_PARTS);
    let slice = unsafe { slice::from_raw_parts(ptr, len) };
    slice.iter().map(|v| *v as u64).sum()
}

pub fn safe_sum(input: &[u8]) -> u64 {
    install_panic_hook();
    unsafe { unsafe_sum_raw_parts(input.as_ptr(), input.len()) }
}
