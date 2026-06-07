use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_MUT_WRITE: &str = "S00001";
pub const FN_UNSAFE_WRITE: &str = "crate::write_unique_raw";

/// # Safety
///
/// `ptr` must be non-null, properly aligned, valid for writes, and must be
/// the only mutable reference to the pointed-to byte for the duration of the call.
pub unsafe fn write_unique_raw(ptr: *mut u8, value: u8) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_UNSAFE_WRITE);
    dpr_hit!(SITE_RAW_MUT_WRITE);
    *ptr = value;
    *ptr
}

pub fn safe_write(slot: &mut u8, value: u8) -> u8 {
    unsafe { write_unique_raw(slot as *mut u8, value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn safe_wrapper_is_valid() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let mut byte = 1;
        assert_eq!(safe_write(&mut byte, 7), 7);
    }
}
