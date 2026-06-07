use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_MUTATE_RAW: &str = "S00001";
pub const FN_MUTATE: &str = "crate::mutate_unique";

/// # Safety
///
/// The caller must provide a unique, valid, aligned mutable pointer.
pub unsafe fn mutate_unique(ptr: *mut u32, value: u32) -> u32 {
    install_panic_hook();
    let _guard = dpr_function!(FN_MUTATE);
    dpr_hit!(SITE_MUTATE_RAW);
    *ptr = value;
    *ptr
}

pub fn mutate_safe(slot: &mut u32, value: u32) -> u32 {
    unsafe { mutate_unique(slot as *mut u32, value) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn safe_wrapper_is_valid() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let mut slot = 0;
        assert_eq!(mutate_safe(&mut slot, 42), 42);
    }
}
