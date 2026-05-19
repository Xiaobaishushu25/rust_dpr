use rustdpr_trace::{dpr_function, install_panic_hook};

pub const FN_DEREF: &str = "crate::deref_non_null";

pub unsafe fn deref_non_null(ptr: *const u8) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_DEREF);
    assert!(!ptr.is_null(), "pointer must be non-null");
    *ptr
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn harness_misuse_null() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let ptr = std::ptr::null();
        unsafe { let _ = deref_non_null(ptr); }
    }
}
