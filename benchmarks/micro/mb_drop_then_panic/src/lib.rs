use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_MANUAL_DROP: &str = "S00001";
pub const FN_DROP_THEN_CHECK: &str = "crate::drop_then_check";

pub fn drop_then_check(reject: bool) {
    install_panic_hook();
    let _guard = dpr_function!(FN_DROP_THEN_CHECK);

    let raw = Box::into_raw(Box::new(5u8));
    unsafe {
        dpr_hit!(SITE_MANUAL_DROP);
        drop(Box::from_raw(raw));
    }

    assert!(!reject, "panic after manual ownership drop");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_manual_drop() {
        init_trace("artifacts/trace.jsonl").unwrap();
        drop_then_check(true);
    }
}
