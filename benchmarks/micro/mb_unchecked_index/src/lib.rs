use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_UNCHECKED_INDEX: &str = "S00001";
pub const FN_UNCHECKED_THEN_CHECK: &str = "crate::unchecked_then_check";

pub fn unchecked_then_check(input: &[u8], reject: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_UNCHECKED_THEN_CHECK);

    let value = unsafe {
        dpr_hit!(SITE_UNCHECKED_INDEX);
        *input.get_unchecked(0)
    };

    assert!(!reject, "panic after unchecked index access");
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_unchecked_index() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = unchecked_then_check(&[9], true);
    }
}
