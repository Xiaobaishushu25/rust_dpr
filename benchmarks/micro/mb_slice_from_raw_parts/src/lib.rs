use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_FROM_RAW_PARTS: &str = "S00001";
pub const FN_VIEW_THEN_CHECK: &str = "crate::view_then_check";

pub fn view_then_check(reject: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_VIEW_THEN_CHECK);

    let data = [10u8, 20, 30, 40];
    let slice = unsafe {
        dpr_hit!(SITE_FROM_RAW_PARTS);
        std::slice::from_raw_parts(data.as_ptr(), data.len())
    };

    assert!(!reject, "panic after slice::from_raw_parts");
    slice[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_from_raw_parts() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = view_then_check(true);
    }
}
