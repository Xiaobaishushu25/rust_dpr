use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_ASSERT_REGION: &str = "S00001";
pub const FN_CHECK: &str = "crate::check_inside_unsafe";

pub fn check_inside_unsafe(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_CHECK);
    unsafe {
        dpr_hit!(SITE_ASSERT_REGION);
        let len = input.len();
        assert!(len >= 3, "assert macro panic inside unsafe region");
        let p = input.as_ptr().add(2);
        *p as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn assert_panics_inside_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = check_inside_unsafe(&[1]);
    }
}
