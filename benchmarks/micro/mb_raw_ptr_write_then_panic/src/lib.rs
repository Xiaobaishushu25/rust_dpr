use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_WRITE: &str = "S00001";
pub const FN_WRITE_THEN_CHECK: &str = "crate::write_then_check";

pub fn write_then_check(value: u8, reject: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_WRITE_THEN_CHECK);

    let mut out = 0u8;
    let ptr = &mut out as *mut u8;
    unsafe {
        dpr_hit!(SITE_RAW_WRITE);
        ptr.write(value);
    }

    assert!(!reject, "panic after raw pointer write");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_raw_ptr_write() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = write_then_check(3, true);
    }
}
