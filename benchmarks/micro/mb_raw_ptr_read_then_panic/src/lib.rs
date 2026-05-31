use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_READ: &str = "S00001";
pub const FN_READ_THEN_CHECK: &str = "crate::read_then_check";

pub fn read_then_check(input: &[u8], reject: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_READ_THEN_CHECK);

    let fallback = 0u8;
    let ptr = input.first().map_or(&fallback as *const u8, |b| b as *const u8);
    let value = unsafe {
        dpr_hit!(SITE_RAW_READ);
        ptr.read()
    };

    assert!(!reject, "panic after raw pointer read");
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_raw_ptr_read() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = read_then_check(&[1], true);
    }
}
