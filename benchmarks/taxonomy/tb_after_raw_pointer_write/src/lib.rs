use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_WRITE: &str = "S00001";
pub const FN_TRIGGER: &str = "crate::trigger";

pub fn trigger(value: u8, trigger_panic: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_TRIGGER);

    let mut out = 0u8;
    let ptr = &mut out as *mut u8;

    unsafe {
        dpr_hit!(SITE_RAW_WRITE);
        ptr.write(value);
    }

    assert!(!trigger_panic, "panic after raw pointer write");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_raw_pointer_write() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger(7, true);
    }
}
