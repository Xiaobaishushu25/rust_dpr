use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::mem::MaybeUninit;

pub const SITE_MAYBEUNINIT_READ: &str = "S00001";
pub const FN_READ_THEN_CHECK: &str = "crate::maybeuninit_read_then_check";

pub fn maybeuninit_read_then_check(reject: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_READ_THEN_CHECK);

    let value = MaybeUninit::new(13u8);
    let byte = unsafe {
        dpr_hit!(SITE_MAYBEUNINIT_READ);
        value.assume_init_read()
    };

    assert!(!reject, "panic after MaybeUninit read");
    byte
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_maybeuninit_read() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = maybeuninit_read_then_check(true);
    }
}
