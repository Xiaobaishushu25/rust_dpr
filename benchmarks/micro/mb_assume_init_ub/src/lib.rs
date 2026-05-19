use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::mem::MaybeUninit;

pub const SITE_ASSUME_INIT: &str = "S00001";
pub const FN_MATERIALIZE: &str = "crate::materialize";

pub fn materialize(trigger: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_MATERIALIZE);

    let x = MaybeUninit::<u8>::uninit();
    unsafe {
        dpr_hit!(SITE_ASSUME_INIT);
        let value = x.assume_init();
        assert!(!trigger, "panic after assume_init candidate");
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_assume_init() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = materialize(true);
    }
}
