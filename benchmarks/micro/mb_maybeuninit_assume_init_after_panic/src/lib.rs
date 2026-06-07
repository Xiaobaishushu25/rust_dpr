use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::mem::MaybeUninit;

pub const SITE_ASSUME_INIT: &str = "S00001";
pub const FN_BUILD: &str = "crate::build_then_validate";

pub fn build_then_validate(input: &[u8]) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_BUILD);
    let mut slot = MaybeUninit::<u8>::uninit();
    let byte = input.first().copied().unwrap_or(0);
    slot.write(byte);
    let value = unsafe {
        dpr_hit!(SITE_ASSUME_INIT);
        slot.assume_init()
    };
    if value == 0 {
        panic!("validation panic after MaybeUninit::assume_init");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn zero_panics_after_assume_init() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = build_then_validate(&[0]);
    }

    #[test]
    fn nonzero_returns_after_assume_init() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(build_then_validate(&[8]), 8);
    }
}
