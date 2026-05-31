use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::mem::ManuallyDrop;

pub const SITE_DROP_INVARIANT: &str = "S00001";
pub const FN_TRIGGER: &str = "crate::trigger";

pub fn trigger(trigger_panic: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_TRIGGER);

    let mut value = ManuallyDrop::new(Box::new(42u8));
    let recovered = unsafe {
        dpr_hit!(SITE_DROP_INVARIANT);
        ManuallyDrop::take(&mut value)
    };

    let byte = *recovered;
    drop(recovered);
    assert!(!trigger_panic, "panic after manual drop-invariant operation");
    byte
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_manual_drop_invariant() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger(true);
    }
}
