use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::mem::MaybeUninit;

pub fn trigger() -> bool {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    unsafe {
        dpr_hit!("S00001");
        MaybeUninit::<bool>::uninit().assume_init()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn uninit_bool_is_ub() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger();
    }
}
