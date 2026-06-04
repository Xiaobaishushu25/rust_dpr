use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn trigger() -> u8 {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    let ptr = core::ptr::null::<u8>();
    unsafe {
        dpr_hit!("S00001");
        *ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn null_deref_is_ub() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger();
    }
}
