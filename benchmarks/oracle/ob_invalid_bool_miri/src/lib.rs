use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn trigger() -> bool {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");

    unsafe {
        dpr_hit!("S00001");

        // 2 is not a valid bool representation.
        // Miri should report invalid value / constructing invalid value.
        std::mem::transmute::<u8, bool>(2u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn invalid_bool_is_ub() {
        init_trace("artifacts/trace.jsonl").unwrap();

        let b = trigger();

        // Force the invalid bool to be consumed so Miri must validate it.
        if b {
            std::hint::black_box(1usize);
        } else {
            std::hint::black_box(0usize);
        }
    }
}