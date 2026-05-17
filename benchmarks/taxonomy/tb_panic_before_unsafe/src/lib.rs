use rustdpr_trace::{dpr_function, dpr_hit};

pub const SITE_RAW_DEREF: &str = "S00001";
pub const FN_TRIGGER: &str = "crate::trigger";

pub fn trigger(flag: bool) {
    let _guard = dpr_function!(FN_TRIGGER);

    if flag {
        panic!("guard panic before unsafe");
    }

    let x = 1u8;
    let p = &x as *const u8;

    unsafe {
        dpr_hit!(SITE_RAW_DEREF);
        let _ = *p;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::{init_trace, install_panic_hook};

    #[test]
    fn trigger_blocking_panic() {
        init_trace("trace.jsonl").unwrap();
        install_panic_hook();
        let _ = std::panic::catch_unwind(|| trigger(true));
    }
}
