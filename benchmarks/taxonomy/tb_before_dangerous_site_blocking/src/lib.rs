use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_RAW_READ: &str = "S00001";
pub const FN_TRIGGER: &str = "crate::trigger";

pub fn trigger(block: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_TRIGGER);

    if block {
        panic!("input rejected before dangerous site");
    }

    let value = 9u8;
    let ptr = &value as *const u8;
    unsafe {
        dpr_hit!(SITE_RAW_READ);
        *ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_blocks_raw_read() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger(true);
    }
}
