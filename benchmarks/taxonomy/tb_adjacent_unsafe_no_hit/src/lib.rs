use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_ADJACENT_RAW_READ: &str = "S00001";
pub const FN_TRIGGER: &str = "crate::trigger";
pub const FN_DANGEROUS_HELPER: &str = "crate::dangerous_helper";

pub fn trigger(block: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!(FN_TRIGGER);

    if block {
        panic!("panic in caller before adjacent unsafe helper is executed");
    }

    let value = 11u8;
    dangerous_helper(&value as *const u8)
}

fn dangerous_helper(ptr: *const u8) -> u8 {
    let _guard = dpr_function!(FN_DANGEROUS_HELPER);
    unsafe {
        dpr_hit!(SITE_ADJACENT_RAW_READ);
        *ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn caller_panic_before_adjacent_helper() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger(true);
    }
}
