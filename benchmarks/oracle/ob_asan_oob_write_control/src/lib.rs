use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_OOB_WRITE: &str = "S00001";
pub const FN_PROCESS: &str = "crate::write_one_past_end";

pub fn write_one_past_end(trigger: bool) {
    install_panic_hook();
    let _guard = dpr_function!(FN_PROCESS);
    let mut buf = vec![0u8; 4];
    let ptr = buf.as_mut_ptr();
    if trigger {
        unsafe {
            dpr_hit!(SITE_OOB_WRITE);
            *ptr.add(buf.len()) = 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn nontrigger_path_is_safe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        write_one_past_end(false);
    }

    #[test]
    #[ignore = "intentionally writes one byte past the allocation for ASan/Miri oracle runs"]
    fn trigger_path_is_oob() {
        init_trace("artifacts/trace.jsonl").unwrap();
        write_one_past_end(true);
    }
}
