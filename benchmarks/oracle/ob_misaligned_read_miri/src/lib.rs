use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn trigger() -> u32 {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    let bytes = [0u8; 8];
    let ptr = unsafe { bytes.as_ptr().add(1) as *const u32 };
    unsafe {
        dpr_hit!("S00001");
        core::ptr::read(ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn misaligned_read_is_ub() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger();
    }
}
