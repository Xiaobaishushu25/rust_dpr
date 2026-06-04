use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn drain_col_like(trigger_panic: bool) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::drain_col_like");
    let mut data = vec![1u8, 2, 3, 4, 5, 6];
    unsafe {
        dpr_hit!("S00001");
        let dst = data.as_mut_ptr();
        let src = data.as_ptr().add(1);
        std::ptr::copy(src, dst, data.len() - 1);
    }
    if trigger_panic {
        panic!("drop-time invariant check after drain column copy");
    }
    data.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_draincol_copy() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = drain_col_like(true);
    }
}
