use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn trigger(index: usize) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!("crate::trigger");
    let data = [1u8, 2, 3, 4];
    unsafe {
        dpr_hit!("S00001");
        *data.as_ptr().add(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn stack_oob_read() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = trigger(16);
    }
}
