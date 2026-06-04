use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn create_ring_buffer_like(cap: usize, trigger_panic: bool) -> Vec<u8> {
    install_panic_hook();
    let _guard = dpr_function!("crate::create_ring_buffer_like");
    let mut buf: Vec<u8> = Vec::with_capacity(cap);
    unsafe {
        dpr_hit!("S00001");
        buf.set_len(cap);
    }
    if trigger_panic {
        panic!("panic after set_len-created ring buffer");
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_set_len_ring_buffer() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = create_ring_buffer_like(8, true);
    }
}
