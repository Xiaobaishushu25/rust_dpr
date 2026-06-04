use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub unsafe extern "C" fn c_len(ptr: *const u8, len: usize) -> usize {
    if ptr.is_null() { return 0; }
    len
}

pub fn adapt_buffer(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::adapt_buffer");
    if input.is_empty() { return 0; }
    let n = unsafe {
        dpr_hit!("S00001");
        c_len(input.as_ptr(), input.len())
    };
    if input[0] == 0xff {
        panic!("panic after FFI boundary validation");
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_ffi_boundary() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = adapt_buffer(&[0xff, 1, 2]);
    }
}
