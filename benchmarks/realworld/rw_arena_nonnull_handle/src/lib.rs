use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::ptr::NonNull;

pub fn allocate_handle(input: &[u8]) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::allocate_handle");
    if input.is_empty() {
        return 0;
    }
    let mut buf = input.to_vec();
    let handle = unsafe {
        dpr_hit!("S00001");
        NonNull::new_unchecked(buf.as_mut_ptr())
    };
    if input[0] == 0xfe {
        panic!("panic after arena handle creation");
    }
    handle.as_ptr() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_nonnull_handle() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = allocate_handle(&[0xfe, 1, 2]);
    }
}
