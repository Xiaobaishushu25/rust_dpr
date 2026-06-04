use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::mem::ManuallyDrop;

pub struct InstrumentedLike<T> {
    span_id: usize,
    inner: T,
}

pub fn into_inner_like(trigger_panic: bool) -> u8 {
    install_panic_hook();
    let _guard = dpr_function!("crate::into_inner_like");
    let this = ManuallyDrop::new(InstrumentedLike { span_id: 7, inner: 9u8 });
    let inner_ptr: *const u8 = &this.inner;
    unsafe {
        dpr_hit!("S00001");
        let value = std::ptr::read(inner_ptr);
        if trigger_panic {
            panic!("panic after ptr::read in into_inner-like code");
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_forget_style_ptr_read() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = into_inner_like(true);
    }
}
