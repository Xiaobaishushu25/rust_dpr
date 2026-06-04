use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

#[repr(C)]
pub struct Padded {
    pub a: u8,
    pub b: u32,
}

pub fn any_as_u8_slice_like(value: &Padded, trigger_panic: bool) -> &[u8] {
    install_panic_hook();
    let _guard = dpr_function!("crate::any_as_u8_slice_like");
    let bytes = unsafe {
        dpr_hit!("S00001");
        std::slice::from_raw_parts(
            value as *const Padded as *const u8,
            std::mem::size_of::<Padded>(),
        )
    };
    if trigger_panic {
        panic!("panic after exposing padded object as byte slice");
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn panic_after_any_as_u8_slice() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let value = Padded { a: 1, b: 2 };
        let _ = any_as_u8_slice_like(&value, true);
    }
}
