use rustdpr_trace::hit;

pub fn trigger(do_invalid_free: bool) {
    let mut stack_value = 17u8;
    let ptr = &mut stack_value as *mut u8;

    unsafe {
        hit("S00001");
        if do_invalid_free {
            drop(Box::from_raw(ptr));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::{init_trace, install_panic_hook};

    #[test]
    fn trigger_invalid_free() {
        init_trace("trace.jsonl").unwrap();
        install_panic_hook();
        trigger(true);
    }
}
