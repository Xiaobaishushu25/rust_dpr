use rustdpr_trace::hit;

pub fn trigger(read_after_scope: bool) -> u8 {
    let ptr: *const u8;

    {
        let local = 23u8;
        ptr = &local as *const u8;
        unsafe {
            hit("S00001");
        }
    }

    if read_after_scope { unsafe { *ptr } } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::{init_trace, install_panic_hook};

    #[test]
    fn trigger_use_after_scope() {
        init_trace("trace.jsonl").unwrap();
        install_panic_hook();
        let _ = trigger(true);
    }
}
