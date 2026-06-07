use rustdpr_trace::hit;

pub fn trigger(flag: bool) -> u8 {
    let b = Box::new(7u8);
    let ptr = Box::into_raw(b);

    unsafe {
        hit("S00001");
        drop(Box::from_raw(ptr));

        if flag { *ptr } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::{init_trace, install_panic_hook};

    #[test]
    fn trigger_heap_uaf() {
        init_trace("trace.jsonl").unwrap();
        install_panic_hook();
        let _ = trigger(true);
    }
}
