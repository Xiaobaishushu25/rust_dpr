use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub fn drain_filter_like(should_panic: bool) -> usize {
    install_panic_hook();
    let _guard = dpr_function!("crate::drain_filter_like");
    let mut data = vec![10u8, 20, 30];
    let ptr = data.as_mut_ptr();
    unsafe {
        dpr_hit!("S00001");
        let _candidate: *mut u8 = ptr.add(1);
    }
    if should_panic {
        panic!("predicate panic during drain_filter-like iteration");
    }
    data.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn predicate_panic_after_raw_iterator_state() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = drain_filter_like(true);
    }
}
