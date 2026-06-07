use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_FIXED_DRAIN_FILTER_ADVANCE: &str = "S00001";
pub const FN_REPRODUCE_FIXED: &str = "crate::reproduce_slice_deque_2021_0047_fixed";

#[derive(Debug)]
struct DropProbe(u8);

impl Drop for DropProbe {
    fn drop(&mut self) {
        let _ = self.0;
    }
}

pub fn reproduce_slice_deque_2021_0047_fixed(trigger_panic: bool) -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_REPRODUCE_FIXED);

    let mut items = vec![DropProbe(1), DropProbe(2), DropProbe(3)];
    let mut idx = 0usize;
    let old_len = items.len();

    while idx != old_len {
        let i = idx;
        // Manual fixed control: evaluate the user predicate before
        // advancing iterator state or touching raw iterator state.
        if trigger_panic && i == 1 {
            panic!("predicate panic before fixed drain_filter state advance");
        }
        unsafe {
            dpr_hit!(SITE_FIXED_DRAIN_FILTER_ADVANCE);
            let base = items.as_mut_ptr();
            let _candidate = base.add(i);
        }
        idx += 1;
    }

    items.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn predicate_panic_before_fixed_state_advance() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = reproduce_slice_deque_2021_0047_fixed(true);
    }

    #[test]
    fn no_panic_completes_and_reaches_unsafe() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(reproduce_slice_deque_2021_0047_fixed(false), 3);
    }
}
