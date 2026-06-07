use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};

pub const SITE_DRAIN_FILTER_STATE_ADVANCE: &str = "S00001";
pub const FN_REPRODUCE: &str = "crate::reproduce_slice_deque_2021_0047";

#[derive(Debug)]
struct DropProbe(u8);

impl Drop for DropProbe {
    fn drop(&mut self) {
        // The real advisory concerns double-drop after panic.  The
        // minimized reproducer keeps Drop observable but does not
        // intentionally double-free during normal smoke tests.
        let _ = self.0;
    }
}

pub fn reproduce_slice_deque_2021_0047(trigger_panic: bool) -> usize {
    install_panic_hook();
    let _guard = dpr_function!(FN_REPRODUCE);

    let mut items = vec![DropProbe(1), DropProbe(2), DropProbe(3)];
    let mut idx = 0usize;
    let old_len = items.len();

    while idx != old_len {
        let i = idx;
        // Vulnerable pattern from RUSTSEC-2021-0047: iterator state is
        // advanced before invoking a user predicate that may panic.
        idx += 1;
        unsafe {
            dpr_hit!(SITE_DRAIN_FILTER_STATE_ADVANCE);
            let base = items.as_mut_ptr();
            let _candidate = base.add(i);
        }
        if trigger_panic && i == 1 {
            panic!("predicate panic after drain_filter iterator state advance");
        }
    }

    items.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[should_panic]
    fn predicate_panic_after_vulnerable_state_advance() {
        init_trace("artifacts/trace.jsonl").unwrap();
        let _ = reproduce_slice_deque_2021_0047(true);
    }

    #[test]
    fn no_panic_completes() {
        init_trace("artifacts/trace.jsonl").unwrap();
        assert_eq!(reproduce_slice_deque_2021_0047(false), 3);
    }
}
