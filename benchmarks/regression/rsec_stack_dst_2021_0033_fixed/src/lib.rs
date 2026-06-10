//! Official fixed-version control for RUSTSEC-2021-0033 / stack_dst.

use rustdpr_trace::{dpr_function, install_panic_hook};
use stack_dst::StackA;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const FN_STACK_DST_FIXED: &str = "crate::run_fixed_public_api_contract_panic";

static DROP_1: AtomicUsize = AtomicUsize::new(0);
static DROP_2: AtomicUsize = AtomicUsize::new(0);
static DROP_3: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub struct DropDetector {
    id: u32,
    _payload: Box<u64>,
}

impl DropDetector {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            _payload: Box::new(0x57AC_D57_u64 ^ id as u64),
        }
    }
}

impl Drop for DropDetector {
    fn drop(&mut self) {
        match self.id {
            1 => { DROP_1.fetch_add(1, Ordering::SeqCst); }
            2 => { DROP_2.fetch_add(1, Ordering::SeqCst); }
            3 => { DROP_3.fetch_add(1, Ordering::SeqCst); }
            _ => {}
        }
    }
}

impl Clone for DropDetector {
    fn clone(&self) -> Self {
        panic!("RUSTDPR_STACK_DST_FIXED_CLONE_CONTRACT_PANIC_{}", self.id);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedObservation {
    pub clone_panicked: bool,
    pub drop_1: usize,
    pub drop_2: usize,
    pub drop_3: usize,
    pub abnormal_drop_pattern: bool,
}

fn reset_drop_counts() {
    DROP_1.store(0, Ordering::SeqCst);
    DROP_2.store(0, Ordering::SeqCst);
    DROP_3.store(0, Ordering::SeqCst);
}

fn drop_counts() -> (usize, usize, usize) {
    (
        DROP_1.load(Ordering::SeqCst),
        DROP_2.load(Ordering::SeqCst),
        DROP_3.load(Ordering::SeqCst),
    )
}

pub fn run_fixed_public_api_contract_panic() -> FixedObservation {
    install_panic_hook();
    let _guard = dpr_function!(FN_STACK_DST_FIXED);
    reset_drop_counts();

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut stack = StackA::<[DropDetector], [usize; 9]>::new();
        stack.push_stable([DropDetector::new(1)], |p| p).unwrap();
        stack.push_stable([DropDetector::new(2)], |p| p).unwrap();
        let _second_drop = stack.pop();
        stack.push_cloned(&[DropDetector::new(3)]).unwrap();
    }));

    let (drop_1, drop_2, drop_3) = drop_counts();
    FixedObservation {
        clone_panicked: result.is_err(),
        drop_1,
        drop_2,
        drop_3,
        abnormal_drop_pattern: drop_1 > 1 || drop_2 > 1 || drop_3 > 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    fn rustdpr_fixed_contract_panic_trace() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        let obs = run_fixed_public_api_contract_panic();
        assert!(obs.clone_panicked, "{obs:?}");
        assert!(!obs.abnormal_drop_pattern, "{obs:?}");
        assert!(obs.drop_1 <= 1, "{obs:?}");
        assert!(obs.drop_2 <= 1, "{obs:?}");
        assert!(obs.drop_3 <= 1, "{obs:?}");
    }
}
