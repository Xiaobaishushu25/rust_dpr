//! Official fixed-version control for RUSTSEC-2021-0030 / scratchpad.

use rustdpr_trace::{dpr_function, install_panic_hook};
use scratchpad::SliceMoveSource;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};

pub const FN_SCRATCHPAD_FIXED: &str = "crate::run_fixed_public_api_contract_panic";

static DROP_1234: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug)]
pub struct DropDetector {
    id: u32,
    _payload: Box<u64>,
}

impl DropDetector {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            _payload: Box::new(0x5C12_47AD_u64 ^ id as u64),
        }
    }
}

impl Drop for DropDetector {
    fn drop(&mut self) {
        if self.id == 1234 {
            DROP_1234.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedObservation {
    pub closure_panicked: bool,
    pub drop_1234: usize,
    pub abnormal_drop_pattern: bool,
}

fn reset_drop_counts() {
    DROP_1234.store(0, Ordering::SeqCst);
}

pub fn run_fixed_public_api_contract_panic() -> FixedObservation {
    install_panic_hook();
    let _guard = dpr_function!(FN_SCRATCHPAD_FIXED);
    reset_drop_counts();

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let values = [DropDetector::new(1234)];
        values.move_elements(|moved_value| {
            let _ = &moved_value;
            panic!("RUSTDPR_SCRATCHPAD_FIXED_CLOSURE_CONTRACT_PANIC");
        });
    }));

    let drop_1234 = DROP_1234.load(Ordering::SeqCst);
    FixedObservation {
        closure_panicked: result.is_err(),
        drop_1234,
        abnormal_drop_pattern: drop_1234 != 1,
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
        assert!(obs.closure_panicked, "{obs:?}");
        assert!(!obs.abnormal_drop_pattern, "{obs:?}");
        assert_eq!(obs.drop_1234, 1, "{obs:?}");
    }
}
