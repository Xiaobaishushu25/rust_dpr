use rustdpr_trace::{dpr_function, install_panic_hook};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use toodee::TooDee;

pub const FN_REPRODUCE_TOODEE_FIXED: &str = "crate::run_fixed_public_api_contract_panic";

static DROP_1: AtomicUsize = AtomicUsize::new(0);
static DROP_2: AtomicUsize = AtomicUsize::new(0);
static DROP_3: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub struct DropDetector(pub u32);

impl Drop for DropDetector {
    fn drop(&mut self) {
        match self.0 {
            1 => {
                DROP_1.fetch_add(1, Ordering::SeqCst);
            }
            2 => {
                DROP_2.fetch_add(1, Ordering::SeqCst);
            }
            3 => {
                DROP_3.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

#[derive(Debug, Default)]
pub struct PanickingIterator;

impl Iterator for PanickingIterator {
    type Item = DropDetector;

    fn next(&mut self) -> Option<Self::Item> {
        panic!("RUSTDPR_TOODEE_FIXED_ITERATOR_CONTRACT_PANIC");
    }
}

impl ExactSizeIterator for PanickingIterator {
    fn len(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedObservation {
    pub iterator_panicked: bool,
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

/// Real fixed-version control for RUSTSEC-2021-0028.
///
/// This calls the real toodee 0.3.0 TooDee::insert_row API with the same
/// panicking iterator shape as the vulnerable PoC. The expected behavior is
/// a catchable iterator/contract panic without duplicate drop evidence.
pub fn run_fixed_public_api_contract_panic() -> FixedObservation {
    install_panic_hook();
    let _guard = dpr_function!(FN_REPRODUCE_TOODEE_FIXED);
    reset_drop_counts();

    let mut toodee: TooDee<_> = TooDee::from_vec(
        1,
        3,
        vec![DropDetector(1), DropDetector(2), DropDetector(3)],
    );

    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        toodee.insert_row(0, PanickingIterator);
    }));

    drop(toodee);
    let (drop_1, drop_2, drop_3) = drop_counts();
    let abnormal_drop_pattern = drop_1 != 1 || drop_2 != 1 || drop_3 != 1;

    FixedObservation {
        iterator_panicked: result.is_err(),
        drop_1,
        drop_2,
        drop_3,
        abnormal_drop_pattern,
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
        assert!(obs.iterator_panicked, "{obs:?}");
        assert!(!obs.abnormal_drop_pattern, "{obs:?}");
        assert_eq!(obs.drop_1, 1, "{obs:?}");
        assert_eq!(obs.drop_2, 1, "{obs:?}");
        assert_eq!(obs.drop_3, 1, "{obs:?}");
    }
}
