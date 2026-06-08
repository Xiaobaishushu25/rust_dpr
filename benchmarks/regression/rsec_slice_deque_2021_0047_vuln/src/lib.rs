//! Regression reproducer for RUSTSEC-2021-0047 / CVE-2021-29938.
//!
//! This intentionally calls the real vulnerable public API
//! `slice_deque::SliceDeque::drain_filter` from slice-deque 0.3.0.
//! It is not a hand-written Vec/VecDeque imitation.

use slice_deque::SliceDeque;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};

// These probes intentionally have no destructor-owning fields.  If the
// vulnerable crate double-drops one logical element, the probe records
// the event without making the probe itself responsible for a double free.
static DROP_1: AtomicUsize = AtomicUsize::new(0);
static DROP_2: AtomicUsize = AtomicUsize::new(0);
static DROP_3: AtomicUsize = AtomicUsize::new(0);
static DROP_OTHER: AtomicUsize = AtomicUsize::new(0);

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
            _ => {
                DROP_OTHER.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropObservation {
    pub predicate_panicked: bool,
    pub drop_1: usize,
    pub drop_2: usize,
    pub drop_3: usize,
    pub drop_other: usize,
    pub double_drop_observed: bool,
    pub missing_drop_observed: bool,
}

fn reset_drop_counts() {
    DROP_1.store(0, Ordering::SeqCst);
    DROP_2.store(0, Ordering::SeqCst);
    DROP_3.store(0, Ordering::SeqCst);
    DROP_OTHER.store(0, Ordering::SeqCst);
}

fn read_observation(predicate_panicked: bool) -> DropObservation {
    let drop_1 = DROP_1.load(Ordering::SeqCst);
    let drop_2 = DROP_2.load(Ordering::SeqCst);
    let drop_3 = DROP_3.load(Ordering::SeqCst);
    let drop_other = DROP_OTHER.load(Ordering::SeqCst);
    DropObservation {
        predicate_panicked,
        drop_1,
        drop_2,
        drop_3,
        drop_other,
        double_drop_observed: drop_1 > 1 || drop_2 > 1 || drop_3 > 1,
        missing_drop_observed: drop_1 == 0 || drop_2 == 0 || drop_3 == 0,
    }
}

/// Public-API reproducer for the advisory.
///
/// The upstream issue demonstrates this shape:
///   * element 1 is selected for draining;
///   * element 2 is retained;
///   * the predicate panics on element 3;
///   * the vulnerable iterator has already advanced internal state.
pub fn reproduce_public_api() -> DropObservation {
    reset_drop_counts();

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut deq = SliceDeque::new();
        deq.push_back(DropDetector(1));
        deq.push_back(DropDetector(2));
        deq.push_back(DropDetector(3));

        let _drained = deq
            .drain_filter(|x| {
                if x.0 == 1 {
                    true
                } else if x.0 == 2 {
                    false
                } else {
                    panic!("predicate panicked after drain_filter advanced state");
                }
            })
            .collect::<SliceDeque<_>>();
    }));

    read_observation(result.is_err())
}

/// Optional ASan-oriented reproducer.  This uses a Box-owning element so
/// that a logical double drop can become a sanitizer-visible double free.
/// Keep this on the oracle/replay path, not in ordinary smoke tests.
pub fn reproduce_asan_double_free() {
    #[derive(Debug)]
    struct BoxDetector(Box<u8>, u32);

    let _ = catch_unwind(AssertUnwindSafe(|| {
        let mut deq = SliceDeque::new();
        deq.push_back(BoxDetector(Box::new(1), 1));
        deq.push_back(BoxDetector(Box::new(2), 2));
        deq.push_back(BoxDetector(Box::new(3), 3));

        let _drained = deq
            .drain_filter(|x| {
                if x.1 == 1 {
                    true
                } else if x.1 == 2 {
                    false
                } else {
                    panic!("predicate panicked after drain_filter advanced state");
                }
            })
            .collect::<SliceDeque<_>>();
    }));
}

/// Fuzz entry used by the libFuzzer harness.
pub fn fuzz_entry(data: &[u8]) {
    // Keep a non-crashing branch so the target is not a trivial
    // all-inputs-crash benchmark.  Add a seed file containing 0x47 for
    // deterministic replay.
    if data.first().copied() != Some(0x47) {
        return;
    }

    let obs = reproduce_public_api();
    if obs.predicate_panicked && (obs.double_drop_observed || obs.missing_drop_observed) {
        panic!(
            "RUSTSEC-2021-0047 reproduced: drop counts are id1={}, id2={}, id3={}, other={}",
            obs.drop_1, obs.drop_2, obs.drop_3, obs.drop_other
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "intentionally triggers the historical panic-safety bug"]
    fn reproduces_public_advisory_drop_pattern() {
        let obs = reproduce_public_api();
        assert!(obs.predicate_panicked);
        assert!(
            obs.double_drop_observed || obs.missing_drop_observed,
            "{obs:?}"
        );
    }
}
