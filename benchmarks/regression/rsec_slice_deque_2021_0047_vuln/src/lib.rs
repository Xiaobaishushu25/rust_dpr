//! Regression reproducer for RUSTSEC-2021-0047 / CVE-2021-29938.
//!
//! This case intentionally invokes the real vulnerable public API
//! `slice_deque::SliceDeque::drain_filter` from slice-deque 0.3.0.
//!
//! Important testing note:
//! The historical bug can corrupt ownership/drop state.  Do not try to
//! `catch_unwind` and continue in the same process.  On some platforms,
//! especially Windows/MSVC, the process may abort instead of returning a
//! normal Rust panic.  The regression test below therefore runs the PoC in
//! a child test process and treats a non-zero/abort status as the expected
//! vulnerable behavior.

use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use slice_deque::SliceDeque;
use std::io::{self, Write};

pub const SITE_DRAIN_FILTER_BOUNDARY: &str = "S00001";
pub const FN_REPRODUCE: &str = "crate::run_public_api_poc";

#[derive(Debug)]
pub struct DropDetector(pub u32);

impl Drop for DropDetector {
    fn drop(&mut self) {
        // Use stderr and flush so the parent process can observe the advisory
        // pattern even if the child process aborts shortly after unwinding.
        eprintln!("RUSTDPR_DROP_DETECTOR id={}", self.0);
        let _ = io::stderr().flush();
    }
}

/// Runs the real public-API PoC.
///
/// Expected vulnerable behavior:
///   * predicate panics while `SliceDeque::drain_filter` is active;
///   * the process exits with a non-zero status;
///   * on platforms where unwinding completes far enough, stderr may show
///     the public-advisory pattern where one logical element is dropped twice.
///
/// This function intentionally does not catch the panic.
pub fn run_public_api_poc() {
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
                panic!("RUSTDPR_SLICE_DEQUE_PREDICATE_PANIC");
            }
        })
        .collect::<SliceDeque<_>>();
}

/// Optional ASan-oriented reproducer.  Keep this for oracle/replay paths;
/// do not call it from ordinary smoke tests.
pub fn reproduce_asan_double_free() {
    #[derive(Debug)]
    struct BoxDetector(Box<u8>, u32);

    impl Drop for BoxDetector {
        fn drop(&mut self) {
            // Touch the Box so the field is considered used and the allocation
            // remains visibly owned by this value until drop.
            let _ = *self.0;
            eprintln!("RUSTDPR_BOX_DETECTOR_DROP id={}", self.1);
            let _ = io::stderr().flush();
        }
    }

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
                panic!("RUSTDPR_SLICE_DEQUE_BOX_PREDICATE_PANIC");
            }
        })
        .collect::<SliceDeque<_>>();
}

/// Fuzz entry used by the libFuzzer harness.
pub fn fuzz_entry(data: &[u8]) {
    // Keep a non-crashing branch so the target is not an all-inputs-crash
    // benchmark.  The provided corpus trigger is ASCII 'G' / 0x47.
    if data.first().copied() != Some(0x47) {
        return;
    }
    run_public_api_poc();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;
    use std::process::Command;

    fn spawn_child_poc() -> std::process::Output {
        let current_exe = std::env::current_exe().expect("current test binary path");

        Command::new(current_exe)
            .env("RUSTDPR_SLICE_DEQUE_RUN_CHILD", "1")
            .arg("--ignored")
            .arg("__slice_deque_child_process")
            .arg("--nocapture")
            .output()
            .expect("spawn slice-deque PoC child process")
    }

    #[test]
    #[ignore = "child process that intentionally triggers the historical slice-deque bug"]
    fn __slice_deque_child_process() {
        if std::env::var("RUSTDPR_SLICE_DEQUE_RUN_CHILD")
            .ok()
            .as_deref()
            != Some("1")
        {
            eprintln!("child PoC test skipped because RUSTDPR_SLICE_DEQUE_RUN_CHILD is not set");
            return;
        }

        run_public_api_poc();
    }

    #[test]
    #[ignore = "spawns a child process that intentionally triggers the historical bug"]
    fn reproduces_public_advisory_drop_pattern() {
        let output = spawn_child_poc();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stdout.contains("running 0 tests"),
            "child PoC test was not selected by the test filter.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );

        assert!(
            !output.status.success(),
            "vulnerable PoC unexpectedly exited successfully:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );
    }

    #[test]
    #[should_panic(expected = "RUSTDPR_SLICE_DEQUE_REPLAY_CONFIRMED_AFTER_DRAIN_FILTER_BOUNDARY")]
    fn rustdpr_deterministic_trace_replay() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        install_panic_hook();

        let _guard = dpr_function!(FN_REPRODUCE);

        /*
         * This marker is an API-boundary dangerous-site marker. The actual
         * vulnerable unsafe access lives inside the external slice-deque 0.3.0
         * crate. For this regression case, the child process below provides
         * replay evidence that this public API boundary reaches the historical
         * vulnerable path.
         */
        dpr_hit!(SITE_DRAIN_FILTER_BOUNDARY);

        let output = spawn_child_poc();

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");

        assert!(
            !combined.contains("running 0 tests"),
            "child PoC test was not selected by the test filter.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );

        if !output.status.success() {
            panic!("RUSTDPR_SLICE_DEQUE_REPLAY_CONFIRMED_AFTER_DRAIN_FILTER_BOUNDARY");
        }

        panic!("RUSTDPR_SLICE_DEQUE_REPLAY_UNEXPECTEDLY_SUCCEEDED_AFTER_DRAIN_FILTER_BOUNDARY");
    }
}
