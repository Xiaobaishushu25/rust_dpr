//! Regression reproducer for RUSTSEC-2021-0030 / scratchpad.
//!
//! This benchmark invokes the real `scratchpad` 1.3.0 public API
//! `SliceMoveSource::move_elements`. The advisory trigger is a
//! user-provided closure that panics after the crate has moved an
//! element with `ptr::read`, which can duplicate ownership during
//! unwinding.

use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use scratchpad::SliceMoveSource;
use std::process::{Command, Output};

pub const SITE_SCRATCHPAD_MOVE_ELEMENTS_BOUNDARY: &str = "S00001";
pub const FN_SCRATCHPAD_MOVE_ELEMENTS_VULN: &str = "crate::run_public_api_poc";

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
        println!("Dropping scratchpad {}", self.id);
    }
}

/// Real public-API PoC for RUSTSEC-2021-0030.
pub fn run_public_api_poc() {
    install_panic_hook();
    let _guard = dpr_function!(FN_SCRATCHPAD_MOVE_ELEMENTS_VULN);

    let values = [DropDetector::new(1234)];

    dpr_hit!(SITE_SCRATCHPAD_MOVE_ELEMENTS_BOUNDARY);
    values.move_elements(|moved_value| {
        let _ = &moved_value;
        panic!("RUSTDPR_SCRATCHPAD_MOVE_ELEMENTS_CLOSURE_PANIC");
    });
}

fn spawn_child_poc() -> Output {
    let current_exe = std::env::current_exe().expect("current test binary path");
    Command::new(current_exe)
        .env("RUSTDPR_SCRATCHPAD_RUN_CHILD", "1")
        .arg("--ignored")
        .arg("__scratchpad_child_process")
        .arg("--nocapture")
        .output()
        .expect("spawn scratchpad PoC child process")
}

fn child_output_has_replay_evidence(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    let duplicate_drop = combined.matches("Dropping scratchpad 1234").count() >= 2;

    !output.status.success()
        || duplicate_drop
        || combined.contains("RUSTDPR_SCRATCHPAD_MOVE_ELEMENTS_CLOSURE_PANIC")
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
    #[ignore = "child process that intentionally triggers the historical scratchpad bug"]
    fn __scratchpad_child_process() {
        if std::env::var("RUSTDPR_SCRATCHPAD_RUN_CHILD").ok().as_deref() != Some("1") {
            eprintln!("child PoC test skipped because RUSTDPR_SCRATCHPAD_RUN_CHILD is not set");
            return;
        }
        run_public_api_poc();
    }

    #[test]
    #[ignore = "spawns a child process that intentionally triggers the historical scratchpad bug"]
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
            "vulnerable scratchpad PoC did not expose replay evidence.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );
    }

    #[test]
    #[should_panic(expected = "RUSTDPR_SCRATCHPAD_REPLAY_CONFIRMED_AFTER_API_BOUNDARY")]
    fn rustdpr_deterministic_trace_replay() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        install_panic_hook();
        let _guard = dpr_function!(FN_SCRATCHPAD_MOVE_ELEMENTS_VULN);

        dpr_hit!(SITE_SCRATCHPAD_MOVE_ELEMENTS_BOUNDARY);

        let output = spawn_child_poc();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stdout.contains("running 0 tests"),
            "child PoC test was not selected by the test filter.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );

        if child_output_has_replay_evidence(&output) {
            panic!("RUSTDPR_SCRATCHPAD_REPLAY_CONFIRMED_AFTER_API_BOUNDARY");
        }

        panic!("RUSTDPR_SCRATCHPAD_REPLAY_UNEXPECTEDLY_SUCCEEDED_AFTER_API_BOUNDARY");
    }
}
