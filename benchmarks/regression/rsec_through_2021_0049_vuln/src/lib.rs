//! Regression reproducer for RUSTSEC-2021-0049 / GHSA-5hpj-m323-cphm.
//!
//! The case invokes the real `through` 0.1.0 public API. The advisory
//! trigger is a user-provided mapping closure that panics after the
//! crate has duplicated ownership with `ptr::read`.

use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use std::process::{Command, Output};
use through::through;

pub const SITE_THROUGH_BOUNDARY: &str = "S00001";
pub const FN_THROUGH_VULN: &str = "crate::run_public_api_poc";

#[derive(Debug)]
pub struct DropDetector {
    id: u32,
    _payload: Box<u64>,
}

impl DropDetector {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            _payload: Box::new(0x7A7A_D0D0_u64 ^ id as u64),
        }
    }
}

impl Drop for DropDetector {
    fn drop(&mut self) {
        // Keep this textual pattern: replay tests treat duplicate prints
        // as optional evidence on platforms that unwind far enough.
        println!("Dropping through {}", self.id);
    }
}

/// Real public-API PoC for RUSTSEC-2021-0049.
pub fn run_public_api_poc() {
    install_panic_hook();
    let _guard = dpr_function!(FN_THROUGH_VULN);

    let mut value = DropDetector::new(1);

    dpr_hit!(SITE_THROUGH_BOUNDARY);
    through(&mut value, |_owned: DropDetector| -> DropDetector {
        panic!("RUSTDPR_THROUGH_MAPPING_CLOSURE_PANIC");
    });
}

fn spawn_child_poc() -> Output {
    let current_exe = std::env::current_exe().expect("current test binary path");
    Command::new(current_exe)
        .env("RUSTDPR_THROUGH_RUN_CHILD", "1")
        .arg("--ignored")
        .arg("__through_child_process")
        .arg("--nocapture")
        .output()
        .expect("spawn through PoC child process")
}

fn child_output_has_replay_evidence(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    let duplicate_drop_1 = combined.matches("Dropping through 1").count() >= 2;

    !output.status.success()
        || duplicate_drop_1
        || combined.contains("RUSTDPR_THROUGH_MAPPING_CLOSURE_PANIC")
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
    #[ignore = "child process that intentionally triggers the historical through bug"]
    fn __through_child_process() {
        if std::env::var("RUSTDPR_THROUGH_RUN_CHILD").ok().as_deref() != Some("1") {
            eprintln!("child PoC test skipped because RUSTDPR_THROUGH_RUN_CHILD is not set");
            return;
        }
        run_public_api_poc();
    }

    #[test]
    #[ignore = "spawns a child process that intentionally triggers the historical through bug"]
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
            "vulnerable through PoC did not expose replay evidence.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );
    }

    #[test]
    #[should_panic(expected = "RUSTDPR_THROUGH_REPLAY_CONFIRMED_AFTER_API_BOUNDARY")]
    fn rustdpr_deterministic_trace_replay() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        install_panic_hook();
        let _guard = dpr_function!(FN_THROUGH_VULN);

        // API-boundary marker. The true unsafe operation lives inside
        // the external through 0.1.0 dependency.
        dpr_hit!(SITE_THROUGH_BOUNDARY);

        let output = spawn_child_poc();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stdout.contains("running 0 tests"),
            "child PoC test was not selected by the test filter.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );

        if child_output_has_replay_evidence(&output) {
            panic!("RUSTDPR_THROUGH_REPLAY_CONFIRMED_AFTER_API_BOUNDARY");
        }

        panic!("RUSTDPR_THROUGH_REPLAY_UNEXPECTEDLY_SUCCEEDED_AFTER_API_BOUNDARY");
    }
}
