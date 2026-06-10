//! Regression reproducer for RUSTSEC-2021-0033 / stack_dst.
//!
//! The case invokes the real `stack_dst` 0.6.0 public API
//! `StackA::push_cloned`. The advisory trigger is a user-provided
//! `Clone` implementation that panics after stack_dst has updated
//! internal length state too early.

use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use stack_dst::StackA;
use std::process::{Command, Output};

pub const SITE_STACK_DST_PUSH_CLONED_BOUNDARY: &str = "S00001";
pub const FN_STACK_DST_PUSH_CLONED_VULN: &str = "crate::run_public_api_poc";

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
        println!("Dropping stack_dst {}", self.id);
    }
}

impl Clone for DropDetector {
    fn clone(&self) -> Self {
        panic!("RUSTDPR_STACK_DST_CLONE_PANIC_{}", self.id);
    }
}

/// Real public-API PoC for RUSTSEC-2021-0033.
pub fn run_public_api_poc() {
    install_panic_hook();
    let _guard = dpr_function!(FN_STACK_DST_PUSH_CLONED_VULN);

    let mut stack = StackA::<[DropDetector], [usize; 9]>::new();
    stack.push_stable([DropDetector::new(1)], |p| p).unwrap();
    stack.push_stable([DropDetector::new(2)], |p| p).unwrap();
    let _second_drop = stack.pop();

    dpr_hit!(SITE_STACK_DST_PUSH_CLONED_BOUNDARY);
    stack.push_cloned(&[DropDetector::new(3)]).unwrap();
}

fn spawn_child_poc() -> Output {
    let current_exe = std::env::current_exe().expect("current test binary path");
    Command::new(current_exe)
        .env("RUSTDPR_STACK_DST_RUN_CHILD", "1")
        .arg("--ignored")
        .arg("__stack_dst_child_process")
        .arg("--nocapture")
        .output()
        .expect("spawn stack_dst PoC child process")
}

fn child_output_has_replay_evidence(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    let duplicate_drop_1 = combined.matches("Dropping stack_dst 1").count() >= 2;
    let duplicate_drop_2 = combined.matches("Dropping stack_dst 2").count() >= 2;
    let duplicate_drop_3 = combined.matches("Dropping stack_dst 3").count() >= 2;

    !output.status.success()
        || duplicate_drop_1
        || duplicate_drop_2
        || duplicate_drop_3
        || combined.contains("RUSTDPR_STACK_DST_CLONE_PANIC")
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
    #[ignore = "child process that intentionally triggers the historical stack_dst bug"]
    fn __stack_dst_child_process() {
        if std::env::var("RUSTDPR_STACK_DST_RUN_CHILD").ok().as_deref() != Some("1") {
            eprintln!("child PoC test skipped because RUSTDPR_STACK_DST_RUN_CHILD is not set");
            return;
        }
        run_public_api_poc();
    }

    #[test]
    #[ignore = "spawns a child process that intentionally triggers the historical stack_dst bug"]
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
            "vulnerable stack_dst PoC did not expose replay evidence.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );
    }

    #[test]
    #[should_panic(expected = "RUSTDPR_STACK_DST_REPLAY_CONFIRMED_AFTER_API_BOUNDARY")]
    fn rustdpr_deterministic_trace_replay() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        install_panic_hook();
        let _guard = dpr_function!(FN_STACK_DST_PUSH_CLONED_VULN);

        dpr_hit!(SITE_STACK_DST_PUSH_CLONED_BOUNDARY);

        let output = spawn_child_poc();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stdout.contains("running 0 tests"),
            "child PoC test was not selected by the test filter.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );

        if child_output_has_replay_evidence(&output) {
            panic!("RUSTDPR_STACK_DST_REPLAY_CONFIRMED_AFTER_API_BOUNDARY");
        }

        panic!("RUSTDPR_STACK_DST_REPLAY_UNEXPECTEDLY_SUCCEEDED_AFTER_API_BOUNDARY");
    }
}
