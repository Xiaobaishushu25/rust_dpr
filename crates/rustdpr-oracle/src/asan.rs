use rustdpr_core::model::{
    OracleFinding,
    OracleKind,
    OracleResult,
    OracleVerdict,
};

pub fn parse_asan_output(output: &str) -> OracleResult {
    let mut findings = Vec::new();

    let verdict = if output.contains("double-free") {
        OracleVerdict::DoubleFree
    } else if output.contains("heap-use-after-free") {
        OracleVerdict::UseAfterFree
    } else if output.contains("heap-buffer-overflow") {
        OracleVerdict::OutOfBounds
    } else if output.contains("AddressSanitizer") {
        OracleVerdict::MemoryCorruption
    } else {
        OracleVerdict::Unknown
    };

    if !matches!(verdict, OracleVerdict::Unknown) {
        findings.push(OracleFinding {
            oracle: OracleKind::AddressSanitizer,
            verdict,
            raw_message: output.to_string(),
        });
    }

    OracleResult { findings }
}