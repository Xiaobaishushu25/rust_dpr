use crate::verdict::OracleReport;
use rustdpr_core::OracleVerdict;

pub fn parse_asan_log(content: &str, raw_log_path: Option<String>) -> OracleReport {
    let lower = content.to_lowercase();

    let verdict = if lower.contains("double-free") {
        OracleVerdict::AddressSanitizerDoubleFree
    } else if lower.contains("use-after-free") {
        OracleVerdict::AddressSanitizerUseAfterFree
    } else if lower.contains("out-of-bounds") || lower.contains("heap-buffer-overflow") {
        OracleVerdict::AddressSanitizerOutOfBounds
    } else {
        OracleVerdict::Unknown
    };

    OracleReport {
        oracle_name: "asan".into(),
        status: if verdict == OracleVerdict::Unknown {
            "unknown".into()
        } else {
            "confirmed".into()
        },
        verdict,
        bug_kind: None,
        raw_log_path,
        unsupported_reason: None,
    }
}