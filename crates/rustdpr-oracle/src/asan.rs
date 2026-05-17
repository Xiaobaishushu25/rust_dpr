use crate::verdict::OracleReport;
use rustdpr_core::{OracleEvidenceStrength, OracleVerdict};

pub fn parse_asan_log(content: &str, raw_log_path: Option<String>) -> OracleReport {
    let lower = content.to_lowercase();
    let mut evidence = Vec::new();

    let (verdict, bug_kind) = if contains_any(&lower, &["double-free", "attempting double-free"]) {
        evidence.push("ASan reported double-free".to_string());
        (OracleVerdict::AddressSanitizerDoubleFree, Some("double-free".to_string()))
    } else if contains_any(&lower, &["heap-use-after-free", "stack-use-after-return", "use-after-free"]) {
        evidence.push("ASan reported use-after-free".to_string());
        (OracleVerdict::AddressSanitizerUseAfterFree, Some("use-after-free".to_string()))
    } else if contains_any(&lower, &["heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow", "container-overflow", "out-of-bounds"]) {
        evidence.push("ASan reported buffer overflow/out-of-bounds".to_string());
        (OracleVerdict::AddressSanitizerOutOfBounds, Some("out-of-bounds".to_string()))
    } else if contains_any(&lower, &["attempting free on address which was not malloc", "bad-free", "invalid-free", "alloc-dealloc-mismatch"]) {
        evidence.push("ASan reported invalid free or allocation/deallocation mismatch".to_string());
        (OracleVerdict::AddressSanitizerInvalidFree, Some("invalid-free".to_string()))
    } else if contains_any(&lower, &["leaksanitizer", "detected memory leaks", "direct leak of", "indirect leak of"]) {
        evidence.push("LeakSanitizer reported memory leak".to_string());
        (OracleVerdict::AddressSanitizerLeak, Some("memory-leak".to_string()))
    } else if contains_any(&lower, &["timeout", "alarm", "max_total_time"]) {
        evidence.push("oracle run appears to have timed out".to_string());
        (OracleVerdict::OracleTimeout, Some("timeout".to_string()))
    } else {
        (OracleVerdict::Unknown, None)
    };

    if lower.contains("summary: addresssanitizer") {
        evidence.push("log contains AddressSanitizer SUMMARY line".to_string());
    }
    if lower.contains("==") && lower.contains("error: addresssanitizer") {
        evidence.push("log contains canonical ASan ERROR header".to_string());
    }

    let status = if verdict == OracleVerdict::Unknown { "unknown" } else { "confirmed" };
    let evidence_strength = if verdict == OracleVerdict::Unknown {
        OracleEvidenceStrength::Unknown
    } else if evidence.iter().any(|e| e.contains("SUMMARY") || e.contains("canonical")) {
        OracleEvidenceStrength::Confirmed
    } else {
        OracleEvidenceStrength::StrongHeuristic
    };

    OracleReport {
        oracle_name: "asan".into(),
        status: status.into(),
        verdict,
        bug_kind,
        raw_log_path,
        unsupported_reason: None,
        evidence_strength,
        target_api_misuse: false,
        evidence,
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}
