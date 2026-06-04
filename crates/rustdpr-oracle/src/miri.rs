use crate::verdict::OracleReport;
use rustdpr_core::{OracleEvidenceStrength, OracleVerdict};

pub fn parse_miri_log(content: &str, raw_log_path: Option<String>) -> OracleReport {
    let lower = content.to_lowercase();
    let mut evidence = Vec::new();
    let mut target_api_misuse = false;

    let ub_markers = [
        "error: undefined behavior",
        "undefined behavior:",
        "miri: undefined behavior",
        "out-of-bounds pointer arithmetic",
        "dangling pointer",
        "pointer to unallocated allocation",
        "attempting a read access using",
        "attempting a write access using",
        "deallocating while item is protected",
        "data race",
        "uninitialized",
        "invalid enum discriminant",
        "violated precondition",

        // Extra Miri UB diagnostics seen in validity and alignment cases.
        "constructing invalid value",
        "invalid value",
        "expected a boolean",
        "encountered 0x",
        "not a valid",
        "validity invariant",
        "misaligned pointer dereference",
        "memory access failed",
        "not dereferenceable",
    ];

    let api_misuse_markers = [
        "calling this function with a null pointer is undefined behavior",
        "slice::from_raw_parts requires",
        "from_raw_parts requires",
        "nonnull::new_unchecked requires",
        "copy_nonoverlapping requires",
        "unsafe precondition",
        "violated precondition",
    ];

    // Confirmed UB should win over unsupported-environment notes. This matters
    // when Miri is run with -Zmiri-disable-isolation: the log may mention
    // isolation while still containing the concrete UB report we need.
    if contains_any(&lower, &ub_markers) {
        evidence.push("Miri reported concrete UB/precondition violation".to_string());
        if contains_any(&lower, &api_misuse_markers) {
            target_api_misuse = true;
            evidence.push("UB evidence appears tied to target API misuse/precondition violation".to_string());
        }

        let evidence_strength = if target_api_misuse {
            OracleEvidenceStrength::TargetApiMisuse
        } else {
            OracleEvidenceStrength::Confirmed
        };

        return OracleReport {
            oracle_name: "miri".into(),
            status: "confirmed".into(),
            verdict: OracleVerdict::MiriUndefinedBehavior,
            bug_kind: if target_api_misuse {
                Some("target-api-misuse-or-unsafe-precondition".into())
            } else {
                None
            },
            raw_log_path,
            unsupported_reason: None,
            evidence_strength,
            target_api_misuse,
            evidence,
        };
    }

    let unsupported = [
        "unsupported operation",
        "miri does not support",
        "can't call foreign function",
        "can't call extern function",
        "is not supported by miri",
        "operation is not available under isolation",
        "operation not available under isolation",
        "isolation error",
    ];
    if contains_any(&lower, &unsupported) {
        evidence.push("Miri reported unsupported feature/operation".to_string());
        return OracleReport {
            oracle_name: "miri".into(),
            status: "unsupported".into(),
            verdict: OracleVerdict::MiriUnsupported,
            bug_kind: None,
            raw_log_path,
            unsupported_reason: Some("unsupported operation or FFI/OS dependency in Miri run".into()),
            evidence_strength: OracleEvidenceStrength::Unsupported,
            target_api_misuse: false,
            evidence,
        };
    }

    let verdict = if lower.contains("error:") && lower.contains("miri") {
        evidence.push("Miri emitted an error, but no precise UB marker matched".to_string());
        OracleVerdict::Unknown
    } else {
        OracleVerdict::Unknown
    };

    let evidence_strength = if !evidence.is_empty() {
        OracleEvidenceStrength::WeakHeuristic
    } else {
        OracleEvidenceStrength::Unknown
    };

    OracleReport {
        oracle_name: "miri".into(),
        status: if verdict == OracleVerdict::Unknown { "unknown".into() } else { "confirmed".into() },
        verdict,
        bug_kind: None,
        raw_log_path,
        unsupported_reason: None,
        evidence_strength,
        target_api_misuse,
        evidence,
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}