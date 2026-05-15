use crate::verdict::OracleReport;
use rustdpr_core::OracleVerdict;

pub fn parse_miri_log(content: &str, raw_log_path: Option<String>) -> OracleReport {
    let lower = content.to_lowercase();
    let verdict = if lower.contains("undefined behavior") || lower.contains("ub") {
        OracleVerdict::MiriUndefinedBehavior
    } else {
        OracleVerdict::Unknown
    };

    OracleReport {
        oracle_name: "miri".into(),
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