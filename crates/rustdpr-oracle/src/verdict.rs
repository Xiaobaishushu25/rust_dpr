use rustdpr_core::OracleVerdict;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleReport {
    pub oracle_name: String,
    pub status: String,
    pub verdict: OracleVerdict,
    pub bug_kind: Option<String>,
    pub raw_log_path: Option<String>,
    pub unsupported_reason: Option<String>,
}