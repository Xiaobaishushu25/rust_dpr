use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidityStatus {
    LikelyValid,
    LikelyMisuse,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityEvidence {
    pub rule: String,
    pub message: String,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessValidityReport {
    pub harness_path: String,
    pub status: ValidityStatus,
    pub evidence: Vec<ValidityEvidence>,
}