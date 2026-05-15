use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ValidityStatus {
    ConfirmedValid,
    LikelyValid,
    LikelyMisuse,
    Invalid,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidityEvidence {
    pub rule: String,
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HarnessValidityReport {
    pub harness_path: String,
    pub status: ValidityStatus,
    pub evidence: Vec<ValidityEvidence>,
    pub violated_patterns: Vec<String>,
    pub needs_manual_review: bool,
}