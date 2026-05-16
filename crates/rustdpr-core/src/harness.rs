use crate::schema_version::RUSTDPR_SCHEMA_VERSION;
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidityEvidence {
    pub rule: String,
    pub severity: String,
    pub message: String,
    pub file: String,
    pub line: usize,

    #[serde(default)]
    pub span_end_line: Option<usize>,

    #[serde(default)]
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessValidityReport {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub harness_path: String,
    pub status: ValidityStatus,
    pub evidence: Vec<ValidityEvidence>,
    pub violated_patterns: Vec<String>,
    pub needs_manual_review: bool,

    #[serde(default)]
    pub summary: Option<String>,

    #[serde(default)]
    pub score: Option<f32>,
}

impl Default for HarnessValidityReport {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            harness_path: String::new(),
            status: ValidityStatus::Unknown,
            evidence: Vec::new(),
            violated_patterns: Vec::new(),
            needs_manual_review: false,
            summary: None,
            score: None,
        }
    }
}

fn default_schema_version() -> String {
    RUSTDPR_SCHEMA_VERSION.to_string()
}