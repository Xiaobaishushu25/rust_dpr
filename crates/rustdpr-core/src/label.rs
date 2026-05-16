use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrimaryLabel {
    Noise,
    ContractPanic,
    HarnessMisuse,
    BlockingPanic,
    PanicAfterUnsafe,
    InsideUnsafePanic,
    DangerousPathReached,
    OracleConfirmedBug,
    SuspiciousCandidate,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum RelationLabel {
    NoneObserved,
    BeforeUnsafe,
    AfterUnsafe,
    InsideUnsafe,
    AdjacentToUnsafe,
    FfiBoundary,
    #[default]
    Unknown,
}