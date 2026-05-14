use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpanInfo {
    pub file: String,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DangerousKind {
    UnsafeFn,
    UnsafeBlock,
    RawDerefCandidate,
    FfiDeclaration,
    FfiCallCandidate,
    Transmute,
    ManualAllocCandidate,
    ManualFreeCandidate,
    IndexingCandidate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PanicKind {
    PanicMacro,
    AssertMacro,
    UnwrapLike,
    ExpectLike,
    TodoMacro,
    UnimplementedMacro,
    IndexingPanicCandidate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousSite {
    pub site_id: String,
    pub kind: DangerousKind,
    pub enclosing_fn: String,
    pub span: SpanInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanicSite {
    pub panic_id: String,
    pub kind: PanicKind,
    pub enclosing_fn: String,
    pub span: SpanInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiteMap {
    pub crate_root: String,
    pub dangerous_sites: Vec<DangerousSite>,
    pub panic_sites: Vec<PanicSite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub function_id: String,
    pub is_public: bool,
    pub file: String,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallEdge {
    pub caller: String,
    pub callee: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionIndex {
    pub functions: Vec<FunctionSummary>,
    pub call_edges: Vec<FunctionCallEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceEvent {
    Hit {
        site_id: String,
        ts_millis: u64,
    },
    Panic {
        message: Option<String>,
        file: Option<String>,
        line: Option<u32>,
        ts_millis: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TraceLog {
    pub events: Vec<TraceEvent>,
}

impl TraceLog {
    pub fn hit_site_ids(&self) -> Vec<&str> {
        self.events
            .iter()
            .filter_map(|e| match e {
                TraceEvent::Hit { site_id, .. } => Some(site_id.as_str()),
                _ => None,
            })
            .collect()
    }

    pub fn has_panic(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, TraceEvent::Panic { .. }))
    }

    pub fn first_panic(&self) -> Option<&TraceEvent> {
        self.events
            .iter()
            .find(|e| matches!(e, TraceEvent::Panic { .. }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OracleVerdict {
    Unknown,
    AddressSanitizerDoubleFree,
    AddressSanitizerUseAfterFree,
    AddressSanitizerOutOfBounds,
    MiriUndefinedBehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PanicDangerRelation {
    NoneObserved,
    BeforeUnsafe,
    AfterUnsafe,
    InsideUnsafeApprox,
    AdjacentToUnsafe,
    FarFromUnsafe,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FinalClass {
    NormalContractPanic,
    BlockingPanic,
    PanicAfterUnsafe,
    DangerousPathReached,
    SuspiciousCandidate,
    HarnessMisuse,
    OracleConfirmedDoubleFree,
    OracleConfirmedUseAfterFree,
    OracleConfirmedOutOfBounds,
    OracleConfirmedUb,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClassificationNotes {
    pub notes: Vec<String>,
    pub counters: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub final_class: FinalClass,
    pub relation: PanicDangerRelation,
    pub reached_dangerous_sites: Vec<String>,
    pub nearest_dangerous_site: Option<String>,
    pub distance_to_dangerous_site: Option<u32>,
    pub oracle_verdict: OracleVerdict,
    pub harness_status: crate::harness::ValidityStatus,
    pub notes: ClassificationNotes,
}