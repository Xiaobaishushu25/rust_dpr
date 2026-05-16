use crate::harness::ValidityStatus;
use crate::label::{PrimaryLabel, RelationLabel};
use crate::schema_version::RUSTDPR_SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SpanInfo {
    pub file: String,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DangerousKind {
    #[default]
    UnsafeFn,
    UnsafeBlock,
    RawDerefCandidate,
    FfiDeclaration,
    FfiCallCandidate,
    FfiBoundary,
    Transmute,
    TransmuteCopy,
    ManualAllocCandidate,
    ManualFreeCandidate,
    BoxFromRaw,
    BoxIntoRaw,
    FromRawParts,
    MemForget,
    ManuallyDropCandidate,
    MaybeUninitCandidate,
    PtrReadCandidate,
    PtrWriteCandidate,
    CopyNonOverlappingCandidate,
    IndexingCandidate,
    DropSensitiveCandidate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum PanicKind {
    PanicMacro,
    AssertMacro,
    UnwrapLike,
    ExpectLike,
    TodoMacro,
    UnimplementedMacro,
    IndexingPanicCandidate,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DangerousSite {
    pub site_id: String,
    pub kind: DangerousKind,
    pub kind_weight: f32,
    pub enclosing_fn: String,
    pub span: SpanInfo,
    pub matched_by_rule: String,
    pub confidence: String,

    #[serde(default)]
    pub obligation: Option<String>,

    #[serde(default)]
    pub macro_expanded: bool,

    #[serde(default)]
    pub generic_context: Option<String>,

    #[serde(default)]
    pub ffi_abi: Option<String>,

    #[serde(default)]
    pub site_group: Option<String>,

    #[serde(default)]
    pub source_level: Option<String>,

    #[serde(default)]
    pub review_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PanicSite {
    pub panic_id: String,
    pub kind: PanicKind,
    pub enclosing_fn: String,
    pub span: SpanInfo,
    pub matched_by_rule: String,

    #[serde(default)]
    pub message_pattern: Option<String>,

    #[serde(default)]
    pub runtime_generated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiteMap {
    pub schema_version: String,
    pub crate_root: String,
    pub dangerous_sites: Vec<DangerousSite>,
    pub panic_sites: Vec<PanicSite>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionSummary {
    pub function_id: String,
    pub is_public: bool,
    pub file: String,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    EnterFunction {
        function: String,
        ts_millis: u64,
        input_id: Option<String>,
        run_id: Option<String>,
        thread_id: String,
    },
    ExitFunction {
        function: String,
        ts_millis: u64,
        input_id: Option<String>,
        run_id: Option<String>,
        thread_id: String,
    },
    Hit {
        site_id: String,
        ts_millis: u64,
        input_id: Option<String>,
        run_id: Option<String>,
        thread_id: String,
    },
    Panic {
        message: Option<String>,
        file: Option<String>,
        line: Option<u32>,
        ts_millis: u64,
        input_id: Option<String>,
        run_id: Option<String>,
        thread_id: String,
    },
    OracleMarker {
        oracle: String,
        detail: String,
        ts_millis: u64,
        input_id: Option<String>,
        run_id: Option<String>,
        thread_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceLog {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    #[serde(default)]
    pub case_name: Option<String>,

    #[serde(default)]
    pub suite: Option<String>,

    #[serde(default)]
    pub run_id: Option<String>,

    #[serde(default)]
    pub events: Vec<TraceEvent>,
}

impl Default for TraceLog {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            case_name: None,
            suite: None,
            run_id: None,
            events: Vec::new(),
        }
    }
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

    pub fn hit_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, TraceEvent::Hit { .. }))
            .count()
    }

    pub fn panic_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, TraceEvent::Panic { .. }))
            .count()
    }

    pub fn has_panic(&self) -> bool {
        self.events.iter().any(|e| matches!(e, TraceEvent::Panic { .. }))
    }

    pub fn first_panic(&self) -> Option<&TraceEvent> {
        self.events.iter().find(|e| matches!(e, TraceEvent::Panic { .. }))
    }

    pub fn first_hit(&self) -> Option<&TraceEvent> {
        self.events.iter().find(|e| matches!(e, TraceEvent::Hit { .. }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OracleVerdict {
    Unknown,
    AddressSanitizerDoubleFree,
    AddressSanitizerUseAfterFree,
    AddressSanitizerOutOfBounds,
    AddressSanitizerInvalidFree,
    AddressSanitizerLeak,
    MiriUndefinedBehavior,
    MiriUnsupported,
    OracleTimeout,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClassificationNotes {
    #[serde(default)]
    pub notes: Vec<String>,

    #[serde(default)]
    pub counters: BTreeMap<String, usize>,

    #[serde(default)]
    pub fired_rules: Vec<String>,

    #[serde(default)]
    pub conflicting_evidence: Vec<String>,

    #[serde(default)]
    pub evidence_summary: Vec<String>,

    #[serde(default)]
    pub decision_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    #[serde(default)]
    pub case_name: Option<String>,

    #[serde(default)]
    pub suite: Option<String>,

    pub primary_label: PrimaryLabel,
    pub relation: RelationLabel,
    pub reached_dangerous_sites: Vec<String>,
    pub nearest_dangerous_site: Option<String>,
    pub distance_to_dangerous_site: Option<u32>,
    pub oracle_verdict: OracleVerdict,
    pub harness_status: ValidityStatus,
    pub confidence: f32,
    pub review_required: bool,
    pub notes: ClassificationNotes,
}

fn default_schema_version() -> String {
    RUSTDPR_SCHEMA_VERSION.to_string()
}