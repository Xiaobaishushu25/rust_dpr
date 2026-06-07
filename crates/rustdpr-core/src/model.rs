use crate::harness::ValidityStatus;
use crate::label::{PrimaryLabel, RelationLabel};
use crate::schema_version::RUSTDPR_SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SpanInfo {
    pub file: String,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CrateMeta {
    pub name: String,
    pub version: String,
    pub manifest_path: PathBuf,
    pub workspace_root: PathBuf,
    pub targets: Vec<TargetMeta>,
    pub features: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetMeta {
    pub name: String,
    pub kind: Vec<String>,
    pub src_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum DangerousCategory {
    #[default]
    UnsafeRust, // unsafe Rust 通用类别
    RawPointer,          // 裸指针操作
    Ffi,                 // 外部函数接口
    TypePunning,         // 类型双关（transmute）
    AllocationOwnership, // 内存分配所有权 比如手动内存管理
    Initialization,      // 初始化问题
    DropInvariant,       // Drop 不变量破坏
    RuntimeCheck,        // 运行时检查
    PanicBoundary,       // Panic 边界问题
    Unknown,             // 未知类别
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum EvidenceStrength {
    Confirmed, // 已确认（通过 ASAN/Miri 等工具）
    Strong,    // 强证据（明确的静态模式匹配）
    Medium,    // 中等证据
    Weak,      // 弱证据
    #[default]
    Heuristic, // 启发式推断（默认）
    Unsupported, // 不支持检测
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DangerousKind {
    #[default]
    UnsafeFn,
    UnsafeBlock,
    RawDerefCandidate,
    RawAddrCandidate,
    FfiDeclaration,
    FfiCallCandidate,
    FfiBoundary,
    FfiUnwindBoundary,
    Transmute,
    TransmuteCopy,
    ManualAllocCandidate,
    ManualFreeCandidate,
    BoxFromRaw,
    BoxIntoRaw,
    FromRawParts,
    VecFromRawParts,
    NonNullNewUnchecked,
    MemForget,
    ManuallyDropCandidate,
    MaybeUninitCandidate,
    AssumeInitCandidate,
    PtrReadCandidate,
    PtrWriteCandidate,
    CopyNonOverlappingCandidate,
    IndexingCandidate,
    DropSensitiveCandidate,
    SetLenCandidate,
    UnsafeTraitImpl,
    TargetApiMisuseCandidate,
}

impl DangerousKind {
    pub fn category(&self) -> DangerousCategory {
        match self {
            DangerousKind::UnsafeFn
            | DangerousKind::UnsafeBlock
            | DangerousKind::UnsafeTraitImpl => DangerousCategory::UnsafeRust,
            DangerousKind::RawDerefCandidate
            | DangerousKind::RawAddrCandidate
            | DangerousKind::PtrReadCandidate
            | DangerousKind::PtrWriteCandidate
            | DangerousKind::CopyNonOverlappingCandidate
            | DangerousKind::NonNullNewUnchecked => DangerousCategory::RawPointer,
            DangerousKind::FfiDeclaration
            | DangerousKind::FfiCallCandidate
            | DangerousKind::FfiBoundary
            | DangerousKind::FfiUnwindBoundary => DangerousCategory::Ffi,
            DangerousKind::Transmute | DangerousKind::TransmuteCopy => {
                DangerousCategory::TypePunning
            }
            DangerousKind::ManualAllocCandidate
            | DangerousKind::ManualFreeCandidate
            | DangerousKind::BoxFromRaw
            | DangerousKind::BoxIntoRaw
            | DangerousKind::FromRawParts
            | DangerousKind::VecFromRawParts => DangerousCategory::AllocationOwnership,
            DangerousKind::MaybeUninitCandidate | DangerousKind::AssumeInitCandidate => {
                DangerousCategory::Initialization
            }
            DangerousKind::ManuallyDropCandidate
            | DangerousKind::DropSensitiveCandidate
            | DangerousKind::SetLenCandidate => DangerousCategory::DropInvariant,
            DangerousKind::IndexingCandidate => DangerousCategory::RuntimeCheck,
            DangerousKind::MemForget => DangerousCategory::DropInvariant,
            DangerousKind::TargetApiMisuseCandidate => DangerousCategory::PanicBoundary,
        }
    }

    pub fn default_weight(&self) -> f32 {
        // Paper-facing prioritization weights. These are not security ground truth;
        // they only rank dangerous-path evidence for DPC/wDPC reporting.
        match self {
            DangerousKind::FfiBoundary
            | DangerousKind::FfiUnwindBoundary
            | DangerousKind::FfiCallCandidate
            | DangerousKind::FfiDeclaration => 5.0,

            DangerousKind::RawDerefCandidate
            | DangerousKind::PtrReadCandidate
            | DangerousKind::PtrWriteCandidate
            | DangerousKind::CopyNonOverlappingCandidate
            | DangerousKind::NonNullNewUnchecked => 5.0,

            DangerousKind::FromRawParts
            | DangerousKind::VecFromRawParts
            | DangerousKind::BoxFromRaw
            | DangerousKind::ManualFreeCandidate => 5.0,

            DangerousKind::SetLenCandidate => 4.0,

            DangerousKind::MaybeUninitCandidate
            | DangerousKind::AssumeInitCandidate
            | DangerousKind::Transmute
            | DangerousKind::TransmuteCopy => 4.0,

            DangerousKind::ManuallyDropCandidate
            | DangerousKind::MemForget
            | DangerousKind::DropSensitiveCandidate => 3.0,

            DangerousKind::UnsafeTraitImpl => 2.0,

            DangerousKind::UnsafeFn
            | DangerousKind::UnsafeBlock
            | DangerousKind::RawAddrCandidate
            | DangerousKind::IndexingCandidate
            | DangerousKind::TargetApiMisuseCandidate
            | DangerousKind::BoxIntoRaw
            | DangerousKind::ManualAllocCandidate => 1.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum PanicKind {
    PanicMacro,
    AssertMacro,
    DebugAssertMacro,
    UnwrapLike,
    ExpectLike,
    TodoMacro,
    UnimplementedMacro,
    UnreachableMacro,
    IndexingPanicCandidate,
    RuntimeCheckCandidate,
    FfiUnwindPanicCandidate,
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
    pub category: DangerousCategory,

    #[serde(default)]
    pub evidence_strength: EvidenceStrength,

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

    #[serde(default)]
    pub macro_expanded: bool,

    #[serde(default)]
    pub evidence_strength: EvidenceStrength,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiteMap {
    pub schema_version: String,
    pub crate_root: String,
    pub dangerous_sites: Vec<DangerousSite>,
    pub panic_sites: Vec<PanicSite>,

    #[serde(default)]
    pub taxonomy: TaxonomySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaxonomySummary {
    #[serde(default)]
    pub dangerous_by_category: BTreeMap<DangerousCategory, usize>,
    #[serde(default)]
    pub dangerous_by_kind: BTreeMap<String, usize>,
    #[serde(default)]
    pub panic_by_kind: BTreeMap<String, usize>,
    #[serde(default)]
    pub evidence_by_strength: BTreeMap<EvidenceStrength, usize>,
}

impl SiteMap {
    pub fn refresh_taxonomy(&mut self) {
        let mut summary = TaxonomySummary::default();
        for site in &self.dangerous_sites {
            *summary
                .dangerous_by_category
                .entry(site.category.clone())
                .or_insert(0) += 1;
            *summary
                .dangerous_by_kind
                .entry(format!("{:?}", site.kind))
                .or_insert(0) += 1;
            *summary
                .evidence_by_strength
                .entry(site.evidence_strength.clone())
                .or_insert(0) += 1;
        }
        for site in &self.panic_sites {
            *summary
                .panic_by_kind
                .entry(format!("{:?}", site.kind))
                .or_insert(0) += 1;
            *summary
                .evidence_by_strength
                .entry(site.evidence_strength.clone())
                .or_insert(0) += 1;
        }
        self.taxonomy = summary;
    }
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

    pub fn enter_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, TraceEvent::EnterFunction { .. }))
            .count()
    }

    pub fn exit_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, TraceEvent::ExitFunction { .. }))
            .count()
    }

    pub fn panic_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, TraceEvent::Panic { .. }))
            .count()
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

    pub fn first_hit(&self) -> Option<&TraceEvent> {
        self.events
            .iter()
            .find(|e| matches!(e, TraceEvent::Hit { .. }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OracleVerdict {
    Unknown,
    NoOracleFinding,
    AddressSanitizerDoubleFree,
    AddressSanitizerUseAfterFree,
    AddressSanitizerOutOfBounds,
    AddressSanitizerInvalidFree,
    AddressSanitizerLeak,
    MiriUndefinedBehavior,
    MiriUnsupported,
    OracleTimeout,
    OracleBuildFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum OracleEvidenceStrength {
    Confirmed,
    StrongHeuristic,
    WeakHeuristic,
    TargetApiMisuse,
    Unsupported,
    #[default]
    Unknown,
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

    #[serde(default)]
    pub oracle_evidence_strength: OracleEvidenceStrength,

    #[serde(default)]
    pub target_api_misuse: bool,

    pub harness_status: ValidityStatus,
    pub confidence: f32,
    pub review_required: bool,
    pub notes: ClassificationNotes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationOptions {
    #[serde(default = "default_true")]
    pub use_dynamic_trace: bool,
    #[serde(default = "default_true")]
    pub use_dpg_adjacency: bool,
    #[serde(default = "default_true")]
    pub use_harness_validity: bool,
    #[serde(default = "default_true")]
    pub use_oracle: bool,
    #[serde(default)]
    pub panic_only: bool,
    #[serde(default)]
    pub static_only: bool,
    #[serde(default = "default_true")]
    pub weighted_sites: bool,
}

impl Default for ClassificationOptions {
    fn default() -> Self {
        Self {
            use_dynamic_trace: true,
            use_dpg_adjacency: true,
            use_harness_validity: true,
            use_oracle: true,
            panic_only: false,
            static_only: false,
            weighted_sites: true,
        }
    }
}

fn default_schema_version() -> String {
    RUSTDPR_SCHEMA_VERSION.to_string()
}

fn default_true() -> bool {
    true
}
