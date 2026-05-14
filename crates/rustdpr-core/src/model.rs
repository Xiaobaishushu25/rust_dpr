use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// 表示代码位置的跨度信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanInfo {
    /// 文件路径
    pub file: PathBuf,
    /// 起始行号
    pub line_start: usize,
    /// 结束行号
    pub line_end: usize,
}

/// Crate 元数据信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateMeta {
    /// Crate 名称
    pub name: String,
    /// Crate 版本
    pub version: String,
    /// Cargo.toml 文件路径
    pub manifest_path: PathBuf,
    /// 工作区根目录
    pub workspace_root: PathBuf,
    /// 目标列表（bin、lib等）
    pub targets: Vec<TargetMeta>,
    /// 特性配置
    pub features: BTreeMap<String, Vec<String>>,
}

/// 编译目标元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetMeta {
    /// 目标名称
    pub name: String,
    /// 目标类型（bin、lib、test等）
    pub kind: Vec<String>,
    /// 源文件路径
    pub src_path: PathBuf,
}

/// 危险操作类型枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DangerousKind {
    /// 不安全函数
    UnsafeFn,
    /// 不安全代码块
    UnsafeBlock,
    /// 原始指针解引用候选
    RawDerefCandidate,
    /// FFI 声明
    FfiDeclaration,
    /// FFI 调用候选
    FfiCallCandidate,
    /// transmute 调用
    TransmuteCall,
    /// 索引表达式候选
    IndexExprCandidate,
}

/// Panic 类型枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PanicKind {
    /// panic! 宏
    PanicMacro,
    /// assert! 宏
    AssertMacro,
    /// unwrap() 调用
    UnwrapCall,
    /// expect() 调用
    ExpectCall,
    /// todo! 宏
    TodoMacro,
    /// unimplemented! 宏
    UnimplementedMacro,
    /// 索引表达式运行时检查
    IndexExprRuntimeCheck,
}

/// 危险代码站点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousSite {
    /// 站点唯一标识
    pub site_id: String,
    /// 危险操作类型
    pub kind: DangerousKind,
    /// 所在函数名（如果有）
    pub enclosing_fn: Option<String>,
    /// 代码位置
    pub span: SpanInfo,
}

/// Panic 站点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanicSite {
    /// Panic 站点唯一标识
    pub panic_id: String,
    /// Panic 类型
    pub kind: PanicKind,
    /// 所在函数名（如果有）
    pub enclosing_fn: Option<String>,
    /// 代码位置
    pub span: SpanInfo,
}

/// 站点地图，包含所有危险站点和 panic 站点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteMap {
    /// Crate 名称
    pub crate_name: String,
    /// 危险站点列表
    pub dangerous_sites: Vec<DangerousSite>,
    /// Panic 站点列表
    pub panic_sites: Vec<PanicSite>,
}

/// 追踪事件枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceEvent {
    /// 危险站点被访问的事件
    Hit {
        /// 站点 ID
        site_id: String,
        /// 时间戳（毫秒）
        ts_millis: u128,
    },
    /// Panic 发生的事件
    Panic {
        /// Panic 消息
        message: Option<String>,
        /// 文件名
        file: Option<String>,
        /// 行号
        line: Option<u32>,
        /// 时间戳（毫秒）
        ts_millis: u128,
    },
}

/// 追踪日志，包含一系列事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceLog {
    /// 事件列表
    pub events: Vec<TraceEvent>,
}

/// Panic 与危险操作的关系
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PanicRelation {
    /// 没有危险站点被访问
    NoDangerousSiteReached,
    /// Panic 发生在危险操作之前
    BeforeUnsafe,
    /// Panic 发生在危险操作之后
    AfterUnsafe,
    /// Panic 发生在危险操作内部（近似）
    InsideUnsafeApprox,
    /// 关系未知
    Unknown,
}

/// 案例分类枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaseClass {
    /// 正常的契约 panic
    NormalContractPanic,
    /// 阻塞性 panic（阻止了危险路径执行）
    BlockingPanic,
    /// 危险操作后的 panic
    PanicAfterUnsafe,
    /// 测试工具误用
    HarnessMisuse,
    /// 可疑候选案例
    SuspiciousCandidate,
    OracleConfirmedMemoryBug,
    /// 未知类型
    Unknown,
}

/// 分类结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// Panic 与危险操作的关系
    pub relation: PanicRelation,
    /// 案例分类
    pub class: CaseClass,
    /// 已访问的站点 ID 列表
    pub reached_site_ids: Vec<String>,
    /// 备注说明
    pub notes: Vec<String>,
    pub panic_message: Option<String>,
    pub panic_file: Option<String>,
    pub panic_line: Option<u32>,
    pub oracle_confirmed: bool,
    pub oracle_results: Vec<OracleFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OracleKind {
    AddressSanitizer,
    Miri,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OracleVerdict {
    NoIssue,
    MemoryCorruption,
    DoubleFree,
    UseAfterFree,
    OutOfBounds,
    InvalidFree,
    UndefinedBehavior,
    PanicOnly,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleFinding {
    pub oracle: OracleKind,
    pub verdict: OracleVerdict,
    pub message: String,
    pub stack: Option<Vec<String>>,
    pub location: Option<String>,
    pub raw_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleResult {
    pub findings: Vec<OracleFinding>,
}