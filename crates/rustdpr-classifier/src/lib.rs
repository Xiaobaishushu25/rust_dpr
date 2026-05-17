use std::collections::{BTreeSet, HashMap};

use rustdpr_core::{
    ClassificationNotes, ClassificationResult, DangerousPathGraph, DangerousSite,
    HarnessValidityReport, OracleVerdict, PrimaryLabel, RelationLabel, SiteMap, TraceEvent,
    TraceLog, ValidityStatus, RUSTDPR_SCHEMA_VERSION,
};

/// 对执行轨迹进行分类，确定危险站点与panic之间的关系
/// 
/// # 参数
/// * `site_map` - 危险站点映射表，包含所有已识别的危险代码位置
/// * `trace` - 执行轨迹日志，记录了程序运行过程中的事件序列
/// * `dpg` - 危险路径图，描述了函数间的调用关系和到危险站点的距离
/// * `harness` - 测试 harness 的有效性报告（可选）
/// * `oracle` - 外部验证工具的结果（如ASAN、Miri等，可选）
/// 
/// # 返回值
/// 返回分类结果，包含主要标签、关系标签、置信度等信息
pub fn classify_execution(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    harness: Option<&HarnessValidityReport>,
    oracle: Option<OracleVerdict>,
) -> ClassificationResult {
    // 初始化分类结果的各个字段
    let harness_status = harness
        .map(|h| h.status.clone())
        .unwrap_or(ValidityStatus::Unknown);
    let oracle_verdict = oracle.unwrap_or(OracleVerdict::Unknown);

    let mut notes = ClassificationNotes::default();

    // 收集在执行轨迹中实际到达的危险站点
    let reached_dangerous_sites = collect_reached_dangerous_sites(site_map, trace);
    // 推断危险站点与panic之间的关系证据
    let relation_evidence = infer_relation_evidence(site_map, trace, dpg, &reached_dangerous_sites);

    // 记录基本的统计信息到分类笔记中
    notes
        .counters
        .insert("trace_events".into(), trace.events.len());
    notes
        .counters
        .insert("dangerous_hits".into(), reached_dangerous_sites.len());
    notes
        .counters
        .insert("panic_count".into(), trace.panic_count());

    // 将关系证据的解释添加到笔记中
    if let Some(msg) = relation_evidence.explanation.clone() {
        notes.notes.push(msg.clone());
        notes.evidence_summary.push(msg);
    }

    // 记录触发的规则和冲突证据
    notes.fired_rules.extend(relation_evidence.fired_rules.clone());
    notes
        .conflicting_evidence
        .extend(relation_evidence.conflicting_evidence.clone());

    // 如果存在到达的危险站点，将其添加到证据摘要中
    if !reached_dangerous_sites.is_empty() {
        notes.evidence_summary.push(format!(
            "reached dangerous sites: {}",
            reached_dangerous_sites.join(", ")
        ));
    }

    // 优先检查测试 harness 是否存在误用情况，如果是则直接返回HarnessMisuse分类
    if harness_status == ValidityStatus::LikelyMisuse {
        notes.fired_rules.push("harness-misuse-short-circuit".into());
        notes.decision_path.push("harness_status=LikelyMisuse".into());
        return ClassificationResult {
            schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
            case_name: trace.case_name.clone(),
            suite: trace.suite.clone(),
            primary_label: PrimaryLabel::HarnessMisuse,
            relation: relation_evidence.relation,
            reached_dangerous_sites,
            nearest_dangerous_site: relation_evidence.nearest_dangerous_site,
            distance_to_dangerous_site: relation_evidence.distance_to_dangerous_site,
            oracle_verdict,
            harness_status,
            confidence: 0.95,
            review_required: false,
            notes,
        };
    }

    // 检查是否有外部验证工具确认了bug的存在
    if is_oracle_confirmed(&oracle_verdict) {
        notes.fired_rules.push("oracle-confirmed".into());
        notes
            .decision_path
            .push(format!("oracle_verdict={:?}", oracle_verdict));
        notes
            .evidence_summary
            .push(format!("oracle confirmed: {:?}", oracle_verdict));

        return ClassificationResult {
            schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
            case_name: trace.case_name.clone(),
            suite: trace.suite.clone(),
            primary_label: PrimaryLabel::OracleConfirmedBug,
            relation: relation_evidence.relation,
            reached_dangerous_sites,
            nearest_dangerous_site: relation_evidence.nearest_dangerous_site,
            distance_to_dangerous_site: relation_evidence.distance_to_dangerous_site.or(Some(0)),
            oracle_verdict,
            harness_status,
            confidence: 0.99,
            review_required: false,
            notes,
        };
    }

    // 基于panic和危险站点访问情况决定主要的分类标签
    let has_panic = trace.has_panic();
    let has_reached = !reached_dangerous_sites.is_empty();

    let (primary_label, confidence, review_required) = decide_primary_label(
        has_panic,
        has_reached,
        relation_evidence.relation.clone(),
        &mut notes,
    );

    ClassificationResult {
        schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
        case_name: trace.case_name.clone(),
        suite: trace.suite.clone(),
        primary_label,
        relation: relation_evidence.relation,
        reached_dangerous_sites,
        nearest_dangerous_site: relation_evidence.nearest_dangerous_site,
        distance_to_dangerous_site: relation_evidence.distance_to_dangerous_site,
        oracle_verdict,
        harness_status,
        confidence,
        review_required,
        notes,
    }
}

/// 根据panic状态、危险站点访问情况和关系标签来决定主要的分类标签
/// 
/// # 参数
/// * `has_panic` - 是否发生了panic
/// * `has_reached` - 是否到达了危险站点
/// * `relation` - 推断出的关系标签
/// * `notes` - 可变引用，用于记录决策过程和触发的规则
/// 
/// # 返回值
/// 返回三元组：(主要标签, 置信度, 是否需要人工审查)
fn decide_primary_label(
    has_panic: bool,
    has_reached: bool,
    relation: RelationLabel,
    notes: &mut ClassificationNotes,
) -> (PrimaryLabel, f32, bool) {
    // 记录决策路径，便于后续分析和调试
    notes
        .decision_path
        .push(format!("has_panic={has_panic}, has_reached={has_reached}, relation={relation:?}"));

    // 根据不同的组合情况匹配相应的分类规则
    match (has_panic, has_reached, relation) {
        // 没有panic但到达了危险站点，且无特定关系观察到
        (false, true, RelationLabel::NoneObserved) => {
            notes.fired_rules.push("dangerous-path-reached".into());
            (PrimaryLabel::DangerousPathReached, 0.88, false)
        }
        // panic发生在unsafe操作之后
        (true, true, RelationLabel::AfterUnsafe) => {
            notes.fired_rules.push("panic-after-unsafe".into());
            (PrimaryLabel::PanicAfterUnsafe, 0.93, false)
        }
        // panic发生在unsafe块内部
        (true, _, RelationLabel::InsideUnsafe) => {
            notes.fired_rules.push("inside-unsafe-panic".into());
            (PrimaryLabel::InsideUnsafePanic, 0.92, false)
        }
        // panic发生在unsafe操作之前，阻止了危险代码的执行
        (true, false, RelationLabel::BeforeUnsafe) => {
            notes.fired_rules.push("blocking-panic".into());
            (PrimaryLabel::BlockingPanic, 0.86, false)
        }
        // panic与unsafe操作相邻，但没有到达危险站点
        (true, false, RelationLabel::AdjacentToUnsafe) => {
            notes.fired_rules.push("adjacent-panic".into());
            (PrimaryLabel::SuspiciousCandidate, 0.72, true)
        }
        // panic与unsafe操作相邻，且到达了危险站点（模糊情况）
        (true, true, RelationLabel::AdjacentToUnsafe) => {
            notes.fired_rules.push("ambiguous-adjacent".into());
            (PrimaryLabel::SuspiciousCandidate, 0.61, true)
        }
        // panic涉及FFI边界
        (true, _, RelationLabel::FfiBoundary) => {
            notes.fired_rules.push("ffi-boundary".into());
            (PrimaryLabel::SuspiciousCandidate, 0.68, true)
        }
        // 合约违反导致的panic，未观察到与unsafe的关系
        (true, _, RelationLabel::NoneObserved) => {
            notes.fired_rules.push("contract-panic".into());
            (PrimaryLabel::ContractPanic, 0.68, true)
        }
        // 未知关系的panic
        (true, _, RelationLabel::Unknown) => {
            notes.fired_rules.push("unknown-panic".into());
            (PrimaryLabel::Unknown, 0.42, true)
        }
        // 既没有panic也没有到达危险站点，视为噪声
        (false, false, _) => {
            notes.fired_rules.push("noise".into());
            (PrimaryLabel::Noise, 0.40, false)
        }
        // 没有panic但到达了危险站点的备用规则
        (false, true, _) => {
            notes.fired_rules.push("dangerous-path-reached-fallback".into());
            (PrimaryLabel::DangerousPathReached, 0.75, true)
        }
        // 有panic且到达了危险站点，但关系被推断为BeforeUnsafe（冲突情况）
        (true, true, RelationLabel::BeforeUnsafe) => {
            notes.fired_rules.push("conflicting-before-unsafe".into());
            notes.conflicting_evidence.push(
                "dangerous site was hit in trace, but relation was inferred as BeforeUnsafe".into(),
            );
            (PrimaryLabel::SuspiciousCandidate, 0.55, true)
        }
        // 静态分析显示在unsafe之后，但动态轨迹中没有命中危险站点
        (true, false, RelationLabel::AfterUnsafe) => {
            notes.fired_rules.push("static-after-unsafe-without-hit".into());
            (PrimaryLabel::SuspiciousCandidate, 0.63, true)
        }
    }
}

/// 判断外部验证工具的裁决是否确认了bug的存在
/// 
/// # 参数
/// * `verdict` - 外部验证工具的裁决结果
/// 
/// # 返回值
/// 如果裁决确认了内存安全问题则返回true，否则返回false
fn is_oracle_confirmed(verdict: &OracleVerdict) -> bool {
    matches!(
        verdict,
        OracleVerdict::AddressSanitizerDoubleFree
            | OracleVerdict::AddressSanitizerUseAfterFree
            | OracleVerdict::AddressSanitizerOutOfBounds
            | OracleVerdict::AddressSanitizerInvalidFree
            | OracleVerdict::AddressSanitizerLeak
            | OracleVerdict::MiriUndefinedBehavior
    )
}

/// 关系证据结构体，存储关于危险站点与panic之间关系的详细信息
#[derive(Debug, Clone, Default)]
struct RelationEvidence {
    /// 推断出的关系标签
    relation: RelationLabel,
    /// 最近的危险站点ID
    nearest_dangerous_site: Option<String>,
    /// 到危险站点的距离
    distance_to_dangerous_site: Option<u32>,
    /// 关系推断的解释说明
    explanation: Option<String>,
    /// 触发的分类规则列表
    fired_rules: Vec<String>,
    /// 冲突证据列表
    conflicting_evidence: Vec<String>,
}

/// 收集在执行轨迹中实际到达的危险站点列表
/// 
/// # 参数
/// * `site_map` - 危险站点映射表
/// * `trace` - 执行轨迹日志
/// 
/// # 返回值
/// 返回按字母顺序排序的已到达危险站点ID列表
fn collect_reached_dangerous_sites(site_map: &SiteMap, trace: &TraceLog) -> Vec<String> {
    let hit_ids: BTreeSet<&str> = trace.hit_site_ids().into_iter().collect();
    site_map
        .dangerous_sites
        .iter()
        .filter(|site| hit_ids.contains(site.site_id.as_str()))
        .map(|site| site.site_id.clone())
        .collect()
}

/// 推断危险站点与panic之间的关系证据
/// 
/// 该函数综合分析动态轨迹信息和静态代码结构，确定panic与危险站点之间的关系。
/// 优先考虑动态轨迹证据，其次是静态位置分析，最后是图邻接性分析。
/// 
/// # 参数
/// * `site_map` - 危险站点映射表
/// * `trace` - 执行轨迹日志
/// * `dpg` - 危险路径图
/// * `reached_dangerous_sites` - 已到达的危险站点列表
/// 
/// # 返回值
/// 返回关系证据结构体，包含推断的关系类型及相关信息
fn infer_relation_evidence(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    reached_dangerous_sites: &[String],
) -> RelationEvidence {
    // 查找第一个Hit事件的位置索引
    let first_hit_idx = trace
        .events
        .iter()
        .position(|e| matches!(e, TraceEvent::Hit { .. }));

    // 查找第一个Panic事件的位置索引
    let first_panic_idx = trace
        .events
        .iter()
        .position(|e| matches!(e, TraceEvent::Panic { .. }));

    // 根据第一个Hit和Panic事件的相对位置进行初步判断
    match (first_hit_idx, first_panic_idx) {
        // Hit事件在Panic事件之前发生，表明panic发生在unsafe操作之后
        (Some(hit), Some(panic)) if hit < panic => {
            return RelationEvidence {
                relation: RelationLabel::AfterUnsafe,
                nearest_dangerous_site: reached_dangerous_sites.first().cloned(),
                distance_to_dangerous_site: Some(0),
                explanation: Some("dynamic trace observed dangerous-site hit before panic".into()),
                fired_rules: vec!["dynamic-after-unsafe".into()],
                conflicting_evidence: vec![],
            }
        }
        // Panic事件在Hit事件之前发生，表明panic阻止了unsafe操作的执行
        (Some(hit), Some(panic)) if panic < hit => {
            return RelationEvidence {
                relation: RelationLabel::BeforeUnsafe,
                nearest_dangerous_site: reached_dangerous_sites.first().cloned(),
                distance_to_dangerous_site: Some(0),
                explanation: Some("dynamic trace observed panic before dangerous-site hit".into()),
                fired_rules: vec!["dynamic-before-unsafe".into()],
                conflicting_evidence: vec![],
            }
        }
        _ => {}
    }

    // 如果没有panic但到达了危险站点，标记为NoneObserved
    if !trace.has_panic() && !reached_dangerous_sites.is_empty() {
        return RelationEvidence {
            relation: RelationLabel::NoneObserved,
            nearest_dangerous_site: reached_dangerous_sites.first().cloned(),
            distance_to_dangerous_site: Some(0),
            explanation: Some("dangerous site reached without panic".into()),
            fired_rules: vec!["none-observed".into()],
            conflicting_evidence: vec![],
        };
    }

    // 尝试通过静态panic位置推断关系
    if let Some(ev) = infer_from_static_panic_location(site_map, trace, dpg) {
        return ev;
    }

    // 最后尝试通过图邻接性推断关系
    infer_from_graph_adjacency(trace, dpg)
}

/// 从静态panic位置推断关系证据
/// 
/// 通过分析panic发生的源代码位置与危险站点的空间关系来推断两者之间的关系。
/// 
/// # 参数
/// * `site_map` - 危险站点映射表
/// * `trace` - 执行轨迹日志
/// * `dpg` - 危险路径图
/// 
/// # 返回值
/// 如果能够从静态位置推断出关系则返回Some(RelationEvidence)，否则返回None
fn infer_from_static_panic_location(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
) -> Option<RelationEvidence> {
    // 获取第一个panic事件
    let panic = trace.first_panic()?;
    // 提取panic发生的文件和行号信息
    let (panic_file, panic_line) = match panic {
        TraceEvent::Panic {
            file: Some(file),
            line: Some(line),
            ..
        } => (file.as_str(), *line as usize),
        _ => return None,
    };

    // 检查panic位置是否落在某个危险站点的范围内
    if let Some(site) = find_dangerous_site_covering(site_map, panic_file, panic_line) {
        return Some(RelationEvidence {
            relation: RelationLabel::InsideUnsafe,
            nearest_dangerous_site: Some(site.site_id.clone()),
            distance_to_dangerous_site: Some(0),
            explanation: Some(format!(
                "panic location {}:{} falls inside dangerous site {}",
                panic_file, panic_line, site.site_id
            )),
            fired_rules: vec!["static-inside-unsafe".into()],
            conflicting_evidence: vec![],
        });
    }

    // 推断panic发生的函数名称
    let panic_fn_hint = infer_panic_function_hint(trace)?;
    // 查找与panic发生在同一函数内的危险站点候选
    let same_fn_candidates: Vec<&DangerousSite> = site_map
        .dangerous_sites
        .iter()
        .filter(|s| s.enclosing_fn == panic_fn_hint)
        .collect();

    // 如果存在同函数的危险站点候选，选择最近的一个进行分析
    if !same_fn_candidates.is_empty() {
        let nearest = same_fn_candidates
            .iter()
            .min_by_key(|s| line_gap_to_span(panic_line, s))
            .copied()
            .unwrap();

        // 根据panic行号与危险站点范围的相对位置确定关系
        let relation = if panic_line < nearest.span.line_start {
            RelationLabel::BeforeUnsafe
        } else if panic_line > nearest.span.line_end {
            RelationLabel::AfterUnsafe
        } else {
            RelationLabel::InsideUnsafe
        };

        // 计算从panic函数到任意危险站点的最短距离
        let distance = dpg.shortest_distance_to_any_dangerous_site(&panic_fn_hint).distance;

        return Some(RelationEvidence {
            relation,
            nearest_dangerous_site: Some(nearest.site_id.clone()),
            distance_to_dangerous_site: distance.or(Some(1)),
            explanation: Some(format!(
                "static same-function relation inferred in {} relative to site {}",
                panic_fn_hint, nearest.site_id
            )),
            fired_rules: vec!["static-same-function".into()],
            conflicting_evidence: vec![],
        });
    }

    None
}

/// 从图的邻接性推断关系证据
/// 
/// 当无法通过动态轨迹或静态位置确定关系时，利用危险路径图中的函数调用关系
/// 来判断panic函数与危险站点的邻近程度。
/// 
/// # 参数
/// * `trace` - 执行轨迹日志
/// * `dpg` - 危险路径图
/// 
/// # 返回值
/// 返回基于图邻接性分析的关系证据
fn infer_from_graph_adjacency(trace: &TraceLog, dpg: &DangerousPathGraph) -> RelationEvidence {
    // 尝试获取panic发生的函数名称
    if let Some(panic_fn) = infer_panic_function_hint(trace) {
        // 计算该函数到任意危险站点的最短距离
        let distance = dpg.shortest_distance_to_any_dangerous_site(&panic_fn);
        if let Some(d) = distance.distance {
            // 如果距离为1或2，认为函数与危险站点相邻
            if d == 1 || d == 2 {
                return RelationEvidence {
                    relation: RelationLabel::AdjacentToUnsafe,
                    nearest_dangerous_site: distance.nearest_site,
                    distance_to_dangerous_site: Some(d),
                    explanation: Some(format!(
                        "panic function {} is statically adjacent to dangerous site (distance={})",
                        panic_fn, d
                    )),
                    fired_rules: vec!["graph-adjacent".into()],
                    conflicting_evidence: vec![],
                };
            }
        }
    }

    // 默认情况：观察到panic但未找到危险站点证据或unsafe邻接关系
    RelationEvidence {
        relation: RelationLabel::NoneObserved,
        nearest_dangerous_site: None,
        distance_to_dangerous_site: None,
        explanation: Some(
            "panic observed but no dangerous-site evidence or unsafe adjacency was found".into()
        ),
        fired_rules: vec!["fallback-none-observed".into()],
        conflicting_evidence: vec![],
    }
}

/// 推断panic发生的函数名称提示
/// 
/// 通过追踪执行轨迹中的函数进入事件，确定panic发生时当前活跃的函数。
/// 
/// # 参数
/// * `trace` - 执行轨迹日志
/// 
/// # 返回值
/// 如果能够确定panic发生的函数则返回Some(函数名)，否则返回None
fn infer_panic_function_hint(trace: &TraceLog) -> Option<String> {
    // 维护每个线程当前正在执行的函数映射
    let mut current_fn_by_thread: HashMap<String, String> = HashMap::new();

    // 遍历所有轨迹事件，跟踪函数调用栈
    for event in &trace.events {
        match event {
            // 记录函数进入事件，更新当前线程的活跃函数
            TraceEvent::EnterFunction {
                function,
                thread_id,
                ..
            } => {
                current_fn_by_thread.insert(thread_id.clone(), function.clone());
            }
            // 当遇到panic事件时，返回当前线程的活跃函数
            TraceEvent::Panic { thread_id, .. } => {
                if let Some(active) = current_fn_by_thread.get(thread_id) {
                    return Some(active.clone());
                }
            }
            _ => {}
        }
    }
    // 如果未能找到panic对应的函数，返回None
    None
}

/// 查找覆盖指定位置的危險站点
/// 
/// 检查给定的文件和行号是否落在任何危险站点的源代码范围内。
/// 
/// # 参数
/// * `site_map` - 危险站点映射表
/// * `file` - 源文件路径
/// * `line` - 行号
/// 
/// # 返回值
/// 如果找到覆盖该位置的危險站点则返回引用，否则返回None
fn find_dangerous_site_covering<'a>(
    site_map: &'a SiteMap,
    file: &str,
    line: usize,
) -> Option<&'a DangerousSite> {
    // 查找文件路径匹配且行号在站点范围内的危险站点
    site_map.dangerous_sites.iter().find(|site| {
        same_file_path(&site.span.file, file)
            && line >= site.span.line_start
            && line <= site.span.line_end
    })
}

/// 比较两个文件路径是否指向同一个文件
/// 
/// 该函数处理不同平台的路径分隔符差异，并支持相对路径和绝对路径的比较。
/// 
/// # 参数
/// * `a` - 第一个文件路径
/// * `b` - 第二个文件路径
/// 
/// # 返回值
/// 如果两个路径指向同一文件则返回true，否则返回false
fn same_file_path(a: &str, b: &str) -> bool {
    // 统一路径分隔符为正斜杠，然后进行精确匹配或后缀匹配
    let na = a.replace('\\', "/");
    let nb = b.replace('\\', "/");
    na == nb || na.ends_with(&nb) || nb.ends_with(&na)
}

/// 计算给定行号与危险站点跨度之间的行差距
/// 
/// # 参数
/// * `line` - 目标行号
/// * `site` - 危险站点引用
/// 
/// # 返回值
/// 返回行号与站点跨度之间的最小距离，如果行号在站点范围内则返回0
fn line_gap_to_span(line: usize, site: &DangerousSite) -> usize {
    // 根据行号相对于站点跨度的位置计算差距
    if line < site.span.line_start {
        site.span.line_start - line
    } else if line > site.span.line_end {
        line - site.span.line_end
    } else {
        0
    }
}