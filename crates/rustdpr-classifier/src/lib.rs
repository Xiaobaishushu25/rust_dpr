///1. harness 检查
///    如果 harness 是 LikelyMisuse / Invalid，直接 HarnessMisuse。
///    relation 强制设为 NoneObserved。
///
/// 2. oracle 检查
///    如果 Miri / ASAN 已确认 UB，直接 OracleConfirmedBug。
///
/// 3. candidate 构造
///    对每个 dangerous site 计算：
///    - structural relation
///    - dynamic temporal relation
///    - same-function relation
///    - graph adjacency relation
///
/// 4. candidate 排序
///    根据：
///    - relation priority
///    - kind specificity
///    - dynamic hit bonus
///    - temporal gap
///    - line gap
///    - graph distance
///    - actionability
///    选出最佳 candidate。
///
/// 5. primary_label 决策
///    - InsideUnsafe → InsideUnsafePanic
///    - AfterUnsafe + 高 actionability → PanicAfterUnsafe
///    - AfterUnsafe + 低 actionability → SuspiciousCandidate
///    - BeforeUnsafe → BlockingPanic
///    - AdjacentToUnsafe → SuspiciousCandidate
///    - NoneObserved + panic → ContractPanic
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};

use rustdpr_core::{
    ClassificationNotes, ClassificationOptions, ClassificationResult, DangerousCategory,
    DangerousKind, DangerousPathGraph, DangerousSite, EvidenceStrength, HarnessValidityReport,
    OracleEvidenceStrength, OracleVerdict, PrimaryLabel, RUSTDPR_SCHEMA_VERSION, RelationLabel,
    SiteMap, TraceEvent, TraceLog, ValidityStatus,
};

pub fn classify_execution_with_options(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    harness: Option<&HarnessValidityReport>,
    oracle: Option<OracleVerdict>,
    options: ClassificationOptions,
) -> ClassificationResult {
    let harness = if options.use_harness_validity {
        harness
    } else {
        None
    };
    let oracle = if options.use_oracle { oracle } else { None };

    if options.panic_only {
        return classify_panic_only(site_map, trace, harness, oracle);
    }

    if options.static_only {
        return classify_static_only(site_map, trace, dpg, harness, oracle);
    }

    if !options.use_dynamic_trace || !options.use_dpg_adjacency {
        return classify_execution_restricted(site_map, trace, dpg, harness, oracle, &options);
    }

    let harness_status = harness
        .map(|h| h.status.clone())
        .unwrap_or(ValidityStatus::Unknown);
    let oracle_verdict = oracle.unwrap_or(OracleVerdict::Unknown);
    let oracle_evidence_strength = strength_for_oracle(&oracle_verdict);
    let target_api_misuse = harness
        .map(|h| {
            h.evidence
                .iter()
                .any(|e| e.rule.contains("target-api") || e.rule.contains("direct-unsafe"))
        })
        .unwrap_or(false);

    let mut notes = ClassificationNotes::default();
    let reached_dangerous_sites = collect_reached_dangerous_sites(site_map, trace);
    let relation_evidence = infer_relation_evidence(site_map, trace, dpg);

    notes
        .counters
        .insert("trace_events".into(), trace.events.len());
    notes
        .counters
        .insert("function_enter".into(), trace.enter_count());
    notes
        .counters
        .insert("function_exit".into(), trace.exit_count());
    notes
        .counters
        .insert("dangerous_hits".into(), reached_dangerous_sites.len());
    notes
        .counters
        .insert("panic_count".into(), trace.panic_count());
    notes
        .counters
        .insert("dpg_reachability_facts".into(), dpg.reachability.len());

    if let Some(msg) = relation_evidence.explanation.clone() {
        notes.notes.push(msg.clone());
        notes.evidence_summary.push(msg);
    }
    notes
        .fired_rules
        .extend(relation_evidence.fired_rules.clone());
    notes
        .conflicting_evidence
        .extend(relation_evidence.conflicting_evidence.clone());

    if !reached_dangerous_sites.is_empty() {
        notes.evidence_summary.push(format!(
            "reached dangerous sites: {}",
            reached_dangerous_sites.join(", ")
        ));
    }
    notes.evidence_summary.push(format!(
        "oracle evidence strength: {:?}",
        oracle_evidence_strength
    ));

    // Harness 本身不可信时，优先短路。
    // 这里不要再保留 InsideUnsafe / AfterUnsafe 关系，否则会把 harness 误用和目标库缺陷混在一起。
    if harness_status == ValidityStatus::LikelyMisuse || harness_status == ValidityStatus::Invalid {
        notes
            .fired_rules
            .push("harness-misuse-short-circuit".into());
        notes
            .decision_path
            .push(format!("harness_status={:?}", harness_status));
        notes.counters.insert(
            "raw_dangerous_hits_before_harness_filter".into(),
            reached_dangerous_sites.len(),
        );
        return ClassificationResult {
            schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
            case_name: trace.case_name.clone(),
            suite: trace.suite.clone(),
            primary_label: PrimaryLabel::HarnessMisuse,
            relation: RelationLabel::HarnessMisuse,
            // reached_dangerous_sites,
            reached_dangerous_sites: vec![],
            nearest_dangerous_site: None,
            distance_to_dangerous_site: None,
            oracle_verdict,
            oracle_evidence_strength,
            target_api_misuse: true,
            harness_status,
            confidence: 0.95,
            review_required: false,
            notes,
        };
    }

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
            oracle_evidence_strength,
            target_api_misuse,
            harness_status,
            confidence: 0.99,
            review_required: false,
            notes,
        };
    }

    let has_panic = trace.has_panic();
    let has_reached = !reached_dangerous_sites.is_empty();
    let (primary_label, confidence, review_required) = decide_primary_label(
        has_panic,
        has_reached,
        &relation_evidence,
        oracle_evidence_strength.clone(),
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
        oracle_evidence_strength,
        target_api_misuse,
        harness_status,
        confidence,
        review_required,
        notes,
    }
}

fn decide_primary_label(
    has_panic: bool,
    has_reached: bool,
    relation_evidence: &RelationEvidence,
    oracle_strength: OracleEvidenceStrength,
    notes: &mut ClassificationNotes,
) -> (PrimaryLabel, f32, bool) {
    let relation = relation_evidence.relation.clone();
    let actionability = relation_evidence.actionability.unwrap_or(0.0);
    let site_kind = relation_evidence.site_kind.clone();

    notes.decision_path.push(format!(
        "has_panic={has_panic}, has_reached={has_reached}, relation={relation:?}, site_kind={site_kind:?}, actionability={actionability:.2}, oracle_strength={oracle_strength:?}"
    ));

    match (has_panic, has_reached, relation) {
        (false, true, RelationLabel::NoneObserved) => {
            notes.fired_rules.push("dangerous-path-reached".into());
            (PrimaryLabel::DangerousPathReached, 0.88, false)
        }

        (true, _, RelationLabel::InsideUnsafe) => {
            notes.fired_rules.push("inside-unsafe-panic".into());
            (PrimaryLabel::InsideUnsafePanic, 0.92, false)
        }

        (true, _, RelationLabel::AfterUnsafe) => {
            // AfterUnsafe 只是“panic 发生在危险点之后”的关系，不等于一定是强 bug。
            // 是否升级为 PanicAfterUnsafe，取决于候选危险点的可操作性和证据强度。
            if actionability >= 0.72 {
                notes
                    .fired_rules
                    .push("panic-after-actionable-unsafe".into());
                (PrimaryLabel::PanicAfterUnsafe, 0.90, false)
            } else {
                notes
                    .fired_rules
                    .push("after-unsafe-review-worthy-candidate".into());
                notes.evidence_summary.push(format!(
                    "AfterUnsafe relation is present, but the selected site is weak or review-only: kind={site_kind:?}, actionability={actionability:.2}"
                ));
                (PrimaryLabel::SuspiciousCandidate, 0.72, true)
            }
        }

        (true, false, RelationLabel::BeforeUnsafe) => {
            notes.fired_rules.push("blocking-panic".into());
            (PrimaryLabel::BlockingPanic, 0.86, false)
        }

        (true, true, RelationLabel::BeforeUnsafe) => {
            notes.fired_rules.push("conflicting-before-unsafe".into());
            notes.conflicting_evidence.push(
                "dangerous site was hit in trace, but relation was inferred as BeforeUnsafe".into(),
            );
            (PrimaryLabel::SuspiciousCandidate, 0.55, true)
        }

        (true, _, RelationLabel::AdjacentToUnsafe) => {
            notes.fired_rules.push("adjacent-panic".into());
            (PrimaryLabel::SuspiciousCandidate, 0.68, true)
        }

        (true, _, RelationLabel::FfiBoundary) => {
            notes.fired_rules.push("ffi-boundary-panic".into());
            (PrimaryLabel::InsideUnsafePanic, 0.90, false)
        }

        (_, _, RelationLabel::HarnessMisuse) => {
            notes.fired_rules.push("harness-misuse-relation".into());
            (PrimaryLabel::HarnessMisuse, 0.95, false)
        }

        (_, _, RelationLabel::UnsupportedOracle) => {
            notes.fired_rules.push("unsupported-oracle-relation".into());
            (PrimaryLabel::SuspiciousCandidate, 0.50, true)
        }

        (true, _, RelationLabel::NoneObserved) => {
            notes.fired_rules.push("contract-panic".into());
            (PrimaryLabel::ContractPanic, 0.68, true)
        }

        (true, _, RelationLabel::Unknown) => {
            notes.fired_rules.push("unknown-panic".into());
            (PrimaryLabel::Unknown, 0.42, true)
        }

        (false, false, _) => {
            notes.fired_rules.push("noise".into());
            (PrimaryLabel::Noise, 0.40, false)
        }

        (false, true, _) => {
            notes
                .fired_rules
                .push("dangerous-path-reached-fallback".into());
            (PrimaryLabel::DangerousPathReached, 0.75, true)
        }
    }
}

fn strength_for_oracle(verdict: &OracleVerdict) -> OracleEvidenceStrength {
    match verdict {
        OracleVerdict::AddressSanitizerDoubleFree
        | OracleVerdict::AddressSanitizerUseAfterFree
        | OracleVerdict::AddressSanitizerOutOfBounds
        | OracleVerdict::AddressSanitizerInvalidFree
        | OracleVerdict::AddressSanitizerLeak
        | OracleVerdict::MiriUndefinedBehavior => OracleEvidenceStrength::Confirmed,
        OracleVerdict::MiriUnsupported => OracleEvidenceStrength::Unsupported,
        OracleVerdict::OracleTimeout | OracleVerdict::OracleBuildFailure => {
            OracleEvidenceStrength::WeakHeuristic
        }
        OracleVerdict::NoOracleFinding | OracleVerdict::Unknown => OracleEvidenceStrength::Unknown,
    }
}

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

#[derive(Debug, Clone, Default)]
struct RelationEvidence {
    relation: RelationLabel,
    nearest_dangerous_site: Option<String>,
    distance_to_dangerous_site: Option<u32>,
    explanation: Option<String>,
    fired_rules: Vec<String>,
    conflicting_evidence: Vec<String>,

    // 新增：用于 primary_label 决策的结构化证据。
    site_kind: Option<DangerousKind>,
    actionability: Option<f32>,
    candidate_score: Option<f32>,
}

#[derive(Debug, Clone)]
struct PanicLocation {
    event_idx: usize,
    file: Option<String>,
    line: Option<usize>,
}

#[derive(Debug, Clone)]
struct DangerousCandidate<'a> {
    site: &'a DangerousSite,
    relation: RelationLabel,
    hit_idx: Option<usize>,
    temporal_gap: Option<usize>,
    line_gap: Option<usize>,
    graph_distance: Option<u32>,
    actionability: f32,
    score: f32,
    reason: String,
    fired_rule: String,
}

fn collect_reached_dangerous_sites(site_map: &SiteMap, trace: &TraceLog) -> Vec<String> {
    let hit_ids: BTreeSet<&str> = trace.hit_site_ids().into_iter().collect();
    site_map
        .dangerous_sites
        .iter()
        .filter(|site| hit_ids.contains(site.site_id.as_str()))
        .map(|site| site.site_id.clone())
        .collect()
}

/// Collect dangerous-site hits in the actual dynamic trace order.
fn collect_dangerous_hit_events(site_map: &SiteMap, trace: &TraceLog) -> Vec<(usize, String)> {
    let dangerous_ids: BTreeSet<&str> = site_map
        .dangerous_sites
        .iter()
        .map(|site| site.site_id.as_str())
        .collect();

    trace
        .events
        .iter()
        .enumerate()
        .filter_map(|(idx, event)| match event {
            TraceEvent::Hit { site_id, .. } if dangerous_ids.contains(site_id.as_str()) => {
                Some((idx, site_id.clone()))
            }
            _ => None,
        })
        .collect()
}

fn infer_relation_evidence(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
) -> RelationEvidence {
    let dangerous_hits = collect_dangerous_hit_events(site_map, trace);
    let panic = first_panic_location(trace);

    // 没有 panic 但 hit 了 dangerous site：说明路径到达了危险点，但没有 panic 关系。
    if panic.is_none() && !dangerous_hits.is_empty() {
        return RelationEvidence {
            relation: RelationLabel::NoneObserved,
            nearest_dangerous_site: dangerous_hits.first().map(|(_, site_id)| site_id.clone()),
            distance_to_dangerous_site: Some(0),
            explanation: Some("dangerous site reached without panic".into()),
            fired_rules: vec!["none-observed".into()],
            conflicting_evidence: vec![],
            site_kind: dangerous_hits
                .first()
                .and_then(|(_, id)| find_dangerous_site_by_id(site_map, id))
                .map(|s| s.kind.clone()),
            actionability: dangerous_hits
                .first()
                .and_then(|(_, id)| find_dangerous_site_by_id(site_map, id))
                .map(dangerous_actionability),
            candidate_score: None,
        };
    }

    let Some(panic) = panic else {
        return RelationEvidence {
            relation: RelationLabel::NoneObserved,
            nearest_dangerous_site: None,
            distance_to_dangerous_site: None,
            explanation: Some("no panic and no dangerous-site evidence was observed".into()),
            fired_rules: vec!["fallback-none-observed".into()],
            conflicting_evidence: vec![],
            site_kind: None,
            actionability: None,
            candidate_score: None,
        };
    };

    let candidates = build_relation_candidates(site_map, trace, dpg, &dangerous_hits, &panic);
    if let Some(best) = select_best_candidate(&candidates) {
        let mut explanation = format!(
            "selected dangerous candidate {} as {:?}: {}; score={:.2}, actionability={:.2}",
            best.site.site_id, best.relation, best.reason, best.score, best.actionability
        );

        if let Some(gap) = best.temporal_gap {
            explanation.push_str(&format!(", temporal_gap={gap}"));
        }
        if let Some(gap) = best.line_gap {
            explanation.push_str(&format!(", line_gap={gap}"));
        }
        if let Some(d) = best.graph_distance {
            explanation.push_str(&format!(", graph_distance={d}"));
        }

        return RelationEvidence {
            relation: best.relation.clone(),
            nearest_dangerous_site: Some(best.site.site_id.clone()),
            distance_to_dangerous_site: relation_distance(best),
            explanation: Some(explanation),
            fired_rules: vec![best.fired_rule.clone(), "candidate-ranking".into()],
            conflicting_evidence: collect_candidate_conflicts(best, &candidates),
            site_kind: Some(best.site.kind.clone()),
            actionability: Some(best.actionability),
            candidate_score: Some(best.score),
        };
    }

    // infer_from_graph_adjacency(trace, dpg)
    infer_from_graph_adjacency(site_map, trace, dpg, &panic)
}

fn first_panic_location(trace: &TraceLog) -> Option<PanicLocation> {
    trace
        .events
        .iter()
        .enumerate()
        .find_map(|(idx, event)| match event {
            TraceEvent::Panic { file, line, .. } => Some(PanicLocation {
                event_idx: idx,
                file: file.clone(),
                line: line.map(|v| v as usize),
            }),
            _ => None,
        })
}

fn build_relation_candidates<'a>(
    site_map: &'a SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    dangerous_hits: &[(usize, String)],
    panic: &PanicLocation,
) -> Vec<DangerousCandidate<'a>> {
    let panic_fn_hint = infer_panic_function_hint(trace);
    let graph_nearest = panic_fn_hint
        .as_ref()
        .map(|f| dpg.shortest_distance_to_any_dangerous_site(f));
    let mut candidates = Vec::new();

    for site in &site_map.dangerous_sites {
        let hit_idx = nearest_hit_for_site(dangerous_hits, &site.site_id, panic.event_idx);
        let dynamic_relation = hit_idx.map(|idx| {
            if idx < panic.event_idx {
                RelationLabel::AfterUnsafe
            } else if idx > panic.event_idx {
                RelationLabel::BeforeUnsafe
            } else {
                RelationLabel::InsideUnsafe
            }
        });

        let structural_relation = structural_relation_to_panic(site, panic);
        let same_fn_relation = same_function_relation(site, panic, panic_fn_hint.as_deref());
        let graph_relation = graph_nearest.as_ref().and_then(|nearest| {
            if nearest.distance.is_some_and(|d| d <= 2)
                && nearest
                    .nearest_site
                    .as_ref()
                    .map(|id| same_site_id(id, &site.site_id))
                    .unwrap_or(false)
            {
                Some(RelationLabel::AdjacentToUnsafe)
            } else {
                None
            }
        });

        let ffi_relation =
            if is_ffi_boundary_site(site) && hit_idx.is_some() {
                Some(RelationLabel::FfiBoundary)
            } else {
                None
            };

        // 关系优先级不是简单 “dynamic > static”。
        // 1. panic 落在具体危险操作 span 内时，优先 InsideUnsafe；
        // 2. 如果 panic 落在 unsafe block 容器内，但同函数中存在更具体的危险操作，后续 scoring 会选择更具体的 operation candidate；
        // 3. dynamic hit 用于确认路径真的到达 unsafe 区域，但不强行覆盖源码结构关系。
        let (relation, fired_rule, reason) = if let Some(rel) = ffi_relation {
            (
                rel,
                "ffi-boundary-candidate".to_string(),
                "dangerous-site hit occurs at an FFI boundary before the panic".to_string(),
            )
        }else if let Some(rel) = structural_relation {
            (
                rel,
                "static-structural-candidate".to_string(),
                "panic location is structurally related to the dangerous site span".to_string(),
            )
        } else if let Some(rel) = dynamic_relation {
            (
                rel,
                "dynamic-temporal-candidate".to_string(),
                "dynamic trace orders dangerous-site hit relative to panic".to_string(),
            )
        } else if let Some(rel) = same_fn_relation {
            (
                rel,
                "static-same-function-candidate".to_string(),
                "panic and dangerous site are in the same function".to_string(),
            )
        } else if let Some(rel) = graph_relation {
            (
                rel,
                "graph-adjacent-candidate".to_string(),
                "panic function is close to a dangerous site in DPG".to_string(),
            )
        } else {
            continue;
        };

        let temporal_gap = hit_idx.map(|idx| idx.abs_diff(panic.event_idx));
        let line_gap = panic.line.map(|line| line_gap_to_span(line, site));
        let graph_distance = graph_nearest.as_ref().and_then(|nearest| {
            if nearest
                .nearest_site
                .as_ref()
                .map(|id| same_site_id(id, &site.site_id))
                .unwrap_or(false)
            {
                nearest.distance
            } else {
                None
            }
        });
        let actionability = dangerous_actionability(site);
        let score = candidate_score(
            site,
            &relation,
            hit_idx,
            temporal_gap,
            line_gap,
            graph_distance,
            actionability,
        );

        candidates.push(DangerousCandidate {
            site,
            relation,
            hit_idx,
            temporal_gap,
            line_gap,
            graph_distance,
            actionability,
            score,
            reason,
            fired_rule,
        });
    }

    candidates
}

fn select_best_candidate<'a, 'b>(
    candidates: &'b [DangerousCandidate<'a>],
) -> Option<&'b DangerousCandidate<'a>> {
    candidates.iter().max_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| compare_relation_priority(&a.relation, &b.relation))
            .then_with(|| compare_specificity(a.site, b.site))
    })
}

fn compare_relation_priority(a: &RelationLabel, b: &RelationLabel) -> Ordering {
    relation_priority(a).cmp(&relation_priority(b))
}

fn relation_priority(relation: &RelationLabel) -> i32 {
    match relation {
        RelationLabel::InsideUnsafe => 5,
        RelationLabel::AfterUnsafe => 4,
        RelationLabel::BeforeUnsafe => 3,
        RelationLabel::AdjacentToUnsafe => 2,
        RelationLabel::FfiBoundary => 2,
        RelationLabel::HarnessMisuse => 2,
        RelationLabel::UnsupportedOracle => 1,
        RelationLabel::NoneObserved => 1,
        RelationLabel::Unknown => 0,
    }
}

fn compare_specificity(a: &DangerousSite, b: &DangerousSite) -> Ordering {
    kind_specificity(a).total_cmp(&kind_specificity(b))
}

fn nearest_hit_for_site(
    dangerous_hits: &[(usize, String)],
    site_id: &str,
    panic_idx: usize,
) -> Option<usize> {
    // 优先选择 panic 前最近的 hit；如果没有，再选择 panic 后最近的 hit。
    // 这使 AfterUnsafe 的 nearest site 表示“离 panic 最近的前序危险点”。
    dangerous_hits
        .iter()
        .filter(|(idx, id)| id == site_id && *idx < panic_idx)
        .map(|(idx, _)| *idx)
        .max()
        .or_else(|| {
            dangerous_hits
                .iter()
                .filter(|(idx, id)| id == site_id && *idx > panic_idx)
                .map(|(idx, _)| *idx)
                .min()
        })
}

fn structural_relation_to_panic(
    site: &DangerousSite,
    panic: &PanicLocation,
) -> Option<RelationLabel> {
    let (Some(file), Some(line)) = (panic.file.as_deref(), panic.line) else {
        return None;
    };

    if same_file_path(&site.span.file, file)
        && line >= site.span.line_start
        && line <= site.span.line_end
    {
        return Some(RelationLabel::InsideUnsafe);
    }

    None
}

fn same_function_relation(
    site: &DangerousSite,
    panic: &PanicLocation,
    panic_fn_hint: Option<&str>,
) -> Option<RelationLabel> {
    let Some(panic_fn_hint) = panic_fn_hint else {
        return None;
    };
    let Some(line) = panic.line else {
        return None;
    };

    if site.enclosing_fn != panic_fn_hint {
        return None;
    }

    if line < site.span.line_start {
        Some(RelationLabel::BeforeUnsafe)
    } else if line > site.span.line_end {
        Some(RelationLabel::AfterUnsafe)
    } else {
        Some(RelationLabel::InsideUnsafe)
    }
}

fn relation_distance(candidate: &DangerousCandidate<'_>) -> Option<u32> {
    if candidate.hit_idx.is_some() || candidate.relation == RelationLabel::InsideUnsafe {
        Some(0)
    } else {
        candidate.graph_distance.or(Some(1))
    }
}

fn collect_candidate_conflicts(
    best: &DangerousCandidate<'_>,
    candidates: &[DangerousCandidate<'_>],
) -> Vec<String> {
    let mut conflicts = Vec::new();

    if best.relation == RelationLabel::AfterUnsafe
        && candidates.iter().any(|c| {
            c.site.site_id != best.site.site_id
                && c.relation == RelationLabel::InsideUnsafe
                && is_container_site(c.site)
        })
    {
        conflicts.push(
            "an unsafe container also covers the panic, but a more specific dangerous operation was selected".into(),
        );
    }

    conflicts
}

fn candidate_score(
    site: &DangerousSite,
    relation: &RelationLabel,
    hit_idx: Option<usize>,
    temporal_gap: Option<usize>,
    line_gap: Option<usize>,
    graph_distance: Option<u32>,
    actionability: f32,
) -> f32 {
    let relation_score = match relation {
        RelationLabel::InsideUnsafe => 100.0,
        RelationLabel::AfterUnsafe => 82.0,
        RelationLabel::BeforeUnsafe => 62.0,
        RelationLabel::AdjacentToUnsafe => 35.0,
        RelationLabel::FfiBoundary => 35.0,
        RelationLabel::HarnessMisuse => 30.0,
        RelationLabel::UnsupportedOracle => 15.0,
        RelationLabel::NoneObserved => 10.0,
        RelationLabel::Unknown => 0.0,
    };

    let specificity_score = kind_specificity(site);
    let dynamic_bonus = if hit_idx.is_some() { 8.0 } else { 0.0 };
    let temporal_bonus = temporal_gap
        .map(|gap| 8.0 / (gap as f32 + 1.0))
        .unwrap_or(0.0);
    let line_bonus = line_gap.map(|gap| 6.0 / (gap as f32 + 1.0)).unwrap_or(0.0);
    let graph_bonus = graph_distance
        .map(|d| 4.0 / (d as f32 + 1.0))
        .unwrap_or(0.0);

    relation_score
        + specificity_score
        + dynamic_bonus
        + temporal_bonus
        + line_bonus
        + graph_bonus
        + actionability * 10.0
}

fn kind_specificity(site: &DangerousSite) -> f32 {
    match site.kind {
        DangerousKind::UnsafeFn | DangerousKind::UnsafeBlock | DangerousKind::UnsafeTraitImpl => {
            -22.0
        }
        DangerousKind::TargetApiMisuseCandidate => -15.0,
        DangerousKind::FfiDeclaration | DangerousKind::FfiBoundary => -5.0,
        DangerousKind::MaybeUninitCandidate | DangerousKind::AssumeInitCandidate => 30.0,
        DangerousKind::IndexingCandidate => 8.0,
        _ => 28.0,
    }
}

fn dangerous_actionability(site: &DangerousSite) -> f32 {
    let kind_score = match site.kind {
        DangerousKind::RawDerefCandidate
        | DangerousKind::PtrReadCandidate
        | DangerousKind::PtrWriteCandidate
        | DangerousKind::CopyNonOverlappingCandidate
        | DangerousKind::FromRawParts
        | DangerousKind::VecFromRawParts
        | DangerousKind::BoxFromRaw
        | DangerousKind::ManualFreeCandidate
        | DangerousKind::Transmute
        | DangerousKind::TransmuteCopy => 0.95,

        DangerousKind::SetLenCandidate
        | DangerousKind::ManualAllocCandidate
        | DangerousKind::BoxIntoRaw
        | DangerousKind::NonNullNewUnchecked
        | DangerousKind::ManuallyDropCandidate
        | DangerousKind::DropSensitiveCandidate => 0.82,

        // 初始化类候选经常需要 oracle 或人工复核确认，不直接升级为强 PanicAfterUnsafe。
        DangerousKind::AssumeInitCandidate => 0.62,
        DangerousKind::MaybeUninitCandidate => 0.55,

        DangerousKind::FfiCallCandidate
        | DangerousKind::FfiUnwindBoundary
        | DangerousKind::FfiBoundary => 0.84,
        DangerousKind::FfiDeclaration => 0.55,

        DangerousKind::UnsafeBlock | DangerousKind::UnsafeFn | DangerousKind::UnsafeTraitImpl => {
            0.50
        }
        DangerousKind::TargetApiMisuseCandidate => 0.30,
        DangerousKind::RawAddrCandidate => 0.40,
        DangerousKind::MemForget => 0.58,
        DangerousKind::IndexingCandidate => 0.25,
    };

    let category = if site.category == DangerousCategory::Unknown {
        site.kind.category()
    } else {
        site.category.clone()
    };
    let category_score = match category {
        DangerousCategory::RawPointer => 0.95,
        DangerousCategory::AllocationOwnership => 0.90,
        DangerousCategory::TypePunning => 0.88,
        DangerousCategory::DropInvariant => 0.80,
        DangerousCategory::Initialization => 0.55,
        DangerousCategory::Ffi => 0.78,
        DangerousCategory::UnsafeRust => 0.50,
        DangerousCategory::RuntimeCheck => 0.25,
        DangerousCategory::PanicBoundary => 0.35,
        DangerousCategory::Unknown => 0.40,
    };

    let strength_score = match &site.evidence_strength {
        EvidenceStrength::Confirmed => 1.0,
        EvidenceStrength::Strong => 0.88,
        EvidenceStrength::Medium => 0.72,
        EvidenceStrength::Weak => 0.55,
        EvidenceStrength::Heuristic => 0.48,
        EvidenceStrength::Unsupported => 0.25,
    };

    // kind 是最核心的语义，category 和 evidence strength 用来平滑。
    kind_score * 0.55 + category_score * 0.25 + strength_score * 0.20
}

fn is_container_site(site: &DangerousSite) -> bool {
    matches!(
        site.kind,
        DangerousKind::UnsafeFn | DangerousKind::UnsafeBlock | DangerousKind::UnsafeTraitImpl
    )
}

fn find_dangerous_site_by_id<'a>(
    site_map: &'a SiteMap,
    site_id: &str,
) -> Option<&'a DangerousSite> {
    site_map
        .dangerous_sites
        .iter()
        .find(|site| same_site_id(&site.site_id, site_id))
}

fn same_site_id(a: &str, b: &str) -> bool {
    a == b || a.ends_with(b) || b.ends_with(a)
}

fn infer_from_graph_adjacency(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    panic: &PanicLocation,
) -> RelationEvidence {
    let mut panic_functions = Vec::new();

    if let Some(panic_fn) = infer_panic_function_hint(trace) {
        panic_functions.push(panic_fn);
    }

    for ps in &site_map.panic_sites {
        let line_matches = panic
            .line
            .map(|line| line >= ps.span.line_start && line <= ps.span.line_end)
            .unwrap_or(false);

        let file_matches = match (&panic.file, ps.span.file.as_str()) {
            (Some(runtime_file), static_file) => same_file_path(runtime_file, static_file),
            _ => true,
        };

        if line_matches && file_matches {
            panic_functions.push(ps.enclosing_fn.clone());
        }
    }

    panic_functions.sort();
    panic_functions.dedup();

    for panic_fn in panic_functions {
        let distance = dpg.shortest_distance_to_any_dangerous_site(&panic_fn);
        if let Some(d) = distance.distance {
            if d <= 2 {
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
                    site_kind: None,
                    actionability: None,
                    candidate_score: None,
                };
            }
        }
    }

    RelationEvidence {
        relation: RelationLabel::NoneObserved,
        nearest_dangerous_site: None,
        distance_to_dangerous_site: None,
        explanation: Some(
            "panic observed but no dangerous-site evidence or unsafe adjacency was found".into(),
        ),
        fired_rules: vec!["fallback-none-observed".into()],
        conflicting_evidence: vec![],
        site_kind: None,
        actionability: None,
        candidate_score: None,
    }
}

/// 从执行轨迹中推断发生 panic 的函数名
///
/// 通过跟踪函数调用栈来确定 panic 发生时正在执行的函数。
/// 遍历轨迹事件，维护每个线程的函数调用栈，在遇到 Panic 事件时返回当前栈顶的函数。
///
/// # 参数
///
/// * `trace` - 执行轨迹日志，包含函数进入、退出和 panic 等事件
///
/// # 返回值
///
/// 返回 panic 发生时正在执行的函数名，如果无法确定则返回 None
fn infer_panic_function_hint(trace: &TraceLog) -> Option<String> {
    let mut stack_by_thread: HashMap<String, Vec<String>> = HashMap::new();
    for event in &trace.events {
        match event {
            TraceEvent::EnterFunction {
                function,
                thread_id,
                ..
            } => {
                stack_by_thread
                    .entry(thread_id.clone())
                    .or_default()
                    .push(function.clone());
            }
            TraceEvent::ExitFunction {
                function,
                thread_id,
                ..
            } => {
                if let Some(stack) = stack_by_thread.get_mut(thread_id) {
                    if stack.last().map(|s| s.as_str()) == Some(function.as_str()) {
                        stack.pop();
                    } else if let Some(pos) = stack.iter().rposition(|s| s == function) {
                        stack.truncate(pos);
                    }
                }
            }
            TraceEvent::Panic { thread_id, .. } => {
                if let Some(stack) = stack_by_thread.get(thread_id) {
                    if let Some(active) = stack.last() {
                        return Some(active.clone());
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn same_file_path(a: &str, b: &str) -> bool {
    let na = a.replace('\\', "/");
    let nb = b.replace('\\', "/");
    na == nb || na.ends_with(&nb) || nb.ends_with(&na)
}

fn line_gap_to_span(line: usize, site: &DangerousSite) -> usize {
    if line < site.span.line_start {
        site.span.line_start - line
    } else if line > site.span.line_end {
        line - site.span.line_end
    } else {
        0
    }
}


fn is_ffi_boundary_site(site: &DangerousSite) -> bool {
    matches!(
        site.kind,
        DangerousKind::FfiBoundary
            | DangerousKind::FfiUnwindBoundary
            | DangerousKind::FfiCallCandidate
            | DangerousKind::FfiDeclaration
    )
}

pub fn classify_execution(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    harness: Option<&HarnessValidityReport>,
    oracle: Option<OracleVerdict>,
) -> ClassificationResult {
    classify_execution_with_options(
        site_map,
        trace,
        dpg,
        harness,
        oracle,
        ClassificationOptions::default(),
    )
}

fn classify_panic_only(
    _site_map: &SiteMap,
    trace: &TraceLog,
    harness: Option<&HarnessValidityReport>,
    oracle: Option<OracleVerdict>,
) -> ClassificationResult {
    let oracle = oracle.unwrap_or(OracleVerdict::Unknown);
    let harness_status = harness
        .map(|h| h.status.clone())
        .unwrap_or(ValidityStatus::Unknown);
    let mut notes = ClassificationNotes::default();
    notes.fired_rules.push("panic-only-baseline".into());

    let primary_label = if trace.has_panic() {
        PrimaryLabel::SuspiciousCandidate
    } else {
        PrimaryLabel::Noise
    };

    ClassificationResult {
        schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
        case_name: trace.case_name.clone(),
        suite: trace.suite.clone(),
        primary_label,
        relation: RelationLabel::Unknown,
        reached_dangerous_sites: vec![],
        nearest_dangerous_site: None,
        distance_to_dangerous_site: None,
        oracle_verdict: oracle.clone(),
        oracle_evidence_strength: strength_for_oracle(&oracle),
        target_api_misuse: false,
        harness_status,
        confidence: 0.50,
        review_required: trace.has_panic(),
        notes,
    }
}

fn classify_static_only(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    harness: Option<&HarnessValidityReport>,
    oracle: Option<OracleVerdict>,
) -> ClassificationResult {
    let oracle = oracle.unwrap_or(OracleVerdict::Unknown);
    let harness_status = harness
        .map(|h| h.status.clone())
        .unwrap_or(ValidityStatus::Unknown);
    let mut notes = ClassificationNotes::default();
    notes.fired_rules.push("static-only-baseline".into());
    notes.counters.insert(
        "static_dangerous_sites".into(),
        site_map.dangerous_sites.len(),
    );
    notes
        .counters
        .insert("static_panic_sites".into(), site_map.panic_sites.len());
    notes
        .counters
        .insert("dpg_reachability_facts".into(), dpg.reachability.len());

    let has_static_risk = !site_map.dangerous_sites.is_empty();
    ClassificationResult {
        schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
        case_name: trace.case_name.clone(),
        suite: trace.suite.clone(),
        primary_label: if has_static_risk {
            PrimaryLabel::SuspiciousCandidate
        } else {
            PrimaryLabel::Noise
        },
        relation: RelationLabel::Unknown,
        reached_dangerous_sites: vec![],
        nearest_dangerous_site: site_map.dangerous_sites.first().map(|s| s.site_id.clone()),
        distance_to_dangerous_site: None,
        oracle_verdict: oracle.clone(),
        oracle_evidence_strength: strength_for_oracle(&oracle),
        target_api_misuse: false,
        harness_status,
        confidence: if has_static_risk { 0.45 } else { 0.30 },
        review_required: has_static_risk,
        notes,
    }
}

fn classify_execution_restricted(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    harness: Option<&HarnessValidityReport>,
    oracle: Option<OracleVerdict>,
    options: &ClassificationOptions,
) -> ClassificationResult {
    if options.use_dynamic_trace && !options.use_dpg_adjacency {
        let empty_dpg = DangerousPathGraph::default();
        return classify_execution(site_map, trace, &empty_dpg, harness, oracle);
    }

    if !options.use_dynamic_trace {
        let mut trace_without_hits = trace.clone();
        trace_without_hits
            .events
            .retain(|event| !matches!(event, TraceEvent::Hit { .. }));
        return classify_execution(site_map, &trace_without_hits, dpg, harness, oracle);
    }

    classify_execution(site_map, trace, dpg, harness, oracle)
}
