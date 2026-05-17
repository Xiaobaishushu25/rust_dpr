use std::collections::{BTreeSet, HashMap};

use rustdpr_core::{
    ClassificationNotes, ClassificationResult, DangerousPathGraph, DangerousSite,
    HarnessValidityReport, OracleEvidenceStrength, OracleVerdict, PrimaryLabel, RelationLabel,
    SiteMap, TraceEvent, TraceLog, ValidityStatus, RUSTDPR_SCHEMA_VERSION,
};

pub fn classify_execution(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    harness: Option<&HarnessValidityReport>,
    oracle: Option<OracleVerdict>,
) -> ClassificationResult {
    let harness_status = harness.map(|h| h.status.clone()).unwrap_or(ValidityStatus::Unknown);
    let oracle_verdict = oracle.unwrap_or(OracleVerdict::Unknown);
    let oracle_evidence_strength = strength_for_oracle(&oracle_verdict);
    let target_api_misuse = harness
        .map(|h| h.evidence.iter().any(|e| e.rule.contains("target-api") || e.rule.contains("direct-unsafe")))
        .unwrap_or(false);

    let mut notes = ClassificationNotes::default();
    let reached_dangerous_sites = collect_reached_dangerous_sites(site_map, trace);
    let relation_evidence = infer_relation_evidence(site_map, trace, dpg, &reached_dangerous_sites);

    notes.counters.insert("trace_events".into(), trace.events.len());
    notes.counters.insert("function_enter".into(), trace.enter_count());
    notes.counters.insert("function_exit".into(), trace.exit_count());
    notes.counters.insert("dangerous_hits".into(), reached_dangerous_sites.len());
    notes.counters.insert("panic_count".into(), trace.panic_count());
    notes.counters.insert("dpg_reachability_facts".into(), dpg.reachability.len());

    if let Some(msg) = relation_evidence.explanation.clone() {
        notes.notes.push(msg.clone());
        notes.evidence_summary.push(msg);
    }
    notes.fired_rules.extend(relation_evidence.fired_rules.clone());
    notes.conflicting_evidence.extend(relation_evidence.conflicting_evidence.clone());

    if !reached_dangerous_sites.is_empty() {
        notes.evidence_summary.push(format!("reached dangerous sites: {}", reached_dangerous_sites.join(", ")));
    }
    notes.evidence_summary.push(format!("oracle evidence strength: {:?}", oracle_evidence_strength));

    if harness_status == ValidityStatus::LikelyMisuse || harness_status == ValidityStatus::Invalid {
        notes.fired_rules.push("harness-misuse-short-circuit".into());
        notes.decision_path.push(format!("harness_status={:?}", harness_status));
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
        notes.decision_path.push(format!("oracle_verdict={:?}", oracle_verdict));
        notes.evidence_summary.push(format!("oracle confirmed: {:?}", oracle_verdict));
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
        relation_evidence.relation.clone(),
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
    relation: RelationLabel,
    oracle_strength: OracleEvidenceStrength,
    notes: &mut ClassificationNotes,
) -> (PrimaryLabel, f32, bool) {
    notes.decision_path.push(format!(
        "has_panic={has_panic}, has_reached={has_reached}, relation={relation:?}, oracle_strength={oracle_strength:?}"
    ));

    match (has_panic, has_reached, relation) {
        (false, true, RelationLabel::NoneObserved) => {
            notes.fired_rules.push("dangerous-path-reached".into());
            (PrimaryLabel::DangerousPathReached, 0.88, false)
        }
        (true, true, RelationLabel::AfterUnsafe) => {
            notes.fired_rules.push("panic-after-unsafe".into());
            (PrimaryLabel::PanicAfterUnsafe, 0.93, false)
        }
        (true, _, RelationLabel::InsideUnsafe) => {
            notes.fired_rules.push("inside-unsafe-panic".into());
            (PrimaryLabel::InsideUnsafePanic, 0.92, false)
        }
        (true, false, RelationLabel::BeforeUnsafe) => {
            notes.fired_rules.push("blocking-panic".into());
            (PrimaryLabel::BlockingPanic, 0.86, false)
        }
        (true, false, RelationLabel::AdjacentToUnsafe) => {
            notes.fired_rules.push("adjacent-panic".into());
            (PrimaryLabel::SuspiciousCandidate, 0.72, true)
        }
        (true, true, RelationLabel::AdjacentToUnsafe) => {
            notes.fired_rules.push("ambiguous-adjacent".into());
            (PrimaryLabel::SuspiciousCandidate, 0.61, true)
        }
        (true, _, RelationLabel::FfiBoundary) => {
            notes.fired_rules.push("ffi-boundary".into());
            (PrimaryLabel::SuspiciousCandidate, 0.68, true)
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
            notes.fired_rules.push("dangerous-path-reached-fallback".into());
            (PrimaryLabel::DangerousPathReached, 0.75, true)
        }
        (true, true, RelationLabel::BeforeUnsafe) => {
            notes.fired_rules.push("conflicting-before-unsafe".into());
            notes.conflicting_evidence.push(
                "dangerous site was hit in trace, but relation was inferred as BeforeUnsafe".into(),
            );
            (PrimaryLabel::SuspiciousCandidate, 0.55, true)
        }
        (true, false, RelationLabel::AfterUnsafe) => {
            notes.fired_rules.push("static-after-unsafe-without-hit".into());
            (PrimaryLabel::SuspiciousCandidate, 0.63, true)
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
        OracleVerdict::OracleTimeout => OracleEvidenceStrength::WeakHeuristic,
        OracleVerdict::Unknown => OracleEvidenceStrength::Unknown,
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

fn infer_relation_evidence(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    reached_dangerous_sites: &[String],
) -> RelationEvidence {
    let first_hit_idx = trace.events.iter().position(|e| matches!(e, TraceEvent::Hit { .. }));
    let first_panic_idx = trace.events.iter().position(|e| matches!(e, TraceEvent::Panic { .. }));

    match (first_hit_idx, first_panic_idx) {
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

    if let Some(ev) = infer_from_static_panic_location(site_map, trace, dpg) {
        return ev;
    }

    infer_from_graph_adjacency(trace, dpg)
}

fn infer_from_static_panic_location(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
) -> Option<RelationEvidence> {
    let panic = trace.first_panic()?;
    let (panic_file, panic_line) = match panic {
        TraceEvent::Panic { file: Some(file), line: Some(line), .. } => (file.as_str(), *line as usize),
        _ => return None,
    };

    if let Some(site) = find_dangerous_site_covering(site_map, panic_file, panic_line) {
        return Some(RelationEvidence {
            relation: RelationLabel::InsideUnsafe,
            nearest_dangerous_site: Some(site.site_id.clone()),
            distance_to_dangerous_site: Some(0),
            explanation: Some(format!("panic location {}:{} falls inside dangerous site {}", panic_file, panic_line, site.site_id)),
            fired_rules: vec!["static-inside-unsafe".into()],
            conflicting_evidence: vec![],
        });
    }

    let panic_fn_hint = infer_panic_function_hint(trace)?;
    let same_fn_candidates: Vec<&DangerousSite> = site_map
        .dangerous_sites
        .iter()
        .filter(|s| s.enclosing_fn == panic_fn_hint)
        .collect();

    if !same_fn_candidates.is_empty() {
        let nearest = same_fn_candidates.iter().min_by_key(|s| line_gap_to_span(panic_line, s)).copied().unwrap();
        let relation = if panic_line < nearest.span.line_start {
            RelationLabel::BeforeUnsafe
        } else if panic_line > nearest.span.line_end {
            RelationLabel::AfterUnsafe
        } else {
            RelationLabel::InsideUnsafe
        };
        let distance = dpg.shortest_distance_to_any_dangerous_site(&panic_fn_hint).distance;
        return Some(RelationEvidence {
            relation,
            nearest_dangerous_site: Some(nearest.site_id.clone()),
            distance_to_dangerous_site: distance.or(Some(1)),
            explanation: Some(format!("static same-function relation inferred in {} relative to site {}", panic_fn_hint, nearest.site_id)),
            fired_rules: vec!["static-same-function".into()],
            conflicting_evidence: vec![],
        });
    }

    None
}

fn infer_from_graph_adjacency(trace: &TraceLog, dpg: &DangerousPathGraph) -> RelationEvidence {
    if let Some(panic_fn) = infer_panic_function_hint(trace) {
        let distance = dpg.shortest_distance_to_any_dangerous_site(&panic_fn);
        if let Some(d) = distance.distance {
            if d <= 2 {
                return RelationEvidence {
                    relation: RelationLabel::AdjacentToUnsafe,
                    nearest_dangerous_site: distance.nearest_site,
                    distance_to_dangerous_site: Some(d),
                    explanation: Some(format!("panic function {} is statically adjacent to dangerous site (distance={})", panic_fn, d)),
                    fired_rules: vec!["graph-adjacent".into()],
                    conflicting_evidence: vec![],
                };
            }
        }
    }

    RelationEvidence {
        relation: RelationLabel::NoneObserved,
        nearest_dangerous_site: None,
        distance_to_dangerous_site: None,
        explanation: Some("panic observed but no dangerous-site evidence or unsafe adjacency was found".into()),
        fired_rules: vec!["fallback-none-observed".into()],
        conflicting_evidence: vec![],
    }
}

fn infer_panic_function_hint(trace: &TraceLog) -> Option<String> {
    let mut stack_by_thread: HashMap<String, Vec<String>> = HashMap::new();
    for event in &trace.events {
        match event {
            TraceEvent::EnterFunction { function, thread_id, .. } => {
                stack_by_thread.entry(thread_id.clone()).or_default().push(function.clone());
            }
            TraceEvent::ExitFunction { function, thread_id, .. } => {
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

fn find_dangerous_site_covering<'a>(site_map: &'a SiteMap, file: &str, line: usize) -> Option<&'a DangerousSite> {
    site_map.dangerous_sites.iter().find(|site| {
        same_file_path(&site.span.file, file) && line >= site.span.line_start && line <= site.span.line_end
    })
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
