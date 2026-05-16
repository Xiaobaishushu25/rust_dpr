use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use rustdpr_core::{
    ClassificationNotes, ClassificationResult, DangerousPathGraph, DangerousSite,
    HarnessValidityReport, OracleVerdict, PrimaryLabel, RelationLabel, SiteMap, TraceEvent,
    TraceLog, ValidityStatus,
};

pub fn classify_execution(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    harness: Option<&HarnessValidityReport>,
    oracle: Option<OracleVerdict>,
) -> ClassificationResult {
    let harness_status = harness
        .map(|h| h.status.clone())
        .unwrap_or(ValidityStatus::Unknown);
    let oracle_verdict = oracle.unwrap_or(OracleVerdict::Unknown);

    let mut notes = ClassificationNotes::default();

    let reached_dangerous_sites = collect_reached_dangerous_sites(site_map, trace);
    if !reached_dangerous_sites.is_empty() {
        notes
            .counters
            .insert("reached_dangerous_sites".into(), reached_dangerous_sites.len());
        notes.notes.push(format!(
            "Reached dangerous sites: {}",
            reached_dangerous_sites.join(", ")
        ));
    }

    let relation_evidence = infer_relation_evidence(site_map, trace, dpg, &reached_dangerous_sites);
    if let Some(msg) = &relation_evidence.explanation {
        notes.notes.push(msg.clone());
    }
    notes.fired_rules.extend(relation_evidence.fired_rules.clone());
    notes
        .conflicting_evidence
        .extend(relation_evidence.conflicting_evidence.clone());

    if harness_status == ValidityStatus::LikelyMisuse {
        notes.fired_rules.push("harness-misuse".into());
        notes.notes.push(
            "Harness validity heuristics suggest likely misuse; classification is short-circuited."
                .into(),
        );
        return ClassificationResult {
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

    if is_oracle_confirmed(&oracle_verdict) {
        notes.fired_rules.push("oracle-confirmed".into());
        notes.notes.push(format!("Oracle confirmed bug: {:?}", oracle_verdict));
        return ClassificationResult {
            primary_label: PrimaryLabel::OracleConfirmedBug,
            relation: relation_evidence.relation,
            reached_dangerous_sites,
            nearest_dangerous_site: relation_evidence.nearest_dangerous_site,
            distance_to_dangerous_site: relation_evidence.distance_to_dangerous_site.or(Some(0u32)),
            oracle_verdict,
            harness_status,
            confidence: 0.99,
            review_required: false,
            notes,
        };
    }

    let has_panic = trace.has_panic();
    let has_reached = !reached_dangerous_sites.is_empty();
    let relation = relation_evidence.relation.clone();

    let (primary_label, confidence, review_required) =
        decide_primary_label(has_panic, has_reached, relation.clone(), &mut notes);

    ClassificationResult {
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

fn decide_primary_label(
    has_panic: bool,
    has_reached: bool,
    relation: RelationLabel,
    notes: &mut ClassificationNotes,
) -> (PrimaryLabel, f32, bool) {
    match (has_panic, has_reached, relation) {
        (false, true, RelationLabel::NoneObserved) => {
            notes.fired_rules.push("dangerous-path-reached".into());
            (PrimaryLabel::DangerousPathReached, 0.88, false)
        }

        (true, true, RelationLabel::AfterUnsafe) => {
            notes.fired_rules.push("panic-after-unsafe-dynamic".into());
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
            notes.fired_rules.push("suspicious-adjacent-panic".into());
            (PrimaryLabel::SuspiciousCandidate, 0.72, true)
        }

        (true, true, RelationLabel::BeforeUnsafe) => {
            notes.fired_rules.push("conflicting-hit-before-panic".into());
            notes.conflicting_evidence.push(
                "Trace shows both dangerous-site hit and panic, but relation inferred as BeforeUnsafe."
                    .into(),
            );
            (PrimaryLabel::SuspiciousCandidate, 0.55, true)
        }

        (true, true, RelationLabel::AdjacentToUnsafe) => {
            notes.fired_rules.push("ambiguous-hit-and-panic".into());
            (PrimaryLabel::SuspiciousCandidate, 0.58, true)
        }

        (true, _, RelationLabel::Unknown) => {
            notes.fired_rules.push("unknown-panic".into());
            (PrimaryLabel::Unknown, 0.42, true)
        }

        (false, false, _) => {
            notes.fired_rules.push("no-signal".into());
            (PrimaryLabel::Noise, 0.40, false)
        }

        (false, true, _) => {
            notes.fired_rules.push("dangerous-path-reached-fallback".into());
            (PrimaryLabel::DangerousPathReached, 0.75, true)
        }

        (true, false, RelationLabel::AfterUnsafe) => {
            notes.fired_rules.push("static-after-unsafe-without-hit".into());
            (PrimaryLabel::SuspiciousCandidate, 0.63, true)
        }

        (true, _, RelationLabel::NoneObserved) => {
            notes.fired_rules.push("contract-panic".into());
            (PrimaryLabel::ContractPanic, 0.65, true)
        }

        (_, _, RelationLabel::FfiBoundary) => {
            notes.fired_rules.push("ffi-boundary-fallback".into());
            (PrimaryLabel::SuspiciousCandidate, 0.60, true)
        }
    }
}

fn is_oracle_confirmed(verdict: &OracleVerdict) -> bool {
    matches!(
        verdict,
        OracleVerdict::AddressSanitizerDoubleFree
            | OracleVerdict::AddressSanitizerUseAfterFree
            | OracleVerdict::AddressSanitizerOutOfBounds
            | OracleVerdict::MiriUndefinedBehavior
    )
}

#[derive(Debug, Clone)]
struct RelationEvidence {
    relation: RelationLabel,
    nearest_dangerous_site: Option<String>,
    distance_to_dangerous_site: Option<u32>,
    explanation: Option<String>,
    fired_rules: Vec<String>,
    conflicting_evidence: Vec<String>,
}

impl Default for RelationEvidence {
    fn default() -> Self {
        Self {
            relation: RelationLabel::Unknown,
            nearest_dangerous_site: None,
            distance_to_dangerous_site: None,
            explanation: None,
            fired_rules: vec![],
            conflicting_evidence: vec![],
        }
    }
}

fn infer_relation_evidence(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
    reached_dangerous_sites: &[String],
) -> RelationEvidence {
    let lanes = summarize_lanes(site_map, trace);

    if let Some(ev) = infer_from_dynamic_lane_order(site_map, &lanes) {
        return ev;
    }

    if !trace.has_panic() {
        if !reached_dangerous_sites.is_empty() {
            return RelationEvidence {
                relation: RelationLabel::NoneObserved,
                nearest_dangerous_site: reached_dangerous_sites.first().cloned(),
                distance_to_dangerous_site: Some(0u32),
                explanation: Some(
                    "Dangerous site was reached and no panic was observed in trace.".into(),
                ),
                fired_rules: vec!["relation-none-observed".into()],
                conflicting_evidence: vec![],
            };
        }
        return RelationEvidence {
            relation: RelationLabel::Unknown,
            nearest_dangerous_site: None,
            distance_to_dangerous_site: None,
            explanation: Some("No panic and no dangerous-site hit observed in trace.".into()),
            fired_rules: vec!["relation-unknown-no-panic".into()],
            conflicting_evidence: vec![],
        };
    }

    // Panic exists, but the benchmark / crate exposes no dangerous sites at all.
    // This is a normal non-unsafe-related panic, not an unknown relation.
    if reached_dangerous_sites.is_empty() && site_map.dangerous_sites.is_empty() {
        return RelationEvidence {
            relation: RelationLabel::NoneObserved,
            nearest_dangerous_site: None,
            distance_to_dangerous_site: None,
            explanation: Some(
                "Panic observed, but no dangerous sites exist in the site map; treating as non-unsafe-related panic."
                    .into(),
            ),
            fired_rules: vec!["panic-without-any-dangerous-sites".into()],
            conflicting_evidence: vec![],
        };
    }

    if let Some(ev) = infer_from_static_panic_location(site_map, trace, dpg) {
        return ev;
    }

    infer_from_graph_adjacency(site_map, trace, dpg)
}

#[derive(Debug, Clone, Default)]
struct LaneSummary {
    key: String,
    first_hit_index: Option<usize>,
    first_hit_site: Option<String>,
    first_panic_index: Option<usize>,
    first_panic_file: Option<String>,
    first_panic_line: Option<u32>,
    active_function_at_panic: Option<String>,
}

#[derive(Debug, Default)]
struct LaneAccumulator {
    summary: LaneSummary,
    stack: Vec<String>,
}

fn summarize_lanes(site_map: &SiteMap, trace: &TraceLog) -> Vec<LaneSummary> {
    let dangerous_ids: BTreeSet<&str> = site_map
        .dangerous_sites
        .iter()
        .map(|s| s.site_id.as_str())
        .collect();

    let mut lanes: HashMap<String, LaneAccumulator> = HashMap::new();

    for (idx, event) in trace.events.iter().enumerate() {
        let Some(key) = lane_key(event) else {
            continue;
        };

        let lane = lanes.entry(key.clone()).or_insert_with(|| LaneAccumulator {
            summary: LaneSummary {
                key: key.clone(),
                ..LaneSummary::default()
            },
            stack: Vec::new(),
        });

        match event {
            TraceEvent::EnterFunction { function, .. } => {
                lane.stack.push(function.clone());
            }
            TraceEvent::ExitFunction { function, .. } => {
                if lane.stack.last() == Some(function) {
                    lane.stack.pop();
                } else if let Some(pos) = lane.stack.iter().rposition(|f| f == function) {
                    lane.stack.truncate(pos);
                }
            }
            TraceEvent::Hit { site_id, .. } => {
                if dangerous_ids.contains(site_id.as_str()) && lane.summary.first_hit_index.is_none()
                {
                    lane.summary.first_hit_index = Some(idx);
                    lane.summary.first_hit_site = Some(site_id.clone());
                }
            }
            TraceEvent::Panic { file, line, .. } => {
                if lane.summary.first_panic_index.is_none() {
                    lane.summary.first_panic_index = Some(idx);
                    lane.summary.first_panic_file = file.clone();
                    lane.summary.first_panic_line = *line;
                    lane.summary.active_function_at_panic = lane.stack.last().cloned();
                }
            }
            TraceEvent::OracleMarker { .. } => {}
        }
    }

    lanes.into_values().map(|v| v.summary).collect()
}

fn lane_key(event: &TraceEvent) -> Option<String> {
    match event {
        TraceEvent::EnterFunction {
            run_id,
            input_id,
            thread_id,
            ..
        }
        | TraceEvent::ExitFunction {
            run_id,
            input_id,
            thread_id,
            ..
        }
        | TraceEvent::Hit {
            run_id,
            input_id,
            thread_id,
            ..
        }
        | TraceEvent::Panic {
            run_id,
            input_id,
            thread_id,
            ..
        } => Some(format!(
            "{}|{}|{}",
            run_id.as_deref().unwrap_or("_"),
            input_id.as_deref().unwrap_or("_"),
            thread_id
        )),
        TraceEvent::OracleMarker { .. } => None,
    }
}

fn infer_from_dynamic_lane_order(
    site_map: &SiteMap,
    lanes: &[LaneSummary],
) -> Option<RelationEvidence> {
    for lane in lanes {
        let (Some(hit_idx), Some(panic_idx)) = (lane.first_hit_index, lane.first_panic_index) else {
            continue;
        };

        if let (Some(file), Some(line)) = (&lane.first_panic_file, lane.first_panic_line) {
            if let Some(site) = find_dangerous_site_covering(site_map, file, line as usize) {
                return Some(RelationEvidence {
                    relation: RelationLabel::InsideUnsafe,
                    nearest_dangerous_site: Some(site.site_id.clone()),
                    distance_to_dangerous_site: Some(0u32),
                    explanation: Some(format!(
                        "Lane {} panicked inside dangerous site {}.",
                        lane.key, site.site_id
                    )),
                    fired_rules: vec!["dynamic-inside-unsafe".into()],
                    conflicting_evidence: vec![],
                });
            }
        }

        let nearest = lane.first_hit_site.clone();

        if panic_idx > hit_idx {
            return Some(RelationEvidence {
                relation: RelationLabel::AfterUnsafe,
                nearest_dangerous_site: nearest,
                distance_to_dangerous_site: Some(0u32),
                explanation: Some(format!(
                    "Lane {} observed dangerous-site hit before panic.",
                    lane.key
                )),
                fired_rules: vec!["dynamic-after-unsafe".into()],
                conflicting_evidence: vec![],
            });
        }

        if panic_idx < hit_idx {
            return Some(RelationEvidence {
                relation: RelationLabel::BeforeUnsafe,
                nearest_dangerous_site: nearest,
                distance_to_dangerous_site: Some(0u32),
                explanation: Some(format!(
                    "Lane {} observed panic before dangerous-site hit.",
                    lane.key
                )),
                fired_rules: vec!["dynamic-before-unsafe".into()],
                conflicting_evidence: vec![],
            });
        }
    }

    None
}

fn infer_from_static_panic_location(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
) -> Option<RelationEvidence> {
    let panic = trace.first_panic()?;
    let (panic_file, panic_line_u32) = match panic {
        TraceEvent::Panic {
            file: Some(file),
            line: Some(line),
            ..
        } => (file.as_str(), *line),
        _ => return None,
    };

    let panic_line = panic_line_u32 as usize;

    if let Some(site) = find_dangerous_site_covering(site_map, panic_file, panic_line) {
        return Some(RelationEvidence {
            relation: RelationLabel::InsideUnsafe,
            nearest_dangerous_site: Some(site.site_id.clone()),
            distance_to_dangerous_site: Some(0u32),
            explanation: Some(format!(
                "Panic location {}:{} falls inside dangerous site {}.",
                panic_file, panic_line, site.site_id
            )),
            fired_rules: vec!["static-inside-unsafe".into()],
            conflicting_evidence: vec![],
        });
    }

    let panic_fn_hint = infer_panic_function_hint(site_map, trace)?;
    let same_fn_candidates: Vec<&DangerousSite> = site_map
        .dangerous_sites
        .iter()
        .filter(|s| s.enclosing_fn == panic_fn_hint && same_file_path(&s.span.file, panic_file))
        .collect();

    if !same_fn_candidates.is_empty() {
        let nearest = same_fn_candidates
            .iter()
            .min_by_key(|s| line_gap_to_span(panic_line, s))
            .copied()
            .unwrap();

        let relation = if panic_line < nearest.span.line_start {
            RelationLabel::BeforeUnsafe
        } else if panic_line > nearest.span.line_end {
            RelationLabel::AfterUnsafe
        } else {
            RelationLabel::InsideUnsafe
        };

        let explanation = format!(
            "Static same-function ordering in {} inferred relation {:?} relative to dangerous site {}.",
            panic_fn_hint, relation, nearest.site_id
        );

        let graph_distance = dpg.shortest_distance_to_any_dangerous_site(&panic_fn_hint);
        let distance = graph_distance.distance.or(Some(1u32));

        return Some(RelationEvidence {
            relation,
            nearest_dangerous_site: Some(nearest.site_id.clone()),
            distance_to_dangerous_site: distance,
            explanation: Some(explanation),
            fired_rules: vec!["static-same-function-order".into()],
            conflicting_evidence: vec![],
        });
    }

    None
}

fn infer_from_graph_adjacency(
    site_map: &SiteMap,
    trace: &TraceLog,
    dpg: &DangerousPathGraph,
) -> RelationEvidence {
    let panic_fn_hint = infer_panic_function_hint(site_map, trace);
    let distance = panic_fn_hint
        .as_deref()
        .map(|from| dpg.shortest_distance_to_any_dangerous_site(from))
        .unwrap_or_default();

    let relation = match distance.distance {
        Some(0) => RelationLabel::InsideUnsafe,
        Some(1) | Some(2) => RelationLabel::AdjacentToUnsafe,
        Some(_) | None => RelationLabel::Unknown,
    };

    let explanation = match (&panic_fn_hint, distance.distance, &distance.nearest_site) {
        (Some(func), Some(d), Some(site)) => Some(format!(
            "DPG fallback: panic function {} is graph-distance {} from dangerous site {}.",
            func, d, site
        )),
        (Some(func), None, _) => Some(format!(
            "DPG fallback: panic function {} has no known graph path to a dangerous site.",
            func
        )),
        _ => Some("DPG fallback could not infer a stronger relation.".into()),
    };

    let fired_rule = match relation {
        RelationLabel::InsideUnsafe => "graph-fallback-inside",
        RelationLabel::AdjacentToUnsafe => "graph-fallback-adjacent",
        _ => "graph-fallback-unknown",
    };

    RelationEvidence {
        relation,
        nearest_dangerous_site: distance.nearest_site,
        distance_to_dangerous_site: distance.distance,
        explanation,
        fired_rules: vec![fired_rule.into()],
        conflicting_evidence: vec![],
    }
}

fn collect_reached_dangerous_sites(site_map: &SiteMap, trace: &TraceLog) -> Vec<String> {
    let dangerous_ids: BTreeSet<&str> = site_map
        .dangerous_sites
        .iter()
        .map(|s| s.site_id.as_str())
        .collect();

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for hit in trace.hit_site_ids() {
        if dangerous_ids.contains(hit) && seen.insert(hit.to_string()) {
            out.push(hit.to_string());
        }
    }

    out
}

fn find_dangerous_site_covering<'a>(
    site_map: &'a SiteMap,
    file: &str,
    line: usize,
) -> Option<&'a DangerousSite> {
    site_map.dangerous_sites.iter().find(|s| {
        same_file_path(&s.span.file, file)
            && s.span.line_start <= line
            && line <= s.span.line_end
    })
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

fn normalize_path_str(s: &str) -> String {
    let replaced = s.replace('\\', "/");
    let p = Path::new(&replaced);

    if let Ok(canon) = p.canonicalize() {
        canon.to_string_lossy().replace('\\', "/").to_lowercase()
    } else {
        replaced.to_lowercase()
    }
}

fn same_file_path(a: &str, b: &str) -> bool {
    let na = normalize_path_str(a);
    let nb = normalize_path_str(b);

    if na == nb {
        return true;
    }

    na.ends_with(&nb) || nb.ends_with(&na)
}

fn infer_panic_function_hint(site_map: &SiteMap, trace: &TraceLog) -> Option<String> {
    let panic = trace.first_panic()?;
    match panic {
        TraceEvent::Panic {
            file: Some(file),
            line: Some(line),
            ..
        } => {
            let line = *line as usize;

            if let Some(site) = site_map.panic_sites.iter().find(|p| {
                same_file_path(&p.span.file, file)
                    && p.span.line_start <= line
                    && line <= p.span.line_end
            }) {
                return Some(site.enclosing_fn.clone());
            }

            if let Some(site) = site_map.panic_sites.iter().find(|p| {
                same_file_path(&p.span.file, file)
                    && p.span.line_start.saturating_sub(2) <= line
                    && line <= p.span.line_end + 2
            }) {
                return Some(site.enclosing_fn.clone());
            }

            let same_file_sites: Vec<_> = site_map
                .panic_sites
                .iter()
                .filter(|p| same_file_path(&p.span.file, file))
                .collect();

            if same_file_sites.len() == 1 {
                return Some(same_file_sites[0].enclosing_fn.clone());
            }

            None
        }
        _ => None,
    }
}