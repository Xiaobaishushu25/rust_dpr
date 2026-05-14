use rustdpr_core::{
    ClassificationNotes, ClassificationResult, DangerousPathGraph, FinalClass, HarnessValidityReport,
    OracleVerdict, PanicDangerRelation, SiteMap, TraceEvent, TraceLog, ValidityStatus,
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

    let reached_dangerous_sites: Vec<String> = trace
        .hit_site_ids()
        .into_iter()
        .filter(|hit| site_map.dangerous_sites.iter().any(|s| s.site_id == *hit))
        .map(|s| s.to_string())
        .collect();

    if !reached_dangerous_sites.is_empty() {
        notes
            .counters
            .insert("reached_dangerous_sites".into(), reached_dangerous_sites.len());
        notes.notes.push(format!(
            "Reached dangerous sites: {}",
            reached_dangerous_sites.join(", ")
        ));
    }

    if harness_status == ValidityStatus::LikelyMisuse {
        notes
            .notes
            .push("Harness validity heuristics suggest likely misuse.".into());
        return ClassificationResult {
            final_class: FinalClass::HarnessMisuse,
            relation: PanicDangerRelation::Unknown,
            reached_dangerous_sites,
            nearest_dangerous_site: None,
            distance_to_dangerous_site: None,
            oracle_verdict,
            harness_status,
            notes,
        };
    }

    match oracle_verdict {
        OracleVerdict::AddressSanitizerDoubleFree => {
            return ClassificationResult {
                final_class: FinalClass::OracleConfirmedDoubleFree,
                relation: relation_from_trace(&reached_dangerous_sites, trace),
                reached_dangerous_sites,
                nearest_dangerous_site: None,
                distance_to_dangerous_site: Some(0),
                oracle_verdict,
                harness_status,
                notes,
            };
        }
        OracleVerdict::AddressSanitizerUseAfterFree => {
            return ClassificationResult {
                final_class: FinalClass::OracleConfirmedUseAfterFree,
                relation: relation_from_trace(&reached_dangerous_sites, trace),
                reached_dangerous_sites,
                nearest_dangerous_site: None,
                distance_to_dangerous_site: Some(0),
                oracle_verdict,
                harness_status,
                notes,
            };
        }
        OracleVerdict::AddressSanitizerOutOfBounds => {
            return ClassificationResult {
                final_class: FinalClass::OracleConfirmedOutOfBounds,
                relation: relation_from_trace(&reached_dangerous_sites, trace),
                reached_dangerous_sites,
                nearest_dangerous_site: None,
                distance_to_dangerous_site: Some(0),
                oracle_verdict,
                harness_status,
                notes,
            };
        }
        OracleVerdict::MiriUndefinedBehavior => {
            return ClassificationResult {
                final_class: FinalClass::OracleConfirmedUb,
                relation: relation_from_trace(&reached_dangerous_sites, trace),
                reached_dangerous_sites,
                nearest_dangerous_site: None,
                distance_to_dangerous_site: Some(0),
                oracle_verdict,
                harness_status,
                notes,
            };
        }
        OracleVerdict::Unknown => {}
    }

    if !reached_dangerous_sites.is_empty() {
        if trace.has_panic() {
            return ClassificationResult {
                final_class: FinalClass::PanicAfterUnsafe,
                relation: PanicDangerRelation::AfterUnsafe,
                reached_dangerous_sites,
                nearest_dangerous_site: Some(
                    reached_dangerous_sites
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                ),
                distance_to_dangerous_site: Some(0),
                oracle_verdict,
                harness_status,
                notes,
            };
        }

        return ClassificationResult {
            final_class: FinalClass::DangerousPathReached,
            relation: PanicDangerRelation::NoneObserved,
            reached_dangerous_sites: reached_dangerous_sites.clone(),
            nearest_dangerous_site: reached_dangerous_sites.first().cloned(),
            distance_to_dangerous_site: Some(0),
            oracle_verdict,
            harness_status,
            notes,
        };
    }

    let panic_fn_hint = infer_panic_function_hint(site_map, trace);
    let distance = panic_fn_hint
        .as_deref()
        .map(|from| dpg.shortest_distance_to_any_dangerous_site(from))
        .unwrap_or_else(|| rustdpr_core::UnsafeDistanceResult {
            from_node: "<unknown>".into(),
            nearest_site: None,
            distance: None,
        });

    let relation = if trace.has_panic() {
        match distance.distance {
            Some(1) | Some(2) => PanicDangerRelation::AdjacentToUnsafe,
            Some(d) if d >= 3 => PanicDangerRelation::FarFromUnsafe,
            _ => PanicDangerRelation::BeforeUnsafe,
        }
    } else {
        PanicDangerRelation::Unknown
    };

    let final_class = if trace.has_panic() {
        match relation {
            PanicDangerRelation::AdjacentToUnsafe => FinalClass::BlockingPanic,
            PanicDangerRelation::FarFromUnsafe => FinalClass::NormalContractPanic,
            PanicDangerRelation::BeforeUnsafe => FinalClass::BlockingPanic,
            _ => FinalClass::Unknown,
        }
    } else {
        FinalClass::Unknown
    };

    ClassificationResult {
        final_class,
        relation,
        reached_dangerous_sites,
        nearest_dangerous_site: distance.nearest_site,
        distance_to_dangerous_site: distance.distance,
        oracle_verdict,
        harness_status,
        notes,
    }
}

fn relation_from_trace(reached_dangerous_sites: &[String], trace: &TraceLog) -> PanicDangerRelation {
    if reached_dangerous_sites.is_empty() {
        if trace.has_panic() {
            PanicDangerRelation::BeforeUnsafe
        } else {
            PanicDangerRelation::Unknown
        }
    } else if trace.has_panic() {
        PanicDangerRelation::AfterUnsafe
    } else {
        PanicDangerRelation::NoneObserved
    }
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
                p.span.file == *file && p.span.line_start <= line && line <= p.span.line_end
            }) {
                return Some(site.enclosing_fn.clone());
            }

            if let Some(site) = site_map.panic_sites.iter().find(|p| {
                p.span.file == *file && p.span.line_start.saturating_sub(2) <= line && line <= p.span.line_end + 2
            }) {
                return Some(site.enclosing_fn.clone());
            }

            None
        }
        _ => None,
    }
}