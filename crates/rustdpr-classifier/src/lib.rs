use std::path::Path;
use rustdpr_core::{
    ClassificationNotes, ClassificationResult, DangerousPathGraph, HarnessValidityReport,
    OracleVerdict, PrimaryLabel, RelationLabel, SiteMap, TraceEvent, TraceLog, ValidityStatus,
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
        notes.fired_rules.push("harness-misuse".into());

        return ClassificationResult {
            primary_label: PrimaryLabel::HarnessMisuse,
            relation: RelationLabel::Unknown,
            reached_dangerous_sites,
            nearest_dangerous_site: None,
            distance_to_dangerous_site: None,
            oracle_verdict,
            harness_status,
            confidence: 0.95,
            review_required: false,
            notes,
        };
    }

    match oracle_verdict {
        OracleVerdict::AddressSanitizerDoubleFree
        | OracleVerdict::AddressSanitizerUseAfterFree
        | OracleVerdict::AddressSanitizerOutOfBounds
        | OracleVerdict::MiriUndefinedBehavior => {
            notes.fired_rules.push("oracle-confirmed".into());
            return ClassificationResult {
                primary_label: PrimaryLabel::OracleConfirmedBug,
                relation: relation_from_trace(&reached_dangerous_sites, trace),
                reached_dangerous_sites,
                nearest_dangerous_site: None,
                distance_to_dangerous_site: Some(0),
                oracle_verdict,
                harness_status,
                confidence: 0.99,
                review_required: false,
                notes,
            };
        }
        OracleVerdict::Unknown => {}
    }

    if !reached_dangerous_sites.is_empty() {
        let nearest = reached_dangerous_sites.first().cloned();

        if trace.has_panic() {
            notes.fired_rules.push("panic-after-unsafe".into());
            return ClassificationResult {
                primary_label: PrimaryLabel::PanicAfterUnsafe,
                relation: RelationLabel::AfterUnsafe,
                reached_dangerous_sites,
                nearest_dangerous_site: nearest,
                distance_to_dangerous_site: Some(0),
                oracle_verdict,
                harness_status,
                confidence: 0.85,
                review_required: true,
                notes,
            };
        }

        notes.fired_rules.push("dangerous-path-reached".into());
        return ClassificationResult {
            primary_label: PrimaryLabel::DangerousPathReached,
            relation: RelationLabel::NoneObserved,
            reached_dangerous_sites,
            nearest_dangerous_site: nearest,
            distance_to_dangerous_site: Some(0),
            oracle_verdict,
            harness_status,
            confidence: 0.8,
            review_required: false,
            notes,
        };
    }

    let panic_fn_hint = infer_panic_function_hint(site_map, trace);
    let distance = panic_fn_hint
        .as_deref()
        .map(|from| dpg.shortest_distance_to_any_dangerous_site(from))
        .unwrap_or_default();

    let relation = if trace.has_panic() {
        match distance.distance {
            Some(0) => RelationLabel::InsideUnsafe,
            Some(1) | Some(2) => RelationLabel::AdjacentToUnsafe,
            Some(_) => RelationLabel::BeforeUnsafe,
            None => RelationLabel::Unknown,
        }
    } else {
        RelationLabel::Unknown
    };

    let (primary_label, confidence, review_required) = if trace.has_panic() {
        match relation {
            RelationLabel::AdjacentToUnsafe => {
                notes.fired_rules.push("blocking-panic-adjacent".into());
                (PrimaryLabel::BlockingPanic, 0.72, true)
            }
            RelationLabel::BeforeUnsafe => {
                notes.fired_rules.push("contract-or-blocking-panic".into());
                (PrimaryLabel::BlockingPanic, 0.68, true)
            }
            RelationLabel::InsideUnsafe => {
                notes.fired_rules.push("inside-unsafe-panic".into());
                (PrimaryLabel::InsideUnsafePanic, 0.85, true)
            }
            RelationLabel::Unknown | RelationLabel::NoneObserved | RelationLabel::AfterUnsafe | RelationLabel::FfiBoundary => {
                notes.fired_rules.push("unknown-panic".into());
                (PrimaryLabel::Unknown, 0.4, true)
            }
        }
    } else {
        notes.fired_rules.push("no-signal".into());
        (PrimaryLabel::Noise, 0.4, false)
    };

    ClassificationResult {
        primary_label,
        relation,
        reached_dangerous_sites,
        nearest_dangerous_site: distance.nearest_site,
        distance_to_dangerous_site: distance.distance,
        oracle_verdict,
        harness_status,
        confidence,
        review_required,
        notes,
    }
}

fn relation_from_trace(reached_dangerous_sites: &[String], trace: &TraceLog) -> RelationLabel {
    if reached_dangerous_sites.is_empty() {
        if trace.has_panic() {
            RelationLabel::BeforeUnsafe
        } else {
            RelationLabel::Unknown
        }
    } else if trace.has_panic() {
        RelationLabel::AfterUnsafe
    } else {
        RelationLabel::NoneObserved
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

    // 兜底：有时 panic hook 给的是相对路径，site_map 里是绝对路径
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

            // 再兜底：如果同一文件里只有一个 unwrap-like panic site，就直接用它
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