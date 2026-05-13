use anyhow::Result;
use rustdpr_core::model::{CaseClass, ClassificationResult, OracleResult, OracleVerdict, PanicRelation, SiteMap, TraceEvent, TraceLog};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn load_trace(path: &Path) -> Result<TraceLog> {
    let f = fs::File::open(path)?;
    let reader = BufReader::new(f);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let ev: TraceEvent = serde_json::from_str(&line)?;
        events.push(ev);
    }

    Ok(TraceLog { events })
}

pub fn classify(
    trace: &TraceLog,
    site_map: &SiteMap,
    oracle: Option<&OracleResult>,
) -> ClassificationResult {

    let mut reached = Vec::new();

    let mut panic_message = None;
    let mut panic_file = None;
    let mut panic_line = None;

    let mut panic_seen = false;

    for ev in &trace.events {
        match ev {
            TraceEvent::Hit { site_id, .. } => {
                reached.push(site_id.clone());
            }
            TraceEvent::Panic {
                message,
                file,
                line,
                ..
            } => {
                panic_seen = true;
                if panic_message.is_none() { panic_message = message.clone(); }
                if panic_file.is_none() { panic_file = file.clone(); }
                if panic_line.is_none() { panic_line = *line; }
            }
        }
    }

    let has_dangerous_sites =
        !site_map.dangerous_sites.is_empty();
    let (relation, mut class, mut notes) =
        if panic_seen
            && reached.is_empty()
            && !has_dangerous_sites
        {
            (
                PanicRelation::NoDangerousSiteReached,
                CaseClass::NormalContractPanic,
                vec![
                    "panic observed and crate has no dangerous site"
                        .to_string()
                ],
            )
        } else if panic_seen
            && reached.is_empty()
            && has_dangerous_sites
        {
            (
                PanicRelation::NoDangerousSiteReached,
                CaseClass::BlockingPanic,
                vec![
                    "panic observed before any dangerous site was reached"
                        .to_string()
                ],
            )
        } else if panic_seen && !reached.is_empty() {
            (
                PanicRelation::AfterUnsafe,
                CaseClass::PanicAfterUnsafe,
                vec![
                    "dangerous site reached before panic"
                        .to_string()
                ],
            )
        } else if !panic_seen && !reached.is_empty() {
            (
                PanicRelation::Unknown,
                CaseClass::SuspiciousCandidate,
                vec![
                    "dangerous site reached without panic"
                        .to_string()
                ],
            )
        } else {
            (
                PanicRelation::Unknown,
                CaseClass::Unknown,
                vec![
                    "no panic and no dangerous site hit"
                        .to_string()
                ],
            )
        };

    // =========================================
    // Oracle integration
    // =========================================

    let mut oracle_confirmed = false;
    let mut oracle_results = vec![];

    if let Some(o) = oracle {
        oracle_results.extend(o.findings.clone());
        for finding in &o.findings {
            match finding.verdict {
                OracleVerdict::DoubleFree
                | OracleVerdict::UseAfterFree
                | OracleVerdict::OutOfBounds
                | OracleVerdict::MemoryCorruption
                | OracleVerdict::UndefinedBehavior => {
                    oracle_confirmed = true;
                }
                _ => {}
            }
        }
    }

    // Oracle evidence overrides heuristic class

    if oracle_confirmed {
        class = CaseClass::OracleConfirmedMemoryBug;
        notes.push("oracle confirmed memory safety violation".to_string());
    }

    ClassificationResult {
        relation,
        class,
        reached_site_ids: reached,
        notes,
        panic_message,
        panic_file,
        panic_line,
        oracle_confirmed,
        oracle_results,
    }
}