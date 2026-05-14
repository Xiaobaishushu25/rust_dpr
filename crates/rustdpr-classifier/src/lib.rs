use anyhow::Result;
use rustdpr_core::model::{CaseClass, ClassificationResult, OracleResult, OracleVerdict, PanicRelation, SiteMap, TraceEvent, TraceLog};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

fn oracle_verdict_to_case_class(verdict: &OracleVerdict) -> Option<CaseClass> {
    match verdict {
        OracleVerdict::DoubleFree => Some(CaseClass::OracleConfirmedDoubleFree),
        OracleVerdict::UseAfterFree => Some(CaseClass::OracleConfirmedUseAfterFree),
        OracleVerdict::OutOfBounds => Some(CaseClass::OracleConfirmedOutOfBounds),
        OracleVerdict::MemoryCorruption => Some(CaseClass::OracleConfirmedMemoryCorruption),
        OracleVerdict::UndefinedBehavior => Some(CaseClass::OracleConfirmedUndefinedBehavior),
        OracleVerdict::InvalidFree => Some(CaseClass::OracleConfirmedMemoryBug),
        _ => None,
    }
}

fn strongest_oracle_case(findings: &[rustdpr_core::model::OracleFinding]) -> Option<CaseClass> {
    for verdict in [
        OracleVerdict::DoubleFree,
        OracleVerdict::UseAfterFree,
        OracleVerdict::OutOfBounds,
        OracleVerdict::MemoryCorruption,
        OracleVerdict::UndefinedBehavior,
        OracleVerdict::InvalidFree,
    ] {
        if findings.iter().any(|f| f.verdict == verdict) {
            return oracle_verdict_to_case_class(&verdict);
        }
    }
    None
}

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


/**
为什么这里引入 ReachableUnsafeNoPanic 又还保留 SuspiciousCandidate
因为它们用途不同：
ReachableUnsafeNoPanic：启发式观察结果
SuspiciousCandidate：最终对外标签，表示“危险已达但未证实”
这版逻辑里，先得到启发式类；如果没有 panic 且 hit 了 dangerous site：
有 oracle 且 oracle 没证实 → SuspiciousCandidate
没有 oracle → 也落到 SuspiciousCandidate
这样对外分类更稳定，但你仍然保留了中间语义到
**/
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
                if panic_message.is_none() {
                    panic_message = message.clone();
                }
                if panic_file.is_none() {
                    panic_file = file.clone();
                }
                if panic_line.is_none() {
                    panic_line = *line;
                }
            }
        }
    }

    let reached_dangerous_site = !reached.is_empty();
    let has_dangerous_sites = !site_map.dangerous_sites.is_empty();

    let (relation, mut class, mut notes, mut taxonomy_reason) =
        if panic_seen && !reached_dangerous_site && !has_dangerous_sites {
            (
                PanicRelation::NoDangerousSiteReached,
                CaseClass::NormalContractPanic,
                vec!["panic observed and crate has no dangerous site".to_string()],
                "panic observed, and no dangerous site exists in the site map".to_string(),
            )
        } else if panic_seen && !reached_dangerous_site && has_dangerous_sites {
            (
                PanicRelation::NoDangerousSiteReached,
                CaseClass::BlockingPanic,
                vec!["panic observed before any dangerous site was reached".to_string()],
                "panic observed before any dangerous site was reached".to_string(),
            )
        } else if panic_seen && reached_dangerous_site {
            (
                PanicRelation::AfterUnsafe,
                CaseClass::PanicAfterUnsafe,
                vec!["dangerous site reached before panic".to_string()],
                "dangerous site was reached and panic was later observed".to_string(),
            )
        } else if !panic_seen && reached_dangerous_site {
            (
                PanicRelation::Unknown,
                CaseClass::ReachableUnsafeNoPanic,
                vec!["dangerous site reached without panic".to_string()],
                "dangerous site was reached but no panic was observed".to_string(),
            )
        } else {
            (
                PanicRelation::Unknown,
                CaseClass::Unknown,
                vec!["no panic and no dangerous site hit".to_string()],
                "no panic observed and no dangerous site reached".to_string(),
            )
        };

    let mut oracle_confirmed = false;
    let mut oracle_results = vec![];

    if let Some(o) = oracle {
        oracle_results.extend(o.findings.clone());

        if let Some(oracle_case) = strongest_oracle_case(&o.findings) {
            oracle_confirmed = true;
            class = oracle_case;
            taxonomy_reason = "oracle confirmed a concrete memory-safety violation".to_string();
            notes.push("oracle confirmed memory safety violation".to_string());
        } else if !panic_seen && reached_dangerous_site {
            class = CaseClass::SuspiciousCandidate;
            taxonomy_reason =
                "dangerous site reached without panic, but oracle did not confirm a concrete bug"
                    .to_string();
            notes.push("oracle did not confirm a concrete bug".to_string());
        }
    } else if !panic_seen && reached_dangerous_site {
        class = CaseClass::SuspiciousCandidate;
        taxonomy_reason =
            "dangerous site reached without panic and no oracle evidence was provided".to_string();
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
        reached_dangerous_site,
        panic_observed: panic_seen,
        taxonomy_reason,
    }
}