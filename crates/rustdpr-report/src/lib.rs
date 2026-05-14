use anyhow::Result;
use rustdpr_core::model::{CaseClass, ClassificationResult, OracleResult, SiteMap, TraceLog};

pub fn render_report(
    crate_name: &str,
    site_map: &SiteMap,
    trace: &TraceLog,
    result: &ClassificationResult,
    oracle: Option<&OracleResult>,
) -> Result<String> {
    let mut out = String::new();

    out.push_str(&format!("# RustDPR Report: {crate_name}\n\n"));

    out.push_str("## Dangerous Sites\n");
    if site_map.dangerous_sites.is_empty() {
        out.push_str("- none\n");
    } else {
        for s in &site_map.dangerous_sites {
            out.push_str(&format!(
                "- {} {:?} {}:{}-{}\n",
                s.site_id,
                s.kind,
                s.span.file.display(),
                s.span.line_start,
                s.span.line_end
            ));
        }
    }

    out.push_str("\n## Panic Sites\n");
    if site_map.panic_sites.is_empty() {
        out.push_str("- none\n");
    } else {
        for p in &site_map.panic_sites {
            out.push_str(&format!(
                "- {} {:?} {}:{}-{}\n",
                p.panic_id,
                p.kind,
                p.span.file.display(),
                p.span.line_start,
                p.span.line_end
            ));
        }
    }

    out.push_str("\n## Trace Events\n");
    if trace.events.is_empty() {
        out.push_str("- none\n");
    } else {
        for e in &trace.events {
            out.push_str(&format!("- {:?}\n", e));
        }
    }

    out.push_str("\n## Classification\n");
    out.push_str(&format!("- Relation: {:?}\n", result.relation));
    out.push_str(&format!("- Class: {:?}\n", result.class));
    out.push_str(&format!("- Reached Sites: {:?}\n", result.reached_site_ids));
    out.push_str(&format!("- Panic Message: {:?}\n", result.panic_message));
    out.push_str(&format!("- Panic File: {:?}\n", result.panic_file));
    out.push_str(&format!("- Panic Line: {:?}\n", result.panic_line));
    out.push_str(&format!("- Panic Observed: {}\n", result.panic_observed));
    out.push_str(&format!(
        "- Reached Dangerous Site: {}\n",
        result.reached_dangerous_site
    ));
    out.push_str(&format!("- Taxonomy Reason: {}\n", result.taxonomy_reason));

    out.push_str("\n## Taxonomy Summary\n");
    out.push_str(&format!("- Final Class: {:?}\n", result.class));
    out.push_str(&format!("- Oracle Confirmed: {}\n", result.oracle_confirmed));

    out.push_str("\n## Oracle Findings\n");
    match oracle {
        Some(oracle_result) if !oracle_result.findings.is_empty() => {
            for finding in &oracle_result.findings {
                out.push_str(&format!("\n### {:?} / {:?}\n", finding.oracle, finding.verdict));
                out.push_str(&format!("- Message: {}\n", finding.message));
                if let Some(location) = &finding.location {
                    out.push_str(&format!("- Location: {}\n", location));
                }
                if let Some(stack) = &finding.stack {
                    if stack.is_empty() {
                        out.push_str("- Stack: none\n");
                    } else {
                        out.push_str("- Stack:\n");
                        for frame in stack {
                            out.push_str(&format!("  - {}\n", frame));
                        }
                    }
                } else {
                    out.push_str("- Stack: none\n");
                }
            }
        }
        _ => {
            out.push_str("- none\n");
        }
    }

    out.push_str("\n## Notes\n");
    if result.notes.is_empty() {
        out.push_str("- none\n");
    } else {
        for n in &result.notes {
            out.push_str(&format!("- {n}\n"));
        }
    }
    out.push_str(&format!(
        "- Description: {}\n",
        class_description(&result.class)
    ));

    Ok(out)
}

fn class_description(class: &CaseClass) -> &'static str {
    match class {
        CaseClass::NormalContractPanic => "panic appears to be part of normal contract enforcement",
        CaseClass::BlockingPanic => "panic prevents dangerous path from being reached",
        CaseClass::HarnessMisuse => "panic likely comes from test or harness misuse",
        CaseClass::ReachableUnsafeNoPanic => "dangerous code is reachable but no panic was observed",
        CaseClass::PanicAfterUnsafe => "panic happened after dangerous code became reachable",
        CaseClass::SuspiciousCandidate => "dangerous code is reachable but not oracle-confirmed",
        CaseClass::OracleConfirmedDoubleFree => "oracle confirmed double free",
        CaseClass::OracleConfirmedUseAfterFree => "oracle confirmed use-after-free",
        CaseClass::OracleConfirmedOutOfBounds => "oracle confirmed out-of-bounds access",
        CaseClass::OracleConfirmedMemoryCorruption => "oracle confirmed memory corruption",
        CaseClass::OracleConfirmedUndefinedBehavior => "oracle confirmed undefined behavior",
        CaseClass::OracleConfirmedMemoryBug => "oracle confirmed a memory-safety bug",
        CaseClass::Unknown => "classification is inconclusive",
    }
}