use anyhow::Result;
use rustdpr_core::model::{ClassificationResult, SiteMap, TraceLog};

pub fn render_report(
    crate_name: &str,
    site_map: &SiteMap,
    trace: &TraceLog,
    result: &ClassificationResult,
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

    out.push_str("\n## Notes\n");
    if result.notes.is_empty() {
        out.push_str("- none\n");
    } else {
        for n in &result.notes {
            out.push_str(&format!("- {n}\n"));
        }
    }

    Ok(out)
}