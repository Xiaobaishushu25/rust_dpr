use rustdpr_core::{ClassificationResult, DangerousPathGraph, HarnessValidityReport, SiteMap, TraceLog};

pub fn render_markdown_report(
    site_map: &SiteMap,
    dpg: &DangerousPathGraph,
    trace: &TraceLog,
    harness: Option<&HarnessValidityReport>,
    classification: &ClassificationResult,
) -> String {
    let mut md = String::new();

    md.push_str("# RustDPR Report\n\n");
    md.push_str("## Crate Metadata\n\n");
    md.push_str(&format!("- Crate root: `{}`\n", site_map.crate_root));
    md.push_str(&format!("- Dangerous sites: {}\n", site_map.dangerous_sites.len()));
    md.push_str(&format!("- Panic sites: {}\n", site_map.panic_sites.len()));
    md.push_str(&format!("- DPG nodes: {}\n", dpg.nodes.len()));
    md.push_str(&format!("- DPG edges: {}\n\n", dpg.edges.len()));

    md.push_str("## Trace Summary\n\n");
    md.push_str(&format!("- Total trace events: {}\n", trace.events.len()));
    md.push_str(&format!("- Panic observed: {}\n\n", trace.has_panic()));

    md.push_str("## Harness Validity\n\n");
    if let Some(h) = harness {
        md.push_str(&format!("- Status: `{:?}`\n", h.status));
        md.push_str(&format!("- Needs review: `{}`\n", h.needs_manual_review));
        if !h.evidence.is_empty() {
            md.push_str("- Evidence:\n");
            for e in &h.evidence {
                md.push_str(&format!(
                    "  - [{}] {}:{} {}\n",
                    e.rule, e.file, e.line, e.message
                ));
            }
        }
        md.push('\n');
    } else {
        md.push_str("- No harness analysis provided.\n\n");
    }

    md.push_str("## Classification\n\n");
    md.push_str(&format!("- Primary label: `{:?}`\n", classification.primary_label));
    md.push_str(&format!("- Relation: `{:?}`\n", classification.relation));
    md.push_str(&format!("- Confidence: `{:.2}`\n", classification.confidence));
    md.push_str(&format!(
        "- Review required: `{}`\n",
        classification.review_required
    ));
    md.push_str(&format!(
        "- Oracle verdict: `{:?}`\n",
        classification.oracle_verdict
    ));
    md.push_str(&format!(
        "- Harness status: `{:?}`\n",
        classification.harness_status
    ));
    md.push_str(&format!(
        "- Reached dangerous sites: `{}`\n",
        classification.reached_dangerous_sites.join(", ")
    ));
    md.push_str(&format!(
        "- Nearest dangerous site: `{:?}`\n",
        classification.nearest_dangerous_site
    ));
    md.push_str(&format!(
        "- Distance to dangerous site: `{:?}`\n\n",
        classification.distance_to_dangerous_site
    ));

    if !classification.notes.notes.is_empty() {
        md.push_str("## Notes\n\n");
        for n in &classification.notes.notes {
            md.push_str(&format!("- {}\n", n));
        }
        md.push('\n');
    }

    if !classification.notes.fired_rules.is_empty() {
        md.push_str("## Fired Rules\n\n");
        for n in &classification.notes.fired_rules {
            md.push_str(&format!("- {}\n", n));
        }
        md.push('\n');
    }

    md
}