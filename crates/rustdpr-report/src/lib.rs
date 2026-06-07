use rustdpr_core::{
    ClassificationResult, DangerousPathGraph, HarnessValidityReport, SiteMap, TraceEvent, TraceLog,
};

pub fn render_markdown_report(
    site_map: &SiteMap,
    dpg: &DangerousPathGraph,
    trace: &TraceLog,
    harness: Option<&HarnessValidityReport>,
    classification: &ClassificationResult,
) -> String {
    let mut md = String::new();

    md.push_str("# RustDPR Report\n\n");

    md.push_str("## Metadata\n\n");
    md.push_str(&format!(
        "- Schema version: `{}`\n",
        classification.schema_version
    ));
    md.push_str(&format!(
        "- Suite: `{}`\n",
        classification
            .suite
            .clone()
            .unwrap_or_else(|| "unknown".into())
    ));
    md.push_str(&format!(
        "- Case: `{}`\n\n",
        classification
            .case_name
            .clone()
            .unwrap_or_else(|| "unknown".into())
    ));

    md.push_str("## Crate Metadata\n\n");
    md.push_str(&format!("- Crate root: `{}`\n", site_map.crate_root));
    md.push_str(&format!(
        "- Dangerous sites: {}\n",
        site_map.dangerous_sites.len()
    ));
    md.push_str(&format!("- Panic sites: {}\n", site_map.panic_sites.len()));
    md.push_str(&format!("- DPG nodes: {}\n", dpg.nodes.len()));
    md.push_str(&format!("- DPG edges: {}\n\n", dpg.edges.len()));

    md.push_str("## Trace Summary\n\n");
    md.push_str(&format!("- Total trace events: {}\n", trace.events.len()));
    md.push_str(&format!("- Hit count: {}\n", trace.hit_count()));
    md.push_str(&format!("- Panic count: {}\n", trace.panic_count()));
    md.push_str(&format!("- Panic observed: {}\n\n", trace.has_panic()));

    if let Some(first_hit) = trace.first_hit() {
        md.push_str("### First Hit Event\n\n");
        md.push_str(&format!("- `{first_hit:?}`\n\n"));
    }

    if let Some(first_panic) = trace.first_panic() {
        md.push_str("### First Panic Event\n\n");
        md.push_str(&format!("- `{first_panic:?}`\n\n"));
    }

    md.push_str("## Harness Validity\n\n");
    if let Some(h) = harness {
        md.push_str(&format!("- Status: `{:?}`\n", h.status));
        md.push_str(&format!("- Needs review: `{}`\n", h.needs_manual_review));
        md.push_str(&format!("- Score: `{:?}`\n", h.score));
        md.push_str(&format!(
            "- Summary: `{}`\n",
            h.summary.clone().unwrap_or_else(|| "none".into())
        ));
        if !h.evidence.is_empty() {
            md.push_str("- Evidence:\n");
            for e in &h.evidence {
                md.push_str(&format!(
                    "  - [{}|{}] {}:{} {}\n",
                    e.rule, e.severity, e.file, e.line, e.message
                ));
                if let Some(snippet) = &e.snippet {
                    md.push_str(&format!("    - snippet: `{}`\n", snippet));
                }
            }
        }
        md.push('\n');
    } else {
        md.push_str("- No harness analysis provided.\n\n");
    }

    md.push_str("## Classification\n\n");
    md.push_str(&format!(
        "- Primary label: `{:?}`\n",
        classification.primary_label
    ));
    md.push_str(&format!("- Relation: `{:?}`\n", classification.relation));
    md.push_str(&format!(
        "- Confidence: `{:.2}`\n",
        classification.confidence
    ));
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

    if !classification.notes.evidence_summary.is_empty() {
        md.push_str("## Evidence Summary\n\n");
        for n in &classification.notes.evidence_summary {
            md.push_str(&format!("- {}\n", n));
        }
        md.push('\n');
    }

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

    if !classification.notes.decision_path.is_empty() {
        md.push_str("## Decision Path\n\n");
        for n in &classification.notes.decision_path {
            md.push_str(&format!("- {}\n", n));
        }
        md.push('\n');
    }

    if !classification.notes.conflicting_evidence.is_empty() {
        md.push_str("## Conflicting Evidence\n\n");
        for n in &classification.notes.conflicting_evidence {
            md.push_str(&format!("- {}\n", n));
        }
        md.push('\n');
    }

    md.push_str("## Reviewer Action\n\n");
    if classification.review_required {
        md.push_str("- Manual review is recommended for this case.\n");
    } else {
        md.push_str("- No immediate manual review required.\n");
    }

    let oracle_markers: Vec<&TraceEvent> = trace
        .events
        .iter()
        .filter(|e| matches!(e, TraceEvent::OracleMarker { .. }))
        .collect();
    if !oracle_markers.is_empty() {
        md.push_str("\n### Oracle Markers in Trace\n\n");
        for marker in oracle_markers {
            md.push_str(&format!("- `{marker:?}`\n"));
        }
    }

    md
}
