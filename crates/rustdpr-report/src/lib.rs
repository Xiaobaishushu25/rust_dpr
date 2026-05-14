use rustdpr_core::{ClassificationResult, SiteMap, TraceLog, TraceEvent};

pub fn render_markdown_report(
    site_map: &SiteMap,
    trace: &TraceLog,
    result: &ClassificationResult,
) -> String {
    let mut out = String::new();

    out.push_str("# RustDPR Report\n\n");

    out.push_str("## Summary\n\n");
    out.push_str(&format!("- Final Class: {:?}\n", result.final_class));
    out.push_str(&format!("- Relation: {:?}\n", result.relation));
    out.push_str(&format!(
        "- Reached Dangerous Sites: {:?}\n",
        result.reached_dangerous_sites
    ));
    out.push_str(&format!(
        "- Nearest Dangerous Site: {:?}\n",
        result.nearest_dangerous_site
    ));
    out.push_str(&format!(
        "- Distance to Dangerous Site: {:?}\n",
        result.distance_to_dangerous_site
    ));
    out.push_str(&format!("- Oracle Verdict: {:?}\n", result.oracle_verdict));
    out.push_str(&format!("- Harness Status: {:?}\n", result.harness_status));
    out.push('\n');

    out.push_str("## Dangerous Sites\n\n");
    if site_map.dangerous_sites.is_empty() {
        out.push_str("- None\n\n");
    } else {
        for s in &site_map.dangerous_sites {
            out.push_str(&format!(
                "- {} {:?} in `{}` at {}:{}-{}\n",
                s.site_id,
                s.kind,
                s.enclosing_fn,
                s.span.file,
                s.span.line_start,
                s.span.line_end
            ));
        }
        out.push('\n');
    }

    out.push_str("## Panic Sites\n\n");
    if site_map.panic_sites.is_empty() {
        out.push_str("- None\n\n");
    } else {
        for p in &site_map.panic_sites {
            out.push_str(&format!(
                "- {} {:?} in `{}` at {}:{}-{}\n",
                p.panic_id,
                p.kind,
                p.enclosing_fn,
                p.span.file,
                p.span.line_start,
                p.span.line_end
            ));
        }
        out.push('\n');
    }

    out.push_str("## Trace Events\n\n");
    if trace.events.is_empty() {
        out.push_str("- None\n\n");
    } else {
        for e in &trace.events {
            match e {
                TraceEvent::Hit { site_id, ts_millis } => {
                    out.push_str(&format!("- HIT {} at {} ms\n", site_id, ts_millis));
                }
                TraceEvent::Panic {
                    message,
                    file,
                    line,
                    ts_millis,
                } => {
                    out.push_str(&format!(
                        "- PANIC at {} ms, file={:?}, line={:?}, message={:?}\n",
                        ts_millis, file, line, message
                    ));
                }
            }
        }
        out.push('\n');
    }

    out.push_str("## Notes\n\n");
    if result.notes.notes.is_empty() && result.notes.counters.is_empty() {
        out.push_str("- None\n");
    } else {
        for n in &result.notes.notes {
            out.push_str(&format!("- {}\n", n));
        }
        for (k, v) in &result.notes.counters {
            out.push_str(&format!("- {}: {}\n", k, v));
        }
    }

    out
}