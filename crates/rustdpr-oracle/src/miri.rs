use rustdpr_core::model::{OracleFinding, OracleKind, OracleResult, OracleVerdict};

pub fn parse_miri_output(output: &str) -> OracleResult {
    let mut findings = Vec::new();

    let lower = output.to_lowercase();

    let verdict = if lower.contains("undefined behavior") || lower.contains("ub") {
        Some(OracleVerdict::UndefinedBehavior)
    } else if lower.contains("out-of-bounds")
        || lower.contains("out of bounds")
        || lower.contains("pointer to alloc")
        || lower.contains("memory access failed")
    {
        Some(OracleVerdict::OutOfBounds)
    } else if lower.contains("dangling")
        || lower.contains("use after free")
        || lower.contains("use-after-free")
    {
        Some(OracleVerdict::UseAfterFree)
    } else {
        None
    };

    if let Some(verdict) = verdict {
        findings.push(OracleFinding {
            oracle: OracleKind::Miri,
            verdict,
            message: first_summary_line(output),
            stack: extract_stack_frames(output),
            location: extract_primary_location(output),
            raw_message: output.to_string(),
        });
    }

    OracleResult { findings }
}

fn first_summary_line(output: &str) -> String {
    for line in output.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        if trimmed.is_empty() {
            continue;
        }

        if lower.contains("undefined behavior")
            || lower.contains("out-of-bounds")
            || lower.contains("out of bounds")
            || lower.contains("dangling")
            || lower.contains("memory access failed")
            || lower.contains("pointer to alloc")
        {
            return trimmed.to_string();
        }
    }

    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("Miri reported undefined behavior")
        .to_string()
}

fn extract_stack_frames(output: &str) -> Option<Vec<String>> {
    let frames: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("at ")
                || line.starts_with('#')
                || line.contains("src/")
                || line.contains(".rs:")
                || line.contains("inside ")
        })
        .take(8)
        .map(|s| s.to_string())
        .collect();

    if frames.is_empty() {
        None
    } else {
        Some(frames)
    }
}

fn extract_primary_location(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains(".rs:") || trimmed.contains("src/") {
            return Some(trimmed.to_string());
        }
    }

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("at ") {
            return Some(trimmed.to_string());
        }
    }

    None
}