use rustdpr_core::model::{OracleFinding, OracleKind, OracleResult, OracleVerdict};

pub fn parse_asan_output(output: &str) -> OracleResult {
    let mut findings = Vec::new();

    let lower = output.to_lowercase();

    let verdict = if lower.contains("attempting double-free")
        || lower.contains("double-free")
        || lower.contains("double free")
    {
        Some(OracleVerdict::DoubleFree)
    } else if lower.contains("heap-use-after-free")
        || lower.contains("use-after-free")
        || lower.contains("use after free")
    {
        Some(OracleVerdict::UseAfterFree)
    } else if lower.contains("heap-buffer-overflow")
        || lower.contains("stack-buffer-overflow")
        || lower.contains("global-buffer-overflow")
        || lower.contains("out-of-bounds")
        || lower.contains("out of bounds")
    {
        Some(OracleVerdict::OutOfBounds)
    } else if lower.contains("addresssanitizer")
        || lower.contains("sanitizer")
        || lower.contains("memory corruption")
    {
        Some(OracleVerdict::MemoryCorruption)
    } else {
        None
    };

    if let Some(verdict) = verdict {
        findings.push(OracleFinding {
            oracle: OracleKind::AddressSanitizer,
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

        if lower.contains("error: addresssanitizer")
            || lower.contains("double-free")
            || lower.contains("double free")
            || lower.contains("use-after-free")
            || lower.contains("use after free")
            || lower.contains("buffer-overflow")
            || lower.contains("out-of-bounds")
            || lower.contains("out of bounds")
            || lower.contains("memory corruption")
        {
            return trimmed.to_string();
        }
    }

    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("AddressSanitizer reported a memory error")
        .to_string()
}

fn extract_stack_frames(output: &str) -> Option<Vec<String>> {
    let frames: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with('#')
                || line.starts_with("at ")
                || line.contains(" in ")
                || line.contains("src/")
                || line.contains(".rs:")
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