use rustdpr_core::OracleVerdict;

pub fn parse_asan_output(text: &str) -> Option<OracleVerdict> {
    let lower = text.to_ascii_lowercase();

    if lower.contains("double-free") || lower.contains("attempting double-free") {
        return Some(OracleVerdict::AddressSanitizerDoubleFree);
    }

    if lower.contains("heap-use-after-free") || lower.contains("use-after-free") {
        return Some(OracleVerdict::AddressSanitizerUseAfterFree);
    }

    if lower.contains("out-of-bounds")
        || lower.contains("heap-buffer-overflow")
        || lower.contains("stack-buffer-overflow")
        || lower.contains("global-buffer-overflow")
    {
        return Some(OracleVerdict::AddressSanitizerOutOfBounds);
    }

    None
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