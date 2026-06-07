use crate::verdict::OracleReport;
use rustdpr_core::{OracleEvidenceStrength, OracleVerdict};

pub fn parse_asan_log(content: &str, raw_log_path: Option<String>) -> OracleReport {
    let lower = content.to_lowercase();
    let mut evidence = Vec::new();

    let mut parsed_from_canonical_line = false;
    let (verdict, bug_kind) =
        if let Some((verdict, bug_kind)) = classify_canonical_asan_lines(&lower) {
            parsed_from_canonical_line = true;
            (verdict, Some(bug_kind.to_string()))
        } else if let Some((verdict, bug_kind)) = classify_asan_issue_text(&lower) {
            (verdict, Some(bug_kind.to_string()))
        } else if contains_any(&lower, &["timeout", "alarm", "max_total_time"]) {
            (OracleVerdict::OracleTimeout, Some("timeout".to_string()))
        } else if contains_any(
            &lower,
            &[
                "build failed",
                "could not compile",
                "linking with",
                "error: aborting due to",
            ],
        ) {
            (
                OracleVerdict::OracleBuildFailure,
                Some("build-failure".to_string()),
            )
        } else {
            (OracleVerdict::NoOracleFinding, None)
        };

    match verdict {
        OracleVerdict::AddressSanitizerDoubleFree => {
            evidence.push("ASan reported double-free".to_string())
        }
        OracleVerdict::AddressSanitizerUseAfterFree => {
            evidence.push("ASan reported use-after-free".to_string())
        }
        OracleVerdict::AddressSanitizerOutOfBounds => {
            evidence.push("ASan reported buffer overflow/out-of-bounds".to_string())
        }
        OracleVerdict::AddressSanitizerInvalidFree => evidence
            .push("ASan reported invalid free or allocation/deallocation mismatch".to_string()),
        OracleVerdict::AddressSanitizerLeak => {
            evidence.push("LeakSanitizer reported memory leak".to_string())
        }
        OracleVerdict::OracleTimeout => {
            evidence.push("oracle run appears to have timed out".to_string())
        }
        OracleVerdict::OracleBuildFailure => {
            evidence.push("oracle run failed to build or link".to_string())
        }
        OracleVerdict::NoOracleFinding => {
            evidence.push("ASan log did not contain a recognized sanitizer finding".to_string())
        }
        _ => {}
    }

    if parsed_from_canonical_line {
        evidence.push("log contains canonical ASan ERROR/SUMMARY classification line".to_string());
    }
    if lower.contains("summary: addresssanitizer") {
        evidence.push("log contains AddressSanitizer SUMMARY line".to_string());
    }
    if lower.contains("==") && lower.contains("error: addresssanitizer") {
        evidence.push("log contains canonical ASan ERROR header".to_string());
    }

    let status = match verdict {
        OracleVerdict::OracleTimeout => "timeout",
        OracleVerdict::OracleBuildFailure => "build_failure",
        OracleVerdict::NoOracleFinding => "no_finding",
        OracleVerdict::Unknown => "unknown",
        _ => "confirmed",
    };
    let evidence_strength = match verdict {
        OracleVerdict::OracleTimeout | OracleVerdict::OracleBuildFailure => {
            OracleEvidenceStrength::Unsupported
        }
        OracleVerdict::NoOracleFinding | OracleVerdict::Unknown => OracleEvidenceStrength::Unknown,
        _ if parsed_from_canonical_line
            || evidence
                .iter()
                .any(|e| e.contains("SUMMARY") || e.contains("canonical")) =>
        {
            OracleEvidenceStrength::Confirmed
        }
        _ => OracleEvidenceStrength::StrongHeuristic,
    };

    OracleReport {
        oracle_name: "asan".into(),
        status: status.into(),
        verdict,
        bug_kind,
        raw_log_path,
        unsupported_reason: None,
        evidence_strength,
        target_api_misuse: false,
        evidence,
    }
}

fn classify_canonical_asan_lines(content: &str) -> Option<(OracleVerdict, &'static str)> {
    for line in content.lines() {
        if line.contains("error: addresssanitizer:") || line.contains("summary: addresssanitizer:")
        {
            if let Some(classification) = classify_asan_issue_text(line) {
                return Some(classification);
            }
        }
    }
    None
}

fn classify_asan_issue_text(text: &str) -> Option<(OracleVerdict, &'static str)> {
    if contains_any(text, &["double-free", "attempting double-free"]) {
        return Some((OracleVerdict::AddressSanitizerDoubleFree, "double-free"));
    }
    if contains_any(
        text,
        &[
            "heap-buffer-overflow",
            "stack-buffer-overflow",
            "global-buffer-overflow",
            "container-overflow",
            "out-of-bounds",
        ],
    ) {
        return Some((OracleVerdict::AddressSanitizerOutOfBounds, "out-of-bounds"));
    }
    if contains_any(
        text,
        &[
            "heap-use-after-free",
            "stack-use-after-return",
            "use-after-free",
        ],
    ) {
        return Some((
            OracleVerdict::AddressSanitizerUseAfterFree,
            "use-after-free",
        ));
    }
    if contains_any(
        text,
        &[
            "attempting free on address which was not malloc",
            "bad-free",
            "invalid-free",
            "alloc-dealloc-mismatch",
        ],
    ) {
        return Some((OracleVerdict::AddressSanitizerInvalidFree, "invalid-free"));
    }
    if contains_any(
        text,
        &[
            "leaksanitizer",
            "detected memory leaks",
            "direct leak of",
            "indirect leak of",
        ],
    ) {
        return Some((OracleVerdict::AddressSanitizerLeak, "memory-leak"));
    }
    None
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}
