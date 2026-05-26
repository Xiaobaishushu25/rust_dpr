use anyhow::{Context, Result};
use rustdpr_core::{
    HarnessValidityReport, RUSTDPR_SCHEMA_VERSION, ValidityEvidence, ValidityStatus,
};
use std::fs;
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprCall, ExprMethodCall, ExprPath, ExprUnary, ExprUnsafe, File, UnOp};
use walkdir::WalkDir;

pub fn analyze_harness_validity(harness_path: &Path) -> Result<HarnessValidityReport> {
    let mut evidence = Vec::new();

    let files = if harness_path.is_dir() {
        let mut rs_files = vec![];
        for entry in WalkDir::new(harness_path) {
            let entry = entry?;
            let p = entry.path();
            if p.is_file() && p.extension().map(|x| x == "rs").unwrap_or(false) {
                rs_files.push(p.to_path_buf());
            }
        }
        rs_files
    } else {
        vec![harness_path.to_path_buf()]
    };

    for file in files {
        let content = fs::read_to_string(&file)
            .with_context(|| format!("failed to read harness {}", file.display()))?;
        let ast: File = syn::parse_file(&content)
            .with_context(|| format!("failed to parse harness {}", file.display()))?;

        let mut visitor = HarnessVisitor {
            file: file.display().to_string(),
            source: content,
            evidence: vec![],
        };
        visitor.visit_file(&ast);
        //用文本级 fallback识别误用，不然闭包里面的代码识别不到
        visitor.scan_source_fallback();
        evidence.extend(visitor.evidence);
    }

    let violated_patterns: Vec<String> = evidence.iter().map(|e| e.rule.clone()).collect();

    let high_count = evidence.iter().filter(|e| e.severity == "high").count();
    let medium_count = evidence.iter().filter(|e| e.severity == "medium").count();

    let score = (high_count as f32 * 0.65) + (medium_count as f32 * 0.25);

    let status = if evidence.is_empty() {
        ValidityStatus::LikelyValid
    } else if high_count >= 1 {
        ValidityStatus::LikelyMisuse
    } else {
        ValidityStatus::Unknown
    };

    let summary = if evidence.is_empty() {
        Some("no obvious harness misuse pattern detected".to_string())
    } else {
        Some(format!(
            "detected {} evidence items (high={}, medium={})",
            evidence.len(),
            high_count,
            medium_count
        ))
    };

    let needs_manual_review = matches!(status, ValidityStatus::Unknown);

    Ok(HarnessValidityReport {
        schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
        harness_path: harness_path.display().to_string(),
        status,
        evidence,
        violated_patterns,
        needs_manual_review,
        summary,
        score: Some(score.min(1.0)),
    })
}

struct HarnessVisitor {
    file: String,
    source: String,
    evidence: Vec<ValidityEvidence>,
}

impl HarnessVisitor {
    fn line_of<T: Spanned>(&self, node: &T) -> usize {
        node.span().start().line
    }

    fn end_line_of<T: Spanned>(&self, node: &T) -> usize {
        node.span().end().line
    }

    fn snippet_for<T: Spanned>(&self, node: &T) -> Option<String> {
        let start = self.line_of(node);
        self.source
            .lines()
            .nth(start.saturating_sub(1))
            .map(|s| s.trim().to_string())
    }

    fn add<T: Spanned>(&mut self, node: &T, rule: &str, severity: &str, message: &str) {
        self.evidence.push(ValidityEvidence {
            rule: rule.to_string(),
            severity: severity.to_string(),
            message: message.to_string(),
            file: self.file.clone(),
            line: self.line_of(node),
            span_end_line: Some(self.end_line_of(node)),
            snippet: self.snippet_for(node),
        });
    }

    fn path_to_string(expr: &ExprPath) -> String {
        expr.path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::")
    }
    fn add_textual(
        &mut self,
        line: usize,
        rule: &str,
        severity: &str,
        message: &str,
        snippet: &str,
    ) {
        self.evidence.push(ValidityEvidence {
            rule: rule.to_string(),
            severity: severity.to_string(),
            message: message.to_string(),
            file: self.file.clone(),
            line,
            span_end_line: Some(line),
            snippet: Some(snippet.trim().to_string()),
        });
    }

    fn scan_source_fallback(&mut self) {
        let lines: Vec<String> = self.source.lines().map(|s| s.to_string()).collect();

        for (idx, raw) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = raw.trim();
            let lower = trimmed.to_lowercase();

            if trimmed.starts_with("//") {
                continue;
            }

            if lower.contains("std::ptr::null")
                || lower.contains("ptr::null")
                || lower.contains("null_mut")
            {
                self.add_textual(
                    line_no,
                    "null-pointer-construction",
                    "high",
                    "harness constructs a null pointer",
                    trimmed,
                );
            }

            if lower.contains("unsafe {") || lower.starts_with("unsafe{") {
                self.add_textual(
                    line_no,
                    "direct-unsafe-block",
                    "high",
                    "harness contains an explicit unsafe block",
                    trimmed,
                );
            }

            if lower.contains("from_raw_parts") {
                self.add_textual(
                    line_no,
                    "from-raw-parts",
                    "high",
                    "harness constructs a slice from raw parts",
                    trimmed,
                );
            }

            if lower.contains("transmute") {
                self.add_textual(
                    line_no,
                    "transmute-in-harness",
                    "high",
                    "harness performs transmute directly",
                    trimmed,
                );
            }

            if lower.contains("assume_init") {
                self.add_textual(
                    line_no,
                    "assume-init-in-harness",
                    "high",
                    "harness assumes MaybeUninit initialized state",
                    trimmed,
                );
            }
        }
    }
}

impl<'ast> Visit<'ast> for HarnessVisitor {
    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        self.add(
            node,
            "direct-unsafe-block",
            "high",
            "harness contains an explicit unsafe block",
        );
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let syn::Expr::Path(expr_path) = &*node.func {
            let callee = Self::path_to_string(expr_path).to_lowercase();

            if callee.contains("rustdpr_trace::hit") || callee == "hit" || callee.ends_with("::hit") {
                self.add(
                    node,
                    "manual-hit-in-harness",
                    "medium",
                    "harness manually emits a dangerous-site hit; prefer library-side site ids",
                );
            }

            if callee.starts_with("unsafe_") || callee.contains("::unsafe_") || callee.contains("unchecked") {
                self.add(
                    node,
                    "target-api-unsafe-or-unchecked-call",
                    "high",
                    "harness calls an unsafe/unchecked target API or helper; verify caller obligations",
                );
            }

            if callee.contains("null") {
                self.add(
                    node,
                    "null-pointer-construction",
                    "high",
                    "harness constructs a null pointer",
                );
            }

            if callee.contains("nonnull::new_unchecked") {
                self.add(
                    node,
                    "nonnull-new-unchecked",
                    "high",
                    "harness constructs NonNull using unchecked API",
                );
            }

            if callee.contains("from_raw_parts") || callee.contains("from_raw_parts_mut") {
                self.add(
                    node,
                    "from-raw-parts",
                    "high",
                    "harness constructs a slice from raw parts",
                );
            }

            if callee.contains("vec::from_raw_parts") {
                self.add(
                    node,
                    "vec-from-raw-parts",
                    "high",
                    "harness reconstructs Vec from raw parts",
                );
            }

            if callee.contains("box::from_raw") {
                self.add(
                    node,
                    "box-from-raw",
                    "high",
                    "harness reconstructs ownership from a raw pointer",
                );
            }

            if callee.contains("transmute") {
                self.add(
                    node,
                    "transmute-in-harness",
                    "high",
                    "harness performs transmute directly",
                );
            }

            if callee.contains("assume_init") {
                self.add(
                    node,
                    "assume-init-in-harness",
                    "high",
                    "harness assumes MaybeUninit initialized state",
                );
            }

            if callee.contains("copy_nonoverlapping") || callee.contains("ptr::write") || callee.contains("ptr::read") {
                self.add(
                    node,
                    "raw-pointer-primitive",
                    "high",
                    "harness directly performs raw pointer primitive operation",
                );
            }
        }

        visit::visit_expr_call(self, node);
    }


    fn visit_expr_unary(&mut self, node: &'ast ExprUnary) {
        if matches!(node.op, UnOp::Deref(_)) {
            self.add(
                node,
                "raw-deref-in-harness-candidate",
                "high",
                "harness dereferences through unary *; verify this is not constructing invalid target state",
            );
        }
        visit::visit_expr_unary(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();

        match method.as_str() {
            "unwrap" | "expect" => {
                self.add(
                    node,
                    "unwrap-like-in-harness",
                    "medium",
                    "harness itself may panic before target exploration",
                );
            }
            "set_len" => {
                self.add(
                    node,
                    "set-len-in-harness",
                    "high",
                    "harness mutates container length unsafely",
                );
            }
            "assume_init" => {
                self.add(
                    node,
                    "assume-init-in-harness",
                    "high",
                    "harness assumes MaybeUninit initialized state",
                );
            }
            _ => {}
        }

        visit::visit_expr_method_call(self, node);
    }
}