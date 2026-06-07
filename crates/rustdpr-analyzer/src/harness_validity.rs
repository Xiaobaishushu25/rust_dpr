use anyhow::{Context, Result};
use rustdpr_core::{
    HarnessValidityReport, RUSTDPR_SCHEMA_VERSION, ValidityEvidence, ValidityStatus,
};
use std::collections::HashSet;
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

        // syn 普通 visitor 不会深入解析 fuzz_target!(|data| { ... }) 的宏 token。
        // 所以这里保留文本级 fallback，但必须避免误扫 use/import/module/crate name。
        visitor.scan_source_fallback();

        evidence.extend(visitor.evidence);
    }

    dedup_evidence(&mut evidence);

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

    fn path_segments(expr: &ExprPath) -> Vec<String> {
        expr.path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect()
    }

    fn path_to_string(expr: &ExprPath) -> String {
        Self::path_segments(expr).join("::")
    }

    fn path_last_segment_is(expr: &ExprPath, name: &str) -> bool {
        expr.path
            .segments
            .last()
            .map(|seg| seg.ident.to_string() == name)
            .unwrap_or(false)
    }

    fn path_last_segment_contains(expr: &ExprPath, needle: &str) -> bool {
        expr.path
            .segments
            .last()
            .map(|seg| seg.ident.to_string().contains(needle))
            .unwrap_or(false)
    }

    fn path_has_segment_ignore_case(expr: &ExprPath, name: &str) -> bool {
        expr.path
            .segments
            .iter()
            .any(|seg| seg.ident.to_string().eq_ignore_ascii_case(name))
    }

    fn is_manual_trace_hit(expr: &ExprPath) -> bool {
        let callee = Self::path_to_string(expr).to_lowercase();

        callee == "hit" || callee == "rustdpr_trace::hit" || callee.ends_with("::hit")
    }

    fn is_target_unsafe_or_unchecked_call(expr: &ExprPath) -> bool {
        let last = expr
            .path
            .segments
            .last()
            .map(|seg| seg.ident.to_string())
            .unwrap_or_default();

        last.starts_with("unsafe_") || last.contains("unchecked")
    }

    fn is_null_pointer_constructor(expr: &ExprPath) -> bool {
        Self::path_last_segment_is(expr, "null") || Self::path_last_segment_is(expr, "null_mut")
    }

    fn is_nonnull_new_unchecked(expr: &ExprPath) -> bool {
        Self::path_last_segment_is(expr, "new_unchecked")
            && Self::path_has_segment_ignore_case(expr, "NonNull")
    }

    fn is_from_raw_parts(expr: &ExprPath) -> bool {
        Self::path_last_segment_is(expr, "from_raw_parts")
            || Self::path_last_segment_is(expr, "from_raw_parts_mut")
    }

    fn is_vec_from_raw_parts(expr: &ExprPath) -> bool {
        Self::path_last_segment_is(expr, "from_raw_parts")
            && Self::path_has_segment_ignore_case(expr, "Vec")
    }

    fn is_box_from_raw(expr: &ExprPath) -> bool {
        Self::path_last_segment_is(expr, "from_raw")
            && Self::path_has_segment_ignore_case(expr, "Box")
    }

    fn is_transmute_call(expr: &ExprPath) -> bool {
        Self::path_last_segment_is(expr, "transmute")
    }

    fn is_assume_init_call(expr: &ExprPath) -> bool {
        Self::path_last_segment_is(expr, "assume_init")
    }

    fn is_raw_pointer_primitive(expr: &ExprPath) -> bool {
        let last = expr
            .path
            .segments
            .last()
            .map(|seg| seg.ident.to_string())
            .unwrap_or_default();

        let is_ptr_namespace = Self::path_has_segment_ignore_case(expr, "ptr");

        is_ptr_namespace
            && matches!(
                last.as_str(),
                "read"
                    | "write"
                    | "copy_nonoverlapping"
                    | "copy"
                    | "copy_to"
                    | "copy_to_nonoverlapping"
            )
    }

    fn scan_source_fallback(&mut self) {
        let lines: Vec<String> = self.source.lines().map(|s| s.to_string()).collect();

        for (idx, raw) in lines.iter().enumerate() {
            let line_no = idx + 1;

            let Some(code) = normalize_code_line(raw) else {
                continue;
            };

            let lower = code.to_lowercase();

            if looks_like_null_pointer_construction(&lower) {
                self.add_textual(
                    line_no,
                    "null-pointer-construction",
                    "high",
                    "harness constructs a null pointer",
                    &code,
                );
            }

            if looks_like_direct_unsafe_block(&lower) {
                self.add_textual(
                    line_no,
                    "direct-unsafe-block",
                    "high",
                    "harness contains an explicit unsafe block",
                    &code,
                );
            }

            if looks_like_from_raw_parts(&lower) {
                self.add_textual(
                    line_no,
                    "from-raw-parts",
                    "high",
                    "harness constructs a slice from raw parts",
                    &code,
                );
            }

            if looks_like_transmute_call(&lower) {
                self.add_textual(
                    line_no,
                    "transmute-in-harness",
                    "high",
                    "harness performs transmute directly",
                    &code,
                );
            }

            if looks_like_assume_init_call(&lower) {
                self.add_textual(
                    line_no,
                    "assume-init-in-harness",
                    "high",
                    "harness assumes MaybeUninit initialized state",
                    &code,
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
            if Self::is_manual_trace_hit(expr_path) {
                self.add(
                    node,
                    "manual-hit-in-harness",
                    "medium",
                    "harness manually emits a dangerous-site hit; prefer library-side site ids",
                );
            }

            if Self::is_target_unsafe_or_unchecked_call(expr_path) {
                self.add(
                    node,
                    "target-api-unsafe-or-unchecked-call",
                    "high",
                    "harness calls an unsafe/unchecked target API or helper; verify caller obligations",
                );
            }

            if Self::is_null_pointer_constructor(expr_path) {
                self.add(
                    node,
                    "null-pointer-construction",
                    "high",
                    "harness constructs a null pointer",
                );
            }

            if Self::is_nonnull_new_unchecked(expr_path) {
                self.add(
                    node,
                    "nonnull-new-unchecked",
                    "high",
                    "harness constructs NonNull using unchecked API",
                );
            }

            if Self::is_from_raw_parts(expr_path) {
                self.add(
                    node,
                    "from-raw-parts",
                    "high",
                    "harness constructs a slice from raw parts",
                );
            }

            if Self::is_vec_from_raw_parts(expr_path) {
                self.add(
                    node,
                    "vec-from-raw-parts",
                    "high",
                    "harness reconstructs Vec from raw parts",
                );
            }

            if Self::is_box_from_raw(expr_path) {
                self.add(
                    node,
                    "box-from-raw",
                    "high",
                    "harness reconstructs ownership from a raw pointer",
                );
            }

            if Self::is_transmute_call(expr_path) {
                self.add(
                    node,
                    "transmute-in-harness",
                    "high",
                    "harness performs transmute directly",
                );
            }

            if Self::is_assume_init_call(expr_path) {
                self.add(
                    node,
                    "assume-init-in-harness",
                    "high",
                    "harness assumes MaybeUninit initialized state",
                );
            }

            if Self::is_raw_pointer_primitive(expr_path) {
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

fn normalize_code_line(raw: &str) -> Option<String> {
    let mut s = raw.trim().to_string();

    if let Some(pos) = s.find("//") {
        s.truncate(pos);
    }

    let s = s.trim();

    if s.is_empty() {
        return None;
    }

    if s.starts_with("//")
        || s.starts_with("#[")
        || s.starts_with("use ")
        || s.starts_with("pub use ")
        || s.starts_with("extern crate ")
        || s.starts_with("mod ")
        || s.starts_with("pub mod ")
    {
        return None;
    }

    Some(s.to_string())
}

fn looks_like_direct_unsafe_block(line: &str) -> bool {
    line.contains("unsafe {") || line.contains("unsafe{")
}

fn looks_like_null_pointer_construction(line: &str) -> bool {
    line.contains("std::ptr::null::<")
        || line.contains("std::ptr::null(")
        || line.contains("ptr::null::<")
        || line.contains("ptr::null(")
        || line.contains("std::ptr::null_mut::<")
        || line.contains("std::ptr::null_mut(")
        || line.contains("ptr::null_mut::<")
        || line.contains("ptr::null_mut(")
}

fn looks_like_from_raw_parts(line: &str) -> bool {
    line.contains("from_raw_parts(")
        || line.contains("from_raw_parts::<")
        || line.contains("from_raw_parts_mut(")
        || line.contains("from_raw_parts_mut::<")
        || line.contains("::from_raw_parts(")
        || line.contains("::from_raw_parts::<")
        || line.contains("::from_raw_parts_mut(")
        || line.contains("::from_raw_parts_mut::<")
}

fn looks_like_transmute_call(line: &str) -> bool {
    line.contains("std::mem::transmute(")
        || line.contains("std::mem::transmute::<")
        || line.contains("mem::transmute(")
        || line.contains("mem::transmute::<")
        || line.contains("::transmute(")
        || line.contains("::transmute::<")
        || line.starts_with("transmute(")
        || line.starts_with("transmute::<")
}

fn looks_like_assume_init_call(line: &str) -> bool {
    line.contains(".assume_init(")
        || line.contains(".assume_init::<")
        || line.contains("::assume_init(")
        || line.contains("::assume_init::<")
        || line.starts_with("assume_init(")
        || line.starts_with("assume_init::<")
}

fn dedup_evidence(evidence: &mut Vec<ValidityEvidence>) {
    let mut seen = HashSet::new();

    evidence.retain(|e| {
        seen.insert((
            e.rule.clone(),
            e.file.clone(),
            e.line,
            e.span_end_line,
            e.snippet.clone().unwrap_or_default(),
        ))
    });
}
