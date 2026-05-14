use anyhow::{Context, Result};
use rustdpr_core::{HarnessValidityReport, ValidityEvidence, ValidityStatus};
use std::fs;
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprCall, ExprMethodCall, ExprPath, ExprUnsafe, File};
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
            evidence: vec![],
        };
        visitor.visit_file(&ast);
        evidence.extend(visitor.evidence);
    }

    let status = if evidence.is_empty() {
        ValidityStatus::LikelyValid
    } else if evidence.iter().any(|e| {
        e.rule == "direct-unsafe-block"
            || e.rule == "null-pointer-construction"
            || e.rule == "from-raw-parts"
    }) {
        ValidityStatus::LikelyMisuse
    } else {
        ValidityStatus::Unknown
    };

    Ok(HarnessValidityReport {
        harness_path: harness_path.display().to_string(),
        status,
        evidence,
    })
}

struct HarnessVisitor {
    file: String,
    evidence: Vec<ValidityEvidence>,
}

impl HarnessVisitor {
    fn line_of<T: Spanned>(&self, node: &T) -> usize {
        node.span().start().line
    }

    fn add<T: Spanned>(&mut self, node: &T, rule: &str, message: &str) {
        self.evidence.push(ValidityEvidence {
            rule: rule.to_string(),
            message: message.to_string(),
            file: self.file.clone(),
            line: self.line_of(node),
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
}

impl<'ast> Visit<'ast> for HarnessVisitor {
    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        self.add(
            node,
            "direct-unsafe-block",
            "harness contains an explicit unsafe block",
        );
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let syn::Expr::Path(expr_path) = &*node.func {
            let callee = Self::path_to_string(expr_path);

            if callee.contains("null") {
                self.add(
                    node,
                    "null-pointer-construction",
                    "harness constructs a null pointer",
                );
            }
            if callee.contains("from_raw_parts") || callee.contains("from_raw_parts_mut") {
                self.add(
                    node,
                    "from-raw-parts",
                    "harness constructs a slice from raw parts",
                );
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();

        if method == "unwrap" || method == "expect" {
            self.add(
                node,
                "unwrap-like-in-harness",
                "harness itself may panic before target exploration",
            );
        }
        visit::visit_expr_method_call(self, node);
    }
}