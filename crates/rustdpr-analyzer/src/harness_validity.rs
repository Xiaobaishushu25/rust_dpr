use anyhow::{Context, Result};
use rustdpr_core::{HarnessValidityReport, ValidityEvidence, ValidityStatus};
use std::fs;
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprCall, ExprMethodCall, ExprPath, ExprUnsafe, File};
use walkdir::WalkDir;

/// 分析测试工具(harness)的有效性
/// 
/// 通过静态分析检查测试代码中是否存在可能导致误判的模式，
/// 如直接使用unsafe块、空指针构造等危险操作。
pub fn analyze_harness_validity(harness_path: &Path) -> Result<HarnessValidityReport> {
    let mut evidence = Vec::new(); // 存储发现的违规证据

    // 确定要分析的Rust源文件列表
    let files = if harness_path.is_dir() {
        // 如果是目录，递归查找所有.rs文件
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
        // 如果是单个文件，直接加入列表
        vec![harness_path.to_path_buf()]
    };

    // 遍历每个文件进行AST分析
    for file in files {
        let content = fs::read_to_string(&file)
            .with_context(|| format!("failed to read harness {}", file.display()))?;
        let ast: File = syn::parse_file(&content)
            .with_context(|| format!("failed to parse harness {}", file.display()))?;
        let mut visitor = HarnessVisitor {
            file: file.display().to_string(),
            evidence: vec![],
        };
        visitor.visit_file(&ast); // 访问AST节点收集证据
        evidence.extend(visitor.evidence);
    }

    // 提取所有违反的规则名称
    let violated_patterns: Vec<String> = evidence.iter().map(|e| e.rule.clone()).collect();

    // 根据发现的证据确定有效性状态
    let status = if evidence.is_empty() {
        ValidityStatus::LikelyValid // 没有发现问题，可能有效
    } else if evidence.iter().any(|e| {
        // 发现高风险模式，判定为可能的误用
        e.rule == "direct-unsafe-block"
            || e.rule == "null-pointer-construction"
            || e.rule == "from-raw-parts"
            || e.rule == "box-from-raw"
    }) {
        ValidityStatus::LikelyMisuse
    } else {
        ValidityStatus::Unknown // 发现其他问题，需要人工审查
    };

    // 如果状态未知，则需要人工审查
    let needs_manual_review = matches!(status, ValidityStatus::Unknown);

    // 构建并返回有效性报告
    Ok(HarnessValidityReport {
        harness_path: harness_path.display().to_string(),
        status,
        evidence,
        violated_patterns,
        needs_manual_review,
    })
}

/// AST访问者，用于检测测试工具中的潜在问题模式
struct HarnessVisitor {
    file: String,           // 当前分析的文件路径
    evidence: Vec<ValidityEvidence>, // 收集到的违规证据
}

impl HarnessVisitor {
    /// 获取语法节点的起始行号
    fn line_of<T: Spanned>(&self, node: &T) -> usize {
        node.span().start().line
    }

    /// 添加一条违规证据记录
    fn add<T: Spanned>(&mut self, node: &T, rule: &str, severity: &str, message: &str) {
        self.evidence.push(ValidityEvidence {
            rule: rule.to_string(),
            severity: severity.to_string(),
            message: message.to_string(),
            file: self.file.clone(),
            line: self.line_of(node),
        });
    }

    /// 将路径表达式转换为字符串形式（如 std::ptr::null）
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
    /// 访问unsafe块表达式，检测直接的unsafe使用
    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        self.add(
            node,
            "direct-unsafe-block",
            "high",
            "harness contains an explicit unsafe block",
        );
        visit::visit_expr_unsafe(self, node); // 继续访问子节点
    }

    /// 访问函数调用表达式，检测危险的指针操作
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let syn::Expr::Path(expr_path) = &*node.func {
            let callee = Self::path_to_string(expr_path).to_lowercase();

            // 检测空指针构造
            if callee.contains("null") {
                self.add(
                    node,
                    "null-pointer-construction",
                    "high",
                    "harness constructs a null pointer",
                );
            }

            // 检测从原始部分构造切片
            if callee.contains("from_raw_parts") || callee.contains("from_raw_parts_mut") {
                self.add(
                    node,
                    "from-raw-parts",
                    "high",
                    "harness constructs a slice from raw parts",
                );
            }

            // 检测从原始指针重建Box所有权
            if callee.contains("box::from_raw") {
                self.add(
                    node,
                    "box-from-raw",
                    "high",
                    "harness reconstructs ownership from a raw pointer",
                );
            }
        }

        visit::visit_expr_call(self, node); // 继续访问子节点
    }

    /// 访问方法调用表达式，检测可能导致提前panic的unwrap/expect调用
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if method == "unwrap" || method == "expect" {
            self.add(
                node,
                "unwrap-like-in-harness",
                "medium",
                "harness itself may panic before target exploration",
            );
        }
        visit::visit_expr_method_call(self, node); // 继续访问子节点
    }
}