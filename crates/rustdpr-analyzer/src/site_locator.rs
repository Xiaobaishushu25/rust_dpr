use anyhow::{Context, Result};
use rustdpr_core::{
    DangerousKind, DangerousSite, FunctionCallEdge, FunctionIndex, FunctionSummary, PanicKind,
    PanicSite, SiteMap, SpanInfo, RUSTDPR_SCHEMA_VERSION,
};
use std::fs;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Expr, ExprCall, ExprIndex, ExprMethodCall, ExprPath, ExprUnsafe, File, ForeignItem, Item,
    ItemFn, ItemForeignMod,
};
use walkdir::WalkDir;

pub fn analyze_crate(crate_root: &Path) -> Result<(SiteMap, FunctionIndex)> {
    let mut site_map = SiteMap {
        schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
        crate_root: crate_root.display().to_string(),
        dangerous_sites: vec![],
        panic_sites: vec![],
    };
    let mut function_index = FunctionIndex::default();

    let rs_files = collect_rs_files(crate_root)?;
    for file_path in rs_files {
        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("failed to read {}", file_path.display()))?;
        let ast: File = syn::parse_file(&content)
            .with_context(|| format!("failed to parse {}", file_path.display()))?;

        let mut visitor = SiteAndCallVisitor::new(file_path.clone(), &content);
        visitor.visit_file(&ast);

        site_map.dangerous_sites.extend(visitor.dangerous_sites);
        site_map.panic_sites.extend(visitor.panic_sites);
        function_index.functions.extend(visitor.functions);
        function_index.call_edges.extend(visitor.call_edges);
    }

    Ok((site_map, function_index))
}

fn collect_rs_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = vec![];
    for entry in WalkDir::new(root) {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().map(|x| x == "rs").unwrap_or(false) {
            files.push(path.to_path_buf());
        }
    }
    Ok(files)
}

struct SiteAndCallVisitor {
    file_path: PathBuf,
    dangerous_sites: Vec<DangerousSite>,
    panic_sites: Vec<PanicSite>,
    functions: Vec<FunctionSummary>,
    call_edges: Vec<FunctionCallEdge>,
    current_fn: Option<String>,
    dangerous_counter: usize,
    panic_counter: usize,
}

impl SiteAndCallVisitor {
    fn new(file_path: PathBuf, _source: &str) -> Self {
        Self {
            file_path,
            dangerous_sites: vec![],
            panic_sites: vec![],
            functions: vec![],
            call_edges: vec![],
            current_fn: None,
            dangerous_counter: 0,
            panic_counter: 0,
        }
    }

    fn next_dangerous_id(&mut self) -> String {
        self.dangerous_counter += 1;
        format!("S{:04}", self.dangerous_counter)
    }

    fn next_panic_id(&mut self) -> String {
        self.panic_counter += 1;
        format!("P{:04}", self.panic_counter)
    }

    fn span_info<T: Spanned>(&self, node: &T) -> SpanInfo {
        let span = node.span();
        let start = span.start();
        let end = span.end();
        SpanInfo {
            file: self.file_path.display().to_string(),
            line_start: start.line,
            line_end: end.line,
        }
    }

    fn enclosing_fn_name(&self) -> String {
        self.current_fn
            .clone()
            .unwrap_or_else(|| "crate::root".to_string())
    }

    fn add_dangerous<T: Spanned>(
        &mut self,
        node: &T,
        kind: DangerousKind,
        rule: &str,
        confidence: &str,
        weight: f32,
    ) {
        let site = DangerousSite {
            site_id: self.next_dangerous_id(),
            kind,
            kind_weight: weight,
            enclosing_fn: self.enclosing_fn_name(),
            span: self.span_info(node),
            matched_by_rule: rule.to_string(),
            confidence: confidence.to_string(),
            obligation: None,
            macro_expanded: false,
            generic_context: None,
            ffi_abi: None,
        };
        self.dangerous_sites.push(site);
    }

    fn add_panic<T: Spanned>(&mut self, node: &T, kind: PanicKind, rule: &str) {
        let site = PanicSite {
            panic_id: self.next_panic_id(),
            kind,
            enclosing_fn: self.enclosing_fn_name(),
            span: self.span_info(node),
            matched_by_rule: rule.to_string(),
        };
        self.panic_sites.push(site);
    }

    fn expr_path_to_string(expr: &ExprPath) -> String {
        expr.path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::")
    }

    fn record_call(&mut self, callee: String) {
        if let Some(current_fn) = self.current_fn.clone() {
            self.call_edges.push(FunctionCallEdge {
                caller: current_fn,
                callee,
            });
        }
    }
}

impl<'ast> Visit<'ast> for SiteAndCallVisitor {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let fn_name = node.sig.ident.to_string();
        let old_fn = self.current_fn.clone();
        self.current_fn = Some(fn_name.clone());

        let span = self.span_info(node);
        self.functions.push(FunctionSummary {
            function_id: fn_name.clone(),
            is_public: matches!(node.vis, syn::Visibility::Public(_)),
            file: self.file_path.display().to_string(),
            line_start: span.line_start,
            line_end: span.line_end,
        });

        if node.sig.unsafety.is_some() {
            self.add_dangerous(node, DangerousKind::UnsafeFn, "unsafe-fn", "high", 1.0);
        }

        visit::visit_item_fn(self, node);
        self.current_fn = old_fn;
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        self.add_dangerous(node, DangerousKind::UnsafeBlock, "unsafe-block", "high", 1.0);
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast ItemForeignMod) {
        self.add_dangerous(node, DangerousKind::FfiDeclaration, "ffi-foreign-mod", "high", 0.9);

        let abi = node.abi.name.as_ref().map(|x| x.value()).unwrap_or_else(|| "unknown".into());
        if abi.contains("unwind") {
            self.add_dangerous(node, DangerousKind::FfiBoundary, "ffi-unwind-boundary", "high", 1.0);
        }

        for item in &node.items {
            if let ForeignItem::Fn(f) = item {
                self.add_dangerous(f, DangerousKind::FfiDeclaration, "ffi-foreign-fn", "high", 0.9);
            }
        }
        visit::visit_item_foreign_mod(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        self.add_dangerous(node, DangerousKind::IndexingCandidate, "index-expression", "medium", 0.2);
        self.add_panic(node, PanicKind::IndexingPanicCandidate, "index-expression");
        visit::visit_expr_index(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(expr_path) = &*node.func {
            let callee = Self::expr_path_to_string(expr_path);
            if !callee.is_empty() {
                self.record_call(callee.clone());
            }

            let lower = callee.to_lowercase();

            if lower.ends_with("panic") || lower == "panic" {
                self.add_panic(node, PanicKind::PanicMacro, "panic-call");
            }
            if lower.contains("transmute_copy") {
                self.add_dangerous(node, DangerousKind::TransmuteCopy, "transmute-copy", "high", 1.0);
            } else if lower.contains("transmute") {
                self.add_dangerous(node, DangerousKind::Transmute, "transmute", "high", 1.0);
            }
            if lower.contains("alloc") {
                self.add_dangerous(node, DangerousKind::ManualAllocCandidate, "alloc-call", "medium", 0.8);
            }
            if lower.contains("dealloc") || lower.contains("free") {
                self.add_dangerous(node, DangerousKind::ManualFreeCandidate, "free-call", "medium", 0.8);
            }
            if lower.contains("from_raw_parts_mut") || lower.contains("from_raw_parts") {
                self.add_dangerous(node, DangerousKind::FromRawParts, "from-raw-parts", "high", 1.0);
            }
            if lower.contains("box::from_raw") {
                self.add_dangerous(node, DangerousKind::BoxFromRaw, "box-from-raw", "high", 1.0);
            }
            if lower.contains("box::into_raw") {
                self.add_dangerous(node, DangerousKind::BoxIntoRaw, "box-into-raw", "medium", 0.8);
            }
            if lower.contains("copy_nonoverlapping") {
                self.add_dangerous(node, DangerousKind::CopyNonOverlappingCandidate, "copy-nonoverlapping", "high", 1.0);
            }
            if lower.contains("ptr::read") {
                self.add_dangerous(node, DangerousKind::PtrReadCandidate, "ptr-read", "medium", 0.8);
            }
            if lower.contains("ptr::write") {
                self.add_dangerous(node, DangerousKind::PtrWriteCandidate, "ptr-write", "medium", 0.8);
            }
            if lower.contains("forget") {
                self.add_dangerous(node, DangerousKind::MemForget, "mem-forget", "medium", 0.6);
            }
        }

        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        self.record_call(method.clone());
        match method.as_str() {
            "unwrap" => self.add_panic(node, PanicKind::UnwrapLike, "unwrap-like"),
            "expect" => self.add_panic(node, PanicKind::ExpectLike, "expect-like"),
            _ => {}
        }

        visit::visit_expr_method_call(self, node);
    }

    fn visit_item(&mut self, node: &'ast Item) {
        if let Item::Macro(m) = node {
            let name = m
                .mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            match name.as_str() {
                "panic" => self.add_panic(node, PanicKind::PanicMacro, "panic-macro"),
                "assert" | "assert_eq" | "assert_ne" => {
                    self.add_panic(node, PanicKind::AssertMacro, "assert-macro")
                }
                "todo" => self.add_panic(node, PanicKind::TodoMacro, "todo-macro"),
                "unimplemented" => {
                    self.add_panic(node, PanicKind::UnimplementedMacro, "unimplemented-macro")
                }
                _ => {}
            }
        }
        visit::visit_item(self, node);
    }
}