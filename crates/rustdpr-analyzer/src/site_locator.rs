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
    ItemFn, ItemForeignMod, Visibility,
};
use walkdir::{DirEntry, WalkDir};

pub fn analyze_crate(crate_root: &Path) -> Result<(SiteMap, FunctionIndex)> {
    let mut site_map = SiteMap {
        schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
        crate_root: crate_root.display().to_string(),
        dangerous_sites: vec![],
        panic_sites: vec![],
    };
    let mut function_index = FunctionIndex::default();

    let rs_files = collect_rs_files(crate_root)?;
    let crate_root = crate_root.canonicalize().unwrap_or_else(|_| crate_root.to_path_buf());

    let mut global_site_counter = 0usize;
    let mut global_panic_counter = 0usize;

    for file_path in rs_files {
        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("failed to read {}", file_path.display()))?;
        let ast: File = syn::parse_file(&content)
            .with_context(|| format!("failed to parse {}", file_path.display()))?;

        let mut visitor = SiteAndCallVisitor::new(
            crate_root.clone(),
            file_path.clone(),
            &mut global_site_counter,
            &mut global_panic_counter,
        );
        visitor.visit_file(&ast);

        site_map.dangerous_sites.extend(visitor.dangerous_sites);
        site_map.panic_sites.extend(visitor.panic_sites);
        function_index.functions.extend(visitor.functions);
        function_index.call_edges.extend(visitor.call_edges);
    }

    dedup_call_edges(&mut function_index.call_edges);

    Ok((site_map, function_index))
}

fn should_skip_dir(entry: &DirEntry) -> bool {
    let path = entry.path();
    let name = path.file_name().and_then(|x| x.to_str()).unwrap_or_default();
    matches!(name, "target" | ".git" | "artifacts" | "data" | "node_modules")
}

fn collect_rs_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = vec![];
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !should_skip_dir(e))
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().map(|x| x == "rs").unwrap_or(false) {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn dedup_call_edges(edges: &mut Vec<FunctionCallEdge>) {
    edges.sort_by(|a, b| {
        a.caller
            .cmp(&b.caller)
            .then_with(|| a.callee.cmp(&b.callee))
    });
    edges.dedup_by(|a, b| a.caller == b.caller && a.callee == b.callee);
}

struct SiteAndCallVisitor<'a> {
    crate_root: PathBuf,
    file_path: PathBuf,
    dangerous_sites: Vec<DangerousSite>,
    panic_sites: Vec<PanicSite>,
    functions: Vec<FunctionSummary>,
    call_edges: Vec<FunctionCallEdge>,
    current_fn: Option<String>,
    global_site_counter: &'a mut usize,
    global_panic_counter: &'a mut usize,
}

impl<'a> SiteAndCallVisitor<'a> {
    fn new(
        crate_root: PathBuf,
        file_path: PathBuf,
        global_site_counter: &'a mut usize,
        global_panic_counter: &'a mut usize,
    ) -> Self {
        Self {
            crate_root,
            file_path,
            dangerous_sites: vec![],
            panic_sites: vec![],
            functions: vec![],
            call_edges: vec![],
            current_fn: None,
            global_site_counter,
            global_panic_counter,
        }
    }

    fn next_dangerous_id(&mut self) -> String {
        *self.global_site_counter += 1;
        format!("S{:05}", *self.global_site_counter)
    }

    fn next_panic_id(&mut self) -> String {
        *self.global_panic_counter += 1;
        format!("P{:05}", *self.global_panic_counter)
    }

    fn span_info<T: Spanned>(&self, node: &T) -> SpanInfo {
        let span = node.span();
        let start = span.start();
        let end = span.end();
        SpanInfo {
            file: self.rel_file_path(),
            line_start: start.line,
            line_end: end.line,
        }
    }

    fn rel_file_path(&self) -> String {
        self.file_path
            .strip_prefix(&self.crate_root)
            .unwrap_or(&self.file_path)
            .display()
            .to_string()
    }

    fn module_prefix(&self) -> String {
        let rel = self
            .file_path
            .strip_prefix(&self.crate_root)
            .unwrap_or(&self.file_path)
            .to_string_lossy()
            .replace('\\', "/");

        let rel = rel.strip_suffix(".rs").unwrap_or(&rel);
        if rel == "src/lib" || rel == "src/main" {
            "crate".to_string()
        } else if let Some(stripped) = rel.strip_prefix("src/") {
            format!("crate::{}", stripped.replace('/', "::"))
        } else {
            format!("crate::{}", rel.replace('/', "::"))
        }
    }

    fn stable_fn_name(&self, local_name: &str) -> String {
        format!("{}::{}", self.module_prefix(), local_name)
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
        let obligation = match kind {
            DangerousKind::UnsafeFn => Some("caller must uphold safety preconditions".to_string()),
            DangerousKind::UnsafeBlock => Some("unsafe block may bypass Rust safety guarantees".to_string()),
            DangerousKind::FfiDeclaration | DangerousKind::FfiBoundary => {
                Some("FFI boundary may rely on ABI/unwind/ownership invariants".to_string())
            }
            DangerousKind::FromRawParts
            | DangerousKind::BoxFromRaw
            | DangerousKind::BoxIntoRaw
            | DangerousKind::PtrReadCandidate
            | DangerousKind::PtrWriteCandidate
            | DangerousKind::RawDerefCandidate => {
                Some("raw-pointer-derived operation requires pointer validity".to_string())
            }
            _ => None,
        };

        let site = DangerousSite {
            site_id: self.next_dangerous_id(),
            kind,
            kind_weight: weight,
            enclosing_fn: self.enclosing_fn_name(),
            span: self.span_info(node),
            matched_by_rule: rule.to_string(),
            confidence: confidence.to_string(),
            obligation,
            macro_expanded: false,
            generic_context: None,
            ffi_abi: None,
            site_group: None,
            source_level: Some("ast-heuristic".to_string()),
            review_note: None,
        };
        self.dangerous_sites.push(site);
    }

    fn add_dangerous_with_abi<T: Spanned>(
        &mut self,
        node: &T,
        kind: DangerousKind,
        rule: &str,
        confidence: &str,
        weight: f32,
        abi: Option<String>,
    ) {
        let mut site = DangerousSite {
            site_id: self.next_dangerous_id(),
            kind,
            kind_weight: weight,
            enclosing_fn: self.enclosing_fn_name(),
            span: self.span_info(node),
            matched_by_rule: rule.to_string(),
            confidence: confidence.to_string(),
            obligation: Some("FFI declaration or boundary requires ABI-compatible behavior".to_string()),
            macro_expanded: false,
            generic_context: None,
            ffi_abi: abi,
            site_group: Some("ffi".to_string()),
            source_level: Some("ast-heuristic".to_string()),
            review_note: None,
        };
        if matches!(site.kind, DangerousKind::FfiBoundary) {
            site.review_note = Some("check panic=abort/unwind behavior around this ABI".to_string());
        }
        self.dangerous_sites.push(site);
    }

    fn add_panic<T: Spanned>(&mut self, node: &T, kind: PanicKind, rule: &str) {
        let site = PanicSite {
            panic_id: self.next_panic_id(),
            kind,
            enclosing_fn: self.enclosing_fn_name(),
            span: self.span_info(node),
            matched_by_rule: rule.to_string(),
            message_pattern: None,
            runtime_generated: false,
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
        if callee.is_empty() {
            return;
        }
        if let Some(current_fn) = self.current_fn.clone() {
            self.call_edges.push(FunctionCallEdge {
                caller: current_fn,
                callee,
            });
        }
    }

    fn maybe_record_special_call(&mut self, node: &ExprCall, callee: &str) {
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
        if lower.contains("dealloc") || lower.ends_with("free") || lower.contains("free::") {
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
        if lower.contains("maybeuninit") {
            self.add_dangerous(node, DangerousKind::MaybeUninitCandidate, "maybeuninit", "medium", 0.7);
        }
        if lower.contains("manuallydrop") {
            self.add_dangerous(node, DangerousKind::ManuallyDropCandidate, "manuallydrop", "medium", 0.7);
        }
        if lower.contains("set_len") {
            self.add_dangerous(node, DangerousKind::DropSensitiveCandidate, "vec-set-len", "medium", 0.8);
        }
    }
}

impl<'ast> Visit<'ast> for SiteAndCallVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let fn_name = self.stable_fn_name(&node.sig.ident.to_string());
        let old_fn = self.current_fn.clone();
        self.current_fn = Some(fn_name.clone());

        let span = self.span_info(node);
        self.functions.push(FunctionSummary {
            function_id: fn_name.clone(),
            is_public: matches!(node.vis, Visibility::Public(_)),
            file: self.rel_file_path(),
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
        let abi = node
            .abi
            .name
            .as_ref()
            .map(|x| x.value())
            .unwrap_or_else(|| "unknown".into());

        self.add_dangerous_with_abi(
            node,
            DangerousKind::FfiDeclaration,
            "ffi-foreign-mod",
            "high",
            0.9,
            Some(abi.clone()),
        );

        if abi.contains("unwind") {
            self.add_dangerous_with_abi(
                node,
                DangerousKind::FfiBoundary,
                "ffi-unwind-boundary",
                "high",
                1.0,
                Some(abi.clone()),
            );
        }

        for item in &node.items {
            if let ForeignItem::Fn(f) = item {
                self.add_dangerous_with_abi(
                    f,
                    DangerousKind::FfiDeclaration,
                    "ffi-foreign-fn",
                    "high",
                    0.9,
                    Some(abi.clone()),
                );
            }
        }

        visit::visit_item_foreign_mod(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        self.add_dangerous(
            node,
            DangerousKind::IndexingCandidate,
            "index-expression",
            "medium",
            0.2,
        );
        self.add_panic(node, PanicKind::IndexingPanicCandidate, "index-expression");
        visit::visit_expr_index(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(expr_path) = &*node.func {
            let callee = Self::expr_path_to_string(expr_path);
            if !callee.is_empty() {
                self.record_call(callee.clone());
                self.maybe_record_special_call(node, &callee);
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
            "assume_init" => {
                self.add_dangerous(node, DangerousKind::MaybeUninitCandidate, "assume-init", "high", 0.9)
            }
            "set_len" => {
                self.add_dangerous(node, DangerousKind::DropSensitiveCandidate, "set-len", "medium", 0.8)
            }
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