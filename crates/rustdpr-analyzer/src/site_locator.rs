use anyhow::{Context, Result};
use rustdpr_core::{
    DangerousKind, DangerousSite, EvidenceStrength, FunctionCallEdge, FunctionIndex,
    FunctionSummary, PanicKind, PanicSite, RUSTDPR_SCHEMA_VERSION, SiteMap, SpanInfo,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Block, Expr, ExprCall, ExprIndex, ExprMacro, ExprMethodCall, ExprPath, ExprUnary, ExprUnsafe,
    File, ForeignItem, Item, ItemFn, ItemForeignMod, ItemImpl, ItemMod, PathArguments, Stmt,
    TraitItem, Type, UnOp, Visibility,
};
use walkdir::{DirEntry, WalkDir};

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub crate_name: Option<String>,
    pub source_origin: Option<String>,
    /// Optional site-id namespace. Keep this as None for wrapper/current-crate
    /// analysis so legacy benchmark traces that emit S00001/P00001 still match.
    /// Dependency analysis sets this to the dependency crate name, e.g. bytes::S00001.
    pub site_id_prefix: Option<String>,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            crate_name: None,
            source_origin: Some("wrapper".to_string()),
            site_id_prefix: None,
        }
    }
}

pub fn analyze_crate(crate_root: &Path) -> Result<(SiteMap, FunctionIndex)> {
    analyze_crate_with_options(crate_root, AnalyzeOptions::default())
}

pub fn analyze_crate_with_options(
    crate_root: &Path,
    options: AnalyzeOptions,
) -> Result<(SiteMap, FunctionIndex)> {
    let crate_root = crate_root
        .canonicalize()
        .unwrap_or_else(|_| crate_root.to_path_buf());

    let mut site_map = SiteMap {
        schema_version: RUSTDPR_SCHEMA_VERSION.to_string(),
        crate_root: crate_root.display().to_string(),
        dangerous_sites: vec![],
        panic_sites: vec![],
        taxonomy: Default::default(),
    };
    let mut function_index = FunctionIndex::default();

    let rs_files = collect_rs_files(&crate_root)?;

    let mut global_site_counter = 0usize;
    let mut global_panic_counter = 0usize;

    for file_path in rs_files {
        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("failed to read {}", file_path.display()))?;
        let ast: File = syn::parse_file(&content)
            .with_context(|| format!("failed to parse {}", file_path.display()))?;

        let abi_functions = collect_abi_functions(&ast);

        let mut visitor = SiteAndCallVisitor::new(
            crate_root.clone(),
            file_path.clone(),
            &mut global_site_counter,
            &mut global_panic_counter,
            abi_functions,
            options.clone(),
        );
        visitor.visit_file(&ast);

        site_map.dangerous_sites.extend(visitor.dangerous_sites);
        site_map.panic_sites.extend(visitor.panic_sites);
        function_index.functions.extend(visitor.functions);
        function_index.call_edges.extend(visitor.call_edges);
    }

    dedup_call_edges(&mut function_index.call_edges);
    site_map.refresh_taxonomy();

    Ok((site_map, function_index))
}

pub fn merge_analysis_results(
    mut base_site_map: SiteMap,
    mut base_function_index: FunctionIndex,
    extra: Vec<(SiteMap, FunctionIndex)>,
) -> (SiteMap, FunctionIndex) {
    for (site_map, function_index) in extra {
        base_site_map.dangerous_sites.extend(site_map.dangerous_sites);
        base_site_map.panic_sites.extend(site_map.panic_sites);
        base_function_index.functions.extend(function_index.functions);
        base_function_index.call_edges.extend(function_index.call_edges);
    }

    dedup_call_edges(&mut base_function_index.call_edges);
    base_site_map.refresh_taxonomy();
    (base_site_map, base_function_index)
}

fn should_skip_dir(entry: &DirEntry) -> bool {
    let path = entry.path();
    let name = path
        .file_name()
        .and_then(|x| x.to_str())
        .unwrap_or_default();
    matches!(
        name,
        "target" | ".git" | "artifacts" | "data" | "node_modules"
    )
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
            files.push(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
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
    module_stack: Vec<String>,
    raw_ptr_locals: HashSet<String>,
    abi_functions: HashMap<String, AbiFunctionInfo>,
    global_site_counter: &'a mut usize,
    global_panic_counter: &'a mut usize,
    crate_name: Option<String>,
    source_origin: Option<String>,
    site_id_prefix: Option<String>,
}

impl<'a> SiteAndCallVisitor<'a> {
    fn new(
        crate_root: PathBuf,
        file_path: PathBuf,
        global_site_counter: &'a mut usize,
        global_panic_counter: &'a mut usize,
        abi_functions: HashMap<String, AbiFunctionInfo>,
        options: AnalyzeOptions,
    ) -> Self {
        Self {
            crate_root,
            file_path,
            dangerous_sites: vec![],
            panic_sites: vec![],
            functions: vec![],
            call_edges: vec![],
            current_fn: None,
            module_stack: vec![],
            raw_ptr_locals: HashSet::new(),
            abi_functions,
            global_site_counter,
            global_panic_counter,
            crate_name: options.crate_name,
            source_origin: options.source_origin,
            site_id_prefix: options.site_id_prefix,
        }
    }

    fn next_dangerous_id(&mut self) -> String {
        *self.global_site_counter += 1;
        match &self.site_id_prefix {
            Some(prefix) if !prefix.is_empty() => {
                format!("{}::S{:05}", prefix, *self.global_site_counter)
            }
            _ => format!("S{:05}", *self.global_site_counter),
        }
    }

    fn next_panic_id(&mut self) -> String {
        *self.global_panic_counter += 1;
        match &self.site_id_prefix {
            Some(prefix) if !prefix.is_empty() => {
                format!("{}::P{:05}", prefix, *self.global_panic_counter)
            }
            _ => format!("P{:05}", *self.global_panic_counter),
        }
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
            .replace('\\', "/")
    }

    fn file_module_base(&self) -> Vec<String> {
        let rel = self
            .file_path
            .strip_prefix(&self.crate_root)
            .unwrap_or(&self.file_path)
            .to_string_lossy()
            .replace('\\', "/");

        let rel = rel.strip_suffix(".rs").unwrap_or(&rel);

        if rel == "src/lib" || rel == "src/main" {
            return vec![];
        }

        if rel.ends_with("/mod") {
            let trimmed = rel.strip_suffix("/mod").unwrap_or(rel);
            if let Some(stripped) = trimmed.strip_prefix("src/") {
                return stripped
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
            }
        }

        if let Some(stripped) = rel.strip_prefix("src/") {
            return stripped
                .split('/')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
        }

        rel.split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }

    fn module_prefix(&self) -> String {
        let mut parts = self.file_module_base();
        parts.extend(self.module_stack.iter().cloned());
        let root = if self.site_id_prefix.is_some() {
            self.crate_name.as_deref().unwrap_or("dependency")
        } else {
            "crate"
        };

        if parts.is_empty() {
            root.to_string()
        } else {
            format!("{}::{}", root, parts.join("::"))
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

    fn source_root_string(&self) -> Option<String> {
        Some(self.crate_root.display().to_string())
    }

    fn add_dangerous<T: Spanned>(
        &mut self,
        node: &T,
        kind: DangerousKind,
        rule: &str,
        confidence: &str,
        evidence_strength: EvidenceStrength,
    ) {
        let obligation = match kind {
            DangerousKind::UnsafeFn => Some("caller must uphold safety preconditions".to_string()),
            DangerousKind::UnsafeBlock => {
                Some("unsafe block may bypass Rust safety guarantees".to_string())
            }
            DangerousKind::FfiDeclaration
            | DangerousKind::FfiCallCandidate
            | DangerousKind::FfiBoundary
            | DangerousKind::FfiUnwindBoundary => Some(
                "FFI boundary may rely on ABI, unwind, lifetime, and ownership invariants"
                    .to_string(),
            ),
            DangerousKind::FromRawParts
            | DangerousKind::VecFromRawParts
            | DangerousKind::BoxFromRaw
            | DangerousKind::BoxIntoRaw
            | DangerousKind::PtrReadCandidate
            | DangerousKind::PtrWriteCandidate
            | DangerousKind::RawDerefCandidate
            | DangerousKind::NonNullNewUnchecked => Some(
                "raw-pointer-derived operation requires pointer validity and aliasing invariants"
                    .to_string(),
            ),
            DangerousKind::AssumeInitCandidate | DangerousKind::MaybeUninitCandidate => {
                Some("initialization invariant must hold before reading value".to_string())
            }
            DangerousKind::SetLenCandidate | DangerousKind::DropSensitiveCandidate => {
                Some("container length/drop invariant must remain valid".to_string())
            }
            _ => None,
        };
        let category = kind.category();
        let weight = kind.default_weight();
        let site = DangerousSite {
            site_id: self.next_dangerous_id(),
            kind,
            kind_weight: weight,
            enclosing_fn: self.enclosing_fn_name(),
            span: self.span_info(node),
            matched_by_rule: rule.to_string(),
            confidence: confidence.to_string(),
            category,
            evidence_strength,
            obligation,
            macro_expanded: false,
            generic_context: None,
            ffi_abi: None,
            site_group: None,
            source_level: Some("ast-heuristic".to_string()),
            source_crate: self.crate_name.clone(),
            source_origin: self.source_origin.clone(),
            source_version: None,
            source_root: self.source_root_string(),
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
        evidence_strength: EvidenceStrength,
        abi: Option<String>,
    ) {
        let category = kind.category();
        let weight = kind.default_weight();
        let mut site = DangerousSite {
            site_id: self.next_dangerous_id(),
            kind,
            kind_weight: weight,
            enclosing_fn: self.enclosing_fn_name(),
            span: self.span_info(node),
            matched_by_rule: rule.to_string(),
            confidence: confidence.to_string(),
            category,
            evidence_strength,
            obligation: Some(
                "FFI declaration or boundary requires ABI-compatible behavior".to_string(),
            ),
            macro_expanded: false,
            generic_context: None,
            ffi_abi: abi,
            site_group: Some("ffi".to_string()),
            source_level: Some("ast-heuristic".to_string()),
            source_crate: self.crate_name.clone(),
            source_origin: self.source_origin.clone(),
            source_version: None,
            source_root: self.source_root_string(),
            review_note: None,
        };
        if matches!(
            site.kind,
            DangerousKind::FfiUnwindBoundary | DangerousKind::FfiBoundary
        ) {
            site.review_note =
                Some("check panic=abort/unwind behavior around this ABI".to_string());
        }
        self.dangerous_sites.push(site);
    }

    fn add_macro_dangerous<T: Spanned>(&mut self, node: &T, kind: DangerousKind, rule: &str) {
        let category = kind.category();
        let weight = kind.default_weight();
        let site_id = self.next_dangerous_id();
        let enclosing_fn = self.enclosing_fn_name();
        let span = self.span_info(node);

        self.dangerous_sites.push(DangerousSite {
            site_id,
            kind,
            kind_weight: weight,
            enclosing_fn,
            span,
            matched_by_rule: rule.to_string(),
            confidence: "medium".to_string(),
            category,
            evidence_strength: EvidenceStrength::Heuristic,
            obligation: Some(
                "macro may expand to unsafe or panic-bearing code; confirm with expanded source/MIR"
                    .to_string(),
            ),
            macro_expanded: true,
            generic_context: None,
            ffi_abi: None,
            site_group: Some("macro".to_string()),
            source_level: Some("ast-macro-call".to_string()),
            source_crate: self.crate_name.clone(),
            source_origin: self.source_origin.clone(),
            source_version: None,
            source_root: self.source_root_string(),
            review_note: Some(
                "AST-level macro call detected; exact expanded span requires cargo expand/rustc HIR"
                    .to_string(),
            ),
        });
    }

    fn add_panic<T: Spanned>(&mut self, node: &T, kind: PanicKind, rule: &str) {
        let panic_id = self.next_panic_id();
        let enclosing_fn = self.enclosing_fn_name();
        let span = self.span_info(node);

        self.panic_sites.push(PanicSite {
            panic_id,
            kind,
            enclosing_fn,
            span,
            matched_by_rule: rule.to_string(),
            message_pattern: None,
            runtime_generated: false,
            macro_expanded: rule.contains("macro"),
            evidence_strength: EvidenceStrength::Medium,
        });
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

    fn scan_unsafe_block_for_ffi_boundary(&self, block: &Block) -> Option<UnsafeBlockFfiSummary> {
        let mut scanner = UnsafeBlockFfiScanner {
            abi_functions: &self.abi_functions,
            summary: UnsafeBlockFfiSummary::default(),
        };

        scanner.visit_block(block);

        if scanner.summary.calls_abi_function {
            Some(scanner.summary)
        } else {
            None
        }
    }

    fn maybe_record_special_call<T: Spanned>(&mut self, node: &T, callee: &str) {
        let lower = normalize_path(callee);
        if lower.ends_with("::panic") || lower == "panic" {
            self.add_panic(node, PanicKind::PanicMacro, "panic-call");
        }
        if lower.contains("transmute_copy") {
            self.add_dangerous(
                node,
                DangerousKind::TransmuteCopy,
                "transmute-copy",
                "high",
                EvidenceStrength::Strong,
            );
        } else if lower.contains("transmute") {
            self.add_dangerous(
                node,
                DangerousKind::Transmute,
                "transmute",
                "high",
                EvidenceStrength::Strong,
            );
        }
        if lower.contains("alloc::alloc") || lower.ends_with("::alloc") {
            self.add_dangerous(
                node,
                DangerousKind::ManualAllocCandidate,
                "alloc-call",
                "medium",
                EvidenceStrength::Medium,
            );
        }
        if lower.contains("dealloc") || lower.ends_with("free") || lower.contains("::free") {
            self.add_dangerous(
                node,
                DangerousKind::ManualFreeCandidate,
                "free-call",
                "medium",
                EvidenceStrength::Medium,
            );
        }
        if lower.contains("vec::from_raw_parts") {
            self.add_dangerous(
                node,
                DangerousKind::VecFromRawParts,
                "vec-from-raw-parts",
                "high",
                EvidenceStrength::Strong,
            );
        } else if lower.contains("from_raw_parts_mut") || lower.contains("from_raw_parts") {
            self.add_dangerous(
                node,
                DangerousKind::FromRawParts,
                "from-raw-parts",
                "high",
                EvidenceStrength::Strong,
            );
        }
        if lower.contains("nonnull::new_unchecked") {
            self.add_dangerous(
                node,
                DangerousKind::NonNullNewUnchecked,
                "nonnull-new-unchecked",
                "high",
                EvidenceStrength::Strong,
            );
        }
        if lower.contains("box::from_raw") {
            self.add_dangerous(
                node,
                DangerousKind::BoxFromRaw,
                "box-from-raw",
                "high",
                EvidenceStrength::Strong,
            );
        }
        if lower.contains("box::into_raw") {
            self.add_dangerous(
                node,
                DangerousKind::BoxIntoRaw,
                "box-into-raw",
                "medium",
                EvidenceStrength::Medium,
            );
        }
        if lower.contains("copy_nonoverlapping") {
            self.add_dangerous(
                node,
                DangerousKind::CopyNonOverlappingCandidate,
                "copy-nonoverlapping",
                "high",
                EvidenceStrength::Strong,
            );
        }
        if lower.contains("ptr::read") || lower.ends_with("::read") {
            self.add_dangerous(
                node,
                DangerousKind::PtrReadCandidate,
                "ptr-read",
                "medium",
                EvidenceStrength::Medium,
            );
        }
        if lower.contains("ptr::write") || lower.ends_with("::write") {
            self.add_dangerous(
                node,
                DangerousKind::PtrWriteCandidate,
                "ptr-write",
                "medium",
                EvidenceStrength::Medium,
            );
        }
        if lower.contains("forget") {
            self.add_dangerous(
                node,
                DangerousKind::MemForget,
                "mem-forget",
                "medium",
                EvidenceStrength::Medium,
            );
        }
        if lower.contains("maybeuninit") {
            self.add_dangerous(
                node,
                DangerousKind::MaybeUninitCandidate,
                "maybeuninit",
                "medium",
                EvidenceStrength::Medium,
            );
        }
        if lower.contains("manuallydrop") {
            self.add_dangerous(
                node,
                DangerousKind::ManuallyDropCandidate,
                "manuallydrop",
                "medium",
                EvidenceStrength::Medium,
            );
        }
        if lower.contains("set_len") {
            self.add_dangerous(
                node,
                DangerousKind::SetLenCandidate,
                "vec-set-len",
                "high",
                EvidenceStrength::Strong,
            );
        }
    }

    fn register_stmt_macro(&mut self, stmt_macro: &syn::StmtMacro) {
        let name = macro_name(&stmt_macro.mac.path);
        match name.as_str() {
            "panic" => self.add_panic(stmt_macro, PanicKind::PanicMacro, "stmt-panic-macro"),
            "assert" | "assert_eq" | "assert_ne" => {
                self.add_panic(stmt_macro, PanicKind::AssertMacro, "stmt-assert-macro")
            }
            "debug_assert" | "debug_assert_eq" | "debug_assert_ne" => self.add_panic(
                stmt_macro,
                PanicKind::DebugAssertMacro,
                "stmt-debug-assert-macro",
            ),
            "todo" => self.add_panic(stmt_macro, PanicKind::TodoMacro, "stmt-todo-macro"),
            "unimplemented" => self.add_panic(
                stmt_macro,
                PanicKind::UnimplementedMacro,
                "stmt-unimplemented-macro",
            ),
            "unreachable" => self.add_panic(
                stmt_macro,
                PanicKind::UnreachableMacro,
                "stmt-unreachable-macro",
            ),
            "dpr_hit" => self.add_macro_dangerous(
                stmt_macro,
                DangerousKind::TargetApiMisuseCandidate,
                "trace-hit-macro",
            ),
            other if other.contains("panic") => {
                self.add_panic(stmt_macro, PanicKind::PanicMacro, "stmt-panic-like-macro")
            }
            other if other.contains("unsafe") || other.contains("raw") => self.add_macro_dangerous(
                stmt_macro,
                DangerousKind::UnsafeBlock,
                "stmt-unsafe-like-macro",
            ),
            _ => {}
        }
    }

    fn expr_is_raw_ptr_like(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Paren(e) => self.expr_is_raw_ptr_like(&e.expr),
            Expr::Group(e) => self.expr_is_raw_ptr_like(&e.expr),
            Expr::Cast(e) => matches!(&*e.ty, Type::Ptr(_)),
            Expr::Path(p) => {
                if let Some(ident) = p.path.get_ident() {
                    self.raw_ptr_locals.contains(&ident.to_string())
                } else {
                    false
                }
            }
            Expr::MethodCall(m) => {
                let method = m.method.to_string();
                matches!(
                    method.as_str(),
                    "as_ptr" | "as_mut_ptr" | "as_non_null_ptr" | "as_mut" | "as_ref" | "cast"
                )
            }
            Expr::Call(call) => {
                if let Expr::Path(path) = &*call.func {
                    let callee = normalize_path(&Self::expr_path_to_string(path));
                    callee.contains("from_raw")
                        || callee.contains("as_ptr")
                        || callee.contains("as_mut_ptr")
                        || callee.contains("nonnull::new_unchecked")
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn remember_raw_ptr_binding_from_pat_and_expr(&mut self, pat: &syn::Pat, init_expr: &Expr) {
        if !self.expr_is_raw_ptr_like(init_expr) {
            return;
        }

        if let syn::Pat::Ident(pat_ident) = pat {
            self.raw_ptr_locals.insert(pat_ident.ident.to_string());
        }
    }
}

impl<'ast> Visit<'ast> for SiteAndCallVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if let Some((_, items)) = &node.content {
            self.module_stack.push(node.ident.to_string());
            for item in items {
                self.visit_item(item);
            }
            self.module_stack.pop();
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let fn_name = self.stable_fn_name(&node.sig.ident.to_string());
        let old_fn = self.current_fn.clone();
        let old_raw_ptr_locals = std::mem::take(&mut self.raw_ptr_locals);

        self.current_fn = Some(fn_name.clone());

        let span = self.span_info(node);
        self.functions.push(FunctionSummary {
            function_id: fn_name.clone(),
            is_public: matches!(node.vis, Visibility::Public(_)),
            file: self.rel_file_path(),
            line_start: span.line_start,
            line_end: span.line_end,
            source_crate: self.crate_name.clone(),
            source_origin: self.source_origin.clone(),
        });

        if node.sig.unsafety.is_some() {
            self.add_dangerous(
                node,
                DangerousKind::UnsafeFn,
                "unsafe-fn",
                "high",
                EvidenceStrength::Strong,
            );
        }

        visit::visit_item_fn(self, node);

        self.raw_ptr_locals = old_raw_ptr_locals;
        self.current_fn = old_fn;
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if node.unsafety.is_some() {
            self.add_dangerous(
                node,
                DangerousKind::UnsafeTraitImpl,
                "unsafe-impl",
                "medium",
                EvidenceStrength::Medium,
            );
        }
        visit::visit_item_impl(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast TraitItem) {
        if let TraitItem::Fn(f) = node {
            if f.sig.unsafety.is_some() {
                self.add_dangerous(
                    f,
                    DangerousKind::UnsafeFn,
                    "unsafe-trait-method",
                    "medium",
                    EvidenceStrength::Medium,
                );
            }
        }
        visit::visit_trait_item(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        if let Some(ffi_summary) = self.scan_unsafe_block_for_ffi_boundary(&node.block) {
            let kind = if ffi_summary.may_unwind_or_panic {
                DangerousKind::FfiUnwindBoundary
            } else {
                DangerousKind::FfiBoundary
            };

            let rule = if ffi_summary.may_unwind_or_panic {
                "unsafe-block-ffi-unwind-boundary"
            } else {
                "unsafe-block-ffi-boundary"
            };

            self.add_dangerous_with_abi(
                node,
                kind,
                rule,
                "high",
                EvidenceStrength::Strong,
                ffi_summary.abi.clone(),
            );
        } else {
            self.add_dangerous(
                node,
                DangerousKind::UnsafeBlock,
                "unsafe-block",
                "high",
                EvidenceStrength::Strong,
            );
        }

        visit::visit_expr_unsafe(self, node);
    }

    fn visit_expr_unary(&mut self, node: &'ast ExprUnary) {
        if matches!(node.op, UnOp::Deref(_)) && self.expr_is_raw_ptr_like(&node.expr) {
            self.add_dangerous(
                node,
                DangerousKind::RawDerefCandidate,
                "unary-deref-raw-candidate",
                "medium",
                EvidenceStrength::Heuristic,
            );
        }
        visit::visit_expr_unary(self, node);
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
            EvidenceStrength::Strong,
            Some(abi.clone()),
        );

        if abi.to_lowercase().contains("unwind") {
            self.add_dangerous_with_abi(
                node,
                DangerousKind::FfiUnwindBoundary,
                "ffi-unwind-boundary",
                "high",
                EvidenceStrength::Strong,
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
                    EvidenceStrength::Strong,
                    Some(abi.clone()),
                );
            }
        }

        visit::visit_item_foreign_mod(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast Stmt) {
        if let Stmt::Macro(stmt_macro) = node {
            self.register_stmt_macro(stmt_macro);
        }

        visit::visit_stmt(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(init) = &node.init {
            self.remember_raw_ptr_binding_from_pat_and_expr(&node.pat, &init.expr);
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        self.add_dangerous(
            node,
            DangerousKind::IndexingCandidate,
            "index-expression",
            "medium",
            EvidenceStrength::Heuristic,
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
            "assume_init" => self.add_dangerous(
                node,
                DangerousKind::AssumeInitCandidate,
                "assume-init",
                "high",
                EvidenceStrength::Strong,
            ),
            "set_len" => self.add_dangerous(
                node,
                DangerousKind::SetLenCandidate,
                "set-len",
                "high",
                EvidenceStrength::Strong,
            ),
            "read" => self.add_dangerous(
                node,
                DangerousKind::PtrReadCandidate,
                "method-read-candidate",
                "medium",
                EvidenceStrength::Heuristic,
            ),
            "write" => self.add_dangerous(
                node,
                DangerousKind::PtrWriteCandidate,
                "method-write-candidate",
                "medium",
                EvidenceStrength::Heuristic,
            ),
            _ => {}
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast ExprMacro) {
        let name = macro_name(&node.mac.path);
        match name.as_str() {
            "panic" => self.add_panic(node, PanicKind::PanicMacro, "panic-macro"),
            "assert" | "assert_eq" | "assert_ne" => {
                self.add_panic(node, PanicKind::AssertMacro, "assert-macro")
            }
            "debug_assert" | "debug_assert_eq" | "debug_assert_ne" => {
                self.add_panic(node, PanicKind::DebugAssertMacro, "debug-assert-macro")
            }
            "todo" => self.add_panic(node, PanicKind::TodoMacro, "todo-macro"),
            "unimplemented" => {
                self.add_panic(node, PanicKind::UnimplementedMacro, "unimplemented-macro")
            }
            "unreachable" => self.add_panic(node, PanicKind::UnreachableMacro, "unreachable-macro"),
            "dpr_hit" => self.add_macro_dangerous(
                node,
                DangerousKind::TargetApiMisuseCandidate,
                "trace-hit-macro",
            ),
            other if other.contains("panic") => {
                self.add_panic(node, PanicKind::PanicMacro, "panic-like-macro")
            }
            other if other.contains("unsafe") || other.contains("raw") => {
                self.add_macro_dangerous(node, DangerousKind::UnsafeBlock, "unsafe-like-macro")
            }
            _ => {}
        }
        visit::visit_expr_macro(self, node);
    }

    fn visit_item(&mut self, node: &'ast Item) {
        if let Item::Macro(m) = node {
            let name = macro_name(&m.mac.path);
            match name.as_str() {
                "panic" => self.add_panic(node, PanicKind::PanicMacro, "item-panic-macro"),
                "assert" | "assert_eq" | "assert_ne" => {
                    self.add_panic(node, PanicKind::AssertMacro, "item-assert-macro")
                }
                "debug_assert" | "debug_assert_eq" | "debug_assert_ne" => {
                    self.add_panic(node, PanicKind::DebugAssertMacro, "item-debug-assert-macro")
                }
                "todo" => self.add_panic(node, PanicKind::TodoMacro, "item-todo-macro"),
                "unimplemented" => self.add_panic(
                    node,
                    PanicKind::UnimplementedMacro,
                    "item-unimplemented-macro",
                ),
                "unreachable" => {
                    self.add_panic(node, PanicKind::UnreachableMacro, "item-unreachable-macro")
                }
                _ => {}
            }
        }
        visit::visit_item(self, node);
    }
}

fn macro_name(path: &syn::Path) -> String {
    path.segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default()
}

fn normalize_path(path: &str) -> String {
    path.replace(' ', "")
        .replace('<', "::")
        .replace('>', "")
        .to_lowercase()
}

#[derive(Debug, Clone, Default)]
struct AbiFunctionInfo {
    abi: String,
    may_panic: bool,
}

#[derive(Debug, Clone, Default)]
struct UnsafeBlockFfiSummary {
    calls_abi_function: bool,
    may_unwind_or_panic: bool,
    abi: Option<String>,
}

fn collect_abi_functions(ast: &File) -> HashMap<String, AbiFunctionInfo> {
    let mut collector = AbiFunctionCollector {
        functions: HashMap::new(),
    };

    collector.visit_file(ast);

    collector.functions
}

struct AbiFunctionCollector {
    functions: HashMap<String, AbiFunctionInfo>,
}

impl<'ast> Visit<'ast> for AbiFunctionCollector {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if let Some(abi) = &node.sig.abi {
            let abi_name = abi
                .name
                .as_ref()
                .map(|x| x.value())
                .unwrap_or_else(|| "unknown".to_string());

            let may_panic = block_may_panic(&node.block);

            self.functions.insert(
                node.sig.ident.to_string(),
                AbiFunctionInfo {
                    abi: abi_name,
                    may_panic,
                },
            );
        }

        visit::visit_item_fn(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast ItemForeignMod) {
        let abi_name = node
            .abi
            .name
            .as_ref()
            .map(|x| x.value())
            .unwrap_or_else(|| "unknown".to_string());

        for item in &node.items {
            if let ForeignItem::Fn(f) = item {
                self.functions.insert(
                    f.sig.ident.to_string(),
                    AbiFunctionInfo {
                        abi: abi_name.clone(),
                        may_panic: abi_name.to_lowercase().contains("unwind"),
                    },
                );
            }
        }

        visit::visit_item_foreign_mod(self, node);
    }
}

fn block_may_panic(block: &Block) -> bool {
    let mut scanner = PanicInBlockScanner { may_panic: false };
    scanner.visit_block(block);
    scanner.may_panic
}

struct PanicInBlockScanner {
    may_panic: bool,
}

impl<'ast> Visit<'ast> for PanicInBlockScanner {
    fn visit_expr_macro(&mut self, node: &'ast ExprMacro) {
        let name = macro_name(&node.mac.path);

        if matches!(
            name.as_str(),
            "panic"
                | "assert"
                | "assert_eq"
                | "assert_ne"
                | "debug_assert"
                | "debug_assert_eq"
                | "debug_assert_ne"
                | "todo"
                | "unimplemented"
                | "unreachable"
        ) {
            self.may_panic = true;
        }

        visit::visit_expr_macro(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast Stmt) {
        if let Stmt::Macro(stmt_macro) = node {
            let name = macro_name(&stmt_macro.mac.path);

            if matches!(
                name.as_str(),
                "panic"
                    | "assert"
                    | "assert_eq"
                    | "assert_ne"
                    | "debug_assert"
                    | "debug_assert_eq"
                    | "debug_assert_ne"
                    | "todo"
                    | "unimplemented"
                    | "unreachable"
            ) {
                self.may_panic = true;
            }
        }

        visit::visit_stmt(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();

        if method == "unwrap" || method == "expect" {
            self.may_panic = true;
        }

        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(expr_path) = &*node.func {
            let callee = path_to_string(expr_path).to_lowercase();

            if callee == "panic" || callee.ends_with("::panic") {
                self.may_panic = true;
            }
        }

        visit::visit_expr_call(self, node);
    }
}

struct UnsafeBlockFfiScanner<'a> {
    abi_functions: &'a HashMap<String, AbiFunctionInfo>,
    summary: UnsafeBlockFfiSummary,
}

impl<'a, 'ast> Visit<'ast> for UnsafeBlockFfiScanner<'a> {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(expr_path) = &*node.func {
            let callee = path_to_string(expr_path);
            let last = last_path_segment(expr_path).unwrap_or_default();

            if let Some(info) = self.abi_functions.get(&last) {
                self.summary.calls_abi_function = true;
                self.summary.abi.get_or_insert_with(|| info.abi.clone());

                let abi_lower = info.abi.to_lowercase();

                if info.may_panic || abi_lower.contains("unwind") {
                    self.summary.may_unwind_or_panic = true;
                }
            }

            // 兜底：如果函数名明显是 callback / ffi / extern 风格，也认为它具有 FFI-like 边界特征。
            // 这个兜底只用于 unsafe block 内部，不会污染普通函数调用。
            let callee_lower = callee.to_lowercase();
            let last_lower = last.to_lowercase();

            if last_lower.contains("callback")
                || callee_lower.contains("callback")
                || last_lower.contains("ffi")
                || callee_lower.contains("ffi")
            {
                self.summary.calls_abi_function = true;
                self.summary.may_unwind_or_panic = true;
            }
        }

        visit::visit_expr_call(self, node);
    }
    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        let last = last_path_segment(node).unwrap_or_default();

        if let Some(info) = self.abi_functions.get(&last) {
            self.summary.calls_abi_function = true;
            self.summary.abi.get_or_insert_with(|| info.abi.clone());

            let abi_lower = info.abi.to_lowercase();
            if info.may_panic || abi_lower.contains("unwind") {
                self.summary.may_unwind_or_panic = true;
            }
        }

        visit::visit_expr_path(self, node);
    }
}

fn path_to_string(expr: &ExprPath) -> String {
    expr.path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn last_path_segment(expr: &ExprPath) -> Option<String> {
    expr.path.segments.last().map(|s| s.ident.to_string())
}

#[allow(dead_code)]
fn path_has_generic_args(expr_path: &ExprPath) -> bool {
    expr_path
        .path
        .segments
        .iter()
        .any(|s| !matches!(s.arguments, PathArguments::None))
}
