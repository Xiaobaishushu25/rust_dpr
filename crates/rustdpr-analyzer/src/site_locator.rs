use anyhow::Result;
use proc_macro2::Span;
use rustdpr_core::model::{
    DangerousKind, DangerousSite, PanicKind, PanicSite, SiteMap, SpanInfo,
};
use std::fs;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Expr, ExprCall, ExprIndex, ExprMacro, ExprMethodCall, ExprUnsafe, File, ForeignItem, Item,
    ItemFn, ItemForeignMod,
};
use walkdir::WalkDir;

/// 构建站点地图，扫描 Crate 中所有的危险代码和 panic 代码
/// 
/// # 参数
/// * `crate_dir` - Crate 根目录路径
/// * `crate_name` - Crate 名称
/// 
/// # 返回值
/// 返回包含所有危险站点和 panic 站点的 SiteMap
pub fn build_site_map(crate_dir: &Path, crate_name: String) -> Result<SiteMap> {
    let mut dangerous_sites = Vec::new();
    let mut panic_sites = Vec::new();

    // 递归遍历 crate 目录下的所有 .rs 文件
    for entry in WalkDir::new(crate_dir) {
        let entry = entry?;
        let path = entry.path();

        // 跳过非文件和不是 Rust 源文件的条目
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }

        // 读取并解析 Rust 源文件
        let content = fs::read_to_string(path)?;
        let syntax: File = syn::parse_file(&content)?;

        // 使用访问者模式扫描 AST
        let mut visitor = SiteVisitor::new(path.to_path_buf());
        visitor.visit_file(&syntax);

        dangerous_sites.extend(visitor.dangerous_sites);
        panic_sites.extend(visitor.panic_sites);
    }

    Ok(SiteMap {
        crate_name,
        dangerous_sites,
        panic_sites,
    })
}

/// AST 访问者，用于扫描危险代码和 panic 代码
struct SiteVisitor {
    /// 当前处理的文件路径
    file: PathBuf,
    /// 收集到的危险站点列表
    dangerous_sites: Vec<DangerousSite>,
    /// 收集到的 panic 站点列表
    panic_sites: Vec<PanicSite>,
    /// 当前所在的函数名
    current_fn: Option<String>,
    /// 危险站点计数器
    site_counter: usize,
    /// Panic 站点计数器
    panic_counter: usize,
}

impl SiteVisitor {
    /// 创建新的 SiteVisitor 实例
    fn new(file: PathBuf) -> Self {
        Self {
            file,
            dangerous_sites: Vec::new(),
            panic_sites: Vec::new(),
            current_fn: None,
            site_counter: 0,
            panic_counter: 0,
        }
    }

    /// 生成下一个危险站点的唯一 ID（格式：S0001, S0002, ...）
    fn next_site_id(&mut self) -> String {
        self.site_counter += 1;
        format!("S{:04}", self.site_counter)
    }

    /// 生成下一个 panic 站点的唯一 ID（格式：P0001, P0002, ...）
    fn next_panic_id(&mut self) -> String {
        self.panic_counter += 1;
        format!("P{:04}", self.panic_counter)
    }

    /// 将 Span 转换为 SpanInfo
    fn span_info(&self, span: Span) -> SpanInfo {
        let start = span.start();
        let end = span.end();
        SpanInfo {
            file: self.file.clone(),
            line_start: start.line,
            line_end: end.line.max(start.line),
        }
    }

    /// 添加一个危险站点
    fn add_dangerous(&mut self, kind: DangerousKind, span: Span) {
        let site_id = self.next_site_id();
        let enclosing_fn = self.current_fn.clone();
        let span = self.span_info(span);

        self.dangerous_sites.push(DangerousSite {
            site_id,
            kind,
            enclosing_fn,
            span,
        });
    }

    /// 添加一个 panic 站点
    fn add_panic(&mut self, kind: PanicKind, span: Span) {
        let panic_id = self.next_panic_id();
        let enclosing_fn = self.current_fn.clone();
        let span = self.span_info(span);

        self.panic_sites.push(PanicSite {
            panic_id,
            kind,
            enclosing_fn,
            span,
        });
    }
}

impl<'ast> Visit<'ast> for SiteVisitor {
    /// 访问函数定义节点
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        // 保存之前的函数上下文
        let prev = self.current_fn.clone();
        // 更新当前函数名
        self.current_fn = Some(node.sig.ident.to_string());

        // 检查是否为 unsafe 函数
        if node.sig.unsafety.is_some() {
            self.add_dangerous(DangerousKind::UnsafeFn, node.sig.ident.span());
        }

        // 继续访问函数体
        visit::visit_item_fn(self, node);
        // 恢复之前的函数上下文
        self.current_fn = prev;
    }

    /// 访问 unsafe 代码块
    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        self.add_dangerous(DangerousKind::UnsafeBlock, node.unsafe_token.span());
        visit::visit_expr_unsafe(self, node);
    }

    /// 访问外部模块声明（FFI）
    fn visit_item_foreign_mod(&mut self, node: &'ast ItemForeignMod) {
        self.add_dangerous(DangerousKind::FfiDeclaration, node.abi.extern_token.span());
        for item in &node.items {
            if let ForeignItem::Fn(f) = item {
                self.add_dangerous(DangerousKind::FfiDeclaration, f.sig.ident.span());
            }
        }
        visit::visit_item_foreign_mod(self, node);
    }

    /// 访问宏调用表达式
    fn visit_expr_macro(&mut self, node: &'ast ExprMacro) {
        let last = node.mac.path.segments.last().map(|s| s.ident.to_string());
        match last.as_deref() {
            Some("panic") => self.add_panic(PanicKind::PanicMacro, node.span()),
            Some("assert") | Some("debug_assert") => self.add_panic(PanicKind::AssertMacro, node.span()),
            Some("todo") => self.add_panic(PanicKind::TodoMacro, node.span()),
            Some("unimplemented") => self.add_panic(PanicKind::UnimplementedMacro, node.span()),
            _ => {}
        }
        visit::visit_expr_macro(self, node);
    }

    /// 访问方法调用表达式
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let name = node.method.to_string();
        if name == "unwrap" {
            self.add_panic(PanicKind::UnwrapCall, node.span());
        } else if name == "expect" {
            self.add_panic(PanicKind::ExpectCall, node.span());
        }
        visit::visit_expr_method_call(self, node);
    }

    /// 访问函数调用表达式
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(path) = &*node.func {
            if let Some(seg) = path.path.segments.last() {
                let name = seg.ident.to_string();
                // 检测 transmute 调用
                if name == "transmute" {
                    self.add_dangerous(DangerousKind::TransmuteCall, node.span());
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    /// 访问索引表达式
    fn visit_expr_index(&mut self, node: &'ast ExprIndex) {
        // 索引操作既可能是 panic 点（越界检查），也可能是危险操作候选
        self.add_panic(PanicKind::IndexExprRuntimeCheck, node.span());
        self.add_dangerous(DangerousKind::IndexExprCandidate, node.span());
        visit::visit_expr_index(self, node);
    }

    /// 访问通用表达式节点
    fn visit_expr(&mut self, node: &'ast Expr) {
        visit::visit_expr(self, node);
    }

    /// 访问通用项节点
    fn visit_item(&mut self, node: &'ast Item) {
        visit::visit_item(self, node);
    }
}