use anyhow::Result;
use clap::{Parser, Subcommand};
use rustdpr_analyzer::metadata::collect_metadata;
use rustdpr_analyzer::site_locator::build_site_map;
use std::fs;
use std::path::PathBuf;
use rustdpr_classifier::{classify, load_trace};
use rustdpr_core::model::{ClassificationResult, SiteMap};
use rustdpr_report::render_report;

/// RustDPR 命令行工具的主结构
#[derive(Parser)]
#[command(name = "rustdpr")]
#[command(version)]
#[command(about = "Rust Dangerous Path Reachability MVP")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// 支持的子命令枚举
#[derive(Subcommand)]
enum Commands {
    /// Collect 子命令：收集 Crate 元数据
    Collect {
        /// Crate 根目录路径
        #[arg(long)]
        crate_dir: PathBuf,
        /// 输出文件路径
        #[arg(long)]
        out: PathBuf,
    },
    /// AnalyzeSites 子命令：分析并构建站点地图
    AnalyzeSites {
        /// Crate 根目录路径
        #[arg(long)]
        crate_dir: PathBuf,
        /// 输出文件路径（JSON 格式的 SiteMap）
        #[arg(long)]
        out: PathBuf,
    },
    /// Classify 子命令：对追踪日志进行分类
    Classify {
        /// 追踪日志文件路径
        #[arg(long)]
        trace: PathBuf,
        /// 站点地图文件路径
        #[arg(long)]
        site_map: PathBuf,
        /// 输出文件路径（JSON 格式的分类结果）
        #[arg(long)]
        out: PathBuf,
    },
    /// Report 子命令：生成分析报告
    Report {
        /// 追踪日志文件路径
        #[arg(long)]
        trace: PathBuf,
        /// 站点地图文件路径
        #[arg(long)]
        site_map: PathBuf,
        /// 分类结果文件路径
        #[arg(long)]
        result: PathBuf,
        /// 输出文件路径（Markdown 格式的报告）
        #[arg(long)]
        out: PathBuf,
    },
}

/// 主函数：解析命令行参数并执行相应的子命令
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // Collect 命令：收集并保存 Crate 元数据
        Commands::Collect { crate_dir, out } => {
            let meta = collect_metadata(&crate_dir)?;
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(out, serde_json::to_vec_pretty(&meta)?)?;
        }
        // AnalyzeSites 命令：分析源代码并生成站点地图
        Commands::AnalyzeSites { crate_dir, out } => {
            let meta = collect_metadata(&crate_dir)?;
            let site_map = build_site_map(&crate_dir, meta.name)?;
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(out, serde_json::to_vec_pretty(&site_map)?)?;
        }
        // Classify 命令：加载追踪日志和站点地图，执行分类
        Commands::Classify { trace, site_map, out } => {
            let trace_log = load_trace(&trace)?;
            let site_map: SiteMap = serde_json::from_slice(&fs::read(&site_map)?)?;
            let result = classify(&trace_log, &site_map);

            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(out, serde_json::to_vec_pretty(&result)?)?;
        }

        // Report 命令：生成完整的 Markdown 报告
        Commands::Report {
            trace,
            site_map,
            result,
            out,
        } => {
            let trace_log = load_trace(&trace)?;
            let site_map: SiteMap = serde_json::from_slice(&fs::read(&site_map)?)?;
            let result: ClassificationResult =
                serde_json::from_slice(&fs::read(&result)?)?;

            let md = render_report(
                &site_map.crate_name,
                &site_map,
                &trace_log,
                &result,
            )?;

            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(out, md)?;
        }
    }

    Ok(())
}