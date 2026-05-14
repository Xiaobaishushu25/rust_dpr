use anyhow::Result;
use clap::{Parser, Subcommand};
use rustdpr_analyzer::metadata::collect_metadata;
use rustdpr_analyzer::site_locator::build_site_map;
use rustdpr_classifier::{classify, load_trace};
use rustdpr_core::model::{ClassificationResult, OracleResult, SiteMap, TraceLog};
use rustdpr_oracle::{parse_asan_output, parse_miri_output};
use rustdpr_report::render_report;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rustdpr")]
#[command(version)]
#[command(about = "Rust Dangerous Path Reachability MVP")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Collect {
        #[arg(long)]
        crate_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    AnalyzeSites {
        #[arg(long)]
        crate_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Classify {
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        site_map: PathBuf,
        #[arg(long)]
        oracle: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    Report {
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        site_map: PathBuf,
        #[arg(long)]
        result: PathBuf,
        #[arg(long)]
        oracle: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    OracleParse {
        #[arg(long)]
        asan_log: Option<PathBuf>,
        #[arg(long)]
        miri_log: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    SummarizeClass {
        #[arg(long)]
        result: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Collect { crate_dir, out } => {
            let meta = collect_metadata(&crate_dir)?;
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(out, serde_json::to_vec_pretty(&meta)?)?;
        }

        Commands::AnalyzeSites { crate_dir, out } => {
            let meta = collect_metadata(&crate_dir)?;
            let site_map = build_site_map(&crate_dir, meta.name)?;
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(out, serde_json::to_vec_pretty(&site_map)?)?;
        }

        Commands::Classify {
            trace,
            site_map,
            oracle,
            out,
        } => {
            let trace_log = load_trace(&trace)?;
            let site_map: SiteMap = serde_json::from_slice(&fs::read(&site_map)?)?;

            let oracle_result: Option<OracleResult> = if let Some(path) = oracle {
                Some(serde_json::from_slice(&fs::read(path)?)?)
            } else {
                None
            };

            let result = classify(&trace_log, &site_map, oracle_result.as_ref());

            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(out, serde_json::to_vec_pretty(&result)?)?;
        }

        Commands::Report {
            trace,
            site_map,
            result,
            oracle,
            out,
        } => {
            let trace: TraceLog = load_trace(&trace)?;
            let site_map: SiteMap = serde_json::from_slice(&fs::read(&site_map)?)?;
            let result: ClassificationResult = serde_json::from_slice(&fs::read(&result)?)?;

            let oracle_result: Option<OracleResult> = if let Some(path) = oracle {
                Some(serde_json::from_slice(&fs::read(path)?)?)
            } else {
                None
            };

            let md = render_report(
                &site_map.crate_name,
                &site_map,
                &trace,
                &result,
                oracle_result.as_ref(),
            )?;

            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(out, md)?;
        }

        Commands::OracleParse {
            asan_log,
            miri_log,
            out,
        } => {
            let oracle_result = if let Some(path) = asan_log {
                let content = fs::read_to_string(path)?;
                parse_asan_output(&content)
            } else if let Some(path) = miri_log {
                let content = fs::read_to_string(path)?;
                parse_miri_output(&content)
            } else {
                OracleResult { findings: vec![] }
            };

            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(out, serde_json::to_vec_pretty(&oracle_result)?)?;
        }
        Commands::SummarizeClass { result } => {
            let result: ClassificationResult = serde_json::from_slice(&fs::read(&result)?)?;
            println!("class={:?}", result.class);
            println!("oracle_confirmed={}", result.oracle_confirmed);
            println!("panic_observed={}", result.panic_observed);
            println!("reached_dangerous_site={}", result.reached_dangerous_site);
            println!("taxonomy_reason={}", result.taxonomy_reason);
        }
    }

    Ok(())
}