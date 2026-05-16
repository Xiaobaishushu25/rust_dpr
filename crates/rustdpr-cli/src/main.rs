use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rustdpr_analyzer::{analyze_crate, analyze_harness_validity, build_dpg};
use rustdpr_classifier::classify_execution;
use rustdpr_core::{DangerousPathGraph, HarnessValidityReport, SiteMap, TraceLog};
use rustdpr_oracle::{parse_asan_log, parse_miri_log};
use rustdpr_report::render_markdown_report;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rustdpr")]
#[command(about = "Panic-aware dangerous-path validation for Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    AnalyzeSites {
        #[arg(long)]
        crate_root: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        function_out: Option<PathBuf>,
    },
    BuildDpg {
        #[arg(long)]
        site_map: PathBuf,
        #[arg(long)]
        function_index: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    ValidateHarness {
        #[arg(long)]
        harness: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Classify {
        #[arg(long)]
        site_map: PathBuf,
        #[arg(long)]
        dpg: PathBuf,
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        harness: Option<PathBuf>,
        #[arg(long)]
        asan_log: Option<PathBuf>,
        #[arg(long)]
        miri_log: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    Report {
        #[arg(long)]
        site_map: PathBuf,
        #[arg(long)]
        dpg: PathBuf,
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        classification: PathBuf,
        #[arg(long)]
        harness: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::AnalyzeSites {
            crate_root,
            out,
            function_out,
        } => {
            let (site_map, function_index) = analyze_crate(&crate_root)?;
            write_json(&out, &site_map)?;
            if let Some(function_out) = function_out {
                write_json(&function_out, &function_index)?;
            }
        }
        Commands::BuildDpg {
            site_map,
            function_index,
            out,
        } => {
            let site_map: SiteMap = read_json(&site_map)?;
            let function_index = read_json(&function_index)?;
            let dpg = build_dpg(&site_map, &function_index);
            write_json(&out, &dpg)?;
        }
        Commands::ValidateHarness { harness, out } => {
            let report = analyze_harness_validity(&harness)?;
            write_json(&out, &report)?;
        }
        Commands::Classify {
            site_map,
            dpg,
            trace,
            harness,
            asan_log,
            miri_log,
            out,
        } => {
            let site_map: SiteMap = read_json(&site_map)?;
            let dpg: DangerousPathGraph = read_json(&dpg)?;
            let trace: TraceLog = read_json(&trace)?;
            let harness: Option<HarnessValidityReport> = match harness {
                Some(path) => Some(read_json(&path)?),
                None => None,
            };

            let oracle = if let Some(path) = asan_log {
                let content = fs::read_to_string(&path)?;
                Some(parse_asan_log(&content, Some(path.display().to_string())).verdict)
            } else if let Some(path) = miri_log {
                let content = fs::read_to_string(&path)?;
                Some(parse_miri_log(&content, Some(path.display().to_string())).verdict)
            } else {
                None
            };

            let result = classify_execution(&site_map, &trace, &dpg, harness.as_ref(), oracle);
            write_json(&out, &result)?;
        }
        Commands::Report {
            site_map,
            dpg,
            trace,
            classification,
            harness,
            out,
        } => {
            let site_map: SiteMap = read_json(&site_map)?;
            let dpg: DangerousPathGraph = read_json(&dpg)?;
            let trace: TraceLog = read_json(&trace)?;
            let classification = read_json(&classification)?;
            let harness: Option<HarnessValidityReport> = match harness {
                Some(path) => Some(read_json(&path)?),
                None => None,
            };

            let md = render_markdown_report(&site_map, &dpg, &trace, harness.as_ref(), &classification);
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create parent dir {}", parent.display()))?;
            }
            fs::write(&out, md).with_context(|| format!("failed to write {}", out.display()))?;
        }
    }

    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse json {}", path.display()))?;
    Ok(parsed)
}

fn write_json<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent dir {}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(value)?;
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}