use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rustdpr_analyzer::{analyze_crate, analyze_harness_validity, build_dpg, collect_metadata};
use rustdpr_classifier::classify_execution_with_options;
use rustdpr_core::{ClassificationOptions, DangerousPathGraph, HarnessValidityReport, OracleVerdict, SiteMap, TraceLog};
use rustdpr_oracle::{parse_asan_log, parse_miri_log, OracleReport};
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
    Collect {
        #[arg(long, alias = "crate")]
        crate_root: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
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
        panic_only: bool,
        #[arg(long)]
        static_only: bool,
        #[arg(long)]
        no_trace: bool,
        #[arg(long)]
        no_dpg: bool,
        #[arg(long)]
        no_harness_validity: bool,
        #[arg(long)]
        no_oracle: bool,
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
        Commands::Collect { crate_root, out } => {
            let meta = collect_metadata(&crate_root)?;
            write_json(&out, &meta)?;
        }
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
            panic_only,
            static_only,
            no_trace,
            no_dpg,
            no_harness_validity,
            no_oracle,
            out,
        } => {
            let site_map: SiteMap = read_json(&site_map)?;
            let dpg: DangerousPathGraph = read_json(&dpg)?;
            let trace: TraceLog = read_json(&trace)?;
            let harness: Option<HarnessValidityReport> = match harness {
                Some(path) => Some(read_json(&path)?),
                None => None,
            };

            // let oracle = if let Some(path) = asan_log {
            //     let content = fs::read_to_string(&path)?;
            //     Some(parse_asan_log(&content, Some(path.display().to_string())).verdict)
            // } else if let Some(path) = miri_log {
            //     let content = fs::read_to_string(&path)?;
            //     Some(parse_miri_log(&content, Some(path.display().to_string())).verdict)
            // } else {
            //     None
            // };
            let oracle = select_oracle_verdict(asan_log, miri_log)?;

            let options = ClassificationOptions {
                use_dynamic_trace: !no_trace,
                use_dpg_adjacency: !no_dpg,
                use_harness_validity: !no_harness_validity,
                use_oracle: !no_oracle,
                panic_only,
                static_only,
                weighted_sites: true,
            };

            let result = classify_execution_with_options(&site_map, &trace, &dpg, harness.as_ref(), oracle, options);
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

fn select_oracle_verdict(
    asan_log: Option<PathBuf>,
    miri_log: Option<PathBuf>,
) -> Result<Option<OracleVerdict>> {
    let mut reports = Vec::new();

    if let Some(path) = asan_log {
        let content = fs::read_to_string(&path)?;
        reports.push(parse_asan_log(&content, Some(path.display().to_string())));
    }

    if let Some(path) = miri_log {
        let content = fs::read_to_string(&path)?;
        reports.push(parse_miri_log(&content, Some(path.display().to_string())));
    }

    Ok(select_best_oracle_report(reports).map(|report| report.verdict))
}

fn select_best_oracle_report(reports: Vec<OracleReport>) -> Option<OracleReport> {
    reports
        .into_iter()
        .max_by_key(|report| oracle_verdict_priority(&report.verdict))
}

fn oracle_verdict_priority(verdict: &OracleVerdict) -> u8 {
    match verdict {
        OracleVerdict::AddressSanitizerDoubleFree
        | OracleVerdict::AddressSanitizerUseAfterFree
        | OracleVerdict::AddressSanitizerOutOfBounds
        | OracleVerdict::AddressSanitizerInvalidFree
        | OracleVerdict::AddressSanitizerLeak => 100,
        OracleVerdict::MiriUndefinedBehavior => 90,
        OracleVerdict::OracleTimeout => 20,
        OracleVerdict::MiriUnsupported => 10,
        OracleVerdict::Unknown => 0,
    }
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