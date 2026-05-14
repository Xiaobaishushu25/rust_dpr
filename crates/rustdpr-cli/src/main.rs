use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rustdpr_analyzer::{analyze_crate, analyze_harness_validity, build_dpg};
use rustdpr_classifier::classify_execution;
use rustdpr_core::{
    DangerousPathGraph, HarnessValidityReport, OracleVerdict, SiteMap, TraceEvent, TraceLog,
};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rustdpr")]
#[command(about = "Rust Dangerous Path Reachability prototype CLI")]
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
        function_index_out: Option<PathBuf>,
    },
    BuildDpg {
        #[arg(long)]
        crate_root: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    ValidateHarness {
        #[arg(long)]
        harness: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Distance {
        #[arg(long)]
        dpg: PathBuf,
        #[arg(long)]
        from: String,
    },
    Classify {
        #[arg(long)]
        site_map: PathBuf,
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        dpg: PathBuf,
        #[arg(long)]
        harness_validity: Option<PathBuf>,
        #[arg(long)]
        oracle: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::AnalyzeSites {
            crate_root,
            out,
            function_index_out,
        } => {
            let (site_map, function_index) = analyze_crate(&crate_root)?;
            write_json(&out, &site_map)?;
            if let Some(idx_out) = function_index_out {
                write_json(&idx_out, &function_index)?;
            }
        }

        Commands::BuildDpg { crate_root, out } => {
            let (site_map, function_index) = analyze_crate(&crate_root)?;
            let dpg = build_dpg(&site_map, &function_index);
            write_json(&out, &dpg)?;
        }

        Commands::ValidateHarness { harness, out } => {
            let report = analyze_harness_validity(&harness)?;
            write_json(&out, &report)?;
        }

        Commands::Distance { dpg, from } => {
            let dpg: DangerousPathGraph = read_json(&dpg)?;
            let result = dpg.shortest_distance_to_any_dangerous_site(&from);
            println!("{}", serde_json::to_string_pretty(&result)?);
        }

        Commands::Classify {
            site_map,
            trace,
            dpg,
            harness_validity,
            oracle,
            out,
        } => {
            let site_map: SiteMap = read_json(&site_map)?;
            let trace = read_trace_jsonl(&trace)?;
            let dpg: DangerousPathGraph = read_json(&dpg)?;

            let harness: Option<HarnessValidityReport> = match harness_validity {
                Some(path) => Some(read_json(&path)?),
                None => None,
            };

            let oracle = oracle
                .as_deref()
                .map(parse_oracle_verdict)
                .transpose()?
                .unwrap_or(OracleVerdict::Unknown);

            let result = classify_execution(
                &site_map,
                &trace,
                &dpg,
                harness.as_ref(),
                Some(oracle),
            );

            if let Some(out_path) = out {
                write_json(&out_path, &result)?;
            } else {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        }
    }

    Ok(())
}

fn write_json<T: serde::Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .context("output path has no parent directory")?;
    fs::create_dir_all(parent)?;
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let value = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse JSON {}", path.display()))?;
    Ok(value)
}

fn read_trace_jsonl(path: &PathBuf) -> Result<TraceLog> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read trace {}", path.display()))?;

    let mut events = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: TraceEvent = serde_json::from_str(line)
            .with_context(|| format!("invalid trace JSONL at line {}", idx + 1))?;
        events.push(event);
    }

    Ok(TraceLog { events })
}

fn parse_oracle_verdict(s: &str) -> Result<OracleVerdict> {
    let v = match s {
        "unknown" => OracleVerdict::Unknown,
        "asan-double-free" => OracleVerdict::AddressSanitizerDoubleFree,
        "asan-uaf" => OracleVerdict::AddressSanitizerUseAfterFree,
        "asan-oob" => OracleVerdict::AddressSanitizerOutOfBounds,
        "miri-ub" => OracleVerdict::MiriUndefinedBehavior,
        _ => anyhow::bail!("unknown oracle verdict: {s}"),
    };
    Ok(v)
}