use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use ghost_scanner::reporter::security_reporter::VulnerabilityReport;
use ghost_scanner::verify_engine::{verify_report, VerifyRequirements};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Pretty,
}

#[derive(Debug, Parser)]
#[command(name = "forthres-verify")]
#[command(about = "forthres verify engine built on top of the existing scan report", long_about = None)]
struct Cli {
    #[arg(long)]
    report_file: Option<PathBuf>,

    #[arg(long, value_enum, default_value = "pretty")]
    output: OutputFormat,

    #[arg(long, action = ArgAction::SetTrue)]
    no_self_destruct: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    ownership_timelock: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    require_fork_validation: bool,

    #[arg(long, action = ArgAction::SetTrue)]
    require_proxy_access_control: bool,

    #[arg(long)]
    max_exploit_probability: Option<f64>,

    #[arg(long)]
    max_risk_adjusted_value_eth: Option<f64>,

    #[arg(long = "forbid-selector")]
    forbid_flagged_selectors: Vec<String>,
}

fn read_report_json(report_file: &Option<PathBuf>) -> Result<String> {
    if let Some(path) = report_file {
        return fs::read_to_string(path)
            .with_context(|| format!("failed to read report file {}", path.display()));
    }

    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .context("failed to read report JSON from stdin")?;
    Ok(buffer)
}

fn print_pretty(result: &ghost_scanner::verify_engine::VerifyDecision) {
    println!("forthres Verify Engine");
    println!("Contract: {}", result.report.contract_address);
    println!("Chain: {}", result.report.chain);
    println!("Passed: {}", if result.passed { "true" } else { "false" });
    println!("Estimated Risk: {}", result.estimated_risk);
    println!("Confidence: {}/100", result.confidence);
    println!("Summary: {}", result.summary);
    println!("Violations:");

    if result.violations.is_empty() {
        println!("- none");
    } else {
        for violation in &result.violations {
            println!("- [{}] {}", violation.severity, violation.message);
            if !violation.evidence.is_empty() {
                for evidence in &violation.evidence {
                    println!("  evidence: {}", evidence);
                }
            }
            if let Some(fix) = &violation.recommended_fix {
                println!("  fix: {}", fix);
            }
        }
    }

    if !result.unsupported_checks.is_empty() {
        println!(
            "Unsupported Checks: {}",
            result.unsupported_checks.join(", ")
        );
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let report_json = read_report_json(&cli.report_file)?;
    let report: VulnerabilityReport =
        serde_json::from_str(&report_json).context("failed to parse VulnerabilityReport JSON")?;

    let requirements = VerifyRequirements {
        no_self_destruct: cli.no_self_destruct,
        ownership_transfer_requires_timelock: cli.ownership_timelock,
        require_fork_validation: cli.require_fork_validation,
        require_proxy_access_control: cli.require_proxy_access_control,
        max_exploit_probability: cli.max_exploit_probability,
        max_risk_adjusted_value_eth: cli.max_risk_adjusted_value_eth,
        forbid_flagged_selectors: cli.forbid_flagged_selectors,
    };

    let result = verify_report(&report, &requirements);

    match cli.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Pretty => {
            print_pretty(&result);
        }
    }

    if result.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
