use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::{fmt, EnvFilter};

mod bytecode;
mod config;
mod forensics;
mod load_balancer;
mod reporter;
mod scanner;

use crate::config::ScannerConfig;
use crate::reporter::{EndpointHealthSnapshot, ScannerStatusSnapshot};
use crate::scanner::{ForkMode, ScanRequest, ScanStream, ScanMode};

#[derive(Parser, Debug)]
#[command(
    name = "ghost-scanner",
    about = "The Ghost Scanner - production EVM smart contract auditing engine",
    version = "0.2.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Scan {
        #[arg(long)]
        contract_address: String,
        #[arg(long, value_enum, default_value_t = ScanModeArg::Fast)]
        mode: ScanModeArg,
        #[arg(long, value_enum, default_value_t = SimulationArg::True)]
        simulation: SimulationArg,
        #[arg(long, value_enum, default_value_t = ForkModeArg::Auto)]
        fork: ForkModeArg,
    },
    Status,
    Endpoints,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ScanModeArg {
    Fast,
    Deep,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ForkModeArg {
    Auto,
    Force,
    Off,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SimulationArg {
    True,
    False,
}

impl From<ScanModeArg> for ScanMode {
    fn from(value: ScanModeArg) -> Self {
        match value {
            ScanModeArg::Fast => ScanMode::Fast,
            ScanModeArg::Deep => ScanMode::Deep,
        }
    }
}

impl From<ForkModeArg> for ForkMode {
    fn from(value: ForkModeArg) -> Self {
        match value {
            ForkModeArg::Auto => ForkMode::Auto,
            ForkModeArg::Force => ForkMode::Force,
            ForkModeArg::Off => ForkMode::Off,
        }
    }
}

impl From<SimulationArg> for bool {
    fn from(value: SimulationArg) -> Self {
        matches!(value, SimulationArg::True)
    }
}

fn load_dotenv_if_present() -> Result<()> {
    let env_path = PathBuf::from(".env.local");
    if !env_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&env_path)
        .with_context(|| format!("failed to read {}", env_path.display()))?;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim().trim_matches('"').trim_matches('\'');

        if std::env::var_os(key).is_none() {
            unsafe {
                std::env::set_var(key, value);
            }
        }
    }

    Ok(())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    load_dotenv_if_present()?;

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let config = ScannerConfig::from_env()?;

    match cli.command {
        Command::Scan {
            contract_address,
            mode,
            simulation,
            fork,
        } => {
            let request = ScanRequest {
                contract_address,
                mode: mode.into(),
                simulation: simulation.into(),
                fork: fork.into(),
            };

            let mut stream = ScanStream::new();
            let report = scanner::scan_contract(&config, request, |event| stream.emit(event)).await?;
            print_json(&stream.complete(report))?;
        }
        Command::Status => {
            let snapshot: ScannerStatusSnapshot = scanner::collect_status(&config).await?;
            print_json(&snapshot)?;
        }
        Command::Endpoints => {
            let snapshot: Vec<EndpointHealthSnapshot> = scanner::collect_endpoints(&config).await?;
            print_json(&snapshot)?;
        }
    }

    Ok(())
}
