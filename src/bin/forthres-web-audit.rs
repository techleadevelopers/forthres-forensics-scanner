use anyhow::Result;
use clap::{Parser, Subcommand};
use ghost_scanner::web_audit::orchestrator::run_assessment;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(
    name = "forthres-web-audit",
    about = "Forthres parallel Rust web audit engine shadowing the Python analysis runtime",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Scan {
        #[arg(long)]
        target: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Scan { target } => {
            let report = run_assessment(&target).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
    }

    Ok(())
}
