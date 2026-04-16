use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VulnerabilityKind {
    UnprotectedSelfDestruct,
    DangerousDelegatecall,
    MissingAccessControl,
    ReentrancyRisk,
    PrivilegedCallcode,
    SuspiciousBytecode,
    Create2Exploit,
}

impl std::fmt::Display for VulnerabilityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilityKind::UnprotectedSelfDestruct => write!(f, "UNPROTECTED_SELFDESTRUCT"),
            VulnerabilityKind::DangerousDelegatecall => write!(f, "DANGEROUS_DELEGATECALL"),
            VulnerabilityKind::MissingAccessControl => write!(f, "MISSING_ACCESS_CONTROL"),
            VulnerabilityKind::ReentrancyRisk => write!(f, "REENTRANCY_RISK"),
            VulnerabilityKind::PrivilegedCallcode => write!(f, "PRIVILEGED_CALLCODE"),
            VulnerabilityKind::SuspiciousBytecode => write!(f, "SUSPICIOUS_BYTECODE"),
            VulnerabilityKind::Create2Exploit => write!(f, "CREATE2_EXPLOIT"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityReport {
    pub id: String,
    pub chain: String,
    pub contract_address: String,
    pub tx_hash: String,
    pub severity: Severity,
    pub kind: VulnerabilityKind,
    pub description: String,
    pub function_selector: Option<String>,
    pub flagged_selectors: Vec<String>,
    pub state_delta: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub fork_validated: bool,
    pub confidence_score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerStatusSnapshot {
    pub chain: String,
    pub running: bool,
    pub chain_id: u64,
    pub endpoint_count: usize,
    pub healthy_endpoints: usize,
    pub processed_transactions: u64,
    pub flagged_contracts: u64,
    pub uptime: String,
    pub anvil_connected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointHealthSnapshot {
    pub endpoint: String,
    pub is_healthy: bool,
    pub failures: u32,
    pub requests_served: u64,
    pub avg_latency_ms: f64,
}

pub struct VulnerabilityReporter {
    output_dir: PathBuf,
    report_count: AtomicUsize,
}

impl VulnerabilityReporter {
    pub fn new(output_dir: String) -> Self {
        Self {
            output_dir: PathBuf::from(output_dir),
            report_count: AtomicUsize::new(0),
        }
    }

    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.output_dir).await?;
        info!("Reports directory: {}", self.output_dir.display());
        Ok(())
    }

    pub async fn submit(&self, report: &VulnerabilityReport) -> Result<()> {
        self.report_count.fetch_add(1, Ordering::Relaxed);
        self.write_report(report).await
    }

    async fn write_report(&self, report: &VulnerabilityReport) -> Result<()> {
        let filename = format!(
            "{}_{}_{}",
            report.severity.to_string().to_lowercase(),
            report.kind.to_string().to_lowercase(),
            &report.id[..8]
        );

        let json_path = self.output_dir.join(format!("{}.json", filename));
        let json = serde_json::to_string_pretty(report)?;
        if let Err(error) = fs::write(&json_path, &json).await {
            error!("Failed to write JSON report: {}", error);
        }

        let md_path = self.output_dir.join(format!("{}.md", filename));
        let markdown = report.to_markdown();
        if let Err(error) = fs::write(&md_path, markdown).await {
            warn!("Failed to write Markdown report: {}", error);
        }

        Ok(())
    }
}

impl VulnerabilityReport {
    pub fn to_markdown(&self) -> String {
        let selectors = if self.flagged_selectors.is_empty() {
            "- none".to_string()
        } else {
            self.flagged_selectors
                .iter()
                .map(|selector| format!("- `{selector}`"))
                .collect::<Vec<_>>()
                .join("\n")
        };

        format!(
            "# Ghost Scanner Vulnerability Report\n\n## Summary\n\n- Report ID: `{}`\n- Chain: `{}`\n- Contract: `{}`\n- Transaction: `{}`\n- Severity: `{}`\n- Kind: `{}`\n- Confidence: `{}`\n- Fork validated: `{}`\n- Timestamp: `{}`\n\n## Description\n\n{}\n\n## Flagged Selectors\n\n{}\n\n## State Delta\n\n```\n{}\n```\n",
            self.id,
            self.chain,
            self.contract_address,
            self.tx_hash,
            self.severity,
            self.kind,
            self.confidence_score,
            self.fork_validated,
            self.timestamp.to_rfc3339(),
            self.description,
            selectors,
            self.state_delta.as_deref().unwrap_or("No state delta recorded")
        )
    }
}
