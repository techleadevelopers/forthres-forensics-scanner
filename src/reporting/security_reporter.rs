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
    UpgradeableProxy,
    AdminControlledContract,
    GenericContract,
    ExploitConfirmed,
    ExploitPossible,
    HighRiskPattern,
    MissingAccessControl,
    ReentrancyRisk,
    PrivilegedCallcode,
    SuspiciousBytecode,
    Create2Exploit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BehavioralKind {
    Benign,
    ExecutorContract,
    MaliciousInfrastructure,
}

impl std::fmt::Display for BehavioralKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BehavioralKind::Benign => write!(f, "BENIGN"),
            BehavioralKind::ExecutorContract => write!(f, "EXECUTOR_CONTRACT"),
            BehavioralKind::MaliciousInfrastructure => write!(f, "MALICIOUS_INFRASTRUCTURE"),
        }
    }
}

impl std::fmt::Display for VulnerabilityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilityKind::UnprotectedSelfDestruct => write!(f, "UNPROTECTED_SELFDESTRUCT"),
            VulnerabilityKind::DangerousDelegatecall => write!(f, "DANGEROUS_DELEGATECALL"),
            VulnerabilityKind::UpgradeableProxy => write!(f, "UPGRADEABLE_PROXY"),
            VulnerabilityKind::AdminControlledContract => write!(f, "ADMIN_CONTROLLED_CONTRACT"),
            VulnerabilityKind::GenericContract => write!(f, "GENERIC_CONTRACT"),
            VulnerabilityKind::ExploitConfirmed => write!(f, "EXPLOIT_CONFIRMED"),
            VulnerabilityKind::ExploitPossible => write!(f, "EXPLOIT_POSSIBLE"),
            VulnerabilityKind::HighRiskPattern => write!(f, "HIGH_RISK_PATTERN"),
            VulnerabilityKind::MissingAccessControl => write!(f, "MISSING_ACCESS_CONTROL"),
            VulnerabilityKind::ReentrancyRisk => write!(f, "REENTRANCY_RISK"),
            VulnerabilityKind::PrivilegedCallcode => write!(f, "PRIVILEGED_CALLCODE"),
            VulnerabilityKind::SuspiciousBytecode => write!(f, "SUSPICIOUS_BYTECODE"),
            VulnerabilityKind::Create2Exploit => write!(f, "CREATE2_EXPLOIT"),
        }
    }
}

// ============================================================
// NOVAS STRUCTS OFENSIVAS
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExploitPathReport {
    pub entry_selector: String,
    pub probability: f64,
    pub economic_value_eth: f64,
    pub required_conditions: Vec<String>,
    pub state_changes: Vec<String>,
    pub poc_calldata: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MevOpportunityReport {
    pub mev_type: String,
    pub estimated_profit_eth: f64,
    pub competition_score: f64,
    pub suggested_tip_bps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyReport {
    pub proxy_type: Option<String>,
    pub implementation: Option<String>,
    pub admin: Option<String>,
    pub beacon: Option<String>,
    pub is_access_controlled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceReport {
    pub fork_validated: bool,
    pub exploit_path: bool,
    pub simulation_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueFlowReport {
    pub can_move_funds: bool,
    pub role: String,
    pub risk_surface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BehavioralRiskReport {
    pub kind: BehavioralKind,
    pub score: f64,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BytecodeSignalReport {
    pub label: String,
    pub value: String,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BytecodeConfidenceReport {
    pub score: u32,
    pub dispatcher_confidence: String,
    pub function_count: usize,
    pub basic_block_count: usize,
    pub fallback_detected: bool,
    pub receive_detected: bool,
    pub access_control_score: u32,
    pub summary: String,
    pub capabilities: Vec<String>,
    pub signals: Vec<BytecodeSignalReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkValidationReport {
    pub attempted: bool,
    pub strategy: String,
    pub provider: String,
    pub confirmed: bool,
    pub selectors_tested: usize,
    pub reason: String,
    pub state_change_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionTraceReport {
    pub title: String,
    pub detail: String,
    pub weight: i32,
}

// ============================================================
// VULNERABILITY REPORT COM CAMPOS OFENSIVOS
// ============================================================

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
    pub proxy: Option<ProxyReport>,
    pub evidence: EvidenceReport,
    pub value_flow: ValueFlowReport,
    pub behavioral_risk: BehavioralRiskReport,
    pub bytecode_confidence: BytecodeConfidenceReport,
    pub fork_validation: ForkValidationReport,
    pub decision_traces: Vec<DecisionTraceReport>,
    // NOVOS CAMPOS OFENSIVOS
    pub exploit_paths: Vec<ExploitPathReport>,
    pub mev_opportunities: Vec<MevOpportunityReport>,
    pub exploitation_probability: f64,
    pub risk_adjusted_value: f64,
    pub recommendation: String,
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

        let proxy_section = if let Some(proxy) = &self.proxy {
            format!(
                "\n## Proxy Metadata\n\n- Proxy Type: `{}`\n- Implementation: `{}`\n- Admin: `{}`\n- Beacon: `{}`\n- Access Controlled: `{}`\n",
                proxy.proxy_type.as_deref().unwrap_or("not detected"),
                proxy.implementation.as_deref().unwrap_or("not detected"),
                proxy.admin.as_deref().unwrap_or("not detected"),
                proxy.beacon.as_deref().unwrap_or("not detected"),
                if proxy.is_access_controlled { "yes" } else { "no" }
            )
        } else {
            String::new()
        };

        let evidence_section = format!(
            "\n## Evidence\n\n- Fork Validated: `{}`\n- Exploit Path: `{}`\n- Simulation Only: `{}`\n",
            if self.evidence.fork_validated { "yes" } else { "no" },
            if self.evidence.exploit_path { "yes" } else { "no" },
            if self.evidence.simulation_only { "yes" } else { "no" }
        );

        let value_flow_section = format!(
            "\n## Value Flow\n\n- Can Move Funds: `{}`\n- Role: `{}`\n- Risk Surface: `{}`\n",
            if self.value_flow.can_move_funds { "yes" } else { "no" },
            self.value_flow.role,
            self.value_flow.risk_surface
        );

        let behavioral_section = format!(
            "\n## Behavioral Risk\n\n- Kind: `{}`\n- Score: `{:.2}`\n- Rationale: `{}`\n",
            self.behavioral_risk.kind,
            self.behavioral_risk.score,
            self.behavioral_risk.rationale
        );

        let bytecode_confidence_section = format!(
            "\n## Bytecode Confidence\n\n- Score: `{}`\n- Dispatcher Confidence: `{}`\n- Function Count: `{}`\n- Basic Blocks: `{}`\n- Fallback Detected: `{}`\n- Receive Detected: `{}`\n- Access Control Score: `{}`\n- Capabilities: `{}`\n- Summary: `{}`\n",
            self.bytecode_confidence.score,
            self.bytecode_confidence.dispatcher_confidence,
            self.bytecode_confidence.function_count,
            self.bytecode_confidence.basic_block_count,
            if self.bytecode_confidence.fallback_detected { "yes" } else { "no" },
            if self.bytecode_confidence.receive_detected { "yes" } else { "no" },
            self.bytecode_confidence.access_control_score,
            if self.bytecode_confidence.capabilities.is_empty() {
                "none".to_string()
            } else {
                self.bytecode_confidence.capabilities.join(", ")
            },
            self.bytecode_confidence.summary
        );

        let bytecode_signals_section = if self.bytecode_confidence.signals.is_empty() {
            "\n## Bytecode Signals\n\n- none\n".to_string()
        } else {
            let mut section = String::from("\n## Bytecode Signals\n\n");
            for signal in &self.bytecode_confidence.signals {
                section.push_str(&format!(
                    "- **{}**: `{}` ({})\n",
                    signal.label, signal.value, signal.impact
                ));
            }
            section
        };

        let fork_validation_section = format!(
            "\n## Fork Validation\n\n- Attempted: `{}`\n- Strategy: `{}`\n- Provider: `{}`\n- Confirmed: `{}`\n- Selectors Tested: `{}`\n- Reason: `{}`\n- State Change Summary: `{}`\n",
            if self.fork_validation.attempted { "yes" } else { "no" },
            self.fork_validation.strategy,
            self.fork_validation.provider,
            if self.fork_validation.confirmed { "yes" } else { "no" },
            self.fork_validation.selectors_tested,
            self.fork_validation.reason,
            self.fork_validation.state_change_summary.as_deref().unwrap_or("none")
        );

        let decision_traces_section = if self.decision_traces.is_empty() {
            "\n## Decision Traces\n\n- none\n".to_string()
        } else {
            let mut section = String::from("\n## Decision Traces\n\n");
            for trace in &self.decision_traces {
                section.push_str(&format!(
                    "- **{}**: {} (weight `{}`)\n",
                    trace.title, trace.detail, trace.weight
                ));
            }
            section
        };

        // NOVA SEÇÃO: Exploit Paths
        let exploit_paths_section = if self.exploit_paths.is_empty() {
            "No exploit paths identified.\n".to_string()
        } else {
            let mut section = String::from("\n## Exploit Paths\n\n");
            for (i, path) in self.exploit_paths.iter().enumerate() {
                section.push_str(&format!(
                    "### Path {}\n\n- **Entry Selector:** `{}`\n- **Probability:** `{:.2}%`\n- **Economic Value:** `{:.6} ETH`\n- **Required Conditions:**\n",
                    i + 1,
                    path.entry_selector,
                    path.probability * 100.0,
                    path.economic_value_eth
                ));
                
                if path.required_conditions.is_empty() {
                    section.push_str("  - none\n");
                } else {
                    for cond in &path.required_conditions {
                        section.push_str(&format!("  - `{}`\n", cond));
                    }
                }
                
                section.push_str("\n- **State Changes:**\n");
                if path.state_changes.is_empty() {
                    section.push_str("  - none\n");
                } else {
                    for change in &path.state_changes {
                        section.push_str(&format!("  - `{}`\n", change));
                    }
                }
                
                section.push_str(&format!("\n- **PoC Calldata:** `{}`\n\n", path.poc_calldata));
            }
            section
        };

        // NOVA SEÇÃO: MEV Opportunities
        let mev_section = if self.mev_opportunities.is_empty() {
            "No MEV extraction opportunities identified.\n".to_string()
        } else {
            let mut section = String::from("\n## MEV Extraction Opportunities\n\n");
            section.push_str("| Type | Profit (ETH) | Competition | Tip (bps) |\n");
            section.push_str("|------|--------------|-------------|-----------|\n");
            for mev in &self.mev_opportunities {
                section.push_str(&format!(
                    "| {} | {:.6} | {:.2} | {} |\n",
                    mev.mev_type,
                    mev.estimated_profit_eth,
                    mev.competition_score,
                    mev.suggested_tip_bps
                ));
            }
            section
        };

        // NOVA SEÇÃO: Resumo Ofensivo
        let offensive_summary = format!(
            "\n## Offensive Analysis Summary\n\n- **Exploitation Probability:** `{:.2}%`\n- **Risk-Adjusted Value:** `{:.6} ETH`\n- **Recommendation:** `{}`\n",
            self.exploitation_probability * 100.0,
            self.risk_adjusted_value,
            self.recommendation
        );

        format!(
            "# Ghost Scanner Vulnerability Report\n\n## Summary\n\n- Report ID: `{}`\n- Chain: `{}`\n- Contract: `{}`\n- Transaction: `{}`\n- Severity: `{}`\n- Kind: `{}`\n- Confidence: `{}`\n- Fork validated: `{}`\n- Timestamp: `{}`\n\n## Description\n\n{}\n{}{}{}{}{}{}{}{}\n## Flagged Selectors\n\n{}\n\n## State Delta\n\n```\n{}\n```\n{}{}{}",
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
            proxy_section,
            evidence_section,
            value_flow_section,
            behavioral_section,
            bytecode_confidence_section,
            bytecode_signals_section,
            fork_validation_section,
            decision_traces_section,
            selectors,
            self.state_delta.as_deref().unwrap_or("No state delta recorded"),
            exploit_paths_section,
            mev_section,
            offensive_summary
        )
    }
}
