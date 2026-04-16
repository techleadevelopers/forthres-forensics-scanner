use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};
use tokio_tungstenite::connect_async;

use crate::bytecode::{BytecodeAnalysis, BytecodeScanner, PatternSeverity};
use crate::config::ScannerConfig;
use crate::forensics::ForensicsEngine;
use crate::load_balancer::{LoadBalancer, WsConnectionRequest};
use crate::reporter::{
    EndpointHealthSnapshot, ScannerStatusSnapshot, Severity, VulnerabilityKind, VulnerabilityReport,
    VulnerabilityReporter,
};

#[derive(Debug, Clone, Copy)]
pub enum ScanMode {
    Fast,
    Deep,
}

#[derive(Debug, Clone, Copy)]
pub enum ForkMode {
    Auto,
    Force,
    Off,
}

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub contract_address: String,
    pub mode: ScanMode,
    pub simulation: bool,
    pub fork: ForkMode,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ScanEvent {
    Log {
        message: String,
        level: &'static str,
        ts: String,
    },
    Step {
        id: &'static str,
        label: &'static str,
        status: &'static str,
    },
    Complete {
        report: VulnerabilityReport,
    },
    Error {
        message: String,
    },
}

pub struct ScanStream;

impl ScanStream {
    pub fn new() -> Self {
        Self
    }

    pub fn emit(&mut self, event: ScanEvent) {
        println!("{}", serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string()));
    }

    pub fn complete(&self, report: VulnerabilityReport) -> ScanEvent {
        ScanEvent::Complete { report }
    }
}

struct RpcClient {
    client: Client,
    endpoints: Vec<String>,
}

impl RpcClient {
    fn new(endpoints: Vec<String>) -> Result<Self> {
        Ok(Self {
            client: Client::builder().timeout(Duration::from_secs(20)).build()?,
            endpoints,
        })
    }

    async fn call<T>(&self, method: &str, params: Value) -> Result<(T, String)>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut errors = Vec::new();

        for endpoint in &self.endpoints {
            match self.call_endpoint(endpoint, method, params.clone()).await {
                Ok(value) => return Ok((value, redact_endpoint(endpoint))),
                Err(error) => errors.push(format!("{} {}", redact_endpoint(endpoint), error)),
            }
        }

        Err(anyhow!(errors.join(" | ")))
    }

    async fn call_endpoint<T>(&self, endpoint: &str, method: &str, params: Value) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self
            .client
            .post(endpoint)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .with_context(|| format!("failed request to {}", redact_endpoint(endpoint)))?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("returned HTTP {}", status);
        }

        let payload = response.json::<JsonRpcResponse<T>>().await?;
        if let Some(error) = payload.error {
            anyhow::bail!("RPC error {}: {}", error.code, error.message);
        }

        payload.result.ok_or_else(|| anyhow!("missing JSON-RPC result"))
    }
}

#[derive(Debug, serde::Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, serde::Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

pub async fn scan_contract(
    config: &ScannerConfig,
    request: ScanRequest,
    mut emit: impl FnMut(ScanEvent),
) -> Result<VulnerabilityReport> {
    let reporter = VulnerabilityReporter::new(config.output_dir.clone());
    reporter.init().await?;

    let rpc = RpcClient::new(config.http_endpoints.clone())?;
    let forensics = ForensicsEngine::new(config.anvil_url.clone(), config.chain_id);

    emit(log_event(
        format!("Starting Rust scanner for {}", request.contract_address),
        "info",
    ));
    emit(log_event(
        format!(
            "Mode={} Simulation={} Fork={}",
            mode_label(request.mode),
            request.simulation,
            fork_label(request.fork)
        ),
        "info",
    ));

    emit(step_event("bytecode", "Fetch & decode bytecode", "running"));
    let (bytecode_hex, rpc_source): (String, String) = rpc
        .call(
            "eth_getCode",
            json!([request.contract_address.as_str(), "latest"]),
        )
        .await?;

    if bytecode_hex == "0x" {
        anyhow::bail!("No deployed bytecode found for this address");
    }

    let bytecode = BytecodeScanner::decode_hex(&bytecode_hex)
        .ok_or_else(|| anyhow!("Failed to decode contract bytecode"))?;
    emit(log_event(
        format!(
            "Fetched bytecode from live RPC ({}) with {} bytes",
            rpc_source,
            bytecode.len()
        ),
        "success",
    ));
    emit(step_event("bytecode", "Fetch & decode bytecode", "done"));

    emit(step_event("opcodes", "Opcode analysis", "running"));
    let analysis = BytecodeScanner::analyze(&bytecode);
    if analysis.flags.is_empty() {
        emit(log_event("No dangerous opcodes detected in runtime bytecode".to_string(), "info"));
    } else {
        for flag in &analysis.flags {
            emit(log_event(
                format!("{} at offset 0x{:x}", opcode_name(flag.opcode), flag.offset),
                "warn",
            ));
        }
    }
    emit(step_event("opcodes", "Opcode analysis", "done"));

    emit(step_event("selectors", "ABI selector extraction", "running"));
    let selectors = collect_selectors(&analysis);
    emit(log_event(
        format!("Extracted {} selectors from live bytecode", selectors.len()),
        "info",
    ));
    let dangerous_matches = BytecodeScanner::match_dangerous_signatures(&analysis.function_selectors);
    for dangerous in &dangerous_matches {
        emit(log_event(format!("Dangerous selector match: {dangerous}"), "warn"));
    }
    emit(step_event("selectors", "ABI selector extraction", "done"));

    let mut simulation_confirmed = false;
    if request.simulation {
        emit(step_event("simulation", "eth_call simulation", "running"));
        let selectors_to_simulate = match request.mode {
            ScanMode::Fast => selectors.iter().take(2).cloned().collect::<Vec<_>>(),
            ScanMode::Deep => selectors.iter().take(5).cloned().collect::<Vec<_>>(),
        };

        if selectors_to_simulate.is_empty() {
            emit(log_event("No selectors available for eth_call simulation".to_string(), "info"));
        }

        for selector in selectors_to_simulate {
            match rpc
                .call::<String>(
                    "eth_call",
                    json!([
                        {
                            "to": request.contract_address.as_str(),
                            "data": selector,
                        },
                        "latest"
                    ]),
                )
                .await
            {
                Ok((result, _)) if result != "0x" => {
                    simulation_confirmed = true;
                    emit(log_event(
                        format!("Selector {} returned {}...", selector, truncate(&result, 18)),
                        "success",
                    ));
                }
                Ok(_) => {}
                Err(error) => emit(log_event(
                    format!("Selector {} reverted during eth_call: {}", selector, error),
                    "warn",
                )),
            }
        }

        emit(step_event("simulation", "eth_call simulation", "done"));
    } else {
        emit(step_event("simulation", "eth_call simulation", "skipped"));
    }

    let provisional_score = calculate_confidence(&analysis, dangerous_matches.len(), simulation_confirmed, false);
    let should_run_fork = match request.fork {
        ForkMode::Force => true,
        ForkMode::Off => false,
        ForkMode::Auto => provisional_score >= 60,
    };

    let mut fork_validated = false;
    let mut state_delta = None;

    if should_run_fork {
        emit(step_event("fork", "Anvil fork execution", "running"));
        match forensics
            .validate_with_fork(&request.contract_address, &analysis, "0x0000000000000000000000000000000000000000")
            .await
        {
            Ok(Some(result)) => {
                fork_validated =
                    result.unauthorized_access || result.balance_drained || result.ownership_changed;
                state_delta = Some(result.state_delta);
                if fork_validated {
                    emit(log_event(
                        "Fork validation confirmed a reachable unauthorized execution path".to_string(),
                        "warn",
                    ));
                } else {
                    emit(log_event(
                        "Fork validation completed without exploitable state change".to_string(),
                        "info",
                    ));
                }
            }
            Ok(None) => emit(log_event(
                "Fork validation skipped because Anvil is unavailable".to_string(),
                "warn",
            )),
            Err(error) => emit(log_event(format!("Fork validation failed: {error}"), "warn")),
        }
        emit(step_event("fork", "Anvil fork execution", "done"));
    } else {
        emit(step_event("fork", "Anvil fork execution", "skipped"));
        emit(log_event(
            format!("Fork skipped because confidence {provisional_score}/100 is below threshold"),
            "info",
        ));
    }

    let confidence_score = calculate_confidence(
        &analysis,
        dangerous_matches.len(),
        simulation_confirmed,
        fork_validated,
    );
    let severity = classify_severity(confidence_score, &analysis);
    let kind = classify_kind(&analysis, !dangerous_matches.is_empty());
    let report = VulnerabilityReport {
        id: uuid::Uuid::new_v4().to_string(),
        contract_address: request.contract_address.clone(),
        tx_hash: format!("manual-scan:{}", uuid::Uuid::new_v4()),
        severity,
        kind,
        description: build_description(
            &request.contract_address,
            &rpc_source,
            &analysis,
            &dangerous_matches,
            request.simulation,
            simulation_confirmed,
            fork_validated,
            confidence_score,
        ),
        function_selector: selectors.first().cloned(),
        flagged_selectors: selectors,
        state_delta,
        timestamp: Utc::now(),
        fork_validated,
        confidence_score,
    };

    reporter.submit(&report).await?;
    emit(log_event(
        format!(
            "Scan complete. Severity={} Kind={} Confidence={}/100",
            report.severity, report.kind, report.confidence_score
        ),
        "success",
    ));

    Ok(report)
}

pub async fn collect_status(config: &ScannerConfig) -> Result<ScannerStatusSnapshot> {
    let endpoints = collect_endpoints(config).await?;
    let anvil_connected = is_anvil_connected(config).await;

    Ok(ScannerStatusSnapshot {
        running: endpoints.iter().any(|endpoint| endpoint.is_healthy),
        chain_id: config.chain_id,
        endpoint_count: endpoints.len(),
        healthy_endpoints: endpoints.iter().filter(|endpoint| endpoint.is_healthy).count(),
        processed_transactions: 0,
        flagged_contracts: 0,
        uptime: "managed-by-api-server".to_string(),
        anvil_connected,
    })
}

pub async fn collect_endpoints(config: &ScannerConfig) -> Result<Vec<EndpointHealthSnapshot>> {
    let lb = LoadBalancer::new(config.ws_endpoints.clone());

    for endpoint in &config.ws_endpoints {
        probe_ws_endpoint(&lb, endpoint).await;
    }

    let mut summary = lb
        .health_summary()
        .into_iter()
        .map(|entry| EndpointHealthSnapshot {
            endpoint: redact_endpoint(&entry.endpoint),
            is_healthy: entry.is_healthy,
            failures: entry.failures,
            requests_served: entry.requests_served,
            avg_latency_ms: entry.avg_latency_ms,
        })
        .collect::<Vec<_>>();

    summary.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
    Ok(summary)
}

async fn probe_ws_endpoint(lb: &LoadBalancer, endpoint: &str) {
    let request = WsConnectionRequest::new(endpoint.to_string());
    match connect_async(endpoint).await {
        Ok((mut stream, _)) => {
            lb.record_success(endpoint, request.elapsed_ms());
            let _ = stream.close(None).await;
        }
        Err(_) => lb.record_failure(endpoint),
    }
}

async fn is_anvil_connected(config: &ScannerConfig) -> bool {
    let client = match Client::builder().timeout(Duration::from_secs(5)).build() {
        Ok(client) => client,
        Err(_) => return false,
    };

    match client
        .post(&config.anvil_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_chainId",
            "params": [],
        }))
        .send()
        .await
    {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

fn collect_selectors(analysis: &BytecodeAnalysis) -> Vec<String> {
    analysis
        .function_selectors
        .iter()
        .map(BytecodeScanner::selector_to_hex)
        .collect()
}

fn calculate_confidence(
    analysis: &BytecodeAnalysis,
    dangerous_match_count: usize,
    simulation_confirmed: bool,
    fork_validated: bool,
) -> u32 {
    let mut score = analysis.risk_score + dangerous_match_count as u32 * 10;

    if simulation_confirmed {
        score += 15;
    }

    if fork_validated {
        score += 20;
    }

    score.min(100)
}

fn classify_severity(score: u32, analysis: &BytecodeAnalysis) -> Severity {
    if matches!(analysis.top_severity(), Some(PatternSeverity::Critical)) || score >= 85 {
        Severity::Critical
    } else if matches!(analysis.top_severity(), Some(PatternSeverity::High)) || score >= 65 {
        Severity::High
    } else if score >= 40 {
        Severity::Medium
    } else if score >= 15 {
        Severity::Low
    } else {
        Severity::Info
    }
}

fn classify_kind(analysis: &BytecodeAnalysis, has_dangerous_matches: bool) -> VulnerabilityKind {
    if analysis.has_selfdestruct {
        VulnerabilityKind::UnprotectedSelfDestruct
    } else if analysis.has_delegatecall {
        VulnerabilityKind::DangerousDelegatecall
    } else if analysis.has_callcode {
        VulnerabilityKind::PrivilegedCallcode
    } else if analysis.has_create2 {
        VulnerabilityKind::Create2Exploit
    } else if has_dangerous_matches {
        VulnerabilityKind::MissingAccessControl
    } else {
        VulnerabilityKind::SuspiciousBytecode
    }
}

fn build_description(
    contract_address: &str,
    rpc_source: &str,
    analysis: &BytecodeAnalysis,
    dangerous_matches: &[String],
    simulation_enabled: bool,
    simulation_confirmed: bool,
    fork_validated: bool,
    confidence_score: u32,
) -> String {
    let mut segments = vec![format!(
        "Rust scanner executed against {} using {}.",
        contract_address, rpc_source
    )];

    if analysis.flags.is_empty() {
        segments.push("No critical opcode signature was found.".to_string());
    } else {
        segments.push(format!(
            "Detected opcodes: {}.",
            analysis
                .flags
                .iter()
                .map(|flag| opcode_name(flag.opcode))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if dangerous_matches.is_empty() {
        segments.push("No dangerous selector match was found.".to_string());
    } else {
        segments.push(format!("Dangerous selectors: {}.", dangerous_matches.join("; ")));
    }

    segments.push(if simulation_enabled {
        if simulation_confirmed {
            "eth_call simulation produced executable return data.".to_string()
        } else {
            "eth_call simulation did not confirm an executable path.".to_string()
        }
    } else {
        "eth_call simulation was disabled.".to_string()
    });

    segments.push(if fork_validated {
        "Fork validation confirmed a reachable unauthorized execution path.".to_string()
    } else {
        "Fork validation did not confirm a state-changing exploit.".to_string()
    });

    segments.push(format!("Confidence score: {confidence_score}/100."));
    segments.join(" ")
}

fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0xF4 => "DELEGATECALL",
        0xFF => "SELFDESTRUCT",
        0xF2 => "CALLCODE",
        0xF5 => "CREATE2",
        _ => "UNKNOWN",
    }
}

fn mode_label(mode: ScanMode) -> &'static str {
    match mode {
        ScanMode::Fast => "FAST",
        ScanMode::Deep => "DEEP",
    }
}

fn fork_label(mode: ForkMode) -> &'static str {
    match mode {
        ForkMode::Auto => "AUTO",
        ForkMode::Force => "FORCE",
        ForkMode::Off => "OFF",
    }
}

fn log_event(message: String, level: &'static str) -> ScanEvent {
    ScanEvent::Log {
        message,
        level,
        ts: Utc::now().to_rfc3339(),
    }
}

fn step_event(id: &'static str, label: &'static str, status: &'static str) -> ScanEvent {
    ScanEvent::Step { id, label, status }
}

fn redact_endpoint(endpoint: &str) -> String {
    let Some((prefix, secret)) = endpoint.rsplit_once('/') else {
        return endpoint.to_string();
    };

    if secret.len() <= 4 {
        return endpoint.to_string();
    }

    format!("{}/***{}", prefix, &secret[secret.len() - 4..])
}

fn truncate(value: &str, len: usize) -> &str {
    let end = value.len().min(len);
    &value[..end]
}
