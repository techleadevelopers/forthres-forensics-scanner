use std::{panic::AssertUnwindSafe, time::Duration};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use futures_util::{future::join_all, FutureExt};
use reqwest::Client;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::time::timeout;
use tokio_tungstenite::connect_async;

use crate::bytecode::{BytecodeAnalysis, BytecodeScanner};
use crate::config::ScannerConfig;
use crate::forensics::ForensicsEngine;
use crate::load_balancer::{LoadBalancer, WsConnectionRequest};
use crate::offensive::{OffensiveConfig, OffensiveEngine};
use crate::reporter::{
    BehavioralKind, BehavioralRiskReport, BytecodeConfidenceReport, BytecodeSignalReport,
    DecisionTraceReport, EndpointHealthSnapshot, EvidenceReport, ForkValidationReport, ProxyReport,
    ScannerStatusSnapshot, Severity, ValueFlowReport, VulnerabilityKind, VulnerabilityReport, VulnerabilityReporter,
};

#[derive(Debug, Clone, Copy)]
pub enum ScanMode {
    Fast,
    Deep,
}

#[derive(Debug, Clone, Copy, PartialEq)]
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

#[derive(Debug, Default, Clone, Copy)]
struct SimulationOutcome {
    attempts: usize,
    successes: usize,
    reverts: usize,
}

#[derive(Debug, Clone)]
struct ReplayCandidate {
    selector: String,
    score: u32,
}

impl SimulationOutcome {
    fn has_confirmed_execution(&self) -> bool {
        self.successes > 0
    }

    fn all_reverted(&self) -> bool {
        self.attempts > 0 && self.reverts == self.attempts && self.successes == 0
    }
}

#[derive(Debug, Default, Clone)]
struct ProxyMetadata {
    implementation: Option<String>,
    admin: Option<String>,
    beacon: Option<String>,
}

impl ProxyMetadata {
    fn proxy_type(&self) -> Option<&'static str> {
        if self.beacon.is_some() {
            Some("EIP-1967 Beacon")
        } else if self.implementation.is_some() && self.admin.is_some() {
            Some("EIP-1967 Transparent")
        } else if self.implementation.is_some() {
            Some("EIP-1967/UUPS")
        } else {
            None
        }
    }

    fn is_proxy(&self) -> bool {
        self.implementation.is_some() || self.beacon.is_some()
    }

    fn has_admin_control(&self) -> bool {
        self.admin.is_some()
    }
}

#[derive(Debug, Clone)]
struct Resolution {
    severity: Severity,
    kind: VulnerabilityKind,
    confidence_score: u32,
}

#[derive(Debug, Clone, Copy)]
enum DispatcherConfidence {
    High,
    Medium,
    Low,
}

impl DispatcherConfidence {
    fn as_str(self) -> &'static str {
        match self {
            DispatcherConfidence::High => "HIGH",
            DispatcherConfidence::Medium => "MEDIUM",
            DispatcherConfidence::Low => "LOW",
        }
    }
}

const STANDARD_TOKEN_SELECTORS: [&str; 6] = [
    "0x06fdde03",
    "0x095ea7b3",
    "0x18160ddd",
    "0x70a08231",
    "0xa9059cbb",
    "0xdd62ed3e",
];
const ERC20_FLOW_SELECTORS: [&str; 4] = [
    "0x23b872dd",
    "0xa9059cbb",
    "0x095ea7b3",
    "0xdd62ed3e",
];
const DEX_FLOW_SELECTORS: [&str; 6] = [
    "0x38ed1739",
    "0x18cbafe5",
    "0x7ff36ab5",
    "0x4a25d94a",
    "0xe8e33700",
    "0xbaa2abde",
];

#[derive(Debug, Clone, Copy)]
enum ContractRole {
    Executor,
    Vault,
    Router,
    Token,
    Proxy,
    Generic,
}

impl ContractRole {
    fn as_str(self) -> &'static str {
        match self {
            ContractRole::Executor => "EXECUTOR",
            ContractRole::Vault => "VAULT",
            ContractRole::Router => "ROUTER",
            ContractRole::Token => "TOKEN",
            ContractRole::Proxy => "PROXY",
            ContractRole::Generic => "GENERIC",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RiskSurface {
    ExternalFunds,
    ContractBalance,
    Limited,
}

impl RiskSurface {
    fn as_str(self) -> &'static str {
        match self {
            RiskSurface::ExternalFunds => "EXTERNAL_FUNDS",
            RiskSurface::ContractBalance => "CONTRACT_BALANCE",
            RiskSurface::Limited => "LIMITED",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ValueFlowHeuristics {
    can_move_funds: bool,
    role: ContractRole,
    risk_surface: RiskSurface,
}

#[derive(Debug, Clone)]
struct BehavioralInference {
    kind: BehavioralKind,
    score: f64,
    rationale: &'static str,
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

    async fn get_storage_at(&self, address: &str, slot: &str) -> Result<(String, String)> {
        self.call("eth_getStorageAt", json!([address, slot, "latest"])).await
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

const EIP1967_IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const EIP1967_ADMIN_SLOT: &str =
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const EIP1967_BEACON_SLOT: &str =
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

/// Análise RPC avançada que detecta ownership real e proteções
async fn advanced_rpc_analysis(
    rpc: &RpcClient,
    contract_address: &str,
    analysis: &BytecodeAnalysis,
    selectors: &[String],
) -> Result<(bool, Option<serde_json::Value>)> {
    let mut suspicious = false;
    let mut state_changes = Vec::new();
    
    // ============================================================
    // 1. DESCOBRE O OWNER REAL
    // ============================================================
    let mut real_owner = None;
    let owner_slots = [
        "0x0000000000000000000000000000000000000000000000000000000000000000", // slot 0
        "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", // EIP-1967 admin
    ];
    
    for slot in owner_slots {
        if let Ok((value, _)) = rpc.get_storage_at(contract_address, slot).await {
            if value != "0x0000000000000000000000000000000000000000000000000000000000000000" {
                // Extrai o endereço do storage (últimos 20 bytes)
                let addr_str = if value.len() >= 66 {
                    format!("0x{}", &value[value.len() - 40..])
                } else {
                    value.clone()
                };
                real_owner = Some(addr_str);
                tracing::info!("🔑 Owner detectado: {:?}", real_owner);
                break;
            }
        }
    }
    
    // ============================================================
    // 2. VERIFICA SLOTS PERIGOSOS
    // ============================================================
    let dangerous_slots = [
        ("owner", "0x0000000000000000000000000000000000000000000000000000000000000000"),
        ("pendingOwner", "0x0000000000000000000000000000000000000000000000000000000000000001"),
        ("guardian", "0x0000000000000000000000000000000000000000000000000000000000000002"),
    ];
    
    for (slot_name, slot_key) in dangerous_slots {
        match rpc.get_storage_at(contract_address, slot_key).await {
            Ok((value, _)) => {
                if value != "0x0000000000000000000000000000000000000000000000000000000000000000" {
                    suspicious = true;
                    state_changes.push(format!("{} slot contains non-zero value: {}", slot_name, &value[..20]));
                    tracing::warn!("⚠️ Slot {} não-zero detectado: {}", slot_name, value);
                }
            }
            Err(_) => {}
        }
    }
    
    // ============================================================
    // 3. TESTA PRIVILEGE ESCALATION (transferOwnership)
    // ============================================================
let dangerous_selectors = [
    ("transferOwnership", "0xf2fde38b"),
    ("renounceOwnership", "0x715018a6"),
    ("upgradeTo", "0x3659cfe6"),
    ("setAdmin", "0x7045eab0"),
];

// Se encontrou o owner real, testa se a função é protegida
if let Some(owner) = &real_owner {
    for (func_name, selector) in dangerous_selectors {
        if selectors.contains(&selector.to_string()) {
            tracing::info!("🔍 Testando {}(address) com diferentes callers", func_name);
            
            let test_address = "0x0000000000000000000000000000000000012345";
            let calldata = format!("{}{:0>64}", selector.trim_start_matches("0x"), test_address.trim_start_matches("0x"));
            let calldata = format!("0x{}", calldata);
            
            let test_callers = [
                ("random", "0x1111111111111111111111111111111111111111"),
                ("zero", "0x0000000000000000000000000000000000000000"),
                ("attacker", "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            ];
            
            let mut protected = true;
            
            for (caller_type, caller) in test_callers {
                let params = json!([
                    {
                        "to": contract_address,
                        "from": caller,
                        "data": calldata,
                    },
                    "latest"
                ]);
                
                match rpc.call::<String>("eth_call", params).await {
                    Ok((result, _)) => {
                        // Revert silencioso é proteção
                        if result == "0x" || result == "0x0000000000000000000000000000000000000000000000000000000000000000" {
                            tracing::debug!("{} com {}: revert silencioso (protegido)", func_name, caller_type);
                        } else if result != "0x" {
                            protected = false;
                            state_changes.push(format!(
                                "🚨 {} via {} succeeded with caller {}! Contrato VULNERÁVEL!",
                                func_name, selector, caller_type
                            ));
                            tracing::warn!("🚨 {} via {} succeeded! Contrato VULNERÁVEL!", func_name, selector);
                        }
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        if error_msg.contains("caller is not the owner") 
                            || error_msg.contains("Ownable") 
                            || error_msg.contains("only owner")
                            || error_msg.contains("onlyOwner") {
                            tracing::debug!("{} com {}: protegido por onlyOwner", func_name, caller_type);
                        } else {
                            tracing::debug!("{} com {} reverteu: {}", func_name, caller_type, error_msg);
                        }
                    }
                }
            }
            
            if protected {
                state_changes.push(format!(
                    "{} via {}: 🔒 PROTEGIDO (apenas owner real: {}). Não explorável publicamente.",
                    func_name, selector, owner
                ));
                tracing::info!("{} protegido - apenas owner pode chamar", func_name);
            } else {
                suspicious = true;
                state_changes.push(format!(
                    "🔥 EXPLOIT CONFIRMADO! {} pode ser chamado por qualquer caller!",
                    func_name
                ));
            }
        }
    }
}
    
    // ============================================================
    // 4. TESTES GERAIS COM DIFERENTES CALLERS
    // ============================================================
    let test_callers = [
        "0x0000000000000000000000000000000000000001",
        "0xB631BACe85E3d3c0851D756C7D75Cd19d9a4bC8d",
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    ];
    
    for selector in selectors.iter().take(10) {
        // Pula selectores perigosos que já testamos
        let is_dangerous = dangerous_selectors.iter().any(|(_, s)| s == selector);
        if is_dangerous {
            continue;
        }
        
        for caller in test_callers {
            let params = json!([
                {
                    "to": contract_address,
                    "from": caller,
                    "data": selector,
                },
                "latest"
            ]);
            
            match rpc.call::<String>("eth_call", params).await {
                Ok((result, _)) => {
                    if result != "0x" && !result.contains("0000000000000000000000000000000000000000000000000000000000000000") {
                        suspicious = true;
                        state_changes.push(format!(
                            "Selector {} from caller {} returned non-zero: {}", 
                            selector, 
                            &caller[..10], 
                            truncate(&result, 30)
                        ));
                    }
                }
                Err(_) => {}
            }
        }
    }
    
    // ============================================================
    // 5. TESTA TRANSFERÊNCIAS
    // ============================================================
    let transfer_selectors = ["0xa9059cbb", "0x23b872dd", "0x095ea7b3"];
    for selector in transfer_selectors {
        if selectors.contains(&selector.to_string()) {
            let calldata = format!("{}00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001", selector);
            
            // Testa com um caller aleatório que não seja o owner
            let test_caller = "0x1111111111111111111111111111111111111111";
            let params = json!([
                {
                    "to": contract_address,
                    "from": test_caller,
                    "data": calldata,
                },
                "latest"
            ]);
            
            match rpc.call::<String>("eth_call", params).await {
                Ok((result, _)) => {
                    if result != "0x" && result.contains("0000000000000000000000000000000000000000000000000000000000000001") {
                        suspicious = true;
                        state_changes.push(format!("Transfer selector {} succeeded with test params", selector));
                    }
                }
                Err(_) => {}
            }
        }
    }
    
    // ============================================================
    // 6. DELEGATECALL
    // ============================================================
    if analysis.has_delegatecall {
        suspicious = true;
        state_changes.push("DELEGATECALL opcode detected - potential for storage collision".to_string());
    }
    
    // ============================================================
    // 7. RESULTADO FINAL
    // ============================================================
    let delta = if !state_changes.is_empty() {
        Some(json!({
            "rpc_analysis": {
                "suspicious_patterns": state_changes,
                "analysis_type": "fallback_rpc",
                "contract": contract_address,
                "real_owner": real_owner,
            }
        }))
    } else {
        None
    };
    
    Ok((suspicious, delta))
}

pub async fn scan_contract(
    config: &ScannerConfig,
    request: ScanRequest,
    mut emit: impl FnMut(ScanEvent),
) -> Result<VulnerabilityReport> {
    let reporter = VulnerabilityReporter::new(config.output_dir.clone());
    reporter.init().await?;

    let rpc = RpcClient::new(config.http_endpoints.clone())?;
    
    // 🔥 AGORA USA SUA RPC PAGA (sem Tenderly)
    let fork_url = if request.fork == ForkMode::Force {
        tracing::info!("Usando Tenderly fork para validação (respeita onlyOwner)");
        std::env::var("TENDERLY_FORK_URL").expect("TENDERLY_FORK_URL must be set")
    } else {
        config.anvil_url.clone()
    };
    
    let forensics = ForensicsEngine::new(fork_url, Default::default());
    let live_chain_id = fetch_chain_id(&rpc).await?;
    if live_chain_id != config.chain_id {
        anyhow::bail!(
            "RPC chain mismatch: configured {} (id {}), but live RPC returned chain id {}. Fix SCANNER_CHAIN / SCANNER_CHAIN_ID / RPC_HTTP_ENDPOINTS before scanning.",
            config.chain.as_str(),
            config.chain_id,
            live_chain_id
        );
    }

    emit(log_event(
        format!(
            "Starting Rust scanner for {} on {}",
            request.contract_address,
            config.chain.as_str()
        ),
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
                format!(
                    "{} severity={} at offset 0x{:x}",
                    opcode_name(flag.opcode),
                    flag.severity,
                    flag.offset
                ),
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

    emit(step_event("proxy", "Proxy & admin slot analysis", "running"));
    let proxy = detect_proxy_metadata(&rpc, &request.contract_address).await?;
    if proxy.is_proxy() {
        let implementation = proxy.implementation.as_deref().unwrap_or("unknown");
        emit(log_event(
            format!("EIP-1967 proxy detected; implementation {implementation}"),
            "info",
        ));
        if let Some(admin) = proxy.admin.as_deref() {
            emit(log_event(
                format!("Proxy admin slot is set to {admin}; treating upgrade paths as access controlled until disproven"),
                "info",
            ));
        }
    } else {
        emit(log_event(
            "No EIP-1967 implementation or beacon slot detected".to_string(),
            "info",
        ));
    }
    emit(step_event("proxy", "Proxy & admin slot analysis", "done"));

    let replay_candidates = prioritized_selectors_for_replay(
        &analysis,
        &selectors,
        &dangerous_matches,
        &proxy,
        request.mode,
    );
    let prioritized_selectors = replay_candidates
        .iter()
        .map(|candidate| candidate.selector.clone())
        .collect::<Vec<_>>();
    if !replay_candidates.is_empty() {
        let summary = replay_candidates
            .iter()
            .map(|candidate| format!("{}({})", candidate.selector, candidate.score))
            .collect::<Vec<_>>()
            .join(", ");
        emit(log_event(
            format!("Prioritized replay selectors: {summary}"),
            "info",
        ));
    }

    let mut simulation = SimulationOutcome::default();
    if request.simulation {
        emit(step_event("simulation", "eth_call simulation", "running"));
        let selectors_to_simulate = prioritized_selectors.clone();

        if selectors_to_simulate.is_empty() {
            emit(log_event("No selectors available for eth_call simulation".to_string(), "info"));
        }

        for selector in selectors_to_simulate {
            simulation.attempts += 1;
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
                    simulation.successes += 1;
                    emit(log_event(
                        format!("Selector {} returned {}...", selector, truncate(&result, 18)),
                        "success",
                    ));
                }
                Ok(_) => {}
                Err(error) => {
                    simulation.reverts += 1;
                    emit(log_event(
                        format!("Selector {} reverted during eth_call: {}", selector, error),
                        "warn",
                    ));
                }
            }
        }

        if simulation.all_reverted() {
            emit(log_event(
                "All simulated selectors reverted; treating this as evidence of access control".to_string(),
                "info",
            ));
        }

        emit(step_event("simulation", "eth_call simulation", "done"));
    } else {
        emit(step_event("simulation", "eth_call simulation", "skipped"));
    }

    let provisional_score = calculate_confidence(
        &analysis,
        dangerous_matches.len(),
        simulation,
        false,
        false,
        simulation.all_reverted() || proxy.has_admin_control(),
    );
    let should_run_fork = match request.fork {
        ForkMode::Force => true,
        ForkMode::Off => false,
        ForkMode::Auto => analysis.has_delegatecall || provisional_score >= 60,
    };

    let mut fork_validated = false;
    let mut state_delta: Option<String> = None;
    let mut fork_reason = "Fork was not attempted".to_string();

    if should_run_fork {
    emit(step_event("fork", "Anvil fork execution", "running"));
    
    // 🔥 PRIMEIRO: Roda advanced_rpc_analysis para detectar onlyOwner
    match advanced_rpc_analysis(&rpc, &request.contract_address, &analysis, &prioritized_selectors).await {
        Ok((rpc_found_exploit, rpc_state_delta)) => {
            if rpc_found_exploit {
                // Só é potencialmente vulnerável - testa no fork
                match forensics
                    .validate_with_fork(
                        &request.contract_address,
                        &analysis,
                        &prioritized_selectors,
                        "0x0000000000000000000000000000000000000000",
                    )
                    .await
                {
                    Ok(Some(result)) => {
                        fork_validated = result.unauthorized_access || result.balance_drained || result.ownership_changed;
                        state_delta = Some(result.state_delta);
                        if fork_validated {
                            fork_reason = "Fork replay produced a reachable unauthorized execution path".to_string();
                            emit(log_event(
                                "Fork validation confirmed a reachable unauthorized execution path".to_string(),
                                "warn",
                            ));
                        } else {
                            fork_reason = "Fork executed but did not produce a confirming state change".to_string();
                            emit(log_event(
                                "Fork validation completed without exploitable state change".to_string(),
                                "info",
                            ));
                        }
                    }
                    Ok(None) => {
                        fork_reason = "Fork provider unavailable; advanced RPC evidence retained".to_string();
                        emit(log_event(
                            "Fork não disponível — usando análise RPC".to_string(),
                            "info",
                        ));
                        fork_validated = rpc_found_exploit;
                        state_delta = rpc_state_delta.map(|v| v.to_string());
                    }
                    Err(error) => {
                        fork_reason = format!("Fork validation failed; advanced RPC fallback retained: {error}");
                        emit(log_event(format!("Fork validation failed: {error}"), "warn"));
                        fork_validated = rpc_found_exploit;
                        state_delta = rpc_state_delta.map(|v| v.to_string());
                    }
                }
            } else {
                // 🔥 Contrato é PROTEGIDO (onlyOwner detectado)
                fork_validated = false;
                fork_reason = "Advanced RPC analysis determined privileged paths are access controlled".to_string();
                emit(log_event(
                    "✅ Contrato é PROTEGIDO por onlyOwner. Não é explorável publicamente.".to_string(),
                    "info",
                ));
            }
        }
        Err(error) => {
            fork_reason = format!("Advanced RPC analysis failed before fork replay: {}", error);
            emit(log_event(
                format!("Advanced RPC analysis failed: {}", error),
                "warn",
            ));
            // Fallback: tenta fork direto
            match forensics
                .validate_with_fork(
                    &request.contract_address,
                    &analysis,
                    &prioritized_selectors,
                    "0x0000000000000000000000000000000000000000",
                )
                .await
            {
                Ok(Some(result)) => {
                    fork_validated = result.unauthorized_access || result.balance_drained || result.ownership_changed;
                    state_delta = Some(result.state_delta);
                    if fork_validated {
                        fork_reason = "Fallback direct fork replay confirmed a state-changing path".to_string();
                        emit(log_event(
                            "Fork validation confirmed a reachable unauthorized execution path".to_string(),
                            "warn",
                        ));
                    } else {
                        fork_reason = "Fallback direct fork replay ran without confirming exploitability".to_string();
                    }
                }
                Ok(None) => {
                    fork_reason = "Fallback fork provider unavailable".to_string();
                    emit(log_event("Fork não disponível".to_string(), "info"));
                }
                Err(e) => {
                    fork_reason = format!("Fallback fork validation failed: {}", e);
                    emit(log_event(format!("Fork validation failed: {}", e), "warn"));
                }
            }
        }
    }
    emit(step_event("fork", "Anvil fork execution", "done"));
} else {
    fork_reason = format!("Fork skipped because confidence {provisional_score}/100 is below threshold");
    emit(step_event("fork", "Anvil fork execution", "skipped"));
    emit(log_event(
        format!("Fork skipped because confidence {provisional_score}/100 is below threshold"),
        "info",
    ));
}

    let has_access_control = simulation.all_reverted() || proxy.has_admin_control();
    
    emit(step_event("offensive", "Offensive exploit analysis", "running"));
    
    let mut exploit_paths = Vec::new();
    let mut mev_opportunities = Vec::new();
    let mut exploitation_probability = 0.0;
    let mut risk_adjusted_value = 0.0;
    
    let offensive_config = OffensiveConfig {
        max_paths: 10,
        monte_carlo_samples: 100,
        min_probability: 0.01,
        min_economic_value_eth: 0.001,
        ..Default::default()
    };
    
    let offensive_engine = OffensiveEngine::new(offensive_config, forensics.clone());
    
    match AssertUnwindSafe(offensive_engine.analyze(&request.contract_address, &analysis))
        .catch_unwind()
        .await
    {
        Ok(Ok(offensive_report)) => {
            exploit_paths = offensive_report.exploit_paths;
            mev_opportunities = offensive_report.mev_opportunities;
            exploitation_probability = offensive_report.exploitation_probability;
            risk_adjusted_value = offensive_report.risk_adjusted_value;
            
            if !exploit_paths.is_empty() {
                emit(log_event(
                    format!(
                        "Found {} exploit paths (max probability: {:.2}%, max value: {:.4} ETH)",
                        exploit_paths.len(),
                        exploitation_probability * 100.0,
                        risk_adjusted_value
                    ),
                    "warn",
                ));
                
                for path in &exploit_paths {
                    emit(log_event(
                        format!(
                            "  → Selector {} | P={:.2}% | Value={:.4} ETH | Conditions: {}",
                            path.entry_selector,
                            path.probability * 100.0,
                            path.economic_value_eth,
                            path.required_conditions.len()
                        ),
                        "info",
                    ));
                }
            } else {
                emit(log_event("No viable exploit paths found".to_string(), "info"));
            }
            
            if !mev_opportunities.is_empty() {
                emit(log_event(
                    format!("Found {} MEV extraction opportunities", mev_opportunities.len()),
                    "warn",
                ));
            }
        }
        Ok(Err(error)) => {
            emit(log_event(
                format!("Offensive analysis failed: {}", error),
                "warn",
            ));
        }
        Err(_) => {
            emit(log_event(
                "Offensive analysis panicked; continuing with non-offensive evidence only".to_string(),
                "warn",
            ));
        }
    }
    
    emit(step_event("offensive", "Offensive exploit analysis", "done"));
    
    let base_confidence = calculate_confidence(
        &analysis,
        dangerous_matches.len(),
        simulation,
        fork_validated,
        !exploit_paths.is_empty(),
        has_access_control,
    );
    let resolution = resolve_classification(
        base_confidence,
        fork_validated,
        !exploit_paths.is_empty(),
        exploitation_probability,
        risk_adjusted_value,
        proxy.is_proxy(),
        has_access_control,
        analysis.flags.is_empty(),
        has_only_admin_functions(&dangerous_matches),
        looks_like_standard_token(&selectors),
        looks_like_known_legit_contract(&request.contract_address, &selectors),
    );
    let simulation_only = request.simulation && !fork_validated;
    let value_flow = infer_value_flow(&selectors, proxy.is_proxy());
    let behavioral_risk = infer_behavioral_risk(value_flow, simulation, proxy.is_proxy(), !exploit_paths.is_empty());
    let bytecode_confidence = build_bytecode_confidence_report(&analysis, &dangerous_matches, value_flow, &proxy);
    let final_kind = if matches!(resolution.kind, VulnerabilityKind::GenericContract)
        && matches!(behavioral_risk.kind, BehavioralKind::ExecutorContract)
    {
        VulnerabilityKind::GenericContract
    } else {
        resolution.kind.clone()
    };
    let decision_traces = build_decision_traces(
        &dangerous_matches,
        simulation,
        fork_validated,
        should_run_fork,
        &fork_reason,
        exploitation_probability,
        risk_adjusted_value,
        &resolution,
        &bytecode_confidence,
        value_flow,
        &proxy,
    );

    let report = VulnerabilityReport {
        id: uuid::Uuid::new_v4().to_string(),
        chain: config.chain.as_str().to_string(),
        contract_address: request.contract_address.clone(),
        tx_hash: format!("manual-scan:{}", uuid::Uuid::new_v4()),
        severity: resolution.severity.clone(),
        kind: final_kind.clone(),
        description: build_description(
            &request.contract_address,
            &rpc_source,
            &analysis,
            &dangerous_matches,
            request.simulation,
            simulation.has_confirmed_execution(),
            fork_validated,
            resolution.confidence_score,
            has_access_control,
            &proxy,
            !exploit_paths.is_empty(),
            value_flow,
            &final_kind,
        ),
        function_selector: selectors.first().cloned(),
        flagged_selectors: selectors.clone(),
        state_delta: state_delta.clone(),
        timestamp: Utc::now(),
        fork_validated,
        confidence_score: resolution.confidence_score,
        proxy: proxy.to_report(has_access_control),
        evidence: EvidenceReport {
            fork_validated,
            exploit_path: !exploit_paths.is_empty(),
            simulation_only,
        },
        value_flow: ValueFlowReport {
            can_move_funds: value_flow.can_move_funds,
            role: value_flow.role.as_str().to_string(),
            risk_surface: value_flow.risk_surface.as_str().to_string(),
        },
        behavioral_risk: BehavioralRiskReport {
            kind: behavioral_risk.kind.clone(),
            score: behavioral_risk.score,
            rationale: behavioral_risk.rationale.to_string(),
        },
        bytecode_confidence,
        fork_validation: ForkValidationReport {
            attempted: should_run_fork,
            strategy: match request.fork {
                ForkMode::Force => "FORCED_FORK",
                ForkMode::Auto => "AUTO_FORK",
                ForkMode::Off => "FORK_DISABLED",
            }.to_string(),
            provider: if should_run_fork {
                if request.fork == ForkMode::Force {
                    "TENDERLY_OR_CONFIGURED_FORK".to_string()
                } else {
                    "ANVIL_OR_CONFIGURED_FORK".to_string()
                }
            } else {
                "NOT_USED".to_string()
            },
            confirmed: fork_validated,
            selectors_tested: prioritized_selectors.len(),
            reason: fork_reason,
            state_change_summary: state_delta.clone(),
        },
        decision_traces,
        exploit_paths,
        mev_opportunities,
        exploitation_probability,
        risk_adjusted_value,
        recommendation: build_recommendation(
            resolution.confidence_score,
            fork_validated,
            exploitation_probability,
            risk_adjusted_value,
            &final_kind,
            &proxy,
            &behavioral_risk,
        ),
    };

    reporter.submit(&report).await?;
    emit(log_event(
        format!(
            "Scan complete. Severity={} Kind={} Confidence={}/100 | Offensive: P={:.2}% EV={:.4} ETH",
            report.severity, report.kind, report.confidence_score,
            exploitation_probability * 100.0,
            risk_adjusted_value
        ),
        "success",
    ));

    Ok(report)
}

pub async fn collect_status(config: &ScannerConfig) -> Result<ScannerStatusSnapshot> {
    let endpoints = collect_endpoints(config).await?;
    let anvil_connected = is_anvil_connected(config).await;

    Ok(ScannerStatusSnapshot {
        chain: config.chain.as_str().to_string(),
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

    join_all(
        config
            .ws_endpoints
            .iter()
            .map(|endpoint| probe_ws_endpoint(&lb, endpoint)),
    )
    .await;

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
    let request = WsConnectionRequest::new();
    match timeout(Duration::from_secs(8), connect_async(endpoint)).await {
        Ok(Ok((mut stream, _))) => {
            lb.record_success(endpoint, request.elapsed_ms());
            let _ = stream.close(None).await;
        }
        Ok(Err(_)) | Err(_) => lb.record_failure(endpoint),
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

fn prioritized_selectors_for_replay(
    analysis: &BytecodeAnalysis,
    selectors: &[String],
    dangerous_matches: &[String],
    proxy: &ProxyMetadata,
    mode: ScanMode,
) -> Vec<ReplayCandidate> {
    let dangerous_labels = dangerous_matches
        .iter()
        .map(|entry| entry.to_ascii_lowercase())
        .collect::<Vec<_>>();

    let mut ranked = selectors
        .iter()
        .map(|selector| ReplayCandidate {
            selector: selector.clone(),
            score: score_selector_for_replay(
                analysis,
                selector,
                &dangerous_labels,
                proxy,
            ),
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.selector.cmp(&right.selector))
    });

    let limit = match mode {
        ScanMode::Fast => 3,
        ScanMode::Deep => 8,
    };
    ranked.truncate(limit.min(ranked.len()));
    ranked
}

fn score_selector_for_replay(
    analysis: &BytecodeAnalysis,
    selector_hex: &str,
    dangerous_labels: &[String],
    proxy: &ProxyMetadata,
) -> u32 {
    let Some(selector_bytes) = parse_selector_hex(selector_hex) else {
        return 0;
    };
    let selector_fragment = selector_hex
        .strip_prefix("0x")
        .unwrap_or(selector_hex)
        .to_ascii_lowercase();

    let mut score = 10;
    if let Some(function) = analysis.get_function_by_selector(&selector_bytes) {
        if function.is_dangerous {
            score += 35;
        }
        if !function.has_access_control {
            score += 12;
        }

        let block_score = analysis
            .basic_blocks
            .iter()
            .find(|block| function.offset >= block.start && function.offset <= block.end)
            .map(score_basic_block_for_replay)
            .unwrap_or(0);
        score += block_score;
    }

    if dangerous_labels
        .iter()
        .any(|entry| entry.contains(&selector_fragment))
    {
        score += 30;
    }
    if analysis.has_delegatecall {
        score += 10;
    }
    if analysis.has_reentrancy_risk {
        score += 8;
    }
    if analysis.has_upgrade_surface && proxy.is_proxy() {
        score += 10;
    }
    if analysis.has_admin_surface {
        score += 6;
    }

    score
}

fn score_basic_block_for_replay(block: &crate::bytecode::BasicBlockInfo) -> u32 {
    let mut score = (block.successors.len() as u32) * 4;
    if block.instructions.iter().any(|inst| inst.mnemonic == "SSTORE") {
        score += 10;
    }
    if block.instructions.iter().any(|inst| inst.mnemonic == "CALL") {
        score += 8;
    }
    if block
        .instructions
        .iter()
        .any(|inst| matches!(inst.mnemonic, "DELEGATECALL" | "CALLCODE"))
    {
        score += 12;
    }
    if block.instructions.iter().any(|inst| inst.mnemonic == "SELFDESTRUCT") {
        score += 20;
    }
    if block.instructions.iter().any(|inst| inst.mnemonic == "JUMPI") {
        score += 6;
    }
    score
}

fn parse_selector_hex(selector_hex: &str) -> Option<[u8; 4]> {
    let raw = selector_hex.strip_prefix("0x").unwrap_or(selector_hex);
    if raw.len() != 8 {
        return None;
    }
    let decoded = hex::decode(raw).ok()?;
    let bytes: [u8; 4] = decoded.try_into().ok()?;
    Some(bytes)
}

fn opcode_capability_summary(analysis: &BytecodeAnalysis) -> String {
    let mut capabilities = Vec::new();

    if analysis.has_selfdestruct {
        capabilities.push("selfdestruct");
    }
    if analysis.has_delegatecall {
        capabilities.push("delegatecall");
    }
    if analysis.has_callcode {
        capabilities.push("callcode");
    }
    if analysis.has_create2 {
        capabilities.push("create2");
    }

    let byte_len = analysis.bytecode.len();
    let severity = analysis
        .top_severity()
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| "NONE".to_string());

    if capabilities.is_empty() {
        format!("Opcode capability summary: topSeverity={severity} bytecodeBytes={byte_len}.")
    } else {
        format!(
            "Opcode capability summary: topSeverity={} capabilities={} bytecodeBytes={}.",
            severity,
            capabilities.join(","),
            byte_len
        )
    }
}

fn classify_dispatcher_confidence(analysis: &BytecodeAnalysis) -> DispatcherConfidence {
    if analysis.function_selectors.len() >= 4
        && analysis.basic_blocks.len() >= 8
        && analysis.dispatcher_targets >= 2
    {
        DispatcherConfidence::High
    } else if !analysis.function_selectors.is_empty()
        && analysis.basic_blocks.len() >= 3
        && analysis.dispatcher_targets >= 1
    {
        DispatcherConfidence::Medium
    } else {
        DispatcherConfidence::Low
    }
}

fn detect_fallback(analysis: &BytecodeAnalysis) -> bool {
    analysis.has_fallback
}

fn detect_receive(analysis: &BytecodeAnalysis) -> bool {
    analysis.has_receive
}

fn capability_labels(
    analysis: &BytecodeAnalysis,
    value_flow: ValueFlowHeuristics,
    proxy: &ProxyMetadata,
) -> Vec<String> {
    let mut capabilities = Vec::new();
    if value_flow.can_move_funds {
        capabilities.push("fund_movement".to_string());
    }
    if proxy.is_proxy() || analysis.has_upgrade_surface {
        capabilities.push("upgrade".to_string());
    }
    if proxy.has_admin_control() || analysis.has_admin_surface {
        capabilities.push("auth".to_string());
    }
    if analysis.has_delegatecall || analysis.has_callcode || analysis.has_reentrancy_risk {
        capabilities.push("external_call".to_string());
    }
    capabilities
}

fn build_bytecode_confidence_report(
    analysis: &BytecodeAnalysis,
    dangerous_matches: &[String],
    value_flow: ValueFlowHeuristics,
    proxy: &ProxyMetadata,
) -> BytecodeConfidenceReport {
    let dispatcher_confidence = classify_dispatcher_confidence(analysis);
    let fallback_detected = detect_fallback(analysis);
    let receive_detected = detect_receive(analysis);
    let access_control_score = if analysis.functions.is_empty() {
        0
    } else {
        ((analysis.functions.iter().filter(|f| f.has_access_control).count() * 100)
            / analysis.functions.len()) as u32
    };

    let mut score = analysis.risk_score.min(100);
    score = score.saturating_add((analysis.basic_blocks.len().min(20) as u32) / 2);
    score = score.saturating_add((dangerous_matches.len().min(5) as u32) * 4);
    if matches!(dispatcher_confidence, DispatcherConfidence::High) {
        score = score.saturating_add(10);
    }
    if proxy.is_proxy() {
        score = score.saturating_add(5);
    }
    score = score.min(100);

    let signals = vec![
        BytecodeSignalReport {
            label: "selectors".to_string(),
            value: analysis.function_selectors.len().to_string(),
            impact: "dispatcher coverage".to_string(),
        },
        BytecodeSignalReport {
            label: "basic_blocks".to_string(),
            value: analysis.basic_blocks.len().to_string(),
            impact: "control-flow visibility".to_string(),
        },
        BytecodeSignalReport {
            label: "dispatcher_targets".to_string(),
            value: analysis.dispatcher_targets.to_string(),
            impact: "jump-table resolution".to_string(),
        },
        BytecodeSignalReport {
            label: "dangerous_matches".to_string(),
            value: dangerous_matches.len().to_string(),
            impact: "high-risk selector surface".to_string(),
        },
        BytecodeSignalReport {
            label: "access_control_score".to_string(),
            value: access_control_score.to_string(),
            impact: "authorization coverage".to_string(),
        },
    ];

    BytecodeConfidenceReport {
        score,
        dispatcher_confidence: dispatcher_confidence.as_str().to_string(),
        function_count: analysis.function_selectors.len(),
        basic_block_count: analysis.basic_blocks.len(),
        fallback_detected,
        receive_detected,
        access_control_score,
        summary: format!(
            "Dispatcher confidence={} selectors={} basicBlocks={} dangerousMatches={}.",
            dispatcher_confidence.as_str(),
            analysis.function_selectors.len(),
            analysis.basic_blocks.len(),
            dangerous_matches.len()
        ),
        capabilities: capability_labels(analysis, value_flow, proxy),
        signals,
    }
}

fn build_decision_traces(
    dangerous_matches: &[String],
    simulation: SimulationOutcome,
    fork_validated: bool,
    should_run_fork: bool,
    fork_reason: &str,
    exploitation_probability: f64,
    risk_adjusted_value: f64,
    resolution: &Resolution,
    bytecode_confidence: &BytecodeConfidenceReport,
    value_flow: ValueFlowHeuristics,
    proxy: &ProxyMetadata,
) -> Vec<DecisionTraceReport> {
    let mut traces = vec![
        DecisionTraceReport {
            title: "bytecode_model".to_string(),
            detail: bytecode_confidence.summary.clone(),
            weight: bytecode_confidence.score as i32,
        },
        DecisionTraceReport {
            title: "selector_surface".to_string(),
            detail: if dangerous_matches.is_empty() {
                "No dangerous selector signatures matched.".to_string()
            } else {
                format!("Dangerous selectors: {}", dangerous_matches.join("; "))
            },
            weight: (dangerous_matches.len() as i32) * 8,
        },
        DecisionTraceReport {
            title: "simulation".to_string(),
            detail: format!(
                "Simulation attempts={} successes={} reverts={}",
                simulation.attempts, simulation.successes, simulation.reverts
            ),
            weight: if simulation.has_confirmed_execution() { 10 } else { -5 },
        },
        DecisionTraceReport {
            title: "fork_validation".to_string(),
            detail: if should_run_fork {
                fork_reason.to_string()
            } else {
                "Fork pipeline skipped by confidence gate.".to_string()
            },
            weight: if fork_validated { 20 } else { 0 },
        },
        DecisionTraceReport {
            title: "value_flow".to_string(),
            detail: format!(
                "role={} canMoveFunds={} riskSurface={} proxy={}",
                value_flow.role.as_str(),
                value_flow.can_move_funds,
                value_flow.risk_surface.as_str(),
                proxy.is_proxy()
            ),
            weight: if value_flow.can_move_funds { 12 } else { 0 },
        },
        DecisionTraceReport {
            title: "resolution".to_string(),
            detail: format!(
                "severity={} kind={} confidence={} probability={:.2}% rav={:.4}ETH",
                resolution.severity,
                resolution.kind,
                resolution.confidence_score,
                exploitation_probability * 100.0,
                risk_adjusted_value
            ),
            weight: resolution.confidence_score as i32,
        },
    ];

    traces.sort_by(|a, b| b.weight.cmp(&a.weight));
    traces
}

fn calculate_confidence(
    analysis: &BytecodeAnalysis,
    dangerous_match_count: usize,
    simulation: SimulationOutcome,
    fork_validated: bool,
    has_exploit_path: bool,
    has_access_control: bool,
) -> u32 {
    let mut score = analysis.risk_score + dangerous_match_count as u32 * 10;

    if simulation.all_reverted() {
        score = score.saturating_sub(15);
    }

    if has_exploit_path && has_access_control {
        score = score.saturating_sub(20);
    }

    if fork_validated {
        score += 20;
    }

    if !has_exploit_path {
        score = score.min(60);
    }

    score.min(100)
}

fn resolve_classification(
    base_confidence: u32,
    fork_validated: bool,
    has_exploit_path: bool,
    exploitation_probability: f64,
    risk_adjusted_value: f64,
    is_proxy: bool,
    has_access_control: bool,
    has_no_dangerous_opcode: bool,
    has_only_admin_functions: bool,
    looks_like_standard_token: bool,
    looks_like_known_legit_contract: bool,
) -> Resolution {
    const CONFIRMED_MIN_PROBABILITY: f64 = 0.20;
    const CONFIRMED_MIN_RISK_ADJUSTED_VALUE_ETH: f64 = 0.01;
    const POSSIBLE_MIN_PROBABILITY: f64 = 0.10;
    const HIGH_RISK_MIN_PROBABILITY: f64 = 0.45;

    let meets_confirmed_thresholds = has_exploit_path
        && exploitation_probability >= CONFIRMED_MIN_PROBABILITY
        && risk_adjusted_value >= CONFIRMED_MIN_RISK_ADJUSTED_VALUE_ETH;

    if fork_validated && meets_confirmed_thresholds {
        return Resolution {
            severity: Severity::Critical,
            kind: VulnerabilityKind::ExploitConfirmed,
            confidence_score: base_confidence.max(95),
        };
    }

    if looks_like_known_legit_contract && !has_exploit_path {
        return Resolution {
            severity: Severity::Info,
            kind: VulnerabilityKind::GenericContract,
            confidence_score: base_confidence.clamp(20, 35),
        };
    }

    if fork_validated && has_exploit_path {
        return Resolution {
            severity: Severity::High,
            kind: VulnerabilityKind::ExploitPossible,
            confidence_score: base_confidence.max(82),
        };
    }

    if has_exploit_path
        && (exploitation_probability >= POSSIBLE_MIN_PROBABILITY || risk_adjusted_value > 0.0)
    {
        return Resolution {
            severity: Severity::High,
            kind: VulnerabilityKind::ExploitPossible,
            confidence_score: base_confidence.max(75),
        };
    }

    if exploitation_probability >= HIGH_RISK_MIN_PROBABILITY {
        return Resolution {
            severity: Severity::High,
            kind: VulnerabilityKind::HighRiskPattern,
            confidence_score: base_confidence.max(70),
        };
    }

    if is_proxy && has_access_control {
        return Resolution {
            severity: Severity::Info,
            kind: VulnerabilityKind::UpgradeableProxy,
            confidence_score: base_confidence.min(35),
        };
    }

    if !has_exploit_path
        && has_no_dangerous_opcode
        && has_only_admin_functions
        && (has_access_control || looks_like_standard_token)
    {
        return Resolution {
            severity: Severity::Info,
            kind: VulnerabilityKind::AdminControlledContract,
            confidence_score: base_confidence.max(80),
        };
    }

    if !has_exploit_path && has_no_dangerous_opcode && !is_proxy && !has_only_admin_functions {
        return Resolution {
            severity: Severity::Info,
            kind: VulnerabilityKind::GenericContract,
            confidence_score: base_confidence.clamp(30, 50),
        };
    }

    Resolution {
        severity: Severity::Medium,
        kind: VulnerabilityKind::SuspiciousBytecode,
        confidence_score: base_confidence.clamp(40, 69),
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
    has_access_control: bool,
    proxy: &ProxyMetadata,
    has_exploit_path: bool,
    value_flow: ValueFlowHeuristics,
    resolved_kind: &VulnerabilityKind,
) -> String {
    let mut segments = vec![format!(
        "Rust scanner executed against {} using {}.",
        contract_address, rpc_source
    )];

    if proxy.is_proxy() {
        let implementation = proxy.implementation.as_deref().unwrap_or("unknown");
        if let Some(admin) = proxy.admin.as_deref() {
            segments.push(format!(
                "{} proxy detected with implementation {} and admin {}.",
                proxy.proxy_type().unwrap_or("Upgradeable"),
                implementation,
                admin
            ));
        } else {
            segments.push(format!(
                "{} proxy detected with implementation {}.",
                proxy.proxy_type().unwrap_or("Upgradeable"),
                implementation
            ));
        }
    }

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
    segments.push(opcode_capability_summary(analysis));

    if dangerous_matches.is_empty() {
        segments.push("No dangerous selector match was found.".to_string());
    } else {
        segments.push(format!("Dangerous selectors: {}.", dangerous_matches.join("; ")));
    }

    segments.push(format!(
        "Value-flow assessment: role={} canMoveFunds={} riskSurface={}.",
        value_flow.role.as_str(),
        value_flow.can_move_funds,
        value_flow.risk_surface.as_str()
    ));

    segments.push(if simulation_enabled {
        if simulation_confirmed {
            "eth_call simulation produced executable return data.".to_string()
        } else if has_access_control {
            "eth_call simulation consistently reverted, suggesting the flagged entrypoints are access controlled.".to_string()
        } else {
            "eth_call simulation did not confirm an executable path.".to_string()
        }
    } else {
        "eth_call simulation was disabled.".to_string()
    });

    segments.push(if matches!(resolved_kind, VulnerabilityKind::ExploitConfirmed) {
        "Fork validation confirmed a reachable unauthorized execution path.".to_string()
    } else if fork_validated && has_exploit_path {
        "Fork validation reached a candidate state-changing path, but confirmation thresholds for exploitability were not met.".to_string()
    } else if fork_validated {
        "Fork validation executed successfully, but did not satisfy the thresholds required to confirm exploitability.".to_string()
    } else if has_exploit_path {
        "Offensive analysis identified candidate exploit paths, but fork validation did not confirm a state-changing exploit.".to_string()
    } else {
        "Fork validation did not confirm a state-changing exploit.".to_string()
    });

    segments.push(format!("Confidence score: {confidence_score}/100."));
    segments.join(" ")
}

fn build_recommendation(
    confidence_score: u32,
    fork_validated: bool,
    exploitation_probability: f64,
    risk_adjusted_value: f64,
    kind: &VulnerabilityKind,
    proxy: &ProxyMetadata,
    behavioral_risk: &BehavioralInference,
) -> String {
    if matches!(kind, VulnerabilityKind::ExploitConfirmed) {
        return "Fork validation confirmed an exploitable path. Treat this as a critical issue and remediate before further deployment or privileged operations.".to_string();
    }

    if matches!(kind, VulnerabilityKind::ExploitPossible) {
        return "Offensive analysis found candidate exploit paths without fork confirmation. Prioritize manual validation and reproduce on a controlled fork immediately.".to_string();
    }

    if matches!(kind, VulnerabilityKind::HighRiskPattern) {
        return "Heuristic exploitability is high despite missing deterministic confirmation. Review authorization boundaries and replay the scenario on a fork.".to_string();
    }

    if matches!(kind, VulnerabilityKind::UpgradeableProxy) {
        return format!(
            "This contract behaves as an upgradeable proxy ({}). Privileged upgrade functions are present but protected by access control. No exploitable execution path was identified. Implementation: {}. Admin: {}. Risk is primarily associated with admin key compromise.",
            proxy.proxy_type().unwrap_or("EIP-1967"),
            proxy.implementation.as_deref().unwrap_or("unknown"),
            proxy.admin.as_deref().unwrap_or("unknown"),
        );
    }

    if matches!(kind, VulnerabilityKind::AdminControlledContract) {
        return "This contract exposes standard privileged administration flows, but no exploit path or abnormal execution pattern was detected. Risk is limited to intended privileged role misuse rather than an exploitable vulnerability.".to_string();
    }

    if matches!(kind, VulnerabilityKind::GenericContract) {
        if matches!(behavioral_risk.kind, BehavioralKind::ExecutorContract) {
            return "This contract behaves as an execution router capable of moving external funds. No direct exploit path was identified, but its design suggests use as an execution layer such as bots, aggregators, or attack flows. Risk depends on how it is invoked and what permissions are granted.".to_string();
        }
        return "No exploit path or dangerous execution pattern was identified. Observed behavior appears generic based on available signals, with limited semantic visibility into contract intent.".to_string();
    }

    if fork_validated || confidence_score >= 85 || exploitation_probability >= 0.75 {
        return "Immediate remediation recommended: pause privileged flows, review access control, and validate all flagged selectors on a local fork before redeployment.".to_string();
    }

    if confidence_score >= 60 || exploitation_probability >= 0.35 || risk_adjusted_value >= 0.1 {
        return "Prioritize manual review of the flagged execution paths, add explicit authorization checks, and re-run the scanner in deep mode with fork validation enabled.".to_string();
    }

    "Monitor the contract, review the flagged selectors for intended behavior, and re-scan after the next code or configuration change.".to_string()
}

async fn detect_proxy_metadata(rpc: &RpcClient, contract_address: &str) -> Result<ProxyMetadata> {
    let implementation = read_eip1967_address(rpc, contract_address, EIP1967_IMPLEMENTATION_SLOT).await?;
    let admin = read_eip1967_address(rpc, contract_address, EIP1967_ADMIN_SLOT).await?;
    let beacon = read_eip1967_address(rpc, contract_address, EIP1967_BEACON_SLOT).await?;

    Ok(ProxyMetadata {
        implementation,
        admin,
        beacon,
    })
}

async fn fetch_chain_id(rpc: &RpcClient) -> Result<u64> {
    let (chain_id_hex, _) = rpc.call::<String>("eth_chainId", json!([])).await?;
    let stripped = chain_id_hex.trim_start_matches("0x");
    u64::from_str_radix(stripped, 16)
        .with_context(|| format!("failed to parse eth_chainId result: {chain_id_hex}"))
}

async fn read_eip1967_address(
    rpc: &RpcClient,
    contract_address: &str,
    slot: &str,
) -> Result<Option<String>> {
    let (raw, _) = rpc.get_storage_at(contract_address, slot).await?;
    Ok(storage_word_to_address(&raw))
}

fn storage_word_to_address(value: &str) -> Option<String> {
    let stripped = value.trim().trim_start_matches("0x");
    if stripped.len() != 64 {
        return None;
    }

    let address = &stripped[24..];
    if address.chars().all(|ch| ch == '0') {
        return None;
    }

    Some(format!("0x{address}"))
}

impl ProxyMetadata {
    fn to_report(&self, is_access_controlled: bool) -> Option<ProxyReport> {
        if !self.is_proxy() && !self.has_admin_control() {
            return None;
        }

        Some(ProxyReport {
            proxy_type: self.proxy_type().map(str::to_string),
            implementation: self.implementation.clone(),
            admin: self.admin.clone(),
            beacon: self.beacon.clone(),
            is_access_controlled,
        })
    }
}

fn opcode_name(opcode: u8) -> &'static str {
    BytecodeScanner::opcode_to_mnemonic(opcode)
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

fn has_only_admin_functions(dangerous_matches: &[String]) -> bool {
    !dangerous_matches.is_empty()
        && dangerous_matches.iter().all(|entry| {
            entry.contains("transferOwnership(address)")
                || entry.contains("renounceOwnership()")
                || entry.contains("pause()")
                || entry.contains("unpause()")
                || entry.contains("mint(")
        })
}

fn looks_like_standard_token(selectors: &[String]) -> bool {
    STANDARD_TOKEN_SELECTORS
        .iter()
        .all(|selector| selectors.iter().any(|candidate| candidate == selector))
}

fn looks_like_known_legit_contract(contract_address: &str, selectors: &[String]) -> bool {
    const KNOWN_ADDRESSES: [&str; 3] = [
        "0xdac17f958d2ee523a2206206994597c13d831ec7",
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    ];
    const ERC20_SELECTORS: [&str; 6] = [
        "0x06fdde03",
        "0x095ea7b3",
        "0x18160ddd",
        "0x70a08231",
        "0xa9059cbb",
        "0xdd62ed3e",
    ];

    let address = contract_address.to_ascii_lowercase();
    if KNOWN_ADDRESSES.contains(&address.as_str()) {
        return true;
    }

    let erc20_count = ERC20_SELECTORS
        .iter()
        .filter(|selector| selectors.iter().any(|candidate| candidate == **selector))
        .count();

    erc20_count >= 4
}

fn infer_value_flow(selectors: &[String], is_proxy: bool) -> ValueFlowHeuristics {
    let has_erc20_flow = ERC20_FLOW_SELECTORS
        .iter()
        .any(|selector| selectors.iter().any(|candidate| candidate == selector));
    let has_dex_flow = DEX_FLOW_SELECTORS
        .iter()
        .any(|selector| selectors.iter().any(|candidate| candidate == selector));
    let looks_token = looks_like_standard_token(selectors);
    let has_vault_shape = selectors.iter().any(|selector| {
        matches!(
            selector.as_str(),
            "0x2e1a7d4d" | "0xba087652" | "0x853828b6" | "0xd0e30db0"
        )
    });

    let role = if is_proxy {
        ContractRole::Proxy
    } else if has_dex_flow {
        ContractRole::Router
    } else if looks_token {
        ContractRole::Token
    } else if has_vault_shape {
        ContractRole::Vault
    } else if has_erc20_flow {
        ContractRole::Executor
    } else {
        ContractRole::Generic
    };

    let can_move_funds = has_erc20_flow || has_dex_flow || matches!(role, ContractRole::Vault | ContractRole::Executor | ContractRole::Router);
    let risk_surface = if can_move_funds {
        RiskSurface::ExternalFunds
    } else if has_vault_shape {
        RiskSurface::ContractBalance
    } else {
        RiskSurface::Limited
    };

    ValueFlowHeuristics {
        can_move_funds,
        role,
        risk_surface,
    }
}

fn infer_behavioral_risk(
    value_flow: ValueFlowHeuristics,
    simulation: SimulationOutcome,
    is_proxy: bool,
    has_exploit_path: bool,
) -> BehavioralInference {
    let revert_rate = if simulation.attempts == 0 {
        0.0
    } else {
        simulation.reverts as f64 / simulation.attempts as f64
    };

    if !has_exploit_path
        && !is_proxy
        && value_flow.can_move_funds
        && matches!(value_flow.role, ContractRole::Executor)
        && revert_rate >= 0.8
    {
        return BehavioralInference {
            kind: BehavioralKind::ExecutorContract,
            score: 0.6,
            rationale: "Execution-oriented contract with external fund movement capability and high gated-call revert rate",
        };
    }

    if has_exploit_path && value_flow.can_move_funds && revert_rate >= 0.8 {
        return BehavioralInference {
            kind: BehavioralKind::MaliciousInfrastructure,
            score: 0.85,
            rationale: "Execution infrastructure with external fund movement capability and exploit-aligned behavior",
        };
    }

    BehavioralInference {
        kind: BehavioralKind::Benign,
        score: 0.1,
        rationale: "No strong behavioral abuse pattern identified",
    }
}
