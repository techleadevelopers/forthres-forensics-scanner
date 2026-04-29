// ============================================================
// forensics.rs - VERSÃO AUMENTADA
// ============================================================

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn, error};

use crate::bytecode::BytecodeAnalysis;
use crate::offensive::feedback_loop::{FeedbackLoopEngine, ExploitAttempt, HexoraGuidedFuzzer};
use crate::offensive::economic_impact::RealTimeEconomicEngine;
use crate::offensive::mev_integration::{MevEngine, MevConfig, MevOpportunity};

/// Resultado forense avançado com análise ofensiva
#[derive(Debug, Clone)]
pub struct ForensicResult {
    pub state_delta: String,
    pub unauthorized_access: bool,
    pub balance_drained: bool,
    pub ownership_changed: bool,
    /// Exploits confirmados via feedback loop
    pub confirmed_exploits: Vec<ExploitAttempt>,
    /// MEV opportunities identificadas
    pub mev_opportunities: Vec<MevOpportunity>,
    /// Probabilidade de exploração
    pub exploitation_probability: f64,
    /// Valor econômico ajustado por risco
    pub risk_adjusted_value_eth: f64,
    /// Tempo total de análise
    pub analysis_duration_ms: u64,
}

/// Configuração avançada do Forensics
#[derive(Debug, Clone)]
pub struct ForensicsConfig {
    pub max_iterations: u32,
    pub max_paths: usize,
    pub enable_mev: bool,
    pub enable_fuzzing: bool,
    pub min_economic_value_eth: f64,
    pub rpc_retries: u32,
    pub rpc_timeout_ms: u64,
}

impl Default for ForensicsConfig {
    fn default() -> Self {
        Self {
            max_iterations: 15,
            max_paths: 50,
            enable_mev: true,
            enable_fuzzing: true,
            min_economic_value_eth: 0.001,
            rpc_retries: 3,
            rpc_timeout_ms: 10000,
        }
    }
}

/// JSON-RPC request structure
#[derive(Debug, Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: Value,
}

/// JSON-RPC response structure
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: Option<Value>,
    error: Option<Value>,
}

/// Deep forensic validation engine usando local Anvil fork
/// COM ANÁLISE OFENSIVA COMPLETA
#[derive(Clone)]
pub struct ForensicsEngine {
    anvil_url: String,
    http_client: Client,
    config: ForensicsConfig,
    rpc_semaphore: Arc<Semaphore>,
}

impl ForensicsEngine {
    pub fn new(anvil_url: String, config: ForensicsConfig) -> Self {
        Self {
            anvil_url,
            http_client: Client::builder()
                .timeout(Duration::from_millis(config.rpc_timeout_ms))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
            rpc_semaphore: Arc::new(Semaphore::new(10)),
        }
    }

    /// Send a JSON-RPC request with retry and backoff
    async fn rpc_call_with_retry(&self, method: &str, params: Value) -> Result<Value> {
        let mut last_error = None;
        
        for attempt in 0..self.config.rpc_retries {
            if attempt > 0 {
                let backoff = Duration::from_millis(100 * 2u64.pow(attempt - 1));
                tokio::time::sleep(backoff).await;
            }
            
            match self.rpc_call(method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    warn!("RPC call attempt {} failed: {:?}", attempt + 1, last_error);
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("RPC call failed after {} attempts", self.config.rpc_retries)))
    }

    /// Send a JSON-RPC request to the local Anvil node
    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value> {
        let _permit = self.rpc_semaphore.acquire().await.unwrap();
        
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };

        let resp = self
            .http_client
            .post(&self.anvil_url)
            .json(&req)
            .send()
            .await?
            .json::<JsonRpcResponse>()
            .await?;

        if let Some(err) = resp.error {
            anyhow::bail!("RPC error: {}", err);
        }

        Ok(resp.result.unwrap_or(Value::Null))
    }

    /// Create a snapshot of the current Anvil state (for rollback)
    pub async fn snapshot(&self) -> Result<String> {
        let snap = self.rpc_call_with_retry("evm_snapshot", json!([])).await?;
        Ok(snap.as_str().unwrap_or("0x0").to_string())
    }

    /// Revert to a previously captured snapshot
    pub async fn revert(&self, snapshot_id: &str) -> Result<()> {
        self.rpc_call_with_retry("evm_revert", json!([snapshot_id])).await?;
        Ok(())
    }

    /// Impersonate an account (no private key needed) — Anvil extension
    pub async fn impersonate(&self, address: &str) -> Result<()> {
        // Verifica se é contrato antes de impersonar
        let code = self.rpc_call_with_retry("eth_getCode", json!([address, "latest"])).await?;
        let is_contract = code.as_str().unwrap_or("0x").len() > 10;
        
        if is_contract {
            warn!("Impersonating contract address {} may have unexpected behavior", address);
        }
        
        self.rpc_call_with_retry("anvil_impersonateAccount", json!([address])).await?;
        debug!("Impersonating account: {}", address);
        Ok(())
    }

    /// Set the ETH balance of an account — Anvil extension
    pub async fn set_balance(&self, address: &str, balance_hex: &str) -> Result<()> {
        self.rpc_call_with_retry("anvil_setBalance", json!([address, balance_hex])).await?;
        debug!("Set balance {} for {}", balance_hex, address);
        Ok(())
    }

    /// Get the ETH balance of an address
    pub async fn get_balance(&self, address: &str) -> Result<u128> {
        let result = self.rpc_call_with_retry("eth_getBalance", json!([address, "latest"])).await?;
        let hex = result.as_str().unwrap_or("0x0");
        let stripped = hex.trim_start_matches("0x");
        Ok(u128::from_str_radix(stripped, 16).unwrap_or(0))
    }

    /// Get a storage slot value
    pub async fn get_storage(&self, address: &str, slot: &str) -> Result<String> {
        let result = self
            .rpc_call_with_retry("eth_getStorageAt", json!([address, slot, "latest"]))
            .await?;
        Ok(result.as_str().unwrap_or("0x0").to_string())
    }

    /// Simulate a call against the fork
    pub async fn eth_call(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
    ) -> Result<String> {
        let params = json!([{
            "from": from,
            "to": to,
            "data": data,
            "value": value
        }, "latest"]);

        let result = self.rpc_call_with_retry("eth_call", params).await?;
        Ok(result.as_str().unwrap_or("0x").to_string())
    }

    /// Simulate with gas limit
    pub async fn eth_call_with_gas(
        &self,
        from: &str,
        to: &str,
        data: &str,
        value: &str,
        gas: u64,
    ) -> Result<String> {
        let params = json!([{
            "from": from,
            "to": to,
            "data": data,
            "value": value,
            "gas": format!("0x{:x}", gas)
        }, "latest"]);

        let result = self.rpc_call_with_retry("eth_call", params).await?;
        Ok(result.as_str().unwrap_or("0x").to_string())
    }

    /// Get multiple storage slots at once
    pub async fn get_multiple_storage(&self, address: &str, slots: &[u64]) -> Result<Vec<(u64, String)>> {
        let mut results = Vec::new();
        for slot in slots {
            let slot_hex = format!("0x{:x}", slot);
            let value = self.get_storage(address, &slot_hex).await?;
            results.push((*slot, value));
        }
        Ok(results)
    }

    /// Capture complete state for comparison
    pub async fn capture_state(&self, address: &str, critical_slots: &[u64]) -> Result<StateSnapshot> {
        let balance = self.get_balance(address).await?;
        let storage = self.get_multiple_storage(address, critical_slots).await?;
        
        Ok(StateSnapshot {
            balance,
            storage: storage.into_iter().collect(),
            timestamp: Instant::now(),
        })
    }

    /// Compare two states and return delta
    pub fn compare_states(&self, before: &StateSnapshot, after: &StateSnapshot) -> StateDelta {
        let mut changes = Vec::new();
        
        if before.balance != after.balance {
            let delta = if after.balance > before.balance {
                after.balance - before.balance
            } else {
                before.balance - after.balance
            };
            changes.push(StateChange::BalanceChanged {
                from: before.balance,
                to: after.balance,
                delta,
            });
        }
        
        for (slot, before_val) in &before.storage {
            if let Some(after_val) = after.storage.get(slot) {
                if before_val != after_val {
                    changes.push(StateChange::StorageChanged {
                        slot: *slot,
                        from: before_val.clone(),
                        to: after_val.clone(),
                    });
                }
            }
        }
        
        StateDelta { changes }
    }

    /// Core forensic validation flow WITH OFFENSIVE ANALYSIS
    pub async fn validate_with_fork(
        &self,
        contract_address: &str,
        analysis: &BytecodeAnalysis,
        _original_caller: &str,
    ) -> Result<Option<ForensicResult>> {
        let start = Instant::now();
        
        if !self.is_anvil_available().await {
            warn!("Anvil not available — skipping deep forensic validation");
            return Ok(None);
        }

        info!("Starting forensic validation for contract: {}", contract_address);

        let attacker = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF";
        let snap = self.snapshot().await.unwrap_or_else(|_| "0x0".to_string());

        // Calcula balance necessário
        let required_balance = self.calculate_required_balance(analysis).await;
        let balance_hex = format!("0x{:x}", required_balance);
        let _ = self.set_balance(attacker, &balance_hex).await;
        let _ = self.impersonate(attacker).await;

        // Captura estado inicial
        let critical_slots = [0u64, 1, 2, 3, 4, 5, 10, 11, 12, 100];
        let state_before = self.capture_state(contract_address, &critical_slots).await?;

        let mut unauthorized_access = false;
        let mut balance_drained = false;
        let mut ownership_changed = false;
        let mut delta_notes = Vec::new();
        
        // ============================================================
        // ANÁLISE OFENSIVA COMPLETA
        // ============================================================
        
        let mut confirmed_exploits = Vec::new();
        let mut mev_opportunities = Vec::new();
        let mut exploitation_probability = 0.0;
        
        if self.config.enable_fuzzing {
            info!("🎯 Running offensive fuzzing analysis...");
            
            // Importa os módulos ofensivos
            use crate::offensive::feedback_loop::run_offensive_analysis;
            use crate::offensive::path_finder::find_exploit_paths;
            
            // Encontra paths de exploit
            let paths = find_exploit_paths(analysis, self.config.max_paths);
            
            if !paths.is_empty() {
                // Executa análise ofensiva com feedback loop
                match run_offensive_analysis(self.clone(), paths, contract_address).await {
                    Ok((exploits, mev)) => {
                        confirmed_exploits = exploits;
                        mev_opportunities = mev;
                        
                        if !confirmed_exploits.is_empty() {
                            unauthorized_access = true;
                            exploitation_probability = confirmed_exploits
                                .iter()
                                .map(|e| e.confidence as f64)
                                .fold(0.0, f64::max);
                            
                            for exploit in &confirmed_exploits {
                                if exploit.score > 0.7 {
                                    delta_notes.push(format!(
                                        "🚨 EXPLOIT CONFIRMED: selector={} score={:.2} value={:.4} ETH",
                                        exploit.selector, exploit.score, exploit.economic_value_eth
                                    ));
                                    
                                    if exploit.economic_value_eth > 0.01 {
                                        balance_drained = true;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Offensive analysis failed: {}", e);
                    }
                }
            }
            
            // Analisa MEV
            if self.config.enable_mev {
                let mut mev_engine = MevEngine::new(MevConfig::default());
                // TODO: converter paths para ExploitPathWithValue
                // mev_opportunities = mev_engine.analyze_mev(&paths_with_value, contract_address, self).await;
            }
        }
        
        // Verificação tradicional de selectors
        for selector in &analysis.function_selectors {
            let calldata = format!("0x{}", hex::encode(selector));

            match self
                .eth_call_with_gas(attacker, contract_address, &calldata, "0x0", 5_000_000)
                .await
            {
                Ok(output) if output != "0x" => {
                    if !unauthorized_access {
                        unauthorized_access = true;
                    }
                    delta_notes.push(format!(
                        "Selector 0x{} returned {} from unauthorized caller",
                        hex::encode(selector),
                        &output[..output.len().min(20)]
                    ));
                }
                _ => {}
            }
        }

        // Verifica mudanças de estado
        let state_after = self.capture_state(contract_address, &critical_slots).await?;
        let state_delta = self.compare_states(&state_before, &state_after);
        
        for change in state_delta.changes {
            match change {
                StateChange::BalanceChanged { from, to, delta } => {
                    if from > to {
                        balance_drained = true;
                        delta_notes.push(format!(
                            "Balance drained: {} wei removed ({:.4} ETH)",
                            delta,
                            delta as f64 / 1e18
                        ));
                    }
                }
                StateChange::StorageChanged { slot, from, to } => {
                    if slot == 0 && to != "0x0000000000000000000000000000000000000000" {
                        ownership_changed = true;
                        delta_notes.push(format!(
                            "Ownership slot 0x0 changed: {} → {}",
                            &from[..from.len().min(20)],
                            &to[..to.len().min(20)]
                        ));
                    }
                }
            }
        }

        // Revert fork state — non-destructive
        let _ = self.revert(&snap).await;
        debug!("Fork state reverted to snapshot {}", snap);

        let state_delta_str = if delta_notes.is_empty() {
            "No critical state changes detected in simulation".to_string()
        } else {
            delta_notes.join("; ")
        };
        
        let risk_adjusted_value: f64 = confirmed_exploits
            .iter()
            .map(|e| e.economic_value_eth * e.confidence as f64)
            .sum();

        Ok(Some(ForensicResult {
            state_delta: state_delta_str,
            unauthorized_access,
            balance_drained,
            ownership_changed,
            confirmed_exploits,
            mev_opportunities,
            exploitation_probability,
            risk_adjusted_value_eth: risk_adjusted_value,
            analysis_duration_ms: start.elapsed().as_millis() as u64,
        }))
    }

    /// Calcula balance necessário baseado nas funções suspeitas
    async fn calculate_required_balance(&self, analysis: &BytecodeAnalysis) -> u128 {
        let mut max_value = 1_000_000_000_000_000_000u128; // 1 ETH default
        
        // TODO: Analisar bytecode para encontrar CALLVALUE usages
        // e calcular o valor máximo necessário
        
        max_value
    }

    /// Check if local Anvil node is reachable
    async fn is_anvil_available(&self) -> bool {
        self.rpc_call_with_retry("eth_chainId", json!([])).await.is_ok()
    }
}

// ============================================================
// ESTRUTURAS AUXILIARES
// ============================================================

#[derive(Debug, Clone)]
pub struct StateSnapshot {
    pub balance: u128,
    pub storage: std::collections::HashMap<u64, String>,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct StateDelta {
    pub changes: Vec<StateChange>,
}

#[derive(Debug, Clone)]
pub enum StateChange {
    BalanceChanged {
        from: u128,
        to: u128,
        delta: u128,
    },
    StorageChanged {
        slot: u64,
        from: String,
        to: String,
    },
}