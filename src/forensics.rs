use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{debug, info, warn};

use crate::bytecode::BytecodeAnalysis;

/// Result of forensic fork validation
#[derive(Debug, Clone)]
pub struct ForensicResult {
    pub success: bool,
    pub state_delta: String,
    pub unauthorized_access: bool,
    pub balance_drained: bool,
    pub ownership_changed: bool,
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

/// Deep forensic validation engine using local Anvil fork.
/// Simulates unauthorized interactions in an ephemeral fork environment.
/// ZERO impact on mainnet — all operations are strictly local.
pub struct ForensicsEngine {
    anvil_url: String,
    chain_id: u64,
    http_client: Client,
}

impl ForensicsEngine {
    pub fn new(anvil_url: String, chain_id: u64) -> Self {
        Self {
            anvil_url,
            chain_id,
            http_client: Client::new(),
        }
    }

    /// Send a JSON-RPC request to the local Anvil node
    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value> {
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
        let snap = self.rpc_call("evm_snapshot", json!([])).await?;
        Ok(snap.as_str().unwrap_or("0x0").to_string())
    }

    /// Revert to a previously captured snapshot
    pub async fn revert(&self, snapshot_id: &str) -> Result<()> {
        self.rpc_call("evm_revert", json!([snapshot_id])).await?;
        Ok(())
    }

    /// Impersonate an account (no private key needed) — Anvil extension
    pub async fn impersonate(&self, address: &str) -> Result<()> {
        self.rpc_call("anvil_impersonateAccount", json!([address])).await?;
        debug!("Impersonating account: {}", address);
        Ok(())
    }

    /// Set the ETH balance of an account — Anvil extension
    pub async fn set_balance(&self, address: &str, balance_hex: &str) -> Result<()> {
        self.rpc_call("anvil_setBalance", json!([address, balance_hex])).await?;
        debug!("Set balance {} for {}", balance_hex, address);
        Ok(())
    }

    /// Get the ETH balance of an address
    pub async fn get_balance(&self, address: &str) -> Result<u128> {
        let result = self.rpc_call("eth_getBalance", json!([address, "latest"])).await?;
        let hex = result.as_str().unwrap_or("0x0");
        let stripped = hex.trim_start_matches("0x");
        Ok(u128::from_str_radix(stripped, 16).unwrap_or(0))
    }

    /// Get a storage slot value
    pub async fn get_storage(&self, address: &str, slot: &str) -> Result<String> {
        let result = self
            .rpc_call("eth_getStorageAt", json!([address, slot, "latest"]))
            .await?;
        Ok(result.as_str().unwrap_or("0x0").to_string())
    }

    /// Simulate a call against the fork — returns output hex or error
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

        let result = self.rpc_call("eth_call", params).await?;
        Ok(result.as_str().unwrap_or("0x").to_string())
    }

    /// Core forensic validation flow:
    /// 1. Snapshot state
    /// 2. Impersonate an unauthorized attacker address
    /// 3. Attempt to call flagged functions
    /// 4. Audit state delta (balance, ownership slot)
    /// 5. Revert to snapshot (non-destructive)
    pub async fn validate_with_fork(
        &self,
        contract_address: &str,
        analysis: &BytecodeAnalysis,
        _original_caller: &str,
    ) -> Result<Option<ForensicResult>> {
        // Skip if Anvil is not available (graceful degradation)
        if !self.is_anvil_available().await {
            warn!("Anvil not available — skipping deep forensic validation");
            return Ok(None);
        }

        info!(
            "Starting forensic validation for contract: {}",
            contract_address
        );

        // Canonical attacker address — fresh account, no prior permissions
        let attacker = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF";

        // Take a snapshot before any changes
        let snap = self.snapshot().await.unwrap_or_else(|_| "0x0".to_string());

        // Fund the attacker and impersonate
        let _ = self.set_balance(attacker, "0xDE0B6B3A7640000").await; // 1 ETH
        let _ = self.impersonate(attacker).await;

        let before_balance = self.get_balance(contract_address).await.unwrap_or(0);
        let before_owner_slot = self
            .get_storage(contract_address, "0x0")
            .await
            .unwrap_or_else(|_| "0x0".to_string());

        let mut unauthorized_access = false;
        let mut balance_drained = false;
        let mut ownership_changed = false;
        let mut delta_notes = Vec::new();

        // Attempt to call each flagged selector
        for selector in &analysis.function_selectors {
            let calldata = format!("0x{}", hex::encode(selector));

            match self
                .eth_call(attacker, contract_address, &calldata, "0x0")
                .await
            {
                Ok(output) if output != "0x" => {
                    unauthorized_access = true;
                    delta_notes.push(format!(
                        "Selector 0x{} returned {} from unauthorized caller",
                        hex::encode(selector),
                        &output[..output.len().min(20)]
                    ));
                }
                _ => {}
            }
        }

        // Check post-call state
        let after_balance = self.get_balance(contract_address).await.unwrap_or(0);
        let after_owner_slot = self
            .get_storage(contract_address, "0x0")
            .await
            .unwrap_or_else(|_| "0x0".to_string());

        if after_balance < before_balance {
            balance_drained = true;
            let drained = before_balance - after_balance;
            delta_notes.push(format!(
                "Balance drained: {} wei removed ({:.4} ETH)",
                drained,
                drained as f64 / 1e18
            ));
        }

        if after_owner_slot != before_owner_slot && !after_owner_slot.ends_with("0000") {
            ownership_changed = true;
            delta_notes.push(format!(
                "Ownership slot 0x0 changed: {} → {}",
                &before_owner_slot[..before_owner_slot.len().min(20)],
                &after_owner_slot[..after_owner_slot.len().min(20)]
            ));
        }

        // Revert fork state — non-destructive
        let _ = self.revert(&snap).await;
        debug!("Fork state reverted to snapshot {}", snap);

        let state_delta = if delta_notes.is_empty() {
            "No critical state changes detected in simulation".to_string()
        } else {
            delta_notes.join("; ")
        };

        Ok(Some(ForensicResult {
            success: true,
            state_delta,
            unauthorized_access,
            balance_drained,
            ownership_changed,
        }))
    }

    /// Check if local Anvil node is reachable
    async fn is_anvil_available(&self) -> bool {
        self.rpc_call("eth_chainId", json!([])).await.is_ok()
    }
}
