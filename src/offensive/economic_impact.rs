// src/offensive/economic_impact.rs
use crate::forensics::ForensicsEngine;
use super::path_finder::{ControlFlowPath, StateChange};
use super::probability_engine::ControlFlowPathWithProb;

#[derive(Debug, Clone)]
pub struct ExploitPathWithValue {
    pub path: ControlFlowPath,
    pub probability: f64,
    pub economic_value_eth: f64,
    pub risk_adjusted_value: f64,
}

// Coingecko/CoinMarketCap price cache simples
use std::collections::HashMap;
use std::sync::OnceLock;

static PRICE_CACHE: OnceLock<HashMap<String, f64>> = OnceLock::new();

fn get_price_cache() -> &'static HashMap<String, f64> {
    PRICE_CACHE.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("USDC".to_string(), 1.0);
        m.insert("USDT".to_string(), 1.0);
        m.insert("DAI".to_string(), 1.0);
        m.insert("WETH".to_string(), 3000.0);
        m.insert("WBTC".to_string(), 60000.0);
        m
    })
}

async fn get_token_price(token_address: &str) -> f64 {
    // Cache de preços simplificado
    // Em produção, consultaria Coingecko API com cache
    let _cache = get_price_cache();
    
    if token_address.contains("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") {
        return 1.0; // USDC
    }
    if token_address.contains("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2") {
        return 3000.0; // WETH
    }
    if token_address.contains("2260fac5e5542a773aa44fbcfedf7c193bc2c599") {
        return 60000.0; // WBTC
    }
    
    // Token desconhecido
    0.1
}

fn get_gas_price_gwei() -> f64 {
    // TODO: Buscar gas price atual via RPC
    20.0 // 20 Gwei padrão
}

pub async fn calculate_economic_value(
    paths: Vec<ControlFlowPathWithProb>,
    contract: &str,
    forensics: &ForensicsEngine,
) -> Vec<ExploitPathWithValue> {
    let mut results = Vec::new();
    
    for path_prob in paths {
        let value = calculate_path_value(&path_prob.path, contract, forensics).await;
        
        results.push(ExploitPathWithValue {
            path: path_prob.path,
            probability: path_prob.probability,
            economic_value_eth: value,
            risk_adjusted_value: value * path_prob.probability,
        });
    }
    
    results.sort_by(|a, b| b.risk_adjusted_value.partial_cmp(&a.risk_adjusted_value).unwrap());
    results
}

async fn calculate_path_value(
    path: &ControlFlowPath,
    contract: &str,
    forensics: &ForensicsEngine,
) -> f64 {
    let mut total_eth = 0.0;
    
    // Pega saldo atual do contrato
    let contract_balance = forensics.get_balance(contract).await.unwrap_or(0);
    let contract_balance_eth = contract_balance as f64 / 1e18;
    
    for change in &path.state_changes {
        match change {
            StateChange::SelfDestruct(_) => {
                total_eth += contract_balance_eth;
            }
            StateChange::Transfer(amount, Some(token)) => {
                let token_price = get_token_price(token).await;
                total_eth += *amount as f64 / 1e18 * token_price;
            }
            StateChange::Transfer(amount, None) => {
                total_eth += *amount as f64 / 1e18;
            }
            StateChange::Mint(amount, token) => {
                let token_price = get_token_price(token).await;
                // Assumindo 30% slippage para venda
                total_eth += *amount as f64 / 1e18 * token_price * 0.7;
            }
            StateChange::Delegatecall(target) => {
                // Delegatecall pode executar código arbitrário
                // Estimativa conservadora: 50% do saldo + tokens
                total_eth += contract_balance_eth * 0.5;
                
                // Tenta verificar se o target tem funções de drenagem
                if let Ok(code) = forensics.eth_call(target, target, "0x", "0x0").await {
                    if code.contains("withdraw") || code.contains("drain") {
                        total_eth += contract_balance_eth;
                    }
                }
            }
            StateChange::Call(_target, value, _) => {
                total_eth += *value as f64 / 1e18;
            }
            StateChange::StorageWrite(slot, _value) => {
                if *slot == 0 {
                    // Ownership change - valor indireto
                    total_eth += contract_balance_eth * 0.3;
                }
            }
            _ => {}
        }
    }
    
    // Subtrai custo de gas
    let gas_price_eth = get_gas_price_gwei() * 1e9 / 1e18;
    let gas_cost_eth = path.gas_estimate as f64 * gas_price_eth;
    
    (total_eth - gas_cost_eth).max(0.0)
}