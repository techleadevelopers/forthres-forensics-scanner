// src/offensive/probability_engine.rs
//! Hexora Bayesian Probability Engine
//!
//! Estima probabilidades de execução de paths usando:
//! - Bayesian inference com aprendizado online
//! - Cache de observações para evitar RPC calls repetidas
//! - Heurísticas baseadas em padrões conhecidos
//! - Monte Carlo otimizado com amostragem inteligente

use lru::LruCache;
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::timeout;

use crate::forensics::ForensicsEngine;
use super::path_finder::{ControlFlowPath, Condition};

// ============================================================
// ESTRUTURAS BASE (mantidas)
// ============================================================

#[derive(Debug, Clone)]
pub struct ControlFlowPathWithProb {
    pub path: ControlFlowPath,
    pub probability: f64,
    pub confidence: f64,        // Nível de confiança na estimativa
    pub samples_used: usize,    // Número de samples usados
}

// ============================================================
// NOVO: BAYESIAN PROBABILITY ENGINE
// ============================================================

#[derive(Debug, Clone)]
pub struct BayesianPrior {
    pub mean: f64,
    pub variance: f64,
    pub sample_count: u32,
}

impl Default for BayesianPrior {
    fn default() -> Self {
        Self {
            mean: 0.5,
            variance: 0.25,
            sample_count: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Observation {
    pub condition_key: String,
    pub success: bool,
    pub timestamp: Instant,
    pub context: String,
}

pub struct BayesianProbabilityEngine {
    // Prior probabilities por tipo de condição
    prior_probabilities: HashMap<String, BayesianPrior>,
    // Cache de observações (LRU)
    observation_cache: Arc<Mutex<LruCache<String, bool>>>,
    // Contador de updates por condição
    update_count: HashMap<String, u32>,
    // Histórico recente para smoothing
    recent_observations: HashMap<String, VecDeque<bool>>,
    // Configuração
    max_history_size: usize,
    enable_heuristics: bool,
    // Cache de resultados de RPC calls
    rpc_cache: Arc<Mutex<LruCache<String, (f64, Instant)>>>,
    rpc_cache_ttl_secs: u64,
}

impl BayesianProbabilityEngine {
    pub fn new(max_history_size: usize, enable_heuristics: bool) -> Self {
        Self {
            prior_probabilities: HashMap::new(),
            observation_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(1000).expect("non-zero cache size"),
            ))),
            update_count: HashMap::new(),
            recent_observations: HashMap::new(),
            max_history_size,
            enable_heuristics,
            rpc_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(500).expect("non-zero cache size"),
            ))),
            rpc_cache_ttl_secs: 60, // Cache por 60 segundos
        }
    }
    
    /// Obtém a chave única para uma condição
    pub fn condition_key(condition: &Condition) -> String {
        match condition {
            Condition::CallerEq(addr) => format!("caller_eq_{}", addr),
            Condition::CallerEqStorage(slot) => format!("caller_eq_storage_{}", slot),
            Condition::ValueGt(v) => format!("value_gt_{}", v),
            Condition::ValueLt(v) => format!("value_lt_{}", v),
            Condition::BalanceGt(v) => format!("balance_gt_{}", v),
            Condition::BalanceLt(v) => format!("balance_lt_{}", v),
            Condition::StorageSlotEq(slot, val) => format!("storage_eq_{}_{}", slot, val),
            Condition::StorageSlotNeq(slot, val) => format!("storage_neq_{}_{}", slot, val),
            Condition::TimestampGt(t) => format!("timestamp_gt_{}", t),
            Condition::TimestampLt(t) => format!("timestamp_lt_{}", t),
            Condition::BlockNumberGt(b) => format!("block_gt_{}", b),
            Condition::BlockNumberLt(b) => format!("block_lt_{}", b),
            Condition::IsContract(addr) => format!("is_contract_{}", addr),
            Condition::NotZeroAddress => "not_zero".to_string(),
        }
    }
    
    /// Atualiza probabilidade com teorema de Bayes e smoothing
    pub fn update_probability(&mut self, condition: &Condition, observed_success: bool) -> f64 {
        let key = Self::condition_key(condition);
        let prior = self.prior_probabilities
            .entry(key.clone())
            .or_insert_with(BayesianPrior::default);
        
        // Likelihood: P(observation | condition_true)
        let likelihood = if observed_success { 0.95 } else { 0.05 };
        
        // Evidence: P(observation)
        let evidence = prior.mean * likelihood + (1.0 - prior.mean) * 0.5;
        
        // Posterior = P(condition | observation)
        let posterior = (prior.mean * likelihood) / evidence;
        
        // Atualiza prior com Bayesian update
        let new_count = prior.sample_count + 1;
        let new_mean = (prior.mean * prior.sample_count as f64 + posterior) / new_count as f64;
        let new_variance = (prior.variance * prior.sample_count as f64 
            + (posterior - new_mean).powi(2)) / new_count as f64;
        
        prior.mean = new_mean;
        prior.variance = new_variance;
        prior.sample_count = new_count;
        
        // Smoothing com laplace (evita overfitting)
        let smoothed = (new_mean * new_count as f64 + 0.5) / (new_count as f64 + 1.0);
        
        // Registra no histórico recente
        let history = self.recent_observations
            .entry(key)
            .or_insert_with(|| VecDeque::with_capacity(self.max_history_size));
        history.push_back(observed_success);
        if history.len() > self.max_history_size {
            history.pop_front();
        }
        
        smoothed.min(1.0).max(0.0)
    }
    
    /// Obtém a probabilidade atual de uma condição
    pub fn get_probability(&self, condition: &Condition) -> f64 {
        let key = Self::condition_key(condition);
        
        if let Some(prior) = self.prior_probabilities.get(&key) {
            // Usa média com smoothing baseado no histórico
            if let Some(history) = self.recent_observations.get(&key) {
                let recent_success_rate = history.iter()
                    .filter(|&&b| b)
                    .count() as f64 / history.len() as f64;
                // Combina prior com histórico recente (0.7 prior, 0.3 recente)
                return prior.mean * 0.7 + recent_success_rate * 0.3;
            }
            prior.mean
        } else {
            // Fallback para heurísticas
            self.estimate_fast(condition)
        }
    }
    
    /// Estima sem RPC calls usando heurísticas + cache
    pub fn estimate_fast(&self, condition: &Condition) -> f64 {
        match condition {
            Condition::CallerEq(addr) => {
                // Heurística baseada no tipo de endereço
                if is_zero_address(addr) {
                    0.000001
                } else if is_deployer_address(addr) {
                    0.001
                } else if is_known_whale(addr) {
                    0.0001
                } else if is_contract_address(addr) {
                    0.01
                } else if is_known_exploit_contract(addr) {
                    0.5  // Endereços conhecidos de exploits
                } else {
                    0.00001
                }
            }
            Condition::CallerEqStorage(_slot) => {
                // Storage pode conter qualquer caller
                0.3
            }
            Condition::ValueGt(threshold) => {
                // Distribuição power law de valores em ETH
                let threshold_eth = *threshold as f64 / 1e18;
                if threshold_eth <= 0.001 {
                    0.5  // > 0.001 ETH é comum
                } else if threshold_eth <= 0.01 {
                    0.2
                } else if threshold_eth <= 0.1 {
                    0.05
                } else if threshold_eth <= 1.0 {
                    0.01
                } else {
                    0.001
                }
            }
            Condition::ValueLt(threshold) => {
                let threshold_eth = *threshold as f64 / 1e18;
                if threshold_eth >= 100.0 {
                    0.99  // < 100 ETH é quase sempre verdade
                } else if threshold_eth >= 10.0 {
                    0.9
                } else if threshold_eth >= 1.0 {
                    0.7
                } else {
                    0.5
                }
            }
            Condition::BalanceGt(threshold) => {
                let threshold_eth = *threshold as f64 / 1e18;
                if threshold_eth <= 1.0 {
                    0.3
                } else if threshold_eth <= 10.0 {
                    0.1
                } else {
                    0.01
                }
            }
            Condition::BalanceLt(threshold) => {
                let threshold_eth = *threshold as f64 / 1e18;
                if threshold_eth >= 1000.0 {
                    0.99
                } else if threshold_eth >= 100.0 {
                    0.8
                } else {
                    0.5
                }
            }
            Condition::StorageSlotEq(_slot, expected) => {
                if expected.contains("admin") || expected.contains("owner") {
                    0.05
                } else {
                    0.3
                }
            }
            Condition::StorageSlotNeq(_slot, _unexpected) => {
                0.7
            }
            Condition::TimestampGt(threshold) => {
                let current = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if current > *threshold {
                    0.99
                } else {
                    let remaining = threshold - current;
                    if remaining > 86400 * 30 { 0.01 }
                    else if remaining > 86400 * 7 { 0.05 }
                    else if remaining > 86400 { 0.1 }
                    else if remaining > 3600 { 0.3 }
                    else { 0.6 }
                }
            }
            Condition::TimestampLt(threshold) => {
                let current = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if current < *threshold { 0.99 } else { 0.01 }
            }
            Condition::BlockNumberGt(threshold) => {
                // Estimativa baseada em block time de 12s
                let current = 20_000_000u64;
                if current > *threshold { 0.99 } else { 0.05 }
            }
            Condition::BlockNumberLt(threshold) => {
                let current = 20_000_000u64;
                if current < *threshold { 0.99 } else { 0.01 }
            }
            Condition::IsContract(addr) => {
                if is_contract_address(addr) { 0.8 } else { 0.05 }
            }
            Condition::NotZeroAddress => 0.999,
        }
    }
    
    /// Verifica se um resultado está em cache
    pub fn get_cached_rpc_result(&self, key: &str) -> Option<f64> {
        let mut cache = self.rpc_cache.lock().unwrap();
        if let Some((value, timestamp)) = cache.get(key) {
            if timestamp.elapsed().as_secs() < self.rpc_cache_ttl_secs {
                return Some(*value);
            }
        }
        None
    }
    
    /// Cacheia um resultado de RPC
    pub fn cache_rpc_result(&mut self, key: String, value: f64) {
        let mut cache = self.rpc_cache.lock().unwrap();
        cache.put(key, (value, Instant::now()));
    }
    
    /// Reseta o estado da engine (útil para novos contratos)
    pub fn reset(&mut self) {
        self.prior_probabilities.clear();
        self.update_count.clear();
        self.recent_observations.clear();
        let mut cache = self.rpc_cache.lock().unwrap();
        cache.clear();
    }
}

// ============================================================
// FUNÇÕES HEURÍSTICAS
// ============================================================

fn is_zero_address(addr: &str) -> bool {
    addr == "0x0000000000000000000000000000000000000000"
}

fn is_deployer_address(addr: &str) -> bool {
    // Endereços conhecidos de deployers comuns
    let deployers = [
        "0x4e59b44847b379578588920ca78fbf26c0b4956c", // Create2 factory
        "0x3fab184622dc19b6109349b94811493bf2a45362",
    ];
    deployers.contains(&addr.to_lowercase().as_str())
}

fn is_known_whale(addr: &str) -> bool {
    // Endereços conhecidos de whales (simplificado)
    let whales = [
        "0xbe0eb53f46cd790cd13851d5eff43d12404d33e8", // Binance
        "0xf977814e90da44bfa03b6295a0616a897441acec", // Binance
        "0x28c6c06298d514db55e5743bf21d60", // Vitalik
    ];
    whales.contains(&addr.to_lowercase().as_str())
}

fn is_contract_address(addr: &str) -> bool {
    // Heurística simples: endereços que começam com 0x e tem 42 chars
    addr.starts_with("0x") && addr.len() == 42
}

fn is_known_exploit_contract(addr: &str) -> bool {
    // Endereços conhecidos de contratos de exploit
    let exploits = [
        "0xa9d1e08c7793af67e9d92fe308d5697fb81d3e43", // Known exploit
    ];
    exploits.contains(&addr.to_lowercase().as_str())
}

// ============================================================
// FUNÇÕES PRINCIPAIS MELHORADAS
// ============================================================

pub async fn calculate_probabilities(
    paths: Vec<ControlFlowPath>,
    forensics: &ForensicsEngine,
    contract: &str,
    samples: usize,
) -> Vec<ControlFlowPathWithProb> {
    let mut results = Vec::new();
    let mut engine = BayesianProbabilityEngine::new(100, true);
    
    for path in paths {
        let (prob, confidence, used) = calculate_path_probability_with_engine(
            &path, forensics, contract, samples, &mut engine
        ).await;
        
        if prob > 0.001 {
            results.push(ControlFlowPathWithProb {
                path,
                probability: prob,
                confidence,
                samples_used: used,
            });
        }
    }
    
    results.sort_by(|a, b| b.probability.total_cmp(&a.probability));
    results
}

async fn calculate_path_probability_with_engine(
    path: &ControlFlowPath,
    forensics: &ForensicsEngine,
    contract: &str,
    samples: usize,
    engine: &mut BayesianProbabilityEngine,
) -> (f64, f64, usize) {
    let mut prob = 1.0;
    let mut total_confidence = 0.0;
    let mut total_samples = 0;
    
    for condition in &path.conditions {
        // Primeiro tenta usar heurísticas/cache
        let cached_prob = engine.get_probability(condition);
        
        // Se a confiança na heurística é alta, usa direto
        let cond_prob = if engine.enable_heuristics && cached_prob > 0.01 && cached_prob < 0.99 {
            cached_prob
        } else {
            // Caso contrário, faz amostragem real
            let (p, samples_used) = estimate_condition_probability(
                condition, forensics, contract, samples.min(10), engine
            ).await;
            total_samples += samples_used;
            p
        };
        
        // Atualiza engine com o resultado (simula observação)
        let observed = cond_prob > 0.5;
        let updated = engine.update_probability(condition, observed);
        
        prob *= updated;
        total_confidence += 1.0 - engine.prior_probabilities
            .get(&BayesianProbabilityEngine::condition_key(condition))
            .map(|p| p.variance.sqrt())
            .unwrap_or(0.1);
        
        if prob < 0.001 {
            break;
        }
    }
    
    let confidence = if total_confidence > 0.0 {
        (total_confidence / path.conditions.len() as f64).min(0.95)
    } else {
        0.5
    };
    
    (prob.min(1.0), confidence, total_samples)
}

async fn estimate_condition_probability(
    condition: &Condition,
    forensics: &ForensicsEngine,
    contract: &str,
    max_samples: usize,
    engine: &mut BayesianProbabilityEngine,
) -> (f64, usize) {
    let key = format!("{:?}_{}", condition, contract);
    
    // Verifica cache de RPC
    if let Some(cached) = engine.get_cached_rpc_result(&key) {
        return (cached, 0);
    }
    
    let result = match condition {
        Condition::CallerEq(address) => {
            (
                estimate_caller_probability_optimized(forensics, contract, address, max_samples).await,
                max_samples,
            )
        }
        Condition::CallerEqStorage(slot) => {
            estimate_caller_storage_probability_optimized(forensics, contract, *slot).await
        }
        Condition::ValueGt(threshold) => {
            (estimate_value_probability_optimized(*threshold, true, max_samples), max_samples)
        }
        Condition::ValueLt(threshold) => {
            (estimate_value_probability_optimized(*threshold, false, max_samples), max_samples)
        }
        Condition::BalanceGt(threshold) => {
            estimate_balance_probability_optimized(forensics, contract, *threshold, true).await
        }
        Condition::BalanceLt(threshold) => {
            estimate_balance_probability_optimized(forensics, contract, *threshold, false).await
        }
        Condition::StorageSlotEq(slot, expected) => {
            estimate_storage_probability_optimized(forensics, contract, *slot, expected).await
        }
        Condition::StorageSlotNeq(slot, unexpected) => {
            estimate_storage_neq_probability_optimized(forensics, contract, *slot, unexpected).await
        }
        Condition::TimestampGt(threshold) => {
            (estimate_timestamp_probability_optimized(*threshold, true), 1)
        }
        Condition::TimestampLt(threshold) => {
            (estimate_timestamp_probability_optimized(*threshold, false), 1)
        }
        Condition::BlockNumberGt(threshold) => {
            (estimate_block_number_probability_optimized(*threshold, true).await, 1)
        }
        Condition::BlockNumberLt(threshold) => {
            (estimate_block_number_probability_optimized(*threshold, false).await, 1)
        }
        Condition::IsContract(address) => {
            (estimate_is_contract_probability_optimized(forensics, address).await, 1)
        }
        Condition::NotZeroAddress => (0.999, 1),
    };
    
    engine.cache_rpc_result(key, result.0);
    result
}

// ============================================================
// FUNÇÕES DE ESTIMATIVA OTIMIZADAS
// ============================================================

async fn estimate_caller_probability_optimized(
    forensics: &ForensicsEngine,
    contract: &str,
    expected_owner: &str,
    max_samples: usize,
) -> f64 {
    // Casos especiais rápidos
    if is_zero_address(expected_owner) {
        return 0.001;
    }
    
    if is_deployer_address(expected_owner) || is_known_whale(expected_owner) {
        // Endereço conhecido, mas improvável de ser o caller em tx aleatória
        return 0.0001;
    }
    
    // Se for um endereço específico e parece ser owner legítimo
    if expected_owner.starts_with("0x") && expected_owner.len() == 42 {
        // Tenta verificar se é o owner real via storage
        let owner_slot = forensics.get_storage(contract, "0x0").await.unwrap_or_default();
        if owner_slot.to_lowercase() == expected_owner.to_lowercase() {
            return 0.9; // É o owner real
        }
        return 0.01;
    }
    
    // Amostragem inteligente: apenas alguns callers relevantes
    let relevant_callers = get_relevant_callers(forensics, contract).await;
    let samples_to_take = max_samples.min(relevant_callers.len());
    
    let mut success_count = 0;
    for caller in relevant_callers.iter().take(samples_to_take) {
        let snap = forensics.snapshot().await.unwrap_or_default();
        
        let result = timeout(
            Duration::from_secs(1),
            forensics.eth_call(caller, contract, "0x", "0x0")
        ).await;
        
        if let Ok(Ok(output)) = result {
            if output != "0x" && !output.contains("revert") {
                success_count += 1;
            }
        }
        
        let _ = forensics.revert(&snap).await;
    }
    
    if samples_to_take == 0 {
        0.01
    } else {
        success_count as f64 / samples_to_take as f64
    }
}

async fn get_relevant_callers(forensics: &ForensicsEngine, contract: &str) -> Vec<String> {
    let mut callers = Vec::new();
    
    // 1. Owner atual (se disponível)
    if let Ok(owner) = forensics.get_storage(contract, "0x0").await {
        if owner != "0x0000000000000000000000000000000000000000" {
            callers.push(owner);
        }
    }
    
    // 2. Endereços conhecidos
    callers.push("0x0000000000000000000000000000000000000000".to_string());
    callers.push("0xBe0eB53F46cd790Cd13851d5EFf43D12404d33E8".to_string()); // Binance
    callers.push("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string()); // Test account
    
    callers
}

async fn estimate_caller_storage_probability_optimized(
    forensics: &ForensicsEngine,
    contract: &str,
    slot: u64,
) -> (f64, usize) {
    let slot_hex = format!("0x{:x}", slot);
    if let Ok(current_owner) = forensics.get_storage(contract, &slot_hex).await {
        if current_owner != "0x0000000000000000000000000000000000000000" {
            // Slot já tem valor, chance moderada
            return (0.15, 1);
        }
    }
    (0.4, 1) // Slot vazio, chance maior
}

fn estimate_value_probability_optimized(threshold: u128, is_greater: bool, samples: usize) -> f64 {
    // Usa distribuição log-normal para valores de transação
    let threshold_eth = threshold as f64 / 1e18;
    
    if is_greater {
        // P(valor > threshold) ~ 1 - CDF(threshold)
        if threshold_eth <= 0.001 {
            0.4
        } else if threshold_eth <= 0.01 {
            0.15
        } else if threshold_eth <= 0.1 {
            0.05
        } else if threshold_eth <= 1.0 {
            0.01
        } else {
            0.001
        }
    } else {
        // P(valor < threshold)
        if threshold_eth >= 100.0 {
            0.99
        } else if threshold_eth >= 10.0 {
            0.95
        } else if threshold_eth >= 1.0 {
            0.8
        } else if threshold_eth >= 0.1 {
            0.6
        } else {
            0.4
        }
    }
}

async fn estimate_balance_probability_optimized(
    forensics: &ForensicsEngine,
    contract: &str,
    threshold: u128,
    is_greater: bool,
) -> (f64, usize) {
    let current_balance = forensics.get_balance(contract).await.unwrap_or(0);
    
    let prob = if is_greater {
        if current_balance > threshold {
            0.95
        } else {
            // Estima probabilidade de balance aumentar baseado em inflows
            let needed = threshold.saturating_sub(current_balance);
            let needed_eth = needed as f64 / 1e18;
            if needed_eth > 1000.0 {
                0.001
            } else if needed_eth > 100.0 {
                0.01
            } else if needed_eth > 10.0 {
                0.05
            } else {
                0.1
            }
        }
    } else {
        if current_balance < threshold {
            0.95
        } else {
            0.05
        }
    };
    
    (prob, 1)
}

async fn estimate_storage_probability_optimized(
    forensics: &ForensicsEngine,
    contract: &str,
    slot: u64,
    expected: &str,
) -> (f64, usize) {
    let slot_hex = format!("0x{:x}", slot);
    if let Ok(current) = forensics.get_storage(contract, &slot_hex).await {
        if current.to_lowercase() == expected.to_lowercase() {
            return (0.99, 1);
        }
    }
    (0.05, 1)
}

async fn estimate_storage_neq_probability_optimized(
    forensics: &ForensicsEngine,
    contract: &str,
    slot: u64,
    unexpected: &str,
) -> (f64, usize) {
    let slot_hex = format!("0x{:x}", slot);
    if let Ok(current) = forensics.get_storage(contract, &slot_hex).await {
        if current.to_lowercase() != unexpected.to_lowercase() {
            return (0.85, 1);
        }
    }
    (0.4, 1)
}

fn estimate_timestamp_probability_optimized(threshold: u64, is_greater: bool) -> f64 {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    if is_greater {
        if current_time > threshold {
            0.99
        } else {
            let remaining = threshold - current_time;
            if remaining > 86400 * 30 { 0.01 }
            else if remaining > 86400 * 7 { 0.05 }
            else if remaining > 86400 { 0.1 }
            else if remaining > 3600 { 0.25 }
            else if remaining > 60 { 0.4 }
            else { 0.6 }
        }
    } else {
        if current_time < threshold {
            0.99
        } else {
            0.01
        }
    }
}

async fn estimate_block_number_probability_optimized(threshold: u64, is_greater: bool) -> f64 {
    // TODO: Buscar block number atual via RPC
    let current_block = 20_000_000u64;
    
    if is_greater {
        if current_block > threshold {
            0.99
        } else {
            let remaining = threshold - current_block;
            if remaining > 1_000_000 { 0.02 }
            else if remaining > 100_000 { 0.05 }
            else if remaining > 10_000 { 0.15 }
            else { 0.3 }
        }
    } else {
        if current_block < threshold {
            0.99
        } else {
            0.01
        }
    }
}

async fn estimate_is_contract_probability_optimized(
    forensics: &ForensicsEngine,
    address: &str,
) -> f64 {
    if let Ok(code) = forensics.eth_call(address, address, "0x", "0x0").await {
        if code != "0x" && code.len() > 10 {
            return 0.95;
        }
    }
    0.05
}

// ============================================================
// FUNÇÕES ORIGINAIS (mantidas para compatibilidade)
// ============================================================

// As funções originais foram mantidas e renomeadas para não quebrar
// código existente. Use as novas funções _optimized para melhor performance.

// As assinaturas originais permanecem para compatibilidade
pub async fn calculate_path_probability(
    path: &ControlFlowPath,
    forensics: &ForensicsEngine,
    contract: &str,
    samples: usize,
) -> f64 {
    let (prob, _, _) = calculate_path_probability_with_engine(
        path, forensics, contract, samples, &mut BayesianProbabilityEngine::new(100, true)
    ).await;
    prob
}

// Mantidas as funções originais (deprecated)
#[allow(dead_code)]
async fn estimate_caller_probability(
    forensics: &ForensicsEngine,
    contract: &str,
    expected_owner: &str,
    samples: usize,
) -> f64 {
    estimate_caller_probability_optimized(forensics, contract, expected_owner, samples).await
}

#[allow(dead_code)]
async fn estimate_block_number_probability(threshold: u64, is_greater: bool) -> f64 {
    estimate_block_number_probability_optimized(threshold, is_greater).await
}

// ============================================================
// TESTES
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bayesian_update() {
        let mut engine = BayesianProbabilityEngine::new(10, true);
        let cond = Condition::NotZeroAddress;
        
        let prob1 = engine.update_probability(&cond, true);
        assert!(prob1 > 0.5);
        
        let prob2 = engine.update_probability(&cond, false);
        assert!(prob2 < prob1);
    }
    
    #[test]
    fn test_condition_key() {
        let cond1 = Condition::NotZeroAddress;
        let cond2 = Condition::ValueGt(1000);
        
        assert_ne!(BayesianProbabilityEngine::condition_key(&cond1),
                   BayesianProbabilityEngine::condition_key(&cond2));
    }
    
    #[test]
    fn test_estimate_fast() {
        let engine = BayesianProbabilityEngine::new(10, true);
        
        let cond_zero = Condition::CallerEq("0x0000000000000000000000000000000000000000".to_string());
        let prob_zero = engine.estimate_fast(&cond_zero);
        assert!(prob_zero < 0.001);
        
        let cond_value = Condition::ValueGt(1_000_000_000_000_000_000u128); // 1 ETH
        let prob_value = engine.estimate_fast(&cond_value);
        assert!(prob_value < 0.5);
    }
}
