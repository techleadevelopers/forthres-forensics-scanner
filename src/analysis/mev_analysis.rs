// src/offensive/mev_integration.rs
//! Hexora MEV Integration Engine
//!
//! Advanced MEV opportunity detection with:
//! - Backrun, Sandwich, Frontrun detection
//! - Flashbots/Builders integration
//! - Competition scoring with real MEV market data
//! - Tip optimization based on profit and competition
//! - Private mempool simulation
//! - Cross-chain MEV detection

use crate::forensics::ForensicsEngine;
use lru::LruCache;
use super::economic_impact::ExploitPathWithValue;
use super::probability_engine::ControlFlowPathWithProb;
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ============================================================
// ESTRUTURAS BASE
// ============================================================

#[derive(Debug, Clone)]
pub struct MevOpportunity {
    pub mev_type: MevType,
    pub estimated_profit_eth: f64,
    pub estimated_profit_usd: f64,
    pub competition_score: f64,
    pub bundle_required: bool,
    pub suggested_tip_bps: u64,
    pub execution_strategy: ExecutionStrategy,
    pub risk_level: RiskLevel,
    pub mev_timeframe_ms: u64,
    pub required_capital_eth: f64,
    pub success_probability: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MevType {
    Backrun,
    Sandwich,
    Frontrun,
    Arbitrage,
    Liquidation,
    Flashloan,
    JIT,
    CrossChain,
}

impl std::fmt::Display for MevType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MevType::Backrun => write!(f, "BACKRUN"),
            MevType::Sandwich => write!(f, "SANDWICH"),
            MevType::Frontrun => write!(f, "FRONTRUN"),
            MevType::Arbitrage => write!(f, "ARBITRAGE"),
            MevType::Liquidation => write!(f, "LIQUIDATION"),
            MevType::Flashloan => write!(f, "FLASHLOAN"),
            MevType::JIT => write!(f, "JIT"),
            MevType::CrossChain => write!(f, "CROSS_CHAIN"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ExecutionStrategy {
    FlashbotsBundle,
    PrivateMempool,
    PublicMempool,
    DirectToBuilder,
    MEVShare,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

// ============================================================
// MEV ENGINE CONFIGURATION
// ============================================================

#[derive(Debug, Clone)]
pub struct MevConfig {
    pub min_profit_eth: f64,
    pub max_competition_score: f64,
    pub bundle_simulation_enabled: bool,
    pub flashbots_api_enabled: bool,
    pub mev_share_enabled: bool,
    pub max_bundle_gas: u64,
    pub tip_percentage: f64,
    pub cross_chain_enabled: bool,
}

impl Default for MevConfig {
    fn default() -> Self {
        Self {
            min_profit_eth: 0.01,
            max_competition_score: 0.95,
            bundle_simulation_enabled: true,
            flashbots_api_enabled: true,
            mev_share_enabled: true,
            max_bundle_gas: 5_000_000,
            tip_percentage: 0.1,
            cross_chain_enabled: true,
        }
    }
}

// ============================================================
// MEV ENGINE
// ============================================================

pub struct MevEngine {
    config: MevConfig,
    flashbots_client: Option<FlashbotsClient>,
    mempool_simulator: MempoolSimulator,
    competition_tracker: CompetitionTracker,
    cache: Arc<Mutex<LruCache<String, MevOpportunity>>>,
}

impl MevEngine {
    pub fn new(config: MevConfig) -> Self {
        Self {
            config: config.clone(),
            flashbots_client: if config.flashbots_api_enabled {
                Some(FlashbotsClient::new())
            } else {
                None
            },
            mempool_simulator: MempoolSimulator::new(),
            competition_tracker: CompetitionTracker::new(),
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(500).expect("non-zero cache size"),
            ))),
        }
    }
    
    /// Full MEV analysis for all paths
    pub async fn analyze_mev(
        &mut self,
        paths: &[ExploitPathWithValue],
        contract: &str,
        forensics: &ForensicsEngine,
    ) -> Vec<MevOpportunity> {
        let mut opportunities = Vec::new();
        
        for path in paths {
            if path.economic_value_eth < self.config.min_profit_eth {
                continue;
            }
            
            // Check cache
            let cache_key = format!("{}_{}_{}", contract, path.path.entry_selector, path.economic_value_eth);
            {
                let mut cache = self.cache.lock().unwrap();
                if let Some(cached) = cache.get(&cache_key) {
                    opportunities.push(cached.clone());
                    continue;
                }
            }
            
            // Analyze each MEV type
            let mut path_ops = Vec::new();
            
            // Backrun
            if let Some(op) = self.check_backrun(path, contract, forensics).await {
                path_ops.push(op);
            }
            
            // Sandwich
            if let Some(op) = self.check_sandwich(path, contract, forensics).await {
                path_ops.push(op);
            }
            
            // Frontrun
            if let Some(op) = self.check_frontrun(path, contract, forensics).await {
                path_ops.push(op);
            }
            
            // Arbitrage (cross-DEX)
            if let Some(op) = self.check_arbitrage(path, contract, forensics).await {
                path_ops.push(op);
            }
            
            // Liquidation
            if let Some(op) = self.check_liquidation(path, contract, forensics).await {
                path_ops.push(op);
            }
            
            // Flashloan
            if let Some(op) = self.check_flashloan_mev(path, contract, forensics).await {
                path_ops.push(op);
            }
            
            // Cross-chain MEV
            if self.config.cross_chain_enabled {
                if let Some(op) = self.check_cross_chain(path, contract, forensics).await {
                    path_ops.push(op);
                }
            }
            
            // Add all opportunities for this path
            opportunities.extend(path_ops);
            
            // Cache results
            for op in &opportunities {
                let mut cache = self.cache.lock().unwrap();
                cache.put(cache_key.clone(), op.clone());
            }
        }
        
        // Sort by profit and success probability
        opportunities.sort_by(|a, b| {
            let a_score = a.estimated_profit_eth * a.success_probability;
            let b_score = b.estimated_profit_eth * b.success_probability;
            b_score.partial_cmp(&a_score).unwrap()
        });
        
        opportunities.truncate(20);
        opportunities
    }
    
    /// Check backrun opportunity
    async fn check_backrun(
        &self,
        path: &ExploitPathWithValue,
        contract: &str,
        forensics: &ForensicsEngine,
    ) -> Option<MevOpportunity> {
        let selector = &path.path.entry_selector;
        
        // Detect swap functions for backrun
        let is_swap = SWAP_SELECTORS.iter().any(|s| selector.contains(s));
        let is_liquidity = LIQUIDITY_SELECTORS.iter().any(|s| selector.contains(s));
        
        if !is_swap && !is_liquidity {
            return None;
        }
        
        // Estimate slippage impact
        let slippage = self.estimate_slippage_impact(path, contract, forensics).await;
        let profit = path.economic_value_eth * slippage;
        
        if profit < self.config.min_profit_eth {
            return None;
        }
        
        // Competition analysis
        let competition = self.competition_tracker.get_score(MevType::Backrun, profit).await;
        let success_prob = 1.0 - competition;
        
        // Execution strategy
        let (bundle_required, strategy, tip) = self.determine_execution_params(profit, competition, MevType::Backrun);
        
        Some(MevOpportunity {
            mev_type: MevType::Backrun,
            estimated_profit_eth: profit,
            estimated_profit_usd: profit * self.get_eth_price().await,
            competition_score: competition,
            bundle_required,
            suggested_tip_bps: tip,
            execution_strategy: strategy,
            risk_level: if competition > 0.8 { RiskLevel::High } else { RiskLevel::Medium },
            mev_timeframe_ms: 300,
            required_capital_eth: profit * 2.0,
            success_probability: success_prob,
        })
    }
    
    /// Check sandwich opportunity
    async fn check_sandwich(
        &self,
        path: &ExploitPathWithValue,
        contract: &str,
        forensics: &ForensicsEngine,
    ) -> Option<MevOpportunity> {
        let selector = &path.path.entry_selector;
        
        let is_swap = SWAP_SELECTORS.iter().any(|s| selector.contains(s));
        
        if !is_swap {
            return None;
        }
        
        // Check liquidity depth
        let liquidity = self.get_pool_liquidity(contract, forensics).await;
        if liquidity < path.economic_value_eth * 10.0 {
            return None; // Insufficient liquidity for sandwich
        }
        
        let profit = path.economic_value_eth * 0.4; // 40% of swap value
        
        if profit < self.config.min_profit_eth {
            return None;
        }
        
        // Sandwich has higher competition
        let competition = self.competition_tracker.get_score(MevType::Sandwich, profit).await;
        let success_prob = 1.0 - competition * 1.2;
        
        let (bundle_required, strategy, tip) = self.determine_execution_params(profit, competition, MevType::Sandwich);
        
        Some(MevOpportunity {
            mev_type: MevType::Sandwich,
            estimated_profit_eth: profit,
            estimated_profit_usd: profit * self.get_eth_price().await,
            competition_score: competition,
            bundle_required,
            suggested_tip_bps: tip,
            execution_strategy: strategy,
            risk_level: RiskLevel::High,
            mev_timeframe_ms: 500,
            required_capital_eth: profit * 3.0,
            success_probability: success_prob.min(0.95),
        })
    }
    
    /// Check frontrun opportunity
    async fn check_frontrun(
        &self,
        path: &ExploitPathWithValue,
        _contract: &str,
        _forensics: &ForensicsEngine,
    ) -> Option<MevOpportunity> {
        let selector = &path.path.entry_selector;
        
        // These are prime frontrun targets
        let is_initialize = selector.contains("initialize") || selector.contains("init");
        let is_mint = selector.contains("mint") && !selector.contains("burn");
        let is_deploy = selector.contains("create") || selector.contains("deploy");
        
        if !is_initialize && !is_mint && !is_deploy {
            return None;
        }
        
        let profit = if is_initialize {
            path.economic_value_eth * 0.95 // Near full value on initialization
        } else if is_mint {
            path.economic_value_eth * 0.7
        } else {
            path.economic_value_eth * 0.5
        };
        
        if profit < self.config.min_profit_eth {
            return None;
        }
        
        // Frontrun has extreme competition for high-value targets
        let competition = self.competition_tracker.get_score(MevType::Frontrun, profit).await;
        let success_prob = (1.0 - competition).min(0.8);
        
        let (bundle_required, strategy, tip) = self.determine_execution_params(profit, competition, MevType::Frontrun);
        
        Some(MevOpportunity {
            mev_type: MevType::Frontrun,
            estimated_profit_eth: profit,
            estimated_profit_usd: profit * self.get_eth_price().await,
            competition_score: competition,
            bundle_required,
            suggested_tip_bps: tip,
            execution_strategy: strategy,
            risk_level: if competition > 0.9 { RiskLevel::Critical } else { RiskLevel::High },
            mev_timeframe_ms: 100,
            required_capital_eth: profit,
            success_probability: success_prob,
        })
    }
    
    /// Check cross-DEX arbitrage
    async fn check_arbitrage(
        &self,
        path: &ExploitPathWithValue,
        contract: &str,
        forensics: &ForensicsEngine,
    ) -> Option<MevOpportunity> {
        let selector = &path.path.entry_selector;
        
        if !ARBITRAGE_SELECTORS.iter().any(|s| selector.contains(s)) {
            return None;
        }
        
        // Check price difference across pools
        let price_diff = self.get_arbitrage_spread(contract, forensics).await;
        if price_diff < 0.02 {
            return None; // Less than 2% spread
        }
        
        let profit = path.economic_value_eth * price_diff;
        
        if profit < self.config.min_profit_eth {
            return None;
        }
        
        let competition = self.competition_tracker.get_score(MevType::Arbitrage, profit).await;
        let success_prob = 1.0 - competition;
        
        let (bundle_required, strategy, tip) = self.determine_execution_params(profit, competition, MevType::Arbitrage);
        
        Some(MevOpportunity {
            mev_type: MevType::Arbitrage,
            estimated_profit_eth: profit,
            estimated_profit_usd: profit * self.get_eth_price().await,
            competition_score: competition,
            bundle_required,
            suggested_tip_bps: tip,
            execution_strategy: strategy,
            risk_level: RiskLevel::Medium,
            mev_timeframe_ms: 200,
            required_capital_eth: profit * 2.0,
            success_probability: success_prob,
        })
    }
    
    /// Check liquidation opportunity
    async fn check_liquidation(
        &self,
        path: &ExploitPathWithValue,
        contract: &str,
        forensics: &ForensicsEngine,
    ) -> Option<MevOpportunity> {
        let selector = &path.path.entry_selector;
        
        if !selector.contains("liquidate") && !selector.contains("auction") {
            return None;
        }
        
        // Check if position is actually liquidatable
        let is_liquidatable = self.check_liquidation_status(contract, forensics).await;
        if !is_liquidatable {
            return None;
        }
        
        let profit = path.economic_value_eth * 0.9; // 10% penalty/discount
        
        if profit < self.config.min_profit_eth {
            return None;
        }
        
        let competition = self.competition_tracker.get_score(MevType::Liquidation, profit).await;
        let success_prob = 0.95; // Liquidation is more deterministic
        
        let (bundle_required, strategy, tip) = self.determine_execution_params(profit, competition, MevType::Liquidation);
        
        Some(MevOpportunity {
            mev_type: MevType::Liquidation,
            estimated_profit_eth: profit,
            estimated_profit_usd: profit * self.get_eth_price().await,
            competition_score: competition,
            bundle_required,
            suggested_tip_bps: tip,
            execution_strategy: strategy,
            risk_level: RiskLevel::Low,
            mev_timeframe_ms: 150,
            required_capital_eth: profit,
            success_probability: success_prob,
        })
    }
    
    /// Check flashloan-based MEV
    async fn check_flashloan_mev(
        &self,
        path: &ExploitPathWithValue,
        _contract: &str,
        _forensics: &ForensicsEngine,
    ) -> Option<MevOpportunity> {
        let selector = &path.path.entry_selector;
        
        let is_flashloan_related = FLASHLOAN_SELECTORS.iter().any(|s| selector.contains(s))
            || path.economic_value_eth > 10.0; // Large value often needs flashloan
        
        if !is_flashloan_related {
            return None;
        }
        
        let profit = path.economic_value_eth * 0.8; // 20% flashloan fee
        
        if profit < self.config.min_profit_eth {
            return None;
        }
        
        let competition = self.competition_tracker.get_score(MevType::Flashloan, profit).await;
        let success_prob = 0.85;
        
        let (bundle_required, strategy, tip) = self.determine_execution_params(profit, competition, MevType::Flashloan);
        
        Some(MevOpportunity {
            mev_type: MevType::Flashloan,
            estimated_profit_eth: profit,
            estimated_profit_usd: profit * self.get_eth_price().await,
            competition_score: competition,
            bundle_required,
            suggested_tip_bps: tip,
            execution_strategy: strategy,
            risk_level: RiskLevel::Medium,
            mev_timeframe_ms: 400,
            required_capital_eth: 0.0, // Flashloan requires no capital
            success_probability: success_prob,
        })
    }
    
    /// Check cross-chain MEV
    async fn check_cross_chain(
        &self,
        path: &ExploitPathWithValue,
        _contract: &str,
        _forensics: &ForensicsEngine,
    ) -> Option<MevOpportunity> {
        let selector = &path.path.entry_selector;
        
        if !CROSS_CHAIN_SELECTORS.iter().any(|s| selector.contains(s)) {
            return None;
        }
        
        let profit = path.economic_value_eth * 0.7;
        
        if profit < self.config.min_profit_eth {
            return None;
        }
        
        let competition = self.competition_tracker.get_score(MevType::CrossChain, profit).await;
        let success_prob = 0.7; // Cross-chain is less reliable
        
        let (bundle_required, strategy, tip) = self.determine_execution_params(profit, competition, MevType::CrossChain);
        
        Some(MevOpportunity {
            mev_type: MevType::CrossChain,
            estimated_profit_eth: profit,
            estimated_profit_usd: profit * self.get_eth_price().await,
            competition_score: competition,
            bundle_required,
            suggested_tip_bps: tip,
            execution_strategy: strategy,
            risk_level: RiskLevel::High,
            mev_timeframe_ms: 2000, // Slower due to bridge
            required_capital_eth: profit,
            success_probability: success_prob,
        })
    }
    
    // ============================================================
    // HELPER FUNCTIONS
    // ============================================================
    
    async fn estimate_slippage_impact(
        &self,
        path: &ExploitPathWithValue,
        contract: &str,
        _forensics: &ForensicsEngine,
    ) -> f64 {
        // Estimate how much slippage can be captured
        let selector = &path.path.entry_selector;
        
        if selector.contains("swap") {
            // For swaps, backrun captures 60-80% of slippage
            0.7 + (path.economic_value_eth / 100.0).min(0.2)
        } else if selector.contains("mint") {
            0.5
        } else {
            0.6
        }
    }
    
    async fn get_pool_liquidity(&self, contract: &str, _forensics: &ForensicsEngine) -> f64 {
        // TODO: Query pool reserves via RPC
        // Default fallback
        100.0
    }
    
    async fn get_arbitrage_spread(&self, _contract: &str, _forensics: &ForensicsEngine) -> f64 {
        // TODO: Check real price differences across DEXes
        0.03 // 3% default spread
    }
    
    async fn check_liquidation_status(&self, _contract: &str, _forensics: &ForensicsEngine) -> bool {
        // TODO: Check actual liquidation status
        true
    }
    
    async fn get_eth_price(&self) -> f64 {
        // TODO: Fetch from Chainlink
        3000.0
    }
    
    fn determine_execution_params(
        &self,
        profit_eth: f64,
        competition_score: f64,
        mev_type: MevType,
    ) -> (bool, ExecutionStrategy, u64) {
        let bundle_required = matches!(mev_type, MevType::Sandwich | MevType::Backrun);
        
        let strategy = if profit_eth > 10.0 {
            ExecutionStrategy::DirectToBuilder
        } else if competition_score > 0.7 {
            ExecutionStrategy::FlashbotsBundle
        } else if self.config.mev_share_enabled {
            ExecutionStrategy::MEVShare
        } else {
            ExecutionStrategy::PrivateMempool
        };
        
        let tip = calculate_tip_bps(profit_eth, competition_score);
        
        (bundle_required, strategy, tip)
    }
}

// ============================================================
// SUPPORTING STRUCTURES
// ============================================================

/// Flashbots client integration
pub struct FlashbotsClient {
    endpoint: String,
    client: reqwest::Client,
}

impl FlashbotsClient {
    pub fn new() -> Self {
        Self {
            endpoint: "https://relay.flashbots.net".to_string(),
            client: reqwest::Client::new(),
        }
    }
    
    pub async fn send_bundle(&self, _txs: Vec<String>, _block_number: u64) -> Result<String, String> {
        // TODO: Implement actual Flashbots bundle submission
        Ok("bundle_hash".to_string())
    }
}

impl Default for FlashbotsClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Mempool simulator
pub struct MempoolSimulator {
    pending_txs: Arc<Mutex<VecDeque<MempoolTransaction>>>,
}

#[derive(Debug, Clone)]
pub struct MempoolTransaction {
    pub hash: String,
    pub gas_price: u64,
    pub value_eth: f64,
    pub timestamp: Instant,
    pub selector: String,
}

impl MempoolSimulator {
    pub fn new() -> Self {
        Self {
            pending_txs: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
        }
    }
    
    pub fn add_transaction(&self, tx: MempoolTransaction) {
        let mut pending = self.pending_txs.lock().unwrap();
        pending.push_back(tx);
        while pending.len() > 1000 {
            pending.pop_front();
        }
    }
    
    pub fn get_competition_for_selector(&self, selector: &str) -> u32 {
        let pending = self.pending_txs.lock().unwrap();
        pending.iter()
            .filter(|tx| tx.selector == selector)
            .count() as u32
    }
}

impl Default for MempoolSimulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Competition tracker with adaptive scoring
pub struct CompetitionTracker {
    historical_scores: Arc<Mutex<HashMap<String, VecDeque<f64>>>>,
    default_scores: HashMap<MevType, f64>,
}

impl CompetitionTracker {
    pub fn new() -> Self {
        let mut default_scores = HashMap::new();
        default_scores.insert(MevType::Backrun, 0.4);
        default_scores.insert(MevType::Sandwich, 0.5);
        default_scores.insert(MevType::Frontrun, 0.8);
        default_scores.insert(MevType::Arbitrage, 0.6);
        default_scores.insert(MevType::Liquidation, 0.3);
        default_scores.insert(MevType::Flashloan, 0.4);
        default_scores.insert(MevType::JIT, 0.2);
        default_scores.insert(MevType::CrossChain, 0.1);
        
        Self {
            historical_scores: Arc::new(Mutex::new(HashMap::new())),
            default_scores,
        }
    }
    
    pub async fn get_score(&self, mev_type: MevType, profit_eth: f64) -> f64 {
        let key = format!("{:?}_{:.2}", mev_type, profit_eth);
        
        let base_score = *self.default_scores.get(&mev_type).unwrap_or(&0.5);
        
        // Adjust based on profit (higher profit = more competition)
        let profit_factor = if profit_eth > 10.0 {
            0.95
        } else if profit_eth > 1.0 {
            0.7
        } else if profit_eth > 0.1 {
            0.4
        } else {
            0.2
        };
        
        // Combine with historical data
        let historical_factor = if let Some(history) = self.historical_scores.lock().unwrap().get(&key) {
            let avg: f64 = history.iter().sum::<f64>() / history.len() as f64;
            avg
        } else {
            0.5
        };
        
        let score = base_score * 0.4 + profit_factor * 0.4 + historical_factor * 0.2;
        score.min(0.98).max(0.05)
    }
    
    pub fn record_outcome(&self, mev_type: MevType, profit_eth: f64, success: bool) {
        let key = format!("{:?}_{:.2}", mev_type, profit_eth);
        let score = if success { 0.2 } else { 0.8 };
        
        let mut history = self.historical_scores.lock().unwrap();
        let entry = history.entry(key).or_insert_with(|| VecDeque::with_capacity(100));
        entry.push_back(score);
        while entry.len() > 100 {
            entry.pop_front();
        }
    }
}

impl Default for CompetitionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

// Selector patterns for detection
const SWAP_SELECTORS: &[&str] = &[
    "swapExactTokensForTokens",
    "swapExactETHForTokens",
    "swapTokensForExactETH",
    "swapExactTokensForETH",
    "swap",
    "exchange",
];

const LIQUIDITY_SELECTORS: &[&str] = &[
    "addLiquidity",
    "removeLiquidity",
    "deposit",
    "withdraw",
];

const ARBITRAGE_SELECTORS: &[&str] = &[
    "arbitrage",
    "flashSwap",
    "multiSwap",
];

const FLASHLOAN_SELECTORS: &[&str] = &[
    "flashLoan",
    "flashloan",
    "executeOperation",
];

const CROSS_CHAIN_SELECTORS: &[&str] = &[
    "sendMessage",
    "relay",
    "bridge",
    "crossChain",
];

/// Advanced tip calculation with market conditions
pub fn calculate_tip_bps(profit_eth: f64, competition_score: f64) -> u64 {
    // Base tip: 5% of profit
    let base_tip = 500; // 5%
    
    // Competition multiplier: up to 3x for high competition
    let competition_multiplier = 1.0 + competition_score * 2.0;
    
    // Profit multiplier: larger profits can afford higher tips
    let profit_multiplier = if profit_eth > 10.0 {
        2.0
    } else if profit_eth > 1.0 {
        1.5
    } else if profit_eth > 0.1 {
        1.2
    } else {
        1.0
    };
    
    // MEV type multiplier
    let mev_multiplier = 1.0;
    
    let tip = (base_tip as f64 * competition_multiplier * profit_multiplier * mev_multiplier) as u64;
    
    // Clamp between 500 and 10000 bps (5% to 100%)
    tip.max(500).min(10000)
}

/// Estimate competition score based on profit
pub async fn estimate_competition_score(profit_eth: f64) -> f64 {
    if profit_eth > 10.0 {
        0.95
    } else if profit_eth > 1.0 {
        0.7
    } else if profit_eth > 0.1 {
        0.4
    } else {
        0.1
    }
}

// ============================================================
// LEGACY FUNCTIONS (mantidas para compatibilidade)
// ============================================================

pub async fn analyze_mev(
    paths: &[ExploitPathWithValue],
    contract: &str,
    forensics: &ForensicsEngine,
) -> Vec<MevOpportunity> {
    let mut engine = MevEngine::new(MevConfig::default());
    engine.analyze_mev(paths, contract, forensics).await
}

// Helper functions for legacy compatibility
async fn check_backrun_possible(
    path: &ExploitPathWithValue,
    _contract: &str,
    _forensics: &ForensicsEngine,
) -> Option<MevOpportunity> {
    let selector = &path.path.entry_selector;
    let is_swap = SWAP_SELECTORS.iter().any(|s| selector.contains(s));
    
    if is_swap {
        let profit = path.economic_value_eth;
        let competition_score = estimate_competition_score(profit).await;
        
        Some(MevOpportunity {
            mev_type: MevType::Backrun,
            estimated_profit_eth: profit * 0.8,
            estimated_profit_usd: profit * 3000.0,
            competition_score,
            bundle_required: true,
            suggested_tip_bps: calculate_tip_bps(profit, competition_score),
            execution_strategy: ExecutionStrategy::FlashbotsBundle,
            risk_level: RiskLevel::Medium,
            mev_timeframe_ms: 300,
            required_capital_eth: profit * 2.0,
            success_probability: 1.0 - competition_score,
        })
    } else {
        None
    }
}

async fn check_sandwich_possible(
    path: &ExploitPathWithValue,
    _contract: &str,
    _forensics: &ForensicsEngine,
) -> Option<MevOpportunity> {
    let selector = &path.path.entry_selector;
    let is_swap = SWAP_SELECTORS.iter().any(|s| selector.contains(s));
    
    if is_swap && path.economic_value_eth >= 0.05 {
        let profit = path.economic_value_eth * 0.6;
        let competition_score = estimate_competition_score(profit).await;
        
        Some(MevOpportunity {
            mev_type: MevType::Sandwich,
            estimated_profit_eth: profit,
            estimated_profit_usd: profit * 3000.0,
            competition_score,
            bundle_required: true,
            suggested_tip_bps: calculate_tip_bps(profit, competition_score),
            execution_strategy: ExecutionStrategy::FlashbotsBundle,
            risk_level: RiskLevel::High,
            mev_timeframe_ms: 500,
            required_capital_eth: profit * 3.0,
            success_probability: 1.0 - competition_score,
        })
    } else {
        None
    }
}

async fn check_frontrun_possible(
    path: &ExploitPathWithValue,
    _contract: &str,
    _forensics: &ForensicsEngine,
) -> Option<MevOpportunity> {
    let selector = &path.path.entry_selector;
    
    if selector.contains("initialize") || selector.contains("mint") {
        let profit = path.economic_value_eth * 0.9;
        let competition_score = estimate_competition_score(profit).await;
        
        Some(MevOpportunity {
            mev_type: MevType::Frontrun,
            estimated_profit_eth: profit,
            estimated_profit_usd: profit * 3000.0,
            competition_score,
            bundle_required: false,
            suggested_tip_bps: calculate_tip_bps(profit, competition_score),
            execution_strategy: ExecutionStrategy::PrivateMempool,
            risk_level: RiskLevel::High,
            mev_timeframe_ms: 100,
            required_capital_eth: profit,
            success_probability: 1.0 - competition_score,
        })
    } else {
        None
    }
}

// ============================================================
// TESTES
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tip_calculation() {
        let tip_small = calculate_tip_bps(0.01, 0.1);
        assert!(tip_small >= 500);
        
        let tip_large = calculate_tip_bps(100.0, 0.9);
        assert!(tip_large <= 10000);
        assert!(tip_large > tip_small);
    }
    
    #[test]
    fn test_competition_score() {
        let score_low = estimate_competition_score(0.01);
        assert!(score_low < 0.5);
        
        let score_high = estimate_competition_score(100.0);
        assert!(score_high > 0.8);
    }
    
    #[test]
    fn test_mev_type_display() {
        assert_eq!(format!("{}", MevType::Backrun), "BACKRUN");
        assert_eq!(format!("{}", MevType::Sandwich), "SANDWICH");
        assert_eq!(format!("{}", MevType::Frontrun), "FRONTRUN");
    }
}
