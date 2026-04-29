// src/offensive/mod.rs
//! Hexora Offensive Security Engine - Main Module
//!
//! Integrates all offensive analysis components:
//! - Symbolic execution (path finding)
//! - Bayesian probability estimation
//! - Real-time economic impact
//! - Guided fuzzing feedback loop
//! - MEV opportunity detection
//! - Cross-validation and PoC generation

// ============================================================
// MODULE DECLARATIONS
// ============================================================

pub(crate) mod path_analysis;
pub(crate) mod probabilistic_risk;
pub(crate) mod economic_risk;
pub(crate) mod mev_analysis;
pub(crate) mod symbolic_analysis;
pub(crate) mod adaptive_feedback;

pub(crate) use adaptive_feedback as feedback_loop;
pub(crate) use economic_risk as economic_impact;
pub(crate) use mev_analysis as mev_integration;
pub(crate) use path_analysis as path_finder;
pub(crate) use probabilistic_risk as probability_engine;
pub(crate) use symbolic_analysis as symbolic_executor;

// ============================================================
// PUBLIC RE-EXPORTS
// ============================================================

pub use path_analysis::{
    find_exploit_paths, 
    ControlFlowPath, 
    Condition, 
    StateChange,
    BasicBlock,
    Instruction,
};

pub use probabilistic_risk::{
    calculate_probabilities,
    ControlFlowPathWithProb,
    BayesianProbabilityEngine,
};

pub use economic_risk::{
    calculate_economic_value,
    ExploitPathWithValue,
    RealTimeEconomicEngine,
    EconomicConfig,
};

pub use mev_analysis::analyze_mev;

pub use symbolic_analysis::{
    HexoraSymbolicExecutor,
    SymbolicConfig,
    SymbolicExecutionResult,
    SymbolicPath,
    SymbolicStateChange,
};

pub use adaptive_feedback::{
    run_offensive_analysis,
    FeedbackLoopEngine,
    ExploitAttempt,
    SimulationResult,
    TestInput,
    HexoraGuidedFuzzer,
};

// ============================================================
// IMPORTS
// ============================================================

use anyhow::Result;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::bytecode::BytecodeAnalysis;
use crate::forensics::ForensicsEngine;
use crate::reporter::{ExploitPathReport, MevOpportunityReport};

// ============================================================
// CONFIGURATION
// ============================================================

#[derive(Debug, Clone)]
pub struct OffensiveConfig {
    pub max_paths: usize,
    pub monte_carlo_samples: usize,
    pub min_probability: f64,
    pub min_economic_value_eth: f64,
    pub max_iterations: u32,
    pub mutation_factor: f32,
    pub enable_symbolic: bool,
    pub enable_fuzzing: bool,
    pub enable_mev_analysis: bool,
    pub enable_poc_generation: bool,
    pub max_concurrent_analysis: usize,
    pub rpc_timeout_ms: u64,
    pub cache_results: bool,
}

impl Default for OffensiveConfig {
    fn default() -> Self {
        Self {
            max_paths: 50,
            monte_carlo_samples: 100,
            min_probability: 0.01,
            min_economic_value_eth: 0.001,
            max_iterations: 15,
            mutation_factor: 0.3,
            enable_symbolic: true,
            enable_fuzzing: true,
            enable_mev_analysis: true,
            enable_poc_generation: true,
            max_concurrent_analysis: 5,
            rpc_timeout_ms: 10000,
            cache_results: true,
        }
    }
}

// ============================================================
// REPORT STRUCTURES
// ============================================================

pub type ExploitPath = ExploitPathReport;
pub type MevOpportunity = MevOpportunityReport;

#[derive(Debug, Clone)]
pub struct ValidatedExploit {
    pub path: SymbolicPath,
    pub exploit: ExploitAttempt,
    pub confidence: f64,
    pub feasibility: bool,
}

#[derive(Debug, Clone)]
pub struct OffensiveReport {
    pub exploit_paths: Vec<ExploitPath>,
    pub mev_opportunities: Vec<MevOpportunity>,
    pub exploitation_probability: f64,
    pub risk_adjusted_value: f64,
    pub validated_exploits: Vec<ValidatedExploit>,
    pub proof_of_concept: Option<String>,
    pub analysis_time_ms: u128,
    pub summary: OffensiveSummary,
}

#[derive(Debug, Clone)]
pub struct OffensiveSummary {
    pub total_paths_analyzed: usize,
    pub high_value_paths: usize,
    pub critical_exploits: usize,
    pub total_economic_value_eth: f64,
    pub max_confidence: f64,
    pub recommended_actions: Vec<String>,
}

// ============================================================
// HEXORA OFFENSIVE ENGINE (FULL INTEGRATION)
// ============================================================

pub struct HexoraOffensiveEngine {
    config: OffensiveConfig,
    forensics: ForensicsEngine,
    symbolic: Mutex<HexoraSymbolicExecutor>,
    fuzzer: Arc<HexoraGuidedFuzzer>,
    economic: Arc<RealTimeEconomicEngine>,
    probability: Arc<BayesianProbabilityEngine>,
    rpc_semaphore: Arc<Semaphore>,
    result_cache: Arc<tokio::sync::Mutex<LruCache<String, OffensiveReport>>>,
}

impl HexoraOffensiveEngine {
    /// Creates a new Hexora Offensive Engine with full integration
    pub fn new(config: OffensiveConfig, forensics: ForensicsEngine) -> Self {
        let symbolic_config = SymbolicConfig {
            max_paths: config.max_paths,
            max_depth: 500,
            max_constraints_per_path: 50,
            enable_smt: false,
            timeout_ms: config.rpc_timeout_ms,
        };
        
        let economic_config = EconomicConfig::default();
        
        Self {
            config: config.clone(),
            forensics: forensics.clone(),
            symbolic: Mutex::new(HexoraSymbolicExecutor::new(symbolic_config)),
            fuzzer: Arc::new(HexoraGuidedFuzzer::new()),
            economic: Arc::new(RealTimeEconomicEngine::new(economic_config)),
            probability: Arc::new(BayesianProbabilityEngine::new(100, true)),
            rpc_semaphore: Arc::new(Semaphore::new(config.max_concurrent_analysis)),
            result_cache: Arc::new(tokio::sync::Mutex::new(LruCache::new(
                NonZeroUsize::new(50).expect("non-zero cache size"),
            ))),
        }
    }
    
    /// Full analysis pipeline - integrates all components
    pub async fn analyze_full(
        &self,
        contract: &str,
        analysis: &BytecodeAnalysis,
    ) -> Result<OffensiveReport> {
        let start = Instant::now();
        
        // Check cache first
        let cache_key = format!("{}_{}", contract, analysis.bytecode.len());
        if self.config.cache_results {
            let mut cache = self.result_cache.lock().await;
            if let Some(cached) = cache.get(&cache_key) {
                info!("📦 Using cached analysis result for {}", contract);
                return Ok(cached.clone());
            }
        }
        
        info!("🔬 [1/6] Building CFG and extracting paths...");
        let paths = if self.config.enable_symbolic {
            self.extract_paths_symbolic(analysis).await?
        } else {
            self.extract_paths_static(analysis).await?
        };
        
        info!("🎯 [2/6] Found {} potential paths", paths.len());
        
        info!("📊 [3/6] Calculating Bayesian probabilities...");
        let paths_with_prob = self.calculate_path_probabilities(&paths, contract).await;
        
        info!("💰 [4/6] Estimating economic impact...");
        let paths_with_value = self.calculate_economic_impact(&paths_with_prob, contract).await;
        
        info!("🔄 [5/6] Running guided fuzzing feedback loop...");
        let exploits = self.run_guided_fuzzing(&paths_with_value, contract).await;
        
        info!("🔍 [6/6] Cross-validating and generating PoC...");
        let validated = self.cross_validate_symbolic_concrete(&paths, &exploits).await;
        
        let analysis_time_ms = start.elapsed().as_millis();
        let summary = self.generate_summary(&paths_with_value, &validated, &exploits);
        
        // Generate PoC if enabled
        let poc = if self.config.enable_poc_generation && !validated.is_empty() {
            Some(self.generate_poc(&validated[0], contract).await?)
        } else {
            None
        };
        
        // Analyze MEV opportunities
        let mev_opportunities = if self.config.enable_mev_analysis {
            self.analyze_mev_opportunities(&paths_with_value, contract).await
        } else {
            Vec::new()
        };
        
        let report = OffensiveReport {
            exploit_paths: self.convert_to_report_paths(&paths_with_value),
            mev_opportunities,
            exploitation_probability: summary.max_confidence,
            risk_adjusted_value: summary.total_economic_value_eth * summary.max_confidence,
            validated_exploits: validated,
            proof_of_concept: poc,
            analysis_time_ms,
            summary: summary.clone(),
        };
        
        // Log critical findings
        if summary.critical_exploits > 0 {
            warn!(
                "🚨 CRITICAL: Found {} high-confidence exploits with total value {:.4} ETH",
                summary.critical_exploits,
                summary.total_economic_value_eth
            );
            
            for action in &summary.recommended_actions {
                warn!("   → {}", action);
            }
        }
        
        // Cache result
        if self.config.cache_results {
            let mut cache = self.result_cache.lock().await;
            cache.put(cache_key, report.clone());
        }
        
        Ok(report)
    }
    
    /// Extract paths using symbolic execution
    async fn extract_paths_symbolic(&self, analysis: &BytecodeAnalysis) -> Result<Vec<ControlFlowPath>> {
        let bytecode = &analysis.bytecode;
        let mut all_paths = Vec::new();
        
        for selector in &analysis.function_selectors {
            let result = self
                .symbolic
                .lock()
                .expect("symbolic executor poisoned")
                .execute(analysis, selector);
            info!("  → Selector {}: {} paths, {} branches", 
                hex::encode(selector), 
                result.paths.len(),
                result.branches_encountered
            );
            
            // Convert symbolic paths to ControlFlowPath
            for sym_path in result.paths {
                let path = self.convert_symbolic_to_controlflow(&sym_path, selector);
                if path.is_dangerous() {
                    all_paths.push(path);
                }
            }
        }
        
        Ok(all_paths)
    }
    
    /// Extract paths using static analysis (fallback)
    async fn extract_paths_static(&self, analysis: &BytecodeAnalysis) -> Result<Vec<ControlFlowPath>> {
        Ok(find_exploit_paths(analysis, self.config.max_paths))
    }
    
    /// Calculate Bayesian probabilities for all paths
    async fn calculate_path_probabilities(
        &self,
        paths: &[ControlFlowPath],
        contract: &str,
    ) -> Vec<ControlFlowPathWithProb> {
        let mut results = Vec::new();
        
        for path in paths {
            let mut path_prob = 1.0;
            
            for condition in &path.conditions {
                let prob = self.probability.estimate_fast(condition);
                path_prob *= prob;
                
                if path_prob < self.config.min_probability {
                    break;
                }
            }
            
            if path_prob >= self.config.min_probability {
                results.push(ControlFlowPathWithProb {
                    path: path.clone(),
                    probability: path_prob.min(1.0),
                    confidence: 0.7,
                    samples_used: 0,
                });
            }
        }
        
        results.sort_by(|a, b| b.probability.total_cmp(&a.probability));
        results.truncate(self.config.max_paths);
        results
    }
    
    /// Calculate economic impact for all paths
    async fn calculate_economic_impact(
        &self,
        paths: &[ControlFlowPathWithProb],
        contract: &str,
    ) -> Vec<ExploitPathWithValue> {
        let mut results = Vec::new();
        
        for path_prob in paths {
            let value = self.estimate_path_value(&path_prob.path, contract).await;
            
            if value >= self.config.min_economic_value_eth {
                results.push(ExploitPathWithValue {
                    path: path_prob.path.clone(),
                    probability: path_prob.probability,
                    economic_value_eth: value,
                    economic_value_usd: value * 3000.0, // ETH price approximation
                    risk_adjusted_value: value * path_prob.probability,
                    liquidity_impact: 0.0,
                    execution_cost_eth: 0.0,
                    net_profit_eth: value,
                });
            }
        }
        
        results.sort_by(|a, b| b.risk_adjusted_value.total_cmp(&a.risk_adjusted_value));
        results
    }
    
    /// Estimate path value using economic engine
    async fn estimate_path_value(&self, path: &ControlFlowPath, contract: &str) -> f64 {
        let mut total_value = 0.0;
        
        // Get contract balance
        let balance = self.forensics.get_balance(contract).await.unwrap_or(0);
        let balance_eth = balance as f64 / 1e18;
        
        for change in &path.state_changes {
            match change {
                StateChange::SelfDestruct(_) => {
                    total_value += balance_eth;
                }
                StateChange::Transfer(amount, Some(token)) => {
                    let price = self.economic.get_price("", token, None).await;
                    total_value += (*amount as f64 / 1e18) * price;
                }
                StateChange::Transfer(amount, None) => {
                    total_value += *amount as f64 / 1e18;
                }
                StateChange::Delegatecall(_) => {
                    total_value += balance_eth * 0.5;
                }
                _ => {}
            }
        }
        
        total_value
    }
    
    /// Run guided fuzzing feedback loop
    async fn run_guided_fuzzing(
        &self,
        paths: &[ExploitPathWithValue],
        contract: &str,
    ) -> Vec<ExploitAttempt> {
        let mut all_attempts = Vec::new();
        
        for path_value in paths.iter().take(10) {
            let attempts = self.run_fuzzing_for_path(path_value, contract).await;
            all_attempts.extend(attempts);
        }
        
        all_attempts.sort_by(|a, b| b.score.total_cmp(&a.score));
        all_attempts.truncate(20);
        all_attempts
    }
    
    async fn run_fuzzing_for_path(
        &self,
        path_value: &ExploitPathWithValue,
        contract: &str,
    ) -> Vec<ExploitAttempt> {
        let mut engine = FeedbackLoopEngine::new(
            self.forensics.clone(),
            self.config.max_iterations,
            self.config.mutation_factor,
        );
        
        match engine.synthesize_exploits(vec![path_value.path.clone()], contract).await {
            Ok(attempts) => attempts,
            Err(e) => {
                debug!("Fuzzing failed for path: {}", e);
                Vec::new()
            }
        }
    }
    
    /// Cross-validate symbolic paths with concrete exploits
    async fn cross_validate_symbolic_concrete(
        &self,
        symbolic_paths: &[ControlFlowPath],
        concrete_exploits: &[ExploitAttempt],
    ) -> Vec<ValidatedExploit> {
        let mut validated = Vec::new();
        
        for sym_path in symbolic_paths {
            for exploit in concrete_exploits {
                if sym_path.entry_selector == exploit.selector {
                    let feasible = self.check_feasibility(sym_path, exploit).await;
                    
                    if feasible {
                        validated.push(ValidatedExploit {
                            path: SymbolicPath {
                                id: 0,
                                entry_selector: sym_path.entry_selector.clone(),
                                pc: 0,
                                stack: Vec::new(),
                                constraints: Vec::new(),
                                state_changes: Vec::new(),
                                is_feasible: true,
                                depth: 0,
                            },
                            exploit: exploit.clone(),
                            confidence: exploit.confidence as f64,
                            feasibility: true,
                        });
                    }
                }
            }
        }
        
        validated
    }
    
    async fn check_feasibility(&self, _sym_path: &ControlFlowPath, exploit: &ExploitAttempt) -> bool {
        // Simple feasibility check based on score
        exploit.score > 0.3 && exploit.success
    }
    
    /// Generate PoC for an exploit
    async fn generate_poc(&self, validated: &ValidatedExploit, contract: &str) -> Result<String> {
        let mut poc = String::new();
        
        poc.push_str("// Hexora Auto-Generated Proof of Concept\n");
        poc.push_str("// DO NOT USE ON MAINNET\n\n");
        
        poc.push_str("// SPDX-License-Identifier: MIT\n");
        poc.push_str("pragma solidity ^0.8.0;\n\n");
        
        poc.push_str("contract ExploitPoC {\n");
        poc.push_str(&format!("    address target = {};\n\n", contract));
        
        poc.push_str("    function execute() external {\n");
        poc.push_str(&format!("        // Selector: {}\n", validated.exploit.selector));
        poc.push_str("        (bool success, ) = target.call(\n");
        poc.push_str(&format!("            abi.encodeWithSignature(\"{}\"", validated.exploit.selector));
        
        if !validated.exploit.calldata.is_empty() {
            poc.push_str(&format!(",\n            {:#?}", validated.exploit.calldata));
        }
        poc.push_str(")\n        );\n");
        poc.push_str("        require(success, \"Exploit failed\");\n");
        poc.push_str("    }\n");
        poc.push_str("}\n");
        
        if validated.exploit.value > 0 {
            poc.push_str(&format!("\n// Attack requires {:.4} ETH\n", 
                validated.exploit.value as f64 / 1e18));
        }
        
        Ok(poc)
    }
    
    /// Analyze MEV opportunities
    async fn analyze_mev_opportunities(
        &self,
        paths: &[ExploitPathWithValue],
        _contract: &str,
    ) -> Vec<MevOpportunity> {
        let mut opportunities = Vec::new();
        
        for path in paths {
            if path.economic_value_eth > 0.01 {
                // Check for arbitrage opportunities
                if path.path.entry_selector.contains("swap") {
                    opportunities.push(MevOpportunity {
                        mev_type: "ARBITRAGE".to_string(),
                        estimated_profit_eth: path.economic_value_eth * 0.7,
                        competition_score: 0.5,
                        suggested_tip_bps: 1000,
                    });
                }
                
                // Check for liquidation opportunities
                if path.path.entry_selector.contains("liquidate") {
                    opportunities.push(MevOpportunity {
                        mev_type: "LIQUIDATION".to_string(),
                        estimated_profit_eth: path.economic_value_eth * 0.9,
                        competition_score: 0.3,
                        suggested_tip_bps: 500,
                    });
                }
            }
        }
        
        opportunities
    }
    
    /// Generate summary report
    fn generate_summary(
        &self,
        paths: &[ExploitPathWithValue],
        validated: &[ValidatedExploit],
        exploits: &[ExploitAttempt],
    ) -> OffensiveSummary {
        let total_economic_value: f64 = paths.iter().map(|p| p.economic_value_eth).sum();
        let high_value_paths = paths.iter().filter(|p| p.economic_value_eth > 1.0).count();
        let critical_exploits = exploits.iter().filter(|e| e.score > 0.8 && e.success).count();
        let max_confidence = validated.iter().map(|v| v.confidence).fold(0.0, f64::max);
        
        let mut recommended_actions = Vec::new();
        
        if critical_exploits > 0 {
            recommended_actions.push("URGENT: Patch immediately - Critical exploit detected".to_string());
        }
        
        if total_economic_value > 10.0 {
            recommended_actions.push("HIGH: Large economic exposure - Review access controls".to_string());
        }
        
        if max_confidence > 0.9 {
            recommended_actions.push("MEDIUM: High-confidence exploit path - Verify implementation".to_string());
        }
        
        OffensiveSummary {
            total_paths_analyzed: paths.len(),
            high_value_paths,
            critical_exploits,
            total_economic_value_eth: total_economic_value,
            max_confidence,
            recommended_actions,
        }
    }
    
    /// Convert to report format
    fn convert_to_report_paths(&self, paths: &[ExploitPathWithValue]) -> Vec<ExploitPath> {
        paths.iter().map(|p| ExploitPath {
            entry_selector: p.path.entry_selector.clone(),
            probability: p.probability,
            economic_value_eth: p.economic_value_eth,
            required_conditions: p
                .path
                .conditions
                .iter()
                .map(|condition| format!("{condition:?}"))
                .collect(),
            state_changes: p
                .path
                .state_changes
                .iter()
                .map(|change| format!("{change:?}"))
                .collect(),
            poc_calldata: String::new(),
        }).collect()
    }
    
    /// Convert symbolic path to ControlFlowPath
    fn convert_symbolic_to_controlflow(&self, sym_path: &SymbolicPath, selector: &[u8; 4]) -> ControlFlowPath {
        let mut conditions = Vec::new();
        for constraint in &sym_path.constraints {
            if constraint.condition.contains("msg.sender") {
                conditions.push(Condition::CallerEq(constraint.condition.clone()));
            } else if constraint.condition.contains("msg.value") {
                conditions.push(Condition::ValueGt(0));
            }
        }
        
        let mut state_changes = Vec::new();
        for change in &sym_path.state_changes {
            match change {
                SymbolicStateChange::StorageWrite(slot, _) => {
                    state_changes.push(StateChange::StorageWrite(*slot, "modified".to_string()));
                }
                SymbolicStateChange::Call(target, _, _) => {
                    state_changes.push(StateChange::Call(target.clone(), 0, vec![]));
                }
                SymbolicStateChange::Delegatecall(target) => {
                    state_changes.push(StateChange::Delegatecall(target.clone()));
                }
                SymbolicStateChange::SelfDestruct(target) => {
                    state_changes.push(StateChange::SelfDestruct(target.clone()));
                }
                _ => {}
            }
        }
        
        ControlFlowPath {
            entry_selector: hex::encode(selector),
            basic_blocks: Vec::new(),
            conditions,
            state_changes,
            gas_estimate: 100000,
        }
    }
}

// ============================================================
// LEGACY ENGINE (mantido para compatibilidade)
// ============================================================

#[derive(Clone)]
pub struct OffensiveEngine {
    config: OffensiveConfig,
    forensics: ForensicsEngine,
}

impl OffensiveEngine {
    pub fn new(config: OffensiveConfig, forensics: ForensicsEngine) -> Self {
        Self { config, forensics }
    }

    pub async fn analyze(&self, contract: &str, analysis: &BytecodeAnalysis) -> Result<OffensiveReport> {
        let hexora_engine = HexoraOffensiveEngine::new(self.config.clone(), self.forensics.clone());
        hexora_engine.analyze_full(contract, analysis).await
    }
}

// ============================================================
// CONVENIENCE FUNCTIONS
// ============================================================

/// Quick analysis with default config
pub async fn quick_analyze(
    contract: &str,
    analysis: &BytecodeAnalysis,
    forensics: ForensicsEngine,
) -> Result<OffensiveReport> {
    let config = OffensiveConfig::default();
    let engine = HexoraOffensiveEngine::new(config, forensics);
    engine.analyze_full(contract, analysis).await
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_default() {
        let config = OffensiveConfig::default();
        assert!(config.enable_symbolic);
        assert!(config.enable_fuzzing);
        assert!(config.max_paths > 0);
    }
    
    #[test]
    fn test_offensive_engine_creation() {
        let forensics = ForensicsEngine::new(String::new(), Default::default());
        let engine = HexoraOffensiveEngine::new(OffensiveConfig::default(), forensics);
        assert!(engine.symbolic.lock().is_ok());
    }
}
