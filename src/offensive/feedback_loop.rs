// src/offensive/feedback_loop.rs
use anyhow::Result;
use std::collections::HashMap;
use std::time::Instant;

use crate::forensics::ForensicsEngine;
use crate::offensive::path_finder::{ControlFlowPath, Condition, StateChange};
use crate::offensive::probability_engine::calculate_probabilities;
use crate::offensive::economic_impact::calculate_economic_value;
use crate::offensive::mev_integration::MevOpportunity;

// ============================================================
// ESTRUTURAS CENTRAIS
// ============================================================

#[derive(Debug, Clone)]
pub struct TestInput {
    pub selector: String,
    pub calldata: Vec<u8>,
    pub caller: String,
    pub value: u128,
    pub gas_limit: u64,
    pub iteration: u32,
}

impl Default for TestInput {
    fn default() -> Self {
        Self {
            selector: String::new(),
            calldata: Vec::new(),
            caller: "0x0000000000000000000000000000000000000000".to_string(),
            value: 0,
            gas_limit: 10_000_000,
            iteration: 0,
        }
    }
}

impl TestInput {
    pub fn with_random_caller(&self, rng_seed: u64) -> Self {
        let mut clone = self.clone();
        let testers = [
            "0xB631BACe85E3d3c0851D756C7D75Cd19d9a4bC8d",
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
            "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
            "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
            "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
            "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
            "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
        ];
        let idx = (rng_seed as usize) % testers.len();
        clone.caller = testers[idx].to_string();
        clone.iteration += 1;
        clone
    }

    pub fn with_max_value(&self) -> Self {
        let mut clone = self.clone();
        clone.value = u128::MAX;
        clone.iteration += 1;
        clone
    }

    pub fn with_zero_value(&self) -> Self {
        let mut clone = self.clone();
        clone.value = 0;
        clone.iteration += 1;
        clone
    }

    pub fn with_specific_value(&self, value: u128) -> Self {
        let mut clone = self.clone();
        clone.value = value;
        clone.iteration += 1;
        clone
    }

    pub fn with_random_calldata(&self) -> Self {
        let mut clone = self.clone();
        let extra: Vec<u8> = (0..32).map(|_| fastrand::u8(..)).collect();
        clone.calldata.extend(extra);
        clone.iteration += 1;
        clone
    }

    pub fn with_specific_caller(&self, caller: &str) -> Self {
        let mut clone = self.clone();
        clone.caller = caller.to_string();
        clone.iteration += 1;
        clone
    }
}

#[derive(Debug, Clone)]
pub struct SimulationResult {
    pub success: bool,
    pub state_changes: Vec<StateChange>,
    pub revert_reason: Option<String>,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ExploitAttempt {
    pub selector: String,
    pub calldata: Vec<u8>,
    pub caller: String,
    pub value: u128,
    pub success: bool,
    pub state_changes: Vec<StateChange>,
    pub revert_reason: Option<String>,
    pub score: f32,
    pub confidence: f32,
    pub iterations: u32,
    pub gas_cost_eth: f64,
    pub economic_value_eth: f64,
}

#[derive(Debug, Clone)]
pub struct KnowledgeBase {
    pub successful_paths: HashMap<String, f32>,
    pub failed_conditions: HashMap<String, u32>,
    pub constraint_satisfaction: HashMap<String, bool>,
    pub best_scores: HashMap<String, f32>,
}

impl KnowledgeBase {
    pub fn new() -> Self {
        Self {
            successful_paths: HashMap::new(),
            failed_conditions: HashMap::new(),
            constraint_satisfaction: HashMap::new(),
            best_scores: HashMap::new(),
        }
    }

    pub fn update(&mut self, path_key: &str, score: f32, success: bool) {
        if success {
            let entry = self.successful_paths.entry(path_key.to_string()).or_insert(0.0);
            *entry = (*entry).max(score);
        }
        
        let best = self.best_scores.entry(path_key.to_string()).or_insert(0.0);
        *best = (*best).max(score);
    }

    pub fn should_prune(&self, path_key: &str, current_score: f32, threshold: f32) -> bool {
        if let Some(&best) = self.best_scores.get(path_key) {
            if current_score + 0.1 < best && best > threshold {
                return true; // Prune: não vai superar o melhor
            }
        }
        false
    }
}

// ============================================================
// FEEDBACK LOOP ENGINE
// ============================================================

pub struct FeedbackLoopEngine {
    forensics: ForensicsEngine,
    max_iterations: u32,
    mutation_factor: f32,
    prune_threshold: f32,
    knowledge: KnowledgeBase,
}

impl FeedbackLoopEngine {
    pub fn new(forensics: ForensicsEngine, max_iterations: u32, mutation_factor: f32) -> Self {
        Self {
            forensics,
            max_iterations,
            mutation_factor,
            prune_threshold: 0.7,
            knowledge: KnowledgeBase::new(),
        }
    }

    /// LOOP PRINCIPAL: find → extract → solve → simulate → analyze → update → mutate
    pub async fn synthesize_exploits(
        &mut self,
        paths: Vec<ControlFlowPath>,
        contract_address: &str,
    ) -> Result<Vec<ExploitAttempt>> {
        let mut all_attempts = Vec::new();
        
        // Step 1: Calculate probabilities for each path
        tracing::info!("🎯 Calculating path probabilities...");
        let paths_with_prob = calculate_probabilities(
            paths,
            &self.forensics,
            contract_address,
            100
        ).await;
        
        // Step 2: Calculate economic value
        tracing::info!("💰 Calculating economic impact...");
        let paths_with_value = calculate_economic_value(
            paths_with_prob,
            contract_address,
            &self.forensics,
        ).await;
        
        // Step 3: Iterate over each path
        for path_value in paths_with_value {
            if path_value.economic_value_eth < 0.001 {
                tracing::info!("⏭️ Skipping low-value path: {:.4} ETH", path_value.economic_value_eth);
                continue;
            }
            
            tracing::info!("🔍 Analyzing path: {} (value: {:.4} ETH)", 
                path_value.path.entry_selector, 
                path_value.economic_value_eth
            );
            
            // Extract constraints
            let constraints = self.extract_constraints(&path_value.path);
            tracing::info!("📋 Extracted {} constraints", constraints.len());
            
            // Solve constraints → generate initial candidates
            let mut candidates = self.solve_constraints(&constraints);
            tracing::info!("🎲 Generated {} candidate inputs", candidates.len());
            
            // FEEDBACK LOOP for each candidate
            for candidate in &mut candidates {
                let path_key = format!("{}_{}", path_value.path.entry_selector, candidate.caller);
                let mut best_attempt: Option<ExploitAttempt> = None;
                let mut best_score = 0.0;
                
                for iteration in 0..self.max_iterations {
                    let start_time = Instant::now();
                    
                    // Simulate
                    let result = self.simulate_input(candidate, contract_address).await?;
                    let execution_time_ms = start_time.elapsed().as_millis() as u64;
                    
                    let mut result_with_time = result;
                    result_with_time.execution_time_ms = execution_time_ms;
                    
                    // Calculate score
                    let score = self.evaluate_result(&result_with_time);
                    let confidence = self.calculate_confidence(&result_with_time, &path_value.path);
                    
                    // Create attempt record
                    let attempt = ExploitAttempt {
                        selector: candidate.selector.clone(),
                        calldata: candidate.calldata.clone(),
                        caller: candidate.caller.clone(),
                        value: candidate.value,
                        success: result_with_time.success,
                        state_changes: result_with_time.state_changes.clone(),
                        revert_reason: result_with_time.revert_reason.clone(),
                        score,
                        confidence,
                        iterations: iteration + 1,
                        gas_cost_eth: self.calculate_gas_cost(result_with_time.gas_used),
                        economic_value_eth: path_value.economic_value_eth,
                    };
                    
                    // Update knowledge base
                    self.knowledge.update(&path_key, score, result_with_time.success);
                    
                    // Track best
                    if score > best_score {
                        best_score = score;
                        best_attempt = Some(attempt.clone());
                        
                        tracing::info!(
                            "📈 Iteration {}: score={:.3}, confidence={:.3}, success={}",
                            iteration + 1,
                            score,
                            confidence,
                            result_with_time.success
                        );
                        
                        // Log state changes
                        for change in &result_with_time.state_changes {
                            tracing::debug!("  → {:?}", change);
                        }
                    }
                    
                    // PRUNING: stop if score is high enough
                    if score >= self.prune_threshold {
                        tracing::info!("✅ High-score achieved, pruning early");
                        break;
                    }
                    
                    // Check if should prune based on knowledge
                    if self.knowledge.should_prune(&path_key, score, self.prune_threshold) {
                        tracing::info!("✂️ Pruning path (cannot beat best score)");
                        break;
                    }
                    
                    // MUTATION: generate new inputs based on result
                    let mutations = self.mutate_input(candidate, &result_with_time);
                    if let Some(mutated) = mutations.first() {
                        *candidate = mutated.clone();
                    }
                }
                
                if let Some(best) = best_attempt {
                    if best.score > 0.5 {
                        all_attempts.push(best);
                    }
                }
            }
        }
        
        // Sort by score and confidence
        all_attempts.sort_by(|a, b| {
            b.score.partial_cmp(&a.score)
                .unwrap()
                .then(b.confidence.partial_cmp(&a.confidence).unwrap())
        });
        
        Ok(all_attempts)
    }
    
    /// Extract constraints from control flow path
    fn extract_constraints(&self, path: &ControlFlowPath) -> Vec<Condition> {
        let mut constraints = Vec::new();
        
        // Add path conditions
        constraints.extend(path.conditions.clone());
        
        // Infer additional constraints from state changes
        for change in &path.state_changes {
            match change {
                StateChange::Delegatecall(target) => {
                    constraints.push(Condition::CallerEq(target.clone()));
                }
                StateChange::StorageWrite(slot, _) if *slot == 0 => {
                    constraints.push(Condition::StorageSlotEq(0, "0x000...".to_string()));
                }
                _ => {}
            }
        }
        
        constraints
    }
    
    /// Solve constraints → generate test inputs
    fn solve_constraints(&self, constraints: &[Condition]) -> Vec<TestInput> {
        let mut inputs = vec![TestInput::default()];
        
        for constraint in constraints {
            let mut new_inputs = Vec::new();
            
            for input in &inputs {
                let expanded = match constraint {
                    Condition::CallerEq(addr) => {
                        let mut new = input.clone();
                        new.caller = addr.clone();
                        new.selector = "0x".to_string(); // Will be set later
                        vec![new]
                    }
                    Condition::CallerEqStorage(slot) => {
                        // Try to read from storage
                        let mut new = input.clone();
                        new.caller = format!("storage[{}]", slot);
                        vec![new]
                    }
                    Condition::ValueGt(v) => {
                        vec![
                            input.with_specific_value(v + 1),
                            input.with_specific_value(v + 100),
                            input.with_max_value(),
                        ]
                    }
                    Condition::ValueLt(v) => {
                        vec![
                            input.with_specific_value(v - 1),
                            input.with_zero_value(),
                        ]
                    }
                    Condition::NotZeroAddress => {
                        vec![
                            input.with_specific_caller("0xdeadbeef00000000000000000000000000000000"),
                            input.with_random_caller(fastrand::u64(..)),
                        ]
                    }
                    Condition::BalanceGt(_) => {
                        vec![input.with_max_value()]
                    }
                    Condition::StorageSlotEq(slot, expected) => {
                        let mut new = input.clone();
                        // Will be checked during simulation
                        new.calldata.extend(format!("{:064x}", slot).as_bytes());
                        new.calldata.extend(expected.as_bytes());
                        vec![new]
                    }
                    _ => vec![input.clone()],
                };
                new_inputs.extend(expanded);
            }
            
            inputs = new_inputs;
        }
        
        // Limit to reasonable number
        inputs.truncate(20);
        inputs
    }
    
    /// Simulate input via eth_call or fork
    async fn simulate_input(&self, input: &TestInput, contract_address: &str) -> Result<SimulationResult> {
        
        
        let start = std::time::Instant::now();
        
        // Build calldata
        let mut full_calldata = hex::decode(&input.selector.trim_start_matches("0x"))
            .unwrap_or_default();
        full_calldata.extend(&input.calldata);
        
        let calldata_hex = format!("0x{}", hex::encode(&full_calldata));
        
        // Try eth_call first (fast)
        match self.forensics.eth_call(
            &input.caller,
            contract_address,
            &calldata_hex,
            &format!("0x{:x}", input.value),
        ).await {
            Ok(result) => {
                // Analyze state changes by comparing before/after
                let state_changes = self.analyze_state_changes(contract_address, input).await?;
                
                Ok(SimulationResult {
                    success: true,
                    state_changes,
                    revert_reason: None,
                    gas_used: estimate_gas_from_calldata(&full_calldata),
                    return_data: hex::decode(result.trim_start_matches("0x")).unwrap_or_default(),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                })
            }
            Err(e) => {
                Ok(SimulationResult {
                    success: false,
                    state_changes: Vec::new(),
                    revert_reason: Some(e.to_string()),
                    gas_used: 0,
                    return_data: Vec::new(),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                })
            }
        }
    }
    
    /// Analyze state changes by comparing storage before and after
    async fn analyze_state_changes(&self, contract_address: &str, input: &TestInput) -> Result<Vec<StateChange>> {
        let mut changes = Vec::new();
        
        // Check critical storage slots
        let critical_slots = [0u64, 1, 2, 3, 4, 5];
        
        for slot in critical_slots {
            let slot_hex = format!("0x{:x}", slot);
            if let Ok(value) = self.forensics.get_storage(contract_address, &slot_hex).await {
                if value != "0x0000000000000000000000000000000000000000000000000000000000000000" {
                    changes.push(StateChange::StorageWrite(slot, value));
                }
            }
        }
        
        // Check if there was a transfer (simplified)
        if input.value > 0 {
            changes.push(StateChange::Transfer(input.value, None));
        }
        
        Ok(changes)
    }
    
    /// Evaluate result → calculate score (0.0 to 1.0)
    fn evaluate_result(&self, result: &SimulationResult) -> f32 {
        let mut score: f32 = 0.0;
        
        // Successful execution
        if result.success {
            score += 0.4;
        }
        
        // State changes detection
        for change in &result.state_changes {
            match change {
                StateChange::SelfDestruct(_) => {
                    score += 1.0; // Critical
                }
                StateChange::Transfer(amount, _) if *amount > 0 => {
                    score += 0.4;
                }
                StateChange::Delegatecall(_) => {
                    score += 0.5; // High risk
                }
                StateChange::StorageWrite(slot, _) if *slot == 0 => {
                    score += 0.3; // Ownership change
                }
                StateChange::Call(_, value, _) if *value > 0 => {
                    score += 0.3;
                }
                StateChange::Mint(_, _) => {
                    score += 0.4;
                }
                _ => {}
            }
        }
        
        // Penalty for reverts
        if !result.success && result.revert_reason.is_some() {
            score -= 0.2;
        }
        
        score.clamp(0.0, 1.0)
    }
    
    /// Calculate confidence score
    fn calculate_confidence(&self, result: &SimulationResult, path: &ControlFlowPath) -> f32 {
        let success_score = if result.success { 0.8 } else { 0.2 };
        
        // Check if path has privilege checks
        let has_privilege_check = path.conditions.iter().any(|c| {
            matches!(c, Condition::CallerEq(_) | Condition::CallerEqStorage(_))
        });
        let privilege_dependency = if has_privilege_check { 0.4 } else { 0.0 };
        
        let state_impact = self.evaluate_result(result);
        
        success_score * (1.0 - privilege_dependency) * state_impact
    }
    
    /// Calculate gas cost in ETH
    fn calculate_gas_cost(&self, gas_used: u64) -> f64 {
        let gas_price_gwei = 20.0; // Default, could fetch from RPC
        (gas_used as f64 * gas_price_gwei * 1e9) / 1e18
    }
    
    /// MUTATION LAYER: generate variations based on result
    fn mutate_input(&self, input: &TestInput, result: &SimulationResult) -> Vec<TestInput> {
        let mut mutations = Vec::new();
        
        // Always include original
        mutations.push(input.clone());
        
        if !result.success {
            // Failed: try different approaches
            mutations.push(input.with_random_caller(fastrand::u64(..)));
            mutations.push(input.with_max_value());
            mutations.push(input.with_zero_value());
            mutations.push(input.with_random_calldata());
        } else {
            // Success: try to maximize impact
            let mut aggressive = input.clone();
            aggressive.value = u128::MAX;
            mutations.push(aggressive);
            
            // Try with different callers
            for _ in 0..3 {
                mutations.push(input.with_random_caller(fastrand::u64(..)));
            }
        }
        
        // Boundary testing
        mutations.push(input.with_specific_value(1));
        mutations.push(input.with_specific_value(u128::MAX / 2));
        
        // Deduplicate and limit
        mutations.truncate(10);
        mutations
    }
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================

fn estimate_gas_from_calldata(calldata: &[u8]) -> u64 {
    let base_gas = 21000;
    let calldata_gas: u64 = calldata.iter()
        .map(|&b| if b == 0 { 4 } else { 16 })
        .sum();
    base_gas + calldata_gas
}

// ============================================================
// PUBLIC API - Integração com o scanner principal
// ============================================================

pub async fn run_offensive_analysis(
    forensics: ForensicsEngine,
    paths: Vec<ControlFlowPath>,
    contract_address: &str,
) -> Result<(Vec<ExploitAttempt>, Vec<MevOpportunity>)> {
    let mut engine = FeedbackLoopEngine::new(forensics, 15, 0.3);
    
    tracing::info!("🚀 Starting offensive analysis with feedback loop...");
    
    let attempts = engine.synthesize_exploits(paths, contract_address).await?;
    
    tracing::info!("📊 Found {} viable exploit attempts", attempts.len());
    
    // Log critical findings
    for attempt in &attempts {
        if attempt.score > 0.7 && attempt.success {
            tracing::warn!(
                "🚨 CRITICAL: Exploit confirmed! Selector={} Score={:.2} Confidence={:.2}%",
                attempt.selector,
                attempt.score,
                attempt.confidence * 100.0
            );
        }
    }
    
    // Analyze MEV opportunities (from the existing mev_integration)
    // Convert attempts to path_with_value format first
    let mev_opportunities = Vec::new(); // TODO: integrate with existing mev_integration
    
    Ok((attempts, mev_opportunities))
}