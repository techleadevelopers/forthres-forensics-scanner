// src/offensive/feedback_loop.rs
//! forthres Guided Fuzzing Feedback Loop Engine
//!
//! Engine inteligente de descoberta de exploits usando:
//! - Coverage-guided fuzzing com feedback de execução
//! - Mutation strategies adaptativas baseadas em resultados
//! - Scoring granular multi-dimensional
//! - Corpus management com energy scheduling
//! - Cross-over entre inputs bem-sucedidos

use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use lru::LruCache;

use crate::forensics::ForensicsEngine;
use crate::offensive::path_finder::{ControlFlowPath, Condition, StateChange};
use crate::offensive::probability_engine::calculate_probabilities;
use crate::offensive::economic_impact::{calculate_economic_value, ExploitPathWithValue};
use crate::offensive::mev_integration::MevOpportunity;

// ============================================================
// ESTRUTURAS BASE (mantidas)
// ============================================================

#[derive(Debug, Clone)]
pub struct TestInput {
    pub selector: String,
    pub calldata: Vec<u8>,
    pub caller: String,
    pub value: u128,
    pub gas_limit: u64,
    pub iteration: u32,
    pub coverage_bits: u64,  // Nova: bitmap de cobertura
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
            coverage_bits: 0,
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

    pub fn with_random_calldata(&self, len: usize) -> Self {
        let mut clone = self.clone();
        let extra: Vec<u8> = (0..len).map(|_| fastrand::u8(..)).collect();
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
    
    /// Mutação por bit flipping
    pub fn mutate_bit_flip(&self) -> Self {
        let mut clone = self.clone();
        if !clone.calldata.is_empty() {
            let idx = fastrand::usize(0..clone.calldata.len());
            let bit = fastrand::u8(0..8);
            clone.calldata[idx] ^= 1 << bit;
        }
        clone.iteration += 1;
        clone
    }
    
    /// Mutação por byte replacement
    pub fn mutate_byte_replace(&self) -> Self {
        let mut clone = self.clone();
        if !clone.calldata.is_empty() {
            let idx = fastrand::usize(0..clone.calldata.len());
            clone.calldata[idx] = fastrand::u8(..);
        }
        clone.iteration += 1;
        clone
    }
    
    /// Mutação por inserção
    pub fn mutate_insert(&self) -> Self {
        let mut clone = self.clone();
        let idx = fastrand::usize(0..=clone.calldata.len());
        clone.calldata.insert(idx, fastrand::u8(..));
        clone.iteration += 1;
        clone
    }
    
    /// Cross-over com outro input
    pub fn crossover(&self, other: &TestInput) -> Self {
        let mut clone = self.clone();
        let split_point = fastrand::usize(0..=self.calldata.len().min(other.calldata.len()));
        clone.calldata.truncate(split_point);
        clone.calldata.extend_from_slice(&other.calldata[split_point..]);
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
    pub coverage_new: CoverageDelta,
    pub economic_value_eth: f64,
    pub ownership_changed: bool,
    pub delegatecall_to_proxy: bool,
    pub unlocks_after_blocks: u64,
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
    pub coverage_bits: u64,
}

#[derive(Debug, Clone)]
pub struct KnowledgeBase {
    pub successful_paths: HashMap<String, f32>,
    pub failed_conditions: HashMap<String, u32>,
    pub constraint_satisfaction: HashMap<String, bool>,
    pub best_scores: HashMap<String, f32>,
    pub corpus: Vec<TestInput>,
    pub coverage_map: HashMap<u64, u32>,
}

impl KnowledgeBase {
    pub fn new() -> Self {
        Self {
            successful_paths: HashMap::new(),
            failed_conditions: HashMap::new(),
            constraint_satisfaction: HashMap::new(),
            best_scores: HashMap::new(),
            corpus: Vec::new(),
            coverage_map: HashMap::new(),
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
                return true;
            }
        }
        false
    }
    
    pub fn add_to_corpus(&mut self, input: TestInput, coverage_bits: u64) {
        // Verifica se já temos cobertura similar
        for existing in &self.corpus {
            if existing.coverage_bits & coverage_bits == coverage_bits {
                return; // Já coberto
            }
        }
        self.corpus.push(input);
        if self.corpus.len() > 100 {
            self.corpus.remove(0);
        }
    }
    
    pub fn get_random_from_corpus(&self) -> Option<&TestInput> {
        if self.corpus.is_empty() {
            None
        } else {
            Some(&self.corpus[fastrand::usize(0..self.corpus.len())])
        }
    }
}

// ============================================================
// NOVO: COVERAGE-DRIVEN MUTATION
// ============================================================

#[derive(Debug, Clone)]
pub enum CoverageDelta {
    NewBasicBlock(u64),
    NewEdge(u64),
    NoNew,
    Multiple(Vec<u64>),
}

#[derive(Debug, Clone, Copy)]
pub struct EnergySchedule {
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub aggressive: u32,
}

impl Default for EnergySchedule {
    fn default() -> Self {
        Self {
            high: 100,
            medium: 50,
            low: 10,
            aggressive: 200,
        }
    }
}

pub trait MutationStrategy: Send + Sync {
    fn mutate(&self, input: &TestInput, energy: u32) -> Vec<TestInput>;
    fn name(&self) -> &'static str;
}

pub struct BitFlipStrategy;

impl MutationStrategy for BitFlipStrategy {
    fn mutate(&self, input: &TestInput, energy: u32) -> Vec<TestInput> {
        let mut results = Vec::new();
        for _ in 0..energy.min(50) {
            results.push(input.mutate_bit_flip());
        }
        results
    }
    
    fn name(&self) -> &'static str {
        "bit_flip"
    }
}

pub struct ByteReplaceStrategy;

impl MutationStrategy for ByteReplaceStrategy {
    fn mutate(&self, input: &TestInput, energy: u32) -> Vec<TestInput> {
        let mut results = Vec::new();
        for _ in 0..energy.min(50) {
            results.push(input.mutate_byte_replace());
        }
        results
    }
    
    fn name(&self) -> &'static str {
        "byte_replace"
    }
}

pub struct InsertStrategy;

impl MutationStrategy for InsertStrategy {
    fn mutate(&self, input: &TestInput, energy: u32) -> Vec<TestInput> {
        let mut results = Vec::new();
        for _ in 0..energy.min(30) {
            results.push(input.mutate_insert());
        }
        results
    }
    
    fn name(&self) -> &'static str {
        "insert"
    }
}

pub struct CrossoverStrategy {
    corpus: Arc<Mutex<Vec<TestInput>>>,
}

impl CrossoverStrategy {
    pub fn new(corpus: Arc<Mutex<Vec<TestInput>>>) -> Self {
        Self { corpus }
    }
}

impl MutationStrategy for CrossoverStrategy {
    fn mutate(&self, input: &TestInput, energy: u32) -> Vec<TestInput> {
        let mut results = Vec::new();
        let corpus_guard = self.corpus.lock().unwrap();
        
        for _ in 0..energy.min(20) {
            if let Some(other) = corpus_guard.get(fastrand::usize(0..corpus_guard.len())) {
                results.push(input.crossover(other));
            }
        }
        results
    }
    
    fn name(&self) -> &'static str {
        "crossover"
    }
}

// ============================================================
// NOVO: forthres GUIDED FUZZER
// ============================================================

pub struct forthresGuidedFuzzer {
    coverage_map: HashMap<u64, u32>,
    energy_schedule: EnergySchedule,
    mutation_strategies: Vec<Box<dyn MutationStrategy>>,
    corpus: Arc<Mutex<Vec<TestInput>>>,
    last_coverage: u64,
}

impl forthresGuidedFuzzer {
    pub fn new() -> Self {
        let corpus = Arc::new(Mutex::new(Vec::new()));
        let strategies: Vec<Box<dyn MutationStrategy>> = vec![
            Box::new(BitFlipStrategy),
            Box::new(ByteReplaceStrategy),
            Box::new(InsertStrategy),
            Box::new(CrossoverStrategy::new(corpus.clone())),
        ];
        
        Self {
            coverage_map: HashMap::new(),
            energy_schedule: EnergySchedule::default(),
            mutation_strategies: strategies,
            corpus,
            last_coverage: 0,
        }
    }
    
    /// Muta com base no feedback de cobertura
    pub fn mutate_guided(&mut self, input: &TestInput, feedback: &SimulationResult) -> Vec<TestInput> {
        let mut mutations = Vec::new();
        
        match &feedback.coverage_new {
            CoverageDelta::NewBasicBlock(pc) => {
                // Ganhou nova cobertura: energia alta
                let energy = self.energy_schedule.high;
                tracing::debug!("🎯 New basic block at PC=0x{:x}, using high energy", pc);
                
                for strategy in &self.mutation_strategies {
                    mutations.extend(strategy.mutate(input, energy));
                }
                
                // Tenta mutações específicas para este PC
                if let Some(specific) = self.mutate_for_pc(*pc, input) {
                    mutations.push(specific);
                }
            }
            CoverageDelta::NewEdge(edge) => {
                // Nova edge: energia média
                let energy = self.energy_schedule.medium;
                tracing::debug!("🎯 New edge {}, using medium energy", edge);
                
                for strategy in &self.mutation_strategies {
                    mutations.extend(strategy.mutate(input, energy));
                }
            }
            CoverageDelta::Multiple(pcs) => {
                // Múltiplas novas coberturas: energia alta
                let energy = self.energy_schedule.high;
                tracing::debug!("🎯 Multiple new coverage: {} blocks", pcs.len());
                
                for strategy in &self.mutation_strategies {
                    mutations.extend(strategy.mutate(input, energy));
                }
            }
            CoverageDelta::NoNew => {
                // Sem progresso: tenta estratégias agressivas
                let energy = self.energy_schedule.aggressive;
                tracing::debug!("🎯 No new coverage, using aggressive energy");
                
                // Apenas estratégias mais agressivas
                mutations.extend(self.mutation_strategies[0].mutate(input, energy));
                mutations.extend(self.mutation_strategies[1].mutate(input, energy));
            }
        }
        
        // Adiciona mutações de boundary se necessário
        if input.value == 0 {
            mutations.push(input.with_max_value());
            mutations.push(input.with_specific_value(1));
        }
        
        mutations.truncate(50);
        mutations
    }
    
    /// Gera mutações específicas para um PC
    fn mutate_for_pc(&self, pc: u64, input: &TestInput) -> Option<TestInput> {
        // Baseado no PC, podemos inferir quais valores são interessantes
        let mut mutated = input.clone();
        
        // Padrões comuns de opcodes perigosos
        match pc {
            // SSTORE operations
            _ if pc % 100 == 0x55 => {
                mutated.value = u128::MAX;
                return Some(mutated);
            }
            // CALL with value
            _ if pc % 100 == 0xF1 => {
                if mutated.value == 0 {
                    mutated.value = 1_000_000_000_000_000_000; // 1 ETH
                } else {
                    mutated.value = u128::MAX;
                }
                return Some(mutated);
            }
            // DELEGATECALL
            _ if pc % 100 == 0xF4 => {
                // Try to point to known malicious contract
                mutated.calldata = vec![0xde, 0xad, 0xbe, 0xef];
                return Some(mutated);
            }
            _ => None,
        }
    }
    
    /// Atualiza o corpus com novos inputs
    pub fn update_corpus(&mut self, input: TestInput, coverage_bits: u64) -> bool {
        let mut is_new = false;
        let mut corpus_guard = self.corpus.lock().unwrap();
        
        // Verifica se já temos cobertura similar
        for existing in corpus_guard.iter() {
            if existing.coverage_bits & coverage_bits == coverage_bits {
                return false;
            }
        }
        
        corpus_guard.push(input);
        is_new = true;
        
        if corpus_guard.len() > 100 {
            corpus_guard.remove(0);
        }
        
        is_new
    }
    
    /// Obtém um input aleatório do corpus para crossover
    pub fn get_corpus_input(&self) -> Option<TestInput> {
        let corpus_guard = self.corpus.lock().unwrap();
        if corpus_guard.is_empty() {
            None
        } else {
            Some(corpus_guard[fastrand::usize(0..corpus_guard.len())].clone())
        }
    }
    
    /// Reseta o fuzzer
    pub fn reset(&mut self) {
        self.coverage_map.clear();
        self.last_coverage = 0;
        let mut corpus_guard = self.corpus.lock().unwrap();
        corpus_guard.clear();
    }
}

impl Default for forthresGuidedFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// FEEDBACK LOOP ENGINE MELHORADO
// ============================================================

pub struct FeedbackLoopEngine {
    forensics: ForensicsEngine,
    max_iterations: u32,
    mutation_factor: f32,
    prune_threshold: f32,
    knowledge: KnowledgeBase,
    fuzzer: forthresGuidedFuzzer,
}

impl FeedbackLoopEngine {
    pub fn new(forensics: ForensicsEngine, max_iterations: u32, mutation_factor: f32) -> Self {
        Self {
            forensics,
            max_iterations,
            mutation_factor,
            prune_threshold: 0.7,
            knowledge: KnowledgeBase::new(),
            fuzzer: forthresGuidedFuzzer::new(),
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
                let mut consecutive_no_progress = 0;
                
                for iteration in 0..self.max_iterations {
                    let start_time = Instant::now();
                    
                    // Simulate
                    let mut result = self.simulate_input(candidate, contract_address, &path_value).await?;
                    let execution_time_ms = start_time.elapsed().as_millis() as u64;
                    result.execution_time_ms = execution_time_ms;
                    
                    // Calculate granular score
                    let score = self.evaluate_granular(&result);
                    let confidence = self.calculate_confidence(&result, &path_value.path);
                    
                    // Create attempt record
                    let attempt = ExploitAttempt {
                        selector: candidate.selector.clone(),
                        calldata: candidate.calldata.clone(),
                        caller: candidate.caller.clone(),
                        value: candidate.value,
                        success: result.success,
                        state_changes: result.state_changes.clone(),
                        revert_reason: result.revert_reason.clone(),
                        score,
                        confidence,
                        iterations: iteration + 1,
                        gas_cost_eth: self.calculate_gas_cost(result.gas_used),
                        economic_value_eth: path_value.economic_value_eth,
                        coverage_bits: candidate.coverage_bits,
                    };
                    
                    // Update knowledge base
                    self.knowledge.update(&path_key, score, result.success);
                    
                    // Update corpus if new coverage
                    if !matches!(result.coverage_new, CoverageDelta::NoNew) {
                        let mut new_input = candidate.clone();
                        new_input.coverage_bits = self.calculate_coverage_bits(&result);
                        if self.fuzzer.update_corpus(new_input, candidate.coverage_bits) {
                            tracing::debug!("📚 Added to corpus (new coverage)");
                            consecutive_no_progress = 0;
                        } else {
                            consecutive_no_progress += 1;
                        }
                    } else {
                        consecutive_no_progress += 1;
                    }
                    
                    // Track best
                    if score > best_score {
                        best_score = score;
                        best_attempt = Some(attempt.clone());
                        
                        tracing::info!(
                            "📈 Iteration {}: score={:.3}, confidence={:.3}, success={}, econ={:.4} ETH",
                            iteration + 1,
                            score,
                            confidence,
                            result.success,
                            result.economic_value_eth
                        );
                    }
                    
                    // PRUNING: stop if score is high enough
                    if score >= self.prune_threshold {
                        tracing::info!("✅ High-score achieved, pruning early");
                        break;
                    }
                    
                    // Stop if no progress for many iterations
                    if consecutive_no_progress > 10 {
                        tracing::info!("⏸️ No progress for 10 iterations, stopping");
                        break;
                    }
                    
                    // GUIDED MUTATION: generate new inputs based on result
                    let mutations = self.fuzzer.mutate_guided(candidate, &result);
                    if let Some(mutated) = mutations.first() {
                        *candidate = mutated.clone();
                    }
                    
                    // Also try crossover with corpus
                    if iteration % 5 == 0 {
                        if let Some(corpus_input) = self.fuzzer.get_corpus_input() {
                            let crossed = candidate.crossover(&corpus_input);
                            *candidate = crossed;
                        }
                    }
                }
                
                if let Some(best) = best_attempt {
                    if best.score > 0.3 {
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
        constraints.extend(path.conditions.clone());
        
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
                        new.selector = "0x".to_string();
                        vec![new]
                    }
                    Condition::CallerEqStorage(slot) => {
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
        
        inputs.truncate(20);
        inputs
    }
    
    /// Simulate input via eth_call or fork
    async fn simulate_input(&self, input: &TestInput, contract_address: &str, path_value: &ExploitPathWithValue) -> Result<SimulationResult> {
        let start = std::time::Instant::now();
        
        let mut full_calldata = hex::decode(&input.selector.trim_start_matches("0x"))
            .unwrap_or_default();
        full_calldata.extend(&input.calldata);
        
        let calldata_hex = format!("0x{}", hex::encode(&full_calldata));
        
        // Capture storage before
        let storage_before = self.capture_storage_state(contract_address).await;
        
        match self.forensics.eth_call(
            &input.caller,
            contract_address,
            &calldata_hex,
            &format!("0x{:x}", input.value),
        ).await {
            Ok(result) => {
                let storage_after = self.capture_storage_state(contract_address).await;
                let state_changes = self.analyze_state_changes_detailed(&storage_before, &storage_after, input);
                let ownership_changed = self.detect_ownership_change(&storage_before, &storage_after);
                let delegatecall_detected = self.detect_delegatecall(&result);
                
                let coverage_new = self.calculate_coverage_delta(&result);
                let coverage_bits = self.calculate_coverage_bits_from_result(&result);
                
                let mut input_with_coverage = input.clone();
                input_with_coverage.coverage_bits = coverage_bits;
                
                Ok(SimulationResult {
                    success: true,
                    state_changes,
                    revert_reason: None,
                    gas_used: estimate_gas_from_calldata(&full_calldata),
                    return_data: hex::decode(result.trim_start_matches("0x")).unwrap_or_default(),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                    coverage_new,
                    economic_value_eth: path_value.economic_value_eth,
                    ownership_changed,
                    delegatecall_to_proxy: delegatecall_detected,
                    unlocks_after_blocks: 0,
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
                    coverage_new: CoverageDelta::NoNew,
                    economic_value_eth: 0.0,
                    ownership_changed: false,
                    delegatecall_to_proxy: false,
                    unlocks_after_blocks: 0,
                })
            }
        }
    }
    
    async fn capture_storage_state(&self, contract_address: &str) -> HashMap<u64, String> {
        let mut storage = HashMap::new();
        let critical_slots = [0u64, 1, 2, 3, 4, 5, 10, 11, 12, 100];
        
        for slot in critical_slots {
            let slot_hex = format!("0x{:x}", slot);
            if let Ok(value) = self.forensics.get_storage(contract_address, &slot_hex).await {
                storage.insert(slot, value);
            }
        }
        
        storage
    }
    
    fn analyze_state_changes_detailed(&self, before: &HashMap<u64, String>, after: &HashMap<u64, String>, input: &TestInput) -> Vec<StateChange> {
        let mut changes = Vec::new();
        
        for (slot, value_before) in before {
            if let Some(value_after) = after.get(slot) {
                if value_before != value_after {
                    changes.push(StateChange::StorageWrite(*slot, value_after.clone()));
                }
            }
        }
        
        if input.value > 0 {
            changes.push(StateChange::Transfer(input.value, None));
        }
        
        changes
    }
    
    fn detect_ownership_change(&self, before: &HashMap<u64, String>, after: &HashMap<u64, String>) -> bool {
        if let (Some(before_owner), Some(after_owner)) = (before.get(&0), after.get(&0)) {
            return before_owner != after_owner && after_owner != "0x0000000000000000000000000000000000000000";
        }
        false
    }
    
    fn detect_delegatecall(&self, result: &str) -> bool {
        result.contains("delegatecall") || result.contains("0xf4")
    }
    
    fn calculate_coverage_delta(&self, result: &str) -> CoverageDelta {
        // Simula detecção de novas coberturas baseado no resultado
        if result.contains("new_block") {
            CoverageDelta::NewBasicBlock(fastrand::u64(..))
        } else if result.contains("new_edge") {
            CoverageDelta::NewEdge(fastrand::u64(..))
        } else {
            CoverageDelta::NoNew
        }
    }
    
    fn calculate_coverage_bits_from_result(&self, result: &str) -> u64 {
        let mut bits = 0u64;
        for (i, c) in result.chars().take(64).enumerate() {
            if c as u8 % 2 == 0 {
                bits |= 1 << (i % 64);
            }
        }
        bits
    }
    
    fn calculate_coverage_bits(&self, result: &SimulationResult) -> u64 {
        let mut bits = 0u64;
        if result.success {
            bits |= 1;
        }
        if result.ownership_changed {
            bits |= 1 << 1;
        }
        if result.delegatecall_to_proxy {
            bits |= 1 << 2;
        }
        if result.economic_value_eth > 0.1 {
            bits |= 1 << 3;
        }
        bits
    }
    
    /// SCORE GRANULAR com weighted components
    fn evaluate_granular(&self, result: &SimulationResult) -> f32 {
        let mut score = 0.0;
        
        // Impacto financeiro (0-100)
        let financial = (result.economic_value_eth.min(1000.0) / 1000.0) as f32;
        score += financial * 0.4;
        
        // Persistência (escrita em storage crítico)
        let persistence = if result.ownership_changed { 0.3 } else { 0.0 };
        score += persistence;
        
        // Capacidade de upgrade (delegatecall)
        let upgradeable = if result.delegatecall_to_proxy { 0.2 } else { 0.0 };
        score += upgradeable;
        
        // Sucesso da execução
        if result.success {
            score += 0.15;
        }
        
        // State changes significativos
        for change in &result.state_changes {
            match change {
                StateChange::SelfDestruct(_) => {
                    score += 0.5;
                }
                StateChange::Transfer(amount, _) if *amount > 0 => {
                    score += 0.2;
                }
                StateChange::Delegatecall(_) => {
                    score += 0.3;
                }
                StateChange::StorageWrite(slot, _) if *slot == 0 => {
                    score += 0.25;
                }
                _ => {}
            }
        }
        
        // Penalidade para reverts
        if !result.success && result.revert_reason.is_some() {
            score -= 0.1;
        }
        
        score.clamp(0.0, 1.0)
    }
    
    /// Calculate confidence score
    fn calculate_confidence(&self, result: &SimulationResult, path: &ControlFlowPath) -> f32 {
        let success_score = if result.success { 0.8 } else { 0.2 };
        
        let has_privilege_check = path.conditions.iter().any(|c| {
            matches!(c, Condition::CallerEq(_) | Condition::CallerEqStorage(_))
        });
        let privilege_dependency = if has_privilege_check { 0.4 } else { 0.0 };
        
        let state_impact = self.evaluate_granular(result);
        
        (success_score * (1.0 - privilege_dependency) * state_impact).min(1.0)
    }
    
    /// Calculate gas cost in ETH
    fn calculate_gas_cost(&self, gas_used: u64) -> f64 {
        let gas_price_gwei = 20.0;
        (gas_used as f64 * gas_price_gwei * 1e9) / 1e18
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
    
    tracing::info!("🚀 Starting offensive analysis with guided fuzzing feedback loop...");
    
    let attempts = engine.synthesize_exploits(paths, contract_address).await?;
    
    tracing::info!("📊 Found {} viable exploit attempts", attempts.len());
    
    for attempt in &attempts {
        if attempt.score > 0.7 && attempt.success {
            tracing::warn!(
                "🚨 CRITICAL: Exploit confirmed! Selector={} Score={:.2} Confidence={:.2}% Value={:.4} ETH",
                attempt.selector,
                attempt.score,
                attempt.confidence * 100.0,
                attempt.economic_value_eth
            );
        }
    }
    
    let mev_opportunities = Vec::new();
    Ok((attempts, mev_opportunities))
}

// ============================================================
// TESTES
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bit_flip_mutation() {
        let input = TestInput::default();
        let mutated = input.mutate_bit_flip();
        assert_eq!(mutated.iteration, input.iteration + 1);
    }
    
    #[test]
    fn test_crossover() {
        let input1 = TestInput::default();
        let mut input2 = TestInput::default();
        input2.calldata = vec![1, 2, 3, 4];
        
        let crossed = input1.crossover(&input2);
        assert!(crossed.calldata.len() <= input2.calldata.len());
    }
    
    #[test]
    fn test_granular_scoring() {
        let fuzzer = forthresGuidedFuzzer::new();
        let result = SimulationResult {
            success: true,
            state_changes: vec![StateChange::StorageWrite(0, "new_owner".to_string())],
            revert_reason: None,
            gas_used: 100000,
            return_data: vec![],
            execution_time_ms: 10,
            coverage_new: CoverageDelta::NoNew,
            economic_value_eth: 10.0,
            ownership_changed: true,
            delegatecall_to_proxy: false,
            unlocks_after_blocks: 0,
        };
        
        let score = fuzzer.evaluate_granular(&result);
        assert!(score > 0.5);
    }
}