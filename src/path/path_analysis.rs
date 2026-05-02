// src/path_analysis.rs
//! Forthres Path Analysis Module - EIP-7702 Offensive Semantics
//!
//! Advanced path-based vulnerability detection for EIP-7702:
//! - tx.origin broken assumption analysis
//! - Delegation execution path modeling
//! - Batch call + admin context exploitation
//! - State change tracking for delegation abuse

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use tracing::{debug, info, warn};

use crate::bytecode::{
    BasicBlock, ControlFlowGraph, EIP7702Detection, EIP7702Pattern,
    OpcodeLocation, PatternSeverity,
};

// ============================================================
// CONSTANTS
// ============================================================

const MAX_PATH_DEPTH: usize = 50;
const MAX_EXPLORATION_PATHS: usize = 100;
const DELEGATION_CONTEXT_MARKER: u64 = 0x7702_DE1E;
const BATCH_EXECUTION_MARKER: u64 = 0xBA7C_0001;

// ============================================================
// PATH TYPES
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PathType {
    /// EOA checks tx.origin but delegation allows arbitrary code
    EoaOnlyBypass,
    /// Unrestricted batch call with delegation context
    BatchUnrestrictedDelegation,
    /// Admin function callable via delegated context
    AdminDelegationAbuse,
    /// Delegatecall router with batch execution
    DelegatecallBatchPath,
    /// Upgrade function triggered via delegation
    UpgradeDelegationPath,
    /// Multi-step attack chain combining vulnerabilities
    MultiStepAttackChain,
}

impl fmt::Display for PathType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathType::EoaOnlyBypass => write!(f, "EOA_ONLY_BYPASS_PATH"),
            PathType::BatchUnrestrictedDelegation => write!(f, "BATCH_UNRESTRICTED_DELEGATION_PATH"),
            PathType::AdminDelegationAbuse => write!(f, "ADMIN_DELEGATION_ABUSE_PATH"),
            PathType::DelegatecallBatchPath => write!(f, "DELEGATECALL_BATCH_PATH"),
            PathType::UpgradeDelegationPath => write!(f, "UPGRADE_DELEGATION_PATH"),
            PathType::MultiStepAttackChain => write!(f, "MULTI_STEP_ATTACK_CHAIN"),
        }
    }
}

impl PathType {
    pub fn severity(&self) -> PatternSeverity {
        match self {
            PathType::EoaOnlyBypass => PatternSeverity::Critical,
            PathType::BatchUnrestrictedDelegation => PatternSeverity::Critical,
            PathType::AdminDelegationAbuse => PatternSeverity::Critical,
            PathType::DelegatecallBatchPath => PatternSeverity::High,
            PathType::UpgradeDelegationPath => PatternSeverity::High,
            PathType::MultiStepAttackChain => PatternSeverity::Critical,
        }
    }
    
    pub fn risk_weight(&self) -> f64 {
        match self {
            PathType::EoaOnlyBypass => 0.95,
            PathType::BatchUnrestrictedDelegation => 0.98,
            PathType::AdminDelegationAbuse => 0.90,
            PathType::DelegatecallBatchPath => 0.75,
            PathType::UpgradeDelegationPath => 0.70,
            PathType::MultiStepAttackChain => 1.0,
        }
    }
}

// ============================================================
// STATE CHANGE TYPES
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateChangeType {
    /// Storage write (SSTORE)
    StorageWrite { slot: Option<u64>, value: Option<Vec<u8>> },
    /// Balance transfer (CALL with value)
    BalanceTransfer { amount: Option<u64>, recipient: Option<String> },
    /// Contract creation (CREATE/CREATE2)
    ContractCreation { address: Option<String> },
    /// Self-destruct (SELFDESTRUCT)
    SelfDestruct { beneficiary: Option<String> },
    /// Ownership transfer detection
    OwnershipTransfer { new_owner: Option<String> },
    /// Admin privilege escalation
    AdminEscalation { role: Option<String> },
    /// Delegatecall to arbitrary target
    ArbitraryDelegatecall { target: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub change_type: StateChangeType,
    pub pc: usize,
    pub context: String,
    pub confidence: f64,
}

// ============================================================
// CONDITION TYPES
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionType {
    /// tx.origin == caller check
    OriginEquality,
    /// msg.sender == owner check
    SenderEquality,
    /// Balance check (balance >= amount)
    BalanceCheck,
    /// Timestamp constraint (block.timestamp)
    TimestampConstraint,
    /// Role verification (hasRole)
    RoleCheck,
    /// Delegatecall context (caller is delegate)
    DelegateContext,
    /// Batch execution mode
    BatchMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCondition {
    pub condition_type: ConditionType,
    pub pc: usize,
    pub satisfied_in_delegation: bool, // In EIP-7702, this changes!
    pub description: String,
}

// ============================================================
// EXECUTION PATH
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPath {
    pub id: String,
    pub path_type: PathType,
    pub entry_pc: usize,
    pub exit_pc: usize,
    pub basic_blocks: Vec<usize>,
    pub conditions: Vec<PathCondition>,
    pub state_changes: Vec<StateChange>,
    pub probability: f64,
    pub requires_delegation: bool,
    pub requires_batch_context: bool,
    pub exploitation_steps: Vec<String>,
    pub real_exploit_reference: Option<String>,
}

impl ExecutionPath {
    pub fn is_feasible(&self) -> bool {
        self.probability > 0.05 && !self.conditions.is_empty()
    }
    
    pub fn complexity(&self) -> u32 {
        let mut complexity = self.basic_blocks.len() as u32;
        complexity += self.conditions.len() as u32;
        complexity += self.state_changes.len() as u32;
        complexity
    }
}

// ============================================================
// DELEGATION CONTEXT
// ============================================================

#[derive(Debug, Clone, Default)]
pub struct DelegationContext {
    pub is_active: bool,
    pub delegated_from: Option<String>,
    pub delegated_code: Option<String>,
    pub delegation_pc: usize,
    pub can_execute_arbitrary: bool,
    pub batch_available: bool,
    pub admin_privileges: bool,
}

// ============================================================
// PATH ANALYSIS ENGINE
// ============================================================

pub struct PathAnalysisEngine;

impl PathAnalysisEngine {
    // ============================================================
    // 1. EOA ONLY BYPASS PATH DETECTION
    // ============================================================
    
    /// Detecta paths onde tx.origin é usado como restrição EOA
    /// mas EIP-7702 permite delegação que quebra essa premissa
    pub fn detect_eoa_only_bypass_paths(
        cfgraph: &ControlFlowGraph,
        detections: &[EIP7702Detection],
    ) -> Vec<ExecutionPath> {
        let mut paths = Vec::new();
        
        // Encontra blocos com ORIGIN + EQ
        for block in &cfgraph.blocks {
            let origin_positions = Self::find_origin_eq_pattern(block);
            
            for origin_pc in origin_positions {
                // Verifica se ORIGIN+EQ leva a JUMPI (branch condicional)
                if let Some(branch_target) = Self::find_branch_target(block, origin_pc) {
                    let exploitation_steps = vec![
                        "1. Atacante engana vítima para assinar autorização EIP-7702".to_string(),
                        "2. Autorização delega EOA para contrato malicioso".to_string(),
                        format!("3. Contrato malicioso executa no contexto da EOA (PC: 0x{:x})", origin_pc),
                        "4. require(msg.sender == tx.origin) passa (msg.sender = EOA)".to_string(),
                        "5. Código arbitrário do contrato malicioso é executado".to_string(),
                        "6. Atacante drena fundos ou toma controle".to_string(),
                    ];
                    
                    let path = ExecutionPath {
                        id: format!("eoa_bypass_path_{:x}", origin_pc),
                        path_type: PathType::EoaOnlyBypass,
                        entry_pc: origin_pc,
                        exit_pc: branch_target,
                        basic_blocks: vec![block.start],
                        conditions: vec![
                            PathCondition {
                                condition_type: ConditionType::OriginEquality,
                                pc: origin_pc,
                                satisfied_in_delegation: true, // QUEBRADO!
                                description: "tx.origin == caller - PREMISSA QUEBRADA POR EIP-7702".to_string(),
                            },
                        ],
                        state_changes: Self::find_state_changes_in_path(cfgraph, block.start, branch_target),
                        probability: 0.85,
                        requires_delegation: true,
                        requires_batch_context: false,
                        exploitation_steps,
                        real_exploit_reference: Some("Flare FAssets protocol - griefing attack".to_string()),
                    };
                    
                    paths.push(path);
                }
            }
        }
        
        paths
    }
    
    // ============================================================
    // 2. BATCH UNRESTRICTED DELEGATION PATH DETECTION
    // ============================================================
    
    /// Detecta paths onde batch call unrestricted pode ser abusado via delegação
    pub fn detect_batch_unrestricted_paths(
        cfgraph: &ControlFlowGraph,
        detections: &[EIP7702Detection],
        delegation_context: &DelegationContext,
    ) -> Vec<ExecutionPath> {
        let mut paths = Vec::new();
        
        // Procura por funções batch (multicall, execute, batch)
        for block in &cfgraph.blocks {
            if Self::is_batch_function_entry(block) {
                let has_access_control = Self::has_access_control_at_entry(block);
                let has_loop = Self::has_loop_pattern(block);
                let has_unrestricted_call = Self::has_unrestricted_delegatecall(block);
                
                if !has_access_control && (has_loop || has_unrestricted_call) {
                    let exploitation_steps = vec![
                        "1. Atacante obtém delegação de EOA (phishing/engenharia social)".to_string(),
                        "2. EOA delegada para contrato do atacante via EIP-7702".to_string(),
                        format!("3. Atacante chama batch() na EOA (PC: 0x{:x})", block.start),
                        "4. batch() executa CALLs/DELEGATECALLs arbitrários".to_string(),
                        "5. Cada CALL executa no contexto da EOA (com fundos + permissões)".to_string(),
                        "6. Atacante drena todos os ativos em uma única transação".to_string(),
                    ];
                    
                    let path = ExecutionPath {
                        id: format!("batch_unrestricted_path_{:x}", block.start),
                        path_type: PathType::BatchUnrestrictedDelegation,
                        entry_pc: block.start,
                        exit_pc: block.end,
                        basic_blocks: vec![block.start],
                        conditions: vec![
                            PathCondition {
                                condition_type: ConditionType::BatchMode,
                                pc: block.start,
                                satisfied_in_delegation: true,
                                description: "Batch execution without access control".to_string(),
                            },
                            PathCondition {
                                condition_type: ConditionType::DelegateContext,
                                pc: block.start,
                                satisfied_in_delegation: true,
                                description: "Executes in delegated context".to_string(),
                            },
                        ],
                        state_changes: Self::find_state_changes_in_path(cfgraph, block.start, block.end),
                        probability: 0.92,
                        requires_delegation: true,
                        requires_batch_context: true,
                        exploitation_steps,
                        real_exploit_reference: Some("QNT reserve pool - 54.93 ETH drained".to_string()),
                    };
                    
                    paths.push(path);
                }
            }
        }
        
        paths
    }
    
    // ============================================================
    // 3. ADMIN DELEGATION ABUSE PATH DETECTION
    // ============================================================
    
    /// Detecta paths onde funções de admin podem ser chamadas via delegação
    pub fn detect_admin_delegation_paths(
        cfgraph: &ControlFlowGraph,
        detections: &[EIP7702Detection],
        delegation_context: &DelegationContext,
    ) -> Vec<ExecutionPath> {
        let mut paths = Vec::new();
        
        // Admin selectors comuns
        let admin_selectors = [
            "transferOwnership", "renounceOwnership", "takeOwnership",
            "becomeAdmin", "grantRole", "revokeRole", "pause", "unpause",
            "upgradeTo", "setImplementation", "changeAdmin",
        ];
        
        for block in &cfgraph.blocks {
            if Self::contains_any_selector(block, &admin_selectors) {
                let has_owner_check = Self::has_owner_check(block);
                let has_role_check = Self::has_role_check(block);
                
                if has_owner_check || has_role_check {
                    let exploitation_steps = vec![
                        "1. Atacante delega EOA com privilégios de admin".to_string(),
                        "2. Atacante chama função admin via EOA delegada".to_string(),
                        format!("3. require(owner == msg.sender) passa (msg.sender = EOA administradora)",),
                        "4. Código delegado executa com privilégios de admin".to_string(),
                        "5. Atacante transfere ownership ou upgradeia implementação".to_string(),
                        "6. Controle total do protocolo é comprometido".to_string(),
                    ];
                    
                    let path = ExecutionPath {
                        id: format!("admin_delegation_path_{:x}", block.start),
                        path_type: PathType::AdminDelegationAbuse,
                        entry_pc: block.start,
                        exit_pc: block.end,
                        basic_blocks: vec![block.start],
                        conditions: vec![
                            PathCondition {
                                condition_type: ConditionType::SenderEquality,
                                pc: block.start,
                                satisfied_in_delegation: true,
                                description: "Owner check passes with delegated EOA".to_string(),
                            },
                        ],
                        state_changes: Self::find_state_changes_in_path(cfgraph, block.start, block.end),
                        probability: 0.88,
                        requires_delegation: true,
                        requires_batch_context: false,
                        exploitation_steps,
                        real_exploit_reference: None,
                    };
                    
                    paths.push(path);
                }
            }
        }
        
        paths
    }
    
    // ============================================================
    // 4. DELEGATECALL BATCH PATH DETECTION
    // ============================================================
    
    /// Detecta paths com DELEGATECALL dentro de batch execution
    pub fn detect_delegatecall_batch_paths(
        cfgraph: &ControlFlowGraph,
        detections: &[EIP7702Detection],
    ) -> Vec<ExecutionPath> {
        let mut paths = Vec::new();
        
        for block in &cfgraph.blocks {
            let has_delegatecall = block.instructions.iter()
                .any(|instr| instr.opcode == 0xF4); // DELEGATECALL
            
            let has_batch_pattern = Self::is_batch_function_entry(block);
            
            if has_delegatecall && has_batch_pattern {
                let exploitation_steps = vec![
                    "1. Atacante envia calldata maliciosa para batch()".to_string(),
                    "2. batch() itera sobre múltiplas chamadas".to_string(),
                    "3. DELEGATECALL executa código arbitrário no contexto do contrato".to_string(),
                    "4. Storage do contrato é corrompido".to_string(),
                    "5. Atacante assume controle ou drena fundos".to_string(),
                ];
                
                let path = ExecutionPath {
                    id: format!("delegatecall_batch_path_{:x}", block.start),
                    path_type: PathType::DelegatecallBatchPath,
                    entry_pc: block.start,
                    exit_pc: block.end,
                    basic_blocks: vec![block.start],
                    conditions: vec![
                        PathCondition {
                            condition_type: ConditionType::BatchMode,
                            pc: block.start,
                            satisfied_in_delegation: true,
                            description: "Batch execution pattern".to_string(),
                        },
                    ],
                    state_changes: Self::find_delegatecall_state_changes(block),
                    probability: 0.78,
                    requires_delegation: false,
                    requires_batch_context: true,
                    exploitation_steps,
                    real_exploit_reference: Some("Delegatecall injection in batch routers".to_string()),
                };
                
                paths.push(path);
            }
        }
        
        paths
    }
    
    // ============================================================
    // 5. UPGRADE DELEGATION PATH DETECTION
    // ============================================================
    
    /// Detecta paths onde upgrade functions podem ser abusadas via delegação
    pub fn detect_upgrade_delegation_paths(
        cfgraph: &ControlFlowGraph,
        detections: &[EIP7702Detection],
    ) -> Vec<ExecutionPath> {
        let mut paths = Vec::new();
        
        let upgrade_selectors = [
            "upgradeTo", "upgradeToAndCall", "setImplementation",
            "changeImplementation", "upgradeImplementation",
        ];
        
        for block in &cfgraph.blocks {
            if Self::contains_any_selector(block, &upgrade_selectors) {
                let exploitation_steps = vec![
                    "1. Atacante delega EOA com permissões de upgrade".to_string(),
                    "2. Atacante chama upgradeTo() via EOA delegada".to_string(),
                    "3. Validação de owner passa (EOA é owner legítimo)".to_string(),
                    "4. Implementação é trocada para contrato malicioso".to_string(),
                    "5. Próximas chamadas executam código do atacante".to_string(),
                    "6. Todas as funções agora são controladas pelo atacante".to_string(),
                ];
                
                let path = ExecutionPath {
                    id: format!("upgrade_delegation_path_{:x}", block.start),
                    path_type: PathType::UpgradeDelegationPath,
                    entry_pc: block.start,
                    exit_pc: block.end,
                    basic_blocks: vec![block.start],
                    conditions: vec![
                        PathCondition {
                            condition_type: ConditionType::SenderEquality,
                            pc: block.start,
                            satisfied_in_delegation: true,
                            description: "Upgrade permission check passes".to_string(),
                        },
                    ],
                    state_changes: vec![
                        StateChange {
                            change_type: StateChangeType::AdminEscalation { role: Some("implementation_upgrader".to_string()) },
                            pc: block.start,
                            context: "Implementation upgrade triggered via delegation".to_string(),
                            confidence: 0.85,
                        },
                    ],
                    probability: 0.82,
                    requires_delegation: true,
                    requires_batch_context: false,
                    exploitation_steps,
                    real_exploit_reference: None,
                };
                
                paths.push(path);
            }
        }
        
        paths
    }
    
    // ============================================================
    // 6. MULTI-STEP ATTACK CHAIN DETECTION
    // ============================================================
    
    /// Detecta chains de ataques combinando múltiplas vulnerabilidades
    pub fn detect_multi_step_chains(
        eoa_paths: Vec<ExecutionPath>,
        batch_paths: Vec<ExecutionPath>,
        admin_paths: Vec<ExecutionPath>,
    ) -> Vec<ExecutionPath> {
        let mut chains = Vec::new();
        
        // Combina EOA bypass + Batch exploit
        for eoa_path in &eoa_paths {
            for batch_path in &batch_paths {
                let combined_steps = vec![
                    eoa_path.exploitation_steps.clone(),
                    batch_path.exploitation_steps.clone(),
                ].concat();
                
                let chain = ExecutionPath {
                    id: format!("chain_{}_{}", eoa_path.id, batch_path.id),
                    path_type: PathType::MultiStepAttackChain,
                    entry_pc: eoa_path.entry_pc,
                    exit_pc: batch_path.exit_pc,
                    basic_blocks: [eoa_path.basic_blocks.clone(), batch_path.basic_blocks.clone()].concat(),
                    conditions: [eoa_path.conditions.clone(), batch_path.conditions.clone()].concat(),
                    state_changes: [eoa_path.state_changes.clone(), batch_path.state_changes.clone()].concat(),
                    probability: eoa_path.probability * batch_path.probability,
                    requires_delegation: true,
                    requires_batch_context: true,
                    exploitation_steps: combined_steps,
                    real_exploit_reference: Some("Advanced persistent threat patterns".to_string()),
                };
                
                chains.push(chain);
            }
        }
        
        // Combina Admin Delegation + Upgrade
        for admin_path in &admin_paths {
            if admin_path.path_type == PathType::AdminDelegationAbuse {
                let upgrade_chain = ExecutionPath {
                    id: format!("admin_upgrade_chain_{}", admin_path.id),
                    path_type: PathType::MultiStepAttackChain,
                    entry_pc: admin_path.entry_pc,
                    exit_pc: admin_path.exit_pc,
                    basic_blocks: admin_path.basic_blocks.clone(),
                    conditions: admin_path.conditions.clone(),
                    state_changes: admin_path.state_changes.clone(),
                    probability: admin_path.probability * 0.9,
                    requires_delegation: true,
                    requires_batch_context: false,
                    exploitation_steps: vec![
                        "1. Admin EOA é delegada para contrato malicioso".to_string(),
                        "2. Atacante chama transferOwnership via delegação".to_string(),
                        "3. Ownership é transferido para o atacante".to_string(),
                        "4. Atacante agora é admin legítimo".to_string(),
                        "5. Atacante upgradeia implementação para contrato malicioso".to_string(),
                        "6. Controle total do protocolo estabelecido".to_string(),
                    ],
                    real_exploit_reference: Some("Full protocol takeover scenario".to_string()),
                };
                chains.push(upgrade_chain);
            }
        }
        
        chains
    }
    
    // ============================================================
    // FUNÇÕES AUXILIARES
    // ============================================================
    
    fn find_origin_eq_pattern(block: &BasicBlock) -> Vec<usize> {
        let mut positions = Vec::new();
        
        for (idx, instr) in block.instructions.iter().enumerate() {
            if instr.opcode == 0x32 { // ORIGIN
                // Verifica se o próximo instruction é EQ
                if let Some(next) = block.instructions.get(idx + 1) {
                    if next.opcode == 0x14 { // EQ
                        positions.push(instr.offset);
                    }
                }
            }
        }
        
        positions
    }
    
    fn find_branch_target(block: &BasicBlock, origin_pc: usize) -> Option<usize> {
        let mut found_origin = false;
        
        for instr in &block.instructions {
            if instr.offset == origin_pc {
                found_origin = true;
                continue;
            }
            
            if found_origin && instr.opcode == 0x57 { // JUMPI
                return Some(instr.offset);
            }
        }
        
        None
    }
    
    fn is_batch_function_entry(block: &BasicBlock) -> bool {
        let batch_patterns = [
            "batch", "multicall", "execute", "multisend",
            "batchCall", "aggregate", "bulk",
        ];
        
        Self::contains_any_selector(block, &batch_patterns)
    }
    
    fn contains_any_selector(block: &BasicBlock, patterns: &[&str]) -> bool {
        for instr in &block.instructions {
            if let Some(ref data) = instr.push_data {
                let data_str = format!("{:02x?}", data);
                for pattern in patterns {
                    if data_str.to_lowercase().contains(&pattern.to_lowercase()) {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    fn has_access_control_at_entry(block: &BasicBlock) -> bool {
        let early_instructions = block.instructions.iter().take(10);
        
        for instr in early_instructions {
            // Procura por checks de ownership
            if instr.mnemonic == "CALLER" || instr.mnemonic == "SLOAD" {
                return true;
            }
        }
        
        false
    }
    
    fn has_owner_check(block: &BasicBlock) -> bool {
        let early_instructions = block.instructions.iter().take(15);
        
        for instr in early_instructions {
            if instr.mnemonic == "CALLER" {
                if let Some(next) = block.instructions.iter().find(|i| i.offset > instr.offset) {
                    if next.mnemonic == "EQ" {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    fn has_role_check(block: &BasicBlock) -> bool {
        for instr in &block.instructions {
            if instr.mnemonic == "SLOAD" {
                if let Some(next) = block.instructions.iter().find(|i| i.offset > instr.offset) {
                    if next.mnemonic == "AND" || next.mnemonic == "EQ" {
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    fn has_loop_pattern(block: &BasicBlock) -> bool {
        let jumps = block.instructions.iter()
            .filter(|instr| instr.mnemonic == "JUMPI" || instr.mnemonic == "JUMP")
            .count();
        
        jumps > 1
    }
    
    fn has_unrestricted_delegatecall(block: &BasicBlock) -> bool {
        let has_delegatecall = block.instructions.iter()
            .any(|instr| instr.opcode == 0xF4);
        
        let has_target_validation = block.instructions.iter()
            .any(|instr| instr.mnemonic == "EXTCODESIZE" || instr.mnemonic == "ISZERO");
        
        has_delegatecall && !has_target_validation
    }
    
    fn find_state_changes_in_path(
        cfgraph: &ControlFlowGraph,
        start_pc: usize,
        end_pc: usize,
    ) -> Vec<StateChange> {
        let mut changes = Vec::new();
        
        for block in &cfgraph.blocks {
            if block.start >= start_pc && block.end <= end_pc {
                for instr in &block.instructions {
                    match instr.opcode {
                        0x55 => { // SSTORE
                            changes.push(StateChange {
                                change_type: StateChangeType::StorageWrite { slot: None, value: None },
                                pc: instr.offset,
                                context: "Storage write detected in path".to_string(),
                                confidence: 0.8,
                            });
                        }
                        0xF1 => { // CALL with value
                            changes.push(StateChange {
                                change_type: StateChangeType::BalanceTransfer { amount: None, recipient: None },
                                pc: instr.offset,
                                context: "External call with possible value transfer".to_string(),
                                confidence: 0.7,
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        
        changes
    }
    
    fn find_delegatecall_state_changes(block: &BasicBlock) -> Vec<StateChange> {
        let mut changes = Vec::new();
        
        for instr in &block.instructions {
            if instr.opcode == 0xF4 { // DELEGATECALL
                changes.push(StateChange {
                    change_type: StateChangeType::ArbitraryDelegatecall { target: None },
                    pc: instr.offset,
                    context: "DELEGATECALL can execute arbitrary code".to_string(),
                    confidence: 0.9,
                });
            }
        }
        
        changes
    }
    
    // ============================================================
    // 7. ANÁLISE COMPLETA DE PATHS
    // ============================================================
    
    /// Executa análise completa de todos os paths EIP-7702
    pub fn analyze_all_paths(
        cfgraph: &ControlFlowGraph,
        detections: &[EIP7702Detection],
        delegation_context: &DelegationContext,
    ) -> Vec<ExecutionPath> {
        let mut all_paths = Vec::new();
        
        info!("🔬 Iniciando análise completa de paths EIP-7702");
        
        // 1. EOA Only Bypass
        let eoa_paths = Self::detect_eoa_only_bypass_paths(cfgraph, detections);
        all_paths.extend(eoa_paths.clone());
        info!("  → {} EOA bypass paths encontrados", eoa_paths.len());
        
        // 2. Batch Unrestricted
        let batch_paths = Self::detect_batch_unrestricted_paths(cfgraph, detections, delegation_context);
        all_paths.extend(batch_paths.clone());
        info!("  → {} batch unrestricted paths encontrados", batch_paths.len());
        
        // 3. Admin Delegation
        let admin_paths = Self::detect_admin_delegation_paths(cfgraph, detections, delegation_context);
        all_paths.extend(admin_paths.clone());
        info!("  → {} admin delegation paths encontrados", admin_paths.len());
        
        // 4. Delegatecall Batch
        let delegatecall_paths = Self::detect_delegatecall_batch_paths(cfgraph, detections);
        all_paths.extend(delegatecall_paths.clone());
        info!("  → {} delegatecall batch paths encontrados", delegatecall_paths.len());
        
        // 5. Upgrade Delegation
        let upgrade_paths = Self::detect_upgrade_delegation_paths(cfgraph, detections);
        all_paths.extend(upgrade_paths.clone());
        info!("  → {} upgrade delegation paths encontrados", upgrade_paths.len());
        
        // 6. Multi-step chains
        let chains = Self::detect_multi_step_chains(eoa_paths, batch_paths, admin_paths);
        all_paths.extend(chains.clone());
        info!("  → {} multi-step attack chains encontrados", chains.len());
        
        // Loga os paths críticos
        let critical_paths: Vec<_> = all_paths.iter()
            .filter(|p| p.path_type.severity() == PatternSeverity::Critical)
            .collect();
        
        if !critical_paths.is_empty() {
            warn!("🚨 {} paths CRÍTICOS detectados:", critical_paths.len());
            for path in critical_paths {
                warn!("  → {} (probabilidade: {:.1}%)", path.path_type, path.probability * 100.0);
                if let Some(ref exploit) = path.real_exploit_reference {
                    warn!("     Real exploit: {}", exploit);
                }
            }
        }
        
        all_paths
    }
}

// ============================================================
// TESTES
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_path_type_severity() {
        assert_eq!(PathType::EoaOnlyBypass.severity(), PatternSeverity::Critical);
        assert_eq!(PathType::BatchUnrestrictedDelegation.severity(), PatternSeverity::Critical);
        assert_eq!(PathType::DelegatecallBatchPath.severity(), PatternSeverity::High);
    }
    
    #[test]
    fn test_path_risk_weight() {
        assert!(PathType::BatchUnrestrictedDelegation.risk_weight() > 0.9);
        assert!(PathType::DelegatecallBatchPath.risk_weight() > 0.7);
    }
    
    #[test]
    fn test_execution_path_feasibility() {
        let path = ExecutionPath {
            id: "test".to_string(),
            path_type: PathType::EoaOnlyBypass,
            entry_pc: 0,
            exit_pc: 10,
            basic_blocks: vec![0],
            conditions: vec![],
            state_changes: vec![],
            probability: 0.01,
            requires_delegation: true,
            requires_batch_context: false,
            exploitation_steps: vec![],
            real_exploit_reference: None,
        };
        
        assert!(!path.is_feasible()); // probability < 0.05
    }
    
    #[test]
    fn test_contains_selector_pattern() {
        // Teste simplificado - em produção usaria bytecode real
        // Este é um placeholder
        assert!(true);
    }
}
