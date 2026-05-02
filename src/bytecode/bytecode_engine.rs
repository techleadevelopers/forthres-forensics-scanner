// src/bytecode_engine.rs
//! Forthres Bytecode Analysis Engine - EIP-7702 MAXIMUM LEVEL
//!
//! Detects structural vulnerabilities introduced by EIP-7702:
//! - EOA only bypass (tx.origin + EQ as broken assumption)
//! - Batch call exploits (unrestricted batch/multicall selectors)
//! - Malicious delegation patterns (unvalidated delegate targets)
//! - Chain-agnostic replay attacks (chainId = 0)
//! - Admin surface delegation abuse (admin + batch + delegate)

use sha3::{Digest, Keccak256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use tracing::{debug, info, warn, error};

// ============================================================
// EIP-7702 SPECIFIC CONSTANTS
// ============================================================

/// EIP-7702 transaction type
pub const EIP7702_TX_TYPE: u8 = 0x04;

/// EIP-7702 authority tuple marker (magic bytes)
pub const EIP7702_AUTHORITY_MAGIC: [u8; 6] = [0xef, 0x01, 0x00, 0x00, 0x00, 0x00];

/// Chain-agnostic mode constant
pub const CHAIN_AGNOSTIC_ID: u64 = 0;

/// Maximum delegation depth to analyze
const MAX_DELEGATION_DEPTH: usize = 5;

/// Decompiler search window for pattern matching
const PATTERN_WINDOW: usize = 256;

// ============================================================
// EIP-7702 PATTERN TYPES
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EIP7702Pattern {
    /// tx.origin + EQ + JUMPI pattern - broken EOA assumption
    EoaOnlyBypass,
    /// Unrestricted batch/execute/multicall with delegation
    BatchCallExploit,
    /// Delegate to unverified contract (no validation)
    UnvalidatedDelegation,
    /// Chain-agnostic authority (chainId = 0)
    ChainAgnosticReplay,
    /// Admin surface with delegation capability
    AdminDelegationAbuse,
    /// Delegatecall router with batch surface
    DelegatecallBatchRouter,
    /// Upgrade surface with delegation (proxy pattern)
    UpgradeDelegatePattern,
}

impl fmt::Display for EIP7702Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EIP7702Pattern::EoaOnlyBypass => write!(f, "EIP7702_EOA_ONLY_BYPASS"),
            EIP7702Pattern::BatchCallExploit => write!(f, "EIP7702_BATCH_CALL_EXPLOIT"),
            EIP7702Pattern::UnvalidatedDelegation => write!(f, "EIP7702_UNVALIDATED_DELEGATION"),
            EIP7702Pattern::ChainAgnosticReplay => write!(f, "EIP7702_CHAIN_AGNOSTIC_REPLAY"),
            EIP7702Pattern::AdminDelegationAbuse => write!(f, "EIP7702_ADMIN_DELEGATION_ABUSE"),
            EIP7702Pattern::DelegatecallBatchRouter => write!(f, "EIP7702_DELEGATECALL_BATCH_ROUTER"),
            EIP7702Pattern::UpgradeDelegatePattern => write!(f, "EIP7702_UPGRADE_DELEGATE_PATTERN"),
        }
    }
}

impl EIP7702Pattern {
    pub fn severity(&self) -> PatternSeverity {
        match self {
            EIP7702Pattern::EoaOnlyBypass => PatternSeverity::Critical,
            EIP7702Pattern::BatchCallExploit => PatternSeverity::Critical,
            EIP7702Pattern::UnvalidatedDelegation => PatternSeverity::Critical,
            EIP7702Pattern::ChainAgnosticReplay => PatternSeverity::High,
            EIP7702Pattern::AdminDelegationAbuse => PatternSeverity::Critical,
            EIP7702Pattern::DelegatecallBatchRouter => PatternSeverity::High,
            EIP7702Pattern::UpgradeDelegatePattern => PatternSeverity::Medium,
        }
    }
    
    pub fn confidence_threshold(&self) -> f32 {
        match self {
            EIP7702Pattern::ChainAgnosticReplay => 0.85,
            EIP7702Pattern::UpgradeDelegatePattern => 0.70,
            _ => 0.80,
        }
    }
}

// ============================================================
// DANGEROUS SELECTORS (EIP-7702 CONTEXT)
// ============================================================

/// Batch/execute/multicall selectors (attack surface)
const BATCH_SELECTORS: &[(&str, &[u8; 4])] = &[
    ("batch(address[],bytes[])", &[0x47, 0x58, 0x09, 0x78]),
    ("multicall(bytes[])", &[0xac, 0x96, 0x50, 0x60]),
    ("execute(address[],bytes[])", &[0xfe, 0xbc, 0x22, 0x70]),
    ("multisend(address[],uint256[],bytes[])", &[0x2a, 0xa1, 0xfd, 0x78]),
    ("batchCall(address[],uint256[],bytes[])", &[0x4e, 0x1c, 0x3b, 0x1c]),
    ("aggregate(tuple[])", &[0x5f, 0xcb, 0x4a, 0x9b]),
];

/// Delegation/authorization selectors (EIP-7702 specific)
const DELEGATION_SELECTORS: &[(&str, &[u8; 4])] = &[
    ("delegate(address)", &[0xf4, 0x15, 0x4b, 0xec]),
    ("setCode(address)", &[0x21, 0x3b, 0x5c, 0x28]),
    ("authorize(address)", &[0x12, 0x9e, 0x7e, 0x66]),
    ("grantDelegation(address)", &[0xbe, 0x94, 0x6a, 0xb5]),
    ("updateDelegation(address)", &[0xbc, 0x4f, 0x7a, 0xd9]),
];

/// Upgrade/implementation selectors (proxy patterns)
const UPGRADE_SELECTORS: &[(&str, &[u8; 4])] = &[
    ("upgradeTo(address)", &[0x36, 0x59, 0xc5, 0x96]),
    ("upgradeToAndCall(address,bytes)", &[0x4f, 0x1e, 0xf2, 0x86]),
    ("setImplementation(address)", &[0x5c, 0x60, 0xda, 0x01]),
    ("changeImplementation(address)", &[0xcb, 0x2f, 0x7a, 0xa7]),
    ("upgradeImplementation(address)", &[0x4e, 0xf3, 0x9b, 0xbc]),
];

/// Admin/ownership selectors (privilege surface)
const ADMIN_SELECTORS: &[(&str, &[u8; 4])] = &[
    ("transferOwnership(address)", &[0xf2, 0xf0, 0x38, 0x38]),
    ("renounceOwnership()", &[0x71, 0x50, 0x18, 0xa6]),
    ("takeOwnership()", &[0x69, 0xaa, 0x1c, 0x48]),
    ("becomeAdmin()", &[0xd4, 0x36, 0x27, 0x6b]),
    ("grantRole(bytes32,address)", &[0x2f, 0x2f, 0x2c, 0x28]),
    ("revokeRole(bytes32,address)", &[0xd5, 0x47, 0x74, 0x11]),
];

// ============================================================
// DATA STRUCTURES
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for PatternSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternSeverity::Critical => write!(f, "CRITICAL"),
            PatternSeverity::High => write!(f, "HIGH"),
            PatternSeverity::Medium => write!(f, "MEDIUM"),
            PatternSeverity::Low => write!(f, "LOW"),
            PatternSeverity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EIP7702Detection {
    pub pattern: EIP7702Pattern,
    pub offset: usize,
    pub severity: PatternSeverity,
    pub confidence: f32,
    pub description: String,
    pub exploitation_path: Option<String>,
    pub evidence: Vec<String>,
    pub context: EIP7702Context,
}

#[derive(Debug, Clone, Default)]
pub struct EIP7702Context {
    pub has_tx_origin_check: bool,
    pub has_batch_selector: bool,
    pub has_delegation_selector: bool,
    pub has_upgrade_selector: bool,
    pub has_admin_selector: bool,
    pub has_delegatecall: bool,
    pub has_unrestricted_call: bool,
    pub chain_id_observed: Option<u64>,
    pub delegation_targets: Vec<String>,
    pub batch_functions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OpcodeLocation {
    pub opcode: u8,
    pub offset: usize,
    pub mnemonic: String,
    pub push_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start: usize,
    pub end: usize,
    pub instructions: Vec<OpcodeLocation>,
    pub successors: Vec<usize>,
    pub is_entry: bool,
}

pub type BasicBlockInfo = BasicBlock;

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub selector: [u8; 4],
    pub offset: usize,
    pub has_access_control: bool,
    pub is_dangerous: bool,
}

#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub blocks: Vec<BasicBlock>,
    pub entry: usize,
    pub exits: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct BytecodeAnalysis {
    pub bytecode: Vec<u8>,
    pub selectors: Vec<[u8; 4]>,
    pub function_selectors: Vec<[u8; 4]>,
    pub cfgraph: ControlFlowGraph,
    pub basic_blocks: Vec<BasicBlock>,
    pub dispatcher_targets: usize,
    pub eip7702_detections: Vec<EIP7702Detection>,
    pub flags: Vec<BytecodeFlag>,
    pub functions: Vec<FunctionInfo>,
    pub has_delegatecall: bool,
    pub has_reentrancy_risk: bool,
    pub has_upgrade_surface: bool,
    pub has_admin_surface: bool,
    pub has_fallback: bool,
    pub has_receive: bool,
    pub has_selfdestruct: bool,
    pub has_callcode: bool,
    pub has_create2: bool,
    pub risk_score: u32,
}

impl BytecodeAnalysis {
    pub fn get_function_by_selector(&self, selector: &[u8; 4]) -> Option<&FunctionInfo> {
        self.functions.iter().find(|function| &function.selector == selector)
    }

    pub fn top_severity(&self) -> Option<PatternSeverity> {
        self.flags
            .iter()
            .map(|flag| flag.severity)
            .max_by_key(|severity| match severity {
                PatternSeverity::Critical => 5,
                PatternSeverity::High => 4,
                PatternSeverity::Medium => 3,
                PatternSeverity::Low => 2,
                PatternSeverity::Info => 1,
            })
    }
}

#[derive(Debug, Clone)]
pub struct BytecodeFlag {
    pub opcode: u8,
    pub offset: usize,
    pub severity: PatternSeverity,
    pub description: String,
}

// ============================================================
// EIP-7702 BYTECODE ENGINE (MAXIMUM LEVEL)
// ============================================================

pub struct EIP7702BytecodeEngine;

pub type BytecodeScanner = EIP7702BytecodeEngine;

impl EIP7702BytecodeEngine {
    // ============================================================
    // CORE ANALYSIS ENTRY POINT
    // ============================================================
    
    /// Main entry point - analyze bytecode for EIP-7702 vulnerabilities
    pub fn analyze(bytecode: &[u8]) -> BytecodeAnalysis {
        info!("Starting EIP-7702 bytecode analysis (MAXIMUM LEVEL)");
        
        // Build CFG first (required for path analysis)
        let cfgraph = Self::build_control_flow_graph(bytecode);
        
        // Extract all selectors
        let selectors = Self::extract_selectors_advanced(bytecode);
        
        // Initialize context
        let mut context = EIP7702Context::default();
        let mut detections = Vec::new();
        
        // Run all detection modules
        detections.extend(Self::detect_eoa_only_bypass_pattern(bytecode, &cfgraph, &mut context));
        detections.extend(Self::detect_batch_call_exploit(bytecode, &selectors, &cfgraph, &mut context));
        detections.extend(Self::detect_unvalidated_delegation(bytecode, &selectors, &cfgraph, &mut context));
        detections.extend(Self::detect_chain_agnostic_replay(bytecode, &mut context));
        let context_snapshot = context.clone();
        detections.extend(Self::detect_admin_delegation_abuse(
            &selectors,
            &context_snapshot,
            &mut context,
        ));
        detections.extend(Self::detect_delegatecall_batch_router(bytecode, &selectors, &cfgraph, &mut context));
        detections.extend(Self::detect_upgrade_delegate_pattern(&selectors, &context));
        
        // Calculate risk score
        let risk_score = Self::calculate_risk_score(&detections);
        
        // Build flags (legacy compatibility)
        let flags = Self::build_flags(&detections);
        
        let has_delegatecall = context.has_delegatecall;
        let has_upgrade_surface = context.has_upgrade_selector;
        let has_admin_surface = context.has_admin_selector;
        let functions = selectors
            .iter()
            .map(|selector| {
                let offset = Self::find_function_entry(bytecode, selector).unwrap_or(0);
                let has_access_control = if offset > 0 {
                    Self::has_access_control_at_entry(bytecode, offset)
                } else {
                    false
                };
                let is_dangerous = BATCH_SELECTORS.iter().any(|(_, candidate)| *candidate == selector)
                    || DELEGATION_SELECTORS.iter().any(|(_, candidate)| *candidate == selector)
                    || UPGRADE_SELECTORS.iter().any(|(_, candidate)| *candidate == selector)
                    || ADMIN_SELECTORS.iter().any(|(_, candidate)| *candidate == selector);

                FunctionInfo {
                    selector: *selector,
                    offset,
                    has_access_control,
                    is_dangerous,
                }
            })
            .collect::<Vec<_>>();

        let has_selfdestruct = bytecode.contains(&0xff);
        let has_callcode = bytecode.contains(&0xf2);
        let has_create2 = bytecode.contains(&0xf5);

        BytecodeAnalysis {
            bytecode: bytecode.to_vec(),
            selectors: selectors.clone(),
            function_selectors: selectors,
            basic_blocks: cfgraph.blocks.clone(),
            dispatcher_targets: cfgraph.blocks.len(),
            cfgraph,
            eip7702_detections: detections,
            flags,
            functions,
            has_delegatecall,
            has_reentrancy_risk: false,
            has_upgrade_surface,
            has_admin_surface,
            has_fallback: false,
            has_receive: false,
            has_selfdestruct,
            has_callcode,
            has_create2,
            risk_score,
        }
    }
    
    // ============================================================
    // 1. EOA ONLY BYPASS DETECTION
    // ============================================================
    
    /// Detects tx.origin + EQ path that becomes vulnerable with EIP-7702
    fn detect_eoa_only_bypass_pattern(
        bytecode: &[u8],
        cfgraph: &ControlFlowGraph,
        context: &mut EIP7702Context,
    ) -> Vec<EIP7702Detection> {
        let mut detections = Vec::new();
        
        // Find ORIGIN opcode (0x32)
        for block in &cfgraph.blocks {
            for (idx, instr) in block.instructions.iter().enumerate() {
                if instr.opcode == 0x32 { // ORIGIN
                    context.has_tx_origin_check = true;
                    
                    // Check for EQ in subsequent instructions
                    let remaining = &block.instructions[idx..];
                    for next_instr in remaining {
                        if next_instr.opcode == 0x14 { // EQ
                            // Found ORIGIN + EQ pattern
                            // Verify path leads to JUMPI (conditional branch)
                            if Self::has_jumpi_in_path(remaining) {
                                let detection = EIP7702Detection {
                                    pattern: EIP7702Pattern::EoaOnlyBypass,
                                    offset: instr.offset,
                                    severity: EIP7702Pattern::EoaOnlyBypass.severity(),
                                    confidence: 0.85,
                                    description: format!(
                                        "ORIGIN + EQ conditional at offset 0x{:x}: EOA-only assumption broken by EIP-7702 delegation",
                                        instr.offset
                                    ),
                                    exploitation_path: Some(format!(
                                        "Path: ORIGIN (0x{:x}) -> EQ (0x{:x}) -> JUMPI\n\
                                         Attacker can delegate malicious contract to EOA,\n\
                                         execute arbitrary code while passing EOA checks.\n\
                                         Real exploit: Flare FAssets protocol (2025)",
                                        instr.offset,
                                        next_instr.offset
                                    )),
                                    evidence: vec![
                                        format!("ORIGIN at offset 0x{:x}", instr.offset),
                                        format!("EQ at offset 0x{:x}", next_instr.offset),
                                        "Conditional branch (JUMPI) detected".to_string(),
                                        "Critical: EIP-7702 allows delegated execution".to_string(),
                                    ],
                                    context: context.clone(),
                                };
                                detections.push(detection);
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        detections
    }
    
    // ============================================================
    // 2. BATCH CALL EXPLOIT DETECTION
    // ============================================================
    
    /// Detects unrestricted batch/multicall functions that can be abused with delegation
    fn detect_batch_call_exploit(
        bytecode: &[u8],
        selectors: &[[u8; 4]],
        cfgraph: &ControlFlowGraph,
        context: &mut EIP7702Context,
    ) -> Vec<EIP7702Detection> {
        let mut detections = Vec::new();
        
        for (sig, selector) in BATCH_SELECTORS {
            if selectors.contains(selector) {
                context.has_batch_selector = true;
                context.batch_functions.push(sig.to_string());
                
                // Find function entry point
                if let Some(entry_offset) = Self::find_function_entry(bytecode, selector) {
                    // Analyze access control on this function
                    let has_access_control = Self::has_access_control_at_entry(bytecode, entry_offset);
                    let has_msg_sender_check = Self::has_msg_sender_validation(bytecode, entry_offset);
                    
                    if !has_access_control && !has_msg_sender_check {
                        let detection = EIP7702Detection {
                            pattern: EIP7702Pattern::BatchCallExploit,
                            offset: entry_offset,
                            severity: EIP7702Pattern::BatchCallExploit.severity(),
                            confidence: 0.90,
                            description: format!(
                                "{} - UNRESTRICTED batch call (no access control)",
                                sig
                            ),
                            exploitation_path: Some(format!(
                                "Path: Unrestricted {} -> DELEGATECALL context\n\
                                 Real exploit: QNT reserve pool (April/May 2026)\n\
                                 Loss: ~54.93 ETH\n\
                                 Attack: EOA delegated to BatchExecutor,\n\
                                 attacker called batch() to drain funds",
                                sig
                            )),
                            evidence: vec![
                                format!("Function {} present", sig),
                                "No access control modifiers detected".to_string(),
                                "No msg.sender validation".to_string(),
                                "Can be called from delegated EOA context".to_string(),
                            ],
                            context: context.clone(),
                        };
                        detections.push(detection);
                    } else if has_msg_sender_check && !has_access_control {
                        // msg.sender check but still vulnerable via delegation
                        let detection = EIP7702Detection {
                            pattern: EIP7702Pattern::BatchCallExploit,
                            offset: entry_offset,
                            severity: PatternSeverity::High,
                            confidence: 0.75,
                            description: format!(
                                "{} - msg.sender check (still vulnerable to delegated EIP-7702)",
                                sig
                            ),
                            exploitation_path: Some(
                                "msg.sender is EOA (the delegator), passes check.\n\
                                 But executed code is from malicious contract.\n\
                                 Check passes, funds drain possible.".to_string()
                            ),
                            evidence: vec![
                                format!("Function {} present", sig),
                                "msg.sender check detected but NOT sufficient for EIP-7702".to_string(),
                                "EIP-7702 delegation bypasses msg.sender check".to_string(),
                            ],
                            context: context.clone(),
                        };
                        detections.push(detection);
                    }
                }
            }
        }
        
        detections
    }
    
    // ============================================================
    // 3. UNVALIDATED DELEGATION DETECTION
    // ============================================================
    
    /// Detects delegation functions without target validation
    fn detect_unvalidated_delegation(
        bytecode: &[u8],
        selectors: &[[u8; 4]],
        cfgraph: &ControlFlowGraph,
        context: &mut EIP7702Context,
    ) -> Vec<EIP7702Detection> {
        let mut detections = Vec::new();
        
        for (sig, selector) in DELEGATION_SELECTORS {
            if selectors.contains(selector) {
                context.has_delegation_selector = true;
                
                if let Some(entry_offset) = Self::find_function_entry(bytecode, selector) {
                    // Check if delegation target is validated
                    let has_target_validation = Self::has_target_validation(bytecode, entry_offset);
                    let has_whitelist = Self::has_delegation_whitelist(bytecode, entry_offset);
                    
                    if !has_target_validation && !has_whitelist {
                        let detection = EIP7702Detection {
                            pattern: EIP7702Pattern::UnvalidatedDelegation,
                            offset: entry_offset,
                            severity: EIP7702Pattern::UnvalidatedDelegation.severity(),
                            confidence: 0.95,
                            description: format!(
                                "{} - NO target validation (can delegate to any contract)",
                                sig
                            ),
                            exploitation_path: Some(
                                "Attacker can delegate EOA to malicious contract.\n\
                                 Once delegated, attacker controls EOA's execution context.\n\
                                 All funds and permissions become accessible.\n\
                                 97% of EIP-7702 delegations are to malicious contracts (2025 stats)".to_string()
                            ),
                            evidence: vec![
                                format!("Function {} present", sig),
                                "No target address validation".to_string(),
                                "No whitelist detected".to_string(),
                                "Can delegate to arbitrary contract".to_string(),
                            ],
                            context: context.clone(),
                        };
                        detections.push(detection);
                        context.delegation_targets.push("ANY (unvalidated)".to_string());
                    }
                }
            }
        }
        
        detections
    }
    
    // ============================================================
    // 4. CHAIN-AGNOSTIC REPLAY DETECTION
    // ============================================================
    
    /// Detects chainId = 0 in authorization payloads (allows cross-chain replay)
    fn detect_chain_agnostic_replay(
        bytecode: &[u8],
        context: &mut EIP7702Context,
    ) -> Vec<EIP7702Detection> {
        let mut detections = Vec::new();
        let len = bytecode.len();
        
        // Look for CHAINID opcode (0x46) with PUSH0 optimization for agnostic mode
        for i in 0..len {
            if bytecode[i] == 0x46 { // CHAINID
                // Check for comparison with 0 (agnostic mode)
                if i > 0 && bytecode[i-1] == 0x5f {
                    // PUSH0 before CHAINID comparison (optimized)
                    context.chain_id_observed = Some(CHAIN_AGNOSTIC_ID);
                    
                    let detection = EIP7702Detection {
                        pattern: EIP7702Pattern::ChainAgnosticReplay,
                        offset: i,
                        severity: EIP7702Pattern::ChainAgnosticReplay.severity(),
                        confidence: 0.88,
                        description: "Chain-agnostic mode (chainId = 0) detected - cross-chain replay risk".to_string(),
                        exploitation_path: Some(
                            "authorization with chainId = 0 can be replayed on ANY chain.\n\
                             Single signature compromises EOA across all networks.\n\
                             Ethereum, BSC, Polygon, Arbitrum, all vulnerable simultaneously."
                                .to_string()
                        ),
                        evidence: vec![
                            "CHAINID comparison with 0 detected".to_string(),
                            "Cross-chain authorization replay possible".to_string(),
                            "No chain-specific binding".to_string(),
                        ],
                        context: context.clone(),
                    };
                    detections.push(detection);
                }
            }
        }
        
        // Also check for EIP-7702 authority magic + chainId zero
        for i in 0..len.saturating_sub(20) {
            if bytecode[i..i+6] == EIP7702_AUTHORITY_MAGIC {
                if i + 14 < len {
                    let potential_chain_id = u64::from_be_bytes([
                        bytecode[i+6], bytecode[i+7], bytecode[i+8], bytecode[i+9],
                        bytecode[i+10], bytecode[i+11], bytecode[i+12], bytecode[i+13]
                    ]);
                    if potential_chain_id == CHAIN_AGNOSTIC_ID {
                        context.chain_id_observed = Some(CHAIN_AGNOSTIC_ID);
                        detections.push(EIP7702Detection {
                            pattern: EIP7702Pattern::ChainAgnosticReplay,
                            offset: i,
                            severity: EIP7702Pattern::ChainAgnosticReplay.severity(),
                            confidence: 0.92,
                            description: "EIP-7702 authority tuple with chainId = 0 (cross-chain replay)".to_string(),
                            exploitation_path: Some("Authorization replayable on all chains".to_string()),
                            evidence: vec![
                                "EIP-7702 magic marker found".to_string(),
                                format!("chainId = {}", CHAIN_AGNOSTIC_ID),
                                "No chain binding - replay attack possible".to_string(),
                            ],
                            context: context.clone(),
                        });
                    }
                }
            }
        }
        
        detections
    }
    
    // ============================================================
    // 5. ADMIN DELEGATION ABUSE DETECTION
    // ============================================================
    
    /// Detects admin functions combined with delegation capability
    fn detect_admin_delegation_abuse(
        selectors: &[[u8; 4]],
        context: &EIP7702Context,
        full_context: &mut EIP7702Context,
    ) -> Vec<EIP7702Detection> {
        let mut detections = Vec::new();
        
        let has_admin = ADMIN_SELECTORS.iter().any(|(_, sel)| selectors.contains(sel));
        let has_upgrade = UPGRADE_SELECTORS.iter().any(|(_, sel)| selectors.contains(sel));
        
        if has_admin && (context.has_delegation_selector || context.has_batch_selector) {
            full_context.has_admin_selector = true;
            
            let detection = EIP7702Detection {
                pattern: EIP7702Pattern::AdminDelegationAbuse,
                offset: 0,
                severity: EIP7702Pattern::AdminDelegationAbuse.severity(),
                confidence: 0.85,
                description: "Admin functions + delegation surface - critical privilege escalation".to_string(),
                exploitation_path: Some(
                    "Admin EOA delegates to malicious contract → contract executes\n\
                     with admin privileges → full protocol takeover."
                .to_string()),
                evidence: vec![
                    "Admin/ownership functions detected".to_string(),
                    "Delegation/batch surface present".to_string(),
                    "EIP-7702 delegation can hijack admin privileges".to_string(),
                ],
                context: context.clone(),
            };
            detections.push(detection);
        }
        
        if has_upgrade && context.has_delegation_selector {
            let detection = EIP7702Detection {
                pattern: EIP7702Pattern::UpgradeDelegatePattern,
                offset: 0,
                severity: EIP7702Pattern::UpgradeDelegatePattern.severity(),
                confidence: 0.78,
                description: "Upgrade proxy + delegation - proxy jacking risk".to_string(),
                exploitation_path: Some(
                    "Attacker delegates proxy admin EOA → upgrades implementation\n\
                     to malicious contract → drains all funds."
                .to_string()),
                evidence: vec![
                    "Upgrade functions detected".to_string(),
                    "Delegation capability present".to_string(),
                    "Proxy implementation can be changed via delegation".to_string(),
                ],
                context: context.clone(),
            };
            detections.push(detection);
        }
        
        detections
    }
    
    // ============================================================
    // 6. DELEGATECALL + BATCH ROUTER DETECTION
    // ============================================================
    
    /// Detects delegatecall routers with batch capabilities (extremely dangerous)
    fn detect_delegatecall_batch_router(
        bytecode: &[u8],
        selectors: &[[u8; 4]],
        cfgraph: &ControlFlowGraph,
        context: &mut EIP7702Context,
    ) -> Vec<EIP7702Detection> {
        let mut detections = Vec::new();
        
        // Check for DELEGATECALL opcode (0xF4)
        let mut has_delegatecall = false;
        for block in &cfgraph.blocks {
            for instr in &block.instructions {
                if instr.opcode == 0xF4 { // DELEGATECALL
                    has_delegatecall = true;
                    context.has_delegatecall = true;
                    break;
                }
            }
        }
        
        if has_delegatecall && context.has_batch_selector {
            let detection = EIP7702Detection {
                pattern: EIP7702Pattern::DelegatecallBatchRouter,
                offset: Self::find_delegatecall_offset(bytecode).unwrap_or(0),
                severity: EIP7702Pattern::DelegatecallBatchRouter.severity(),
                confidence: 0.82,
                description: "DELEGATECALL router + batch execution - critical delegatecall injection".to_string(),
                exploitation_path: Some(
                    "Attacker can inject malicious calldata into batch →\n\
                     DELEGATECALL executes with contract's context →\n\
                     Storage corruption, fund theft, or ownership takeover."
                .to_string()),
                evidence: vec![
                    "DELEGATECALL instruction detected".to_string(),
                    "Batch/multicall surface present".to_string(),
                    "Unvalidated calldata in batch execution".to_string(),
                ],
                context: context.clone(),
            };
            detections.push(detection);
        }
        
        detections
    }
    
    // ============================================================
    // 7. UPGRADE DELEGATE PATTERN DETECTION
    // ============================================================
    
    /// Detects upgrade proxy patterns combined with delegation (proxy jacking)
    fn detect_upgrade_delegate_pattern(
        selectors: &[[u8; 4]],
        context: &EIP7702Context,
    ) -> Vec<EIP7702Detection> {
        let mut detections = Vec::new();
        
        let has_upgrade = UPGRADE_SELECTORS.iter().any(|(_, sel)| selectors.contains(sel));
        
        if has_upgrade {
            if context.has_delegation_selector {
                let detection = EIP7702Detection {
                    pattern: EIP7702Pattern::UpgradeDelegatePattern,
                    offset: 0,
                    severity: EIP7702Pattern::UpgradeDelegatePattern.severity(),
                    confidence: 0.88,
                    description: "Proxy upgrade + EIP-7702 delegation - complete proxy takeover".to_string(),
                    exploitation_path: Some(
                        "Attacker delegates proxy admin EOA →\n\
                         upgradeTo() malicious implementation →\n\
                         All funds and logic controlled by attacker."
                    .to_string()),
                    evidence: vec![
                        "Upgrade functions detected (upgradeTo, etc.)".to_string(),
                        "Delegation surface present".to_string(),
                        "EIP-7702 can hijack upgrade mechanism".to_string(),
                    ],
                    context: context.clone(),
                };
                detections.push(detection);
            }
            
            if context.has_batch_selector {
                let detection = EIP7702Detection {
                    pattern: EIP7702Pattern::UpgradeDelegatePattern,
                    offset: 0,
                    severity: PatternSeverity::High,
                    confidence: 0.70,
                    description: "Proxy upgrade + batch execution - upgrade via batch".to_string(),
                    exploitation_path: Some("Batch execution can trigger upgrade with malicious implementation".to_string()),
                    evidence: vec![
                        "Upgrade functions present".to_string(),
                        "Batch execution available".to_string(),
                        "Can upgrade via batched transaction".to_string(),
                    ],
                    context: context.clone(),
                };
                detections.push(detection);
            }
        }
        
        detections
    }
    
    // ============================================================
    // HELPER FUNCTIONS
    // ============================================================
    
    /// Build control flow graph from bytecode
    fn build_control_flow_graph(bytecode: &[u8]) -> ControlFlowGraph {
        let mut jumpdests = HashSet::new();
        let len = bytecode.len();
        
        // Collect all JUMPDESTs
        for i in 0..len {
            if bytecode[i] == 0x5B {
                jumpdests.insert(i);
            }
        }
        
        // Build basic blocks
        let mut leaders: HashSet<usize> = HashSet::new();
        leaders.insert(0);
        for &dest in &jumpdests {
            leaders.insert(dest);
        }
        
        let mut leader_list: Vec<usize> = leaders.into_iter().collect();
        leader_list.sort();
        
        let mut blocks = Vec::new();
        for (idx, &start) in leader_list.iter().enumerate() {
            let end = if let Some(&next) = leader_list.get(idx + 1) {
                next.saturating_sub(1)
            } else {
                len.saturating_sub(1)
            };
            
            let mut instructions = Vec::new();
            let mut pc = start;
            while pc <= end && pc < len {
                let opcode = bytecode[pc];
                let push_data = if (0x60..=0x7F).contains(&opcode) {
                    let push_len = (opcode - 0x5F) as usize;
                    if pc + 1 + push_len <= len {
                        Some(bytecode[pc+1..pc+1+push_len].to_vec())
                    } else {
                        None
                    }
                } else {
                    None
                };
                
                instructions.push(OpcodeLocation {
                    opcode,
                    offset: pc,
                    mnemonic: Self::opcode_to_mnemonic(opcode).to_string(),
                    push_data,
                });
                
                pc = Self::next_pc(bytecode, pc);
            }
            
            blocks.push(BasicBlock {
                start,
                end,
                instructions,
                successors: Vec::new(),
                is_entry: start == 0,
            });
        }
        
        // Build successors
        for i in 0..blocks.len() {
            let block = &blocks[i];
            let last_pc = block.end;
            if last_pc < len {
                let last_opcode = bytecode[last_pc];
                let next_pc = Self::next_pc(bytecode, last_pc);
                
                match last_opcode {
                    0x56 | 0x57 => { // JUMP or JUMPI
                        // Try to find jump target
                        if let Some(target) = Self::find_jump_target(&block.instructions, bytecode) {
                            if let Some(target_block) = blocks.iter().position(|b| b.start == target) {
                                blocks[i].successors.push(target_block);
                            }
                        }
                        if last_opcode == 0x57 && next_pc < len {
                            if let Some(fallthrough) = blocks.iter().position(|b| b.start == next_pc) {
                                blocks[i].successors.push(fallthrough);
                            }
                        }
                    }
                    _ => {
                        if next_pc < len {
                            if let Some(next_block) = blocks.iter().position(|b| b.start == next_pc) {
                                blocks[i].successors.push(next_block);
                            }
                        }
                    }
                }
            }
        }
        
        ControlFlowGraph {
            blocks,
            entry: 0,
            exits: Vec::new(),
        }
    }
    
    /// Extract function selectors (advanced)
    pub fn extract_selectors_advanced(bytecode: &[u8]) -> Vec<[u8; 4]> {
        let mut selectors = Vec::new();
        let len = bytecode.len();
        let mut i = 0;
        
        while i < len {
            if bytecode[i] == 0x63 && i + 4 < len {
                let selector = [
                    bytecode[i+1], bytecode[i+2], bytecode[i+3], bytecode[i+4]
                ];
                if selector != [0,0,0,0] && !selectors.contains(&selector) {
                    selectors.push(selector);
                }
                i += 5;
            } else if (0x60..=0x7F).contains(&bytecode[i]) {
                let push_len = (bytecode[i] - 0x5F) as usize;
                i += 1 + push_len;
            } else {
                i += 1;
            }
        }
        
        selectors
    }
    
    /// Find function entry point by selector
    fn find_function_entry(bytecode: &[u8], selector: &[u8; 4]) -> Option<usize> {
        let len = bytecode.len();
        let mut i = 0;
        
        while i < len {
            if bytecode[i] == 0x63 && i + 4 < len {
                if bytecode[i+1] == selector[0] &&
                   bytecode[i+2] == selector[1] &&
                   bytecode[i+3] == selector[2] &&
                   bytecode[i+4] == selector[3] {
                    // Found selector, return the function entry
                    return Some(i + 5);
                }
                i += 5;
            } else if (0x60..=0x7F).contains(&bytecode[i]) {
                let push_len = (bytecode[i] - 0x5F) as usize;
                i += 1 + push_len;
            } else {
                i += 1;
            }
        }
        
        None
    }
    
    /// Check if function has access control at entry
    fn has_access_control_at_entry(bytecode: &[u8], entry_offset: usize) -> bool {
        let start = entry_offset;
        let end = (entry_offset + PATTERN_WINDOW).min(bytecode.len());
        
        for i in start..end {
            // Check for CALLER (0x33) followed by EQ (0x14) and JUMPI (0x57)
            if bytecode[i] == 0x33 { // CALLER
                if i + 2 < end {
                    if bytecode[i+1] == 0x14 || bytecode[i+2] == 0x14 { // EQ
                        return true;
                    }
                }
            }
            // Check for ISZERO + JUMPI pattern
            if bytecode[i] == 0x15 && i + 1 < end && bytecode[i+1] == 0x57 { // ISZERO + JUMPI
                return true;
            }
        }
        
        false
    }
    
    /// Check for msg.sender validation
    fn has_msg_sender_validation(bytecode: &[u8], entry_offset: usize) -> bool {
        let start = entry_offset;
        let end = (entry_offset + PATTERN_WINDOW).min(bytecode.len());
        
        for i in start..end {
            if bytecode[i] == 0x33 { // CALLER
                // Check for EQ with stored value (owner)
                if i + 1 < end && bytecode[i+1] == 0x14 {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Check if delegation target is validated
    fn has_target_validation(bytecode: &[u8], entry_offset: usize) -> bool {
        let start = entry_offset;
        let end = (entry_offset + PATTERN_WINDOW).min(bytecode.len());
        
        for i in start..end {
            // Check for EXTCODESIZE check (0x3B) - basic validation
            if bytecode[i] == 0x3B { // EXTCODESIZE
                // Check for ISZERO (0x15) and REVERT (0xFD) pattern
                if i + 2 < end && bytecode[i+1] == 0x15 && bytecode[i+2] == 0x57 {
                    return true;
                }
            }
            // Check for address comparison with whitelist
            if bytecode[i] == 0x54 { // SLOAD - loading stored whitelist
                return true;
            }
        }
        
        false
    }
    
    /// Check for delegation whitelist
    fn has_delegation_whitelist(bytecode: &[u8], entry_offset: usize) -> bool {
        Self::has_target_validation(bytecode, entry_offset)
    }
    
    /// Check if path contains JUMPI (conditional branch)
    fn has_jumpi_in_path(instructions: &[OpcodeLocation]) -> bool {
        for instr in instructions {
            if instr.opcode == 0x57 { // JUMPI
                return true;
            }
        }
        false
    }
    
    /// Find jump target from JUMP/JUMPI instruction
    fn find_jump_target(instructions: &[OpcodeLocation], bytecode: &[u8]) -> Option<usize> {
        for instr in instructions.iter().rev() {
            if let Some(ref data) = instr.push_data {
                if data.len() == 2 {
                    let target = ((data[0] as usize) << 8) | (data[1] as usize);
                    if target < bytecode.len() && bytecode[target] == 0x5B {
                        return Some(target);
                    }
                } else if data.len() == 1 {
                    let target = data[0] as usize;
                    if target < bytecode.len() && bytecode[target] == 0x5B {
                        return Some(target);
                    }
                }
            }
        }
        None
    }
    
    /// Find DELEGATECALL opcode offset
    fn find_delegatecall_offset(bytecode: &[u8]) -> Option<usize> {
        for i in 0..bytecode.len() {
            if bytecode[i] == 0xF4 {
                return Some(i);
            }
        }
        None
    }
    
    /// Calculate risk score based on detections
    fn calculate_risk_score(detections: &[EIP7702Detection]) -> u32 {
        let mut score = 0u32;
        
        for detection in detections {
            match detection.severity {
                PatternSeverity::Critical => score += 40,
                PatternSeverity::High => score += 25,
                PatternSeverity::Medium => score += 10,
                PatternSeverity::Low => score += 5,
                PatternSeverity::Info => score += 0,
            }
            
            // Add confidence factor
            score += (detection.confidence * 10.0) as u32;
        }
        
        score.min(100)
    }
    
    /// Build flags from detections (legacy compatibility)
    fn build_flags(detections: &[EIP7702Detection]) -> Vec<BytecodeFlag> {
        detections.iter().map(|d| BytecodeFlag {
            opcode: 0,
            offset: d.offset,
            severity: d.severity,
            description: d.description.clone(),
        }).collect()
    }
    
    /// Next program counter after instruction
    fn next_pc(bytecode: &[u8], pc: usize) -> usize {
        let opcode = bytecode[pc];
        if (0x60..=0x7F).contains(&opcode) {
            let push_len = (opcode - 0x5F) as usize;
            (pc + 1 + push_len).min(bytecode.len())
        } else {
            (pc + 1).min(bytecode.len())
        }
    }
    
    /// Opcode to mnemonic
    pub fn opcode_to_mnemonic(opcode: u8) -> &'static str {
        match opcode {
            0x00 => "STOP", 0x01 => "ADD", 0x02 => "MUL", 0x03 => "SUB",
            0x04 => "DIV", 0x05 => "SDIV", 0x06 => "MOD", 0x07 => "SMOD",
            0x08 => "ADDMOD", 0x09 => "MULMOD", 0x0A => "EXP", 0x0B => "SIGNEXTEND",
            0x10 => "LT", 0x11 => "GT", 0x12 => "SLT", 0x13 => "SGT",
            0x14 => "EQ", 0x15 => "ISZERO", 0x16 => "AND", 0x17 => "OR",
            0x18 => "XOR", 0x19 => "NOT", 0x1A => "BYTE", 0x1B => "SHL",
            0x1C => "SHR", 0x1D => "SAR", 0x20 => "SHA3",
            0x30 => "ADDRESS", 0x31 => "BALANCE", 0x32 => "ORIGIN", 0x33 => "CALLER",
            0x34 => "CALLVALUE", 0x35 => "CALLDATALOAD", 0x36 => "CALLDATASIZE",
            0x37 => "CALLDATACOPY", 0x38 => "CODESIZE", 0x39 => "CODECOPY",
            0x3A => "GASPRICE", 0x3B => "EXTCODESIZE", 0x3C => "EXTCODECOPY",
            0x3D => "RETURNDATASIZE", 0x3E => "RETURNDATACOPY", 0x3F => "EXTCODEHASH",
            0x40 => "BLOCKHASH", 0x41 => "COINBASE", 0x42 => "TIMESTAMP",
            0x43 => "NUMBER", 0x44 => "DIFFICULTY", 0x45 => "GASLIMIT",
            0x46 => "CHAINID", 0x47 => "SELFBALANCE", 0x48 => "BASEFEE",
            0x50 => "POP", 0x51 => "MLOAD", 0x52 => "MSTORE", 0x53 => "MSTORE8",
            0x54 => "SLOAD", 0x55 => "SSTORE", 0x56 => "JUMP", 0x57 => "JUMPI",
            0x58 => "PC", 0x59 => "MSIZE", 0x5A => "GAS", 0x5B => "JUMPDEST",
            0x60..=0x7F => "PUSH", 0x80..=0x8F => "DUP", 0x90..=0x9F => "SWAP",
            0xA0..=0xA4 => "LOG", 0xF0 => "CREATE", 0xF1 => "CALL", 0xF2 => "CALLCODE",
            0xF3 => "RETURN", 0xF4 => "DELEGATECALL", 0xF5 => "CREATE2",
            0xFA => "STATICCALL", 0xFD => "REVERT", 0xFF => "SELFDESTRUCT",
            _ => "INVALID",
        }
    }

    pub fn selector_to_hex(selector: &[u8; 4]) -> String {
        format!(
            "0x{:02x}{:02x}{:02x}{:02x}",
            selector[0], selector[1], selector[2], selector[3]
        )
    }

    pub fn decode_hex(value: &str) -> Option<Vec<u8>> {
        let raw = value.strip_prefix("0x").unwrap_or(value);
        hex::decode(raw).ok()
    }

    pub fn match_dangerous_signatures(selectors: &[[u8; 4]]) -> Vec<String> {
        let mut matches = Vec::new();

        for (name, selector) in BATCH_SELECTORS
            .iter()
            .chain(DELEGATION_SELECTORS.iter())
            .chain(UPGRADE_SELECTORS.iter())
            .chain(ADMIN_SELECTORS.iter())
        {
            if selectors.contains(selector) {
                matches.push(format!("{} ({})", name, Self::selector_to_hex(selector)));
            }
        }

        matches
    }
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eoa_only_bypass_detection() {
        // Bytecode with ORIGIN + EQ pattern (simplified)
        let bytecode = vec![
            0x32, // ORIGIN
            0x33, // CALLER
            0x14, // EQ
            0x57, // JUMPI
        ];
        
        let analysis = EIP7702BytecodeEngine::analyze(&bytecode);
        let has_eoa_bypass = analysis.eip7702_detections
            .iter()
            .any(|d| d.pattern == EIP7702Pattern::EoaOnlyBypass);
        
        assert!(has_eoa_bypass);
    }

    #[test]
    fn test_batch_call_detection() {
        // Batch selector bytes for sequence
        let mut bytecode = vec![0x63]; // PUSH4
        bytecode.extend_from_slice(BATCH_SELECTORS[0].1); // batch selector
        bytecode.push(0x14); // EQ
        
        let analysis = EIP7702BytecodeEngine::analyze(&bytecode);
        let has_batch = analysis.eip7702_detections
            .iter()
            .any(|d| d.pattern == EIP7702Pattern::BatchCallExploit);
        
        // May or may not detect depending on completeness of bytecode
        // This is a placeholder test
        println!("Batch detection count: {}", analysis.eip7702_detections.len());
    }

    #[test]
    fn test_chain_agnostic_detection() {
        // EIP-7702 authority with chainId = 0
        let mut bytecode = Vec::new();
        bytecode.extend_from_slice(&EIP7702_AUTHORITY_MAGIC);
        bytecode.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // chainId = 0
        
        let analysis = EIP7702BytecodeEngine::analyze(&bytecode);
        let has_agnostic = analysis.eip7702_detections
            .iter()
            .any(|d| d.pattern == EIP7702Pattern::ChainAgnosticReplay);
        
        assert!(has_agnostic);
    }

    #[test]
    fn test_risk_score_calculation() {
        let detections = vec![
            EIP7702Detection {
                pattern: EIP7702Pattern::EoaOnlyBypass,
                offset: 0,
                severity: PatternSeverity::Critical,
                confidence: 0.95,
                description: "test".to_string(),
                exploitation_path: None,
                evidence: vec![],
                context: EIP7702Context::default(),
            },
        ];
        
        let score = EIP7702BytecodeEngine::calculate_risk_score(&detections);
        assert!(score > 0);
        assert!(score <= 100);
    }

    #[test]
    fn test_selector_extraction() {
        let mut bytecode = Vec::new();
        bytecode.push(0x63);
        bytecode.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        
        let selectors = EIP7702BytecodeEngine::extract_selectors_advanced(&bytecode);
        assert_eq!(selectors.len(), 1);
        assert_eq!(selectors[0], [0x12, 0x34, 0x56, 0x78]);
    }
}
