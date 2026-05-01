// src/bytecode.rs
//! forthres Bytecode Analysis Module
//!
//! Advanced EVM bytecode analysis with:
//! - Full opcode detection (all dangerous patterns)
//! - Function selector extraction with jump table support
//! - Access control pattern detection
//! - Storage layout inference
//! - Integration with offensive modules

use sha3::{Digest, Keccak256};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

// ============================================================
// OPCODE CONSTANTS
// ============================================================

pub const OPCODE_STOP: u8 = 0x00;
pub const OPCODE_ADD: u8 = 0x01;
pub const OPCODE_MUL: u8 = 0x02;
pub const OPCODE_SUB: u8 = 0x03;
pub const OPCODE_DIV: u8 = 0x04;
pub const OPCODE_SDIV: u8 = 0x05;
pub const OPCODE_MOD: u8 = 0x06;
pub const OPCODE_SMOD: u8 = 0x07;
pub const OPCODE_ADDMOD: u8 = 0x08;
pub const OPCODE_MULMOD: u8 = 0x09;
pub const OPCODE_EXP: u8 = 0x0A;
pub const OPCODE_SIGNEXTEND: u8 = 0x0B;

pub const OPCODE_LT: u8 = 0x10;
pub const OPCODE_GT: u8 = 0x11;
pub const OPCODE_SLT: u8 = 0x12;
pub const OPCODE_SGT: u8 = 0x13;
pub const OPCODE_EQ: u8 = 0x14;
pub const OPCODE_ISZERO: u8 = 0x15;
pub const OPCODE_AND: u8 = 0x16;
pub const OPCODE_OR: u8 = 0x17;
pub const OPCODE_XOR: u8 = 0x18;
pub const OPCODE_NOT: u8 = 0x19;
pub const OPCODE_BYTE: u8 = 0x1A;
pub const OPCODE_SHL: u8 = 0x1B;
pub const OPCODE_SHR: u8 = 0x1C;
pub const OPCODE_SAR: u8 = 0x1D;

pub const OPCODE_SHA3: u8 = 0x20;

pub const OPCODE_ADDRESS: u8 = 0x30;
pub const OPCODE_BALANCE: u8 = 0x31;
pub const OPCODE_ORIGIN: u8 = 0x32;
pub const OPCODE_CALLER: u8 = 0x33;
pub const OPCODE_CALLVALUE: u8 = 0x34;
pub const OPCODE_CALLDATALOAD: u8 = 0x35;
pub const OPCODE_CALLDATASIZE: u8 = 0x36;
pub const OPCODE_CALLDATACOPY: u8 = 0x37;
pub const OPCODE_CODESIZE: u8 = 0x38;
pub const OPCODE_CODECOPY: u8 = 0x39;
pub const OPCODE_GASPRICE: u8 = 0x3A;
pub const OPCODE_EXTCODESIZE: u8 = 0x3B;
pub const OPCODE_EXTCODECOPY: u8 = 0x3C;
pub const OPCODE_RETURNDATASIZE: u8 = 0x3D;
pub const OPCODE_RETURNDATACOPY: u8 = 0x3E;
pub const OPCODE_EXTCODEHASH: u8 = 0x3F;

pub const OPCODE_BLOCKHASH: u8 = 0x40;
pub const OPCODE_COINBASE: u8 = 0x41;
pub const OPCODE_TIMESTAMP: u8 = 0x42;
pub const OPCODE_NUMBER: u8 = 0x43;
pub const OPCODE_DIFFICULTY: u8 = 0x44;
pub const OPCODE_GASLIMIT: u8 = 0x45;
pub const OPCODE_CHAINID: u8 = 0x46;
pub const OPCODE_SELFBALANCE: u8 = 0x47;
pub const OPCODE_BASEFEE: u8 = 0x48;

pub const OPCODE_POP: u8 = 0x50;
pub const OPCODE_MLOAD: u8 = 0x51;
pub const OPCODE_MSTORE: u8 = 0x52;
pub const OPCODE_MSTORE8: u8 = 0x53;
pub const OPCODE_SLOAD: u8 = 0x54;
pub const OPCODE_SSTORE: u8 = 0x55;
pub const OPCODE_JUMP: u8 = 0x56;
pub const OPCODE_JUMPI: u8 = 0x57;
pub const OPCODE_PC: u8 = 0x58;
pub const OPCODE_MSIZE: u8 = 0x59;
pub const OPCODE_GAS: u8 = 0x5A;
pub const OPCODE_JUMPDEST: u8 = 0x5B;

pub const OPCODE_PUSH1: u8 = 0x60;
pub const OPCODE_PUSH32: u8 = 0x7F;
pub const OPCODE_DUP1: u8 = 0x80;
pub const OPCODE_DUP16: u8 = 0x8F;
pub const OPCODE_SWAP1: u8 = 0x90;
pub const OPCODE_SWAP16: u8 = 0x9F;

pub const OPCODE_LOG0: u8 = 0xA0;
pub const OPCODE_LOG4: u8 = 0xA4;

pub const OPCODE_CREATE: u8 = 0xF0;
pub const OPCODE_CALL: u8 = 0xF1;
pub const OPCODE_CALLCODE: u8 = 0xF2;
pub const OPCODE_RETURN: u8 = 0xF3;
pub const OPCODE_DELEGATECALL: u8 = 0xF4;
pub const OPCODE_CREATE2: u8 = 0xF5;
pub const OPCODE_STATICCALL: u8 = 0xFA;
pub const OPCODE_REVERT: u8 = 0xFD;
pub const OPCODE_SELFDESTRUCT: u8 = 0xFF;

// ============================================================
// SEVERITY AND PATTERN TYPES
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for PatternSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
pub struct BytecodeFlag {
    pub opcode: u8,
    pub offset: usize,
    pub severity: PatternSeverity,
    pub description: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub selector: [u8; 4],
    pub offset: usize,
    pub signature: Option<String>,
    pub is_dangerous: bool,
    pub has_access_control: bool,
}

#[derive(Debug, Clone)]
pub struct AccessControlInfo {
    pub pattern_type: AccessControlPattern,
    pub offset: usize,
    pub expected_caller: Option<String>,
    pub storage_slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AccessControlPattern {
    OnlyOwner,
    OnlyRole,
    OnlyAdmin,
    CustomCheck,
    None,
}

#[derive(Debug, Clone)]
pub struct StorageSlotInfo {
    pub slot: u64,
    pub inferred_type: StorageType,
    pub is_owner_slot: bool,
    pub is_admin_slot: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StorageType {
    Address,
    Uint256,
    Bool,
    Mapping,
    Array,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct BytecodeAnalysis {
    pub function_selectors: Vec<[u8; 4]>,
    pub functions: Vec<FunctionInfo>,
    pub flags: Vec<BytecodeFlag>,
    pub has_selfdestruct: bool,
    pub has_delegatecall: bool,
    pub has_callcode: bool,
    pub has_create2: bool,
    pub has_reentrancy_risk: bool,
    pub access_controls: Vec<AccessControlInfo>,
    pub storage_layout: Vec<StorageSlotInfo>,
    pub risk_score: u32,
    pub bytecode: Vec<u8>,  // Agora obrigatório
    pub jumpdests: HashSet<usize>,
    pub basic_blocks: Vec<BasicBlockInfo>,
    pub has_fallback: bool,
    pub has_receive: bool,
    pub dispatcher_targets: usize,
    pub has_upgrade_surface: bool,
    pub has_admin_surface: bool,
}

#[derive(Debug, Clone)]
pub struct BasicBlockInfo {
    pub start: usize,
    pub end: usize,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub opcode: u8,
    pub pc: usize,
    pub push_data: Option<Vec<u8>>,
    pub mnemonic: &'static str,
}

impl BytecodeAnalysis {
    pub fn top_severity(&self) -> Option<&PatternSeverity> {
        self.flags
            .iter()
            .find(|flag| flag.severity == PatternSeverity::Critical)
            .map(|flag| &flag.severity)
            .or_else(|| {
                self.flags
                    .iter()
                    .find(|flag| flag.severity == PatternSeverity::High)
                    .map(|flag| &flag.severity)
            })
            .or_else(|| {
                self.flags
                    .iter()
                    .find(|flag| flag.severity == PatternSeverity::Medium)
                    .map(|flag| &flag.severity)
            })
    }
    
    /// Obtém informações de uma função pelo selector
    pub fn get_function_by_selector(&self, selector: &[u8; 4]) -> Option<&FunctionInfo> {
        self.functions.iter().find(|f| f.selector == *selector)
    }
    
    /// Verifica se uma função tem access control
    pub fn function_has_access_control(&self, selector: &[u8; 4]) -> bool {
        self.functions
            .iter()
            .find(|f| f.selector == *selector)
            .map(|f| f.has_access_control)
            .unwrap_or(false)
    }
}

// ============================================================
// BYTECODE SCANNER AUMENTADO
// ============================================================

pub struct BytecodeScanner;

impl BytecodeScanner {
    pub fn decode_hex(hex_str: &str) -> Option<Vec<u8>> {
        let stripped = hex_str.trim_start_matches("0x");
        hex::decode(stripped).ok()
    }

    pub fn selector_from_sig(signature: &str) -> [u8; 4] {
        let mut hasher = Keccak256::new();
        hasher.update(signature.as_bytes());
        let result = hasher.finalize();
        [result[0], result[1], result[2], result[3]]
    }

    /// Extract function selectors with jump table support
    pub fn extract_selectors(bytecode: &[u8]) -> Vec<[u8; 4]> {
        let mut selectors = Vec::new();
        let len = bytecode.len();
        let mut i = 0;

        // First pass: find PUSH4 instructions (0x63)
        while i < len {
            let opcode = bytecode[i];

            match opcode {
                0x63 if i + 4 < len => {
                    let selector = [
                        bytecode[i + 1],
                        bytecode[i + 2],
                        bytecode[i + 3],
                        bytecode[i + 4],
                    ];

                    if selector != [0u8; 4] && selector != [0xFF; 4] && !selectors.contains(&selector)
                    {
                        selectors.push(selector);
                        debug!("Found selector: {}", hex::encode(selector));
                    }

                    i += 5;
                    continue;
                }
                // Detects jump table patterns (common in dispatchers)
                0x56 | 0x57 => { // JUMP or JUMPI
                    // Look for jump table
                    if let Some(table_selectors) = Self::extract_from_jump_table(bytecode, i) {
                        for sel in table_selectors {
                            if !selectors.contains(&sel) {
                                selectors.push(sel);
                            }
                        }
                    }
                    i += 1;
                    continue;
                }
                0x60..=0x7F => {
                    let push_len = (opcode - 0x5F) as usize;
                    i += 1 + push_len;
                    continue;
                }
                _ => {}
            }

            i += 1;
        }

        debug!("Extracted {} function selectors", selectors.len());
        selectors
    }
    
    /// Extract selectors from jump table patterns
    fn extract_from_jump_table(bytecode: &[u8], pc: usize) -> Option<Vec<[u8; 4]>> {
        let mut selectors = Vec::new();
        let search_window = 96;
        let mut offset = pc.saturating_sub(search_window);
        let start = offset;
        
        while offset < pc && offset < bytecode.len() {
            if bytecode[offset] == 0x63 && offset + 4 < bytecode.len() {
                let selector = [
                    bytecode[offset + 1],
                    bytecode[offset + 2],
                    bytecode[offset + 3],
                    bytecode[offset + 4],
                ];
                if selector != [0u8; 4]
                    && selector != [0xFF; 4]
                    && !selectors.contains(&selector)
                {
                    selectors.push(selector);
                }
            }
            offset += 1;
            if offset > start + search_window {
                break; // Limit search
            }
        }
        
        if selectors.is_empty() {
            None
        } else {
            Some(selectors)
        }
    }

    /// Advanced bytecode analysis
    pub fn analyze(bytecode: &[u8]) -> BytecodeAnalysis {
        let mut flags = Vec::new();
        let mut has_selfdestruct = false;
        let mut has_delegatecall = false;
        let mut has_callcode = false;
        let mut has_create2 = false;
        let mut has_reentrancy_risk = false;
        let mut risk_score: u32 = 0;
        let mut access_controls = Vec::new();
        let mut jumpdests = HashSet::new();

        let len = bytecode.len();
        let mut i = 0;

        // First pass: collect all JUMPDESTs
        for pos in 0..len {
            if bytecode[pos] == OPCODE_JUMPDEST {
                jumpdests.insert(pos);
            }
        }

        // Second pass: analyze opcodes
        while i < len {
            let opcode = bytecode[i];

            match opcode {
                OPCODE_SELFDESTRUCT => {
                    has_selfdestruct = true;
                    risk_score += 50;
                    flags.push(BytecodeFlag {
                        opcode,
                        offset: i,
                        severity: PatternSeverity::Critical,
                        description: "SELFDESTRUCT allows contract self-destruction".to_string(),
                        context: None,
                    });
                }
                OPCODE_DELEGATECALL => {
                    has_delegatecall = true;
                    risk_score += 35;
                    flags.push(BytecodeFlag {
                        opcode,
                        offset: i,
                        severity: PatternSeverity::High,
                        description: "DELEGATECALL executes code in caller's context".to_string(),
                        context: None,
                    });
                    if Self::has_sstore_before(bytecode, i) {
                        has_reentrancy_risk = true;
                        risk_score += 15;
                        flags.push(BytecodeFlag {
                            opcode,
                            offset: i,
                            severity: PatternSeverity::Medium,
                            description: "Potential reentrancy: external call after storage write".to_string(),
                            context: None,
                        });
                    }
                }
                OPCODE_CALLCODE => {
                    has_callcode = true;
                    risk_score += 30;
                    flags.push(BytecodeFlag {
                        opcode,
                        offset: i,
                        severity: PatternSeverity::High,
                        description: "CALLCODE (deprecated) similar to delegatecall".to_string(),
                        context: None,
                    });
                    if Self::has_sstore_before(bytecode, i) {
                        has_reentrancy_risk = true;
                        risk_score += 15;
                        flags.push(BytecodeFlag {
                            opcode,
                            offset: i,
                            severity: PatternSeverity::Medium,
                            description: "Potential reentrancy: external call after storage write".to_string(),
                            context: None,
                        });
                    }
                }
                OPCODE_CREATE2 => {
                    has_create2 = true;
                    risk_score += 10;
                    flags.push(BytecodeFlag {
                        opcode,
                        offset: i,
                        severity: PatternSeverity::Medium,
                        description: "CREATE2 allows deterministic contract deployment".to_string(),
                        context: None,
                    });
                }
                OPCODE_CALL => {
                    risk_score += 5;
                    flags.push(BytecodeFlag {
                        opcode,
                        offset: i,
                        severity: PatternSeverity::Low,
                        description: "CALL to external contract".to_string(),
                        context: None,
                    });
                    if Self::has_sstore_before(bytecode, i) {
                        has_reentrancy_risk = true;
                        risk_score += 15;
                        flags.push(BytecodeFlag {
                            opcode,
                            offset: i,
                            severity: PatternSeverity::Medium,
                            description: "Potential reentrancy: external call after storage write".to_string(),
                            context: None,
                        });
                    }
                }
                OPCODE_SSTORE => {
                    risk_score += 8;
                    flags.push(BytecodeFlag {
                        opcode,
                        offset: i,
                        severity: PatternSeverity::Medium,
                        description: "SSTORE writes to storage".to_string(),
                        context: None,
                    });
                }
                OPCODE_SLOAD => {
                    risk_score += 3;
                }
                // Detect onlyOwner pattern
                OPCODE_CALLER => {
                    // Look for EQ and JUMPI pattern
                    if let Some(owner_check) = Self::detect_only_owner_pattern(bytecode, i) {
                        access_controls.push(owner_check);
                        risk_score -= 10; // Good: has access control
                    }
                }
                _ => {}
            }

            // Skip PUSH data
            if (0x60..=0x7F).contains(&opcode) {
                let push_len = (opcode - 0x5F) as usize;
                i += push_len;
            }

            i += 1;
        }

        // Extract function selectors
        let selectors = Self::extract_selectors(bytecode);
        
        // Build function info
        let mut functions = Vec::new();
        for selector in &selectors {
            let func = FunctionInfo {
                selector: *selector,
                offset: Self::find_selector_offset(bytecode, selector),
                signature: None, // Can be resolved from 4byte.directory
                is_dangerous: Self::is_selector_dangerous(selector),
                has_access_control: Self::selector_has_access_control(bytecode, selector),
            };
            functions.push(func);
        }

        // Build basic blocks
        let basic_blocks = Self::build_basic_blocks(bytecode, &jumpdests);
        let has_fallback = Self::detect_fallback_entry(bytecode, &selectors, &basic_blocks);
        let has_receive = Self::detect_receive_entry(bytecode, &selectors, &basic_blocks);
        let dispatcher_targets = basic_blocks
            .iter()
            .filter(|block| {
                block.instructions.iter().any(|inst| {
                    matches!(inst.mnemonic, "CALLDATALOAD" | "CALLDATASIZE" | "JUMPI")
                })
            })
            .count();
        let has_upgrade_surface = has_delegatecall
            || has_create2
            || Self::has_upgrade_selectors(&selectors);
        let has_admin_surface = !access_controls.is_empty()
            || Self::has_admin_selectors(&selectors);

        BytecodeAnalysis {
            function_selectors: selectors,
            functions,
            flags,
            has_selfdestruct,
            has_delegatecall,
            has_callcode,
            has_create2,
            has_reentrancy_risk,
            access_controls,
            storage_layout: Vec::new(), // Can be enhanced with storage inference
            risk_score: risk_score.min(100),
            bytecode: bytecode.to_vec(),
            jumpdests,
            basic_blocks,
            has_fallback,
            has_receive,
            dispatcher_targets,
            has_upgrade_surface,
            has_admin_surface,
        }
    }

    /// Opcode to human-readable mnemonic
    pub fn opcode_to_mnemonic(opcode: u8) -> &'static str {
        match opcode {
            0x00 => "STOP",
            0x01 => "ADD",
            0x02 => "MUL",
            0x03 => "SUB",
            0x04 => "DIV",
            0x05 => "SDIV",
            0x06 => "MOD",
            0x07 => "SMOD",
            0x08 => "ADDMOD",
            0x09 => "MULMOD",
            0x0A => "EXP",
            0x0B => "SIGNEXTEND",
            0x10 => "LT",
            0x11 => "GT",
            0x12 => "SLT",
            0x13 => "SGT",
            0x14 => "EQ",
            0x15 => "ISZERO",
            0x16 => "AND",
            0x17 => "OR",
            0x18 => "XOR",
            0x19 => "NOT",
            0x1A => "BYTE",
            0x1B => "SHL",
            0x1C => "SHR",
            0x1D => "SAR",
            0x20 => "SHA3",
            0x30 => "ADDRESS",
            0x31 => "BALANCE",
            0x32 => "ORIGIN",
            0x33 => "CALLER",
            0x34 => "CALLVALUE",
            0x35 => "CALLDATALOAD",
            0x36 => "CALLDATASIZE",
            0x37 => "CALLDATACOPY",
            0x38 => "CODESIZE",
            0x39 => "CODECOPY",
            0x3A => "GASPRICE",
            0x3B => "EXTCODESIZE",
            0x3C => "EXTCODECOPY",
            0x3D => "RETURNDATASIZE",
            0x3E => "RETURNDATACOPY",
            0x3F => "EXTCODEHASH",
            0x40 => "BLOCKHASH",
            0x41 => "COINBASE",
            0x42 => "TIMESTAMP",
            0x43 => "NUMBER",
            0x44 => "DIFFICULTY",
            0x45 => "GASLIMIT",
            0x46 => "CHAINID",
            0x47 => "SELFBALANCE",
            0x48 => "BASEFEE",
            0x50 => "POP",
            0x51 => "MLOAD",
            0x52 => "MSTORE",
            0x53 => "MSTORE8",
            0x54 => "SLOAD",
            0x55 => "SSTORE",
            0x56 => "JUMP",
            0x57 => "JUMPI",
            0x58 => "PC",
            0x59 => "MSIZE",
            0x5A => "GAS",
            0x5B => "JUMPDEST",
            0x60..=0x7F => "PUSH",
            0x80..=0x8F => "DUP",
            0x90..=0x9F => "SWAP",
            0xA0..=0xA4 => "LOG",
            0xF0 => "CREATE",
            0xF1 => "CALL",
            0xF2 => "CALLCODE",
            0xF3 => "RETURN",
            0xF4 => "DELEGATECALL",
            0xF5 => "CREATE2",
            0xFA => "STATICCALL",
            0xFD => "REVERT",
            0xFF => "SELFDESTRUCT",
            _ => "INVALID",
        }
    }

    /// Detect onlyOwner pattern around a CALLER opcode
    fn detect_only_owner_pattern(bytecode: &[u8], pc: usize) -> Option<AccessControlInfo> {
        // Look for EQ opcode in the next few instructions
        let mut offset = pc + 1;
        let limit = (pc + 20).min(bytecode.len());
        
        while offset < limit {
            if bytecode[offset] == OPCODE_EQ {
                // Found equality check
                return Some(AccessControlInfo {
                    pattern_type: AccessControlPattern::OnlyOwner,
                    offset: pc,
                    expected_caller: None, // Would need to extract address
                    storage_slot: Some(0), // Usually slot 0
                });
            }
            offset += 1;
        }
        None
    }

    /// Check if there was an SSTORE before this position
    fn has_sstore_before(bytecode: &[u8], pc: usize) -> bool {
        let start = pc.saturating_sub(50);
        for i in start..pc {
            if bytecode[i] == OPCODE_SSTORE {
                return true;
            }
        }
        false
    }

    /// Find offset of a selector in bytecode
    fn find_selector_offset(bytecode: &[u8], selector: &[u8; 4]) -> usize {
        let len = bytecode.len();
        let mut i = 0;
        
        while i < len {
            if bytecode[i] == 0x63 && i + 4 < len {
                if bytecode[i+1] == selector[0] && 
                   bytecode[i+2] == selector[1] && 
                   bytecode[i+3] == selector[2] && 
                   bytecode[i+4] == selector[3] {
                    return i;
                }
            }
            i += 1;
        }
        0
    }

    /// Check if selector is known dangerous
    fn is_selector_dangerous(selector: &[u8; 4]) -> bool {
        let dangerous_selectors = [
            [0x00, 0x00, 0x00, 0x00], // fallback
            Self::selector_from_sig("selfdestruct()"),
            Self::selector_from_sig("kill()"),
            Self::selector_from_sig("destroy()"),
            Self::selector_from_sig("withdrawAll()"),
            Self::selector_from_sig("drainFunds(address)"),
            Self::selector_from_sig("initialize()"),
        ];
        dangerous_selectors.contains(selector)
    }

    /// Check if selector has access control
    fn selector_has_access_control(bytecode: &[u8], selector: &[u8; 4]) -> bool {
        // Find selector position and check for CALLER checks before it
        let offset = Self::find_selector_offset(bytecode, selector);
        if offset > 10 {
            let start = offset.saturating_sub(30);
            for i in start..offset {
                if bytecode[i] == OPCODE_CALLER {
                    return true;
                }
            }
        }
        false
    }

    fn has_upgrade_selectors(selectors: &[[u8; 4]]) -> bool {
        let upgrade_signatures = [
            "upgradeTo(address)",
            "upgradeToAndCall(address,bytes)",
            "setImplementation(address)",
            "upgradeImplementation(address)",
            "setBeacon(address)",
            "changeImplementation(address)",
        ];

        upgrade_signatures
            .iter()
            .map(|sig| Self::selector_from_sig(sig))
            .any(|selector| selectors.contains(&selector))
    }

    fn has_admin_selectors(selectors: &[[u8; 4]]) -> bool {
        let admin_signatures = [
            "transferOwnership(address)",
            "renounceOwnership()",
            "takeOwnership()",
            "owner()",
            "admin()",
            "changeAdmin(address)",
            "becomeAdmin()",
            "setOwner(address)",
            "grantRole(bytes32,address)",
            "revokeRole(bytes32,address)",
            "pause()",
            "unpause()",
        ];

        admin_signatures
            .iter()
            .map(|sig| Self::selector_from_sig(sig))
            .any(|selector| selectors.contains(&selector))
    }

    fn detect_fallback_entry(
        bytecode: &[u8],
        selectors: &[[u8; 4]],
        basic_blocks: &[BasicBlockInfo],
    ) -> bool {
        if selectors.is_empty() {
            return false;
        }

        let dispatcher_gate = basic_blocks.iter().any(|block| {
            block.instructions
                .iter()
                .any(|inst| matches!(inst.mnemonic, "CALLDATASIZE" | "CALLDATALOAD"))
                && block
                    .instructions
                    .iter()
                    .any(|inst| matches!(inst.mnemonic, "JUMPI" | "REVERT"))
        });
        let zero_selector_check = bytecode
            .windows(4)
            .any(|window| window == [0x00, 0x00, 0x00, 0x00]);

        dispatcher_gate || zero_selector_check
    }

    fn detect_receive_entry(
        _bytecode: &[u8],
        selectors: &[[u8; 4]],
        basic_blocks: &[BasicBlockInfo],
    ) -> bool {
        if selectors.is_empty() {
            return false;
        }

        basic_blocks.iter().take(4).any(|block| {
            let has_callvalue = block
                .instructions
                .iter()
                .any(|inst| inst.mnemonic == "CALLVALUE");
            let has_revert_or_return = block
                .instructions
                .iter()
                .any(|inst| matches!(inst.mnemonic, "JUMPI" | "RETURN" | "STOP" | "REVERT"));
            has_callvalue && has_revert_or_return
        })
    }

    /// Build basic blocks from bytecode and jumpdests
    fn build_basic_blocks(bytecode: &[u8], jumpdests: &HashSet<usize>) -> Vec<BasicBlockInfo> {
        let len = bytecode.len();
        if len == 0 {
            return Vec::new();
        }

        let mut leaders: HashSet<usize> = HashSet::new();
        leaders.insert(0);
        for jumpdest in jumpdests {
            leaders.insert(*jumpdest);
        }

        let mut cursor = 0;
        while cursor < len {
            let opcode = bytecode[cursor];
            let next_pc = Self::next_pc(bytecode, cursor);
            let is_terminal = matches!(
                opcode,
                OPCODE_JUMP | OPCODE_JUMPI | OPCODE_STOP | OPCODE_RETURN | OPCODE_REVERT | OPCODE_SELFDESTRUCT
            );

            if is_terminal && next_pc < len {
                leaders.insert(next_pc);
            }

            cursor = next_pc.max(cursor + 1);
        }

        let mut leader_list: Vec<usize> = leaders.into_iter().filter(|pc| *pc < len).collect();
        leader_list.sort_unstable();

        let mut blocks = Vec::new();
        for (idx, start) in leader_list.iter().enumerate() {
            let end = if let Some(next_start) = leader_list.get(idx + 1) {
                next_start.saturating_sub(1)
            } else {
                len - 1
            };

            let mut instructions = Vec::new();
            let mut pc = *start;
            while pc <= end && pc < len {
                let opcode = bytecode[pc];
                let push_data = if (0x60..=0x7F).contains(&opcode) {
                    let push_len = (opcode - 0x5F) as usize;
                    if pc + 1 + push_len <= len {
                        Some(bytecode[pc + 1..pc + 1 + push_len].to_vec())
                    } else {
                        None
                    }
                } else {
                    None
                };

                instructions.push(Instruction {
                    opcode,
                    pc,
                    push_data,
                    mnemonic: Self::opcode_to_mnemonic(opcode),
                });

                let next_pc = Self::next_pc(bytecode, pc);
                if next_pc <= pc {
                    break;
                }
                pc = next_pc;
            }

            blocks.push(BasicBlockInfo {
                start: *start,
                end,
                instructions,
                successors: Vec::new(),
            });
        }

        let leader_index: HashMap<usize, usize> = blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| (block.start, idx))
            .collect();

        for idx in 0..blocks.len() {
            let mut successors = Vec::new();
            let last_instruction = blocks[idx].instructions.last().cloned();
            let block_end = blocks[idx].end;

            if let Some(inst) = last_instruction {
                match inst.opcode {
                    OPCODE_JUMP => {
                        if let Some(dest) = Self::extract_jump_target(&blocks[idx].instructions) {
                            if leader_index.contains_key(&dest) {
                                successors.push(dest);
                            }
                        }
                    }
                    OPCODE_JUMPI => {
                        if let Some(dest) = Self::extract_jump_target(&blocks[idx].instructions) {
                            if leader_index.contains_key(&dest) {
                                successors.push(dest);
                            }
                        }
                        let fallthrough = block_end.saturating_add(1);
                        if leader_index.contains_key(&fallthrough) {
                            successors.push(fallthrough);
                        }
                    }
                    OPCODE_STOP | OPCODE_RETURN | OPCODE_REVERT | OPCODE_SELFDESTRUCT => {}
                    _ => {
                        let fallthrough = block_end.saturating_add(1);
                        if leader_index.contains_key(&fallthrough) {
                            successors.push(fallthrough);
                        }
                    }
                }
            }

            successors.sort_unstable();
            successors.dedup();
            blocks[idx].successors = successors;
        }

        blocks
    }

    fn next_pc(bytecode: &[u8], pc: usize) -> usize {
        let opcode = bytecode[pc];
        if (0x60..=0x7F).contains(&opcode) {
            let push_len = (opcode - 0x5F) as usize;
            (pc + 1 + push_len).min(bytecode.len())
        } else {
            (pc + 1).min(bytecode.len())
        }
    }

    fn extract_jump_target(instructions: &[Instruction]) -> Option<usize> {
        instructions.iter().rev().skip(1).find_map(|inst| {
            inst.push_data.as_ref().and_then(|data| {
                if data.is_empty() || data.len() > 8 {
                    return None;
                }

                let mut target = 0usize;
                for byte in data {
                    target = (target << 8) | (*byte as usize);
                }
                Some(target)
            })
        })
    }

    /// Match dangerous signatures against selectors
    pub fn match_dangerous_signatures(selectors: &[[u8; 4]]) -> Vec<String> {
        let dangerous_signatures: &[(&str, &str)] = &[
            ("selfdestruct()", "Self-destruct trigger"),
            ("kill()", "Self-destruct alias"),
            ("destroy()", "Self-destruct alias"),
            ("withdrawAll()", "Full balance drain"),
            ("drainFunds(address)", "Explicit drain function"),
            ("transferOwnership(address)", "Ownership transfer"),
            ("renounceOwnership()", "Ownership renunciation"),
            ("upgradeTo(address)", "Upgrade proxy implementation"),
            ("upgradeToAndCall(address,bytes)", "Upgrade with delegatecall"),
            ("initialize()", "Unprotected initializer"),
            ("__destroy__()", "Backdoor destroy"),
            ("emergencyWithdraw()", "Emergency drain"),
            ("sweepTokens(address)", "Token sweep"),
            ("withdraw(address)", "Generic withdraw"),
            ("takeOwnership()", "Ownership takeover"),
            ("becomeAdmin()", "Admin takeover"),
            ("setImplementation(address)", "Implementation change"),
        ];

        let mut matches = Vec::new();

        for (sig, desc) in dangerous_signatures {
            let expected = Self::selector_from_sig(sig);
            if selectors.contains(&expected) {
                matches.push(format!("{} - {}", sig, desc));
            }
        }

        matches
    }

    /// Get additional risk assessment
    pub fn assess_risk(analysis: &BytecodeAnalysis) -> String {
        if analysis.has_selfdestruct {
            "CRITICAL: Contract can self-destruct".to_string()
        } else if analysis.has_delegatecall && !analysis.access_controls.is_empty() {
            "HIGH: Delegatecall with access control".to_string()
        } else if analysis.has_delegatecall {
            "MEDIUM: Delegatecall without visible access control".to_string()
        } else if analysis.has_reentrancy_risk {
            "MEDIUM: Potential reentrancy vulnerability".to_string()
        } else if analysis.risk_score > 30 {
            "MEDIUM: Multiple suspicious patterns".to_string()
        } else if analysis.risk_score > 10 {
            "LOW: Minor concerns detected".to_string()
        } else {
            "LOW: No major concerns detected".to_string()
        }
    }

    pub fn selector_to_hex(selector: &[u8; 4]) -> String {
        format!("0x{}", hex::encode(selector))
    }
}

// ============================================================
// TESTES
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_extraction() {
        let bytecode = vec![
            0x63, 0xAB, 0xCD, 0xEF, 0x01, 0x14, 0x63, 0x12, 0x34, 0x56, 0x78, 0x14,
        ];
        let selectors = BytecodeScanner::extract_selectors(&bytecode);
        assert_eq!(selectors.len(), 2);
        assert_eq!(selectors[0], [0xAB, 0xCD, 0xEF, 0x01]);
        assert_eq!(selectors[1], [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_selfdestruct_detection() {
        let bytecode = vec![0x60, 0x00, OPCODE_SELFDESTRUCT];
        let analysis = BytecodeScanner::analyze(&bytecode);
        assert!(analysis.has_selfdestruct);
        assert!(!analysis.flags.is_empty());
        assert!(analysis.risk_score >= 50);
    }

    #[test]
    fn test_selector_from_sig() {
        let sel = BytecodeScanner::selector_from_sig("transfer(address,uint256)");
        assert_eq!(sel, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_opcode_mnemonic() {
        assert_eq!(BytecodeScanner::opcode_to_mnemonic(OPCODE_STOP), "STOP");
        assert_eq!(BytecodeScanner::opcode_to_mnemonic(OPCODE_CALL), "CALL");
        assert_eq!(BytecodeScanner::opcode_to_mnemonic(OPCODE_SELFDESTRUCT), "SELFDESTRUCT");
    }

    #[test]
    fn test_reentrancy_detection() {
        // SSTORE followed by CALL
        let bytecode = vec![
            OPCODE_SSTORE, // storage write
            OPCODE_CALL,   // external call - reentrancy risk
        ];
        let analysis = BytecodeScanner::analyze(&bytecode);
        assert!(analysis.has_reentrancy_risk);
    }
}
