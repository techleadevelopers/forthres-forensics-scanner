// src/offensive/path_finder.rs
//! Hexora Control Flow Graph Builder
//!
//! Constrói CFG a partir de bytecode EVM com:
//! - Detecção real de padrões (CALLER + PUSH20 + EQ)
//! - Resolução de jump targets (dinâmicos e estáticos)
//! - Análise de stack para condições

use crate::bytecode::BytecodeAnalysis;
use std::collections::{HashMap, VecDeque};

// ============================================================
// ESTRUTURAS BASE (mantidas)
// ============================================================

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_pc: usize,
    pub end_pc: usize,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<usize>,  // Próximos blocos (PCs)
    pub predecessors: Vec<usize>, // Blocos que chegam aqui
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub opcode: u8,
    pub pc: usize,
    pub push_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ControlFlowPath {
    pub entry_selector: String,
    pub basic_blocks: Vec<BasicBlock>,
    pub conditions: Vec<Condition>,
    pub state_changes: Vec<StateChange>,
    pub gas_estimate: u64,
}

#[derive(Debug, Clone)]
pub enum Condition {
    CallerEq(String),
    CallerEqStorage(u64),
    ValueGt(u128),
    ValueLt(u128),
    BalanceGt(u128),
    BalanceLt(u128),
    StorageSlotEq(u64, String),
    StorageSlotNeq(u64, String),
    TimestampGt(u64),
    TimestampLt(u64),
    BlockNumberGt(u64),
    BlockNumberLt(u64),
    IsContract(String),
    NotZeroAddress,
}

#[derive(Debug, Clone)]
pub enum StateChange {
    SelfDestruct(String),
    Transfer(u128, Option<String>),
    Mint(u128, String),
    Delegatecall(String),
    StorageWrite(u64, String),
    Call(String, u128, Vec<u8>),
    Log(String, Vec<String>),
}

impl ControlFlowPath {
    pub fn is_dangerous(&self) -> bool {
        self.state_changes.iter().any(|change| match change {
            StateChange::SelfDestruct(_) => true,
            StateChange::Delegatecall(_) => true,
            StateChange::Transfer(amount, _) => *amount > 0,
            StateChange::StorageWrite(slot, _) => *slot == 0,
            _ => false,
        })
    }
}

// ============================================================
// NOVO: ANALISADOR DE PADRÕES HEXORA
// ============================================================

#[derive(Debug, Clone)]
pub struct PatternDetector;

impl PatternDetector {
    /// Detecta padrão: CALLER (0x33) + PUSH20 address + EQ (0x14)
    pub fn detect_caller_check(blocks: &[BasicBlock], eq_pc: usize) -> Option<Condition> {
        // Busca nos 20 bytes anteriores (espaço suficiente para CALLER + PUSH20)
        let start = eq_pc.saturating_sub(25);
        
        for block in blocks {
            for inst in &block.instructions {
                if inst.pc >= start && inst.pc < eq_pc {
                    match inst.opcode {
                        0x33 => { // CALLER
                            // Procura por PUSH20 nas próximas instruções
                            if let Some(push) = PatternDetector::find_push20_at(blocks, inst.pc + 1) {
                                if let Some(addr) = PatternDetector::extract_address_from_push(&push) {
                                    return Some(Condition::CallerEq(addr));
                                }
                            }
                        }
                        0x32 => { // ORIGIN (tx.origin)
                            if let Some(push) = PatternDetector::find_push20_at(blocks, inst.pc + 1) {
                                if let Some(addr) = PatternDetector::extract_address_from_push(&push) {
                                    return Some(Condition::CallerEq(format!("tx.origin == {}", addr)));
                                }
                            }
                        }
                        _ => continue,
                    }
                }
            }
        }
        None
    }
    
    /// Detecta padrão: SLOAD + EQ para storage checks
    pub fn detect_storage_check(blocks: &[BasicBlock], eq_pc: usize) -> Option<Condition> {
        let start = eq_pc.saturating_sub(15);
        
        for block in blocks {
            for inst in &block.instructions {
                if inst.pc >= start && inst.pc < eq_pc {
                    // SLOAD (0x54) antes de EQ
                    if inst.opcode == 0x54 {
                        // Verifica se há PUSH antes do SLOAD (slot)
                        if let Some(slot_push) = PatternDetector::find_push_before(blocks, inst.pc, 10) {
                            if let Some(slot) = PatternDetector::extract_u64_from_push(&slot_push) {
                                return Some(Condition::CallerEqStorage(slot));
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    /// Detecta padrão: CALLVALUE + LT/GT
    pub fn detect_value_check(blocks: &[BasicBlock], pc: usize, opcode: u8) -> Option<Condition> {
        let start = pc.saturating_sub(10);
        
        for block in blocks {
            for inst in &block.instructions {
                if inst.pc >= start && inst.pc < pc {
                    // CALLVALUE (0x34)
                    if inst.opcode == 0x34 {
                        // Procura por PUSH com threshold
                        if let Some(push) = PatternDetector::find_push_before(blocks, pc, 10) {
                            if let Some(threshold) = PatternDetector::extract_u128_from_push(&push) {
                                return Some(match opcode {
                                    0x10 | 0x12 => Condition::ValueGt(threshold),  // LT/SLT
                                    0x11 | 0x13 => Condition::ValueLt(threshold),  // GT/SGT
                                    _ => Condition::ValueGt(threshold),
                                });
                            }
                        }
                        // Sem threshold específico, usa padrão
                        return Some(match opcode {
                            0x10 | 0x12 => Condition::ValueGt(0),
                            0x11 | 0x13 => Condition::ValueLt(u128::MAX),
                            _ => Condition::ValueGt(0),
                        });
                    }
                }
            }
        }
        None
    }
    
    /// Detecta padrão: ISZERO + CALLER (not owner)
    pub fn detect_not_caller_check(blocks: &[BasicBlock], iszero_pc: usize) -> Option<Condition> {
        let start = iszero_pc.saturating_sub(10);
        
        for block in blocks {
            for inst in &block.instructions {
                if inst.pc >= start && inst.pc < iszero_pc {
                    if inst.opcode == 0x33 { // CALLER
                        return Some(Condition::NotZeroAddress);
                    }
                }
            }
        }
        None
    }
    
    /// Encontra PUSH20 nas proximidades
    pub fn find_push20_at(blocks: &[BasicBlock], start_pc: usize) -> Option<Vec<u8>> {
        for block in blocks {
            for inst in &block.instructions {
                if inst.pc >= start_pc && inst.pc <= start_pc + 10 {
                    // PUSH20 é opcode 0x73 (PUSH20 = 0x60 + 19)
                    if inst.opcode == 0x73 {
                        if let Some(data) = &inst.push_data {
                            if data.len() == 20 {
                                return Some(data.clone());
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    /// Encontra PUSH antes de um PC
    pub fn find_push_before(blocks: &[BasicBlock], target_pc: usize, max_distance: usize) -> Option<Vec<u8>> {
        let start = target_pc.saturating_sub(max_distance);
        
        for block in blocks {
            for inst in &block.instructions {
                if inst.pc >= start && inst.pc < target_pc {
                    if (0x60..=0x7F).contains(&inst.opcode) {
                        if let Some(data) = &inst.push_data {
                            return Some(data.clone());
                        }
                    }
                }
            }
        }
        None
    }
    
    /// Extrai endereço de um PUSH20
    pub fn extract_address_from_push(push_data: &[u8]) -> Option<String> {
        if push_data.len() == 20 {
            Some(format!("0x{}", hex::encode(push_data)))
        } else if push_data.len() == 32 {
            // PUSH32 com endereço nos últimos 20 bytes
            let addr = &push_data[12..32];
            Some(format!("0x{}", hex::encode(addr)))
        } else {
            None
        }
    }
    
    /// Extrai u64 de um PUSH
    pub fn extract_u64_from_push(push_data: &[u8]) -> Option<u64> {
        if push_data.len() <= 8 {
            let mut bytes = [0u8; 8];
            bytes[8 - push_data.len()..].copy_from_slice(push_data);
            Some(u64::from_be_bytes(bytes))
        } else {
            None
        }
    }
    
    /// Extrai u128 de um PUSH
    pub fn extract_u128_from_push(push_data: &[u8]) -> Option<u128> {
        if push_data.len() <= 16 {
            let mut bytes = [0u8; 16];
            bytes[16 - push_data.len()..].copy_from_slice(push_data);
            Some(u128::from_be_bytes(bytes))
        } else {
            None
        }
    }
}

// ============================================================
// NOVO: RESOLVEDOR DE JUMP TARGETS
// ============================================================

#[derive(Debug, Clone)]
pub enum JumpTarget {
    Known(usize),
    Dynamic,      // Não resolvido, precisa de symbolic execution
    Invalid,
}

#[derive(Debug, Clone)]
pub struct JumpResolver;

impl JumpResolver {
    /// Resolve destino de JUMP/JUMPI baseado no stack state
    pub fn resolve_jump_target(
        bytecode: &[u8],
        stack_top: Option<&[u8]>,
        pc: usize,
    ) -> JumpTarget {
        // Tenta resolver stack top se disponível
        if let Some(data) = stack_top {
            if data.len() <= 4 {
                // Destino pequeno, provavelmente válido
                let target = data.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
                if target < bytecode.len() && bytecode[target] == 0x5B {
                    return JumpTarget::Known(target);
                }
            }
        }
        
        // Procura por jump table pattern
        if let Some(table) = JumpResolver::find_jump_table(bytecode, pc) {
            return JumpTarget::Known(table);
        }
        
        // Analisa padrão de dispatching
        if let Some(dispatch) = JumpResolver::find_dispatch_pattern(bytecode, pc) {
            return JumpTarget::Known(dispatch);
        }
        
        JumpTarget::Dynamic
    }
    
    /// Encontra jump table (switch-case pattern)
    pub fn find_jump_table(bytecode: &[u8], pc: usize) -> Option<usize> {
        // Padrão comum: PUSH table_start + JUMP
        if pc >= 2 {
            // Verifica se há PUSH antes do JUMP
            let prev_opcode = bytecode[pc - 1];
            if (0x60..=0x7F).contains(&prev_opcode) {
                let push_len = (prev_opcode - 0x5F) as usize;
                if pc - 1 - push_len > 0 {
                    let start = pc - 1 - push_len;
                    if start + push_len <= bytecode.len() {
                        let target_bytes = &bytecode[start + 1..start + 1 + push_len];
                        let target = target_bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
                        if target < bytecode.len() {
                            return Some(target);
                        }
                    }
                }
            }
        }
        None
    }
    
    /// Encontra padrão de dispatch (PUSH4 selector + JUMPI)
    pub fn find_dispatch_pattern(bytecode: &[u8], pc: usize) -> Option<usize> {
        // Procura por destinos de JUMPI que são basic blocks
        for i in (0..pc).rev().take(50) {
            if bytecode[i] == 0x57 { // JUMPI
                // Encontra destino nos próximos bytes
                let mut j = i + 1;
                while j < bytecode.len() && j < i + 10 {
                    if bytecode[j] == 0x5B { // JUMPDEST
                        return Some(j);
                    }
                    j += 1;
                }
            }
        }
        None
    }
    
    /// Verifica se um PC é um jumpdest válido
    pub fn is_valid_jumpdest(bytecode: &[u8], target: usize) -> bool {
        target < bytecode.len() && bytecode[target] == 0x5B
    }
}

// ============================================================
// FUNÇÕES PRINCIPAIS MELHORADAS
// ============================================================

pub fn find_exploit_paths(analysis: &BytecodeAnalysis, max_paths: usize) -> Vec<ControlFlowPath> {
    let mut paths = Vec::new();
    
    for selector in &analysis.function_selectors {
        let cfg = build_cfg_for_selector(analysis, selector);
        
        // Extrai condições com pattern detection real
        let conditions = extract_conditions_from_bytecode(&cfg);
        
        let state_changes = extract_state_changes_from_bytecode(&cfg, analysis);
        
        let path = ControlFlowPath {
            entry_selector: hex::encode(selector),
            basic_blocks: cfg,
            conditions,
            state_changes,
            gas_estimate: estimate_gas_for_path(selector, analysis),
        };
        
        if path.is_dangerous() {
            paths.push(path);
            if paths.len() >= max_paths {
                break;
            }
        }
    }
    
    paths
}

fn build_cfg_for_selector(analysis: &BytecodeAnalysis, selector: &[u8; 4]) -> Vec<BasicBlock> {
    let mut blocks = Vec::new();
    let bytecode = &analysis.bytecode;
    
    let start_pc = find_selector_in_bytecode(bytecode, selector);
    
    if start_pc < bytecode.len() {
        let mut visited = std::collections::HashSet::new();
        let mut worklist = VecDeque::new();
        
        // Primeiro bloco
        let first_block = build_basic_block(bytecode, start_pc);
        let block_id = blocks.len();
        worklist.push_back((first_block, start_pc));
        visited.insert(start_pc);
        
        while let Some((mut block, block_start)) = worklist.pop_front() {
            // Processa successors
            let last_inst = block.instructions.last();
            if let Some(last) = last_inst {
                match last.opcode {
                    0x56 | 0x57 => { // JUMP ou JUMPI
                        // Tenta resolver destino
                        let target = JumpResolver::resolve_jump_target(bytecode, None, last.pc);
                        match target {
                            JumpTarget::Known(target_pc) => {
                                if target_pc < bytecode.len() && !visited.contains(&target_pc) {
                                    let next_block = build_basic_block(bytecode, target_pc);
                                    block.successors.push(target_pc);
                                    visited.insert(target_pc);
                                    worklist.push_back((next_block, target_pc));
                                }
                            }
                            JumpTarget::Dynamic => {
                                // Marca como dinâmico, será explorado simbolicamente
                                block.successors.push(usize::MAX); // sentinela para dynamic
                            }
                            JumpTarget::Invalid => {}
                        }
                    }
                    0xFD | 0xFE | 0x00 | 0xF3 => {
                        // REVERT, INVALID, STOP, RETURN - sem successors
                    }
                    _ => {
                        // Next sequential block
                        let next_pc = block.end_pc + 1;
                        if next_pc < bytecode.len() && !visited.contains(&next_pc) {
                            let next_block = build_basic_block(bytecode, next_pc);
                            block.successors.push(next_pc);
                            visited.insert(next_pc);
                            worklist.push_back((next_block, next_pc));
                        }
                    }
                }
            }
            
            blocks.push(block);
        }
    }
    
    blocks
}

fn build_basic_block(bytecode: &[u8], start_pc: usize) -> BasicBlock {
    let mut instructions = Vec::new();
    let mut pc = start_pc;
    
    while pc < bytecode.len() {
        let opcode = bytecode[pc];
        let push_data = extract_push_data(bytecode, pc, opcode);
        
        instructions.push(Instruction {
            opcode,
            pc,
            push_data,
        });
        
        let is_terminal = matches!(opcode, 0x56 | 0x57 | 0xFD | 0xFE | 0x00 | 0xF3);
        if is_terminal {
            return BasicBlock {
                start_pc,
                end_pc: pc,
                instructions,
                successors: Vec::new(),
                predecessors: Vec::new(),
            };
        }
        
        pc += 1 + instruction_extra_bytes(opcode);
    }
    
    BasicBlock {
        start_pc,
        end_pc: pc - 1,
        instructions,
        successors: Vec::new(),
        predecessors: Vec::new(),
    }
}

fn find_selector_in_bytecode(bytecode: &[u8], selector: &[u8; 4]) -> usize {
    bytecode
        .windows(4)
        .position(|window| window == selector)
        .unwrap_or(0)
}

fn extract_push_data(bytecode: &[u8], pc: usize, opcode: u8) -> Option<Vec<u8>> {
    if (0x60..=0x7F).contains(&opcode) {
        let push_len = (opcode - 0x5F) as usize;
        if pc + 1 + push_len <= bytecode.len() {
            return Some(bytecode[pc + 1..pc + 1 + push_len].to_vec());
        }
    }
    None
}

fn instruction_extra_bytes(opcode: u8) -> usize {
    if (0x60..=0x7F).contains(&opcode) {
        return (opcode - 0x5F) as usize;
    }
    match opcode {
        0x61 => 1, 0x62 => 2, 0x63 => 3, 0x64 => 4, 0x65 => 5, 0x66 => 6,
        0x67 => 7, 0x68 => 8, 0x69 => 9, 0x6A => 10, 0x6B => 11, 0x6C => 12,
        0x6D => 13, 0x6E => 14, 0x6F => 15, 0x70 => 16, 0x71 => 17, 0x72 => 18,
        0x73 => 19, 0x74 => 20, 0x75 => 21, 0x76 => 22, 0x77 => 23, 0x78 => 24,
        0x79 => 25, 0x7A => 26, 0x7B => 27, 0x7C => 28, 0x7D => 29, 0x7E => 30,
        0x7F => 31, _ => 0,
    }
}

// ============================================================
// FUNÇÕES DE EXTRAÇÃO MELHORADAS
// ============================================================

fn extract_conditions_from_bytecode(blocks: &[BasicBlock]) -> Vec<Condition> {
    let mut conditions = Vec::new();
    
    for block in blocks {
        for inst in &block.instructions {
            match inst.opcode {
                0x14 => { // EQ
                    if let Some(cond) = PatternDetector::detect_caller_check(blocks, inst.pc) {
                        conditions.push(cond);
                    }
                    if let Some(cond) = PatternDetector::detect_storage_check(blocks, inst.pc) {
                        conditions.push(cond);
                    }
                }
                0x10 | 0x11 | 0x12 | 0x13 => { // LT/GT/SLT/SGT
                    if let Some(cond) = PatternDetector::detect_value_check(blocks, inst.pc, inst.opcode) {
                        conditions.push(cond);
                    }
                }
                0x15 => { // ISZERO
                    if let Some(cond) = PatternDetector::detect_not_caller_check(blocks, inst.pc) {
                        conditions.push(cond);
                    }
                }
                0x42 => { // TIMESTAMP
                    if let Some(push) = PatternDetector::find_push_before(blocks, inst.pc, 15) {
                        if let Some(threshold) = PatternDetector::extract_u64_from_push(&push) {
                            conditions.push(Condition::TimestampGt(threshold));
                        }
                    }
                }
                0x43 => { // NUMBER
                    if let Some(push) = PatternDetector::find_push_before(blocks, inst.pc, 15) {
                        if let Some(threshold) = PatternDetector::extract_u64_from_push(&push) {
                            conditions.push(Condition::BlockNumberGt(threshold));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    
    conditions
}

fn extract_state_changes_from_bytecode(blocks: &[BasicBlock], analysis: &BytecodeAnalysis) -> Vec<StateChange> {
    let mut changes = Vec::new();
    
    for block in blocks {
        for inst in &block.instructions {
            match inst.opcode {
                0xFF => {
                    changes.push(StateChange::SelfDestruct("any".to_string()));
                }
                0xF4 => {
                    if let Some(push) = PatternDetector::find_push_before(blocks, inst.pc, 20) {
                        if let Some(target) = PatternDetector::extract_address_from_push(&push) {
                            changes.push(StateChange::Delegatecall(target));
                        } else {
                            changes.push(StateChange::Delegatecall("unknown".to_string()));
                        }
                    } else {
                        changes.push(StateChange::Delegatecall("unknown".to_string()));
                    }
                }
                0xF1 => {
                    let mut target = "unknown".to_string();
                    let mut value = 0u128;
                    
                    if let Some(push) = PatternDetector::find_push_before(blocks, inst.pc, 30) {
                        if let Some(addr) = PatternDetector::extract_address_from_push(&push) {
                            target = addr;
                        }
                    }
                    
                    changes.push(StateChange::Call(target, value, vec![]));
                }
                0x55 => {
                    if let Some(push) = PatternDetector::find_push_before(blocks, inst.pc, 15) {
                        if let Some(slot) = PatternDetector::extract_u64_from_push(&push) {
                            changes.push(StateChange::StorageWrite(slot, "modified".to_string()));
                        } else {
                            changes.push(StateChange::StorageWrite(0, "modified".to_string()));
                        }
                    } else {
                        changes.push(StateChange::StorageWrite(0, "modified".to_string()));
                    }
                }
                0xA0..=0xA4 => {
                    changes.push(StateChange::Log("event".to_string(), vec![]));
                }
                _ => {}
            }
        }
    }
    
    changes
}

fn estimate_gas_for_path(selector: &[u8; 4], analysis: &BytecodeAnalysis) -> u64 {
    let base_gas = 21000;
    let bytecode_len = analysis.bytecode.len();
    let calldata_gas = selector.len() * 16;
    
    base_gas + calldata_gas as u64 + (bytecode_len as u64 / 2).min(100000)
}

// ============================================================
// TESTES
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pattern_detector_extract_address() {
        let push_data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
            0xde, 0xad, 0xbe, 0xef
        ];
        let addr = PatternDetector::extract_address_from_push(&push_data);
        assert!(addr.is_some());
        assert!(addr.unwrap().starts_with("0x"));
    }
    
    #[test]
    fn test_jump_resolver() {
        let bytecode = vec![0x5B]; // JUMPDEST
        let target = JumpResolver::resolve_jump_target(&bytecode, None, 0);
        assert!(matches!(target, JumpTarget::Dynamic));
    }
}
