// src/offensive/symbolic_executor.rs
//! forthres Symbolic Execution Engine
//! 
//! Executor simbólico para bytecode EVM com suporte a:
//! - Path splitting em branches condicionais
//! - SMT solving via Z3 (quando disponível)
//! - Detecção de constraints para geração de exploits

use crate::bytecode::BytecodeAnalysis;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

// ============================================================
// ESTRUTURAS BASE (mantidas do original)
// ============================================================

#[derive(Debug, Clone)]
pub struct SymbolicState {
    pub caller: Symbol,
    pub value: Symbol,
    pub storage: Vec<Symbol>,
    pub stack: Vec<Symbol>,
    pub memory: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Symbol {
    Concrete(U256),
    Symbolic(String),
    Any,
}

#[derive(Debug, Clone)]
pub struct PathCondition {
    pub condition: String,
    pub pc: usize,
    pub is_taken: bool,
}

// ============================================================
// NOVAS ESTRUTURAS forthres
// ============================================================

/// Estado completo de um path simbólico
#[derive(Debug, Clone)]
pub struct SymbolicPath {
    pub id: usize,
    pub entry_selector: String,
    pub pc: usize,
    pub stack: Vec<Symbol>,
    pub constraints: Vec<PathCondition>,
    pub state_changes: Vec<SymbolicStateChange>,
    pub is_feasible: bool,
    pub depth: usize,
}

#[derive(Debug, Clone)]
pub enum SymbolicStateChange {
    StorageWrite(u64, Symbol),
    Transfer(Symbol, Option<String>),
    Call(String, Symbol, Vec<u8>),
    Delegatecall(String),
    SelfDestruct(String),
    Log(String, Vec<Symbol>),
}

/// Resultado da execução simbólica
#[derive(Debug, Clone)]
pub struct SymbolicExecutionResult {
    pub paths: Vec<SymbolicPath>,
    pub total_paths_explored: usize,
    pub branches_encountered: usize,
    pub max_depth_reached: usize,
    pub analysis_time_ms: u64,
}

/// Configuração do executor
#[derive(Debug, Clone)]
pub struct SymbolicConfig {
    pub max_paths: usize,
    pub max_depth: usize,
    pub max_constraints_per_path: usize,
    pub enable_smt: bool,
    pub timeout_ms: u64,
}

impl Default for SymbolicConfig {
    fn default() -> Self {
        Self {
            max_paths: 100,
            max_depth: 500,
            max_constraints_per_path: 50,
            enable_smt: false,  // Z3 opcional
            timeout_ms: 30000,
        }
    }
}

// ============================================================
// forthres SYMBOLIC EXECUTOR
// ============================================================

pub struct forthresSymbolicExecutor {
    config: SymbolicConfig,
    next_path_id: usize,
}

impl forthresSymbolicExecutor {
    pub fn new(config: SymbolicConfig) -> Self {
        Self {
            config,
            next_path_id: 0,
        }
    }
    
    /// Executa simbolicamente um contrato a partir de um selector
    pub fn execute(
        &mut self,
        analysis: &BytecodeAnalysis,
        selector: &[u8; 4],
    ) -> SymbolicExecutionResult {
        let start = std::time::Instant::now();
        
        let bytecode = &analysis.bytecode;
        let start_pc = find_selector_position(bytecode, selector);
        
        let mut all_paths = Vec::new();
        let mut worklist = VecDeque::new();
        let mut branches_encountered = 0;
        let mut max_depth_reached = 0;
        
        // Path inicial
        let initial_path = SymbolicPath {
            id: self.next_path_id(),
            entry_selector: hex::encode(selector),
            pc: start_pc,
            stack: Vec::new(),
            constraints: Vec::new(),
            state_changes: Vec::new(),
            is_feasible: true,
            depth: 0,
        };
        
        worklist.push_back(initial_path);
        
        while let Some(mut path) = worklist.pop_front() {
            if all_paths.len() >= self.config.max_paths {
                break;
            }
            
            if path.depth >= self.config.max_depth {
                continue;
            }
            
            max_depth_reached = max_depth_reached.max(path.depth);
            
            // Executa até encontrar um branch
            let result = self.execute_path_segment(&bytecode, &mut path);
            
            match result {
                SegmentResult::Complete => {
                    // Path chegou ao fim (STOP, RETURN, REVERT)
                    all_paths.push(path);
                }
                SegmentResult::Branch(condition, true_target, false_target) => {
                    branches_encountered += 1;
                    
                    // Branch TRUE
                    let mut true_path = path.clone();
                    true_path.id = self.next_path_id();
                    true_path.pc = true_target;
                    true_path.depth += 1;
                    true_path.constraints.push(PathCondition {
                        condition: condition.clone(),
                        pc: path.pc,
                        is_taken: true,
                    });
                    true_path.is_feasible = self.check_feasibility(&true_path.constraints);
                    
                    // Branch FALSE
                    let mut false_path = path;
                    false_path.id = self.next_path_id();
                    false_path.pc = false_target;
                    false_path.depth += 1;
                    false_path.constraints.push(PathCondition {
                        condition: format!("!({})", condition),
                        pc: false_path.pc,
                        is_taken: false,
                    });
                    false_path.is_feasible = self.check_feasibility(&false_path.constraints);
                    
                    if true_path.is_feasible && true_path.constraints.len() <= self.config.max_constraints_per_path {
                        worklist.push_back(true_path);
                    }
                    if false_path.is_feasible && false_path.constraints.len() <= self.config.max_constraints_per_path {
                        worklist.push_back(false_path);
                    }
                }
                SegmentResult::Revert(reason) => {
                    // Path terminou em REVERT, descarta
                    path.state_changes.push(SymbolicStateChange::Log(reason, vec![]));
                    all_paths.push(path); // Mantém para análise, mas marca como inviável
                }
                SegmentResult::JumpIndirect => {
                    // Jump indireto - não resolvido
                    path.is_feasible = false;
                    all_paths.push(path);
                }
            }
        }
        
        // Filtra paths inviáveis
        let total_paths_explored = all_paths.len();
        let feasible_paths: Vec<SymbolicPath> = all_paths
            .into_iter()
            .filter(|p| p.is_feasible && !p.constraints.is_empty())
            .collect();
        
        SymbolicExecutionResult {
            paths: feasible_paths,
            total_paths_explored,
            branches_encountered,
            max_depth_reached,
            analysis_time_ms: start.elapsed().as_millis() as u64,
        }
    }
    
    /// Executa um segmento linear de código até encontrar um branch
    fn execute_path_segment(
        &mut self,
        bytecode: &[u8],
        path: &mut SymbolicPath,
    ) -> SegmentResult {
        let mut pc = path.pc;
        
        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            
            match opcode {
                0x60..=0x7F => { // PUSH1..PUSH32
                    let push_len = (opcode - 0x5F) as usize;
                    if pc + 1 + push_len <= bytecode.len() {
                        let value = &bytecode[pc + 1..pc + 1 + push_len];
                        path.stack.push(Symbol::Concrete(U256::from_bytes_be(value)));
                    }
                    pc += 1 + push_len;
                    continue;
                }
                
                0x80..=0x8F => { // DUP1..DUP16
                    let n = (opcode - 0x80) as usize;
                    if n < path.stack.len() {
                        path.stack.push(path.stack[path.stack.len() - 1 - n].clone());
                    }
                }
                
                0x90..=0x9F => { // SWAP1..SWAP16
                    let n = (opcode - 0x90) as usize + 1;
                    if n <= path.stack.len() {
                        let len = path.stack.len();
                        path.stack.swap(len - 1, len - 1 - n);
                    }
                }
                
                // EQ - cria branch condicional
                0x14 => {
                    if path.stack.len() >= 2 {
                        let a = path.stack.pop().unwrap();
                        let b = path.stack.pop().unwrap();
                        
                        let condition = self.format_condition(&a, &b, "==");
                        
                        // Para JUMPI que virá depois, precisamos criar branch
                        // Verifica se o próximo opcode é JUMPI
                        let next_pc = pc + 1;
                        if next_pc < bytecode.len() && bytecode[next_pc] == 0x57 {
                            // Retorna branch para ser processado
                            path.stack.push(Symbol::Symbolic("eq_flag".to_string()));
                            return SegmentResult::Branch(
                                condition,
                                next_pc + 1, // true target será resolvido no JUMPI
                                next_pc + 1, // false target
                            );
                        } else {
                            path.stack.push(Symbol::Symbolic(condition));
                        }
                    }
                }
                
                // ISZERO
                0x15 => {
                    if let Some(val) = path.stack.pop() {
                        let condition = match val {
                            Symbol::Concrete(v) if v == U256::zero() => "true".to_string(),
                            Symbol::Concrete(_) => "false".to_string(),
                            Symbol::Symbolic(s) => format!("!{}", s),
                            _ => "!val".to_string(),
                        };
                        path.stack.push(Symbol::Symbolic(condition));
                    }
                }
                
                // JUMPI - branch condicional
                0x57 => {
                    if path.stack.len() >= 2 {
                        let cond = path.stack.pop().unwrap();
                        let dest = path.stack.pop().unwrap();
                        
                        let cond_str = match cond {
                            Symbol::Concrete(v) if v == U256::zero() => "false".to_string(),
                            Symbol::Concrete(_) => "true".to_string(),
                            Symbol::Symbolic(s) => s,
                            _ => "cond".to_string(),
                        };
                        
                        // Resolve destino se for concreto
                        if let Symbol::Concrete(dest_val) = dest {
                            let target_pc = dest_val.0[3] as usize; // Simplificado
                            if target_pc < bytecode.len() && bytecode[target_pc] == 0x5B {
                                return SegmentResult::Branch(cond_str, target_pc, pc + 1);
                            }
                        }
                        
                        // Destino simbólico ou inválido
                        return SegmentResult::JumpIndirect;
                    }
                }
                
                // CALLER
                0x33 => {
                    path.stack.push(Symbol::Symbolic("msg.sender".to_string()));
                }
                
                // CALLVALUE
                0x34 => {
                    path.stack.push(Symbol::Symbolic("msg.value".to_string()));
                }
                
                // SLOAD
                0x54 => {
                    if let Some(slot) = path.stack.pop() {
                        let slot_desc = match slot {
                            Symbol::Concrete(v) => format!("storage[{}]", v),
                            Symbol::Symbolic(s) => format!("storage[{}]", s),
                            _ => "storage[slot]".to_string(),
                        };
                        path.stack.push(Symbol::Symbolic(slot_desc));
                    }
                }
                
                // SSTORE
                0x55 => {
                    if let (Some(slot), Some(value)) = (path.stack.pop(), path.stack.pop()) {
                        let slot_val = match &slot {
                            Symbol::Concrete(v) => v.0[3] as u64,
                            _ => 0,
                        };
                        
                        path.state_changes.push(SymbolicStateChange::StorageWrite(slot_val, value.clone()));
                        
                        let slot_desc = match slot {
                            Symbol::Concrete(v) => format!("storage[{}]", v),
                            Symbol::Symbolic(s) => format!("storage[{}]", s),
                            _ => "storage[slot]".to_string(),
                        };
                        let value_desc = match value {
                            Symbol::Concrete(v) => format!(" = {}", v),
                            Symbol::Symbolic(s) => format!(" = {}", s),
                            _ => " = value".to_string(),
                        };
                        
                        path.constraints.push(PathCondition {
                            condition: format!("{} {}", slot_desc, value_desc),
                            pc,
                            is_taken: true,
                        });
                    }
                }
                
                // CALL
                0xF1 => {
                    if path.stack.len() >= 7 {
                        let gas = path.stack.pop().unwrap();
                        let target = path.stack.pop().unwrap();
                        let value = path.stack.pop().unwrap();
                        let _args_offset = path.stack.pop().unwrap();
                        let _args_length = path.stack.pop().unwrap();
                        let _ret_offset = path.stack.pop().unwrap();
                        let _ret_length = path.stack.pop().unwrap();
                        
                        let target_str = match target {
                            Symbol::Concrete(v) => format!("0x{:040x}", v.0[3]),
                            Symbol::Symbolic(s) => s,
                            _ => "unknown".to_string(),
                        };
                        
                        let value_sym = value.clone();
                        path.state_changes.push(SymbolicStateChange::Call(target_str, value, vec![]));
                        
                        // Adiciona constraint para o valor
                        if let Symbol::Concrete(v) = value_sym {
                            if v != U256::zero() {
                                path.constraints.push(PathCondition {
                                    condition: format!("msg.value >= {}", v),
                                    pc,
                                    is_taken: true,
                                });
                            }
                        }
                        
                        // Resultado da CALL (1 = sucesso, 0 = falha)
                        path.stack.push(Symbol::Symbolic("call_result".to_string()));
                    }
                }
                
                // DELEGATECALL
                0xF4 => {
                    if path.stack.len() >= 6 {
                        let _gas = path.stack.pop().unwrap();
                        let target = path.stack.pop().unwrap();
                        let _args_offset = path.stack.pop().unwrap();
                        let _args_length = path.stack.pop().unwrap();
                        let _ret_offset = path.stack.pop().unwrap();
                        let _ret_length = path.stack.pop().unwrap();
                        
                        let target_str = match target {
                            Symbol::Concrete(v) => format!("0x{:040x}", v.0[3]),
                            Symbol::Symbolic(s) => s,
                            _ => "unknown".to_string(),
                        };
                        
                        path.state_changes.push(SymbolicStateChange::Delegatecall(target_str));
                        path.stack.push(Symbol::Symbolic("delegatecall_result".to_string()));
                    }
                }
                
                // SELFDESTRUCT
                0xFF => {
                    if let Some(_recipient) = path.stack.pop() {
                        path.state_changes.push(SymbolicStateChange::SelfDestruct("any".to_string()));
                        path.constraints.push(PathCondition {
                            condition: "SELFDESTRUCT".to_string(),
                            pc,
                            is_taken: true,
                        });
                        return SegmentResult::Complete;
                    }
                }
                
                // REVERT
                0xFD => {
                    path.constraints.push(PathCondition {
                        condition: "REVERT".to_string(),
                        pc,
                        is_taken: false,
                    });
                    return SegmentResult::Revert("explicit_revert".to_string());
                }
                
                // STOP
                0x00 | 0xF3 => {
                    return SegmentResult::Complete;
                }
                
                // TIMESTAMP
                0x42 => {
                    path.stack.push(Symbol::Symbolic("block.timestamp".to_string()));
                }
                
                // NUMBER (block.number)
                0x43 => {
                    path.stack.push(Symbol::Symbolic("block.number".to_string()));
                }
                
                _ => {}
            }
            
            pc += 1;
        }
        
        SegmentResult::Complete
    }
    
    /// Formata uma condição entre dois símbolos
    fn format_condition(&self, a: &Symbol, b: &Symbol, op: &str) -> String {
        match (a, b) {
            (Symbol::Concrete(va), Symbol::Concrete(vb)) => {
                format!("{} {} {}", va, op, vb)
            }
            (Symbol::Concrete(v), Symbol::Symbolic(s)) |
            (Symbol::Symbolic(s), Symbol::Concrete(v)) => {
                format!("{} {} {}", s, op, v)
            }
            (Symbol::Symbolic(s1), Symbol::Symbolic(s2)) => {
                format!("{} {} {}", s1, op, s2)
            }
            _ => format!("? {} ?", op),
        }
    }
    
    /// Verifica viabilidade de um conjunto de constraints
    fn check_feasibility(&self, constraints: &[PathCondition]) -> bool {
        if !self.config.enable_smt {
            // Sem SMT, assume que são viáveis
            return true;
        }
        
        // TODO: Integrar Z3 solver
        // Por enquanto, verifica contradições óbvias
        
        let mut has_true = false;
        let mut has_false = false;
        
        for constraint in constraints {
            if constraint.condition == "true" {
                has_true = true;
            }
            if constraint.condition == "false" {
                has_false = true;
            }
        }
        
        !(has_true && has_false)
    }
    
    fn next_path_id(&mut self) -> usize {
        let id = self.next_path_id;
        self.next_path_id += 1;
        id
    }
    
    /// Gera concrete test inputs a partir de constraints
    pub fn generate_test_inputs(&self, path: &SymbolicPath) -> Vec<TestInput> {
        let mut inputs = Vec::new();
        
        for constraint in &path.constraints {
            // Parse constraint e gera valores concretos
            if constraint.condition.contains("msg.sender") {
                // Extrai endereço esperado ou gera aleatório
                let caller = self.extract_caller_from_constraint(&constraint.condition);
                inputs.push(TestInput {
                    caller,
                    ..Default::default()
                });
            }
            
            if constraint.condition.contains("msg.value") {
                let value = self.extract_value_from_constraint(&constraint.condition);
                inputs.push(TestInput {
                    value,
                    ..Default::default()
                });
            }
        }
        
        if inputs.is_empty() {
            inputs.push(TestInput::default());
        }
        
        inputs
    }
    
    fn extract_caller_from_constraint(&self, constraint: &str) -> String {
        // Exemplo: "msg.sender == 0x123..." -> extrai o endereço
        let parts: Vec<&str> = constraint.split("==").collect();
        if parts.len() >= 2 {
            let maybe_addr = parts[1].trim();
            if maybe_addr.starts_with("0x") && maybe_addr.len() >= 42 {
                return maybe_addr.to_string();
            }
        }
        "0x0000000000000000000000000000000000000000".to_string()
    }
    
    fn extract_value_from_constraint(&self, constraint: &str) -> u128 {
        let parts: Vec<&str> = constraint.split(">=").collect();
        if parts.len() >= 2 {
            if let Ok(val) = parts[1].trim().parse::<u128>() {
                return val;
            }
        }
        0
    }
    
    /// Exporta constraints para formato SMT-LIB (Z3)
    pub fn export_to_smtlib(&self, path: &SymbolicPath) -> String {
        let mut smt = String::new();
        smt.push_str("(set-logic QF_AUFBV)\n");
        smt.push_str("(declare-fun msg.sender () (_ BitVec 160))\n");
        smt.push_str("(declare-fun msg.value () (_ BitVec 256))\n");
        smt.push_str("(declare-fun block.timestamp () (_ BitVec 256))\n");
        smt.push_str("(declare-fun block.number () (_ BitVec 256))\n\n");
        
        for constraint in &path.constraints {
            let smt_cond = self.constraint_to_smt(&constraint.condition);
            smt.push_str(&format!("(assert {})\n", smt_cond));
        }
        
        smt.push_str("\n(check-sat)\n(get-model)\n");
        smt
    }
    
    fn constraint_to_smt(&self, constraint: &str) -> String {
        if constraint.contains("msg.sender") {
            constraint
                .replace("msg.sender", "msg.sender")
                .replace("==", "=")
        } else if constraint.contains("msg.value") {
            constraint
                .replace("msg.value", "msg.value")
                .replace(">=", "bvuge")
        } else {
            format!("(= true {})", constraint)
        }
    }
}

// ============================================================
// FUNÇÕES AUXILIARES
// ============================================================

#[derive(Debug, Clone)]
pub struct TestInput {
    pub caller: String,
    pub value: u128,
    pub calldata: Vec<u8>,
    pub gas_limit: u64,
}

impl Default for TestInput {
    fn default() -> Self {
        Self {
            caller: "0x0000000000000000000000000000000000000000".to_string(),
            value: 0,
            calldata: Vec::new(),
            gas_limit: 10_000_000,
        }
    }
}

#[derive(Debug)]
enum SegmentResult {
    Complete,
    Branch(String, usize, usize),  // condition, true_target, false_target
    Revert(String),
    JumpIndirect,
}

// ============================================================
// FUNÇÃO ORIGINAL (mantida para compatibilidade)
// ============================================================

pub fn execute_symbolic(analysis: &BytecodeAnalysis, selector: &[u8; 4]) -> Vec<PathCondition> {
    let mut executor = forthresSymbolicExecutor::new(SymbolicConfig::default());
    let result = executor.execute(analysis, selector);
    
    // Converte o primeiro path para o formato antigo
    if let Some(first_path) = result.paths.first() {
        first_path.constraints.clone()
    } else {
        Vec::new()
    }
}

fn find_selector_position(bytecode: &[u8], selector: &[u8; 4]) -> usize {
    bytecode
        .windows(4)
        .position(|window| window == selector)
        .unwrap_or(0)
}

// ============================================================
// U256 (mantido do original)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct U256([u64; 4]);

impl U256 {
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut result = [0u64; 4];
        let len = bytes.len().min(32);
        
        for i in 0..len {
            let byte_idx = i;
            let word_idx = byte_idx / 8;
            let shift = (7 - (byte_idx % 8)) * 8;
            result[word_idx] |= (bytes[i] as u64) << shift;
        }
        
        Self(result)
    }
    
    pub fn from_u64(value: u64) -> Self {
        Self([0, 0, 0, value])
    }
    
    pub fn zero() -> Self {
        Self([0, 0, 0, 0])
    }
    
    pub fn as_u64(&self) -> u64 {
        self.0[3]
    }
}

impl std::fmt::Display for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 {
            write!(f, "{}", self.0[3])
        } else {
            write!(f, "0x{:016x}{:016x}{:016x}{:016x}", self.0[0], self.0[1], self.0[2], self.0[3])
        }
    }
}

// ============================================================
// TESTES
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_u256_conversion() {
        let val = U256::from_u64(42);
        assert_eq!(val.as_u64(), 42);
        assert_eq!(format!("{}", val), "42");
    }
    
    #[test]
    fn test_symbolic_executor_creation() {
        let config = SymbolicConfig::default();
        let executor = forthresSymbolicExecutor::new(config);
        assert_eq!(executor.next_path_id, 0);
    }
}
