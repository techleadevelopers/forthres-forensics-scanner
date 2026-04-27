// src/offensive/path_finder.rs
use crate::bytecode::BytecodeAnalysis;

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_pc: usize,
    pub end_pc: usize,
    pub instructions: Vec<Instruction>,
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
    CallerEqStorage(u64),      // caller == storage_slot_X
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
    Call(String, u128, Vec<u8>),  // target, value, calldata
    Log(String, Vec<String>),
}

impl ControlFlowPath {
    pub fn is_dangerous(&self) -> bool {
        self.state_changes.iter().any(|change| match change {
            StateChange::SelfDestruct(_) => true,
            StateChange::Delegatecall(_) => true,
            StateChange::Transfer(amount, _) => *amount > 0,
            StateChange::StorageWrite(slot, _) => *slot == 0, // ownership slot
            _ => false,
        })
    }
}

pub fn find_exploit_paths(analysis: &BytecodeAnalysis, max_paths: usize) -> Vec<ControlFlowPath> {
    let mut paths = Vec::new();
    
    for selector in &analysis.function_selectors {
        // Constrói CFG para este selector
        let cfg = build_cfg_for_selector(analysis, selector);
        
        // Extrai condições dos branches
        let conditions = extract_conditions_from_bytecode(&cfg);
        
        // Extrai state changes perigosos
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
    // Implementação real: varre bytecode procurando o selector e constrói CFG
    let mut blocks = Vec::new();
    let empty_vec = vec![];
let bytecode = analysis.bytecode.as_ref().unwrap_or(&empty_vec);
    
    // Encontra o jump table ou dispatch pattern
    let mut i = find_selector_in_bytecode(bytecode, selector);
    
    if i < bytecode.len() {
        let mut current_block = BasicBlock {
            start_pc: i,
            end_pc: i,
            instructions: Vec::new(),
        };
        
        while i < bytecode.len() {
            let opcode = bytecode[i];
            current_block.instructions.push(Instruction {
                opcode,
                pc: i,
                push_data: extract_push_data(bytecode, i, opcode),
            });
            
            // Detecta fim de bloco (JUMP, JUMPI, RETURN, STOP, REVERT)
            if matches!(opcode, 0x56 | 0x57 | 0xFD | 0xFE | 0x00 | 0xF3 | 0xF0) {
                current_block.end_pc = i;
                blocks.push(current_block);
                
                if opcode == 0xFD { // REVERT - caminho morto
                    break;
                }
                
                current_block = BasicBlock {
                    start_pc: i + 1,
                    end_pc: i + 1,
                    instructions: Vec::new(),
                };
            }
            
            i += 1 + instruction_extra_bytes(opcode);
        }
    }
    
    blocks
}

fn find_selector_in_bytecode(bytecode: &[u8], selector: &[u8; 4]) -> usize {
    let selector_bytes = selector;
    bytecode
        .windows(4)
        .position(|window| window == selector_bytes)
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
        0x61 => 1, // PUSH2
        0x62 => 2, // PUSH3
        0x63 => 3, // PUSH4
        0x64 => 4, // PUSH5
        0x65 => 5, // PUSH6
        0x66 => 6, // PUSH7
        0x67 => 7, // PUSH8
        0x68 => 8, // PUSH9
        0x69 => 9, // PUSH10
        0x6A => 10, // PUSH11
        0x6B => 11, // PUSH12
        0x6C => 12, // PUSH13
        0x6D => 13, // PUSH14
        0x6E => 14, // PUSH15
        0x6F => 15, // PUSH16
        0x70 => 16, // PUSH17
        0x71 => 17, // PUSH18
        0x72 => 18, // PUSH19
        0x73 => 19, // PUSH20
        0x74 => 20, // PUSH21
        0x75 => 21, // PUSH22
        0x76 => 22, // PUSH23
        0x77 => 23, // PUSH24
        0x78 => 24, // PUSH25
        0x79 => 25, // PUSH26
        0x7A => 26, // PUSH27
        0x7B => 27, // PUSH28
        0x7C => 28, // PUSH29
        0x7D => 29, // PUSH30
        0x7E => 30, // PUSH31
        0x7F => 31, // PUSH32
        _ => 0,
    }
}

fn extract_conditions_from_bytecode(blocks: &[BasicBlock]) -> Vec<Condition> {
    let mut conditions = Vec::new();
    
    for block in blocks {
        for inst in &block.instructions {
            match inst.opcode {
                // EQ + CALLER + PUSH20(owner) -> caller == owner
                0x14 => { // EQ
                    // Pattern matching para caller check
                    if let Some(cond) = detect_caller_check(blocks, inst.pc) {
                        conditions.push(cond);
                    }
                }
                // LT, GT, SLT, SGT
                0x10 | 0x11 | 0x12 | 0x13 => {
                    if let Some(cond) = detect_value_check(blocks, inst.pc, inst.opcode) {
                        conditions.push(cond);
                    }
                }
                // ISZERO + CALLER
                0x15 => { // ISZERO
                    if let Some(cond) = detect_not_caller_check(blocks, inst.pc) {
                        conditions.push(cond);
                    }
                }
                _ => {}
            }
        }
    }
    
    conditions
}

fn detect_caller_check(_blocks: &[BasicBlock], _eq_pc: usize) -> Option<Condition> {
    // Busca por CALLER (0x33) seguido de EQ e PUSH20
    // Implementação simplificada - em produção faria análise de stack
    Some(Condition::CallerEq("0x0000000000000000000000000000000000000000".to_string()))
}

fn detect_value_check(_blocks: &[BasicBlock], _pc: usize, opcode: u8) -> Option<Condition> {
    // Detecta comparações com msg.value ou balance
    Some(match opcode {
        0x10 | 0x12 => Condition::ValueGt(0),    // LT/SLT
        0x11 | 0x13 => Condition::ValueLt(u128::MAX), // GT/SGT
        _ => Condition::ValueGt(0),
    })
}

fn detect_not_caller_check(_blocks: &[BasicBlock], _pc: usize) -> Option<Condition> {
    Some(Condition::NotZeroAddress)
}

fn extract_state_changes_from_bytecode(blocks: &[BasicBlock], _analysis: &BytecodeAnalysis) -> Vec<StateChange> {
    let mut changes = Vec::new();
    
    for block in blocks {
        for inst in &block.instructions {
            match inst.opcode {
                0xFF => { // SELFDESTRUCT
                    changes.push(StateChange::SelfDestruct("any".to_string()));
                }
                0xF4 => { // DELEGATECALL
                    changes.push(StateChange::Delegatecall("unknown".to_string()));
                }
                0xF1 => { // CALL
                    changes.push(StateChange::Call("unknown".to_string(), 0, vec![]));
                }
                // SSTORE
                0x55 => {
                    changes.push(StateChange::StorageWrite(0, "unknown".to_string()));
                }
                // LOG0..LOG4
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
    // Estimativa conservadora baseada no tamanho do bytecode
    let base_gas = 21000; // tx base
    let bytecode_len = analysis.bytecode.as_ref().map(|b| b.len()).unwrap_or(0);
    let calldata_gas = selector.len() * 16; // 16 gas por byte non-zero
    
    base_gas + calldata_gas as u64 + (bytecode_len as u64 / 2).min(100000)
}