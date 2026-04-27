// src/offensive/symbolic_executor.rs
use crate::bytecode::BytecodeAnalysis;

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

pub fn execute_symbolic(analysis: &BytecodeAnalysis, selector: &[u8; 4]) -> Vec<PathCondition> {
    let mut conditions = Vec::new();
    let empty_vec = vec![];
    let bytecode = analysis.bytecode.as_ref().unwrap_or(&empty_vec);
    
    let selector_bytes = selector;
    let start = find_selector_position(bytecode, selector_bytes);
    
    if start < bytecode.len() {
        let mut pc = start;
        let mut stack: Vec<Symbol> = Vec::new();
        
        while pc < bytecode.len() && conditions.len() < 50 {
            let opcode = bytecode[pc];
            
            match opcode {
                0x60..=0x7F => {
                    let push_len = (opcode - 0x5F) as usize;
                    if pc + 1 + push_len <= bytecode.len() {
                        let value = &bytecode[pc + 1..pc + 1 + push_len];
                        stack.push(Symbol::Concrete(U256::from_bytes_be(value)));
                    }
                    pc += 1 + push_len;
                    continue;
                }
                
                0x80..=0x8F => {
                    let n = (opcode - 0x80) as usize;
                    if n < stack.len() {
                        stack.push(stack[stack.len() - 1 - n].clone());
                    }
                }
                
                0x90..=0x9F => {
                    let n = (opcode - 0x90) as usize + 1;
                    if n <= stack.len() {
                        let len = stack.len();
                        stack.swap(len - 1, len - 1 - n);
                    }
                }
                
                0x14 => {
                    if stack.len() >= 2 {
                        let a = stack.pop().unwrap();
                        let b = stack.pop().unwrap();
                        
                        let condition = match (a, b) {
                            (Symbol::Concrete(va), Symbol::Concrete(vb)) => {
                                Some(format!("{} == {}", va, vb))
                            }
                            (Symbol::Concrete(v), Symbol::Symbolic(s)) |
                            (Symbol::Symbolic(s), Symbol::Concrete(v)) => {
                                Some(format!("{} == {}", s, v))
                            }
                            (Symbol::Symbolic(s1), Symbol::Symbolic(s2)) => {
                                Some(format!("{} == {}", s1, s2))
                            }
                            _ => None,
                        };
                        
                        if let Some(cond) = condition {
                            conditions.push(PathCondition {
                                condition: cond,
                                pc,
                                is_taken: true,
                            });
                        }
                        
                        stack.push(Symbol::Symbolic("eq_result".to_string()));
                    }
                }
                
                0x15 => {
                    if let Some(val) = stack.pop() {
                        let condition = match val {
                            Symbol::Concrete(v) if v == U256::zero() => "is_zero".to_string(),
                            Symbol::Symbolic(s) => format!("!{}", s),
                            _ => "!val".to_string(),
                        };
                        conditions.push(PathCondition {
                            condition,
                            pc,
                            is_taken: true,
                        });
                        stack.push(Symbol::Symbolic("iszero_result".to_string()));
                    }
                }
                
                0x33 => {
                    stack.push(Symbol::Symbolic("msg.sender".to_string()));
                }
                
                0x34 => {
                    stack.push(Symbol::Symbolic("msg.value".to_string()));
                }
                
                0x54 => {
                    if let Some(slot) = stack.pop() {
                        let slot_desc = match slot {
                            Symbol::Concrete(v) => format!("storage[{}]", v),
                            Symbol::Symbolic(s) => format!("storage[{}]", s),
                            _ => "storage[slot]".to_string(),
                        };
                        stack.push(Symbol::Symbolic(slot_desc));
                    }
                }
                
                0x55 => {
                    if let (Some(slot), Some(value)) = (stack.pop(), stack.pop()) {
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
                        conditions.push(PathCondition {
                            condition: format!("{} {}", slot_desc, value_desc),
                            pc,
                            is_taken: true,
                        });
                    }
                }
                
                0x57 => {
                    if stack.len() >= 2 {
                        let cond = stack.pop().unwrap();
                        let _dest = stack.pop().unwrap();
                        
                        let condition_desc = match cond {
                            Symbol::Concrete(v) if v == U256::zero() => "false".to_string(),
                            Symbol::Concrete(_) => "true".to_string(),
                            Symbol::Symbolic(s) => format!("if ({})", s),
                            _ => "if (cond)".to_string(),
                        };
                        
                        conditions.push(PathCondition {
                            condition: condition_desc,
                            pc,
                            is_taken: true,
                        });
                    }
                }
                
                0xFD => {
                    conditions.push(PathCondition {
                        condition: "REVERT".to_string(),
                        pc,
                        is_taken: false,
                    });
                    break;
                }
                
                0xFF => {
                    conditions.push(PathCondition {
                        condition: "SELFDESTRUCT".to_string(),
                        pc,
                        is_taken: true,
                    });
                }
                
                _ => {}
            }
            
            pc += 1;
        }
    }
    
    conditions
}

fn find_selector_position(bytecode: &[u8], selector: &[u8; 4]) -> usize {
    bytecode
        .windows(4)
        .position(|window| window == selector)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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