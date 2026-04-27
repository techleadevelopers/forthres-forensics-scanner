use sha3::{Digest, Keccak256};
use tracing::debug;

pub const OPCODE_DELEGATECALL: u8 = 0xF4;
pub const OPCODE_SELFDESTRUCT: u8 = 0xFF;
pub const OPCODE_CALLCODE: u8 = 0xF2;
pub const OPCODE_CREATE2: u8 = 0xF5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternSeverity {
    Critical,
    High,
    Medium,
    Info,
}

impl std::fmt::Display for PatternSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternSeverity::Critical => write!(f, "CRITICAL"),
            PatternSeverity::High => write!(f, "HIGH"),
            PatternSeverity::Medium => write!(f, "MEDIUM"),
            PatternSeverity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BytecodeFlag {
    pub opcode: u8,
    pub offset: usize,
    pub severity: PatternSeverity,
}

#[derive(Debug, Clone)]
pub struct BytecodeAnalysis {
    pub function_selectors: Vec<[u8; 4]>,
    pub flags: Vec<BytecodeFlag>,
    pub has_selfdestruct: bool,
    pub has_delegatecall: bool,
    pub has_callcode: bool,
    pub has_create2: bool,
    pub risk_score: u32,
    pub bytecode: Option<Vec<u8>>,  // ← CAMPO ADICIONADO
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
            .or_else(|| {
                self.flags
                    .iter()
                    .find(|flag| flag.severity == PatternSeverity::Info)
                    .map(|flag| &flag.severity)
            })
    }
}

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

    pub fn extract_selectors(bytecode: &[u8]) -> Vec<[u8; 4]> {
        let mut selectors = Vec::new();
        let len = bytecode.len();
        let mut i = 0;

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
                    }

                    i += 5;
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

    pub fn analyze(bytecode: &[u8]) -> BytecodeAnalysis {
        let mut flags = Vec::new();
        let mut has_selfdestruct = false;
        let mut has_delegatecall = false;
        let mut has_callcode = false;
        let mut has_create2 = false;
        let mut risk_score: u32 = 0;

        let len = bytecode.len();
        let mut i = 0;

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
                    });
                }
                OPCODE_DELEGATECALL => {
                    has_delegatecall = true;
                    risk_score += 35;
                    flags.push(BytecodeFlag {
                        opcode,
                        offset: i,
                        severity: PatternSeverity::High,
                    });
                }
                OPCODE_CALLCODE => {
                    has_callcode = true;
                    risk_score += 30;
                    flags.push(BytecodeFlag {
                        opcode,
                        offset: i,
                        severity: PatternSeverity::High,
                    });
                }
                OPCODE_CREATE2 => {
                    has_create2 = true;
                    risk_score += 10;
                    flags.push(BytecodeFlag {
                        opcode,
                        offset: i,
                        severity: PatternSeverity::Medium,
                    });
                }
                0x60..=0x7F => {
                    let push_len = (opcode - 0x5F) as usize;
                    i += push_len;
                }
                _ => {}
            }

            i += 1;
        }

        BytecodeAnalysis {
            function_selectors: Self::extract_selectors(bytecode),
            flags,
            has_selfdestruct,
            has_delegatecall,
            has_callcode,
            has_create2,
            risk_score,
            bytecode: Some(bytecode.to_vec()),  // ← LINHA ADICIONADA
        }
    }

    pub fn match_dangerous_signatures(selectors: &[[u8; 4]]) -> Vec<String> {
        let dangerous: &[(&str, &str)] = &[
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
        ];

        let mut matches = Vec::new();

        for (sig, desc) in dangerous {
            let expected = Self::selector_from_sig(sig);
            if selectors.contains(&expected) {
                matches.push(format!("{} - {}", sig, desc));
            }
        }

        matches
    }

    pub fn selector_to_hex(selector: &[u8; 4]) -> String {
        format!("0x{}", hex::encode(selector))
    }
}

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
        let bytecode = vec![0x60, 0x00, 0xFF];
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
}