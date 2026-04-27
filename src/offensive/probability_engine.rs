// src/offensive/probability_engine.rs
use rand::Rng;
use std::time::Duration;
use tokio::time::timeout;
use crate::forensics::ForensicsEngine;
use super::path_finder::{ControlFlowPath, Condition};

#[derive(Debug, Clone)]
pub struct ControlFlowPathWithProb {
    pub path: ControlFlowPath,
    pub probability: f64,
}

pub async fn calculate_probabilities(
    paths: Vec<ControlFlowPath>,
    forensics: &ForensicsEngine,
    contract: &str,
    samples: usize,
) -> Vec<ControlFlowPathWithProb> {
    let mut results = Vec::new();
    
    for path in paths {
        let prob = calculate_path_probability(&path, forensics, contract, samples).await;
        if prob > 0.0 {
            results.push(ControlFlowPathWithProb { path, probability: prob });
        }
    }
    
    results.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap());
    results
}

async fn calculate_path_probability(
    path: &ControlFlowPath,
    forensics: &ForensicsEngine,
    contract: &str,
    samples: usize,
) -> f64 {
    let mut prob = 1.0;
    
    for condition in &path.conditions {
        let cond_prob = match condition {
            Condition::CallerEq(address) => {
                estimate_caller_probability(forensics, contract, address, samples).await
            }
            Condition::CallerEqStorage(slot) => {
                estimate_caller_storage_probability(forensics, contract, *slot, samples).await
            }
            Condition::ValueGt(threshold) => {
                estimate_value_probability(*threshold, true, samples)
            }
            Condition::ValueLt(threshold) => {
                estimate_value_probability(*threshold, false, samples)
            }
            Condition::BalanceGt(threshold) => {
                estimate_balance_probability(forensics, contract, *threshold, true, samples).await
            }
            Condition::BalanceLt(threshold) => {
                estimate_balance_probability(forensics, contract, *threshold, false, samples).await
            }
            Condition::StorageSlotEq(slot, expected) => {
                estimate_storage_probability(forensics, contract, *slot, expected, samples).await
            }
            Condition::StorageSlotNeq(slot, unexpected) => {
                estimate_storage_neq_probability(forensics, contract, *slot, unexpected, samples).await
            }
            Condition::TimestampGt(threshold) => {
                estimate_timestamp_probability(*threshold, true)
            }
            Condition::TimestampLt(threshold) => {
                estimate_timestamp_probability(*threshold, false)
            }
            Condition::BlockNumberGt(threshold) => {
                estimate_block_number_probability(*threshold, true).await
            }
            Condition::BlockNumberLt(threshold) => {
                estimate_block_number_probability(*threshold, false).await
            }
            Condition::IsContract(address) => {
                estimate_is_contract_probability(forensics, address).await
            }
            Condition::NotZeroAddress => {
                0.999
            }
        };
        
        prob *= cond_prob;
        
        if prob < 0.001 {
            break;
        }
    }
    
    prob.min(1.0)
}

// NOVA FUNÇÃO: estima probabilidade baseada no block number
async fn estimate_block_number_probability(threshold: u64, is_greater: bool) -> f64 {
    // Em produção, buscaria o block number atual via RPC
    // Por enquanto, usamos um valor estimado (mainnet ~20M)
    let current_block = 20_000_000u64;
    
    if is_greater {
        if current_block > threshold {
            0.99
        } else {
            let remaining = threshold - current_block;
            if remaining > 1_000_000 {
                0.01  // Muitos blocos para chegar
            } else if remaining > 100_000 {
                0.1
            } else if remaining > 10_000 {
                0.3
            } else if remaining > 1_000 {
                0.6
            } else {
                0.8
            }
        }
    } else {
        if current_block < threshold {
            0.99
        } else {
            // Já passou do threshold
            let passed = current_block - threshold;
            if passed > 1_000_000 {
                0.01
            } else if passed > 100_000 {
                0.1
            } else {
                0.5
            }
        }
    }
}

async fn estimate_caller_probability(
    forensics: &ForensicsEngine,
    contract: &str,
    expected_owner: &str,
    samples: usize,
) -> f64 {
    let mut success_count = 0;
    
    if expected_owner == "0x0000000000000000000000000000000000000000" {
        return 0.001;
    }
    
    if expected_owner.starts_with("0x") && expected_owner.len() == 42 {
        return 0.0001;
    }
    
    for _ in 0..samples {
        let random_caller = format!("0x{:040x}", rand::thread_rng().gen::<u128>());
        
        let snap = forensics.snapshot().await.unwrap_or_default();
        
        let result = timeout(
            Duration::from_secs(2),
            forensics.eth_call(&random_caller, contract, "0x", "0x0")
        ).await;
        
        if let Ok(Ok(output)) = result {
            if output != "0x" && !output.contains("revert") {
                success_count += 1;
            }
        }
        
        let _ = forensics.revert(&snap).await;
    }
    
    success_count as f64 / samples as f64
}

async fn estimate_caller_storage_probability(
    forensics: &ForensicsEngine,
    contract: &str,
    slot: u64,
    _samples: usize,
) -> f64 {
    let slot_hex = format!("0x{:x}", slot);
    if let Ok(current_owner) = forensics.get_storage(contract, &slot_hex).await {
        if current_owner != "0x0000000000000000000000000000000000000000" {
            return 0.01;
        }
    }
    
    0.3
}

fn estimate_value_probability(threshold: u128, is_greater: bool, samples: usize) -> f64 {
    let mut count = 0;
    
    for _ in 0..samples {
        let random_value = rand::thread_rng().gen_range(0..1000000000000000000u128);
        let condition_met = if is_greater {
            random_value > threshold
        } else {
            random_value < threshold
        };
        
        if condition_met {
            count += 1;
        }
    }
    
    count as f64 / samples as f64
}

async fn estimate_balance_probability(
    forensics: &ForensicsEngine,
    contract: &str,
    threshold: u128,
    is_greater: bool,
    _samples: usize,
) -> f64 {
    let current_balance = forensics.get_balance(contract).await.unwrap_or(0);
    
    if is_greater {
        if current_balance > threshold {
            0.95
        } else {
            0.05
        }
    } else {
        if current_balance < threshold {
            0.95
        } else {
            0.05
        }
    }
}

async fn estimate_storage_probability(
    forensics: &ForensicsEngine,
    contract: &str,
    slot: u64,
    expected: &str,
    _samples: usize,
) -> f64 {
    let slot_hex = format!("0x{:x}", slot);
    if let Ok(current) = forensics.get_storage(contract, &slot_hex).await {
        if current.to_lowercase() == expected.to_lowercase() {
            return 0.99;
        }
    }
    
    0.1
}

async fn estimate_storage_neq_probability(
    forensics: &ForensicsEngine,
    contract: &str,
    slot: u64,
    unexpected: &str,
    _samples: usize,
) -> f64 {
    let slot_hex = format!("0x{:x}", slot);
    if let Ok(current) = forensics.get_storage(contract, &slot_hex).await {
        if current.to_lowercase() != unexpected.to_lowercase() {
            return 0.95;
        }
    }
    
    0.5
}

fn estimate_timestamp_probability(threshold: u64, is_greater: bool) -> f64 {
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    if is_greater {
        if current_time > threshold {
            return 0.99;
        } else {
            let remaining = threshold - current_time;
            if remaining > 86400 {
                return 0.01;
            } else if remaining > 3600 {
                return 0.1;
            } else if remaining > 60 {
                return 0.3;
            } else {
                return 0.6;
            }
        }
    } else {
        if current_time < threshold {
            return 0.99;
        } else {
            return 0.01;
        }
    }
}

async fn estimate_is_contract_probability(forensics: &ForensicsEngine, address: &str) -> f64 {
    if let Ok(code) = forensics.eth_call(address, address, "0x", "0x0").await {
        if code != "0x" {
            return 0.95;
        }
    }
    0.05
}