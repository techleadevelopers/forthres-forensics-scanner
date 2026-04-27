// src/offensive/mev_integration.rs
use crate::forensics::ForensicsEngine;
use super::economic_impact::ExploitPathWithValue;

#[derive(Debug, Clone)]
pub struct MevOpportunity {
    pub mev_type: String,
    pub estimated_profit_eth: f64,
    pub competition_score: f64,
    pub bundle_required: bool,
    pub suggested_tip_bps: u64,
}

pub async fn analyze_mev(
    paths: &[ExploitPathWithValue],
    contract: &str,
    forensics: &ForensicsEngine,
) -> Vec<MevOpportunity> {
    let mut opportunities = Vec::new();
    
    for path in paths {
        if path.economic_value_eth > 0.01 {
            // Backrun
            if let Some(backrun) = check_backrun_possible(path, contract, forensics).await {
                opportunities.push(backrun);
            }
            
            // Sanduíche
            if let Some(sandwich) = check_sandwich_possible(path, contract, forensics).await {
                opportunities.push(sandwich);
            }
            
            // Frontrun
            if let Some(frontrun) = check_frontrun_possible(path, contract, forensics).await {
                opportunities.push(frontrun);
            }
        }
    }
    
    opportunities
}

async fn check_backrun_possible(
    path: &ExploitPathWithValue,
    _contract: &str,
    _forensics: &ForensicsEngine,
) -> Option<MevOpportunity> {
    // Verifica se é uma função que pode ser backrunada
    let selector = &path.path.entry_selector;
    
    // Funções comuns de swap
    let swap_selectors = vec![
        "swapExactTokensForTokens",
        "swapExactETHForTokens", 
        "swapTokensForExactETH",
        "swap",
    ];
    
    let is_swap = swap_selectors.iter().any(|s| selector.contains(s));
    
    if is_swap {
        let profit = path.economic_value_eth;
        let competition_score = estimate_competition_score(profit).await;
        
        Some(MevOpportunity {
            mev_type: "BACKRUN".to_string(),
            estimated_profit_eth: profit * 0.8, // 20% MEV tax
            competition_score,
            bundle_required: true,
            suggested_tip_bps: calculate_tip_bps(profit, competition_score),
        })
    } else {
        None
    }
}

async fn check_sandwich_possible(
    path: &ExploitPathWithValue,
    _contract: &str,
    _forensics: &ForensicsEngine,
) -> Option<MevOpportunity> {
    // Verifica se tem liquidez suficiente para sandwich
    if path.economic_value_eth < 0.05 {
        return None;
    }
    
    Some(MevOpportunity {
        mev_type: "SANDWICH".to_string(),
        estimated_profit_eth: path.economic_value_eth * 0.6,
        competition_score: 0.7,
        bundle_required: true,
        suggested_tip_bps: 2000, // 20% tip
    })
}

async fn check_frontrun_possible(
    path: &ExploitPathWithValue,
    _contract: &str,
    _forensics: &ForensicsEngine,
) -> Option<MevOpportunity> {
    // Verifica se é uma inicialização ou mint
    let selector = &path.path.entry_selector;
    
    if selector.contains("initialize") || selector.contains("mint") {
        Some(MevOpportunity {
            mev_type: "FRONTRUN".to_string(),
            estimated_profit_eth: path.economic_value_eth * 0.9,
            competition_score: 0.9,
            bundle_required: false,
            suggested_tip_bps: 3000,
        })
    } else {
        None
    }
}

async fn estimate_competition_score(profit_eth: f64) -> f64 {
    // Quanto maior o lucro, maior a competição
    if profit_eth > 10.0 {
        0.95 // Muita competição
    } else if profit_eth > 1.0 {
        0.7
    } else if profit_eth > 0.1 {
        0.4
    } else {
        0.1 // Pouca competição
    }
}

fn calculate_tip_bps(profit_eth: f64, competition_score: f64) -> u64 {
    // Tip baseado em lucro e competição
    let base_tip = 500; // 5%
    let competition_multiplier = (1.0 + competition_score * 2.0).min(3.0);
    let profit_multiplier = (profit_eth / 0.1).min(5.0);
    
    ((base_tip as f64 * competition_multiplier * profit_multiplier) as u64).max(500).min(10000)
}