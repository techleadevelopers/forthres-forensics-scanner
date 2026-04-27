mod path_finder;
mod probability_engine;
mod economic_impact;
mod mev_integration;
mod symbolic_executor;
mod feedback_loop;

// Comentados - não estão sendo usados no OffensiveEngine::analyze atual
// pub use path_finder::{find_exploit_paths, ControlFlowPath, Condition, StateChange};
// pub use probability_engine::calculate_probabilities;
// pub use economic_impact::calculate_economic_value;
// pub use mev_integration::analyze_mev;

use anyhow::Result;
use crate::bytecode::BytecodeAnalysis;
use crate::forensics::ForensicsEngine;
use crate::reporter::{ExploitPathReport, MevOpportunityReport};

#[derive(Debug, Clone)]
pub struct OffensiveConfig {
    pub max_paths: usize,
    pub monte_carlo_samples: usize,
    pub min_probability: f64,
    pub min_economic_value_eth: f64,
}

pub type ExploitPath = ExploitPathReport;
pub type MevOpportunity = MevOpportunityReport;

#[derive(Debug, Clone)]
pub struct OffensiveReport {
    pub exploit_paths: Vec<ExploitPath>,
    pub mev_opportunities: Vec<MevOpportunity>,
    pub exploitation_probability: f64,
    pub risk_adjusted_value: f64,
}

#[derive(Clone)]
pub struct OffensiveEngine {
    config: OffensiveConfig,
    forensics: ForensicsEngine,
}

impl OffensiveEngine {
    pub fn new(config: OffensiveConfig, forensics: ForensicsEngine) -> Self {
        Self { config, forensics }
    }

    pub async fn analyze(&self, _contract: &str, _analysis: &BytecodeAnalysis) -> Result<OffensiveReport> {
        // Implementação simplificada por enquanto
        // TODO: Integrar com feedback_loop quando estiver pronto
        Ok(OffensiveReport {
            exploit_paths: Vec::new(),
            mev_opportunities: Vec::new(),
            exploitation_probability: 0.0,
            risk_adjusted_value: 0.0,
        })
    }
}