// scanner/rust_core/src/lib.rs (antigo mod.rs)

// ============================================================================
// MÓDULOS EXPORTADOS (API PÚBLICA)
// ============================================================================

pub mod config;
pub mod types;

// ============================================================================
// MOTORES VÁLIDOS (PARA INTEGRAÇÃO COM PYTHON VIA PYO3)
// ============================================================================

pub mod regex_engine;
pub mod hyperscan_engine;
pub mod correlation_graph;
pub mod waf_detector;
pub mod waf_payloads;
pub mod rate_limiter;
pub mod payload_dictionary;
pub mod genetic_engine;

// ============================================================================
// NÃO EXPORTADOS (ORQUESTRAÇÃO - MANTER EM PYTHON)
// ============================================================================
// NOTA: orchestrator.rs, modules.rs e waf_behavior_analysis.rs
// NÃO DEVEM SER COMPILADOS NO MÓDULO RUST.
// Estes arquivos contêm lógica de orquestração de alto nível que
// deve permanecer em Python. Remova-os do build ou comente as declarações:
//
// pub mod orchestrator;     // ❌ NÃO EXPORTAR
// pub mod modules;          // ❌ NÃO EXPORTAR
// pub mod waf_behavior_analysis; // ❌ NÃO EXPORTAR
// pub mod port_scanner;     // ❌ NÃO EXPORTAR (dependências externas)
// pub mod subdomain_scanner; // ❌ NÃO EXPORTAR (dependências externas)

// ============================================================================
// RE-EXPORTS PARA FACILITAR O USO
// ============================================================================

pub use config::*;
pub use types::*;
pub use regex_engine::RegexEngine;
pub use hyperscan_engine::HyperscanEngine;
pub use correlation_graph::CorrelationGraph;
pub use waf_detector::WafDetector;
pub use waf_payloads::PayloadMutator;
pub use rate_limiter::RateLimiter;
pub use payload_dictionary::PayloadDictionary;
pub use genetic_engine::GeneticEngine;