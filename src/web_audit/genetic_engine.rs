// scanner/rust_core/src/genetic_engine.rs
use rand::prelude::*;
use rand::distributions::{Distribution, Uniform};
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use ahash::AHashMap;
use crate::payload_dictionary::{Payload, PayloadCategory};

// ============================================================================
// GENES DISPONÍVEIS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub enum EncodingGene {
    Raw,
    UrlEncode,
    DoubleUrl,
    Unicode,
    Hex,
    Base64,
    HtmlEntity,
    Octal,
    Utf7,
    MixedCase,
    Base64Url,
    HexEntity,
    DecimalHtml,
    Utf16,
    PercentDouble,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub enum TechniqueGene {
    Inline,
    CommentInjection,
    NullByte,
    NewlineInjection,
    TabInjection,
    Chunked,
    CaseSwap,
    ConcatSplit,
    WhitespaceVariation,
    EncodingChain,
    FragmentOverlap,
    DelimiterSwap,
    QuoteEscape,
    DoubleEscape,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub enum WafBypassGene {
    ContentTypeSwap,
    MethodOverride,
    HeaderPollution,
    ParameterPollution,
    JsonToXml,
    MultipartBoundary,
    ChunkedTransfer,
    PipelineInjection,
    UnicodeNormalization,
    OverlongUtf8,
    PathNormalization,
    HostHeaderPoisoning,
    RefererSpoofing,
    CookiePadding,
    HttpVersionDowngrade,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub enum InjectionPointGene {
    QueryParam,
    PathSegment,
    HeaderValue,
    CookieValue,
    BodyJson,
    BodyForm,
    BodyXml,
    Fragment,
    PathTraversalSegment,
    JsonKey,
    JsonValue,
    XmlAttribute,
}

// ============================================================================
// ORGANISMO - PAYLOAD EVOLUTIVO
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadOrganism {
    pub id: String,
    pub technique: TechniqueGene,
    pub encoding: EncodingGene,
    pub injection_point: InjectionPointGene,
    pub waf_bypass: Vec<WafBypassGene>,
    pub generation: u32,
    pub fitness: f64,
    pub raw: String,
    pub lineage: Vec<String>,
    pub parent_ids: Vec<String>,
    pub mutation_count: u32,
    pub success_history: Vec<bool>,
    pub response_times: Vec<u64>,
    pub last_test_time: Option<u64>,
}

impl PayloadOrganism {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        Self {
            id: format!("org_{:016x}", rng.gen::<u64>()),
            technique: TECHNIQUES_GENES[rng.gen_range(0..TECHNIQUES_GENES.len())].clone(),
            encoding: ENCODING_GENES[rng.gen_range(0..ENCODING_GENES.len())].clone(),
            injection_point: INJECTION_POINTS_GENES[rng.gen_range(0..INJECTION_POINTS_GENES.len())].clone(),
            waf_bypass: Self::random_waf_bypasses(),
            generation: 0,
            fitness: 0.0,
            raw: String::new(),
            lineage: Vec::new(),
            parent_ids: Vec::new(),
            mutation_count: 0,
            success_history: Vec::new(),
            response_times: Vec::new(),
            last_test_time: None,
        }
    }
    
    fn random_waf_bypasses() -> Vec<WafBypassGene> {
        let mut rng = thread_rng();
        let count = Uniform::from(1..=4).sample(&mut rng);
        let mut shuffled = WAF_BYPASS_GENES.clone();
        shuffled.shuffle(&mut rng);
        shuffled.into_iter().take(count).collect()
    }
    
    pub fn calculate_entropy(&self) -> f64 {
        if self.raw.is_empty() {
            return 0.0;
        }
        let unique_chars: std::collections::HashSet<char> = self.raw.chars().collect();
        unique_chars.len() as f64 / self.raw.len() as f64
    }
    
    pub fn to_dict(&self) -> HashMap<String, serde_json::Value> {
        let mut map = HashMap::new();
        map.insert("id".to_string(), serde_json::Value::String(self.id.clone()));
        map.insert("technique".to_string(), serde_json::Value::String(format!("{:?}", self.technique)));
        map.insert("encoding".to_string(), serde_json::Value::String(format!("{:?}", self.encoding)));
        map.insert("injection_point".to_string(), serde_json::Value::String(format!("{:?}", self.injection_point)));
        map.insert("generation".to_string(), serde_json::Value::Number(serde_json::Number::from(self.generation)));
        map.insert("fitness".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(self.fitness).unwrap_or(0.0.into())));
        map.insert("raw".to_string(), serde_json::Value::String(self.raw.clone()));
        map.insert("mutation_count".to_string(), serde_json::Value::Number(serde_json::Number::from(self.mutation_count)));
        map.insert("success_rate".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(self.success_rate()).unwrap_or(0.0.into())));
        map
    }
    
    pub fn success_rate(&self) -> f64 {
        if self.success_history.is_empty() {
            return 0.0;
        }
        let successes = self.success_history.iter().filter(|&&s| s).count() as f64;
        successes / self.success_history.len() as f64
    }
    
    pub fn avg_response_time(&self) -> f64 {
        if self.response_times.is_empty() {
            return 0.0;
        }
        self.response_times.iter().sum::<u64>() as f64 / self.response_times.len() as f64
    }
}

impl Default for PayloadOrganism {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RESPOSTAS DE FEEDBACK
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFeedback {
    pub status_code: u16,
    pub blocked: bool,
    pub reflected: bool,
    pub detected_vuln: bool,
    pub waf_bypassed: bool,
    pub error_leaked: bool,
    pub response_time_ms: u64,
    pub content_length: usize,
    pub entropy: f64,
    pub header_anomalies: u8,
    pub behavioral_features: BehavioralFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralFeatures {
    pub response_time_delta: f64,
    pub content_length_variation: f64,
    pub entropy_shift: f64,
    pub header_anomalies: u8,
    pub status_code_pattern: String,
}

// ============================================================================
// CONFIGURAÇÕES DO MOTOR GENÉTICO
// ============================================================================

#[derive(Debug, Clone)]
pub struct GeneticConfig {
    pub population_size: usize,
    pub elite_percent: f64,
    pub mutation_rate: f64,
    pub crossover_rate: f64,
    pub tournament_size: usize,
    pub max_generations: u32,
    pub stagnation_limit: u32,
    pub fitness_timeout_ms: u64,
    pub parallel_evaluation: bool,
    pub adaptive_mutation: bool,
    pub diversity_pressure: f64,
}

impl Default for GeneticConfig {
    fn default() -> Self {
        Self {
            population_size: 50,
            elite_percent: 0.2,
            mutation_rate: 0.3,
            crossover_rate: 0.7,
            tournament_size: 3,
            max_generations: 10,
            stagnation_limit: 3,
            fitness_timeout_ms: 30000,
            parallel_evaluation: true,
            adaptive_mutation: true,
            diversity_pressure: 0.1,
        }
    }
}

// ============================================================================
// GENES DISPONÍVEIS (COMPLETOS)
// ============================================================================

pub const ENCODING_GENES: [EncodingGene; 15] = [
    EncodingGene::Raw,
    EncodingGene::UrlEncode,
    EncodingGene::DoubleUrl,
    EncodingGene::Unicode,
    EncodingGene::Hex,
    EncodingGene::Base64,
    EncodingGene::HtmlEntity,
    EncodingGene::Octal,
    EncodingGene::Utf7,
    EncodingGene::MixedCase,
    EncodingGene::Base64Url,
    EncodingGene::HexEntity,
    EncodingGene::DecimalHtml,
    EncodingGene::Utf16,
    EncodingGene::PercentDouble,
];

pub const TECHNIQUES_GENES: [TechniqueGene; 15] = [
    TechniqueGene::Inline,
    TechniqueGene::CommentInjection,
    TechniqueGene::NullByte,
    TechniqueGene::NewlineInjection,
    TechniqueGene::TabInjection,
    TechniqueGene::Chunked,
    TechniqueGene::CaseSwap,
    TechniqueGene::ConcatSplit,
    TechniqueGene::WhitespaceVariation,
    TechniqueGene::EncodingChain,
    TechniqueGene::FragmentOverlap,
    TechniqueGene::DelimiterSwap,
    TechniqueGene::QuoteEscape,
    TechniqueGene::DoubleEscape,
];

pub const WAF_BYPASS_GENES: [WafBypassGene; 16] = [
    WafBypassGene::ContentTypeSwap,
    WafBypassGene::MethodOverride,
    WafBypassGene::HeaderPollution,
    WafBypassGene::ParameterPollution,
    WafBypassGene::JsonToXml,
    WafBypassGene::MultipartBoundary,
    WafBypassGene::ChunkedTransfer,
    WafBypassGene::PipelineInjection,
    WafBypassGene::UnicodeNormalization,
    WafBypassGene::OverlongUtf8,
    WafBypassGene::PathNormalization,
    WafBypassGene::HostHeaderPoisoning,
    WafBypassGene::RefererSpoofing,
    WafBypassGene::CookiePadding,
    WafBypassGene::HttpVersionDowngrade,
];

pub const INJECTION_POINTS_GENES: [InjectionPointGene; 12] = [
    InjectionPointGene::QueryParam,
    InjectionPointGene::PathSegment,
    InjectionPointGene::HeaderValue,
    InjectionPointGene::CookieValue,
    InjectionPointGene::BodyJson,
    InjectionPointGene::BodyForm,
    InjectionPointGene::BodyXml,
    InjectionPointGene::Fragment,
    InjectionPointGene::PathTraversalSegment,
    InjectionPointGene::JsonKey,
    InjectionPointGene::JsonValue,
    InjectionPointGene::XmlAttribute,
];

// ============================================================================
// MUTAÇÃO ADAPTATIVA - TÉCNICAS DE TRANSFORMAÇÃO
// ============================================================================

pub struct MutationEngine {
    rng: ThreadRng,
    adaptive_rate: f64,
    technique_success_rates: AHashMap<TechniqueGene, f64>,
    encoding_success_rates: AHashMap<EncodingGene, f64>,
    waf_bypass_success_rates: AHashMap<WafBypassGene, f64>,
}

impl MutationEngine {
    pub fn new() -> Self {
        Self {
            rng: thread_rng(),
            adaptive_rate: 0.1,
            technique_success_rates: AHashMap::new(),
            encoding_success_rates: AHashMap::new(),
            waf_bypass_success_rates: AHashMap::new(),
        }
    }
    
    pub fn mutate_organism(&mut self, organism: &PayloadOrganism, config: &GeneticConfig) -> PayloadOrganism {
        let mut mutated = organism.clone();
        let mut mutation_applied = false;
        
        // Mutação de técnica
        if self.rng.gen_bool(config.mutation_rate as f64) {
            let new_technique = if self.adaptive_rate > 0.7 {
                self.select_best_technique()
            } else {
                TECHNIQUES_GENES[self.rng.gen_range(0..TECHNIQUES_GENES.len())].clone()
            };
            mutated.technique = new_technique;
            mutation_applied = true;
        }
        
        // Mutação de encoding
        if self.rng.gen_bool(config.mutation_rate as f64) {
            let new_encoding = if self.adaptive_rate > 0.7 {
                self.select_best_encoding()
            } else {
                ENCODING_GENES[self.rng.gen_range(0..ENCODING_GENES.len())].clone()
            };
            mutated.encoding = new_encoding;
            mutation_applied = true;
        }
        
        // Mutação de WAF bypass
        if self.rng.gen_bool(config.mutation_rate as f64) {
            if self.rng.gen_bool(0.6) {
                // Adicionar novo bypass
                let new_bypass = if self.adaptive_rate > 0.7 {
                    self.select_best_waf_bypass()
                } else {
                    WAF_BYPASS_GENES[self.rng.gen_range(0..WAF_BYPASS_GENES.len())].clone()
                };
                if !mutated.waf_bypass.contains(&new_bypass) {
                    mutated.waf_bypass.push(new_bypass);
                }
            } else if mutated.waf_bypass.len() > 1 {
                // Remover bypass existente
                let idx = self.rng.gen_range(0..mutated.waf_bypass.len());
                mutated.waf_bypass.remove(idx);
            }
            mutation_applied = true;
        }
        
        // Mutação de injection point
        if self.rng.gen_bool(config.mutation_rate as f64) {
            let new_point = INJECTION_POINTS_GENES[self.rng.gen_range(0..INJECTION_POINTS_GENES.len())].clone();
            mutated.injection_point = new_point;
            mutation_applied = true;
        }
        
        // Mutação do payload raw
        if self.rng.gen_bool(config.mutation_rate * 1.5) {
            mutated.raw = self.mutate_raw_payload(&organism.raw, &mutated);
            mutation_applied = true;
        }
        
        if mutation_applied {
            mutated.mutation_count += 1;
            mutated.lineage.push(organism.id.clone());
            mutated.generation = organism.generation + 1;
            mutated.parent_ids.push(organism.id.clone());
        }
        
        mutated
    }
    
    fn mutate_raw_payload(&mut self, raw: &str, organism: &PayloadOrganism) -> String {
        let mut result = raw.to_string();
        
        match organism.technique {
            TechniqueGene::CommentInjection => {
                result = result.replace(" ", "/**/");
                result = result.replace("OR", "O/**/R");
                result = result.replace("SELECT", "SE/**/LECT");
                result = result.replace("UNION", "UN/**/ION");
            }
            TechniqueGene::NullByte => {
                result = result.replace("'", "\\x00'");
                result = result.replace("\"", "\\x00\"");
                result = result.replace("<", "\\x00<");
            }
            TechniqueGene::NewlineInjection => {
                result = result.replace(" ", "%0a");
                result = result.replace("'", "%0a'");
            }
            TechniqueGene::TabInjection => {
                result = result.replace(" ", "%09");
                result = result.replace("=", "%09=");
            }
            TechniqueGene::CaseSwap => {
                result = result.chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i % 2 == 0 {
                            c.to_uppercase().next().unwrap_or(c)
                        } else {
                            c.to_lowercase().next().unwrap_or(c)
                        }
                    })
                    .collect();
            }
            TechniqueGene::ConcatSplit => {
                if result.len() > 4 {
                    let mid = result.len() / 2;
                    result = format!("{}'+'{}", &result[..mid], &result[mid..]);
                }
            }
            TechniqueGene::WhitespaceVariation => {
                result = result.replace(" ", "\t");
                result = result.replace(",", "\n,");
                result = result.replace("=", " = ");
            }
            TechniqueGene::EncodingChain => {
                result = urlencoding::encode(&result).to_string();
                result = urlencoding::encode(&result).to_string();
            }
            TechniqueGene::DelimiterSwap => {
                result = result.replace("\"", "'");
                result = result.replace("'", "\"");
            }
            TechniqueGene::QuoteEscape => {
                result = result.replace("'", "\\'");
                result = result.replace("\"", "\\\"");
            }
            TechniqueGene::DoubleEscape => {
                result = result.replace("'", "\\\\'");
                result = result.replace("\"", "\\\\\"");
            }
            _ => {}
        }
        
        match organism.encoding {
            EncodingGene::UrlEncode => {
                result = urlencoding::encode(&result).to_string();
            }
            EncodingGene::DoubleUrl => {
                result = urlencoding::encode(&urlencoding::encode(&result).to_string()).to_string();
            }
            EncodingGene::Unicode => {
                result = result.chars()
                    .map(|c| {
                        if c.is_ascii_punctuation() || c == '<' || c == '>' || c == '\'' || c == '"' {
                            format!("\\u{:04x}", c as u32)
                        } else {
                            c.to_string()
                        }
                    })
                    .collect();
            }
            EncodingGene::Hex => {
                result = result.chars()
                    .map(|c| format!("%{:02x}", c as u8))
                    .collect();
            }
            EncodingGene::Base64 => {
                result = base64::encode(result.as_bytes());
            }
            EncodingGene::HtmlEntity => {
                result = result.chars()
                    .map(|c| {
                        if c.is_ascii_punctuation() || c == '<' || c == '>' || c == '\'' || c == '"' {
                            format!("&#x{:x};", c as u32)
                        } else {
                            c.to_string()
                        }
                    })
                    .collect();
            }
            EncodingGene::Octal => {
                result = result.chars()
                    .map(|c| format!("\\{:o}", c as u8))
                    .collect();
            }
            EncodingGene::MixedCase => {
                result = result.chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i % 3 == 0 {
                            c.to_uppercase().next().unwrap_or(c)
                        } else if i % 3 == 1 {
                            c.to_lowercase().next().unwrap_or(c)
                        } else {
                            c
                        }
                    })
                    .collect();
            }
            EncodingGene::Base64Url => {
                result = base64::encode_config(result.as_bytes(), base64::URL_SAFE);
            }
            EncodingGene::HexEntity => {
                result = result.chars()
                    .map(|c| format!("&#x{:02x};", c as u8))
                    .collect();
            }
            EncodingGene::Utf16 => {
                result = format!("%u{}{}", 
                    result.encode_utf16().map(|c| format!("{:04x}", c)).collect::<String>(),
                    "%00"
                );
            }
            _ => {}
        }
        
        result
    }
    
    fn select_best_technique(&self) -> TechniqueGene {
        self.technique_success_rates
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(k, _)| k.clone())
            .unwrap_or(TECHNIQUES_GENES[0].clone())
    }
    
    fn select_best_encoding(&self) -> EncodingGene {
        self.encoding_success_rates
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(k, _)| k.clone())
            .unwrap_or(ENCODING_GENES[0].clone())
    }
    
    fn select_best_waf_bypass(&self) -> WafBypassGene {
        self.waf_bypass_success_rates
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(k, _)| k.clone())
            .unwrap_or(WAF_BYPASS_GENES[0].clone())
    }
    
    pub fn update_success_rates(&mut self, organisms: &[PayloadOrganism]) {
        for org in organisms {
            if let Some(rate) = self.technique_success_rates.get_mut(&org.technique) {
                *rate = (*rate * 0.8) + (org.success_rate() * 0.2);
            } else {
                self.technique_success_rates.insert(org.technique.clone(), org.success_rate());
            }
            
            if let Some(rate) = self.encoding_success_rates.get_mut(&org.encoding) {
                *rate = (*rate * 0.8) + (org.success_rate() * 0.2);
            } else {
                self.encoding_success_rates.insert(org.encoding.clone(), org.success_rate());
            }
            
            for bypass in &org.waf_bypass {
                if let Some(rate) = self.waf_bypass_success_rates.get_mut(bypass) {
                    *rate = (*rate * 0.8) + (org.success_rate() * 0.2);
                } else {
                    self.waf_bypass_success_rates.insert(bypass.clone(), org.success_rate());
                }
            }
        }
        
        // Ajustar taxa adaptativa baseada no sucesso geral
        let avg_success = organisms.iter().map(|o| o.success_rate()).sum::<f64>() / organisms.len() as f64;
        if avg_success > 0.5 {
            self.adaptive_rate = (self.adaptive_rate * 0.9).max(0.05);
        } else {
            self.adaptive_rate = (self.adaptive_rate * 1.1).min(0.5);
        }
    }
}

impl Default for MutationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CROSSOVER ENGINE
// ============================================================================

pub struct CrossoverEngine {
    rng: ThreadRng,
}

impl CrossoverEngine {
    pub fn new() -> Self {
        Self { rng: thread_rng() }
    }
    
    pub fn crossover(&mut self, parent1: &PayloadOrganism, parent2: &PayloadOrganism) -> (PayloadOrganism, PayloadOrganism) {
        let mut child1 = PayloadOrganism::new();
        let mut child2 = PayloadOrganism::new();
        
        // Técnica
        if self.rng.gen_bool(0.5) {
            child1.technique = parent1.technique.clone();
            child2.technique = parent2.technique.clone();
        } else {
            child1.technique = parent2.technique.clone();
            child2.technique = parent1.technique.clone();
        }
        
        // Encoding
        if self.rng.gen_bool(0.5) {
            child1.encoding = parent1.encoding.clone();
            child2.encoding = parent2.encoding.clone();
        } else {
            child1.encoding = parent2.encoding.clone();
            child2.encoding = parent1.encoding.clone();
        }
        
        // Injection point
        if self.rng.gen_bool(0.5) {
            child1.injection_point = parent1.injection_point.clone();
            child2.injection_point = parent2.injection_point.clone();
        } else {
            child1.injection_point = parent2.injection_point.clone();
            child2.injection_point = parent1.injection_point.clone();
        }
        
        // WAF bypass (crossover de conjuntos)
        let all_bypasses: Vec<WafBypassGene> = parent1.waf_bypass.iter()
            .chain(parent2.waf_bypass.iter())
            .cloned()
            .collect();
        
        let mut shuffled = all_bypasses;
        shuffled.shuffle(&mut self.rng);
        let split = shuffled.len() / 2;
        child1.waf_bypass = shuffled[..split].to_vec();
        child2.waf_bypass = shuffled[split..].to_vec();
        
        // Payload raw (crossover de strings)
        if parent1.raw.len() > 2 && parent2.raw.len() > 2 {
            let split1 = self.rng.gen_range(0..parent1.raw.len());
            let split2 = self.rng.gen_range(0..parent2.raw.len());
            child1.raw = format!("{}{}", &parent1.raw[..split1], &parent2.raw[split2..]);
            child2.raw = format!("{}{}", &parent2.raw[..split2], &parent1.raw[split1..]);
        } else {
            child1.raw = parent1.raw.clone();
            child2.raw = parent2.raw.clone();
        }
        
        child1.parent_ids = vec![parent1.id.clone(), parent2.id.clone()];
        child2.parent_ids = vec![parent1.id.clone(), parent2.id.clone()];
        child1.generation = parent1.generation.max(parent2.generation) + 1;
        child2.generation = parent1.generation.max(parent2.generation) + 1;
        
        (child1, child2)
    }
}

impl Default for CrossoverEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// FITNESS EVALUATOR
// ============================================================================

pub struct FitnessEvaluator {
    config: GeneticConfig,
}

impl FitnessEvaluator {
    pub fn new(config: &GeneticConfig) -> Self {
        Self { config: config.clone() }
    }
    
    pub fn evaluate(&self, organism: &PayloadOrganism, feedback: &ResponseFeedback) -> f64 {
        let mut fitness = 0.0;
        
        // Sucesso principal (peso maior)
        if feedback.detected_vuln {
            fitness += 200.0;
        }
        if feedback.waf_bypassed {
            fitness += 150.0;
        }
        if feedback.reflected {
            fitness += 70.0;
        }
        
        // Status code
        match feedback.status_code {
            200..=299 => fitness += 100.0,
            300..=399 => fitness += 50.0,
            400..=499 => fitness += 10.0 - (feedback.status_code as f64 - 400.0) * 0.1,
            500..=599 => fitness += 30.0,
            _ => {}
        }
        
        // Penalidades
        if feedback.blocked {
            fitness -= 120.0;
        }
        
        // Bônus por erro vazado
        if feedback.error_leaked {
            fitness += 50.0;
        }
        
        // Tempo de resposta (menos é melhor)
        let time_bonus = (3000.0 - feedback.response_time_ms as f64).max(0.0) / 30.0;
        fitness += time_bonus.min(50.0);
        
        // Entropy (variação de conteúdo)
        if feedback.entropy > 4.0 && feedback.entropy < 7.0 {
            fitness += 15.0;
        }
        
        // Anomalias de header (menos é melhor para stealth)
        let anomaly_penalty = (feedback.header_anomalies as f64) * 15.0;
        fitness -= anomaly_penalty;
        
        // Características comportamentais
        if feedback.behavioral_features.response_time_delta > 0.35 {
            fitness += 25.0;
        }
        if feedback.behavioral_features.content_length_variation > 0.25 {
            fitness += 15.0;
        }
        if feedback.behavioral_features.entropy_shift > 0.08 {
            fitness += 10.0;
        }
        
        // Bônus por sucesso histórico
        fitness += organism.success_rate() * 50.0;
        
        // Penalidade para payloads muito longos (stealth)
        let length_penalty = (organism.raw.len() as f64 / 2000.0).min(30.0);
        fitness -= length_penalty;
        
        // Bônus para diversidade (evita convergência prematura)
        fitness += organism.calculate_entropy() * 20.0 * self.config.diversity_pressure;
        
        fitness.max(0.0)
    }
    
    pub fn evaluate_parallel(&self, organisms: &mut [PayloadOrganism], feedbacks: &[ResponseFeedback]) {
        if self.config.parallel_evaluation {
            organisms.par_iter_mut().enumerate().for_each(|(i, org)| {
                let feedback = feedbacks.get(i).unwrap_or(&ResponseFeedback {
                    status_code: 0,
                    blocked: true,
                    reflected: false,
                    detected_vuln: false,
                    waf_bypassed: false,
                    error_leaked: false,
                    response_time_ms: 30000,
                    content_length: 0,
                    entropy: 0.0,
                    header_anomalies: 0,
                    behavioral_features: BehavioralFeatures::default(),
                });
                org.fitness = self.evaluate(org, feedback);
            });
        } else {
            for (i, org) in organisms.iter_mut().enumerate() {
                let feedback = feedbacks.get(i).unwrap_or(&ResponseFeedback {
                    status_code: 0,
                    blocked: true,
                    reflected: false,
                    detected_vuln: false,
                    waf_bypassed: false,
                    error_leaked: false,
                    response_time_ms: 30000,
                    content_length: 0,
                    entropy: 0.0,
                    header_anomalies: 0,
                    behavioral_features: BehavioralFeatures::default(),
                });
                org.fitness = self.evaluate(org, feedback);
            }
        }
    }
}

// ============================================================================
// SELEÇÃO POR TORNEIO
// ============================================================================

pub struct TournamentSelector {
    rng: ThreadRng,
    tournament_size: usize,
}

impl TournamentSelector {
    pub fn new(tournament_size: usize) -> Self {
        Self { rng: thread_rng(), tournament_size }
    }
    
    pub fn select(&mut self, population: &[PayloadOrganism]) -> PayloadOrganism {
        let mut best_idx = self.rng.gen_range(0..population.len());
        let mut best_fitness = population[best_idx].fitness;
        
        for _ in 1..self.tournament_size {
            let idx = self.rng.gen_range(0..population.len());
            if population[idx].fitness > best_fitness {
                best_fitness = population[idx].fitness;
                best_idx = idx;
            }
        }
        
        population[best_idx].clone()
    }
}

// ============================================================================
// GENETIC ENGINE PRINCIPAL
// ============================================================================

pub struct GeneticEngine {
    population: Vec<PayloadOrganism>,
    config: GeneticConfig,
    mutation_engine: MutationEngine,
    crossover_engine: CrossoverEngine,
    selector: TournamentSelector,
    evaluator: FitnessEvaluator,
    generation: u32,
    stagnation_counter: u32,
    best_fitness_history: Vec<f64>,
    avg_fitness_history: Vec<f64>,
    diversity_history: Vec<f64>,
    start_time: Option<Instant>,
}

impl GeneticEngine {
    pub fn new(config: GeneticConfig) -> Self {
        let selector = TournamentSelector::new(config.tournament_size);
        let evaluator = FitnessEvaluator::new(&config);
        
        Self {
            population: Vec::new(),
            config,
            mutation_engine: MutationEngine::new(),
            crossover_engine: CrossoverEngine::new(),
            selector,
            evaluator,
            generation: 0,
            stagnation_counter: 0,
            best_fitness_history: Vec::new(),
            avg_fitness_history: Vec::new(),
            diversity_history: Vec::new(),
            start_time: None,
        }
    }
    
    pub fn initialize_from_payloads(&mut self, base_payloads: &[Payload]) {
        self.start_time = Some(Instant::now());
        
        for payload in base_payloads.iter().take(self.config.population_size) {
            let mut organism = PayloadOrganism::new();
            organism.raw = payload.payload.clone();
            organism.generation = 0;
            self.population.push(organism);
        }
        
        while self.population.len() < self.config.population_size {
            let mut organism = PayloadOrganism::new();
            if let Some(base) = base_payloads.first() {
                organism.raw = base.payload.clone();
            }
            self.population.push(organism);
        }
        
        self.calculate_diversity();
    }
    
    pub fn evolve(&mut self, responses: &[ResponseFeedback]) -> Vec<PayloadOrganism> {
        if self.population.is_empty() {
            return Vec::new();
        }
        
        // Avaliar fitness
        self.evaluator.evaluate_parallel(&mut self.population, responses);
        
        // Registrar histórico
        let best_fitness = self.population.iter().map(|o| o.fitness).fold(0.0, f64::max);
        let avg_fitness = self.population.iter().map(|o| o.fitness).sum::<f64>() / self.population.len() as f64;
        
        self.best_fitness_history.push(best_fitness);
        self.avg_fitness_history.push(avg_fitness);
        
        // Verificar estagnação
        if self.best_fitness_history.len() >= 3 {
            let last_three = &self.best_fitness_history[self.best_fitness_history.len() - 3..];
            if last_three.iter().all(|&v| v == last_three[0]) {
                self.stagnation_counter += 1;
            } else {
                self.stagnation_counter = 0;
            }
        }
        
        // Seleção de elite
        let elite_count = (self.population.len() as f64 * self.config.elite_percent) as usize;
        self.population.sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap());
        let elite: Vec<PayloadOrganism> = self.population[..elite_count].to_vec();
        
        // Criar nova população
        let mut new_population = elite.clone();
        
        // Crossover e mutação para preencher o resto
        while new_population.len() < self.config.population_size {
            if self.config.crossover_rate > 0.0 && self.mutation_engine.rng.gen_bool(self.config.crossover_rate) {
                let parent1 = self.selector.select(&self.population);
                let parent2 = self.selector.select(&self.population);
                let (mut child1, mut child2) = self.crossover_engine.crossover(&parent1, &parent2);
                
                if self.mutation_engine.rng.gen_bool(self.config.mutation_rate) {
                    child1 = self.mutation_engine.mutate_organism(&child1, &self.config);
                    child2 = self.mutation_engine.mutate_organism(&child2, &self.config);
                }
                
                new_population.push(child1);
                if new_population.len() < self.config.population_size {
                    new_population.push(child2);
                }
            } else {
                let mut child = self.selector.select(&self.population);
                child = self.mutation_engine.mutate_organism(&child, &self.config);
                new_population.push(child);
            }
        }
        
        // Atualizar taxas de sucesso
        self.mutation_engine.update_success_rates(&new_population);
        
        self.population = new_population;
        self.generation += 1;
        self.calculate_diversity();
        
        // Retornar os melhores
        self.get_best_payloads(self.config.population_size / 2)
    }
    
    pub fn evolve_until_convergence(&mut self, response_generator: &mut dyn FnMut(&[PayloadOrganism]) -> Vec<ResponseFeedback>) -> Vec<PayloadOrganism> {
        while self.generation < self.config.max_generations && self.stagnation_counter < self.config.stagnation_limit {
            let responses = response_generator(&self.population);
            self.evolve(&responses);
        }
        self.get_best_payloads(10)
    }
    
    pub fn get_best_payloads(&self, n: usize) -> Vec<PayloadOrganism> {
        let mut sorted = self.population.clone();
        sorted.sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap());
        sorted.into_iter().take(n).collect()
    }
    
    pub fn calculate_diversity(&mut self) -> f64 {
        if self.population.is_empty() {
            return 0.0;
        }
        
        let technique_counts: HashMap<TechniqueGene, usize> = self.population.iter()
            .fold(HashMap::new(), |mut acc, org| {
                *acc.entry(org.technique.clone()).or_insert(0) += 1;
                acc
            });
        
        let max_count = technique_counts.values().max().unwrap_or(&0);
        let diversity = 1.0 - (*max_count as f64 / self.population.len() as f64);
        
        self.diversity_history.push(diversity);
        diversity
    }
    
    pub fn generate_report(&self) -> GeneticReport {
        let best = self.get_best_payloads(5);
        let elapsed = self.start_time.map(|t| t.elapsed().as_millis() as u64).unwrap_or(0);
        
        let technique_distribution: HashMap<String, usize> = self.population.iter()
            .fold(HashMap::new(), |mut acc, org| {
                *acc.entry(format!("{:?}", org.technique)).or_insert(0) += 1;
                acc
            });
        
        let encoding_distribution: HashMap<String, usize> = self.population.iter()
            .fold(HashMap::new(), |mut acc, org| {
                *acc.entry(format!("{:?}", org.encoding)).or_insert(0) += 1;
                acc
            });
        
        GeneticReport {
            current_generation: self.generation,
            population_size: self.population.len(),
            best_fitness: self.best_fitness_history.last().copied().unwrap_or(0.0),
            best_fitness_history: self.best_fitness_history.clone(),
            avg_fitness_history: self.avg_fitness_history.clone(),
            diversity_history: self.diversity_history.clone(),
            best_payloads: best.into_iter().map(|o| o.to_dict()).collect(),
            technique_distribution,
            encoding_distribution,
            elapsed_ms: elapsed,
            stagnation_counter: self.stagnation_counter,
            diversity: self.diversity_history.last().copied().unwrap_or(0.0),
        }
    }
    
    pub fn get_population_stats(&self) -> PopulationStats {
        let total_fitness: f64 = self.population.iter().map(|o| o.fitness).sum();
        let avg_fitness = total_fitness / self.population.len() as f64;
        let max_fitness = self.population.iter().map(|o| o.fitness).fold(0.0, f64::max);
        let min_fitness = self.population.iter().map(|o| o.fitness).fold(f64::MAX, f64::min);
        let std_dev = (self.population.iter().map(|o| (o.fitness - avg_fitness).powi(2)).sum::<f64>() / self.population.len() as f64).sqrt();
        
        PopulationStats {
            size: self.population.len(),
            generation: self.generation,
            avg_fitness,
            max_fitness,
            min_fitness,
            std_dev,
            total_mutations: self.population.iter().map(|o| o.mutation_count).sum::<u32>(),
        }
    }
}

impl Default for GeneticEngine {
    fn default() -> Self {
        Self::new(GeneticConfig::default())
    }
}

// ============================================================================
// TIPOS DE RETORNO
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneticReport {
    pub current_generation: u32,
    pub population_size: usize,
    pub best_fitness: f64,
    pub best_fitness_history: Vec<f64>,
    pub avg_fitness_history: Vec<f64>,
    pub diversity_history: Vec<f64>,
    pub best_payloads: Vec<HashMap<String, serde_json::Value>>,
    pub technique_distribution: HashMap<String, usize>,
    pub encoding_distribution: HashMap<String, usize>,
    pub elapsed_ms: u64,
    pub stagnation_counter: u32,
    pub diversity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopulationStats {
    pub size: usize,
    pub generation: u32,
    pub avg_fitness: f64,
    pub max_fitness: f64,
    pub min_fitness: f64,
    pub std_dev: f64,
    pub total_mutations: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_initialize_population() {
        let mut engine = GeneticEngine::default();
        let payloads = vec![
            Payload {
                id: "test".to_string(),
                payload: "<script>alert(1)</script>".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec![],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: crate::regex_engine::Severity::Critical,
                detection: crate::payload_dictionary::DetectionMethod::DomVariable("test".to_string()),
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            }
        ];
        engine.initialize_from_payloads(&payloads);
        assert!(!engine.population.is_empty());
    }
    
    #[test]
    fn test_mutation() {
        let mut engine = GeneticEngine::default();
        let mut organism = PayloadOrganism::new();
        organism.raw = "<script>alert(1)</script>".to_string();
        
        let mutated = engine.mutation_engine.mutate_organism(&organism, &engine.config);
        assert_ne!(mutated.raw, organism.raw);
    }
}