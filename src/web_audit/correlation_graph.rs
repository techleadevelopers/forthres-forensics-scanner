// scanner/rust_core/src/correlation_graph.rs
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};
use ahash::{AHashMap, AHashSet};

// ============================================================================
// REGRAS DE CORRELAÇÃO - 20 REGRAS COMPLETAS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    pub name: String,
    pub requires: HashSet<String>,
    pub bonus: f64,
    pub reasoning: String,
    pub category: CorrelationCategory,
    pub priority: u8,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CorrelationCategory {
    CloudLeakage,
    PrivilegeEscalation,
    DataExfiltration,
    AuthBypass,
    LateralMovement,
    FinancialFraud,
    InfrastructurePivot,
    ClientSide,
}

impl CorrelationRule {
    pub fn new(
        name: &str,
        requires: Vec<&str>,
        bonus: f64,
        reasoning: &str,
        category: CorrelationCategory,
        priority: u8,
    ) -> Self {
        Self {
            name: name.to_string(),
            requires: requires.into_iter().map(|s| s.to_string()).collect(),
            bonus,
            reasoning: reasoning.to_string(),
            category,
            priority,
            weight: bonus,
        }
    }
}

pub static CORRELATION_RULES: once_cell::sync::Lazy<Vec<CorrelationRule>> = once_cell::sync::Lazy::new(|| {
    vec![
        // CLOUD LEAKAGE (5 regras)
        CorrelationRule::new(
            "Cloud Credential + SSRF Vector",
            vec!["cloud_credential", "ssrf_vector"],
            3.0,
            "Cloud key + SSRF → metadata escalation to full IAM takeover",
            CorrelationCategory::CloudLeakage,
            1,
        ),
        CorrelationRule::new(
            "AWS Metadata + IAM Role",
            vec!["aws_metadata", "iam_role_detected"],
            3.2,
            "AWS metadata accessible + IAM role → assume role and escalate",
            CorrelationCategory::CloudLeakage,
            1,
        ),
        CorrelationRule::new(
            "GCP Metadata + Service Account",
            vec!["gcp_metadata", "service_account_detected"],
            2.8,
            "GCP metadata + service account → token theft and cloud takeover",
            CorrelationCategory::CloudLeakage,
            1,
        ),
        CorrelationRule::new(
            "Azure Metadata + Managed Identity",
            vec!["azure_metadata", "managed_identity"],
            2.8,
            "Azure metadata + managed identity → OAuth token theft",
            CorrelationCategory::CloudLeakage,
            1,
        ),
        CorrelationRule::new(
            "Source Map + Cloud Credential",
            vec!["source_map_exposed", "cloud_credential"],
            1.8,
            "Source map reveals structure to use cloud credentials",
            CorrelationCategory::CloudLeakage,
            2,
        ),
        
        // PRIVILEGE ESCALATION (4 regras)
        CorrelationRule::new(
            "Admin Endpoint + No Rate Limit",
            vec!["admin_endpoint", "no_rate_limit"],
            2.5,
            "Admin endpoint without rate limiting → brute force via viable",
            CorrelationCategory::PrivilegeEscalation,
            1,
        ),
        CorrelationRule::new(
            "JWT Secret + Admin Endpoint",
            vec!["jwt_secret", "admin_endpoint"],
            2.2,
            "JWT secret exposed + admin endpoint → forge admin tokens",
            CorrelationCategory::PrivilegeEscalation,
            1,
        ),
        CorrelationRule::new(
            "Hardcoded Password + Admin Endpoint",
            vec!["hardcoded_password", "admin_endpoint"],
            2.0,
            "Hardcoded password + admin endpoint → direct login",
            CorrelationCategory::PrivilegeEscalation,
            1,
        ),
        CorrelationRule::new(
            "Session Hijack + Auth Bypass",
            vec!["session_hijack", "auth_bypass"],
            2.5,
            "JWT/session token + broken auth → silent privilege escalation",
            CorrelationCategory::PrivilegeEscalation,
            1,
        ),
        
        // DATA EXFILTRATION (4 regras)
        CorrelationRule::new(
            "Database Credential + SQLi Vector",
            vec!["database_credential", "sqli_vector"],
            2.8,
            "DB credential + SQLi → complete dump without rate limit",
            CorrelationCategory::DataExfiltration,
            1,
        ),
        CorrelationRule::new(
            "Env File + Database Credential",
            vec!["env_file_exposed", "database_credential"],
            2.2,
            ".env exposed + DB credential → direct database access",
            CorrelationCategory::DataExfiltration,
            2,
        ),
        CorrelationRule::new(
            "SQLi Confirmed + Information Schema",
            vec!["sqli_confirmed", "information_schema"],
            2.0,
            "SQLi + information_schema → table enumeration and full dump",
            CorrelationCategory::DataExfiltration,
            1,
        ),
        CorrelationRule::new(
            "IDOR + PII Data",
            vec!["idor_vulnerable", "pii_detected"],
            2.2,
            "IDOR + PII detected → mass data exfiltration",
            CorrelationCategory::DataExfiltration,
            1,
        ),
        
        // LATERAL MOVEMENT (3 regras)
        CorrelationRule::new(
            "Internal Endpoint + SSRF Vector",
            vec!["internal_endpoint", "ssrf_vector"],
            2.5,
            "Internal endpoint + SSRF → lateral movement",
            CorrelationCategory::LateralMovement,
            1,
        ),
        CorrelationRule::new(
            "SSRF + Redis Internal",
            vec!["ssrf_confirmed", "redis_detected"],
            2.8,
            "SSRF confirmed + Redis accessible → session/cache manipulation",
            CorrelationCategory::LateralMovement,
            1,
        ),
        CorrelationRule::new(
            "SSRF + Docker API",
            vec!["ssrf_confirmed", "docker_api_detected"],
            2.6,
            "SSRF + Docker API → container escape and host compromise",
            CorrelationCategory::LateralMovement,
            1,
        ),
        
        // FINANCIAL FRAUD (2 regras)
        CorrelationRule::new(
            "Price Manipulation + Order Creation",
            vec!["price_manipulation", "order_created"],
            2.5,
            "Price manipulation + order created → financial fraud confirmed",
            CorrelationCategory::FinancialFraud,
            1,
        ),
        CorrelationRule::new(
            "Coupon Forge + Checkout Bypass",
            vec!["coupon_forge", "checkout_bypass"],
            2.3,
            "Coupon forge + checkout bypass → unlimited discounts",
            CorrelationCategory::FinancialFraud,
            1,
        ),
        
        // AUTH BYPASS (2 regras)
        CorrelationRule::new(
            "Token Forge + Admin Access",
            vec!["token_forge", "admin_access"],
            3.0,
            "JWT secret exposed + admin panel → forge admin tokens",
            CorrelationCategory::AuthBypass,
            1,
        ),
        CorrelationRule::new(
            "GraphQL Introspection + Auth Bypass",
            vec!["graphql_introspection", "auth_bypass"],
            2.0,
            "GraphQL introspection + broken auth → schema discovery and abuse",
            CorrelationCategory::AuthBypass,
            2,
        ),
    ]
});

// ============================================================================
// NÓ DO GRAFO DE CORRELAÇÃO
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationNode {
    pub id: String,
    pub name: String,
    pub category: CorrelationCategory,
    pub confidence: f64,
    pub severity: f64,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
    pub edges: Vec<CorrelationEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationEdge {
    pub source_id: String,
    pub target_id: String,
    pub rule: CorrelationRule,
    pub strength: f64,
    pub discovered_at: u64,
}

// ============================================================================
// CORRELATION GRAPH PRINCIPAL
// ============================================================================

pub struct CorrelationGraph {
    nodes: AHashMap<String, CorrelationNode>,
    edges: Vec<CorrelationEdge>,
    rules: Vec<CorrelationRule>,
    node_index: HashMap<String, AHashSet<String>>,
    rules_applied: AHashMap<String, u32>,
    total_weight: f64,
}

impl CorrelationGraph {
    pub fn new() -> Self {
        Self {
            nodes: AHashMap::new(),
            edges: Vec::new(),
            rules: CORRELATION_RULES.clone(),
            node_index: HashMap::new(),
            rules_applied: AHashMap::new(),
            total_weight: 0.0,
        }
    }
    
    pub fn add_hint(&mut self, hint: &str, metadata: HashMap<String, String>) {
        let category = infer_category(hint);
        let timestamp = current_timestamp();

        let node = CorrelationNode {
            id: hint.to_string(),
            name: hint.to_string(),
            category,
            confidence: 1.0,
            severity: 1.0,
            timestamp,
            metadata,
            edges: Vec::new(),
        };

        self.nodes.insert(hint.to_string(), node);
        self.node_index
            .entry(category_key(category).to_string())
            .or_default()
            .insert(hint.to_string());

        self.rebuild_edges();
    }

    pub fn calculate_multiplier(&self, hints: &HashSet<String>) -> f64 {
        if hints.is_empty() {
            return 1.0;
        }

        let mut multiplier = 1.0;
        for rule in &self.rules {
            if rule.requires.iter().all(|required| hints.contains(required)) {
                multiplier += rule.bonus;
            }
        }

        multiplier
    }

    fn rebuild_edges(&mut self) {
        self.edges.clear();
        self.rules_applied.clear();
        self.total_weight = 0.0;

        let available_hints = self.nodes.keys().cloned().collect::<HashSet<_>>();
        let timestamp = current_timestamp();
        let mut generated_edges = Vec::new();

        for rule in &self.rules {
            if !rule.requires.iter().all(|required| available_hints.contains(required)) {
                continue;
            }

            let required = rule.requires.iter().cloned().collect::<Vec<_>>();
            for pair in required.windows(2) {
                if let [source_id, target_id] = pair {
                    generated_edges.push(CorrelationEdge {
                        source_id: source_id.clone(),
                        target_id: target_id.clone(),
                        rule: rule.clone(),
                        strength: rule.weight,
                        discovered_at: timestamp,
                    });
                }
            }

            self.rules_applied.insert(rule.name.clone(), 1);
            self.total_weight += rule.weight;
        }

        for edge in &generated_edges {
            if let Some(source) = self.nodes.get_mut(&edge.source_id) {
                source.edges.push(edge.clone());
            }
        }

        self.edges = generated_edges;
    }
}

fn infer_category(hint: &str) -> CorrelationCategory {
    let normalized = hint.to_ascii_lowercase();

    if normalized.contains("cloud")
        || normalized.contains("aws")
        || normalized.contains("gcp")
        || normalized.contains("azure")
        || normalized.contains("iam")
    {
        CorrelationCategory::CloudLeakage
    } else if normalized.contains("admin")
        || normalized.contains("jwt")
        || normalized.contains("session")
        || normalized.contains("auth")
    {
        CorrelationCategory::PrivilegeEscalation
    } else if normalized.contains("db")
        || normalized.contains("database")
        || normalized.contains("pii")
        || normalized.contains("idor")
        || normalized.contains("sqli")
    {
        CorrelationCategory::DataExfiltration
    } else if normalized.contains("ssrf")
        || normalized.contains("redis")
        || normalized.contains("docker")
        || normalized.contains("internal")
    {
        CorrelationCategory::LateralMovement
    } else if normalized.contains("coupon")
        || normalized.contains("price")
        || normalized.contains("checkout")
        || normalized.contains("order")
    {
        CorrelationCategory::FinancialFraud
    } else if normalized.contains("graphql") || normalized.contains("token_forge") {
        CorrelationCategory::AuthBypass
    } else if normalized.contains("client")
        || normalized.contains("dom")
        || normalized.contains("xss")
    {
        CorrelationCategory::ClientSide
    } else {
        CorrelationCategory::InfrastructurePivot
    }
}

fn category_key(category: CorrelationCategory) -> &'static str {
    match category {
        CorrelationCategory::CloudLeakage => "cloud_leakage",
        CorrelationCategory::PrivilegeEscalation => "privilege_escalation",
        CorrelationCategory::DataExfiltration => "data_exfiltration",
        CorrelationCategory::AuthBypass => "auth_bypass",
        CorrelationCategory::LateralMovement => "lateral_movement",
        CorrelationCategory::FinancialFraud => "financial_fraud",
        CorrelationCategory::InfrastructurePivot => "infrastructure_pivot",
        CorrelationCategory::ClientSide => "client_side",
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
