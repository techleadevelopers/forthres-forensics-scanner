// scanner/rust_core/src/regex_engine.rs
use regex::Regex;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use rayon::prelude::*;
use serde::{Serialize, Deserialize};

// ============================================================================
// STACK DETECTION - 16 STACKS COMPLETAS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackDetectionResult {
    pub detected_stacks: Vec<String>,
    pub tech_labels: Vec<String>,
    pub priority_vectors: Vec<String>,
    pub depriority_vectors: Vec<String>,
    pub stack_signature: String,
    pub confidence_scores: HashMap<String, f64>,
}

pub static STACK_DETECT_PATTERNS: Lazy<Vec<(Regex, &'static str, &'static str, f64)>> = Lazy::new(|| {
    vec![
        // ===== FRAMEWORKS (10) =====
        (Regex::new(r"(?i)express|connect\.sid|express-session|x-powered-by.*express").unwrap(), 
         "express", "Express.js", 0.95),
        (Regex::new(r"(?i)next\.js|_next/|__NEXT_DATA__|next/dist|next/static").unwrap(), 
         "next", "Next.js", 0.93),
        (Regex::new(r"(?i)django|csrfmiddlewaretoken|wsgi|django\.core|django\.contrib").unwrap(), 
         "django", "Django", 0.92),
        (Regex::new(r"(?i)spring|whitelabel error|org\.springframework|spring-boot|actuator").unwrap(), 
         "spring", "Spring Boot", 0.90),
        (Regex::new(r"(?i)laravel|artisan|laravel_session|illuminate").unwrap(), 
         "laravel", "Laravel", 0.91),
        (Regex::new(r"(?i)rails|ruby on rails|_session_id|turbolinks|actionpack").unwrap(), 
         "rails", "Ruby on Rails", 0.89),
        (Regex::new(r"(?i)flask|werkzeug|jinja2|flask-session").unwrap(), 
         "flask", "Flask", 0.88),
        (Regex::new(r"(?i)asp\.net|__viewstate|__eventvalidation|x-aspnet-version|aspx").unwrap(), 
         "aspnet", "ASP.NET", 0.87),
        (Regex::new(r"(?i)wordpress|wp-content|wp-includes|wp-admin|wp-json").unwrap(), 
         "wordpress", "WordPress", 0.94),
        (Regex::new(r"(?i)drupal|sites/all|drupal\.js|drupal\.settings").unwrap(), 
         "drupal", "Drupal", 0.86),
        
        // ===== SERVERS (4) =====
        (Regex::new(r"(?i)nginx|nginx/[\d\.]+").unwrap(), 
         "nginx", "Nginx", 0.96),
        (Regex::new(r"(?i)apache|apache/[\d\.]+|httpd").unwrap(), 
         "apache", "Apache", 0.95),
        (Regex::new(r"(?i)iis|microsoft-iis|asp\.net").unwrap(), 
         "iis", "IIS", 0.94),
        (Regex::new(r"(?i)caddy|Caddy|xcaddy").unwrap(), 
         "caddy", "Caddy", 0.85),
        
        // ===== CLOUD & CDN (4) =====
        (Regex::new(r"(?i)aws|amazonaws|x-amz-|s3\.amazonaws|ec2|lambda").unwrap(), 
         "aws", "AWS", 0.92),
        (Regex::new(r"(?i)gcp|google\.cloud|\.appspot\.com|cloudfunctions|compute\.googleapis").unwrap(), 
         "gcp", "GCP", 0.90),
        (Regex::new(r"(?i)azure|windows\.net|azurewebsites|azure-api").unwrap(), 
         "azure", "Azure", 0.89),
        (Regex::new(r"(?i)cloudflare|cf-ray|__cfduid|cdn-cgi").unwrap(), 
         "cloudflare", "Cloudflare", 0.93),
        
        // ===== DATABASES (4) =====
        (Regex::new(r"(?i)mongodb|mongoose|mongodb\.uri|\.mongodb\.net").unwrap(), 
         "mongodb", "MongoDB", 0.88),
        (Regex::new(r"(?i)redis|redis:|ioredis|redis-commander").unwrap(), 
         "redis", "Redis", 0.87),
        (Regex::new(r"(?i)postgres|postgresql|pg_catalog|pg_tables").unwrap(), 
         "postgres", "PostgreSQL", 0.86),
        (Regex::new(r"(?i)mysql|mariadb|mysql_|mysqli").unwrap(), 
         "mysql", "MySQL", 0.85),
        
        // ===== FRONTEND (4) =====
        (Regex::new(r"(?i)react|react-dom|reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|createRoot").unwrap(), 
         "react", "React", 0.91),
        (Regex::new(r"(?i)angular|ng-version|ng-app|angular\.js|angular/core").unwrap(), 
         "angular", "Angular", 0.90),
        (Regex::new(r"(?i)vue|__vue__|vue-router|vuex|vue\.js").unwrap(), 
         "vue", "Vue.js", 0.89),
        (Regex::new(r"(?i)jquery|jquery\.min\.js|jQuery|\\$\(document\)\.ready").unwrap(), 
         "jquery", "jQuery", 0.88),
        
        // ===== ADDITIONAL (4) =====
        (Regex::new(r"(?i)graphql|__schema|query.*mutation|graphiql").unwrap(), 
         "graphql", "GraphQL", 0.87),
        (Regex::new(r"(?i)firebase|firebaseio\.com|firebaseapp\.com|firestore").unwrap(), 
         "firebase", "Firebase", 0.86),
        (Regex::new(r"(?i)shopify|shopify\.com|myshopify\.com|shopify-section").unwrap(), 
         "shopify", "Shopify", 0.85),
        (Regex::new(r"(?i)kubernetes|k8s|kube-system|serviceAccount|kubectl").unwrap(), 
         "kubernetes", "Kubernetes", 0.84),
    ]
});

// ============================================================================
// SECRET PATTERNS - 37 PATTERNS COMPLETOS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub pattern_type: SecretType,
    pub value: String,
    pub severity: Severity,
    pub location: usize,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretType {
    AwsKey,
    GoogleApiKey,
    StripeKey,
    GithubToken,
    GitlabToken,
    SlackToken,
    JwtToken,
    PrivateKey,
    DatabaseUrl,
    ApiKey,
    GenericSecret,
    Password,
    Token,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub static SECRET_PATTERNS: Lazy<Vec<(Regex, &'static str, SecretType, Severity)>> = Lazy::new(|| {
    vec![
        // AWS (3)
        (Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(), "AWS Access Key ID", SecretType::AwsKey, Severity::Critical),
        (Regex::new(r"\bASIA[0-9A-Z]{16}\b").unwrap(), "AWS Temporary Key", SecretType::AwsKey, Severity::Critical),
        (Regex::new(r#"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"#).unwrap(), "AWS Secret Key", SecretType::AwsKey, Severity::Critical),
        
        // Google (3)
        (Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(), "Google API Key", SecretType::GoogleApiKey, Severity::High),
        (Regex::new(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{35}\b").unwrap(), "Firebase", SecretType::GoogleApiKey, Severity::High),
        (Regex::new(r#"(?i)google_client_secret\s*=\s*['\"]?([A-Za-z0-9_-]{24})['\"]?"#).unwrap(), "Google Client Secret", SecretType::GoogleApiKey, Severity::Critical),
        
        // Stripe (4)
        (Regex::new(r"\bsk_live_[0-9a-zA-Z]{24}\b").unwrap(), "Stripe Live Secret", SecretType::StripeKey, Severity::Critical),
        (Regex::new(r"\bsk_test_[0-9a-zA-Z]{24}\b").unwrap(), "Stripe Test Secret", SecretType::StripeKey, Severity::High),
        (Regex::new(r"\bpk_live_[0-9a-zA-Z]{24}\b").unwrap(), "Stripe Live Publishable", SecretType::StripeKey, Severity::Medium),
        (Regex::new(r"\bpk_test_[0-9a-zA-Z]{24}\b").unwrap(), "Stripe Test Publishable", SecretType::StripeKey, Severity::Low),
        
        // GitHub (3)
        (Regex::new(r"\bghp_[0-9a-zA-Z]{36}\b").unwrap(), "GitHub Personal Token", SecretType::GithubToken, Severity::Critical),
        (Regex::new(r"\bgho_[0-9a-zA-Z]{36}\b").unwrap(), "GitHub OAuth Token", SecretType::GithubToken, Severity::High),
        (Regex::new(r"\bghu_[0-9a-zA-Z]{36}\b").unwrap(), "GitHub User Token", SecretType::GithubToken, Severity::High),
        
        // GitLab (2)
        (Regex::new(r"\bglpat-[0-9a-zA-Z_-]{20,}\b").unwrap(), "GitLab Personal Token", SecretType::GitlabToken, Severity::Critical),
        (Regex::new(r"\bglrt-[0-9a-zA-Z_-]{20,}\b").unwrap(), "GitLab Runner Token", SecretType::GitlabToken, Severity::High),
        
        // Slack (3)
        (Regex::new(r"\bxoxb-[0-9a-zA-Z_-]{48}\b").unwrap(), "Slack Bot Token", SecretType::SlackToken, Severity::High),
        (Regex::new(r"\bxoxp-[0-9a-zA-Z_-]{48}\b").unwrap(), "Slack User Token", SecretType::SlackToken, Severity::High),
        (Regex::new(r"\bxoxa-[0-9a-zA-Z_-]{48}\b").unwrap(), "Slack App Token", SecretType::SlackToken, Severity::High),
        
        // JWT (2)
        (Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap(), "JWT Token", SecretType::JwtToken, Severity::High),
        (Regex::new(r#"(?i)jwt_secret\s*=\s*['\"]?([A-Za-z0-9_\-\.]{32,})['\"]?"#).unwrap(), "JWT Secret", SecretType::JwtToken, Severity::Critical),
        
        // Private Keys (4)
        (Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").unwrap(), "RSA Private Key", SecretType::PrivateKey, Severity::Critical),
        (Regex::new(r"-----BEGIN EC PRIVATE KEY-----").unwrap(), "EC Private Key", SecretType::PrivateKey, Severity::Critical),
        (Regex::new(r"-----BEGIN DSA PRIVATE KEY-----").unwrap(), "DSA Private Key", SecretType::PrivateKey, Severity::Critical),
        (Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap(), "SSH Private Key", SecretType::PrivateKey, Severity::Critical),
        
        // Database URLs (5)
        (Regex::new(r#"postgresql://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+/\w+"#).unwrap(), "PostgreSQL URL", SecretType::DatabaseUrl, Severity::Critical),
        (Regex::new(r#"mysql://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+/\w+"#).unwrap(), "MySQL URL", SecretType::DatabaseUrl, Severity::Critical),
        (Regex::new(r#"mongodb(?:\+srv)?://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+/\w+"#).unwrap(), "MongoDB URL", SecretType::DatabaseUrl, Severity::Critical),
        (Regex::new(r#"redis://[^\s'\"<>]+:[^\s'\"<>]+@[^\s'\"<>]+:\d+"#).unwrap(), "Redis URL", SecretType::DatabaseUrl, Severity::Critical),
        (Regex::new(r#"sqlite:///[^\s'\"<>]+\.db"#).unwrap(), "SQLite URL", SecretType::DatabaseUrl, Severity::High),
        
        // Generic API Keys (4)
        (Regex::new(r#"(?i)api[_-]?key\s*=\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"#).unwrap(), "Generic API Key", SecretType::ApiKey, Severity::High),
        (Regex::new(r#"(?i)api[_-]?secret\s*=\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"#).unwrap(), "Generic API Secret", SecretType::ApiKey, Severity::Critical),
        (Regex::new(r#"(?i)access[_-]?token\s*=\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"#).unwrap(), "Access Token", SecretType::Token, Severity::High),
        (Regex::new(r#"(?i)bearer[_\s]+token\s*=\s*['\"]?([A-Za-z0-9_\-\.]{16,})['\"]?"#).unwrap(), "Bearer Token", SecretType::Token, Severity::High),
        
        // Passwords (4)
        (Regex::new(r#"(?i)password\s*=\s*['\"]?([^'\"]{8,})['\"]?"#).unwrap(), "Password", SecretType::Password, Severity::Critical),
        (Regex::new(r#"(?i)passwd\s*=\s*['\"]?([^'\"]{8,})['\"]?"#).unwrap(), "Passwd", SecretType::Password, Severity::Critical),
        (Regex::new(r#"(?i)secret[_\s]?key\s*=\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"#).unwrap(), "Secret Key", SecretType::GenericSecret, Severity::Critical),
        (Regex::new(r#"(?i)session[_\s]?secret\s*=\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"#).unwrap(), "Session Secret", SecretType::GenericSecret, Severity::Critical),
    ]
});

// ============================================================================
// XSS PATTERNS - 7 PATTERNS
// ============================================================================

pub static XSS_PATTERNS: Lazy<Vec<(Regex, &'static str, Severity)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"<script[^>]*>.*?</script>").unwrap(), "Script Tag Injection", Severity::Critical),
        (Regex::new(r"<img[^>]+onerror\s*=").unwrap(), "Image OnError Injection", Severity::Critical),
        (Regex::new(r"<svg[^>]+onload\s*=").unwrap(), "SVG OnLoad Injection", Severity::Critical),
        (Regex::new(r#"javascript:[^'\"]*"#).unwrap(), "JavaScript URI", Severity::High),
        (Regex::new(r"<iframe[^>]+src\s*=").unwrap(), "Iframe Injection", Severity::High),
        (Regex::new(r"<body[^>]+onload\s*=").unwrap(), "Body OnLoad Injection", Severity::High),
        (Regex::new(r"<input[^>]+onfocus\s*=").unwrap(), "Input OnFocus Injection", Severity::Medium),
    ]
});

// ============================================================================
// ENTERPRISE ROUTES - 22 ROUTES COMPLETAS (4 setores)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseRoute {
    pub path: String,
    pub sector: Sector,
    pub severity: Severity,
    pub cvss: f64,
    pub manipulation_payloads: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Sector {
    Fintech,
    Government,
    Ecommerce,
    Products,
}

pub static ENTERPRISE_ROUTES: Lazy<Vec<EnterpriseRoute>> = Lazy::new(|| {
    vec![
        // FINTECH (5)
        EnterpriseRoute {
            path: "/payments/authorize".to_string(),
            sector: Sector::Fintech,
            severity: Severity::Critical,
            cvss: 9.5,
            manipulation_payloads: vec![
                r#"{"amount": 0.01, "currency": "BRL"}"#.to_string(),
                r#"{"amount": -1, "currency": "USD"}"#.to_string(),
                r#"{"amount": 999999, "currency": "VND"}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/ledger/balance".to_string(),
            sector: Sector::Fintech,
            severity: Severity::Critical,
            cvss: 9.2,
            manipulation_payloads: vec![
                "/ledger/balance?account_id=1".to_string(),
                "/ledger/balance?account_id=2".to_string(),
                "/ledger/balance?wildcard=true".to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/transfer/internal".to_string(),
            sector: Sector::Fintech,
            severity: Severity::Critical,
            cvss: 9.8,
            manipulation_payloads: vec![
                r#"{"from": "victim_id", "to": "attacker_id", "amount": 99999}"#.to_string(),
                r#"{"from": "0", "to": "attacker_id", "amount": "unlimited"}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/kyc/verify".to_string(),
            sector: Sector::Fintech,
            severity: Severity::High,
            cvss: 8.5,
            manipulation_payloads: vec![
                r#"{"document": "../../../etc/passwd"}"#.to_string(),
                r#"{"document": "CPF: 000.000.000-00"}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/auth/mfa/challenge".to_string(),
            sector: Sector::Fintech,
            severity: Severity::High,
            cvss: 8.8,
            manipulation_payloads: vec![
                r#"{"code": "000000"}"#.to_string(),
                r#"{"code": ["111111", "222222", "333333"]}"#.to_string(),
            ],
        },
        
        // GOVERNMENT (5)
        EnterpriseRoute {
            path: "/citizen/registry".to_string(),
            sector: Sector::Government,
            severity: Severity::Critical,
            cvss: 9.8,
            manipulation_payloads: vec![
                "/citizen/registry?id=1".to_string(),
                "/citizen/registry?id=2".to_string(),
                "/citizen/registry?cpf=XXX.XXX.XXX-XX".to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/tax/declaration".to_string(),
            sector: Sector::Government,
            severity: Severity::Critical,
            cvss: 9.5,
            manipulation_payloads: vec![
                "/tax/declaration?cpf=XXX.XXX.XXX-XX".to_string(),
                "/tax/declaration?year=2020".to_string(),
                "/tax/declaration?batch=true".to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/benefits/status".to_string(),
            sector: Sector::Government,
            severity: Severity::High,
            cvss: 8.5,
            manipulation_payloads: vec![
                "/benefits/status?cpf=XXX.XXX.XXX-XX".to_string(),
                "/benefits/status?batch=true".to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/identity/validate".to_string(),
            sector: Sector::Government,
            severity: Severity::High,
            cvss: 8.2,
            manipulation_payloads: vec![
                r#"{"document": "CPF: XXX.XXX.XXX-XX"}"#.to_string(),
                r#"{"document_type": "*", "document": "*"}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/portal/admin/config".to_string(),
            sector: Sector::Government,
            severity: Severity::Critical,
            cvss: 9.0,
            manipulation_payloads: vec![
                "/portal/admin/config?debug=true".to_string(),
                "/portal/admin/config?mode=maintenance".to_string(),
            ],
        },
        
        // ECOMMERCE (6)
        EnterpriseRoute {
            path: "/cart/update".to_string(),
            sector: Sector::Ecommerce,
            severity: Severity::Critical,
            cvss: 8.5,
            manipulation_payloads: vec![
                r#"{"items": [{"id": 1, "unit_price": 0.01, "quantity": 1}]}"#.to_string(),
                r#"{"items": [{"id": 1, "quantity": -1}]}"#.to_string(),
                r#"{"items": [{"id": 1, "price": 0}]}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/checkout/price-override".to_string(),
            sector: Sector::Ecommerce,
            severity: Severity::Critical,
            cvss: 9.0,
            manipulation_payloads: vec![
                r#"{"override_price": 0.01, "reason": "loyalty"}"#.to_string(),
                r#"{"discount_percent": 100, "reason": "admin"}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/coupons/validate".to_string(),
            sector: Sector::Ecommerce,
            severity: Severity::High,
            cvss: 8.0,
            manipulation_payloads: vec![
                r#"{"code": "ADMIN100OFF", "discount_percent": 100}"#.to_string(),
                r#"{"code": ["UNLIMITED", "MEGA50"], "apply_all": true}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/promos/apply".to_string(),
            sector: Sector::Ecommerce,
            severity: Severity::High,
            cvss: 7.8,
            manipulation_payloads: vec![
                r#"{"promo_code": "STACK-OVERFLOW-50", "apply_to_all": true}"#.to_string(),
                r#"{"promo_code": ["DISCOUNT100", "FREESHIP"]}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/inventory/adjust".to_string(),
            sector: Sector::Ecommerce,
            severity: Severity::Medium,
            cvss: 6.5,
            manipulation_payloads: vec![
                r#"{"product_id": 1, "stock": -999}"#.to_string(),
                r#"{"product_id": 1, "stock": 999999}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/tickets/book".to_string(),
            sector: Sector::Ecommerce,
            severity: Severity::Medium,
            cvss: 6.0,
            manipulation_payloads: vec![
                r#"{"price": 0.01, "quantity": 100}"#.to_string(),
                r#"{"discount_code": "FREE", "amount": 0}"#.to_string(),
            ],
        },
        
        // PRODUCTS (6)
        EnterpriseRoute {
            path: "/products/list".to_string(),
            sector: Sector::Products,
            severity: Severity::Medium,
            cvss: 5.5,
            manipulation_payloads: vec![
                "/products/list?limit=-1".to_string(),
                "/products/list?offset=999999".to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/products/details".to_string(),
            sector: Sector::Products,
            severity: Severity::Medium,
            cvss: 5.0,
            manipulation_payloads: vec![
                "/products/details?id=1' OR '1'='1".to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/products/search".to_string(),
            sector: Sector::Products,
            severity: Severity::High,
            cvss: 7.5,
            manipulation_payloads: vec![
                "/products/search?q=<script>alert(1)</script>".to_string(),
                "/products/search?q=' UNION SELECT * FROM users--".to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/products/pricing/dynamic".to_string(),
            sector: Sector::Products,
            severity: Severity::High,
            cvss: 7.8,
            manipulation_payloads: vec![
                r#"{"product_id": 1, "price": 0.01, "rule": "manual_override"}"#.to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/products/stock/check".to_string(),
            sector: Sector::Products,
            severity: Severity::Low,
            cvss: 4.0,
            manipulation_payloads: vec![
                "/products/stock/check?sku=*".to_string(),
            ],
        },
        EnterpriseRoute {
            path: "/admin/products/update".to_string(),
            sector: Sector::Products,
            severity: Severity::Critical,
            cvss: 8.5,
            manipulation_payloads: vec![
                r#"{"product_id": 1, "price": 0.01, "role": "admin"}"#.to_string(),
                r#"{"product_id": 1, "stock": -1, "action": "bulk_update"}"#.to_string(),
            ],
        },
    ]
});

// ============================================================================
// IMPLEMENTAÇÃO PRINCIPAL
// ============================================================================

pub struct RegexEngine {
    stack_patterns: Vec<(Regex, &'static str, &'static str, f64)>,
    secret_patterns: Vec<(Regex, &'static str, SecretType, Severity)>,
    xss_patterns: Vec<(Regex, &'static str, Severity)>,
    enterprise_routes: Vec<EnterpriseRoute>,
}

impl RegexEngine {
    pub fn new() -> Self {
        Self {
            stack_patterns: STACK_DETECT_PATTERNS.clone(),
            secret_patterns: SECRET_PATTERNS.clone(),
            xss_patterns: XSS_PATTERNS.clone(),
            enterprise_routes: ENTERPRISE_ROUTES.clone(),
        }
    }
    
    pub fn detect_stacks(&self, content: &str) -> StackDetectionResult {
        let mut detected = Vec::new();
        let mut confidence_scores = HashMap::new();
        let mut priority_vectors = Vec::new();
        let mut depriority_vectors = Vec::new();
        
        let content_lower = content.to_lowercase();
        
        for (regex, stack_key, tech_label, confidence) in &self.stack_patterns {
            if regex.is_match(&content_lower) {
                detected.push(stack_key.to_string());
                confidence_scores.insert(stack_key.to_string(), *confidence);
                
                // Adiciona vetores prioritários baseados na stack
                priority_vectors.extend(Self::get_priority_vectors(stack_key));
            }
        }
        
        let tech_labels: Vec<String> = detected.iter()
            .filter_map(|k| {
                self.stack_patterns.iter()
                    .find(|(_, key, _, _)| key == k)
                    .map(|(_, _, label, _)| label.to_string())
            })
            .collect();
        
        StackDetectionResult {
            detected_stacks: detected,
            tech_labels,
            priority_vectors: Self::dedupe(priority_vectors),
            depriority_vectors: Self::dedupe(depriority_vectors),
            stack_signature: detected.join("+"),
            confidence_scores,
        }
    }
    
    pub fn scan_secrets(&self, content: &str) -> Vec<SecretMatch> {
        let mut secrets = Vec::new();
        
        for (regex, name, secret_type, severity) in &self.secret_patterns {
            for capture in regex.captures_iter(content) {
                if let Some(matched) = capture.get(0) {
                    let value = matched.as_str();
                    if value.len() >= 8 {
                        secrets.push(SecretMatch {
                            pattern_name: name.to_string(),
                            pattern_type: secret_type.clone(),
                            value: value.to_string(),
                            severity: severity.clone(),
                            location: matched.start(),
                            context: Self::extract_context(content, matched.start(), matched.end()),
                        });
                    }
                }
            }
        }
        
        secrets
    }
    
    pub fn scan_secrets_parallel(&self, content: &str) -> Vec<SecretMatch> {
        let chunks: Vec<&str> = content
            .as_bytes()
            .chunks(1024 * 1024)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
            .collect();
        
        chunks.par_iter()
            .flat_map(|chunk| self.scan_secrets(chunk))
            .collect()
    }
    
    pub fn detect_xss_patterns(&self, content: &str) -> Vec<XSSFinding> {
        let mut findings = Vec::new();
        
        for (regex, name, severity) in &self.xss_patterns {
            for capture in regex.find_iter(content) {
                findings.push(XSSFinding {
                    pattern_name: name.to_string(),
                    severity: severity.clone(),
                    location: capture.start(),
                    matched_text: capture.as_str().to_string(),
                    context: Self::extract_context(content, capture.start(), capture.end()),
                });
            }
        }
        
        findings
    }
    
    pub fn find_enterprise_routes(&self, content: &str) -> Vec<EnterpriseRouteMatch> {
        let mut matches = Vec::new();
        
        for route in &self.enterprise_routes {
            if content.contains(&route.path) {
                matches.push(EnterpriseRouteMatch {
                    route: route.clone(),
                    found_at: content.find(&route.path).unwrap_or(0),
                    context: Self::extract_context(content, 
                        content.find(&route.path).unwrap_or(0),
                        content.find(&route.path).unwrap_or(0) + route.path.len()),
                });
            }
        }
        
        matches
    }
    
    pub fn scan_js_file_complete(&self, content: &str) -> JSFileScanResult {
        JSFileScanResult {
            secrets: self.scan_secrets_parallel(content),
            xss_findings: self.detect_xss_patterns(content),
            enterprise_routes: self.find_enterprise_routes(content),
            total_size: content.len(),
            scan_time_ms: 0, // será preenchido pelo caller
        }
    }
    
    fn get_priority_vectors(stack_key: &str) -> Vec<String> {
        match stack_key {
            "express" => vec![
                "prototype_pollution".to_string(),
                "nosql_injection".to_string(),
                "ssrf".to_string(),
                "path_traversal".to_string(),
            ],
            "next" => vec![
                "ssrf".to_string(),
                "api_exposure".to_string(),
                "broken_auth".to_string(),
                "path_traversal".to_string(),
            ],
            "django" => vec![
                "ssti".to_string(),
                "orm_injection".to_string(),
                "csrf".to_string(),
                "debug_exposure".to_string(),
            ],
            "spring" => vec![
                "deserialization".to_string(),
                "sqli".to_string(),
                "ssti".to_string(),
                "path_traversal".to_string(),
            ],
            "laravel" => vec![
                "sqli".to_string(),
                "lfi".to_string(),
                "rce".to_string(),
                "deserialization".to_string(),
            ],
            "rails" => vec![
                "deserialization".to_string(),
                "sqli".to_string(),
                "ssti".to_string(),
                "mass_assignment".to_string(),
            ],
            "flask" => vec![
                "ssti".to_string(),
                "ssrf".to_string(),
                "debug_exposure".to_string(),
                "path_traversal".to_string(),
            ],
            "aspnet" => vec![
                "deserialization".to_string(),
                "sqli".to_string(),
                "path_traversal".to_string(),
                "viewstate".to_string(),
            ],
            "wordpress" => vec![
                "sqli".to_string(),
                "lfi".to_string(),
                "rce".to_string(),
                "auth_bypass".to_string(),
            ],
            "react" => vec![
                "xss_dangerously".to_string(),
                "xss_dom".to_string(),
                "prototype_pollution".to_string(),
            ],
            "angular" => vec![
                "xss_template".to_string(),
                "xss_csti".to_string(),
                "prototype_pollution".to_string(),
            ],
            "vue" => vec![
                "xss_template".to_string(),
                "xss_csti".to_string(),
                "prototype_pollution".to_string(),
            ],
            "aws" => vec![
                "ssrf_metadata".to_string(),
                "credential_leak".to_string(),
                "iam_escalation".to_string(),
            ],
            "gcp" => vec![
                "ssrf_metadata".to_string(),
                "credential_leak".to_string(),
            ],
            "azure" => vec![
                "ssrf_metadata".to_string(),
                "credential_leak".to_string(),
            ],
            "cloudflare" => vec![
                "waf_bypass".to_string(),
                "ssrf".to_string(),
                "api_abuse".to_string(),
            ],
            "mongodb" => vec![
                "nosql_injection".to_string(),
                "idor".to_string(),
                "broken_auth".to_string(),
            ],
            "redis" => vec![
                "ssrf".to_string(),
                "credential_leak".to_string(),
                "command_injection".to_string(),
            ],
            "graphql" => vec![
                "idor".to_string(),
                "broken_auth".to_string(),
                "introspection".to_string(),
                "injection".to_string(),
            ],
            _ => vec![
                "sqli".to_string(),
                "xss".to_string(),
                "ssrf".to_string(),
                "lfi".to_string(),
            ],
        }
    }
    
    fn extract_context(content: &str, start: usize, end: usize) -> String {
        let ctx_start = if start > 80 { start - 80 } else { 0 };
        let ctx_end = if end + 80 < content.len() { end + 80 } else { content.len() };
        format!("...{}...", &content[ctx_start..ctx_end])
    }
    
    fn dedupe(mut vec: Vec<String>) -> Vec<String> {
        vec.sort();
        vec.dedup();
        vec
    }
}

// ============================================================================
// TIPOS DE RETORNO
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XSSFinding {
    pub pattern_name: String,
    pub severity: Severity,
    pub location: usize,
    pub matched_text: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseRouteMatch {
    pub route: EnterpriseRoute,
    pub found_at: usize,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JSFileScanResult {
    pub secrets: Vec<SecretMatch>,
    pub xss_findings: Vec<XSSFinding>,
    pub enterprise_routes: Vec<EnterpriseRouteMatch>,
    pub total_size: usize,
    pub scan_time_ms: u64,
}

impl Default for RegexEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detect_express_stack() {
        let engine = RegexEngine::new();
        let result = engine.detect_stacks("X-Powered-By: Express, connect.sid cookie present");
        assert!(result.detected_stacks.contains(&"express".to_string()));
    }
    
    #[test]
    fn test_scan_aws_key() {
        let engine = RegexEngine::new();
        let content = "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF";
        let secrets = engine.scan_secrets(content);
        assert!(!secrets.is_empty());
        assert_eq!(secrets[0].pattern_type, SecretType::AwsKey);
    }
    
    #[test]
    fn test_find_enterprise_routes() {
        let engine = RegexEngine::new();
        let content = "/payments/authorize and /cart/update endpoints";
        let routes = engine.find_enterprise_routes(content);
        assert_eq!(routes.len(), 2);
    }
}
