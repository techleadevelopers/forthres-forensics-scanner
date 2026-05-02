// scanner/rust_core/src/waf_behavior_analysis.rs
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use reqwest::Client;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafBehaviorReport {
    pub vendor: String,
    pub detected: bool,
    pub strength: String,
    pub confidence: u32,
    pub baseline_status: u16,
    pub blocked_patterns: Vec<String>,
    pub allowed_encodings: Vec<String>,
    pub preferred_methods: Vec<String>,
    pub header_sensitivity: HashMap<String, f64>,
    pub content_type_tolerance: HashMap<String, String>,
    pub challenge_signals: Vec<String>,
    pub recommended_stealth_level: f64,
    pub sample_observations: Vec<Observation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub name: String,
    pub method: String,
    pub status_code: u16,
    pub elapsed_ms: u64,
    pub blocked: bool,
    pub headers: HashMap<String, String>,
    pub content_type: String,
    pub body: String,
    pub payload_repr: String,
}

pub struct WafBehaviorAnalyzer {
    client: Client,
    base_url: String,
}

impl WafBehaviorAnalyzer {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub async fn analyze(&self, memory_hint: Option<&WafBehaviorReport>) -> WafBehaviorReport {
        let mut report = WafBehaviorReport::default();
        let mut observations = Vec::new();

        let tests = self.build_tests(memory_hint);

        for test in tests {
            if let Some(obs) = self.run_test(&test).await {
                observations.push(obs);
            }
        }

        if observations.is_empty() {
            return report;
        }

        let baseline = &observations[0];
        report.baseline_status = baseline.status_code;

        // Detectar WAF
        let detection = crate::waf_detector::WafDetector::detect(
            baseline.status_code, &baseline.headers, &baseline.body, None
        );
        report.detected = detection.detected;
        report.vendor = detection.vendor;
        report.confidence = detection.confidence;

        // Determinar força
        let blocked_count = observations.iter().filter(|o| o.blocked).count();
        report.strength = if blocked_count >= 4 {
            "strong".to_string()
        } else if blocked_count >= 2 {
            "medium".to_string()
        } else {
            "weak".to_string()
        };

        report.blocked_patterns = self.collect_blocked_patterns(&observations);
        report.allowed_encodings = self.collect_allowed_encodings(&observations);
        report.preferred_methods = self.collect_preferred_methods(&observations);
        report.header_sensitivity = self.measure_header_sensitivity(&observations);
        report.content_type_tolerance = self.measure_content_type_tolerance(&observations);
        report.challenge_signals = self.collect_challenge_signals(&observations);
        report.recommended_stealth_level = self.recommend_stealth(&report, &observations);
        report.sample_observations = observations;

        // Merge com hint de memória
        if let Some(hint) = memory_hint {
            report = self.merge_memory_hint(report, hint);
        }

        report
    }

    fn build_tests(&self, memory_hint: Option<&WafBehaviorReport>) -> Vec<TestConfig> {
        let mut tests = vec![
            TestConfig::baseline(),
            TestConfig::xss_plain(),
            TestConfig::xss_encoded(),
            TestConfig::sqli_plain(),
            TestConfig::sqli_obfuscated(),
            TestConfig::header_probe(),
            TestConfig::json_probe(),
            TestConfig::form_probe(),
        ];

        if let Some(hint) = memory_hint {
            tests = self.build_validation_tests(hint);
        }

        tests
    }

    fn build_validation_tests(&self, hint: &WafBehaviorReport) -> Vec<TestConfig> {
        let mut tests = vec![TestConfig::baseline()];
        
        if let Some(first_blocked) = hint.blocked_patterns.first() {
            tests.push(TestConfig::blocked_pattern_check(first_blocked));
        }
        
        if hint.allowed_encodings.contains(&"url_encoding".to_string()) {
            tests.push(TestConfig::allowed_encoding_check());
        } else {
            tests.push(TestConfig::light_json_check());
        }
        
        tests
    }

    async fn run_test(&self, test: &TestConfig) -> Option<Observation> {
        let url = format!("{}{}", self.base_url, test.path);
        let start = Instant::now();

        let request = self.client.request(test.method.clone(), &url);
        let request = if let Some(ref params) = test.params {
            request.query(params)
        } else {
            request
        };
        let request = if let Some(ref headers) = test.headers {
            let mut req = request;
            for (k, v) in headers {
                req = req.header(k, v);
            }
            req
        } else {
            request
        };
        let request = if let Some(ref json) = test.json {
            request.json(json)
        } else if let Some(ref data) = test.data {
            request.form(data)
        } else {
            request
        };

        match request.send().await {
            Ok(resp) => {
                let elapsed_ms = start.elapsed().as_millis() as u64;
                let status_code = resp.status().as_u16();
                let headers: HashMap<String, String> = resp.headers()
                    .iter()
                    .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body = resp.text().await.unwrap_or_default();
                let body_lower = body.to_lowercase();
                
                let blocked = status_code == 403 || status_code == 406 || status_code == 429 || status_code == 503
                    || body_lower.contains("access denied")
                    || body_lower.contains("request blocked")
                    || body_lower.contains("forbidden")
                    || body_lower.contains("captcha")
                    || body_lower.contains("attention required")
                    || body_lower.contains("firewall");

                Some(Observation {
                    name: test.name.clone(),
                    method: format!("{:?}", test.method),
                    status_code,
                    elapsed_ms,
                    blocked,
                    headers,
                    content_type: resp.headers()
                        .get("content-type")
                        .map(|v| v.to_str().unwrap_or("").to_lowercase())
                        .unwrap_or_default(),
                    body: body.chars().take(2500).collect(),
                    payload_repr: test.payload_repr(),
                })
            }
            Err(e) => {
                eprintln!("Test failed: {} - {}", test.name, e);
                Some(Observation {
                    name: test.name.clone(),
                    method: format!("{:?}", test.method),
                    status_code: 0,
                    elapsed_ms: 0,
                    blocked: false,
                    headers: HashMap::new(),
                    content_type: String::new(),
                    body: e.to_string().chars().take(250).collect(),
                    payload_repr: test.payload_repr(),
                })
            }
        }
    }

    fn collect_blocked_patterns(&self, observations: &[Observation]) -> Vec<String> {
        let tokens = ["<script", "<svg/onload", "alert(1)", "' or '1'='1", "/**/or/**/", "x-original-url", "127.0.0.1"];
        let mut blocked = Vec::new();
        
        for obs in observations {
            if !obs.blocked { continue; }
            let payload = obs.payload_repr.to_lowercase();
            for token in &tokens {
                if payload.contains(token) && !blocked.contains(&token.to_string()) {
                    blocked.push(token.to_string());
                }
            }
        }
        
        blocked.truncate(8);
        blocked
    }

    fn collect_allowed_encodings(&self, observations: &[Observation]) -> Vec<String> {
        let mut allowed = Vec::new();
        
        for obs in observations {
            if obs.blocked { continue; }
            let payload = obs.payload_repr.to_lowercase();
            if payload.contains("%3c") && !allowed.contains(&"url_encoding".to_string()) {
                allowed.push("url_encoding".to_string());
            }
            if payload.contains("/**/") && !allowed.contains(&"comment_injection".to_string()) {
                allowed.push("comment_injection".to_string());
            }
            if payload.contains("<svg/onload") && !allowed.contains(&"tag_swap".to_string()) {
                allowed.push("tag_swap".to_string());
            }
        }
        
        if allowed.is_empty() {
            allowed.push("raw".to_string());
        }
        
        allowed.truncate(6);
        allowed
    }

    fn collect_preferred_methods(&self, observations: &[Observation]) -> Vec<String> {
        let mut scores: HashMap<String, i32> = HashMap::new();
        
        for obs in observations {
            let method = obs.method.clone();
            let score = if obs.blocked { 0 } else { 1 };
            *scores.entry(method).or_insert(0) += score;
        }
        
        let mut methods: Vec<String> = scores.keys().cloned().collect();
        methods.sort_by_key(|m| -scores.get(m).unwrap_or(&0));
        methods.truncate(3);
        methods
    }

    fn measure_header_sensitivity(&self, observations: &[Observation]) -> HashMap<String, f64> {
        let mut result = HashMap::new();
        
        let header_probe = observations.iter().find(|o| o.name == "header_probe");
        let baseline = observations.iter().find(|o| o.name == "baseline_get");
        
        if let (Some(probe), Some(baseline)) = (header_probe, baseline) {
            let sensitivity = if probe.blocked && !baseline.blocked {
                0.9
            } else if probe.status_code != baseline.status_code {
                0.5
            } else {
                0.0
            };
            result.insert("spoofed_forward_headers".to_string(), sensitivity);
        }
        
        result
    }

    fn measure_content_type_tolerance(&self, observations: &[Observation]) -> HashMap<String, String> {
        let mut result = HashMap::new();
        result.insert("application/json".to_string(), "unknown".to_string());
        result.insert("application/x-www-form-urlencoded".to_string(), "unknown".to_string());
        
        for obs in observations {
            if obs.name == "json_probe" {
                result.insert("application/json".to_string(), if obs.blocked { "blocked".to_string() } else { "allowed".to_string() });
            }
            if obs.name == "form_probe" {
                result.insert("application/x-www-form-urlencoded".to_string(), if obs.blocked { "blocked".to_string() } else { "allowed".to_string() });
            }
        }
        
        result
    }

    fn collect_challenge_signals(&self, observations: &[Observation]) -> Vec<String> {
        let mut signals = Vec::new();
        
        for obs in observations {
            if let Some(cf_ray) = obs.headers.get("cf-ray") {
                if !signals.contains(&"cf-ray".to_string()) {
                    signals.push("cf-ray".to_string());
                }
            }
            if obs.headers.contains_key("x-sucuri-block") && !signals.contains(&"x-sucuri-block".to_string()) {
                signals.push("x-sucuri-block".to_string());
            }
            let body = obs.body.to_lowercase();
            if body.contains("captcha") && !signals.contains(&"captcha".to_string()) {
                signals.push("captcha".to_string());
            }
            if body.contains("attention required") && !signals.contains(&"attention_required".to_string()) {
                signals.push("attention_required".to_string());
            }
        }
        
        signals.truncate(8);
        signals
    }

    fn recommend_stealth(&self, report: &WafBehaviorReport, observations: &[Observation]) -> f64 {
        let base = match report.strength.as_str() {
            "weak" => 0.35,
            "medium" => 0.62,
            "strong" => 0.84,
            _ => 0.55,
        };
        
        let mut extra = 0.0;
        if report.header_sensitivity.get("spoofed_forward_headers").unwrap_or(&0.0) >= &0.8 {
            extra += 0.05;
        }
        if !report.challenge_signals.is_empty() {
            extra += 0.04;
        }
        if report.allowed_encodings.len() >= 2 {
            extra -= 0.03;
        }
        
        (base + extra).clamp(0.2, 0.95)
    }

    fn merge_memory_hint(&self, mut report: WafBehaviorReport, hint: &WafBehaviorReport) -> WafBehaviorReport {
        if report.vendor == "unknown" && hint.vendor != "unknown" {
            report.vendor = hint.vendor.clone();
        }
        if report.strength == "unknown" && hint.strength != "unknown" {
            report.strength = hint.strength.clone();
        }
        
        for pattern in &hint.blocked_patterns {
            if !report.blocked_patterns.contains(pattern) {
                report.blocked_patterns.push(pattern.clone());
            }
        }
        
        for encoding in &hint.allowed_encodings {
            if !report.allowed_encodings.contains(encoding) {
                report.allowed_encodings.push(encoding.clone());
            }
        }
        
        if report.preferred_methods.is_empty() && !hint.preferred_methods.is_empty() {
            report.preferred_methods = hint.preferred_methods.clone();
        }
        
        if report.content_type_tolerance.is_empty() && !hint.content_type_tolerance.is_empty() {
            report.content_type_tolerance = hint.content_type_tolerance.clone();
        }
        
        if report.recommended_stealth_level <= 0.2 && hint.recommended_stealth_level > 0.2 {
            report.recommended_stealth_level = hint.recommended_stealth_level;
        }
        
        report
    }
}

impl Default for WafBehaviorReport {
    fn default() -> Self {
        Self {
            vendor: "unknown".to_string(),
            detected: false,
            strength: "unknown".to_string(),
            confidence: 0,
            baseline_status: 0,
            blocked_patterns: Vec::new(),
            allowed_encodings: Vec::new(),
            preferred_methods: Vec::new(),
            header_sensitivity: HashMap::new(),
            content_type_tolerance: HashMap::new(),
            challenge_signals: Vec::new(),
            recommended_stealth_level: 0.5,
            sample_observations: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct TestConfig {
    name: String,
    method: reqwest::Method,
    path: String,
    params: Option<HashMap<String, String>>,
    headers: Option<HashMap<String, String>>,
    json: Option<serde_json::Value>,
    data: Option<HashMap<String, String>>,
}

impl TestConfig {
    fn baseline() -> Self {
        Self {
            name: "baseline_get".to_string(),
            method: reqwest::Method::GET,
            path: "/".to_string(),
            params: None,
            headers: None,
            json: None,
            data: None,
        }
    }
    
    fn xss_plain() -> Self {
        let mut params = HashMap::new();
        params.insert("q".to_string(), "<script>alert(1)</script>".to_string());
        Self {
            name: "xss_plain".to_string(),
            method: reqwest::Method::GET,
            path: "/".to_string(),
            params: Some(params),
            headers: None,
            json: None,
            data: None,
        }
    }
    
    fn xss_encoded() -> Self {
        let mut params = HashMap::new();
        params.insert("q".to_string(), "%3Cscript%3Ealert(1)%3C/script%3E".to_string());
        Self {
            name: "xss_encoded".to_string(),
            method: reqwest::Method::GET,
            path: "/".to_string(),
            params: Some(params),
            headers: None,
            json: None,
            data: None,
        }
    }
    
    fn sqli_plain() -> Self {
        let mut params = HashMap::new();
        params.insert("q".to_string(), "' OR '1'='1".to_string());
        Self {
            name: "sqli_plain".to_string(),
            method: reqwest::Method::GET,
            path: "/search".to_string(),
            params: Some(params),
            headers: None,
            json: None,
            data: None,
        }
    }
    
    fn sqli_obfuscated() -> Self {
        let mut params = HashMap::new();
        params.insert("q".to_string(), "'/**/OR/**/'1'='1".to_string());
        Self {
            name: "sqli_obfuscated".to_string(),
            method: reqwest::Method::GET,
            path: "/search".to_string(),
            params: Some(params),
            headers: None,
            json: None,
            data: None,
        }
    }
    
    fn header_probe() -> Self {
        let mut headers = HashMap::new();
        headers.insert("X-Original-URL".to_string(), "/admin".to_string());
        headers.insert("X-Forwarded-For".to_string(), "127.0.0.1".to_string());
        Self {
            name: "header_probe".to_string(),
            method: reqwest::Method::GET,
            path: "/".to_string(),
            params: None,
            headers: Some(headers),
            json: None,
            data: None,
        }
    }
    
    fn json_probe() -> Self {
        let json = serde_json::json!({"q": "<svg/onload=alert(1)>"});
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        Self {
            name: "json_probe".to_string(),
            method: reqwest::Method::POST,
            path: "/".to_string(),
            params: None,
            headers: Some(headers),
            json: Some(json),
            data: None,
        }
    }
    
    fn form_probe() -> Self {
        let mut data = HashMap::new();
        data.insert("q".to_string(), "<svg/onload=alert(1)>".to_string());
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
        Self {
            name: "form_probe".to_string(),
            method: reqwest::Method::POST,
            path: "/".to_string(),
            params: None,
            headers: Some(headers),
            json: None,
            data: Some(data),
        }
    }
    
    fn blocked_pattern_check(pattern: &str) -> Self {
        let mut params = HashMap::new();
        params.insert("q".to_string(), pattern.to_string());
        Self {
            name: "blocked_pattern_check".to_string(),
            method: reqwest::Method::GET,
            path: "/".to_string(),
            params: Some(params),
            headers: None,
            json: None,
            data: None,
        }
    }
    
    fn allowed_encoding_check() -> Self {
        let mut params = HashMap::new();
        params.insert("q".to_string(), "%3Csvg%2Fonload%3Dalert%281%29%3E".to_string());
        Self {
            name: "allowed_encoding_check".to_string(),
            method: reqwest::Method::GET,
            path: "/".to_string(),
            params: Some(params),
            headers: None,
            json: None,
            data: None,
        }
    }
    
    fn light_json_check() -> Self {
        let json = serde_json::json!({"q": "probe"});
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        Self {
            name: "light_json_check".to_string(),
            method: reqwest::Method::POST,
            path: "/".to_string(),
            params: None,
            headers: Some(headers),
            json: Some(json),
            data: None,
        }
    }
    
    fn payload_repr(&self) -> String {
        if let Some(ref params) = self.params {
            return params.values().next().cloned().unwrap_or_default();
        }
        if let Some(ref json) = self.json {
            return json.to_string();
        }
        if let Some(ref data) = self.data {
            return data.values().next().cloned().unwrap_or_default();
        }
        String::new()
    }
}