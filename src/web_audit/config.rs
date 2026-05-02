use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AllowlistPayload {
    allowed_targets: Vec<String>,
}

pub const DEFAULT_ALLOWLIST: &[&str] = &[
    "*.example.com",
    "*.test.local",
    "localhost",
    "127.0.0.1",
    "10.*.*.*",
    "192.168.*.*",
    "172.16.*.*",
];

pub const MAX_CONCURRENT_JOBS: usize = 3;
pub const PHASE_TIMEOUT_SECONDS: u64 = 120;
pub const MAX_REQUESTS_PER_MODULE: usize = 50;
pub const REQUEST_DELAY_MS: u64 = 200;
pub const USER_AGENT: &str = "OSLO-SecurityAssessment/2.0 (Authorized-Internal-Audit)";

pub fn allowlist_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("analysis")
        .join("scanner")
        .join("allowlist.json")
}

pub fn load_allowlist() -> Vec<String> {
    let path = allowlist_file();
    if path.exists() {
        match fs::read_to_string(path)
            .ok()
            .and_then(|raw| serde_json::from_str::<AllowlistPayload>(&raw).ok())
        {
            Some(payload) if !payload.allowed_targets.is_empty() => payload.allowed_targets,
            _ => DEFAULT_ALLOWLIST.iter().map(|v| (*v).to_string()).collect(),
        }
    } else {
        DEFAULT_ALLOWLIST.iter().map(|v| (*v).to_string()).collect()
    }
}

pub fn save_allowlist(targets: Vec<String>) -> Result<(), String> {
    let path = allowlist_file();
    let payload = AllowlistPayload { allowed_targets: targets };
    let json = serde_json::to_string_pretty(&payload).map_err(|e| format!("Failed to serialize: {}", e))?;
    fs::write(path, json).map_err(|e| format!("Failed to write allowlist: {}", e))
}

pub fn pattern_to_regex(pattern: &str) -> Regex {
    let escaped = regex::escape(pattern);
    Regex::new(&format!("^{}$", escaped.replace(r"\*", ".*"))).expect("valid allowlist regex")
}

pub fn validate_target(target: &str) -> ValidationResult {
    let normalized = if target.contains("://") {
        target.to_string()
    } else {
        format!("https://{target}")
    };

    let parsed = match Url::parse(&normalized) {
        Ok(parsed) => parsed,
        Err(err) => {
            return ValidationResult {
                valid: false,
                reason: Some(format!("Invalid target format: {}", err)),
                hostname: None,
                scheme: None,
                port: None,
                matched_rule: None,
            }
        }
    };

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return ValidationResult {
            valid: false,
            reason: Some(format!("Unsupported scheme: {}", parsed.scheme())),
            hostname: None,
            scheme: None,
            port: None,
            matched_rule: None,
        };
    }

    let Some(hostname) = parsed.host_str().map(|v| v.to_string()) else {
        return ValidationResult {
            valid: false,
            reason: Some("Could not extract hostname from target".to_string()),
            hostname: None,
            scheme: None,
            port: None,
            matched_rule: None,
        };
    };

    let allowlist = load_allowlist();
    for pattern in allowlist {
        let regex = pattern_to_regex(&pattern);
        if regex.is_match(&hostname) {
            return ValidationResult {
                valid: true,
                reason: None,
                hostname: Some(hostname),
                scheme: Some(parsed.scheme().to_string()),
                port: parsed.port(),
                matched_rule: Some(pattern),
            };
        }
    }

    ValidationResult {
        valid: false,
        reason: Some(format!(
            "Target '{}' is not in the allowlist. Only pre-authorized targets can be assessed.",
            hostname
        )),
        hostname: None,
        scheme: None,
        port: None,
        matched_rule: None,
    }
}

pub fn runtime_has_python_allowlist() -> bool {
    Path::new(&allowlist_file()).exists()
}