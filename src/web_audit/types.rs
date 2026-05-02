// scanner/rust_core/src/types.rs
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// TIPOS BÁSICOS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
    
    pub fn cvss_score(&self) -> f64 {
        match self {
            Severity::Critical => 9.0,
            Severity::High => 7.0,
            Severity::Medium => 4.0,
            Severity::Low => 2.0,
            Severity::Info => 0.0,
        }
    }
    
    pub fn weight(&self) -> f64 {
        match self {
            Severity::Critical => 1.0,
            Severity::High => 0.75,
            Severity::Medium => 0.45,
            Severity::Low => 0.20,
            Severity::Info => 0.05,
        }
    }
}

impl From<String> for Severity {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Confidence {
    Confirmed,
    High,
    Medium,
    Low,
    Speculative,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
            Confidence::Speculative => "speculative",
        }
    }
    
    pub fn value(&self) -> f64 {
        match self {
            Confidence::Confirmed => 1.0,
            Confidence::High => 0.85,
            Confidence::Medium => 0.60,
            Confidence::Low => 0.35,
            Confidence::Speculative => 0.15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Phase {
    Surface,
    Exposure,
    Misconfig,
    Simulation,
    Report,
    Reconnaissance,
    Exploitation,
    PrivilegeEscalation,
    LateralMovement,
    DataCapture,
    Exfiltration,
}

impl Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Surface => "surface",
            Phase::Exposure => "exposure",
            Phase::Misconfig => "misconfig",
            Phase::Simulation => "simulation",
            Phase::Report => "report",
            Phase::Reconnaissance => "reconnaissance",
            Phase::Exploitation => "exploitation",
            Phase::PrivilegeEscalation => "privilege_escalation",
            Phase::LateralMovement => "lateral_movement",
            Phase::DataCapture => "data_capture",
            Phase::Exfiltration => "exfiltration",
        }
    }
}

// ============================================================================
// TIPOS DE FINDINGS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Finding {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub phase: String,
    #[serde(default)]
    pub recommendation: String,
    #[serde(default)]
    pub cvss_score: f64,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub module: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub raw_value: String,
    #[serde(default)]
    pub raw_content: String,
    #[serde(default)]
    pub secrets_extracted: Vec<String>,
    #[serde(default)]
    pub response_body: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub confidence: String,
}

impl Finding {
    pub fn new(
        severity: Severity,
        title: &str,
        description: &str,
        phase: Phase,
    ) -> Self {
        Self {
            severity: severity.as_str().to_string(),
            title: title.to_string(),
            description: description.to_string(),
            phase: phase.as_str().to_string(),
            cvss_score: severity.cvss_score(),
            confidence: Confidence::Medium.as_str().to_string(),
            ..Default::default()
        }
    }
    
    pub fn critical(title: &str, description: &str, phase: Phase) -> Self {
        Self::new(Severity::Critical, title, description, phase)
    }
    
    pub fn high(title: &str, description: &str, phase: Phase) -> Self {
        Self::new(Severity::High, title, description, phase)
    }
    
    pub fn medium(title: &str, description: &str, phase: Phase) -> Self {
        Self::new(Severity::Medium, title, description, phase)
    }
    
    pub fn low(title: &str, description: &str, phase: Phase) -> Self {
        Self::new(Severity::Low, title, description, phase)
    }
    
    pub fn info(title: &str, description: &str, phase: Phase) -> Self {
        Self::new(Severity::Info, title, description, phase)
    }
    
    pub fn with_evidence(mut self, evidence: &str) -> Self {
        self.evidence = evidence.to_string();
        self
    }
    
    pub fn with_endpoint(mut self, endpoint: &str) -> Self {
        self.endpoint = endpoint.to_string();
        self
    }
    
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence.as_str().to_string();
        self.cvss_score = self.cvss_score * confidence.value();
        self
    }
}

// ============================================================================
// TIPOS DE SCAN
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditEntry {
    pub timestamp: f64,
    pub action: String,
    pub details: String,
    #[serde(default)]
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentJob {
    pub job_id: String,
    pub target: String,
    pub hostname: String,
    pub scheme: String,
    pub port: Option<u16>,
    pub status: String,
    pub created_at: f64,
    pub completed_at: Option<f64>,
    pub findings: Vec<Finding>,
    pub audit_log: Vec<AuditEntry>,
    pub phases_completed: Vec<String>,
    pub aborted: bool,
}

impl AssessmentJob {
    pub fn new(target: String, hostname: String, scheme: String, port: Option<u16>) -> Self {
        Self {
            job_id: Uuid::new_v4().to_string()[..12].to_string(),
            target,
            hostname,
            scheme,
            port,
            status: "pending".to_string(),
            created_at: now_ts(),
            completed_at: None,
            findings: Vec::new(),
            audit_log: Vec::new(),
            phases_completed: Vec::new(),
            aborted: false,
        }
    }

    pub fn base_url(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{}", self.scheme, self.hostname, port),
            None => format!("{}://{}", self.scheme, self.hostname),
        }
    }

    pub fn add_audit(&mut self, action: impl Into<String>, details: impl Into<String>, phase: impl Into<String>) {
        self.audit_log.push(AuditEntry {
            timestamp: now_ts(),
            action: action.into(),
            details: details.into(),
            phase: phase.into(),
        });
    }
    
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }
    
    pub fn complete(&mut self) {
        self.status = "completed".to_string();
        self.completed_at = Some(now_ts());
    }
    
    pub fn error(&mut self) {
        self.status = "error".to_string();
        self.completed_at = Some(now_ts());
    }
    
    pub fn abort(&mut self) {
        self.aborted = true;
        self.status = "aborted".to_string();
        self.completed_at = Some(now_ts());
    }
}

// ============================================================================
// EVENTOS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventPayload<T> {
    pub event: String,
    pub data: T,
    pub timestamp: f64,
}

impl<T> EventPayload<T> {
    pub fn new(event: &str, data: T) -> Self {
        Self {
            event: event.to_string(),
            data,
            timestamp: now_ts(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStreamEvent {
    pub message: String,
    pub level: String,
    pub phase: String,
}

impl LogStreamEvent {
    pub fn info(message: &str, phase: &str) -> Self {
        Self {
            message: message.to_string(),
            level: "info".to_string(),
            phase: phase.to_string(),
        }
    }
    
    pub fn warn(message: &str, phase: &str) -> Self {
        Self {
            message: message.to_string(),
            level: "warn".to_string(),
            phase: phase.to_string(),
        }
    }
    
    pub fn error(message: &str, phase: &str) -> Self {
        Self {
            message: message.to_string(),
            level: "error".to_string(),
            phase: phase.to_string(),
        }
    }
    
    pub fn success(message: &str, phase: &str) -> Self {
        Self {
            message: message.to_string(),
            level: "success".to_string(),
            phase: phase.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseUpdateEvent {
    pub phase: String,
    pub status: String,
}

impl PhaseUpdateEvent {
    pub fn running(phase: &str) -> Self {
        Self {
            phase: phase.to_string(),
            status: "running".to_string(),
        }
    }
    
    pub fn completed(phase: &str) -> Self {
        Self {
            phase: phase.to_string(),
            status: "completed".to_string(),
        }
    }
    
    pub fn error(phase: &str) -> Self {
        Self {
            phase: phase.to_string(),
            status: "error".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StackHypothesis {
    pub detected_stacks: Vec<String>,
    pub tech_labels: Vec<String>,
    pub priority_vectors: Vec<String>,
    pub depriority: Vec<String>,
    pub stack_signature: String,
}

impl StackHypothesis {
    pub fn new(detected_stacks: Vec<String>, tech_labels: Vec<String>) -> Self {
        // CORRIGIDO: calcular stack_signature ANTES de mover detected_stacks
        let stack_signature = detected_stacks.join("+");
        Self {
            stack_signature,
            detected_stacks,
            tech_labels,
            priority_vectors: Vec::new(),
            depriority: Vec::new(),
        }
    }
    
    pub fn is_empty(&self) -> bool {
        self.detected_stacks.is_empty()
    }
    
    pub fn has_stack(&self, stack: &str) -> bool {
        self.detected_stacks.iter().any(|s| s == stack)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryUpdate {
    pub progress: u32,
    pub active_modules: u32,
    pub threats_detected: u32,
    pub requests_analyzed: u32,
}

impl Default for TelemetryUpdate {
    fn default() -> Self {
        Self {
            progress: 0,
            active_modules: 0,
            threats_detected: 0,
            requests_analyzed: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDetectedEvent {
    pub finding: Finding,
    pub timestamp: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCompleteEvent {
    pub scan_id: String,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub duration_seconds: f64,
}

// ============================================================================
// RELATÓRIO
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentSummary {
    pub total_findings: usize,
    pub severity_distribution: BTreeMap<String, usize>,
    pub max_cvss_score: f64,
    pub risk_level: String,
}

impl AssessmentSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut severity_distribution = BTreeMap::new();
        let mut max_cvss_score = 0.0_f64;
        
        for finding in findings {
            *severity_distribution.entry(finding.severity.clone()).or_insert(0) += 1;
            if finding.cvss_score > max_cvss_score {
                max_cvss_score = finding.cvss_score;
            }
        }
        
        let risk_level = if max_cvss_score >= 9.0 {
            "CRITICAL"
        } else if max_cvss_score >= 7.0 {
            "HIGH"
        } else if max_cvss_score >= 4.0 {
            "MEDIUM"
        } else if max_cvss_score >= 0.1 {
            "LOW"
        } else {
            "NONE"
        }
        .to_string();
        
        Self {
            total_findings: findings.len(),
            severity_distribution,
            max_cvss_score,
            risk_level,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentReport {
    pub job_id: String,
    pub target: String,
    pub hostname: String,
    pub status: String,
    pub created_at: f64,
    pub completed_at: Option<f64>,
    pub duration_seconds: f64,
    pub summary: AssessmentSummary,
    pub findings: Vec<Finding>,
    pub phases_completed: Vec<String>,
    pub audit_log: Vec<AuditEntry>,
    pub stack_hypothesis: StackHypothesis,
}

impl AssessmentReport {
    pub fn from_job(job: &AssessmentJob, stack_hypothesis: StackHypothesis) -> Self {
        Self {
            job_id: job.job_id.clone(),
            target: job.target.clone(),
            hostname: job.hostname.clone(),
            status: job.status.clone(),
            created_at: job.created_at,
            completed_at: job.completed_at,
            duration_seconds: ((job.completed_at.unwrap_or_else(now_ts) - job.created_at) * 100.0).round() / 100.0,
            summary: AssessmentSummary::from_findings(&job.findings),
            findings: job.findings.clone(),
            phases_completed: job.phases_completed.clone(),
            audit_log: job.audit_log.clone(),
            stack_hypothesis,
        }
    }
    
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// ============================================================================
// TIPOS DE SCANNER
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedAsset {
    pub path: String,
    pub asset_type: String,
    pub severity: String,
    pub value: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub probe_type: String,
    pub endpoint: String,
    pub method: String,
    pub status_code: u16,
    pub response_time_ms: u64,
    pub vulnerable: bool,
    pub verdict: String,
    pub severity: String,
    pub description: String,
    pub payload: String,
    pub evidence: String,
    pub timestamp: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTelemetry {
    pub progress: u32,
    pub active_modules: u32,
    pub threats_detected: u32,
    pub requests_analyzed: u32,
    pub scan_speed: f64,
    pub estimated_time_remaining: f64,
}

// ============================================================================
// TIPOS DE CREDENCIAIS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedCredential {
    pub key: String,
    pub value: String,
    pub source: String,
    pub credential_type: String,
    pub timestamp: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialRelayState {
    pub credentials: Vec<CapturedCredential>,
    pub infra_secrets: Vec<String>,
    pub db_credentials: Vec<String>,
    pub session_tokens: Vec<String>,
    pub discovered_users: Vec<String>,
}

// ============================================================================
// FUNÇÕES UTILITÁRIAS
// ============================================================================

pub fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

pub fn format_duration(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{:.1}s", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1}m", seconds / 60.0)
    } else {
        format!("{:.1}h", seconds / 3600.0)
    }
}

// ============================================================================
// TESTES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_severity_from_string() {
        assert_eq!(Severity::from("critical".to_string()), Severity::Critical);
        assert_eq!(Severity::from("high".to_string()), Severity::High);
        assert_eq!(Severity::from("medium".to_string()), Severity::Medium);
        assert_eq!(Severity::from("low".to_string()), Severity::Low);
        assert_eq!(Severity::from("info".to_string()), Severity::Info);
    }
    
    #[test]
    fn test_finding_creation() {
        let finding = Finding::critical("Test Finding", "This is a test", Phase::Surface);
        assert_eq!(finding.severity, "critical");
        assert_eq!(finding.cvss_score, 9.0);
    }
    
    #[test]
    fn test_assessment_job() {
        let job = AssessmentJob::new(
            "https://example.com".to_string(),
            "example.com".to_string(),
            "https".to_string(),
            None,
        );
        assert_eq!(job.status, "pending");
        assert!(!job.job_id.is_empty());
        assert_eq!(job.base_url(), "https://example.com");
    }
    
    #[test]
    fn test_assessment_summary() {
        let findings = vec![
            Finding::critical("Finding 1", "Desc", Phase::Surface),
            Finding::high("Finding 2", "Desc", Phase::Exposure),
            Finding::medium("Finding 3", "Desc", Phase::Misconfig),
        ];
        
        let summary = AssessmentSummary::from_findings(&findings);
        assert_eq!(summary.total_findings, 3);
        assert!(summary.severity_distribution.contains_key("critical"));
        assert_eq!(summary.severity_distribution.get("critical"), Some(&1));
        assert_eq!(summary.risk_level, "CRITICAL");
    }
    
    #[test]
    fn test_stack_hypothesis_new() {
        let stacks = vec!["express".to_string(), "react".to_string()];
        let labels = vec!["Express.js".to_string(), "React".to_string()];
        let hypothesis = StackHypothesis::new(stacks, labels);
        assert_eq!(hypothesis.stack_signature, "express+react");
        assert_eq!(hypothesis.detected_stacks.len(), 2);
    }
}