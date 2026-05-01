use serde::{Deserialize, Serialize};

use crate::reporting::security_reporter::{Severity, VulnerabilityKind, VulnerabilityReport};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequirements {
    pub no_self_destruct: bool,
    pub ownership_transfer_requires_timelock: bool,
    pub require_fork_validation: bool,
    pub require_proxy_access_control: bool,
    pub max_exploit_probability: Option<f64>,
    pub max_risk_adjusted_value_eth: Option<f64>,
    pub forbid_flagged_selectors: Vec<String>,
}

impl Default for VerifyRequirements {
    fn default() -> Self {
        Self {
            no_self_destruct: false,
            ownership_transfer_requires_timelock: false,
            require_fork_validation: false,
            require_proxy_access_control: false,
            max_exploit_probability: None,
            max_risk_adjusted_value_eth: None,
            forbid_flagged_selectors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifyViolationSeverity {
    Critical,
    High,
    Medium,
    Low,
    Unsupported,
}

impl std::fmt::Display for VerifyViolationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyViolationSeverity::Critical => write!(f, "CRITICAL"),
            VerifyViolationSeverity::High => write!(f, "HIGH"),
            VerifyViolationSeverity::Medium => write!(f, "MEDIUM"),
            VerifyViolationSeverity::Low => write!(f, "LOW"),
            VerifyViolationSeverity::Unsupported => write!(f, "UNSUPPORTED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyViolation {
    pub rule: String,
    pub severity: VerifyViolationSeverity,
    pub message: String,
    pub evidence: Vec<String>,
    pub recommended_fix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyDecision {
    pub passed: bool,
    pub estimated_risk: Severity,
    pub confidence: u32,
    pub violations: Vec<VerifyViolation>,
    pub unsupported_checks: Vec<String>,
    pub summary: String,
    pub report: VulnerabilityReport,
}

fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

fn selector_matches(value: &str, needle: &str) -> bool {
    let normalized_value = value.to_lowercase();
    let normalized_needle = needle.to_lowercase();
    normalized_value == normalized_needle || normalized_value.contains(&normalized_needle)
}

fn has_self_destruct(report: &VulnerabilityReport) -> bool {
    report.kind == VulnerabilityKind::UnprotectedSelfDestruct
        || contains_ignore_case(&report.description, "selfdestruct")
        || report
            .flagged_selectors
            .iter()
            .any(|selector| selector_matches(selector, "selfdestruct"))
}

fn has_ownership_transfer_surface(report: &VulnerabilityReport) -> bool {
    report
        .flagged_selectors
        .iter()
        .any(|selector| selector_matches(selector, "transferownership"))
        || contains_ignore_case(&report.description, "ownership")
        || contains_ignore_case(&report.recommendation, "ownership")
}

fn clamp_probability(value: f64) -> f64 {
    value.clamp(0.0, 1.0)
}

pub fn verify_report(report: &VulnerabilityReport, requirements: &VerifyRequirements) -> VerifyDecision {
    let mut violations = Vec::new();
    let mut unsupported_checks = Vec::new();

    if requirements.no_self_destruct && has_self_destruct(report) {
        violations.push(VerifyViolation {
            rule: "noSelfDestruct".to_string(),
            severity: VerifyViolationSeverity::Critical,
            message: "SELFDESTRUCT behavior was detected by the Hexora scan engine.".to_string(),
            evidence: vec![
                format!("kind={}", report.kind),
                format!("description={}", report.description),
            ],
            recommended_fix: Some(
                "Remove SELFDESTRUCT semantics or gate destructive admin flows behind an immutable emergency pattern."
                    .to_string(),
            ),
        });
    }

    if requirements.ownership_transfer_requires_timelock && has_ownership_transfer_surface(report) {
        violations.push(VerifyViolation {
            rule: "ownershipTransferRequiresTimelock".to_string(),
            severity: VerifyViolationSeverity::High,
            message: "Ownership transfer capability was detected, but timelock enforcement cannot be proven from runtime scan output.".to_string(),
            evidence: report.flagged_selectors.iter().cloned().collect(),
            recommended_fix: Some(
                "Enforce ownership transfer through a timelock or two-step governance handoff and re-run verification."
                    .to_string(),
            ),
        });
    }

    if requirements.require_fork_validation && !report.fork_validated {
        violations.push(VerifyViolation {
            rule: "requireForkValidation".to_string(),
            severity: VerifyViolationSeverity::Medium,
            message: "Fork validation was required, but the scan result was not fork-validated.".to_string(),
            evidence: vec![format!("forkValidated={}", report.fork_validated)],
            recommended_fix: Some(
                "Re-run the scan with fork validation enabled and a healthy fork backend before treating the contract as production-ready."
                    .to_string(),
            ),
        });
    }

    if requirements.require_proxy_access_control {
        let access_controlled = report
            .proxy
            .as_ref()
            .map(|proxy| proxy.is_access_controlled)
            .unwrap_or(false);

        if !access_controlled {
            violations.push(VerifyViolation {
                rule: "requireProxyAccessControl".to_string(),
                severity: VerifyViolationSeverity::High,
                message: "Proxy access control was required, but the current report does not prove controlled admin or upgrade paths.".to_string(),
                evidence: vec![format!(
                    "proxyDetected={}",
                    report.proxy.as_ref().map(|_| true).unwrap_or(false)
                )],
                recommended_fix: Some(
                    "Introduce explicit admin control, timelock governance, or immutable upgrade restrictions for proxy management."
                        .to_string(),
                ),
            });
        }
    }

    if let Some(max_probability) = requirements.max_exploit_probability {
        let actual = clamp_probability(report.exploitation_probability);
        if actual > max_probability {
            violations.push(VerifyViolation {
                rule: "maxExploitProbability".to_string(),
                severity: if actual >= 0.5 {
                    VerifyViolationSeverity::Critical
                } else {
                    VerifyViolationSeverity::High
                },
                message: format!(
                    "Exploit probability {:.2}% exceeded the allowed ceiling of {:.2}%.",
                    actual * 100.0,
                    max_probability * 100.0
                ),
                evidence: vec![
                    format!("exploitationProbability={:.6}", actual),
                    format!("confidenceScore={}", report.confidence_score),
                ],
                recommended_fix: Some(
                    "Reduce exploitability through stricter access control, removed dangerous flows, or hardened state transitions before release."
                        .to_string(),
                ),
            });
        }
    }

    if let Some(max_value) = requirements.max_risk_adjusted_value_eth {
        if report.risk_adjusted_value > max_value {
            violations.push(VerifyViolation {
                rule: "maxRiskAdjustedValueEth".to_string(),
                severity: if report.risk_adjusted_value >= 1.0 {
                    VerifyViolationSeverity::Critical
                } else {
                    VerifyViolationSeverity::High
                },
                message: format!(
                    "Risk-adjusted value {:.6} ETH exceeded the allowed ceiling of {:.6} ETH.",
                    report.risk_adjusted_value, max_value
                ),
                evidence: vec![
                    format!("riskAdjustedValueEth={:.6}", report.risk_adjusted_value),
                    format!("exploitPaths={}", report.exploit_paths.len()),
                ],
                recommended_fix: Some(
                    "Reduce privileged value movement and close the exploit path before listing or interacting with this contract."
                        .to_string(),
                ),
            });
        }
    }

    for forbidden in &requirements.forbid_flagged_selectors {
        if report
            .flagged_selectors
            .iter()
            .any(|selector| selector_matches(selector, forbidden))
        {
            violations.push(VerifyViolation {
                rule: "forbidFlaggedSelectors".to_string(),
                severity: VerifyViolationSeverity::High,
                message: format!("Forbidden flagged selector detected: {}.", forbidden),
                evidence: report
                    .flagged_selectors
                    .iter()
                    .filter(|selector| selector_matches(selector, forbidden))
                    .cloned()
                    .collect(),
                recommended_fix: Some(
                    "Remove or explicitly guard the forbidden selector path before production interaction."
                        .to_string(),
                ),
            });
        }
    }

    if requirements.no_self_destruct
        || requirements.ownership_transfer_requires_timelock
        || requirements.require_fork_validation
        || requirements.require_proxy_access_control
        || requirements.max_exploit_probability.is_some()
        || requirements.max_risk_adjusted_value_eth.is_some()
        || !requirements.forbid_flagged_selectors.is_empty()
    {
    } else {
        unsupported_checks.push("noExplicitRequirements".to_string());
        violations.push(VerifyViolation {
            rule: "requirements".to_string(),
            severity: VerifyViolationSeverity::Unsupported,
            message: "No explicit verify requirements were supplied. This decision only mirrors scan posture.".to_string(),
            evidence: Vec::new(),
            recommended_fix: None,
        });
    }

    let passed = violations
        .iter()
        .all(|violation| violation.severity == VerifyViolationSeverity::Unsupported);

    let summary = if passed {
        format!(
            "Verification passed with {} unsupported checks and no enforceable policy violations.",
            unsupported_checks.len()
        )
    } else {
        format!(
            "Verification failed with {} enforceable policy violation(s).",
            violations
                .iter()
                .filter(|violation| violation.severity != VerifyViolationSeverity::Unsupported)
                .count()
        )
    };

    VerifyDecision {
        passed,
        estimated_risk: report.severity.clone(),
        confidence: report.confidence_score,
        violations,
        unsupported_checks,
        summary,
        report: report.clone(),
    }
}
