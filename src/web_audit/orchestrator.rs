// scanner/rust_core/src/orchestrator.rs
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::config::validate_target;
use super::modules::{
    phase_modules, ModuleExecution, ModuleRegistry, ModuleResult,
    SurfaceMappingModule, WafDetectorModule, TlsValidatorModule,
    BrowserReconModule, JsSecretsModule, HeadersAnalyzerModule,
    CorsAnalyzerModule, RateLimitModule, AuthFlowModule,
    InputValidationModule, SeleniumXssModule,
};
use super::types::{
    now_ts, AssessmentJob, AssessmentReport, EventPayload, Finding,
    LogStreamEvent, PhaseUpdateEvent, StackHypothesis, TelemetryUpdate,
    Severity, Phase, Confidence,
};

// ============================================================================
// CONSTANTES
// ============================================================================

pub const PHASE_ORDER: &[&str] = &[
    "surface",
    "exposure",
    "misconfig",
    "simulation",
    "report"
];

pub const VERSION: &str = "2.0.0";
pub const MAX_CONCURRENT_MODULES: usize = 3;
pub const MODULE_TIMEOUT_SECONDS: u64 = 120;

// ============================================================================
// TECH HYPOTHESIS - 16 STACKS COMPLETAS
// ============================================================================

#[derive(Clone, Debug)]
pub struct TechHypothesis {
    pub label: &'static str,
    pub priority: &'static [&'static str],
    pub depriority: &'static [&'static str],
    pub confidence: f64,
}

pub fn stack_hypothesis_map() -> BTreeMap<&'static str, TechHypothesis> {
    BTreeMap::from([
        // Frameworks (10)
        ("express", TechHypothesis {
            label: "Express.js",
            priority: &["prototype_pollution", "nosql_injection", "ssrf", "path_traversal"],
            depriority: &["sqli_traditional"],
            confidence: 0.95,
        }),
        ("next", TechHypothesis {
            label: "Next.js",
            priority: &["ssrf", "api_exposure", "broken_auth", "path_traversal"],
            depriority: &["sqli_traditional", "lfi"],
            confidence: 0.93,
        }),
        ("firebase", TechHypothesis {
            label: "Firebase",
            priority: &["nosql_injection", "broken_auth", "idor", "credential_leak"],
            depriority: &["sqli_traditional", "lfi", "ssti"],
            confidence: 0.92,
        }),
        ("django", TechHypothesis {
            label: "Django",
            priority: &["ssti", "orm_injection", "csrf", "debug_exposure"],
            depriority: &["prototype_pollution"],
            confidence: 0.91,
        }),
        ("spring", TechHypothesis {
            label: "Spring Boot",
            priority: &["deserialization", "sqli", "ssti", "path_traversal"],
            depriority: &["prototype_pollution", "nosql_injection"],
            confidence: 0.90,
        }),
        ("php", TechHypothesis {
            label: "PHP",
            priority: &["sqli", "lfi", "rce", "deserialization", "ssti"],
            depriority: &["prototype_pollution", "nosql_injection"],
            confidence: 0.94,
        }),
        ("rails", TechHypothesis {
            label: "Ruby on Rails",
            priority: &["deserialization", "sqli", "ssti", "mass_assignment"],
            depriority: &["prototype_pollution"],
            confidence: 0.89,
        }),
        ("flask", TechHypothesis {
            label: "Flask",
            priority: &["ssti", "ssrf", "debug_exposure", "path_traversal"],
            depriority: &["prototype_pollution"],
            confidence: 0.88,
        }),
        ("aspnet", TechHypothesis {
            label: "ASP.NET",
            priority: &["deserialization", "sqli", "path_traversal", "viewstate"],
            depriority: &["prototype_pollution", "nosql_injection"],
            confidence: 0.87,
        }),
        ("wordpress", TechHypothesis {
            label: "WordPress",
            priority: &["sqli", "lfi", "rce", "auth_bypass"],
            depriority: &["prototype_pollution"],
            confidence: 0.94,
        }),
        
        // Servers (3)
        ("nginx", TechHypothesis {
            label: "Nginx",
            priority: &["path_traversal", "header_injection", "ssrf"],
            depriority: &[],
            confidence: 0.96,
        }),
        ("apache", TechHypothesis {
            label: "Apache",
            priority: &["path_traversal", "ssti", "cgi_abuse"],
            depriority: &[],
            confidence: 0.95,
        }),
        ("iis", TechHypothesis {
            label: "IIS",
            priority: &["path_traversal", "viewstate", "deserialization"],
            depriority: &[],
            confidence: 0.90,
        }),
        
        // Databases (3)
        ("mongodb", TechHypothesis {
            label: "MongoDB",
            priority: &["nosql_injection", "idor", "broken_auth"],
            depriority: &["sqli_traditional"],
            confidence: 0.88,
        }),
        ("redis", TechHypothesis {
            label: "Redis",
            priority: &["ssrf", "credential_leak", "command_injection"],
            depriority: &[],
            confidence: 0.87,
        }),
        ("postgres", TechHypothesis {
            label: "PostgreSQL",
            priority: &["sqli", "rce", "credential_leak"],
            depriority: &[],
            confidence: 0.86,
        }),
        
        // API (2)
        ("graphql", TechHypothesis {
            label: "GraphQL",
            priority: &["idor", "broken_auth", "introspection", "injection"],
            depriority: &[],
            confidence: 0.92,
        }),
        ("grpc", TechHypothesis {
            label: "gRPC",
            priority: &["deserialization", "auth_bypass", "injection"],
            depriority: &[],
            confidence: 0.85,
        }),
        
        // Cloud (3)
        ("aws", TechHypothesis {
            label: "AWS",
            priority: &["ssrf", "credential_leak", "iam_escalation"],
            depriority: &[],
            confidence: 0.92,
        }),
        ("gcp", TechHypothesis {
            label: "GCP",
            priority: &["ssrf", "credential_leak"],
            depriority: &[],
            confidence: 0.90,
        }),
        ("azure", TechHypothesis {
            label: "Azure",
            priority: &["ssrf", "credential_leak"],
            depriority: &[],
            confidence: 0.89,
        }),
        
        // WAF (1)
        ("cloudflare", TechHypothesis {
            label: "Cloudflare WAF",
            priority: &["waf_bypass", "ssrf", "api_abuse"],
            depriority: &["brute_force"],
            confidence: 0.93,
        }),
    ])
}

// ============================================================================
// STACK DETECTION PATTERNS - 25+ STACKS
// ============================================================================

pub fn stack_detect_patterns() -> BTreeMap<&'static str, Vec<Regex>> {
    BTreeMap::from([
        // Frameworks
        ("express", vec![
            Regex::new(r"(?i)express").unwrap(),
            Regex::new(r"(?i)x-powered-by.*express").unwrap(),
            Regex::new(r"(?i)connect\.sid").unwrap(),
            Regex::new(r"(?i)express-session").unwrap(),
        ]),
        ("next", vec![
            Regex::new(r"(?i)next\.js").unwrap(),
            Regex::new(r"(?i)_next/").unwrap(),
            Regex::new(r"(?i)__NEXT_DATA__").unwrap(),
            Regex::new(r"(?i)vercel").unwrap(),
        ]),
        ("firebase", vec![
            Regex::new(r"(?i)firebase").unwrap(),
            Regex::new(r"(?i)firebaseio\.com").unwrap(),
            Regex::new(r"(?i)firebaseapp\.com").unwrap(),
            Regex::new(r"(?i)firestore").unwrap(),
        ]),
        ("django", vec![
            Regex::new(r"(?i)django").unwrap(),
            Regex::new(r"(?i)csrfmiddlewaretoken").unwrap(),
            Regex::new(r"(?i)wsgi").unwrap(),
            Regex::new(r"(?i)django\.core").unwrap(),
        ]),
        ("spring", vec![
            Regex::new(r"(?i)spring").unwrap(),
            Regex::new(r"(?i)whitelabel error").unwrap(),
            Regex::new(r"(?i)x-application-context").unwrap(),
            Regex::new(r"(?i)spring-boot").unwrap(),
        ]),
        ("php", vec![
            Regex::new(r"(?i)x-powered-by.*php").unwrap(),
            Regex::new(r"(?i)\.php").unwrap(),
            Regex::new(r"(?i)laravel").unwrap(),
            Regex::new(r"(?i)symfony").unwrap(),
            Regex::new(r"(?i)wordpress").unwrap(),
        ]),
        ("rails", vec![
            Regex::new(r"(?i)x-powered-by.*phusion").unwrap(),
            Regex::new(r"(?i)ruby").unwrap(),
            Regex::new(r"(?i)rails").unwrap(),
            Regex::new(r"(?i)_session_id").unwrap(),
        ]),
        ("flask", vec![
            Regex::new(r"(?i)werkzeug").unwrap(),
            Regex::new(r"(?i)flask").unwrap(),
            Regex::new(r"(?i)jinja2").unwrap(),
        ]),
        ("aspnet", vec![
            Regex::new(r"(?i)asp\.net").unwrap(),
            Regex::new(r"(?i)__viewstate").unwrap(),
            Regex::new(r"(?i)x-aspnet").unwrap(),
            Regex::new(r"(?i)aspx").unwrap(),
        ]),
        ("wordpress", vec![
            Regex::new(r"(?i)wp-content").unwrap(),
            Regex::new(r"(?i)wp-includes").unwrap(),
            Regex::new(r"(?i)wp-admin").unwrap(),
            Regex::new(r"(?i)wp-json").unwrap(),
        ]),
        
        // Servers
        ("nginx", vec![
            Regex::new(r"(?i)server.*nginx").unwrap(),
            Regex::new(r"(?i)nginx/[\d\.]+").unwrap(),
        ]),
        ("apache", vec![
            Regex::new(r"(?i)server.*apache").unwrap(),
            Regex::new(r"(?i)apache/[\d\.]+").unwrap(),
        ]),
        ("iis", vec![
            Regex::new(r"(?i)microsoft-iis").unwrap(),
            Regex::new(r"(?i)iis/[\d\.]+").unwrap(),
        ]),
        
        // Databases
        ("mongodb", vec![
            Regex::new(r"(?i)mongodb").unwrap(),
            Regex::new(r"(?i)mongoose").unwrap(),
            Regex::new(r"(?i)nosql").unwrap(),
        ]),
        ("redis", vec![
            Regex::new(r"(?i)redis").unwrap(),
            Regex::new(r"(?i)ioredis").unwrap(),
        ]),
        ("postgres", vec![
            Regex::new(r"(?i)postgresql").unwrap(),
            Regex::new(r"(?i)pg_catalog").unwrap(),
        ]),
        
        // API
        ("graphql", vec![
            Regex::new(r"(?i)graphql").unwrap(),
            Regex::new(r"(?i)__schema").unwrap(),
            Regex::new(r"(?i)query.*mutation").unwrap(),
        ]),
        ("grpc", vec![
            Regex::new(r"(?i)grpc").unwrap(),
            Regex::new(r"(?i)protobuf").unwrap(),
        ]),
        
        // Cloud
        ("aws", vec![
            Regex::new(r"(?i)amazonaws").unwrap(),
            Regex::new(r"(?i)x-amz").unwrap(),
            Regex::new(r"(?i)aws").unwrap(),
            Regex::new(r"(?i)lambda").unwrap(),
            Regex::new(r"(?i)s3://").unwrap(),
        ]),
        ("gcp", vec![
            Regex::new(r"(?i)google\.cloud").unwrap(),
            Regex::new(r"(?i)\.appspot\.com").unwrap(),
            Regex::new(r"(?i)cloudfunctions").unwrap(),
        ]),
        ("azure", vec![
            Regex::new(r"(?i)azure").unwrap(),
            Regex::new(r"(?i)\.azurewebsites\.net").unwrap(),
            Regex::new(r"(?i)azure-api").unwrap(),
        ]),
        
        // WAF
        ("cloudflare", vec![
            Regex::new(r"(?i)cloudflare").unwrap(),
            Regex::new(r"(?i)cf-ray").unwrap(),
            Regex::new(r"(?i)cf-cache").unwrap(),
            Regex::new(r"(?i)__cfduid").unwrap(),
        ]),
    ])
}

// ============================================================================
// BUILD HYPOTHESIS
// ============================================================================

pub fn build_hypothesis(findings: &[Finding]) -> StackHypothesis {
    let stacks = stack_hypothesis_map();
    let patterns = stack_detect_patterns();

    let all_text = findings
        .iter()
        .map(|f| format!(" {} {} {} {}", f.title, f.description, f.evidence, f.category))
        .collect::<String>()
        .to_lowercase();

    let mut detected_stacks = Vec::new();
    let mut tech_labels = Vec::new();
    let mut priority_vectors = Vec::new();
    let mut depriority = Vec::new();
    let mut confidence_scores = BTreeMap::new();

    for (tech_key, tech_patterns) in patterns {
        let matches = tech_patterns.iter().filter(|pat| pat.is_match(&all_text)).count();
        if matches > 0 && !detected_stacks.iter().any(|s| s == tech_key) {
            detected_stacks.push(tech_key.to_string());
            if let Some(hypothesis) = stacks.get(tech_key) {
                tech_labels.push(hypothesis.label.to_string());
                confidence_scores.insert(tech_key.to_string(), hypothesis.confidence * (matches as f64 / 4.0).min(1.0));
                
                for value in hypothesis.priority {
                    if !priority_vectors.iter().any(|existing| existing == value) {
                        priority_vectors.push((*value).to_string());
                    }
                }
                for value in hypothesis.depriority {
                    if !depriority.iter().any(|existing| existing == value) {
                        depriority.push((*value).to_string());
                    }
                }
            }
        }
    }

    // Ordenar por confiança
    priority_vectors.sort();
    priority_vectors.dedup();
    depriority.sort();
    depriority.dedup();

    StackHypothesis {
        stack_signature: if detected_stacks.is_empty() {
            "unknown".to_string()
        } else {
            detected_stacks.join("+")
        },
        detected_stacks,
        tech_labels,
        priority_vectors,
        depriority,
    }
}

// ============================================================================
// FUNÇÕES DE EMISSÃO DE EVENTOS
// ============================================================================

pub fn emit<T: serde::Serialize>(event_type: &str, data: T) -> Result<()> {
    let payload = EventPayload {
        event: event_type.to_string(),
        data,
        timestamp: now_ts(),
    };
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

pub fn emit_log(message: &str, level: &str, phase: &str) -> Result<()> {
    emit("log_stream", LogStreamEvent {
        message: message.to_string(),
        level: level.to_string(),
        phase: phase.to_string(),
    })
}

pub fn emit_phase_update(phase: &str, status: &str) -> Result<()> {
    emit("phase_update", PhaseUpdateEvent {
        phase: phase.to_string(),
        status: status.to_string(),
    })
}

pub fn emit_telemetry(progress: u32, active_modules: u32, threats_detected: u32, requests_analyzed: u32) -> Result<()> {
    emit("telemetry_update", TelemetryUpdate {
        progress,
        active_modules,
        threats_detected,
        requests_analyzed,
    })
}

// ============================================================================
// ORCHESTRATOR PRINCIPAL
// ============================================================================

pub async fn run_assessment(target: &str) -> Result<AssessmentReport> {
    emit_log(&format!("MSE Orchestrator v{} starting", VERSION), "info", "");
    emit_log(&format!("Target: {}", target), "info", "");
    
    // Validação do target
    let validation = validate_target(target);
    if !validation.valid {
        let reason = validation.reason.unwrap_or_else(|| "unknown".to_string());
        emit_log(&format!("TARGET REJECTED: {}", reason), "error", "");
        emit_phase_update("surface", "error")?;
        anyhow::bail!("target validation failed: {}", reason);
    }

    let hostname = validation.hostname.unwrap_or_default();
    let scheme = validation.scheme.unwrap_or_else(|| "https".to_string());
    let matched_rule = validation.matched_rule.unwrap_or_else(|| "N/A".to_string());

    let mut job = AssessmentJob::new(target.to_string(), hostname.clone(), scheme, validation.port);
    job.add_audit(
        "assessment_started",
        format!("Target: {target}, Matched rule: {matched_rule}"),
        "",
    );

    emit_log(
        &format!("Assessment authorized  Target: {} (rule: {})", job.hostname, matched_rule),
        "success",
        "",
    )?;
    emit_log(&format!("Job ID: {}", job.job_id), "info", "")?;
    emit_log(&format!("Base URL: {}", job.base_url()), "info", "")?;

    let total_phases = PHASE_ORDER.len();
    let mut completed_phases = 0;
    let mut total_findings = 0;

    for phase_name in PHASE_ORDER {
        if job.aborted {
            emit_log("Scan aborted by user", "warn", "");
            break;
        }

        emit_phase_update(phase_name, "running")?;
        emit_log(&format!("Starting phase: {}", phase_name), "info", phase_name)?;

        let modules = phase_modules(phase_name);
        let total_modules = modules.len();
        let mut completed_modules = 0;

        for module in modules {
            if job.aborted {
                break;
            }

            emit_log(&format!("  Starting module: {}", module.name()), "info", phase_name)?;
            
            let start_time = std::time::Instant::now();
            
            // Executar módulo com timeout
            let execution = tokio::time::timeout(
                std::time::Duration::from_secs(MODULE_TIMEOUT_SECONDS),
                module.execute(&job),
            ).await;

            match execution {
                Ok(Ok(module_result)) => {
                    let elapsed = start_time.elapsed();
                    
                    // Processar logs
                    for log in module_result.logs {
                        emit("log_stream", log)?;
                    }
                    
                    // Processar findings
                    for finding in module_result.findings {
                        total_findings += 1;
                        job.findings.push(finding);
                    }
                    
                    emit_log(
                        &format!("  Module {} completed in {:.1}s ({} findings)", 
                            module.name(), 
                            elapsed.as_secs_f64(),
                            module_result.findings.len()
                        ),
                        "success",
                        phase_name,
                    )?;
                }
                Ok(Err(e)) => {
                    emit_log(
                        &format!("  Module {} failed: {}", module.name(), e),
                        "error",
                        phase_name,
                    )?;
                    job.add_audit("module_error", format!("Module: {}, Error: {}", module.name(), e), phase_name);
                }
                Err(_) => {
                    emit_log(
                        &format!("  Module {} timed out after {}s", module.name(), MODULE_TIMEOUT_SECONDS),
                        "error",
                        phase_name,
                    )?;
                    job.add_audit("module_timeout", format!("Module: {}", module.name()), phase_name);
                }
            }
            
            completed_modules += 1;
            let progress = ((completed_phases * 100 / total_phases) + 
                           (completed_modules * 100 / total_modules / total_phases)) as u32;
            emit_telemetry(progress, (total_modules - completed_modules) as u32, total_findings as u32, 0)?;
        }

        if !job.aborted && *phase_name != "report" {
            job.phases_completed.push((*phase_name).to_string());
        }

        emit_phase_update(phase_name, "completed")?;
        completed_phases += 1;
        
        // Gerar hipótese após fase surface
        if *phase_name == "surface" {
            let hypothesis = build_hypothesis(&job.findings);
            if !hypothesis.detected_stacks.is_empty() {
                emit_log(
                    &format!("[HYPOTHESIS] Stack detected: {}", hypothesis.stack_signature),
                    "warn",
                    phase_name,
                )?;
                emit_log(
                    &format!("[HYPOTHESIS] Tech labels: {}", hypothesis.tech_labels.join(", ")),
                    "warn",
                    phase_name,
                )?;
                if !hypothesis.priority_vectors.is_empty() {
                    emit_log(
                        &format!("[HYPOTHESIS] Priority vectors: {}", hypothesis.priority_vectors.join(", ")),
                        "warn",
                        phase_name,
                    )?;
                }
                emit("stack_hypothesis", hypothesis)?;
            } else {
                emit_log("[HYPOTHESIS] No specific stack fingerprint detected", "info", phase_name)?;
            }
        }
    }

    // Fase de relatório
    emit_phase_update("report", "running")?;
    emit_log("Compiling assessment report...", "info", "report")?;

    job.status = "completed".to_string();
    job.completed_at = Some(now_ts());
    
    let stack_hypothesis = build_hypothesis(&job.findings);
    let report = job.to_report(stack_hypothesis);
    
    // Emitir resumo
    emit_log(&format!("Total findings: {}", report.summary.total_findings), "info", "report")?;
    emit_log(&format!("Risk level: {}", report.summary.risk_level), 
        if report.summary.risk_level == "CRITICAL" || report.summary.risk_level == "HIGH" { "error" } else { "warn" }, 
        "report")?;
    
    for (severity, count) in &report.summary.severity_distribution {
        let level = if severity == "critical" || severity == "high" { "error" } 
                    else if severity == "medium" { "warn" } 
                    else { "info" };
        emit_log(&format!("  {}: {}", severity.to_uppercase(), count), level, "report")?;
    }
    
    emit_log(&format!("Duration: {:.1}s", report.duration_seconds), "success", "report")?;
    emit_log("Report generation complete", "success", "report")?;
    
    emit_phase_update("report", "completed")?;
    emit("report_generated", &report)?;
    emit_telemetry(100, 0, report.summary.total_findings as u32, 0)?;
    
    Ok(report)
}

// ============================================================================
// SCAN COM PROGRESSO
// ============================================================================

pub struct ScanProgress {
    pub current_phase: String,
    pub current_module: String,
    pub phase_progress: f64,
    pub total_progress: f64,
    pub findings_count: usize,
    pub elapsed_seconds: f64,
}

pub async fn run_assessment_with_progress<F>(
    target: &str,
    mut progress_callback: F,
) -> Result<AssessmentReport>
where
    F: FnMut(ScanProgress),
{
    let start_time = std::time::Instant::now();
    
    let validation = validate_target(target);
    if !validation.valid {
        anyhow::bail!("target validation failed: {}", validation.reason.unwrap_or_default());
    }

    let hostname = validation.hostname.unwrap_or_default();
    let scheme = validation.scheme.unwrap_or_else(|| "https".to_string());
    let matched_rule = validation.matched_rule.unwrap_or_else(|| "N/A".to_string());

    let mut job = AssessmentJob::new(target.to_string(), hostname.clone(), scheme, validation.port);
    job.add_audit("assessment_started", format!("Target: {target}, Matched rule: {matched_rule}"), "");

    let total_phases = PHASE_ORDER.len();
    let mut completed_phases = 0;

    for (phase_idx, phase_name) in PHASE_ORDER.iter().enumerate() {
        if job.aborted {
            break;
        }

        let modules = phase_modules(phase_name);
        let total_modules = modules.len();
        let mut completed_modules = 0;

        for module in modules {
            if job.aborted {
                break;
            }
            
            progress_callback(ScanProgress {
                current_phase: (*phase_name).to_string(),
                current_module: module.name().to_string(),
                phase_progress: completed_modules as f64 / total_modules as f64,
                total_progress: (phase_idx as f64 + (completed_modules as f64 / total_modules as f64)) / total_phases as f64,
                findings_count: job.findings.len(),
                elapsed_seconds: start_time.elapsed().as_secs_f64(),
            });
            
            let execution = module.execute(&job).await?;
            for finding in execution.findings {
                job.findings.push(finding);
            }
            
            completed_modules += 1;
        }

        if *phase_name != "report" {
            job.phases_completed.push((*phase_name).to_string());
        }
        completed_phases += 1;
    }

    job.status = "completed".to_string();
    job.completed_at = Some(now_ts());
    let stack_hypothesis = build_hypothesis(&job.findings);
    let report = job.to_report(stack_hypothesis);
    
    Ok(report)
}

// ============================================================================
// SCAN PARALELO (MÚLTIPLOS TARGETS)
// ============================================================================

pub async fn run_parallel_assessments(targets: &[String]) -> Vec<Result<AssessmentReport>> {
    use futures::future::join_all;
    
    let handles: Vec<_> = targets.iter()
        .map(|target| tokio::spawn(run_assessment(target)))
        .collect();
    
    let results = join_all(handles).await;
    results.into_iter()
        .map(|handle| handle.unwrap_or_else(|e| Err(anyhow::anyhow!("Task failed: {}", e))))
        .collect()
}

// ============================================================================
// TESTES
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_build_hypothesis() {
        let findings = vec![
            Finding::new(Severity::Info, "Express detected", "X-Powered-By: Express", Phase::Surface),
            Finding::new(Severity::Info, "MongoDB found", "Mongoose library detected", Phase::Exposure),
        ];
        
        let hypothesis = build_hypothesis(&findings);
        assert!(hypothesis.detected_stacks.contains(&"express".to_string()) || 
                hypothesis.detected_stacks.contains(&"mongodb".to_string()));
    }
    
    #[test]
    fn test_stack_detection_patterns() {
        let patterns = stack_detect_patterns();
        assert!(patterns.contains_key("express"));
        assert!(patterns.contains_key("nginx"));
        assert!(patterns.contains_key("aws"));
    }
    
    #[test]
    fn test_stack_hypothesis_map() {
        let map = stack_hypothesis_map();
        assert!(map.contains_key("express"));
        assert!(map.contains_key("spring"));
        assert!(map.contains_key("aws"));
        
        let express = map.get("express").unwrap();
        assert_eq!(express.label, "Express.js");
        assert!(express.priority.contains(&"prototype_pollution"));
    }
    
    #[tokio::test]
    async fn test_emit_log() {
        let result = emit_log("Test message", "info", "test");
        assert!(result.is_ok());
    }
}