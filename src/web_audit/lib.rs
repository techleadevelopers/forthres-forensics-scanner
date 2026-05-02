// scanner/rust_core/src/lib.rs

// ============================================================================
// MÓDULOS PRINCIPAIS (CORE)
// ============================================================================

pub mod config;
pub mod modules;
pub mod orchestrator;
pub mod types;

// ============================================================================
// MÓDULOS DE SCANNER (REGEX E HYPERSCAN)
// ============================================================================

pub mod regex_engine;
pub mod hyperscan_engine;

// ============================================================================
// MÓDULOS DE PAYLOAD E DICIONÁRIO
// ============================================================================

pub mod payload_dictionary;

// ============================================================================
// MÓDULOS DE EVOLUÇÃO GENÉTICA E CORRELAÇÃO
// ============================================================================

pub mod genetic_engine;
pub mod correlation_graph;

// ============================================================================
// MÓDULOS DE REDE E SCANNER
// ============================================================================

pub mod port_scanner;
pub mod subdomain_scanner;

// ============================================================================
// MÓDULOS DE WAF (DETECÇÃO, COMPORTAMENTO, PAYLOADS, RATE LIMITER)
// ============================================================================

pub mod waf_detector;
pub mod waf_behavior_analysis;
pub mod waf_payloads;
pub mod rate_limiter;

// ============================================================================
// IMPORTAÇÕES PYTHON (PYO3)
// ============================================================================

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::regex_engine::RegexEngine;
use crate::hyperscan_engine::HyperscanEngine;
use crate::payload_dictionary::PayloadDictionary;
use crate::genetic_engine::GeneticEngine;
use crate::correlation_graph::CorrelationGraph;
use crate::port_scanner::{PortScanner, ScannerConfig as PortScannerConfig, PortCategory, PortScanReport};
use crate::subdomain_scanner::{SubdomainScanner, ScannerConfig as SubdomainConfig, SubdomainReport};
use crate::waf_detector::WafDetector;
use crate::waf_behavior_analysis::{WafBehaviorAnalyzer, WafBehaviorReport};
use crate::waf_payloads::PayloadMutator;
use crate::rate_limiter::RateLimiter;

// ============================================================================
// CLASSES PYTHON - REGEX ENGINE
// ============================================================================

#[pyclass]
pub struct PyRegexEngine {
    inner: RegexEngine,
}

#[pymethods]
impl PyRegexEngine {
    #[new]
    fn new() -> Self {
        Self { inner: RegexEngine::new() }
    }
    
    fn detect_stacks(&self, content: &str) -> PyResult<PyObject> {
        let result = self.inner.detect_stacks(content);
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn scan_secrets(&self, content: &str) -> PyResult<PyObject> {
        let result = self.inner.scan_secrets(content);
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn scan_secrets_parallel(&self, content: &str) -> PyResult<PyObject> {
        let result = self.inner.scan_secrets_parallel(content);
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn detect_xss_patterns(&self, content: &str) -> PyResult<PyObject> {
        let result = self.inner.detect_xss_patterns(content);
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn find_enterprise_routes(&self, content: &str) -> PyResult<PyObject> {
        let result = self.inner.find_enterprise_routes(content);
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn scan_js_file_complete(&self, content: &str) -> PyResult<PyObject> {
        let result = self.inner.scan_js_file_complete(content);
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
}

// ============================================================================
// CLASSES PYTHON - HYPERSCAN ENGINE
// ============================================================================

#[pyclass]
pub struct PyHyperscanEngine {
    inner: HyperscanEngine,
}

#[pymethods]
impl PyHyperscanEngine {
    #[new]
    fn new() -> Self {
        Self { inner: HyperscanEngine::new() }
    }
    
    fn scan_js_file_parallel(&self, content: &str) -> PyResult<PyObject> {
        let result = self.inner.scan_js_file_parallel(content);
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn scan_js_file_with_stats(&self, content: &str) -> PyResult<(PyObject, PyObject)> {
        let (result, stats) = self.inner.scan_js_file_with_stats(content);
        let result_json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let stats_json = serde_json::to_string(&stats).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        Python::with_gil(|py| {
            let result_obj = serde_json::from_str::<PyObject>(&result_json).unwrap_or(py.None());
            let stats_obj = serde_json::from_str::<PyObject>(&stats_json).unwrap_or(py.None());
            Ok((result_obj, stats_obj))
        })
    }
}

// ============================================================================
// CLASSES PYTHON - PAYLOAD DICTIONARY
// ============================================================================

#[pyclass]
pub struct PyPayloadDictionary {
    inner: PayloadDictionary,
}

#[pymethods]
impl PyPayloadDictionary {
    #[new]
    fn new() -> Self {
        Self { inner: PayloadDictionary::new() }
    }
    
    fn get_top_payloads_parallel(
        &mut self,
        tech_stack: Vec<String>,
        page_context: Vec<String>,
        waf_type: String,
        limit: usize,
    ) -> PyResult<PyObject> {
        let result = self.inner.get_top_payloads_parallel(&tech_stack, &page_context, &waf_type, limit);
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn update_weight(&mut self, payload_id: &str, success: bool) -> PyResult<bool> {
        Ok(self.inner.update_weight(payload_id, success))
    }
    
    fn get_evasion_techniques(&self, waf_type: &str) -> PyResult<Vec<String>> {
        Ok(self.inner.get_evasion_techniques(waf_type))
    }
    
    fn get_total_count(&self) -> PyResult<usize> {
        Ok(self.inner.get_total_count())
    }
    
    fn generate_report(&self) -> PyResult<PyObject> {
        let result = self.inner.generate_report();
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
}

// ============================================================================
// CLASSES PYTHON - GENETIC ENGINE
// ============================================================================

#[pyclass]
pub struct PyGeneticEngine {
    inner: GeneticEngine,
}

#[pymethods]
impl PyGeneticEngine {
    #[new]
    fn new() -> Self {
        Self { inner: GeneticEngine::default() }
    }
    
    fn initialize_from_payloads(&mut self, payloads: Vec<String>) -> PyResult<()> {
        // Converter strings para Payloads simples
        let payload_objects: Vec<crate::payload_dictionary::Payload> = payloads
            .into_iter()
            .map(|p| {
                use crate::payload_dictionary::{PayloadCategory, DetectionMethod};
                crate::payload_dictionary::Payload {
                    id: "user_payload".to_string(),
                    payload: p,
                    category: PayloadCategory::XssReflected,
                    context: vec!["input".to_string()],
                    stealth_level: 0.5,
                    waf_bypass_prob: 0.5,
                    severity: crate::types::Severity::High,
                    detection: DetectionMethod::Reflection,
                    base_weight: 0.5,
                    success_count: 0,
                    fail_count: 0,
                }
            })
            .collect();
        self.inner.initialize_from_payloads(&payload_objects);
        Ok(())
    }
    
    fn evolve(&mut self, responses_json: &str) -> PyResult<PyObject> {
        let responses: Vec<crate::genetic_engine::ResponseFeedback> = 
            serde_json::from_str(responses_json)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        
        let results = self.inner.evolve(&responses);
        let json = serde_json::to_string(&results).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn get_best_payloads(&self, n: usize) -> PyResult<PyObject> {
        let results = self.inner.get_best_payloads(n);
        let json = serde_json::to_string(&results).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn generate_report(&self) -> PyResult<PyObject> {
        let result = self.inner.generate_report();
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
}

// ============================================================================
// CLASSES PYTHON - CORRELATION GRAPH
// ============================================================================

#[pyclass]
pub struct PyCorrelationGraph {
    inner: CorrelationGraph,
}

#[pymethods]
impl PyCorrelationGraph {
    #[new]
    fn new() -> Self {
        Self { inner: CorrelationGraph::new() }
    }
    
    fn calculate_multiplier(&self, hints: Vec<String>) -> f64 {
        let hint_set: std::collections::HashSet<String> = hints.into_iter().collect();
        self.inner.calculate_multiplier(&hint_set)
    }
    
    fn add_hint(&mut self, hint: &str, metadata: Py<PyDict>) -> PyResult<()> {
        let mut meta = std::collections::HashMap::new();
        Python::with_gil(|py| {
            let dict = metadata.as_ref(py);
            for (key, value) in dict.iter() {
                let k = key.extract::<String>().unwrap_or_default();
                let v = value.extract::<String>().unwrap_or_default();
                meta.insert(k, v);
            }
        });
        self.inner.add_hint(hint, meta);
        Ok(())
    }
}

// ============================================================================
// CLASSES PYTHON - PORT SCANNER
// ============================================================================

#[pyclass]
pub struct PyPortScanner {
    inner: PortScanner,
}

#[pymethods]
impl PyPortScanner {
    #[new]
    fn new(connect_timeout_ms: u64, read_timeout_ms: u64, max_concurrent: usize, enable_service_detection: bool) -> Self {
        let config = PortScannerConfig {
            connect_timeout_ms,
            read_timeout_ms,
            max_concurrent,
            enable_service_detection,
            enable_tls_detection: true,
            retries: 1,
            delay_between_ports_ms: 0,
        };
        Self { inner: PortScanner::new(config) }
    }
    
    fn scan_ports(&self, host: &str, ports: Vec<u16>) -> PyResult<PyObject> {
        let results = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.inner.scan_ports(host, &ports));
        let json = serde_json::to_string(&results).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn scan_web_ports(&self, host: &str) -> PyResult<PyObject> {
        let results = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.inner.scan_ports(host, &crate::port_scanner::WEB_PORTS));
        let json = serde_json::to_string(&results).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn scan_common(&self, host: &str) -> PyResult<PyObject> {
        let results = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.inner.scan_ports(host, &crate::port_scanner::COMMON_PORTS));
        let json = serde_json::to_string(&results).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn generate_report(&self, host: &str, results_json: &str) -> PyResult<PyObject> {
        let results: Vec<crate::port_scanner::PortScanResult> = 
            serde_json::from_str(results_json)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let duration_ms = 0;
        let report = PortScanReport::from_results(host, results, duration_ms);
        let json = serde_json::to_string(&report).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
}

// ============================================================================
// CLASSES PYTHON - SUBDOMAIN SCANNER
// ============================================================================

#[pyclass]
pub struct PySubdomainScanner {
    inner: SubdomainScanner,
}

#[pymethods]
impl PySubdomainScanner {
    #[new]
    fn new(timeout_ms: u64, max_concurrent: usize, enable_http_check: bool, enable_https_check: bool) -> Self {
        let config = SubdomainConfig {
            timeout_ms,
            max_concurrent,
            enable_wildcard_detection: true,
            enable_http_check,
            enable_https_check,
            retries: 1,
        };
        let inner = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(SubdomainScanner::new(config));
        Self { inner }
    }
    
    fn scan_subdomains(&self, domain: &str, wordlist: Option<Vec<String>>) -> PyResult<PyObject> {
        let wordlist_ref: Option<&[&str]> = None; // Usar padrão
        let results = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.inner.scan_subdomains(domain, wordlist_ref));
        let json = serde_json::to_string(&results).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn generate_report(&self, results_json: &str) -> PyResult<PyObject> {
        let results: Vec<crate::subdomain_scanner::SubdomainResult> = 
            serde_json::from_str(results_json)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        let report = self.inner.generate_report(&results);
        let json = serde_json::to_string(&report).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
}

// ============================================================================
// CLASSES PYTHON - WAF DETECTOR
// ============================================================================

#[pyclass]
pub struct PyWafDetector;

#[pymethods]
impl PyWafDetector {
    #[staticmethod]
    fn detect(status_code: u16, headers: Py<PyDict>, body: &str, ja4_hash: Option<&str>) -> PyResult<PyObject> {
        let mut headers_map = std::collections::HashMap::new();
        Python::with_gil(|py| {
            let dict = headers.as_ref(py);
            for (key, value) in dict.iter() {
                let k = key.extract::<String>().unwrap_or_default();
                let v = value.extract::<String>().unwrap_or_default();
                headers_map.insert(k, v);
            }
        });
        let result = WafDetector::detect(status_code, &headers_map, body, ja4_hash);
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
}

// ============================================================================
// CLASSES PYTHON - WAF BEHAVIOR ANALYZER
// ============================================================================

#[pyclass]
pub struct PyWafBehaviorAnalyzer {
    base_url: String,
}

#[pymethods]
impl PyWafBehaviorAnalyzer {
    #[new]
    fn new(base_url: &str) -> Self {
        Self { base_url: base_url.to_string() }
    }
    
    fn analyze(&self, memory_hint_json: Option<&str>) -> PyResult<PyObject> {
        let analyzer = WafBehaviorAnalyzer::new(&self.base_url);
        let hint = if let Some(json) = memory_hint_json {
            Some(serde_json::from_str::<WafBehaviorReport>(json)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?)
        } else {
            None
        };
        let report = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(analyzer.analyze(hint.as_ref()));
        let json = serde_json::to_string(&report).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
}

// ============================================================================
// CLASSES PYTHON - PAYLOAD MUTATOR
// ============================================================================

#[pyclass]
pub struct PyPayloadMutator {
    inner: PayloadMutator,
}

#[pymethods]
impl PyPayloadMutator {
    #[new]
    fn new() -> Self {
        Self { inner: PayloadMutator::new() }
    }
    
    fn mutate(&mut self, base_payload: &str, vendor_hint: &str, count: usize) -> PyResult<PyObject> {
        let results = self.inner.mutate(base_payload, vendor_hint, count);
        let json = serde_json::to_string(&results).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    fn mutate_sqli(&mut self, base_payload: &str, vendor_hint: &str, count: usize) -> PyResult<PyObject> {
        let results = self.inner.mutate_sqli(base_payload, vendor_hint, count);
        let json = serde_json::to_string(&results).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
}

// ============================================================================
// CLASSES PYTHON - RATE LIMITER
// ============================================================================

#[pyclass]
pub struct PyRateLimiter {
    inner: RateLimiter,
}

#[pymethods]
impl PyRateLimiter {
    #[new]
    fn new(min_delay_ms: u64, max_delay_ms: u64, jitter: bool) -> Self {
        Self { inner: RateLimiter::new(min_delay_ms, max_delay_ms, jitter) }
    }
    
    fn wait(&mut self) -> PyResult<()> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(self.inner.wait());
        Ok(())
    }
    
    fn report_block(&mut self, blocked: bool) {
        self.inner.report_block(blocked);
    }
    
    fn global_block_rate(&self) -> f64 {
        self.inner.global_block_rate()
    }
    
    fn need_proxy_rotation(&self) -> bool {
        self.inner.need_proxy_rotation()
    }
    
    fn to_dict(&self) -> PyResult<PyObject> {
        let result = self.inner.to_dict();
        let json = serde_json::to_string(&result).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
        Python::with_gil(|py| Ok(serde_json::from_str::<PyObject>(&json).unwrap_or(py.None())))
    }
    
    #[getter]
    fn current_level_name(&self) -> &'static str {
        self.inner.current_level.name()
    }
    
    #[getter]
    fn current_level_delay_ms(&self) -> u64 {
        self.inner.current_level.delay_ms()
    }
    
    #[getter]
    fn consecutive_blocks(&self) -> u32 {
        self.inner.consecutive_blocks
    }
    
    #[getter]
    fn escalation_count(&self) -> u32 {
        self.inner.escalation_count
    }
}

// ============================================================================
// MÓDULO PRINCIPAL PYTHON
// ============================================================================

#[pymodule]
fn mse_rust_core(_py: Python, m: &PyModule) -> PyResult<()> {
    // Classes principais
    m.add_class::<PyRegexEngine>()?;
    m.add_class::<PyHyperscanEngine>()?;
    m.add_class::<PyPayloadDictionary>()?;
    m.add_class::<PyGeneticEngine>()?;
    m.add_class::<PyCorrelationGraph>()?;
    m.add_class::<PyPortScanner>()?;
    m.add_class::<PySubdomainScanner>()?;
    m.add_class::<PyWafDetector>()?;
    m.add_class::<PyWafBehaviorAnalyzer>()?;
    m.add_class::<PyPayloadMutator>()?;
    m.add_class::<PyRateLimiter>()?;
    
    // Constantes
    m.add("VERSION", env!("CARGO_PKG_VERSION"))?;
    m.add("SECRET_PATTERNS_COUNT", 37)?;
    m.add("STACKS_COUNT", 26)?;
    m.add("ENTERPRISE_ROUTES_COUNT", 22)?;
    m.add("XSS_PATTERNS_COUNT", 7)?;
    
    // Constantes de Port Scanner
    m.add("COMMON_PORTS_COUNT", crate::port_scanner::COMMON_PORTS.len())?;
    m.add("WEB_PORTS_COUNT", crate::port_scanner::WEB_PORTS.len())?;
    m.add("DB_PORTS_COUNT", crate::port_scanner::DB_PORTS.len())?;
    m.add("ADMIN_PORTS_COUNT", crate::port_scanner::ADMIN_PORTS.len())?;
    
    // Constantes de Subdomain Scanner
    m.add("COMMON_SUBDOMAINS_COUNT", crate::subdomain_scanner::COMMON_SUBDOMAINS.len())?;
    
    Ok(())
}