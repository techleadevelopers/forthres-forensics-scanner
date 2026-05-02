// scanner/rust_core/src/hyperscan_engine.rs
use crate::regex_engine::{
    RegexEngine, SecretMatch, XSSFinding, EnterpriseRouteMatch, JSFileScanResult
};
use rayon::prelude::*;
use std::sync::Arc;
use std::time::Instant;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub chunks_processed: usize,
    pub total_bytes_scanned: usize,
    pub secrets_found: usize,
    pub xss_found: usize,
    pub routes_found: usize,
    pub scan_duration_ms: u64,
    pub average_chunk_time_ms: f64,
}

pub struct HyperscanEngine {
    regex_engine: Arc<RegexEngine>,
    chunk_size: usize,
    max_parallel_chunks: usize,
}

impl HyperscanEngine {
    pub fn new() -> Self {
        Self {
            regex_engine: Arc::new(RegexEngine::new()),
            chunk_size: 1024 * 1024, // 1MB chunks
            max_parallel_chunks: num_cpus::get(),
        }
    }
    
    pub fn with_config(chunk_size: usize, max_parallel: usize) -> Self {
        Self {
            regex_engine: Arc::new(RegexEngine::new()),
            chunk_size,
            max_parallel_chunks: max_parallel,
        }
    }
    
    pub fn scan_js_file_parallel(&self, content: &str) -> JSFileScanResult {
        let start = Instant::now();
        let engine = Arc::clone(&self.regex_engine);
        
        // Divide o conteúdo em chunks para processamento paralelo
        let chunks: Vec<&str> = content
            .as_bytes()
            .chunks(self.chunk_size)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
            .collect();
        
        // Processa chunks em paralelo
        let chunk_results: Vec<ChunkScanResult> = chunks
            .par_iter()
            .enumerate()
            .map(|(idx, chunk)| {
                let chunk_start = Instant::now();
                let secrets = engine.scan_secrets(chunk);
                let xss_findings = engine.detect_xss_patterns(chunk);
                let enterprise_routes = engine.find_enterprise_routes(chunk);
                
                // Ajusta localizações com offset do chunk
                let offset = idx * self.chunk_size;
                let secrets_adjusted: Vec<SecretMatch> = secrets.into_iter()
                    .map(|mut s| { s.location += offset; s })
                    .collect();
                let xss_adjusted: Vec<XSSFinding> = xss_findings.into_iter()
                    .map(|mut x| { x.location += offset; x })
                    .collect();
                let routes_adjusted: Vec<EnterpriseRouteMatch> = enterprise_routes.into_iter()
                    .map(|mut r| { r.found_at += offset; r })
                    .collect();
                
                ChunkScanResult {
                    chunk_index: idx,
                    secrets: secrets_adjusted,
                    xss_findings: xss_adjusted,
                    enterprise_routes: routes_adjusted,
                    scan_time_ms: chunk_start.elapsed().as_millis() as u64,
                    chunk_size_bytes: chunk.len(),
                }
            })
            .collect();
        
        // Consolida resultados
        let mut all_secrets = Vec::new();
        let mut all_xss = Vec::new();
        let mut all_routes = Vec::new();
        let mut total_bytes = 0;
        
        for result in chunk_results {
            all_secrets.extend(result.secrets);
            all_xss.extend(result.xss_findings);
            all_routes.extend(result.enterprise_routes);
            total_bytes += result.chunk_size_bytes;
        }
        
        // Remove duplicatas
        all_secrets = Self::dedupe_secrets(all_secrets);
        all_routes = Self::dedupe_routes(all_routes);
        
        JSFileScanResult {
            secrets: all_secrets,
            xss_findings: all_xss,
            enterprise_routes: all_routes,
            total_size: total_bytes,
            scan_time_ms: start.elapsed().as_millis() as u64,
        }
    }
    
    pub fn scan_js_file_with_stats(&self, content: &str) -> (JSFileScanResult, ScanStatistics) {
        let start = Instant::now();
        let result = self.scan_js_file_parallel(content);
        let duration = start.elapsed();
        
        let stats = ScanStatistics {
            chunks_processed: (content.len() + self.chunk_size - 1) / self.chunk_size,
            total_bytes_scanned: content.len(),
            secrets_found: result.secrets.len(),
            xss_found: result.xss_findings.len(),
            routes_found: result.enterprise_routes.len(),
            scan_duration_ms: duration.as_millis() as u64,
            average_chunk_time_ms: duration.as_millis() as f64 / 
                ((content.len() + self.chunk_size - 1) / self.chunk_size) as f64,
        };
        
        (result, stats)
    }
    
    pub fn scan_multiple_files_parallel(&self, files: &[(&str, &str)]) -> Vec<JSFileScanResult> {
        files.par_iter()
            .map(|(name, content)| {
                let result = self.scan_js_file_parallel(content);
                tracing::debug!("Scanned {}: {} secrets found", name, result.secrets.len());
                result
            })
            .collect()
    }
    
    pub fn stream_scan(&self, content: &str, callback: &mut dyn FnMut(&ChunkScanResult)) {
        let chunks: Vec<&str> = content
            .as_bytes()
            .chunks(self.chunk_size)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
            .collect();
        
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let secrets = self.regex_engine.scan_secrets(chunk);
            let xss_findings = self.regex_engine.detect_xss_patterns(chunk);
            let enterprise_routes = self.regex_engine.find_enterprise_routes(chunk);
            
            let offset = idx * self.chunk_size;
            let secrets_adjusted: Vec<SecretMatch> = secrets.into_iter()
                .map(|mut s| { s.location += offset; s })
                .collect();
            let xss_adjusted: Vec<XSSFinding> = xss_findings.into_iter()
                .map(|mut x| { x.location += offset; x })
                .collect();
            let routes_adjusted: Vec<EnterpriseRouteMatch> = enterprise_routes.into_iter()
                .map(|mut r| { r.found_at += offset; r })
                .collect();
            
            callback(&ChunkScanResult {
                chunk_index: idx,
                secrets: secrets_adjusted,
                xss_findings: xss_adjusted,
                enterprise_routes: routes_adjusted,
                scan_time_ms: 0,
                chunk_size_bytes: chunk.len(),
            });
        }
    }
    
    fn dedupe_secrets(mut secrets: Vec<SecretMatch>) -> Vec<SecretMatch> {
        secrets.sort_by(|a, b| a.location.cmp(&b.location));
        secrets.dedup_by(|a, b| a.pattern_name == b.pattern_name && a.value == b.value);
        secrets
    }
    
    fn dedupe_routes(mut routes: Vec<EnterpriseRouteMatch>) -> Vec<EnterpriseRouteMatch> {
        routes.sort_by(|a, b| a.found_at.cmp(&b.found_at));
        routes.dedup_by(|a, b| a.route.path == b.route.path);
        routes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkScanResult {
    pub chunk_index: usize,
    pub secrets: Vec<SecretMatch>,
    pub xss_findings: Vec<XSSFinding>,
    pub enterprise_routes: Vec<EnterpriseRouteMatch>,
    pub scan_time_ms: u64,
    pub chunk_size_bytes: usize,
}

impl Default for HyperscanEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scan_large_js_file() {
        let engine = HyperscanEngine::new();
        let content = "var AWS_KEY = 'AKIA1234567890ABCDEF'; <script>alert('xss')</script>";
        let result = engine.scan_js_file_parallel(content);
        assert!(!result.secrets.is_empty());
        assert!(!result.xss_findings.is_empty());
    }
    
    #[test]
    fn test_stream_scan() {
        let engine = HyperscanEngine::new();
        let content = "x".repeat(5 * 1024 * 1024); // 5MB
        let mut call_count = 0;
        engine.stream_scan(&content, &mut |_| {
            call_count += 1;
        });
        assert!(call_count > 0);
    }
}