// scanner/rust_core/src/subdomain_scanner.rs
use tokio::net::lookup_host;
use tokio::time::{timeout, Duration};
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use trust_dns_proto::rr::{RecordType, RData};
use trust_dns_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use ahash::AHashMap;

// ============================================================================
// CONSTANTES - WORDLISTS DE SUBDOMÍNIOS
// ============================================================================

pub const COMMON_SUBDOMAINS: [&str; 200] = [
    // Admin/Management (30)
    "admin", "administrator", "dashboard", "panel", "control", "manage", "manager",
    "management", "sysadmin", "itadmin", "webadmin", "serveradmin", "ops", "devops",
    "administration", "master", "root", "super", "superuser", "power", "poweruser",
    "cpanel", "whm", "webmail", "mailadmin", "postmaster", "hostmaster", "webmaster",
    "security", "audit",
    
    // Development (30)
    "dev", "development", "staging", "stage", "test", "testing", "qa", "quality",
    "uat", "preprod", "pre-production", "beta", "alpha", "sandbox", "sandboxed",
    "demo", "dev1", "dev2", "dev3", "test1", "test2", "test3", "stg", "stage1",
    "stage2", "stage3", "int", "integration", "ci", "cd",
    
    // API/Services (25)
    "api", "apis", "rest", "restapi", "graphql", "graph", "query", "data", "dataservice",
    "service", "services", "microservice", "svc", "svcs", "backend", "back", "internal",
    "internal-api", "private", "private-api", "core", "coreapi", "platform", "platform-api",
    "gateway",
    
    // Infrastructure (30)
    "app", "apps", "application", "web", "www", "ww2", "ww3", "web1", "web2", "web3",
    "app1", "app2", "app3", "server", "server1", "server2", "server3", "node", "node1",
    "node2", "node3", "cluster", "cluster1", "cluster2", "lb", "loadbalancer", "cache",
    "cdn", "static", "assets",
    
    // Cloud Specific (25)
    "aws", "amazon", "ec2", "s3", "rds", "lambda", "cloudfront", "elb", "azure",
    "gcp", "google", "cloud", "digitalocean", "do", "linode", "vultr", "heroku",
    "netlify", "vercel", "cloudflare", "cf", "fastly", "akamai", "incapsula", "imperva",
    
    // Security/Monitoring (20)
    "monitor", "monitoring", "health", "status", "stats", "metrics", "log", "logs",
    "audit", "audits", "security", "sec", "waf", "firewall", "ids", "ips", "soc",
    "siem", "splunk", "elk",
    
    // Database/Cache (15)
    "db", "database", "mysql", "postgres", "redis", "mongodb", "elastic", "es",
    "cassandra", "couchdb", "mariadb", "sqlserver", "mssql", "oracle", "dynamodb",
    
    // Versioning (10)
    "v1", "v2", "v3", "v4", "version1", "version2", "version3", "api1", "api2", "api3",
    
    // Misc (15)
    "proxy", "redirect", "cdn", "media", "download", "upload", "files", "ftp", "sftp",
    "ssh", "vpn", "remote", "bastion", "jump", "jumpbox",
];

pub const COMMON_TLDS: [&str; 100] = [
    "com", "org", "net", "io", "co", "me", "us", "uk", "de", "fr", "es", "it", "pt",
    "nl", "be", "ch", "at", "au", "ca", "jp", "cn", "kr", "in", "br", "ru", "pl",
    "se", "no", "fi", "dk", "cz", "hu", "ro", "bg", "hr", "sk", "si", "lt", "lv",
    "ee", "ie", "nz", "za", "mx", "ar", "cl", "pe", "uy", "ec", "ve", "py", "bo",
    "cr", "gt", "hn", "ni", "sv", "pa", "do", "cu", "pr", "tt", "jm", "bz", "gy",
    "sr", "ai", "ag", "bb", "dm", "gd", "kn", "lc", "vc", "bs", "ky", "tc", "vg",
    "vi", "xyz", "tech", "site", "cloud", "digital", "agency", "studio", "design",
    "solutions", "systems", "media", "group", "consulting", "services", "pro", "biz",
];

// ============================================================================
// RESULTADOS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub full_domain: String,
    pub ips: Vec<String>,
    pub cname: Option<String>,
    pub txt_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub status: SubdomainStatus,
    pub response_time_ms: u64,
    pub source: DiscoverySource,
    pub http_status: Option<u16>,
    pub https_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SubdomainStatus {
    Active,
    Inactive,
    NoRecord,
    Timeout,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DiscoverySource {
    Wordlist,
    CertificateTransparency,
    DnsBrute,
    DnsZoneTransfer,
    GoogleDorking,
    Subfinder,
    Amass,
    SecurityTrails,
    CrtSh,
    WaybackMachine,
}

// ============================================================================
// TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

// ============================================================================
// SUBDOMAIN SCANNER PRINCIPAL
// ============================================================================

pub struct SubdomainScanner {
    resolver: Option<TokioAsyncResolver>,
    timeout: Duration,
    max_concurrent: usize,
    enable_wildcard_detection: bool,
    enable_http_check: bool,
    enable_https_check: bool,
    retries: u32,
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub timeout_ms: u64,
    pub max_concurrent: usize,
    pub enable_wildcard_detection: bool,
    pub enable_http_check: bool,
    pub enable_https_check: bool,
    pub retries: u32,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            max_concurrent: 50,
            enable_wildcard_detection: true,
            enable_http_check: true,
            enable_https_check: true,
            retries: 1,
        }
    }
}

impl SubdomainScanner {
    pub async fn new(config: ScannerConfig) -> Self {
        let resolver = Self::create_resolver().await;
        
        Self {
            resolver,
            timeout: Duration::from_millis(config.timeout_ms),
            max_concurrent: config.max_concurrent,
            enable_wildcard_detection: config.enable_wildcard_detection,
            enable_http_check: config.enable_http_check,
            enable_https_check: config.enable_https_check,
            retries: config.retries,
        }
    }
    
    async fn create_resolver() -> Option<TokioAsyncResolver> {
        let resolver_config = ResolverConfig::cloudflare();
        let resolver_opts = ResolverOpts::default();
        
        match TokioAsyncResolver::tokio(resolver_config, resolver_opts) {
            Ok(resolver) => Some(resolver),
            Err(e) => {
                eprintln!("Failed to create DNS resolver: {}", e);
                None
            }
        }
    }
    
    // ========================================================================
    // SCAN PRINCIPAL
    // ========================================================================
    
    pub async fn scan_subdomains(
        &self,
        domain: &str,
        wordlist: Option<&[&str]>,
    ) -> Vec<SubdomainResult> {
        let wordlist = wordlist.unwrap_or(&COMMON_SUBDOMAINS);
        let results = Arc::new(DashMap::new());
        
        // Primeiro, detectar wildcard DNS
        let wildcard_ip = if self.enable_wildcard_detection {
            self.detect_wildcard_dns(domain).await
        } else {
            None
        };
        
        // Scan em paralelo
        let chunks: Vec<&[&str]> = wordlist.chunks(self.max_concurrent).collect();
        
        for chunk in chunks {
            let mut tasks = Vec::new();
            
            for &sub in chunk {
                let domain = domain.to_string();
                let sub = sub.to_string();
                let results = Arc::clone(&results);
                let scanner = self.clone_for_async();
                let wildcard_ip = wildcard_ip.clone();
                
                tasks.push(tokio::spawn(async move {
                    let full_domain = format!("{}.{}", sub, domain);
                    let result = scanner.resolve_subdomain(&full_domain, wildcard_ip.as_deref()).await;
                    if let Some(r) = result {
                        results.insert(full_domain, r);
                    }
                }));
            }
            
            for task in tasks {
                let _ = task.await;
            }
        }
        
        let mut results_vec: Vec<SubdomainResult> = results
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        
        results_vec.sort_by_key(|r| r.subdomain.clone());
        
        // Verificar HTTP/HTTPS
        if self.enable_http_check || self.enable_https_check {
            self.check_http_services(&mut results_vec).await;
        }
        
        results_vec
    }
    
    // ========================================================================
    // SCAN COM RATE LIMITING
    // ========================================================================
    
    pub async fn scan_subdomains_with_rate_limit(
        &self,
        domain: &str,
        wordlist: Option<&[&str]>,
        requests_per_second: usize,
    ) -> Vec<SubdomainResult> {
        let wordlist = wordlist.unwrap_or(&COMMON_SUBDOMAINS);
        let results = Arc::new(DashMap::new());
        let wildcard_ip = if self.enable_wildcard_detection {
            self.detect_wildcard_dns(domain).await
        } else {
            None
        };
        
        let delay = Duration::from_micros(1_000_000 / requests_per_second as u64);
        let mut tasks = FuturesUnordered::new();
        
        for &sub in wordlist {
            let domain = domain.to_string();
            let sub = sub.to_string();
            let results = Arc::clone(&results);
            let scanner = self.clone_for_async();
            let wildcard_ip = wildcard_ip.clone();
            
            tasks.push(tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let full_domain = format!("{}.{}", sub, domain);
                let result = scanner.resolve_subdomain(&full_domain, wildcard_ip.as_deref()).await;
                if let Some(r) = result {
                    results.insert(full_domain, r);
                }
            }));
        }
        
        while let Some(_) = tasks.next().await {}
        
        let mut results_vec: Vec<SubdomainResult> = results
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        
        results_vec.sort_by_key(|r| r.subdomain.clone());
        
        if self.enable_http_check || self.enable_https_check {
            self.check_http_services(&mut results_vec).await;
        }
        
        results_vec
    }
    
    // ========================================================================
    // SCAN COM RESOLUÇÃO RECURSIVA
    // ========================================================================
    
    pub async fn scan_recursive(
        &self,
        domain: &str,
        max_depth: usize,
        wordlist: Option<&[&str]>,
    ) -> Vec<SubdomainResult> {
        let wordlist = wordlist.unwrap_or(&COMMON_SUBDOMAINS);
        let mut all_results = Vec::new();
        let mut discovered = HashSet::new();
        let mut queue = VecDeque::new();
        
        queue.push_back(domain.to_string());
        discovered.insert(domain.to_string());
        
        for _ in 0..max_depth {
            if queue.is_empty() {
                break;
            }
            
            let current_domain = queue.pop_front().unwrap();
            let subdomains = self.scan_subdomains(&current_domain, Some(wordlist)).await;
            
            for sub in subdomains {
                if sub.status == SubdomainStatus::Active && !discovered.contains(&sub.full_domain) {
                    discovered.insert(sub.full_domain.clone());
                    queue.push_back(sub.full_domain.clone());
                    all_results.push(sub);
                }
            }
        }
        
        all_results
    }
    
    // ========================================================================
    // DETECÇÃO DE WILDCARD DNS
    // ========================================================================
    
    async fn detect_wildcard_dns(&self, domain: &str) -> Option<String> {
        use rand::Rng;
        
        let random_sub = format!("wildcard-test-{}.{}", rand::thread_rng().gen::<u32>(), domain);
        
        if let Some(ips) = self.resolve_a_records(&random_sub).await {
            if !ips.is_empty() {
                // Verificar se outro subdomínio aleatório retorna o mesmo IP
                let random_sub2 = format!("wildcard-test-{}.{}", rand::thread_rng().gen::<u32>(), domain);
                if let Some(ips2) = self.resolve_a_records(&random_sub2).await {
                    if ips == ips2 && !ips.is_empty() {
                        return Some(ips[0].clone());
                    }
                }
            }
        }
        
        None
    }
    
    // ========================================================================
    // RESOLUÇÃO DE UM SUBDOMÍNIO
    // ========================================================================
    
    async fn resolve_subdomain(
        &self,
        full_domain: &str,
        wildcard_ip: Option<&str>,
    ) -> Option<SubdomainResult> {
        let start = Instant::now();
        let subdomain = full_domain.split('.').next().unwrap_or(full_domain).to_string();
        
        // Resolver A records
        let ips = self.resolve_a_records(full_domain).await;
        
        // Verificar wildcard
        if let Some(wildcard) = wildcard_ip {
            if let Some(ref ips_vec) = ips {
                if ips_vec.contains(&wildcard.to_string()) {
                    return None;
                }
            }
        }
        
        // Se não encontrou IP, tentar CNAME
        let cname = if ips.is_none() {
            self.resolve_cname(full_domain).await
        } else {
            None
        };
        
        let status = if ips.is_some() || cname.is_some() {
            SubdomainStatus::Active
        } else {
            SubdomainStatus::Inactive
        };
        
        if status == SubdomainStatus::Inactive {
            return None;
        }
        
        // Resolver registros adicionais
        let txt_records = self.resolve_txt_records(full_domain).await;
        let mx_records = self.resolve_mx_records(full_domain).await;
        let ns_records = self.resolve_ns_records(full_domain).await;
        
        Some(SubdomainResult {
            subdomain,
            full_domain: full_domain.to_string(),
            ips: ips.unwrap_or_default(),
            cname,
            txt_records,
            mx_records,
            ns_records,
            status,
            response_time_ms: start.elapsed().as_millis() as u64,
            source: DiscoverySource::Wordlist,
            http_status: None,
            https_available: false,
        })
    }
    
    // ========================================================================
    // RESOLUÇÃO DE REGISTROS DNS
    // ========================================================================
    
    async fn resolve_a_records(&self, domain: &str) -> Option<Vec<String>> {
        if let Some(resolver) = &self.resolver {
            for attempt in 0..=self.retries {
                match timeout(self.timeout, resolver.lookup_ip(domain)).await {
                    Ok(Ok(lookup)) => {
                        let ips: Vec<String> = lookup.iter()
                            .map(|ip| ip.to_string())
                            .collect();
                        if !ips.is_empty() {
                            return Some(ips);
                        }
                    }
                    _ => {
                        if attempt == self.retries {
                            return None;
                        }
                    }
                }
            }
        }
        None
    }
    
    async fn resolve_cname(&self, domain: &str) -> Option<String> {
        if let Some(resolver) = &self.resolver {
            for attempt in 0..=self.retries {
                match timeout(self.timeout, resolver.lookup(domain, RecordType::CNAME)).await {
                    Ok(Ok(lookup)) => {
                        for record in lookup.iter() {
                            if let RData::CNAME(cname) = record {
                                return Some(cname.to_string());
                            }
                        }
                    }
                    _ => {
                        if attempt == self.retries {
                            return None;
                        }
                    }
                }
            }
        }
        None
    }
    
    async fn resolve_txt_records(&self, domain: &str) -> Vec<String> {
        let mut records = Vec::new();
        if let Some(resolver) = &self.resolver {
            if let Ok(Ok(lookup)) = timeout(self.timeout, resolver.lookup(domain, RecordType::TXT)).await {
                for record in lookup.iter() {
                    if let RData::TXT(txt) = record {
                        records.push(txt.to_string());
                    }
                }
            }
        }
        records
    }
    
    async fn resolve_mx_records(&self, domain: &str) -> Vec<String> {
        let mut records = Vec::new();
        if let Some(resolver) = &self.resolver {
            if let Ok(Ok(lookup)) = timeout(self.timeout, resolver.lookup(domain, RecordType::MX)).await {
                for record in lookup.iter() {
                    if let RData::MX(mx) = record {
                        records.push(format!("{} (priority: {})", mx.exchange(), mx.preference()));
                    }
                }
            }
        }
        records.sort();
        records
    }
    
    async fn resolve_ns_records(&self, domain: &str) -> Vec<String> {
        let mut records = Vec::new();
        if let Some(resolver) = &self.resolver {
            if let Ok(Ok(lookup)) = timeout(self.timeout, resolver.lookup(domain, RecordType::NS)).await {
                for record in lookup.iter() {
                    if let RData::NS(ns) = record {
                        records.push(ns.to_string());
                    }
                }
            }
        }
        records
    }
    
    // ========================================================================
    // VERIFICAÇÃO HTTP/HTTPS
    // ========================================================================
    
    async fn check_http_services(&self, results: &mut [SubdomainResult]) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        
        for result in results.iter_mut() {
            if result.status == SubdomainStatus::Active {
                // HTTP check
                if self.enable_http_check {
                    let http_url = format!("http://{}", result.full_domain);
                    if let Ok(resp) = client.get(&http_url).send().await {
                        result.http_status = Some(resp.status().as_u16());
                    }
                }
                
                // HTTPS check
                if self.enable_https_check {
                    let https_url = format!("https://{}", result.full_domain);
                    if let Ok(resp) = client.get(&https_url).send().await {
                        result.https_available = resp.status().is_success() || resp.status().as_u16() == 401;
                        if result.http_status.is_none() {
                            result.http_status = Some(resp.status().as_u16());
                        }
                    }
                }
            }
        }
    }
    
    // ========================================================================
    // SCAN DE TRANSFERÊNCIA DE ZONA
    // ========================================================================
    
    pub async fn scan_zone_transfer(&self, domain: &str, ns_server: &str) -> Vec<DnsRecord> {
        let mut records = Vec::new();
        
        // Tentar AXFR (zone transfer)
        let query = format!("AXFR {}", domain);
        // Implementação simplificada - em produção usar biblioteca DNS completa
        
        records
    }
    
    // ========================================================================
    // RELATÓRIO
    // ========================================================================
    
    pub fn generate_report(&self, results: &[SubdomainResult]) -> SubdomainReport {
        let active: Vec<SubdomainResult> = results
            .iter()
            .filter(|r| r.status == SubdomainStatus::Active)
            .cloned()
            .collect();
        
        let with_http: Vec<&SubdomainResult> = active
            .iter()
            .filter(|r| r.http_status.is_some())
            .collect();
        
        let with_https: Vec<&SubdomainResult> = active
            .iter()
            .filter(|r| r.https_available)
            .collect();
        
        let by_source: HashMap<DiscoverySource, usize> = results
            .iter()
            .fold(HashMap::new(), |mut acc, r| {
                *acc.entry(r.source.clone()).or_insert(0) += 1;
                acc
            });
        
        SubdomainReport {
            total_scanned: results.len(),
            active_subdomains: active.len(),
            with_http: with_http.len(),
            with_https: with_https.len(),
            by_source,
            active_list: active,
            unique_ips: active
                .iter()
                .flat_map(|r| r.ips.clone())
                .collect::<HashSet<_>>()
                .len(),
        }
    }
    
    fn clone_for_async(&self) -> Self {
        Self {
            resolver: None,
            timeout: self.timeout,
            max_concurrent: self.max_concurrent,
            enable_wildcard_detection: self.enable_wildcard_detection,
            enable_http_check: self.enable_http_check,
            enable_https_check: self.enable_https_check,
            retries: self.retries,
        }
    }
}

// ========================================================================
// RELATÓRIO
// ========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainReport {
    pub total_scanned: usize,
    pub active_subdomains: usize,
    pub with_http: usize,
    pub with_https: usize,
    pub by_source: HashMap<DiscoverySource, usize>,
    pub active_list: Vec<SubdomainResult>,
    pub unique_ips: usize,
}

impl SubdomainReport {
    pub fn has_admin_subdomains(&self) -> bool {
        self.active_list.iter().any(|r| {
            r.subdomain.contains("admin") || 
            r.subdomain.contains("panel") || 
            r.subdomain.contains("dashboard") ||
            r.subdomain.contains("control")
        })
    }
    
    pub fn has_dev_subdomains(&self) -> bool {
        self.active_list.iter().any(|r| {
            r.subdomain.contains("dev") || 
            r.subdomain.contains("staging") || 
            r.subdomain.contains("test") ||
            r.subdomain.contains("qa")
        })
    }
    
    pub fn has_api_subdomains(&self) -> bool {
        self.active_list.iter().any(|r| {
            r.subdomain.contains("api") || 
            r.subdomain.contains("graphql") || 
            r.subdomain.contains("rest")
        })
    }
    
    pub fn risk_score(&self) -> f64 {
        let mut score = 0.0;
        
        score += (self.active_subdomains as f64) * 0.1;
        
        if self.has_admin_subdomains() {
            score += 2.0;
        }
        if self.has_dev_subdomains() {
            score += 1.0;
        }
        if self.has_api_subdomains() {
            score += 1.5;
        }
        
        score.min(10.0)
    }
}

// ========================================================================
// TESTES
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_subdomain_scan() {
        let config = ScannerConfig::default();
        let scanner = SubdomainScanner::new(config).await;
        
        let results = scanner.scan_subdomains("example.com", Some(&["www", "api", "admin"])).await;
        
        assert!(!results.is_empty());
    }
    
    #[tokio::test]
    async fn test_wildcard_detection() {
        let config = ScannerConfig::default();
        let scanner = SubdomainScanner::new(config).await;
        
        let wildcard = scanner.detect_wildcard_dns("example.com").await;
        // Pode ser Some ou None dependendo do domínio
    }
}