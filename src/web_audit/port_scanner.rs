// scanner/rust_core/src/port_scanner.rs
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration, Instant};
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use ahash::AHashMap;

// ============================================================================
// CONSTANTES
// ============================================================================

pub const COMMON_PORTS: [u16; 50] = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 179, 199, 443, 445,
    465, 514, 515, 587, 993, 995, 1080, 1194, 1433, 1723, 1883, 3306, 3389,
    5432, 5900, 6379, 6667, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 11211,
    15672, 27017, 27018, 50000, 50001, 50002, 50003, 50004, 50005,
];

pub const WEB_PORTS: [u16; 20] = [
    80, 443, 8080, 8443, 8000, 8888, 8081, 8082, 3000, 5000, 7000, 9000,
    10000, 10443, 12443, 1337, 30000, 30001, 30002, 30003,
];

pub const DB_PORTS: [u16; 15] = [
    1433, 3306, 5432, 6379, 27017, 28015, 5984, 9200, 9300, 11211, 5000,
    9160, 27018, 27019, 27020,
];

pub const ADMIN_PORTS: [u16; 10] = [
    22, 23, 3389, 5900, 5901, 5902, 5800, 5801, 5802, 2222,
];

pub const MISC_PORTS: [u16; 15] = [
    25, 53, 110, 111, 135, 139, 143, 179, 199, 445, 465, 514, 515, 587, 993,
];

// ============================================================================
// RESULTADOS DO SCAN
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub port: u16,
    pub protocol: Protocol,
    pub status: PortStatus,
    pub service_name: String,
    pub service_version: Option<String>,
    pub banner: Option<String>,
    pub response_time_ms: u64,
    pub tls: Option<TlsInfo>,
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: String,
    pub cipher_suite: String,
    pub certificate_issuer: String,
    pub certificate_subject: String,
    pub certificate_expiry: Option<u64>,
    pub sni_supported: bool,
}

// ============================================================================
// SERVICE DETECTION
// ============================================================================

pub struct ServiceDetector {
    probes: HashMap<u16, ServiceProbe>,
}

#[derive(Debug, Clone)]
pub struct ServiceProbe {
    pub port: u16,
    pub name: String,
    pub probe_string: Vec<u8>,
    pub response_patterns: Vec<&'static str>,
    pub default_version_pattern: Option<regex::Regex>,
}

impl ServiceDetector {
    pub fn new() -> Self {
        let mut probes = HashMap::new();
        
        // HTTP/HTTPS
        probes.insert(80, ServiceProbe {
            port: 80,
            name: "http".to_string(),
            probe_string: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec(),
            response_patterns: vec!["HTTP/", "html", "DOCTYPE", "Server:"],
            default_version_pattern: Some(regex::Regex::new(r"Server:\s*([^\r\n]+)").unwrap()),
        });
        
        probes.insert(443, ServiceProbe {
            port: 443,
            name: "https".to_string(),
            probe_string: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec(),
            response_patterns: vec!["HTTP/", "html", "DOCTYPE", "Server:"],
            default_version_pattern: Some(regex::Regex::new(r"Server:\s*([^\r\n]+)").unwrap()),
        });
        
        probes.insert(8080, ServiceProbe {
            port: 8080,
            name: "http-proxy".to_string(),
            probe_string: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n".to_vec(),
            response_patterns: vec!["HTTP/", "html", "Proxy"],
            default_version_pattern: None,
        });
        
        // SSH
        probes.insert(22, ServiceProbe {
            port: 22,
            name: "ssh".to_string(),
            probe_string: b"\n".to_vec(),
            response_patterns: vec!["SSH-", "OpenSSH", "Protocol"],
            default_version_pattern: Some(regex::Regex::new(r"SSH-([\d\.]+)-([^\r\n]+)").unwrap()),
        });
        
        // FTP
        probes.insert(21, ServiceProbe {
            port: 21,
            name: "ftp".to_string(),
            probe_string: b"\n".to_vec(),
            response_patterns: vec!["220", "FTP", "vsFTPd", "ProFTPD", "FileZilla"],
            default_version_pattern: Some(regex::Regex::new(r"220[^\d]*([\d\.]+)").unwrap()),
        });
        
        // MySQL
        probes.insert(3306, ServiceProbe {
            port: 3306,
            name: "mysql".to_string(),
            probe_string: b"\x00\x00\x00\x00\x01".to_vec(),
            response_patterns: vec!["mysql", "MariaDB", "5.", "8.", "10."],
            default_version_pattern: Some(regex::Regex::new(r"(\d+\.\d+\.\d+)").unwrap()),
        });
        
        // PostgreSQL
        probes.insert(5432, ServiceProbe {
            port: 5432,
            name: "postgresql".to_string(),
            probe_string: b"\x00\x00\x00\x08\x04\xd2\x16\x2f".to_vec(),
            response_patterns: vec!["PostgreSQL", "Z", "database", "server"],
            default_version_pattern: Some(regex::Regex::new(r"PostgreSQL[\s\.]+(\d+\.\d+)").unwrap()),
        });
        
        // Redis
        probes.insert(6379, ServiceProbe {
            port: 6379,
            name: "redis".to_string(),
            probe_string: b"*1\r\n$4\r\nPING\r\n".to_vec(),
            response_patterns: vec!["+PONG", "redis_version", "$"],
            default_version_pattern: Some(regex::Regex::new(r"redis_version:(\d+\.\d+\.\d+)").unwrap()),
        });
        
        // MongoDB
        probes.insert(27017, ServiceProbe {
            port: 27017,
            name: "mongodb".to_string(),
            probe_string: b"\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00".to_vec(),
            response_patterns: vec!["MongoDB", "wire protocol", "ismaster"],
            default_version_pattern: Some(regex::Regex::new(r"(\d+\.\d+\.\d+)").unwrap()),
        });
        
        // Elasticsearch
        probes.insert(9200, ServiceProbe {
            port: 9200,
            name: "elasticsearch".to_string(),
            probe_string: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
            response_patterns: vec!["elasticsearch", "cluster_name", "version"],
            default_version_pattern: Some(regex::Regex::new(r"\"number\"\s*:\s*\"(\d+\.\d+\.\d+)\"").unwrap()),
        });
        
        // Memcached
        probes.insert(11211, ServiceProbe {
            port: 11211,
            name: "memcached".to_string(),
            probe_string: b"stats\r\n".to_vec(),
            response_patterns: vec!["STAT", "version", "pid", "uptime"],
            default_version_pattern: Some(regex::Regex::new(r"STAT version ([\d\.]+)").unwrap()),
        });
        
        // RabbitMQ
        probes.insert(15672, ServiceProbe {
            port: 15672,
            name: "rabbitmq".to_string(),
            probe_string: b"GET /api/overview HTTP/1.0\r\n\r\n".to_vec(),
            response_patterns: vec!["rabbitmq_version", "cluster_name", "erlang_version"],
            default_version_pattern: Some(regex::Regex::new(r"rabbitmq_version\"\s*:\s*\"([^\"]+)\"").unwrap()),
        });
        
        // RDP
        probes.insert(3389, ServiceProbe {
            port: 3389,
            name: "rdp".to_string(),
            probe_string: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00".to_vec(),
            response_patterns: vec!["RDP", "Microsoft", "Terminal Server"],
            default_version_pattern: Some(regex::Regex::new(r"Windows\s+Server\s+(\d{4})").unwrap()),
        });
        
        // VNC
        probes.insert(5900, ServiceProbe {
            port: 5900,
            name: "vnc".to_string(),
            probe_string: b"RFB 003.008\n".to_vec(),
            response_patterns: vec!["RFB", "VNC", "tightvnc", "realvnc"],
            default_version_pattern: Some(regex::Regex::new(r"RFB\s+(\d+\.\d+)").unwrap()),
        });
        
        // SMTP
        probes.insert(25, ServiceProbe {
            port: 25,
            name: "smtp".to_string(),
            probe_string: b"HELO localhost\r\n".to_vec(),
            response_patterns: vec!["220", "SMTP", "Postfix", "Sendmail", "Exchange"],
            default_version_pattern: Some(regex::Regex::new(r"(\d+\.\d+\.\d+)[^\r\n]*$").unwrap()),
        });
        
        // DNS
        probes.insert(53, ServiceProbe {
            port: 53,
            name: "dns".to_string(),
            probe_string: b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01".to_vec(),
            response_patterns: vec!["\x00\x01", "domain", "DNS"],
            default_version_pattern: None,
        });
        
        // NetBIOS
        probes.insert(139, ServiceProbe {
            port: 139,
            name: "netbios-ssn".to_string(),
            probe_string: b"\x81\x00\x00\x44\x20\x43\x4b\x46\x44\x45\x4e\x45\x43\x46\x44\x45".to_vec(),
            response_patterns: vec!["SMB", "NETBIOS", "Windows"],
            default_version_pattern: None,
        });
        
        // SMB
        probes.insert(445, ServiceProbe {
            port: 445,
            name: "smb".to_string(),
            probe_string: b"\x00\x00\x00\x00\x00\x18\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            response_patterns: vec!["SMB", "NT LM", "Windows"],
            default_version_pattern: Some(regex::Regex::new(r"SMB\s+([\d\.]+)").unwrap()),
        });
        
        Self { probes }
    }
    
    pub fn detect(&self, port: u16, response: &[u8]) -> (String, Option<String>) {
        if let Some(probe) = self.probes.get(&port) {
            let response_str = String::from_utf8_lossy(response);
            
            for pattern in &probe.response_patterns {
                if response_str.contains(pattern) {
                    let version = if let Some(regex) = &probe.default_version_pattern {
                        regex.captures(&response_str)
                            .and_then(|cap| cap.get(1))
                            .map(|m| m.as_str().to_string())
                    } else {
                        None
                    };
                    return (probe.name.clone(), version);
                }
            }
        }
        
        // Fallback detection
        self.fallback_detect(port, response)
    }
    
    fn fallback_detect(&self, port: u16, response: &[u8]) -> (String, Option<String>) {
        let response_str = String::from_utf8_lossy(response);
        
        if response_str.starts_with("SSH-") {
            return ("ssh".to_string(), None);
        }
        if response_str.starts_with("220") && response_str.contains("FTP") {
            return ("ftp".to_string(), None);
        }
        if response_str.contains("HTTP/") {
            return ("http".to_string(), None);
        }
        if response_str.contains("MySQL") {
            return ("mysql".to_string(), None);
        }
        if response_str.contains("PostgreSQL") {
            return ("postgresql".to_string(), None);
        }
        if response_str.contains("+PONG") || response_str.contains("redis_version") {
            return ("redis".to_string(), None);
        }
        
        ("unknown".to_string(), None)
    }
}

impl Default for ServiceDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PORT SCANNER PRINCIPAL
// ============================================================================

pub struct PortScanner {
    connect_timeout: Duration,
    read_timeout: Duration,
    max_concurrent: usize,
    service_detector: ServiceDetector,
    enable_service_detection: bool,
    enable_tls_detection: bool,
    retries: u32,
    delay_between_ports_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub max_concurrent: usize,
    pub enable_service_detection: bool,
    pub enable_tls_detection: bool,
    pub retries: u32,
    pub delay_between_ports_ms: u64,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 2000,
            read_timeout_ms: 3000,
            max_concurrent: 100,
            enable_service_detection: true,
            enable_tls_detection: true,
            retries: 1,
            delay_between_ports_ms: 0,
        }
    }
}

impl PortScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self {
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            read_timeout: Duration::from_millis(config.read_timeout_ms),
            max_concurrent: config.max_concurrent,
            service_detector: ServiceDetector::new(),
            enable_service_detection: config.enable_service_detection,
            enable_tls_detection: config.enable_tls_detection,
            retries: config.retries,
            delay_between_ports_ms: config.delay_between_ports_ms,
        }
    }
    
    // ========================================================================
    // SCAN SÍNCRONO COM PARALELISMO
    // ========================================================================
    
    pub async fn scan_ports(
        &self,
        host: &str,
        ports: &[u16],
    ) -> Vec<PortScanResult> {
        let results = Arc::new(DashMap::new());
        let host = host.to_string();
        
        let chunks: Vec<&[u16]> = ports.chunks(self.max_concurrent).collect();
        
        for chunk in chunks {
            let mut tasks = Vec::new();
            
            for &port in chunk {
                let host = host.clone();
                let results = Arc::clone(&results);
                let scanner = self.clone_for_async();
                
                if self.delay_between_ports_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(self.delay_between_ports_ms)).await;
                }
                
                tasks.push(tokio::spawn(async move {
                    let result = scanner.scan_single_port(&host, port).await;
                    if let Some(r) = result {
                        results.insert(port, r);
                    }
                }));
            }
            
            for task in tasks {
                let _ = task.await;
            }
        }
        
        let mut results_vec: Vec<PortScanResult> = results
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        
        results_vec.sort_by_key(|r| r.port);
        results_vec
    }
    
    // ========================================================================
    // SCAN ASSÍNCRONO CONCORRENTE MÁXIMO
    // ========================================================================
    
    pub async fn scan_ports_async_max(
        &self,
        host: &str,
        ports: &[u16],
    ) -> Vec<PortScanResult> {
        let host = host.to_string();
        let results = Arc::new(DashMap::new());
        
        let mut futures = FuturesUnordered::new();
        
        for &port in ports {
            let host = host.clone();
            let results = Arc::clone(&results);
            let scanner = self.clone_for_async();
            
            futures.push(tokio::spawn(async move {
                let result = scanner.scan_single_port(&host, port).await;
                if let Some(r) = result {
                    results.insert(port, r);
                }
            }));
        }
        
        while let Some(_) = futures.next().await {}
        
        let mut results_vec: Vec<PortScanResult> = results
            .into_iter()
            .map(|(_, v)| v)
            .collect();
        
        results_vec.sort_by_key(|r| r.port);
        results_vec
    }
    
    // ========================================================================
    // SCAN COM CLASSIFICAÇÃO POR CATEGORIA
    // ========================================================================
    
    pub async fn scan_by_category(
        &self,
        host: &str,
        categories: &[PortCategory],
    ) -> HashMap<PortCategory, Vec<PortScanResult>> {
        let mut ports_to_scan = Vec::new();
        
        for category in categories {
            ports_to_scan.extend(category.ports());
        }
        
        let all_results = self.scan_ports(host, &ports_to_scan).await;
        
        let mut categorized = HashMap::new();
        
        for category in categories {
            let category_ports: HashSet<u16> = category.ports().iter().copied().collect();
            let category_results: Vec<PortScanResult> = all_results
                .iter()
                .filter(|r| category_ports.contains(&r.port))
                .cloned()
                .collect();
            categorized.insert(category.clone(), category_results);
        }
        
        categorized
    }
    
    // ========================================================================
    // SCAN DE UM ÚNICO PORTO
    // ========================================================================
    
    async fn scan_single_port(&self, host: &str, port: u16) -> Option<PortScanResult> {
        let addr = format!("{}:{}", host, port);
        let mut last_error = None;
        
        for attempt in 0..=self.retries {
            let start = Instant::now();
            
            match timeout(self.connect_timeout, TcpStream::connect(&addr)).await {
                Ok(Ok(stream)) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    
                    let mut result = PortScanResult {
                        port,
                        protocol: Protocol::Tcp,
                        status: PortStatus::Open,
                        service_name: "unknown".to_string(),
                        service_version: None,
                        banner: None,
                        response_time_ms: elapsed,
                        tls: None,
                        headers: None,
                    };
                    
                    // Service detection
                    if self.enable_service_detection {
                        if let Some((service, version)) = self.detect_service(host, port, &stream).await {
                            result.service_name = service;
                            result.service_version = version;
                        }
                    }
                    
                    // TLS detection for HTTPS
                    if self.enable_tls_detection && (port == 443 || port == 8443) {
                        result.tls = self.detect_tls(host, port).await;
                    }
                    
                    return Some(result);
                }
                Ok(Err(e)) => {
                    last_error = Some(e);
                    if attempt == self.retries {
                        return Some(PortScanResult {
                            port,
                            protocol: Protocol::Tcp,
                            status: PortStatus::Closed,
                            service_name: "closed".to_string(),
                            service_version: None,
                            banner: None,
                            response_time_ms: start.elapsed().as_millis() as u64,
                            tls: None,
                            headers: None,
                        });
                    }
                }
                Err(_) => {
                    last_error = None;
                    if attempt == self.retries {
                        return Some(PortScanResult {
                            port,
                            protocol: Protocol::Tcp,
                            status: PortStatus::Filtered,
                            service_name: "filtered".to_string(),
                            service_version: None,
                            banner: None,
                            response_time_ms: self.connect_timeout.as_millis() as u64,
                            tls: None,
                            headers: None,
                        });
                    }
                }
            }
        }
        
        None
    }
    
    // ========================================================================
    // DETECÇÃO DE SERVIÇO
    // ========================================================================
    
    async fn detect_service(
        &self,
        host: &str,
        port: u16,
        stream: &TcpStream,
    ) -> Option<(String, Option<String>)> {
        let detector = &self.service_detector;
        
        if let Some(probe) = detector.probes.get(&port) {
            let mut stream_clone = match stream.try_clone() {
                Ok(s) => s,
                Err(_) => return None,
            };
            
            use tokio::io::{AsyncWriteExt, AsyncReadExt};
            
            let _ = stream_clone.write_all(&probe.probe_string).await;
            
            let mut response = Vec::new();
            let read_result = timeout(self.read_timeout, async {
                let mut buf = [0u8; 4096];
                loop {
                    match stream_clone.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => response.extend_from_slice(&buf[..n]),
                        Err(_) => break,
                    }
                    if response.len() > 8192 {
                        break;
                    }
                }
            }).await;
            
            if read_result.is_ok() && !response.is_empty() {
                let (service, version) = detector.detect(port, &response);
                let banner = Some(String::from_utf8_lossy(&response).to_string());
                return Some((service, version));
            }
        }
        
        None
    }
    
    // ========================================================================
    // DETECÇÃO TLS
    // ========================================================================
    
    async fn detect_tls(&self, host: &str, port: u16) -> Option<TlsInfo> {
        use tokio_native_tls::TlsConnector;
        use std::net::ToSocketAddrs;
        
        let addr = format!("{}:{}", host, port);
        let addrs: Vec<SocketAddr> = match addr.to_socket_addrs() {
            Ok(addrs) => addrs.collect(),
            Err(_) => return None,
        };
        
        let stream = match timeout(self.connect_timeout, TcpStream::connect(&addrs[0])).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };
        
        let connector = TlsConnector::new();
        let hostname = host.to_string();
        
        match timeout(self.connect_timeout, connector.connect(&hostname, stream)).await {
            Ok(Ok(tls_stream)) => {
                let negotiated_version = tls_stream.get_ref().negotiated_cipher_suite()
                    .map(|cs| format!("{:?}", cs))
                    .unwrap_or_else(|| "Unknown".to_string());
                
                let certificate = tls_stream.get_ref().peer_certificate()
                    .and_then(|cert| cert.to_der().ok())
                    .and_then(|der| {
                        use x509_parser::parse_x509_certificate;
                        parse_x509_certificate(&der).ok()
                    });
                
                Some(TlsInfo {
                    version: negotiated_version,
                    cipher_suite: "Unknown".to_string(),
                    certificate_issuer: certificate
                        .as_ref()
                        .and_then(|(_, cert)| cert.issuer().to_string().ok())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    certificate_subject: certificate
                        .as_ref()
                        .and_then(|(_, cert)| cert.subject().to_string().ok())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    certificate_expiry: certificate
                        .as_ref()
                        .and_then(|(_, cert)| cert.validity().not_after.timestamp().ok()),
                    sni_supported: true,
                })
            }
            _ => None,
        }
    }
    
    fn clone_for_async(&self) -> Self {
        Self {
            connect_timeout: self.connect_timeout,
            read_timeout: self.read_timeout,
            max_concurrent: self.max_concurrent,
            service_detector: ServiceDetector::new(),
            enable_service_detection: self.enable_service_detection,
            enable_tls_detection: self.enable_tls_detection,
            retries: self.retries,
            delay_between_ports_ms: self.delay_between_ports_ms,
        }
    }
}

// ========================================================================
// CATEGORIAS DE PORTAS
// ========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PortCategory {
    All,
    Web,
    Database,
    Admin,
    Mail,
    Dns,
    Common,
}

impl PortCategory {
    pub fn ports(&self) -> Vec<u16> {
        match self {
            PortCategory::All => COMMON_PORTS.to_vec(),
            PortCategory::Web => WEB_PORTS.to_vec(),
            PortCategory::Database => DB_PORTS.to_vec(),
            PortCategory::Admin => ADMIN_PORTS.to_vec(),
            PortCategory::Mail => vec![25, 110, 143, 465, 587, 993, 995],
            PortCategory::Dns => vec![53],
            PortCategory::Common => COMMON_PORTS.to_vec(),
        }
    }
    
    pub fn description(&self) -> &'static str {
        match self {
            PortCategory::All => "All common ports (50 ports)",
            PortCategory::Web => "Web servers (HTTP/HTTPS proxies)",
            PortCategory::Database => "Database servers (MySQL, PostgreSQL, Redis, MongoDB)",
            PortCategory::Admin => "Admin/Remote access (SSH, RDP, VNC)",
            PortCategory::Mail => "Mail servers (SMTP, POP3, IMAP)",
            PortCategory::Dns => "DNS servers",
            PortCategory::Common => "Most common ports (50 ports)",
        }
    }
}

// ========================================================================
// SCAN REPORT
// ========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanReport {
    pub target: String,
    pub total_scanned: usize,
    pub open_ports: Vec<PortScanResult>,
    pub closed_ports: Vec<PortScanResult>,
    pub filtered_ports: Vec<PortScanResult>,
    pub scan_duration_ms: u64,
    pub by_service: HashMap<String, Vec<u16>>,
    pub web_ports: Vec<PortScanResult>,
    pub db_ports: Vec<PortScanResult>,
    pub admin_ports: Vec<PortScanResult>,
}

impl PortScanReport {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            total_scanned: 0,
            open_ports: Vec::new(),
            closed_ports: Vec::new(),
            filtered_ports: Vec::new(),
            scan_duration_ms: 0,
            by_service: HashMap::new(),
            web_ports: Vec::new(),
            db_ports: Vec::new(),
            admin_ports: Vec::new(),
        }
    }
    
    pub fn from_results(target: &str, results: Vec<PortScanResult>, duration_ms: u64) -> Self {
        let mut report = Self::new(target);
        report.scan_duration_ms = duration_ms;
        report.total_scanned = results.len();
        
        for result in results {
            match result.status {
                PortStatus::Open => {
                    report.open_ports.push(result.clone());
                    
                    report.by_service
                        .entry(result.service_name.clone())
                        .or_insert_with(Vec::new)
                        .push(result.port);
                    
                    if WEB_PORTS.contains(&result.port) {
                        report.web_ports.push(result.clone());
                    }
                    if DB_PORTS.contains(&result.port) {
                        report.db_ports.push(result.clone());
                    }
                    if ADMIN_PORTS.contains(&result.port) {
                        report.admin_ports.push(result.clone());
                    }
                }
                PortStatus::Closed => report.closed_ports.push(result),
                PortStatus::Filtered => report.filtered_ports.push(result),
                PortStatus::Unknown => {}
            }
        }
        
        report
    }
    
    pub fn has_web_server(&self) -> bool {
        !self.web_ports.is_empty()
    }
    
    pub fn has_database(&self) -> bool {
        !self.db_ports.is_empty()
    }
    
    pub fn has_admin_access(&self) -> bool {
        !self.admin_ports.is_empty()
    }
    
    pub fn risk_score(&self) -> f64 {
        let mut score = 0.0;
        
        // Open ports base score
        score += (self.open_ports.len() as f64) * 0.5;
        
        // Database exposure
        if self.has_database() {
            score += 2.0;
        }
        
        // Admin access exposure
        if self.has_admin_access() {
            score += 3.0;
        }
        
        // Web servers (potential attack surface)
        score += (self.web_ports.len() as f64) * 0.3;
        
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
    async fn test_port_scan() {
        let config = ScannerConfig::default();
        let scanner = PortScanner::new(config);
        
        let results = scanner.scan_ports("localhost", &[80, 443, 22, 3306]).await;
        
        assert!(!results.is_empty());
    }
    
    #[test]
    fn test_service_detection() {
        let detector = ServiceDetector::new();
        
        let http_response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html>";
        let (service, version) = detector.detect(80, http_response);
        assert_eq!(service, "http");
        
        let ssh_response = b"SSH-2.0-OpenSSH_8.4\r\n";
        let (service, version) = detector.detect(22, ssh_response);
        assert_eq!(service, "ssh");
    }
    
    #[test]
    fn test_port_category() {
        let web_ports = PortCategory::Web.ports();
        assert!(web_ports.contains(&80));
        assert!(web_ports.contains(&443));
        assert!(web_ports.contains(&8080));
        
        let db_ports = PortCategory::Database.ports();
        assert!(db_ports.contains(&3306));
        assert!(db_ports.contains(&5432));
        assert!(db_ports.contains(&6379));
        assert!(db_ports.contains(&27017));
    }
}