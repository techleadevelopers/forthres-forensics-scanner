use tokio::net::TcpStream;
use tokio::time::timeout;
use std::time::Duration;

pub struct NetworkScanner {
    client: reqwest::Client,
    timeout: Duration,
}

impl NetworkScanner {
    /// Port scan with tokio async - 10x faster than Python asyncio
    pub async fn port_scan_parallel(&self, host: &str, ports: &[u16]) -> Vec<u16> {
        let mut tasks = Vec::new();
        
        for &port in ports {
            let host = host.to_string();
            tasks.push(tokio::spawn(async move {
                match timeout(Duration::from_millis(500), TcpStream::connect(&format!("{}:{}", host, port))).await {
                    Ok(Ok(_)) => Some(port),
                    _ => None,
                }
            }));
        }
        
        let mut open_ports = Vec::new();
        for task in tasks {
            if let Ok(Some(port)) = task.await {
                open_ports.push(port);
            }
        }
        open_ports
    }
    
    /// HTTP requests with connection pooling
    pub async fn probe_endpoints(&self, base_url: &str, paths: &[&str]) -> Vec<ProbeResult> {
        let client = &self.client;
        let futures: Vec<_> = paths
            .iter()
            .map(|path| client.get(format!("{}{}", base_url, path)).send())
            .collect();
        
        let results = futures::future::join_all(futures).await;
        results
            .into_iter()
            .enumerate()
            .filter_map(|(i, resp)| match resp {
                Ok(r) => Some(ProbeResult {
                    path: paths[i].to_string(),
                    status: r.status().as_u16(),
                    size: r.content_length(),
                }),
                Err(_) => None,
            })
            .collect()
    }
}