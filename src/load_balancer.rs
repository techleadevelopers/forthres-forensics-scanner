use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct EndpointHealth {
    pub endpoint: String,
    pub failures: u32,
    pub is_healthy: bool,
    pub requests_served: u64,
    pub avg_latency_ms: f64,
}

impl EndpointHealth {
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            failures: 0,
            is_healthy: true,
            requests_served: 0,
            avg_latency_ms: 0.0,
        }
    }
}

pub struct LoadBalancer {
    health: Arc<DashMap<String, EndpointHealth>>,
    max_failures: u32,
}

impl LoadBalancer {
    pub fn new(endpoints: Vec<String>) -> Self {
        let health = Arc::new(DashMap::new());
        for endpoint in endpoints {
            health.insert(endpoint.clone(), EndpointHealth::new(endpoint));
        }

        Self {
            health,
            max_failures: 3,
        }
    }

    pub fn record_success(&self, endpoint: &str, latency_ms: f64) {
        if let Some(mut health) = self.health.get_mut(endpoint) {
            let served_before = health.requests_served as f64;
            health.avg_latency_ms =
                (health.avg_latency_ms * served_before + latency_ms) / (served_before + 1.0);
            health.requests_served += 1;
            health.is_healthy = true;
        }
    }

    pub fn record_failure(&self, endpoint: &str) {
        if let Some(mut health) = self.health.get_mut(endpoint) {
            health.failures += 1;
            if health.failures >= self.max_failures {
                health.is_healthy = false;
                warn!(
                    "Endpoint marked unhealthy after {} failures: {}",
                    health.failures, endpoint
                );
            }
        }
    }

    pub fn health_summary(&self) -> Vec<EndpointHealth> {
        self.health.iter().map(|entry| entry.value().clone()).collect()
    }
}

pub struct WsConnectionRequest {
    assigned_at: Instant,
}

impl WsConnectionRequest {
    pub fn new() -> Self {
        Self {
            assigned_at: Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> f64 {
        self.assigned_at.elapsed().as_secs_f64() * 1000.0
    }
}
