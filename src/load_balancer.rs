use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, warn};

/// Health status of a single RPC endpoint
#[derive(Debug, Clone)]
pub struct EndpointHealth {
    pub endpoint: String,
    pub failures: u32,
    pub last_failure: Option<Instant>,
    pub is_healthy: bool,
    pub requests_served: u64,
    pub avg_latency_ms: f64,
}

impl EndpointHealth {
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            failures: 0,
            last_failure: None,
            is_healthy: true,
            requests_served: 0,
            avg_latency_ms: 0.0,
        }
    }
}

/// Round-robin load balancer with health tracking for 15+ WebSocket endpoints.
/// Uses atomic counters for lock-free rotation under high concurrency.
pub struct LoadBalancer {
    endpoints: Vec<String>,
    counter: Arc<AtomicUsize>,
    health: Arc<DashMap<String, EndpointHealth>>,
    recovery_window: Duration,
    max_failures: u32,
}

impl LoadBalancer {
    /// Create a new LoadBalancer from a list of WebSocket endpoint URLs.
    pub fn new(endpoints: Vec<String>) -> Self {
        let health: Arc<DashMap<String, EndpointHealth>> = Arc::new(DashMap::new());
        for ep in &endpoints {
            health.insert(ep.clone(), EndpointHealth::new(ep.clone()));
        }

        Self {
            endpoints,
            counter: Arc::new(AtomicUsize::new(0)),
            health,
            recovery_window: Duration::from_secs(30),
            max_failures: 3,
        }
    }

    /// Get the total number of registered endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Select the next healthy endpoint using round-robin rotation.
    /// Falls back to any available endpoint if all are marked unhealthy.
    pub fn next_endpoint(&self) -> Option<String> {
        let len = self.endpoints.len();
        if len == 0 {
            return None;
        }

        // Try up to len times to find a healthy endpoint
        for _ in 0..len {
            let idx = self.counter.fetch_add(1, Ordering::Relaxed) % len;
            let ep = &self.endpoints[idx];

            if let Some(mut health) = self.health.get_mut(ep) {
                // Attempt recovery after window
                if !health.is_healthy {
                    if let Some(last_fail) = health.last_failure {
                        if last_fail.elapsed() >= self.recovery_window {
                            health.is_healthy = true;
                            health.failures = 0;
                            debug!("Endpoint recovered: {}", ep);
                        }
                    }
                }

                if health.is_healthy {
                    health.requests_served += 1;
                    return Some(ep.clone());
                }
            }
        }

        // All endpoints unhealthy — return first available anyway
        warn!("All endpoints unhealthy, using first available");
        self.endpoints.first().cloned()
    }

    /// Record a successful response for latency tracking
    pub fn record_success(&self, endpoint: &str, latency_ms: f64) {
        if let Some(mut health) = self.health.get_mut(endpoint) {
            let n = health.requests_served as f64;
            health.avg_latency_ms = (health.avg_latency_ms * n + latency_ms) / (n + 1.0);
        }
    }

    /// Record a failure for the given endpoint. Marks it unhealthy after max_failures.
    pub fn record_failure(&self, endpoint: &str) {
        if let Some(mut health) = self.health.get_mut(endpoint) {
            health.failures += 1;
            health.last_failure = Some(Instant::now());

            if health.failures >= self.max_failures {
                health.is_healthy = false;
                warn!(
                    "Endpoint marked unhealthy after {} failures: {}",
                    health.failures, endpoint
                );
            }
        }
    }

    /// Returns a summary of current endpoint health for monitoring
    pub fn health_summary(&self) -> Vec<EndpointHealth> {
        self.health.iter().map(|e| e.value().clone()).collect()
    }

    /// Returns all healthy endpoints
    pub fn healthy_endpoints(&self) -> Vec<String> {
        self.health
            .iter()
            .filter(|e| e.value().is_healthy)
            .map(|e| e.key().clone())
            .collect()
    }
}

/// A WebSocket connection pool entry that holds an endpoint URL
/// and allows the load balancer to assign connections.
pub struct WsConnectionRequest {
    pub endpoint: String,
    pub assigned_at: Instant,
}

impl WsConnectionRequest {
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            assigned_at: Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> f64 {
        self.assigned_at.elapsed().as_secs_f64() * 1000.0
    }
}
