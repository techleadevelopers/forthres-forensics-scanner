// scanner/rust_core/src/rate_limiter.rs
use std::time::{Duration, Instant};
use rand::Rng;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiter {
    min_delay_ms: u64,
    max_delay_ms: u64,
    jitter: bool,
    last_request: Instant,
    consecutive_blocks: u32,
    total_requests: u32,
    total_blocks: u32,
    block_timestamps: Vec<Instant>,
    escalation_count: u32,
    deescalation_count: u32,
    current_level: StealthLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StealthLevel {
    Ghost,      // 0.05s
    Whisper,    // 0.25s
    Cautious,   // 0.6s
    Stealth,    // 1.2s
    Crawl,      // 2.0s
    Hibernate,  // 3.0s
}

impl StealthLevel {
    pub fn delay_ms(&self) -> u64 {
        match self {
            StealthLevel::Ghost => 50,
            StealthLevel::Whisper => 250,
            StealthLevel::Cautious => 600,
            StealthLevel::Stealth => 1200,
            StealthLevel::Crawl => 2000,
            StealthLevel::Hibernate => 3000,
        }
    }
    
    pub fn name(&self) -> &'static str {
        match self {
            StealthLevel::Ghost => "GHOST",
            StealthLevel::Whisper => "WHISPER",
            StealthLevel::Cautious => "CAUTIOUS",
            StealthLevel::Stealth => "STEALTH",
            StealthLevel::Crawl => "CRAWL",
            StealthLevel::Hibernate => "HIBERNATE",
        }
    }
    
    pub fn escalate(&self) -> Self {
        match self {
            StealthLevel::Ghost => StealthLevel::Whisper,
            StealthLevel::Whisper => StealthLevel::Cautious,
            StealthLevel::Cautious => StealthLevel::Stealth,
            StealthLevel::Stealth => StealthLevel::Crawl,
            StealthLevel::Crawl => StealthLevel::Hibernate,
            StealthLevel::Hibernate => StealthLevel::Hibernate,
        }
    }
    
    pub fn deescalate(&self) -> Self {
        match self {
            StealthLevel::Ghost => StealthLevel::Ghost,
            StealthLevel::Whisper => StealthLevel::Ghost,
            StealthLevel::Cautious => StealthLevel::Whisper,
            StealthLevel::Stealth => StealthLevel::Cautious,
            StealthLevel::Crawl => StealthLevel::Stealth,
            StealthLevel::Hibernate => StealthLevel::Crawl,
        }
    }
}

impl RateLimiter {
    pub fn new(min_delay_ms: u64, max_delay_ms: u64, jitter: bool) -> Self {
        Self {
            min_delay_ms,
            max_delay_ms,
            jitter,
            last_request: Instant::now(),
            consecutive_blocks: 0,
            total_requests: 0,
            total_blocks: 0,
            block_timestamps: Vec::new(),
            escalation_count: 0,
            deescalation_count: 0,
            current_level: StealthLevel::Ghost,
        }
    }
    
    pub fn default() -> Self {
        Self::new(50, 500, true)
    }
    
    pub async fn wait(&mut self) {
        let base_delay = self.current_level.delay_ms();
        let mut delay = base_delay as f64;
        
        if self.jitter {
            let mut rng = rand::thread_rng();
            let jitter_factor = rng.gen_range(0.8..1.2);
            delay *= jitter_factor;
        }
        
        if self.consecutive_blocks > 2 {
            delay *= 2.0;
        }
        
        let elapsed = self.last_request.elapsed().as_millis() as f64;
        if elapsed < delay {
            tokio::time::sleep(Duration::from_millis((delay - elapsed) as u64)).await;
        }
        
        self.last_request = Instant::now();
    }
    
    pub fn report_block(&mut self, blocked: bool) {
        self.total_requests += 1;
        
        if blocked {
            self.total_blocks += 1;
            self.consecutive_blocks += 1;
            self.block_timestamps.push(Instant::now());
            
            // Limitar histórico de timestamps
            while self.block_timestamps.len() > 100 {
                self.block_timestamps.remove(0);
            }
            
            if self.consecutive_blocks >= 3 {
                self.escalate();
            }
        } else {
            self.consecutive_blocks = self.consecutive_blocks.saturating_sub(1);
            
            if self.consecutive_blocks == 0 && self.current_level != StealthLevel::Ghost {
                self.deescalate();
            }
        }
        
        let recent_block_rate = self.recent_block_rate();
        if recent_block_rate > 0.6 && self.current_level != StealthLevel::Hibernate {
            self.escalate();
        }
    }
    
    pub fn recent_block_rate(&self) -> f64 {
        let now = Instant::now();
        let recent: Vec<_> = self.block_timestamps.iter()
            .filter(|ts| now.duration_since(**ts).as_secs_f64() < 30.0)
            .collect();
        
        if self.total_requests < 5 {
            return 0.0;
        }
        
        let window_requests = self.total_requests.min(recent.len() * 3);
        recent.len() as f64 / window_requests.max(1) as f64
    }
    
    pub fn escalate(&mut self) {
        let old_level = self.current_level;
        self.current_level = self.current_level.escalate();
        if old_level != self.current_level {
            self.escalation_count += 1;
        }
    }
    
    pub fn deescalate(&mut self) {
        let old_level = self.current_level;
        self.current_level = self.current_level.deescalate();
        if old_level != self.current_level {
            self.deescalation_count += 1;
        }
    }
    
    pub fn need_proxy_rotation(&self) -> bool {
        self.consecutive_blocks > 3
    }
    
    pub fn global_block_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.total_blocks as f64 / self.total_requests as f64
    }
    
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "current_level": self.current_level.name(),
            "delay_ms": self.current_level.delay_ms(),
            "total_requests": self.total_requests,
            "total_blocks": self.total_blocks,
            "global_block_rate": format!("{:.1%}", self.global_block_rate()),
            "recent_block_rate": format!("{:.1%}", self.recent_block_rate()),
            "escalations": self.escalation_count,
            "deescalations": self.deescalation_count,
            "consecutive_blocks": self.consecutive_blocks,
        })
    }
}

pub struct ProxyRotator {
    proxies: Vec<String>,
    current_idx: usize,
    failed_proxies: Vec<String>,
}

impl ProxyRotator {
    pub fn new(proxies: Vec<String>) -> Self {
        Self {
            proxies,
            current_idx: 0,
            failed_proxies: Vec::new(),
        }
    }
    
    pub fn get_next_proxy(&mut self) -> Option<String> {
        if self.proxies.is_empty() {
            return None;
        }
        
        for _ in 0..self.proxies.len() {
            let proxy = self.proxies[self.current_idx].clone();
            self.current_idx = (self.current_idx + 1) % self.proxies.len();
            
            if !self.failed_proxies.contains(&proxy) {
                return Some(proxy);
            }
        }
        
        None
    }
    
    pub fn mark_failed(&mut self, proxy: &str) {
        if !self.failed_proxies.contains(&proxy.to_string()) {
            self.failed_proxies.push(proxy.to_string());
        }
    }
    
    pub fn rotate_user_agent(&self) -> String {
        let agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
        ];
        agents[rand::thread_rng().gen_range(0..agents.len())].to_string()
    }
}