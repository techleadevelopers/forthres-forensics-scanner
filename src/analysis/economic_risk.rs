// src/offensive/economic_impact.rs
//! Hexora Real-Time Economic Impact Engine
//!
//! Calcula valor econômico de exploits usando:
//! - Preços em tempo real via Chainlink/Uniswap
//! - Simulação de slippage baseada em liquidez real
//! - Gas prices dinâmicos
//! - Cache multi-camada para performance

use crate::forensics::ForensicsEngine;
use lru::LruCache;
use super::path_finder::{ControlFlowPath, StateChange};
use super::probability_engine::ControlFlowPathWithProb;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use reqwest::Client;
use serde_json::Value;

// ============================================================
// ESTRUTURAS BASE (mantidas)
// ============================================================

#[derive(Debug, Clone)]
pub struct ExploitPathWithValue {
    pub path: ControlFlowPath,
    pub probability: f64,
    pub economic_value_eth: f64,
    pub economic_value_usd: f64,
    pub risk_adjusted_value: f64,
    pub liquidity_impact: f64,      // Impacto na liquidez (0-1)
    pub execution_cost_eth: f64,    // Custo de execução
    pub net_profit_eth: f64,        // Lucro líquido
}

// ============================================================
// NOVO: REAL-TIME ECONOMIC ENGINE
// ============================================================

/// Interface para price feeds
#[async_trait::async_trait]
pub trait PriceFeed: Send + Sync {
    async fn latest_price(&self) -> Result<f64, String>;
    async fn price_at_block(&self, block: u64) -> Result<f64, String>;
}

/// Chainlink price feed
pub struct ChainlinkFeed {
    address: String,
    client: Client,
    decimals: u8,
}

impl ChainlinkFeed {
    pub fn new(address: &str, decimals: u8) -> Self {
        Self {
            address: address.to_string(),
            client: Client::new(),
            decimals,
        }
    }
    
    async fn fetch_latest_round_data(&self) -> Result<Value, String> {
        // Simulação - em produção chamaria o contrato Chainlink via RPC
        // Exemplo: eth_call no aggregator
        Ok(Value::Null)
    }
}

#[async_trait::async_trait]
impl PriceFeed for ChainlinkFeed {
    async fn latest_price(&self) -> Result<f64, String> {
        // TODO: Implementar chamada real ao contrato Chainlink
        // Por enquanto retorna fallback
        Ok(0.0)
    }
    
    async fn price_at_block(&self, _block: u64) -> Result<f64, String> {
        Ok(0.0)
    }
}

/// Simulador de pool Uniswap V2
#[derive(Debug, Clone)]
pub struct UniswapV2Simulator {
    pub pair_address: String,
    pub reserve0: f64,
    pub reserve1: f64,
    pub token0: String,
    pub token1: String,
    pub last_update: Instant,
}

impl UniswapV2Simulator {
    pub fn new(pair_address: &str) -> Self {
        Self {
            pair_address: pair_address.to_string(),
            reserve0: 0.0,
            reserve1: 0.0,
            token0: String::new(),
            token1: String::new(),
            last_update: Instant::now(),
        }
    }
    
    /// Obtém preço atual do pool
    pub async fn get_price(&self, base_token: &str) -> Option<f64> {
        if self.reserve0 == 0.0 || self.reserve1 == 0.0 {
            return None;
        }
        
        if self.token0 == base_token {
            Some(self.reserve1 / self.reserve0)
        } else if self.token1 == base_token {
            Some(self.reserve0 / self.reserve1)
        } else {
            None
        }
    }
    
    /// Simula slippage para uma troca
    pub fn simulate_swap_slippage(&self, amount_in: f64, token_in: &str) -> f64 {
        let (reserve_in, reserve_out) = if self.token0 == token_in {
            (self.reserve0, self.reserve1)
        } else if self.token1 == token_in {
            (self.reserve1, self.reserve0)
        } else {
            return 1.0; // 100% slippage se token não existe
        };
        
        if reserve_in == 0.0 {
            return 1.0;
        }
        
        // Fórmula Uniswap: amount_out = (amount_in * 997 * reserve_out) / (reserve_in * 1000 + amount_in * 997)
        let amount_in_with_fee = amount_in * 0.997;
        let amount_out = (amount_in_with_fee * reserve_out) / (reserve_in + amount_in_with_fee);
        
        // Preço médio vs preço marginal
        let avg_price = amount_out / amount_in;
        let marginal_price = reserve_out / reserve_in;
        
        if marginal_price == 0.0 {
            return 1.0;
        }
        
        let slippage = 1.0 - (avg_price / marginal_price);
        slippage.min(0.5).max(0.0) // Max 50% slippage
    }
    
    /// Atualiza reservas do pool
    pub async fn update_reserves(&mut self, forensics: &ForensicsEngine) -> Result<(), String> {
        // TODO: Buscar reservas reais via RPC
        // getReserves() do contrato UniswapV2Pair
        Ok(())
    }
}

/// Engine econômica principal
pub struct RealTimeEconomicEngine {
    price_feeds: HashMap<String, Arc<dyn PriceFeed + Send + Sync>>,
    pool_simulators: HashMap<String, Arc<Mutex<UniswapV2Simulator>>>,
    chainlink_feeds: HashMap<String, String>, // token -> chainlink feed address
    cache: Arc<Mutex<LruCache<String, CachedPrice>>>,
    http_client: Client,
    gas_price_cache: Arc<Mutex<GasPriceCache>>,
    config: EconomicConfig,
}

#[derive(Debug, Clone)]
pub struct CachedPrice {
    pub price: f64,
    pub timestamp: Instant,
    pub block: u64,
}

#[derive(Debug, Clone)]
pub struct GasPriceCache {
    pub legacy_gwei: f64,
    pub eip1559: Eip1559Fees,
    pub last_update: Instant,
}

#[derive(Debug, Clone)]
pub struct Eip1559Fees {
    pub base_fee: f64,
    pub priority_fee: f64,
    pub max_fee: f64,
}

#[derive(Debug, Clone)]
pub struct EconomicConfig {
    pub use_chainlink: bool,
    pub use_uniswap_fallback: bool,
    pub cache_ttl_seconds: u64,
    pub max_slippage: f64,
    pub flashloan_enabled: bool,
    pub max_flashloan_eth: f64,
}

impl Default for EconomicConfig {
    fn default() -> Self {
        Self {
            use_chainlink: true,
            use_uniswap_fallback: true,
            cache_ttl_seconds: 30,
            max_slippage: 0.5,
            flashloan_enabled: true,
            max_flashloan_eth: 1000.0,
        }
    }
}

impl RealTimeEconomicEngine {
    pub fn new(config: EconomicConfig) -> Self {
        Self {
            price_feeds: HashMap::new(),
            pool_simulators: HashMap::new(),
            chainlink_feeds: Self::init_chainlink_feeds(),
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(1000).expect("non-zero cache size"),
            ))),
            http_client: Client::new(),
            gas_price_cache: Arc::new(Mutex::new(GasPriceCache {
                legacy_gwei: 20.0,
                eip1559: Eip1559Fees {
                    base_fee: 10.0,
                    priority_fee: 2.0,
                    max_fee: 30.0,
                },
                last_update: Instant::now(),
            })),
            config,
        }
    }
    
    /// Inicializa mapeamento de Chainlink feeds conhecidos
    fn init_chainlink_feeds() -> HashMap<String, String> {
        let mut feeds = HashMap::new();
        // Ethereum Mainnet Chainlink feeds
        feeds.insert("WETH".to_string(), "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419".to_string());
        feeds.insert("WBTC".to_string(), "0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c".to_string());
        feeds.insert("USDC".to_string(), "0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6".to_string());
        feeds.insert("USDT".to_string(), "0x3E7d1eAB13ad0104d2750B8863b489D65364e32D".to_string());
        feeds.insert("DAI".to_string(), "0xAed0c38402a5d19df6E4c03F4E2DceD6e29c1ee9".to_string());
        feeds
    }
    
    /// Busca preço em tempo real via Chainlink ou Uniswap
    pub async fn get_price(&self, token_symbol: &str, token_address: &str, block: Option<u64>) -> f64 {
        let cache_key = format!("{}_{}_{:?}", token_symbol, token_address, block);
        let block_num = block.unwrap_or(0);
        let cache_block = block_num / 100; // Cache a cada 100 blocos
        
        let final_cache_key = format!("{}_{}", cache_key, cache_block);
        
        // Verifica cache
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some(cached) = cache.get(&final_cache_key) {
                if cached.timestamp.elapsed().as_secs() < self.config.cache_ttl_seconds {
                    tracing::debug!("💰 Cache hit for price: {} = ${}", token_symbol, cached.price);
                    return cached.price;
                }
            }
        }
        
        let price = self.fetch_price_internal(token_symbol, token_address, block_num).await;
        
        // Cacheia resultado
        {
            let mut cache = self.cache.lock().unwrap();
            cache.put(final_cache_key, CachedPrice {
                price,
                timestamp: Instant::now(),
                block: block_num,
            });
        }
        
        price
    }
    
    async fn fetch_price_internal(&self, token_symbol: &str, token_address: &str, _block: u64) -> f64 {
        // 1. Tenta Chainlink primeiro
        if self.config.use_chainlink {
            if let Some(feed_address) = self.chainlink_feeds.get(token_symbol) {
                if let Ok(price) = self.query_chainlink_feed(feed_address).await {
                    tracing::debug!("💰 Chainlink price for {}: ${}", token_symbol, price);
                    return price;
                }
            }
        }
        
        // 2. Tenta Uniswap como fallback
        if self.config.use_uniswap_fallback {
            if let Some(price) = self.query_uniswap_price(token_address).await {
                tracing::debug!("💰 Uniswap price for {}: ${}", token_symbol, price);
                return price;
            }
        }
        
        // 3. Tenta Coingecko API
        if let Ok(price) = self.query_coingecko(token_symbol).await {
            tracing::debug!("💰 Coingecko price for {}: ${}", token_symbol, price);
            return price;
        }
        
        // 4. Fallback para token desconhecido
        let fallback = self.get_fallback_price(token_symbol);
        tracing::warn!("💰 Using fallback price for {}: ${}", token_symbol, fallback);
        fallback
    }
    
    async fn query_chainlink_feed(&self, feed_address: &str) -> Result<f64, String> {
        // TODO: Implementar chamada real ao contrato Chainlink
        // let latest_answer = contract.method::<_, u128>("latestAnswer")?;
        // Ok(latest_answer as f64 / 10u64.pow(decimals) as f64)
        
        // Simulação com cache de fallback
        match feed_address {
            "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419" => Ok(3000.0), // ETH/USD
            "0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c" => Ok(60000.0), // BTC/USD
            "0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6" => Ok(1.0), // USDC/USD
            "0x3E7d1eAB13ad0104d2750B8863b489D65364e32D" => Ok(1.0), // USDT/USD
            _ => Err("Unknown feed".to_string()),
        }
    }
    
    async fn query_uniswap_price(&self, token_address: &str) -> Option<f64> {
        // Tenta encontrar pool para o token
        if let Some(pool) = self.pool_simulators.values().next() {
            let pool_guard = pool.lock().unwrap();
            return pool_guard.get_price(token_address).await;
        }
        None
    }
    
    async fn query_coingecko(&self, token_symbol: &str) -> Result<f64, String> {
        let symbol_lower = token_symbol.to_lowercase();
        let url = format!("https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd", symbol_lower);
        
        match self.http_client.get(&url).timeout(Duration::from_secs(5)).send().await {
            Ok(response) => {
                if let Ok(json) = response.json::<Value>().await {
                    if let Some(price) = json.get(&symbol_lower).and_then(|p| p.get("usd")).and_then(|p| p.as_f64()) {
                        return Ok(price);
                    }
                }
                Err("Price not found".to_string())
            }
            Err(e) => Err(format!("HTTP error: {}", e)),
        }
    }
    
    fn get_fallback_price(&self, token_symbol: &str) -> f64 {
        match token_symbol {
            "WETH" | "ETH" => 3000.0,
            "WBTC" | "BTC" => 60000.0,
            "USDC" | "USDT" | "DAI" => 1.0,
            _ => 0.1,
        }
    }
    
    /// Busca gas price atual (EIP-1559)
    pub async fn get_gas_price(&self) -> GasPriceCache {
        {
            let cache = self.gas_price_cache.lock().unwrap();
            if cache.last_update.elapsed().as_secs() < 10 {
                return cache.clone();
            }
        }
        
        // TODO: Buscar via RPC
        // eth_gasPrice e eth_feeHistory
        let gas_price = GasPriceCache {
            legacy_gwei: 20.0,
            eip1559: Eip1559Fees {
                base_fee: 10.0,
                priority_fee: 2.0,
                max_fee: 30.0,
            },
            last_update: Instant::now(),
        };
        
        let mut cache = self.gas_price_cache.lock().unwrap();
        *cache = gas_price.clone();
        gas_price
    }
    
    /// Simula slippage baseado no tamanho da trade e liquidez
    pub fn simulate_slippage(&self, amount_eth: f64, pool_liquidity_eth: f64, token_symbol: &str) -> f64 {
        if pool_liquidity_eth == 0.0 {
            return self.config.max_slippage;
        }
        
        // Fórmula avançada de impacto no preço
        let impact = amount_eth / (pool_liquidity_eth + amount_eth);
        let slippage = impact / (1.0 - impact);
        
        // Ajusta por volatilidade do token
        let volatility_factor = self.get_token_volatility(token_symbol);
        let adjusted_slippage = slippage * volatility_factor;
        
        adjusted_slippage.min(self.config.max_slippage).max(0.0)
    }
    
    fn get_token_volatility(&self, token_symbol: &str) -> f64 {
        match token_symbol {
            "WETH" | "ETH" => 1.0,
            "WBTC" | "BTC" => 0.8,
            "USDC" | "USDT" | "DAI" => 0.1,
            _ => 1.5, // Tokens desconhecidos são mais voláteis
        }
    }
    
    /// Calcula custo de execução com gas dinâmico
    pub async fn calculate_execution_cost(&self, gas_estimate: u64) -> f64 {
        let gas_price = self.get_gas_price().await;
        let gas_price_eth = gas_price.legacy_gwei * 1e9 / 1e18;
        gas_estimate as f64 * gas_price_eth
    }
    
    /// Verifica viabilidade de flashloan
    pub fn can_flashloan(&self, amount_eth: f64) -> bool {
        self.config.flashloan_enabled && amount_eth <= self.config.max_flashloan_eth
    }
    
    /// Estima lucro considerando flashloan
    pub fn estimate_flashloan_profit(&self, required_capital: f64, profit: f64) -> f64 {
        if !self.can_flashloan(required_capital) {
            return profit; // Sem flashloan
        }
        
        let flashloan_fee = required_capital * 0.0009; // 0.09% Aave/Uniswap
        profit - flashloan_fee
    }
    
    /// Registra pool Uniswap para simulação
    pub fn register_pool(&mut self, token_symbol: &str, pool_address: &str) {
        self.pool_simulators.insert(
            token_symbol.to_string(),
            Arc::new(Mutex::new(UniswapV2Simulator::new(pool_address))),
        );
    }
    
    /// Atualiza todos os pools
    pub async fn update_all_pools(&self, forensics: &ForensicsEngine) {
        for (_, pool) in &self.pool_simulators {
            let mut pool_guard = pool.lock().unwrap();
            let _ = pool_guard.update_reserves(forensics).await;
        }
    }
}

// ============================================================
// FUNÇÃO PRINCIPAL MELHORADA
// ============================================================

pub async fn calculate_economic_value(
    paths: Vec<ControlFlowPathWithProb>,
    contract: &str,
    forensics: &ForensicsEngine,
) -> Vec<ExploitPathWithValue> {
    let economic_engine = RealTimeEconomicEngine::new(EconomicConfig::default());
    let mut results = Vec::new();
    
    for path_prob in paths {
        let (value_eth, value_usd, liquidity_impact, execution_cost) = calculate_path_value_advanced(
            &path_prob.path, contract, forensics, &economic_engine
        ).await;
        
        let net_profit = value_eth - execution_cost;
        let risk_adjusted = net_profit * path_prob.probability;
        
        results.push(ExploitPathWithValue {
            path: path_prob.path.clone(),
            probability: path_prob.probability,
            economic_value_eth: value_eth,
            economic_value_usd: value_usd,
            risk_adjusted_value: risk_adjusted,
            liquidity_impact,
            execution_cost_eth: execution_cost,
            net_profit_eth: net_profit,
        });
    }
    
    results.sort_by(|a, b| b.risk_adjusted_value.total_cmp(&a.risk_adjusted_value));
    results
}

async fn calculate_path_value_advanced(
    path: &ControlFlowPath,
    contract: &str,
    forensics: &ForensicsEngine,
    economic_engine: &RealTimeEconomicEngine,
) -> (f64, f64, f64, f64) {
    let mut total_eth = 0.0;
    let mut total_usd = 0.0;
    let mut max_liquidity_impact: f64 = 0.0;
    
    // Saldo atual do contrato
    let contract_balance = forensics.get_balance(contract).await.unwrap_or(0);
    let contract_balance_eth = contract_balance as f64 / 1e18;
    
    // Preço ETH atual
    let eth_price = economic_engine.get_price("ETH", "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE", None).await;
    
    for change in &path.state_changes {
        match change {
            StateChange::SelfDestruct(_) => {
                total_eth += contract_balance_eth;
                total_usd += contract_balance_eth * eth_price;
            }
            StateChange::Transfer(amount, Some(token_addr)) => {
                let token_price = economic_engine.get_price("", token_addr, None).await;
                let amount_eth = *amount as f64 / 1e18;
                let impact = economic_engine.simulate_slippage(amount_eth, contract_balance_eth, "");
                max_liquidity_impact = max_liquidity_impact.max(impact);
                
                let amount_with_slippage = amount_eth * (1.0 - impact);
                total_eth += amount_with_slippage * token_price;
                total_usd += amount_with_slippage * token_price;
            }
            StateChange::Transfer(amount, None) => {
                let amount_eth = *amount as f64 / 1e18;
                total_eth += amount_eth;
                total_usd += amount_eth * eth_price;
            }
            StateChange::Mint(amount, token_addr) => {
                let token_price = economic_engine.get_price("", token_addr, None).await;
                let amount_eth = *amount as f64 / 1e18;
                
                // Simula venda do mint com slippage
                let impact = economic_engine.simulate_slippage(amount_eth, contract_balance_eth, "");
                let amount_after_slippage = amount_eth * (1.0 - impact);
                
                total_eth += amount_after_slippage * token_price;
                total_usd += amount_after_slippage * token_price;
                max_liquidity_impact = max_liquidity_impact.max(impact);
            }
            StateChange::Delegatecall(target) => {
                // Delegatecall pode permitir drenagem completa
                total_eth += contract_balance_eth;
                total_usd += contract_balance_eth * eth_price;
                
                // Verifica se target tem funções de drenagem
                if let Ok(code) = forensics.eth_call(target, target, "0x", "0x0").await {
                    if code.contains("withdraw") || code.contains("drain") || code.contains("sweep") {
                        total_eth += contract_balance_eth;
                        total_usd += contract_balance_eth * eth_price;
                    }
                }
            }
            StateChange::Call(target, value, calldata) => {
                let value_eth = *value as f64 / 1e18;
                total_eth += value_eth;
                total_usd += value_eth * eth_price;
                
                // Verifica se é chamada para swap
                if calldata.len() >= 4 {
                    let selector = &calldata[0..4];
                    if selector == [0x38, 0xed, 0x17, 0x39] { // swapExactTokensForTokens
                        // Pode gerar lucro adicional
                        total_eth += contract_balance_eth * 0.2; // Estimativa conservadora
                    }
                }
            }
            StateChange::StorageWrite(slot, _) => {
                if *slot == 0 {
                    // Ownership change - valor de controle do contrato
                    let ownership_value = contract_balance_eth * 0.3;
                    total_eth += ownership_value;
                    total_usd += ownership_value * eth_price;
                }
            }
            _ => {}
        }
    }
    
    // Custo de gas em ETH
    let gas_cost_eth = economic_engine.calculate_execution_cost(path.gas_estimate).await;
    
    // Considera flashloan se necessário
    let required_capital = total_eth.max(contract_balance_eth);
    let flashloan_adjusted_profit = economic_engine.estimate_flashloan_profit(required_capital, total_eth);
    
    let final_eth = (total_eth - gas_cost_eth).max(0.0);
    let final_eth_with_flashloan = flashloan_adjusted_profit.min(final_eth);
    
    (final_eth_with_flashloan, final_eth_with_flashloan * eth_price, max_liquidity_impact, gas_cost_eth)
}

// ============================================================
// FUNÇÕES ORIGINAIS (mantidas para compatibilidade)
// ============================================================

#[allow(dead_code)]
async fn get_token_price(token_address: &str) -> f64 {
    let engine = RealTimeEconomicEngine::new(EconomicConfig::default());
    engine.get_price("", token_address, None).await
}

#[allow(dead_code)]
fn get_gas_price_gwei() -> f64 {
    20.0
}

#[allow(dead_code)]
async fn calculate_path_value(
    path: &ControlFlowPath,
    contract: &str,
    forensics: &ForensicsEngine,
) -> f64 {
    let economic_engine = RealTimeEconomicEngine::new(EconomicConfig::default());
    let (value_eth, _, _, _) = calculate_path_value_advanced(path, contract, forensics, &economic_engine).await;
    value_eth
}

// ============================================================
// TESTES
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_slippage_calculation() {
        let engine = RealTimeEconomicEngine::new(EconomicConfig::default());
        
        // Pequena trade em pool grande
        let slippage_small = engine.simulate_slippage(1.0, 1000.0, "ETH");
        assert!(slippage_small < 0.01);
        
        // Grande trade em pool pequeno
        let slippage_large = engine.simulate_slippage(500.0, 1000.0, "ETH");
        assert!(slippage_large > 0.1);
        assert!(slippage_large <= 0.5);
    }
    
    #[test]
    fn test_flashloan_profit() {
        let engine = RealTimeEconomicEngine::new(EconomicConfig::default());
        
        let profit = engine.estimate_flashloan_profit(100.0, 10.0);
        assert!(profit < 10.0);
        assert!(profit > 9.9); // ~0.09% fee
    }
}
