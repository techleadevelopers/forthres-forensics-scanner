use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScannerChain {
    Ethereum,
    Arbitrum,
    Bnb,
}

impl ScannerChain {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScannerChain::Ethereum => "ethereum",
            ScannerChain::Arbitrum => "arbitrum",
            ScannerChain::Bnb => "bnb",
        }
    }

    pub fn env_prefix(&self) -> &'static str {
        match self {
            ScannerChain::Ethereum => "ETHEREUM",
            ScannerChain::Arbitrum => "ARBITRUM",
            ScannerChain::Bnb => "BNB",
        }
    }

    pub fn env_suffix(&self) -> &'static str {
        match self {
            ScannerChain::Ethereum => "ETHEREUM",
            ScannerChain::Arbitrum => "ARBITRUM",
            ScannerChain::Bnb => "BNB",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub chain: ScannerChain,
    pub chain_id: u64,
    pub anvil_url: String,
    pub output_dir: String,
    pub http_endpoints: Vec<String>,
    pub ws_endpoints: Vec<String>,
}

impl ScannerConfig {
    pub fn from_env() -> Result<Self> {
        let chain = parse_chain(
            std::env::var("SCANNER_CHAIN")
                .ok()
                .as_deref()
                .unwrap_or("ethereum"),
        )?;
        Self::from_env_for_chain(chain)
    }

    pub fn from_env_for_chain(chain: ScannerChain) -> Result<Self> {
        let chain_id = read_chain_id(chain)?
            .or_else(|| {
                std::env::var("SCANNER_CHAIN_ID")
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .unwrap_or(default_chain_id(chain));

        let anvil_url = read_chain_var(chain, "TENDERLY_FORK_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:8545".to_string());

        let output_dir = std::env::var("SCANNER_OUTPUT_DIR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "reports".to_string());

        let http_endpoints = parse_chain_endpoints(chain, "HTTP_ENDPOINTS", "RPC_HTTP_ENDPOINTS")?;
        let ws_endpoints = parse_chain_endpoints(chain, "WS_ENDPOINTS", "RPC_WS_ENDPOINTS")?;

        Ok(Self {
            chain,
            chain_id,
            anvil_url,
            output_dir,
            http_endpoints,
            ws_endpoints,
        })
    }
}

pub fn parse_chain(value: &str) -> Result<ScannerChain> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ethereum" => Ok(ScannerChain::Ethereum),
        "arbitrum" => Ok(ScannerChain::Arbitrum),
        "bnb" => Ok(ScannerChain::Bnb),
        other => anyhow::bail!("Unsupported SCANNER_CHAIN: {other}"),
    }
}

fn parse_values(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>()
}

fn parse_chain_endpoints(chain: ScannerChain, suffix: &str, fallback: &str) -> Result<Vec<String>> {
    let chain_name = format!("{}_{}", chain.env_prefix(), suffix);
    let endpoints = if std::env::var_os(&chain_name).is_some() {
        parse_values(&chain_name)
    } else {
        parse_values(fallback)
    };

    if endpoints.is_empty() {
        anyhow::bail!(
            "{} is required. Configure live RPC endpoints in .env.local or inject them from the api-server runtime.",
            chain_name
        );
    }

    Ok(endpoints)
}

fn read_chain_var(chain: ScannerChain, base_name: &str) -> Result<String> {
    let chain_specific = format!("{}_{}", base_name, chain.env_suffix());
    if let Ok(value) = std::env::var(&chain_specific) {
        return Ok(value);
    }

    Ok(std::env::var(base_name)?)
}

fn read_chain_id(chain: ScannerChain) -> Result<Option<u64>> {
    let chain_name = format!("{}_CHAIN_ID", chain.env_prefix());
    if let Ok(value) = std::env::var(&chain_name) {
        let parsed = value
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("{chain_name} must be a positive integer"))?;
        if parsed == 0 {
            anyhow::bail!("{chain_name} must be a positive integer");
        }
        return Ok(Some(parsed));
    }

    Ok(None)
}

fn default_chain_id(chain: ScannerChain) -> u64 {
    match chain {
        ScannerChain::Ethereum => 1,
        ScannerChain::Arbitrum => 42161,
        ScannerChain::Bnb => 56,
    }
}
