use anyhow::Result;

#[derive(Debug, Clone, Copy)]
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
        let chain_id = std::env::var("SCANNER_CHAIN_ID")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1);

        let anvil_url = std::env::var("ANVIL_RPC_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:8545".to_string());

        let output_dir = std::env::var("SCANNER_OUTPUT_DIR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "reports".to_string());

        let http_endpoints = parse_endpoints("RPC_HTTP_ENDPOINTS")?;
        let ws_endpoints = parse_endpoints("RPC_WS_ENDPOINTS")?;

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

fn parse_chain(value: &str) -> Result<ScannerChain> {
    match value.trim().to_ascii_lowercase().as_str() {
        "ethereum" => Ok(ScannerChain::Ethereum),
        "arbitrum" => Ok(ScannerChain::Arbitrum),
        "bnb" => Ok(ScannerChain::Bnb),
        other => anyhow::bail!("Unsupported SCANNER_CHAIN: {other}"),
    }
}

fn parse_endpoints(name: &str) -> Result<Vec<String>> {
    let endpoints = std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();

    if endpoints.is_empty() {
        anyhow::bail!(
            "{} is required. Configure live RPC endpoints in .env.local or inject them from the api-server runtime.",
            name
        );
    }

    Ok(endpoints)
}
