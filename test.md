cargo run -- scan --contract-address 0xdAC17F958D2ee523a2206206994597C13D831ec7 --mode deep --simulation true --fork force


cargo run -- scan --contract-address 0x0E04736A85433445EF602D07946671685eC94647 --mode deep --simulation true --fork force


# Para rodar o ghost-scanner
cargo run --bin ghost-scanner -- scan --contract-address 0x1af5bb53d00eaf7c689f34f1382d2cb9ed927303 --mode deep --simulation true --fork force

cargo run --bin exploit_executor


0x0E04736A85433445EF602D07946671685eC94647



# Já está certo
$env:SCANNER_CHAIN = "bnb"

# PRECISA SETAR O CHAIN ID CORRETO!
$env:SCANNER_CHAIN_ID = "56"

# RPCs da BSC (já deve ter)
$env:RPC_HTTP_ENDPOINTS = "https://bsc-dataseed.binance.org,https://bsc-dataseed1.binance.org,https://bsc-dataseed2.binance.org"

# Agora roda
cargo run --bin ghost-scanner -- scan `
  --contract-address 0x1Af5BB53d00eAF7C689F34f1382d2cb9Ed927303 `
  --mode deep `
  --simulation true `
  --fork force


  npx forthres-scan scan 0x1Af5BB53d00eAF7C689F34f1382d2cb9Ed927303 --chain ethereum --mode deep --api-key forthres_live_26cce86fde783d01b0822d4fc67aa230cb23ed65022f5fa7
$env:forthres_API_BASE_URL="https://forthres-api-server-production.up.railway.app"
$env:forthres_API_KEY="forthres_live_26cce86fde783d01b0822d4fc67aa230cb23ed65022f5fa7"

