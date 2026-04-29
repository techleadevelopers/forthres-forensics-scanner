use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::StreamExt;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::{
    config::ScannerConfig,
    reporter::{EndpointHealthSnapshot, ScannerStatusSnapshot},
    scanner::{self, ForkMode, ScanMode, ScanRequest},
};

#[derive(Clone)]
struct AppState {
    config: Arc<ScannerConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanHttpRequest {
    #[serde(alias = "contract_address")]
    contract_address: String,
    mode: Option<String>,
    simulation: Option<bool>,
    fork: Option<String>,
}

pub async fn serve_http(config: ScannerConfig, addr: SocketAddr) -> Result<()> {
    let state = AppState {
        config: Arc::new(config),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/status", get(status))
        .route("/endpoints", get(endpoints))
        .route("/scan", post(scan))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "chain": state.config.chain.as_str(),
    }))
}

async fn status(State(state): State<AppState>) -> Result<Json<ScannerStatusSnapshot>, HttpError> {
    let snapshot = scanner::collect_status(&state.config)
        .await
        .map_err(HttpError::internal)?;
    Ok(Json(snapshot))
}

async fn endpoints(
    State(state): State<AppState>,
) -> Result<Json<Vec<EndpointHealthSnapshot>>, HttpError> {
    let snapshot = scanner::collect_endpoints(&state.config)
        .await
        .map_err(HttpError::internal)?;
    Ok(Json(snapshot))
}

async fn scan(
    State(state): State<AppState>,
    Json(body): Json<ScanHttpRequest>,
) -> Result<impl IntoResponse, HttpError> {
    if !is_valid_address(&body.contract_address) {
        return Err(HttpError::bad_request(
            "contractAddress must be a valid EVM address",
        ));
    }

    let request = ScanRequest {
        contract_address: body.contract_address.trim().to_string(),
        mode: parse_mode(body.mode.as_deref())?,
        simulation: body.simulation.unwrap_or(true),
        fork: parse_fork(body.fork.as_deref())?,
    };

    let config = Arc::clone(&state.config);
    let (tx, rx) = mpsc::unbounded_channel::<String>();

    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                let _ = tx.send(json!({
                    "type": "error",
                    "message": format!("failed to start scanner runtime: {err}"),
                })
                .to_string());
                return;
            }
        };

        runtime.block_on(async move {
            let emit = |payload: serde_json::Value| {
                let _ = tx.send(payload.to_string());
            };

            let result = scanner::scan_contract(&config, request, |event| {
                let payload = serde_json::to_value(&event).unwrap_or_else(|_| {
                    json!({ "type": "error", "message": "failed to serialize scan event" })
                });
                emit(payload);
            })
            .await;

            match result {
                Ok(report) => emit(json!({
                    "type": "complete",
                    "report": report,
                })),
                Err(err) => emit(json!({
                    "type": "error",
                    "message": err.to_string(),
                })),
            }
        });
    });

    let stream = UnboundedReceiverStream::new(rx)
        .map(|payload| Ok::<Event, std::convert::Infallible>(Event::default().data(payload)));

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[derive(Debug)]
struct HttpError {
    status: StatusCode,
    message: String,
}

impl HttpError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

fn parse_mode(value: Option<&str>) -> Result<ScanMode, HttpError> {
    match value.unwrap_or("fast").trim().to_ascii_lowercase().as_str() {
        "fast" => Ok(ScanMode::Fast),
        "deep" => Ok(ScanMode::Deep),
        _ => Err(HttpError::bad_request("mode must be fast or deep")),
    }
}

fn parse_fork(value: Option<&str>) -> Result<ForkMode, HttpError> {
    match value.unwrap_or("auto").trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(ForkMode::Auto),
        "force" => Ok(ForkMode::Force),
        "off" => Ok(ForkMode::Off),
        _ => Err(HttpError::bad_request("fork must be auto, force, or off")),
    }
}

fn is_valid_address(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() == 42
        && trimmed.starts_with("0x")
        && trimmed
            .chars()
            .skip(2)
            .all(|char| char.is_ascii_hexdigit())
}
