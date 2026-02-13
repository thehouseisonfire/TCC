// authz-server2: Hyper 1.0 + Tower + tokio-rustls implementation
// - Hyper 1.x HTTP/2-only server (no HTTP/1.1, no upgrades)
// - Uses http-body-util for request body handling
// - Lock-free config with arc-swap
// - Strongly-typed enums for modes
// - Graceful shutdown via Ctrl-C
// - Per-connection semaphore for backpressure
// - Fixed http2::Builder executor
// - Simplified service with TowerToHyperService

use std::{convert::Infallible, env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, body::Incoming, server::conn::http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::RngExt;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::Semaphore, task};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

// ------------------- Config types -------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
enum FailMode {
    #[default]
    None,
    Always,
    Rate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
enum AllowMode {
    AllowAll,
    DenyAll,
    #[default]
    TopicPrefix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppConfig {
    delay_ms: u64,
    fail_mode: FailMode,
    fail_rate: f64,
    allow_mode: AllowMode,
    topic_prefix: String,
    max_conns: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            delay_ms: 0,
            fail_mode: FailMode::None,
            fail_rate: 0.0,
            allow_mode: AllowMode::TopicPrefix,
            topic_prefix: "sensors/".to_string(),
            max_conns: 1024,
        }
    }
}

impl AppConfig {
    fn from_env() -> Self {
        let delay_ms = env::var("AUTHZ_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let fail_mode = env::var("AUTHZ_FAIL_MODE")
            .ok()
            .and_then(|s| match s.to_ascii_lowercase().as_str() {
                "none" => Some(FailMode::None),
                "always" => Some(FailMode::Always),
                "rate" => Some(FailMode::Rate),
                _ => None,
            })
            .unwrap_or_default();

        let fail_rate = env::var("AUTHZ_FAIL_RATE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0);

        let allow_mode = env::var("AUTHZ_ALLOW_MODE")
            .ok()
            .and_then(|s| match s.to_ascii_lowercase().as_str() {
                "allow_all" => Some(AllowMode::AllowAll),
                "deny_all" => Some(AllowMode::DenyAll),
                "topic_prefix" => Some(AllowMode::TopicPrefix),
                _ => None,
            })
            .unwrap_or_default();

        let topic_prefix =
            env::var("AUTHZ_TOPIC_PREFIX").unwrap_or_else(|_| "sensors/".to_string());

        let max_conns = env::var("AUTHZ_MAX_CONNS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);

        Self {
            delay_ms,
            fail_mode,
            fail_rate,
            allow_mode,
            topic_prefix,
            max_conns,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ConfigUpdate {
    delay_ms: Option<u64>,
    fail_mode: Option<FailMode>,
    fail_rate: Option<f64>,
    allow_mode: Option<AllowMode>,
    topic_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    #[serde(default)]
    topic: String,
}

struct AppState {
    config: Arc<ArcSwap<AppConfig>>,
    conn_sema: Arc<Semaphore>,
    max_conns: usize,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            conn_sema: self.conn_sema.clone(),
            max_conns: self.max_conns,
        }
    }
}

// ------------------- Utilities -------------------

fn json_response_bytes(status: StatusCode, bytes: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(bytes))
        .unwrap()
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(payload) {
        Ok(body) => json_response_bytes(status, Bytes::from(body)),
        Err(_) => json_response_bytes(StatusCode::INTERNAL_SERVER_ERROR, Bytes::from_static(b"{}")),
    }
}

// ------------------- Request handler -------------------

async fn handle(
    req: Request<Incoming>,
    state: AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method, path.as_str()) {
        (Method::GET, "/health") => {
            let body = serde_json::json!({"ok": true});
            Ok(json_response(StatusCode::OK, &body))
        }

        (Method::POST, "/config") => {
            // collect body
            let collected = match req.into_body().collect().await {
                Ok(full) => full,
                Err(e) => {
                    error!(%e, "failed reading body");
                    let body = serde_json::json!({"error": "invalid body"});
                    return Ok(json_response(StatusCode::BAD_REQUEST, &body));
                }
            };

            let bytes = collected.to_bytes();

            let update: ConfigUpdate = match serde_json::from_slice(&bytes) {
                Ok(u) => u,
                Err(e) => {
                    error!(%e, "invalid json for config update");
                    let body = serde_json::json!({"error": "invalid json"});
                    return Ok(json_response(StatusCode::BAD_REQUEST, &body));
                }
            };

            let current = state.config.load_full();
            let mut next = (*current).clone();

            if let Some(v) = update.delay_ms {
                next.delay_ms = v;
            }
            if let Some(v) = update.fail_mode {
                next.fail_mode = v;
            }
            if let Some(v) = update.fail_rate {
                next.fail_rate = v;
            }
            if let Some(v) = update.allow_mode {
                next.allow_mode = v;
            }
            if let Some(v) = update.topic_prefix {
                next.topic_prefix = v;
            }

            state.config.store(Arc::new(next.clone()));

            let body = serde_json::json!({
                "ok": true,
                "delay_ms": next.delay_ms,
                "fail_mode": next.fail_mode,
                "fail_rate": next.fail_rate,
                "allow_mode": next.allow_mode,
                "topic_prefix": next.topic_prefix,
            });

            Ok(json_response(StatusCode::OK, &body))
        }

        (Method::POST, "/authorize") => {
            let collected = match req.into_body().collect().await {
                Ok(full) => full,
                Err(e) => {
                    error!(%e, "failed reading body");
                    let body = serde_json::json!({"error": "invalid body"});
                    return Ok(json_response(StatusCode::BAD_REQUEST, &body));
                }
            };

            let bytes = collected.to_bytes();

            let ar: AuthRequest = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    error!(%e, "invalid auth request json");
                    let body = serde_json::json!({"error": "invalid json"});
                    return Ok(json_response(StatusCode::BAD_REQUEST, &body));
                }
            };

            // Snapshot config
            let cfg_arc = state.config.load();
            let cfg = cfg_arc.as_ref().clone();

            // Apply async delay
            if cfg.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(cfg.delay_ms)).await;
            }

            // Fail mode handling
            match cfg.fail_mode {
                FailMode::Always => {
                    warn!("forced failure");
                    let body = serde_json::json!({"allow": false, "error": "forced failure"});
                    return Ok(json_response(StatusCode::SERVICE_UNAVAILABLE, &body));
                }
                FailMode::Rate => {
                    let r: f64 = rand::rng().random();
                    if r < cfg.fail_rate.clamp(0.0, 1.0) {
                        warn!(%r, "random failure triggered");
                        let body = serde_json::json!({"allow": false, "error": "random failure"});
                        return Ok(json_response(StatusCode::SERVICE_UNAVAILABLE, &body));
                    }
                }
                FailMode::None => {}
            }

            // Authorization logic
            let allowed = match cfg.allow_mode {
                AllowMode::AllowAll => true,
                AllowMode::DenyAll => false,
                AllowMode::TopicPrefix => ar.topic.starts_with(&cfg.topic_prefix),
            };

            debug!(topic = %ar.topic, allowed = allowed, "authorize");

            let body = serde_json::json!({"allow": allowed});
            Ok(json_response(StatusCode::OK, &body))
        }

        _ => {
            let body = serde_json::json!({"error": "not found"});
            Ok(json_response(StatusCode::NOT_FOUND, &body))
        }
    }
}

// ------------------- TLS helpers -------------------

fn load_certs_and_key(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| anyhow::anyhow!("failed to parse TLS cert: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse TLS cert: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("no TLS certificates found");
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| anyhow::anyhow!("failed to parse TLS key: {e}"))?;

    Ok((certs, key))
}

fn make_rustls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<ServerConfig> {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(cfg)
}

// ------------------- Main -------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let log_level = env::var("AUTHZ_LOG").unwrap_or_else(|_| "warn".to_string());
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    info!("starting authz-server (hyper 1.x)");

    let host = env::var("AUTHZ_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("AUTHZ_PORT").unwrap_or_else(|_| "8081".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    let shared_config = AppConfig::from_env();

    let state = AppState {
        config: Arc::new(ArcSwap::from_pointee(shared_config.clone())),
        conn_sema: Arc::new(Semaphore::new(shared_config.max_conns)),
        max_conns: shared_config.max_conns,
    };

    let use_tls = env::var("AUTHZ_TLS").unwrap_or_else(|_| "0".to_string());
    let use_tls = matches!(use_tls.as_str(), "1" | "true" | "TRUE");

    // Graceful shutdown signal
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let shutdown_signal = async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install ctrl-c handler");
        let _ = shutdown_tx.try_send(());
    };

    tokio::spawn(shutdown_signal);

    if use_tls {
        info!(%addr, "listening with TLS + HTTP/2");

        let cert_path = env::var("AUTHZ_TLS_CERT").expect("AUTHZ_TLS_CERT missing");
        let key_path = env::var("AUTHZ_TLS_KEY").expect("AUTHZ_TLS_KEY missing");

        let (certs, key) = load_certs_and_key(&PathBuf::from(cert_path), &PathBuf::from(key_path))?;
        let rustls_cfg = make_rustls_config(certs, key)?;
        let acceptor = TlsAcceptor::from(Arc::new(rustls_cfg));

        let listener = TcpListener::bind(addr).await?;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("shutdown requested");
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, peer) = match accept_res {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(%e, "accept failed");
                            continue;
                        }
                    };

                    let permit = match state.conn_sema.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            warn!("semaphore closed");
                            continue;
                        }
                    };

                    let acceptor = acceptor.clone();
                    let state_clone = state.clone();

                    task::spawn(async move {
                        let _permit = permit; // hold permit for lifetime of connection
                        let accept_result = acceptor.accept(stream).await;
                        match accept_result {
                            Ok(tls_stream) => {
                                let executor = TokioExecutor::new();
                                let mut builder = http2::Builder::new(executor);
                                builder.max_concurrent_streams(256);
                                builder.initial_connection_window_size(1024 * 1024);
                                builder.initial_stream_window_size(1024 * 1024);
                                let tls_io = TokioIo::new(tls_stream);
                                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                                    let state = state_clone.clone();
                                    async move { handle(req, state).await }
                                });
                                let serve_result = builder.serve_connection(tls_io, service).await;
                                if let Err(e) = serve_result {
                                    warn!(%e, "tls h2 connection errored for {}", peer);
                                }
                            }
                            Err(e) => {
                                warn!(%e, "tls handshake failed for {}", peer);
                            }
                        }
                    });
                }
            }
        }
    } else {
        info!(%addr, "listening with h2c prior-knowledge (no TLS)");

        let listener = TcpListener::bind(addr).await?;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("shutdown requested");
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, peer) = match accept_res {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(%e, "accept failed");
                            continue;
                        }
                    };

                    let permit = match state.conn_sema.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            warn!("semaphore closed");
                            continue;
                        }
                    };

                    let state_clone = state.clone();

                    task::spawn(async move {
                        let _permit = permit; // hold permit for lifetime of connection
                        let executor = TokioExecutor::new();
                        let mut builder = http2::Builder::new(executor);
                        builder.max_concurrent_streams(256);
                        builder.initial_connection_window_size(1024 * 1024);
                        builder.initial_stream_window_size(1024 * 1024);
                        let stream_io = TokioIo::new(stream);
                        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                            let state = state_clone.clone();
                            async move { handle(req, state).await }
                        });
                        let serve_result = builder.serve_connection(stream_io, service).await;
                        if let Err(e) = serve_result {
                            warn!(%e, "h2c connection errored for {}", peer);
                        }
                    });
                }
            }
        }
    }

    info!("shutting down");
    Ok(())
}
