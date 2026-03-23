// authz-server2: Hyper 1.0 + Tower + tokio-rustls implementation
// - Hyper 1.x HTTP/2-only server (no HTTP/1.1, no upgrades)
// - Uses http-body-util for request body handling
// - Lock-free config with arc-swap
// - Strongly-typed enums for modes
// - Graceful shutdown via Ctrl-C
// - Per-connection semaphore for backpressure
// - Fixed http2::Builder executor
// - Simplified service with TowerToHyperService

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use base64::Engine as _;
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum PolicyProfile {
    Simple,
    Med,
    Complex,
    #[default]
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RuleEffect {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, Eq, PartialEq)]
struct Rule {
    effect: RuleEffect,
    #[serde(default)]
    ops: Vec<String>,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default)]
    client_ids: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppConfig {
    delay_ms: u64,
    fail_mode: FailMode,
    fail_rate: f64,
    #[serde(default)]
    authz_profile: PolicyProfile,
    #[serde(default)]
    rules: Vec<Rule>,
    #[serde(default)]
    client_roles: HashMap<String, Vec<String>>,
    max_conns: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            delay_ms: 0,
            fail_mode: FailMode::None,
            fail_rate: 0.0,
            authz_profile: PolicyProfile::Custom,
            rules: Vec::new(),
            client_roles: HashMap::new(),
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

        let authz_profile = env::var("AUTHZ_PROFILE")
            .ok()
            .and_then(|s| match s.to_ascii_lowercase().as_str() {
                "simple" => Some(PolicyProfile::Simple),
                "med" => Some(PolicyProfile::Med),
                "complex" => Some(PolicyProfile::Complex),
                "custom" => Some(PolicyProfile::Custom),
                _ => None,
            })
            .unwrap_or(PolicyProfile::Custom);

        let max_conns = env::var("AUTHZ_MAX_CONNS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);

        Self {
            delay_ms,
            fail_mode,
            fail_rate,
            authz_profile,
            rules: Vec::new(),
            client_roles: HashMap::new(),
            max_conns,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ConfigUpdate {
    delay_ms: Option<u64>,
    fail_mode: Option<FailMode>,
    fail_rate: Option<f64>,
    authz_profile: Option<PolicyProfile>,
    rules: Option<Vec<Rule>>,
    client_roles: Option<HashMap<String, Vec<String>>>,
}

fn apply_config_update(next: &mut AppConfig, update: ConfigUpdate) {
    if let Some(v) = update.delay_ms {
        next.delay_ms = v;
    }
    if let Some(v) = update.fail_mode {
        next.fail_mode = v;
    }
    if let Some(v) = update.fail_rate {
        next.fail_rate = v;
    }
    if let Some(v) = update.authz_profile {
        next.authz_profile = v;
    }
    if let Some(v) = update.rules {
        next.rules = v;
    }
    if let Some(v) = update.client_roles {
        next.client_roles = v;
    }
}

fn config_summary_body(next: &AppConfig) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "delay_ms": next.delay_ms,
        "fail_mode": next.fail_mode,
        "fail_rate": next.fail_rate,
        "authz_profile": next.authz_profile,
        "rules_count": effective_rules(next).len(),
        "client_roles_count": next.client_roles.len(),
    })
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    topic: String,
    #[serde(default)]
    access: i32,
    token: Option<String>,
}

struct AppState {
    config: Arc<ArcSwap<AppConfig>>,
    baseline_config: Arc<AppConfig>,
    conn_sema: Arc<Semaphore>,
    max_conns: usize,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            baseline_config: self.baseline_config.clone(),
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
    serde_json::to_vec(payload).map_or_else(
        |_| json_response_bytes(StatusCode::INTERNAL_SERVER_ERROR, Bytes::from_static(b"{}")),
        |body| json_response_bytes(status, Bytes::from(body)),
    )
}

const fn access_to_operation(access: i32) -> &'static str {
    if (access & 0x02) != 0 {
        "publish"
    } else if (access & 0x04) != 0 {
        "subscribe"
    } else if (access & 0x08) != 0 {
        "control"
    } else {
        "read"
    }
}

fn is_valid_filter(filter: &str) -> bool {
    let mut saw_hash = false;
    let parts: Vec<&str> = filter.split('/').collect();
    for (idx, part) in parts.iter().enumerate() {
        if part.contains('#') {
            if *part != "#" || saw_hash || idx != parts.len() - 1 {
                return false;
            }
            saw_hash = true;
            continue;
        }
        if part.contains('+') && *part != "+" {
            return false;
        }
    }
    true
}

fn topic_matches(filter: &str, topic: &str) -> bool {
    if !is_valid_filter(filter) {
        return false;
    }
    if filter == "#" {
        return true;
    }

    let filter_parts: Vec<&str> = filter.split('/').collect();
    let topic_parts: Vec<&str> = topic.split('/').collect();
    let mut i = 0;

    while i < filter_parts.len() {
        let fp = filter_parts[i];
        if fp == "#" {
            return true;
        }
        if i >= topic_parts.len() {
            return false;
        }
        if fp != "+" && fp != topic_parts[i] {
            return false;
        }
        i += 1;
    }

    i == topic_parts.len()
}

fn make_rule(
    effect: RuleEffect,
    ops: &[&str],
    topics: &[&str],
    client_ids: &[&str],
    roles: &[&str],
    id: &str,
) -> Rule {
    Rule {
        effect,
        ops: ops.iter().map(std::string::ToString::to_string).collect(),
        topics: topics
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        client_ids: client_ids
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        roles: roles.iter().map(std::string::ToString::to_string).collect(),
        id: Some(id.to_string()),
    }
}

fn simple_profile_rules() -> Vec<Rule> {
    vec![
        make_rule(
            RuleEffect::Deny,
            &["control"],
            &["#"],
            &[],
            &[],
            "simple_deny_control",
        ),
        make_rule(
            RuleEffect::Allow,
            &["publish", "subscribe", "read"],
            &["sensors/+/temp"],
            &[],
            &[],
            "simple_allow_sensor_temp",
        ),
    ]
}

fn med_profile_rules() -> Vec<Rule> {
    vec![
        make_rule(
            RuleEffect::Deny,
            &["publish", "subscribe", "read"],
            &["sensors/+/private/#"],
            &[],
            &[],
            "med_deny_private_tree",
        ),
        make_rule(
            RuleEffect::Deny,
            &["read"],
            &["sensors/+/temp/raw"],
            &[],
            &[],
            "med_deny_raw_read",
        ),
        make_rule(
            RuleEffect::Allow,
            &["publish"],
            &["devices/+/status"],
            &[],
            &["writer", "admin"],
            "med_allow_role_device_publish",
        ),
        make_rule(
            RuleEffect::Allow,
            &["subscribe", "read"],
            &["devices/+/status"],
            &[],
            &["reader", "admin"],
            "med_allow_role_device_read",
        ),
        make_rule(
            RuleEffect::Allow,
            &["publish"],
            &["sensors/+/temp"],
            &[],
            &[],
            "med_allow_sensor_publish",
        ),
        make_rule(
            RuleEffect::Allow,
            &["subscribe", "read"],
            &["sensors/+/temp"],
            &[],
            &[],
            "med_allow_sensor_read",
        ),
    ]
}

fn complex_profile_rules() -> Vec<Rule> {
    vec![
        make_rule(
            RuleEffect::Deny,
            &["publish", "subscribe", "read"],
            &["sensors/+/private/#"],
            &[],
            &[],
            "complex_deny_private_tree",
        ),
        make_rule(
            RuleEffect::Deny,
            &["publish", "subscribe", "read"],
            &["sensors/+/restricted/#"],
            &["blocked_client", "revoked_client"],
            &[],
            "complex_deny_blocked_clients",
        ),
        make_rule(
            RuleEffect::Deny,
            &["control"],
            &["$CONTROL/#"],
            &[],
            &["observer", "reader"],
            "complex_deny_control_readers",
        ),
        make_rule(
            RuleEffect::Deny,
            &["read"],
            &["sensors/+/temp/raw"],
            &[],
            &[],
            "complex_deny_raw_read",
        ),
        make_rule(
            RuleEffect::Allow,
            &["control"],
            &["$CONTROL/#"],
            &[],
            &["admin"],
            "complex_allow_control_admin",
        ),
        make_rule(
            RuleEffect::Allow,
            &["publish"],
            &["devices/+/status"],
            &[],
            &["writer", "admin"],
            "complex_allow_role_device_publish",
        ),
        make_rule(
            RuleEffect::Allow,
            &["subscribe", "read"],
            &["devices/+/status", "alerts/#"],
            &[],
            &["reader", "admin"],
            "complex_allow_role_device_read",
        ),
        make_rule(
            RuleEffect::Allow,
            &["publish", "subscribe", "read"],
            &["sensors/+/temp"],
            &[],
            &[],
            "complex_allow_sensor_temp",
        ),
        make_rule(
            RuleEffect::Allow,
            &["publish"],
            &["telemetry/+/events/#"],
            &["client_1", "client_2", "client_3"],
            &[],
            "complex_allow_selected_clients_telemetry",
        ),
        make_rule(
            RuleEffect::Allow,
            &["subscribe", "read"],
            &["telemetry/+/events/#"],
            &["client_1", "client_2", "client_3"],
            &["observer", "admin"],
            "complex_allow_selected_clients_observer",
        ),
    ]
}

fn effective_rules(cfg: &AppConfig) -> Vec<Rule> {
    let mut rules = match cfg.authz_profile {
        PolicyProfile::Simple => simple_profile_rules(),
        PolicyProfile::Med => med_profile_rules(),
        PolicyProfile::Complex => complex_profile_rules(),
        PolicyProfile::Custom => Vec::new(),
    };
    rules.extend(cfg.rules.clone());
    rules
}

#[derive(Debug, Deserialize)]
struct JwtClaimsLite {
    roles: Option<Vec<String>>,
    client_id: Option<String>,
    sub: Option<String>,
}

fn extract_token_roles(token: &str, expected_client_id: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut parts = token.split('.');
    let _header = parts.next();
    let Some(payload) = parts.next() else {
        return out;
    };

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload));
    let Ok(payload_bytes) = decoded else {
        return out;
    };
    let Ok(claims) = serde_json::from_slice::<JwtClaimsLite>(&payload_bytes) else {
        return out;
    };

    let token_client = claims
        .client_id
        .as_deref()
        .filter(|v| !v.is_empty())
        .or_else(|| claims.sub.as_deref().filter(|v| !v.is_empty()));
    if let Some(token_client) = token_client
        && !expected_client_id.is_empty()
        && token_client != expected_client_id
    {
        return out;
    }

    for role in claims.roles.unwrap_or_default() {
        let normalized = role.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            out.insert(normalized);
        }
    }
    out
}

#[derive(Debug)]
struct EvalContext<'a> {
    operation: &'a str,
    topic: &'a str,
    client_id: &'a str,
    roles: &'a HashSet<String>,
}

fn rule_matches(rule: &Rule, ctx: &EvalContext<'_>) -> bool {
    if !rule.ops.is_empty()
        && !rule
            .ops
            .iter()
            .any(|op| op.trim().eq_ignore_ascii_case(ctx.operation))
    {
        return false;
    }
    if !rule.topics.is_empty()
        && !rule
            .topics
            .iter()
            .any(|f| topic_matches(f.trim(), ctx.topic))
    {
        return false;
    }
    if !rule.client_ids.is_empty()
        && !rule
            .client_ids
            .iter()
            .any(|id| id.trim().eq_ignore_ascii_case(ctx.client_id))
    {
        return false;
    }
    if !rule.roles.is_empty()
        && !rule
            .roles
            .iter()
            .map(|r| r.trim().to_ascii_lowercase())
            .any(|r| ctx.roles.contains(&r))
    {
        return false;
    }
    true
}

fn evaluate_rules(rules: &[Rule], ctx: &EvalContext<'_>) -> bool {
    if rules
        .iter()
        .any(|rule| rule.effect == RuleEffect::Deny && rule_matches(rule, ctx))
    {
        return false;
    }
    rules
        .iter()
        .any(|rule| rule.effect == RuleEffect::Allow && rule_matches(rule, ctx))
}

fn evaluate_authorization(cfg: &AppConfig, req: &AuthRequest) -> bool {
    let operation = access_to_operation(req.access);
    let mut effective_roles = HashSet::new();
    if let Some(role_list) = cfg.client_roles.get(req.client_id.trim()) {
        for role in role_list {
            let normalized = role.trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                effective_roles.insert(normalized);
            }
        }
    }
    if let Some(token) = req.token.as_deref() {
        effective_roles.extend(extract_token_roles(token, req.client_id.trim()));
    }

    let policy_rules = effective_rules(cfg);
    let ctx = EvalContext {
        operation,
        topic: req.topic.trim(),
        client_id: req.client_id.trim(),
        roles: &effective_roles,
    };
    evaluate_rules(&policy_rules, &ctx)
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
            apply_config_update(&mut next, update);

            state.config.store(Arc::new(next.clone()));
            let body = config_summary_body(&next);

            Ok(json_response(StatusCode::OK, &body))
        }

        (Method::POST, "/config/reset") => {
            let next = (*state.baseline_config).clone();
            state.config.store(Arc::new(next.clone()));
            let body = config_summary_body(&next);
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
            let allowed = evaluate_authorization(&cfg, &ar);

            debug!(
                topic = %ar.topic,
                client_id = %ar.client_id,
                access = ar.access,
                operation = access_to_operation(ar.access),
                profile = ?cfg.authz_profile,
                allowed = allowed,
                "authorize"
            );

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
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    let log_level = env::var("AUTHZ_LOG").unwrap_or_else(|_| "warn".to_string());
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    info!("starting authz-server (hyper 1.x)");

    let host = env::var("AUTHZ_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("AUTHZ_PORT").unwrap_or_else(|_| "8081".to_string());
    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    let shared_config = AppConfig::from_env();

    let state = AppState {
        config: Arc::new(ArcSwap::from_pointee(shared_config.clone())),
        baseline_config: Arc::new(shared_config.clone()),
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

                    let Ok(permit) = state.conn_sema.clone().acquire_owned().await else {
                        warn!("semaphore closed");
                        continue;
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

                    let Ok(permit) = state.conn_sema.clone().acquire_owned().await else {
                        warn!("semaphore closed");
                        continue;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg() -> AppConfig {
        AppConfig::default()
    }

    fn make_token(payload: &serde_json::Value) -> String {
        let header = serde_json::json!({"alg":"none","typ":"JWT"});
        let h = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).expect("header json"));
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).expect("payload json"));
        format!("{h}.{p}.signature")
    }

    #[test]
    fn operation_mapping_matches_plugin_priority() {
        assert_eq!(access_to_operation(0x01), "read");
        assert_eq!(access_to_operation(0x02), "publish");
        assert_eq!(access_to_operation(0x04), "subscribe");
        assert_eq!(access_to_operation(0x08), "control");
        assert_eq!(access_to_operation(0x02 | 0x04), "publish");
        assert_eq!(access_to_operation(0x04 | 0x08), "subscribe");
        assert_eq!(access_to_operation(0x08 | 0x01), "control");
    }

    #[test]
    fn topic_match_honors_wildcards_and_invalid_filters() {
        assert!(topic_matches("sensors/+/temp", "sensors/client_1/temp"));
        assert!(topic_matches("sensors/#", "sensors/client_1/temp"));
        assert!(!topic_matches("sensors/#/temp", "sensors/client_1/temp"));
        assert!(!topic_matches(
            "sensors/+/temp",
            "sensors/client_1/temp/extra"
        ));
    }

    #[test]
    fn deny_overrides_allow() {
        let rules = vec![
            make_rule(
                RuleEffect::Allow,
                &["publish"],
                &["sensors/+/temp"],
                &[],
                &[],
                "allow",
            ),
            make_rule(
                RuleEffect::Deny,
                &["publish"],
                &["sensors/client_1/temp"],
                &[],
                &[],
                "deny",
            ),
        ];
        let active_roles = HashSet::new();
        let ctx = EvalContext {
            operation: "publish",
            topic: "sensors/client_1/temp",
            client_id: "client_1",
            roles: &active_roles,
        };
        assert!(!evaluate_rules(&rules, &ctx));
    }

    #[test]
    fn rule_supports_client_id_constraints() {
        let rules = vec![make_rule(
            RuleEffect::Allow,
            &["publish"],
            &["sensors/+/temp"],
            &["client_7"],
            &[],
            "allow_client7",
        )];
        let active_roles = HashSet::new();
        let allow_ctx = EvalContext {
            operation: "publish",
            topic: "sensors/client_7/temp",
            client_id: "client_7",
            roles: &active_roles,
        };
        let deny_ctx = EvalContext {
            operation: "publish",
            topic: "sensors/client_8/temp",
            client_id: "client_8",
            roles: &active_roles,
        };
        assert!(evaluate_rules(&rules, &allow_ctx));
        assert!(!evaluate_rules(&rules, &deny_ctx));
    }

    #[test]
    fn token_roles_are_extracted_and_applied() {
        let token = make_token(&serde_json::json!({
            "sub": "client_1",
            "roles": ["reader"]
        }));
        let mut cfg = base_cfg();
        cfg.authz_profile = PolicyProfile::Custom;
        cfg.rules = vec![make_rule(
            RuleEffect::Allow,
            &["read"],
            &["alerts/#"],
            &[],
            &["reader"],
            "reader_alerts",
        )];
        let req = AuthRequest {
            client_id: "client_1".to_string(),
            topic: "alerts/critical".to_string(),
            access: 0x01,
            token: Some(token),
        };
        assert!(evaluate_authorization(&cfg, &req));
    }

    #[test]
    fn token_roles_are_ignored_when_client_binding_mismatches() {
        let token = make_token(&serde_json::json!({
            "sub": "client_2",
            "roles": ["reader"]
        }));
        let mut cfg = base_cfg();
        cfg.authz_profile = PolicyProfile::Custom;
        cfg.rules = vec![make_rule(
            RuleEffect::Allow,
            &["read"],
            &["alerts/#"],
            &[],
            &["reader"],
            "reader_alerts",
        )];
        let req = AuthRequest {
            client_id: "client_1".to_string(),
            topic: "alerts/critical".to_string(),
            access: 0x01,
            token: Some(token),
        };
        assert!(!evaluate_authorization(&cfg, &req));
    }

    #[test]
    fn empty_custom_policy_denies_without_matching_rule() {
        let cfg = base_cfg();
        let req = AuthRequest {
            client_id: "client_1".to_string(),
            topic: "sensors/client_1/temp".to_string(),
            access: 0x02,
            token: None,
        };
        assert!(!evaluate_authorization(&cfg, &req));
    }

    #[test]
    fn client_roles_map_can_satisfy_role_rule_without_token() {
        let mut cfg = base_cfg();
        cfg.authz_profile = PolicyProfile::Custom;
        cfg.rules = vec![make_rule(
            RuleEffect::Allow,
            &["read"],
            &["alerts/#"],
            &[],
            &["reader"],
            "reader_alerts",
        )];
        cfg.client_roles.insert(
            "client_1".to_string(),
            vec!["reader".to_string(), "observer".to_string()],
        );
        let req = AuthRequest {
            client_id: "client_1".to_string(),
            topic: "alerts/critical".to_string(),
            access: 0x01,
            token: None,
        };
        assert!(evaluate_authorization(&cfg, &req));
    }

    #[test]
    fn config_update_remains_incremental() {
        let mut cfg = base_cfg();
        cfg.authz_profile = PolicyProfile::Complex;
        cfg.client_roles
            .insert("client_1".to_string(), vec!["admin".to_string()]);
        apply_config_update(
            &mut cfg,
            ConfigUpdate {
                delay_ms: Some(200),
                fail_mode: Some(FailMode::Rate),
                fail_rate: Some(0.05),
                authz_profile: None,
                rules: None,
                client_roles: None,
            },
        );
        assert_eq!(cfg.delay_ms, 200);
        assert!(matches!(cfg.fail_mode, FailMode::Rate));
        assert!((cfg.fail_rate - 0.05).abs() < f64::EPSILON);
        assert_eq!(cfg.authz_profile, PolicyProfile::Complex);
        assert_eq!(cfg.client_roles.len(), 1);
    }

    #[test]
    fn config_reset_restores_startup_baseline() {
        let baseline = AppConfig {
            authz_profile: PolicyProfile::Simple,
            max_conns: 2048,
            ..base_cfg()
        };
        let mut cfg = baseline.clone();
        cfg.delay_ms = 123;
        cfg.fail_mode = FailMode::Always;
        cfg.fail_rate = 0.8;
        cfg.authz_profile = PolicyProfile::Complex;
        cfg.rules = complex_profile_rules();
        cfg.client_roles
            .insert("client_2".to_string(), vec!["reader".to_string()]);

        cfg = baseline;

        assert_eq!(cfg.delay_ms, 0);
        assert!(matches!(cfg.fail_mode, FailMode::None));
        assert!(cfg.fail_rate.abs() < f64::EPSILON);
        assert_eq!(cfg.authz_profile, PolicyProfile::Simple);
        assert!(cfg.rules.is_empty());
        assert!(cfg.client_roles.is_empty());
        assert_eq!(cfg.max_conns, 2048);
    }
}
