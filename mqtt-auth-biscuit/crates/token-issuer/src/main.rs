use base64::{Engine as _, engine::general_purpose};
use biscuit_auth::{Biscuit, BlockBuilder, KeyPair, PrivateKey};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::SecretKey;
use pkcs8::{EncodePrivateKey, LineEnding};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::env;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// Type aliases to reduce complexity
type JwtKeyResult = Result<
    (
        Algorithm,
        EncodingKey,
        String,
        Option<String>,
        Option<String>,
    ),
    String,
>;

const DEFAULT_EC_SK_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const DEFAULT_BISCUIT_SK_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
struct JwtIssueRequest {
    client_id: Option<String>,
    subject: Option<String>,
    roles: Option<Vec<String>>,
    grants: Option<Vec<JwtGrant>>,
    denies: Option<Vec<JwtGrant>>,
    ttl_seconds: Option<i64>,
    issuer: Option<String>,
    audience: Option<String>,
    no_default_roles: Option<bool>,
    no_default_grants: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct JwtGrant {
    op: String,
    res: String,
}

fn load_tls_config(enabled: bool) -> Result<Option<Arc<ServerConfig>>, String> {
    if !enabled {
        return Ok(None);
    }
    let cert_path = env::var("TOKEN_ISSUER_TLS_CERT").map_err(|_| {
        "TOKEN_ISSUER_TLS_CERT required when TOKEN_ISSUER_TLS is enabled".to_string()
    })?;
    let key_path = env::var("TOKEN_ISSUER_TLS_KEY").map_err(|_| {
        "TOKEN_ISSUER_TLS_KEY required when TOKEN_ISSUER_TLS is enabled".to_string()
    })?;
    let certs = CertificateDer::pem_file_iter(&cert_path)
        .map_err(|e| format!("failed to parse TLS cert: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse TLS cert: {e}"))?;
    if certs.is_empty() {
        return Err("no TLS certificates found".to_string());
    }
    let key = PrivateKeyDer::from_pem_file(&key_path)
        .map_err(|e| format!("failed to parse TLS key: {e}"))?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config error: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Some(Arc::new(config)))
}

fn escape_datalog_str(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Debug, Deserialize)]
struct BiscuitIssueRequest {
    client_id: Option<String>,
    topic: Option<String>,
    roles: Option<Vec<String>>,
    denies: Option<Vec<JwtGrant>>,
    ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    token: String,
    exp: i64,
    issued_at: i64,
    alg: String,
}

/// Binary token response for MQTT v5 AUTH packet (raw Protobuf, no `Base64URL`)
#[derive(Debug, Serialize)]
struct BinaryTokenResponse {
    /// Base64-encoded binary data (for JSON transport)
    data_b64: String,
    exp: i64,
    issued_at: i64,
    alg: String,
    /// Size of the raw binary data in bytes
    size_bytes: usize,
}

struct IssuerConfig {
    host: String,
    port: u16,
    jwt_alg: Algorithm,
    jwt_key: EncodingKey,
    jwt_alg_label: String,
    jwt_default_issuer: Option<String>,
    jwt_default_audience: Option<String>,
    biscuit_keypair: KeyPair,
    jwt_no_default_roles: bool,
    jwt_no_default_grants: bool,
    tls_config: Option<Arc<ServerConfig>>,
}

fn env_default(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_flag(name: &str) -> bool {
    matches!(env::var(name).as_deref(), Ok("1" | "true" | "TRUE"))
}

fn parse_hex_key(hex_key: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(hex_key).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != expected_len {
        return Err(format!(
            "expected {expected_len} bytes, got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn load_jwt_key(allow_default_keys: bool) -> JwtKeyResult {
    let alg_raw = env_default("JWT_ALG", "ES256");
    let alg = match alg_raw.as_str() {
        "ES256" => Algorithm::ES256,
        _ => return Err(format!("unsupported JWT_ALG {alg_raw}")),
    };

    let key = match alg {
        Algorithm::ES256 => {
            let hex_key = env_default("JWT_EC_PRIVATE_KEY_HEX", DEFAULT_EC_SK_HEX);
            if hex_key == DEFAULT_EC_SK_HEX {
                if !allow_default_keys {
                    return Err(
                        "JWT_EC_PRIVATE_KEY_HEX must be set (default key disallowed)".to_string(),
                    );
                }
                eprintln!("warning: using default JWT_EC_PRIVATE_KEY_HEX (benchmark-only)");
            }
            let bytes = parse_hex_key(&hex_key, 32)?;
            let secret =
                SecretKey::from_slice(&bytes).map_err(|e| format!("invalid EC key: {e}"))?;
            let pem = secret
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| format!("pkcs8 encode failed: {e}"))?;
            EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| format!("ec pem parse: {e}"))?
        }
        _ => return Err("unsupported algorithm".to_string()),
    };

    let issuer = env::var("JWT_ISSUER").ok();
    let audience = env::var("JWT_AUDIENCE").ok();

    Ok((alg, key, alg_raw, issuer, audience))
}

fn load_biscuit_keypair(allow_default_keys: bool) -> Result<KeyPair, String> {
    let hex_key = env_default("BISCUIT_ROOT_PRIVATE_KEY_HEX", DEFAULT_BISCUIT_SK_HEX);
    if hex_key == DEFAULT_BISCUIT_SK_HEX {
        if !allow_default_keys {
            return Err(
                "BISCUIT_ROOT_PRIVATE_KEY_HEX must be set (default key disallowed)".to_string(),
            );
        }
        eprintln!("warning: using default BISCUIT_ROOT_PRIVATE_KEY_HEX (benchmark-only)");
    }
    let bytes = parse_hex_key(&hex_key, 32)?;
    let priv_key = PrivateKey::from_bytes(&bytes, biscuit_auth::Algorithm::Ed25519)
        .map_err(|e| format!("invalid Biscuit key: {e}"))?;
    Ok(KeyPair::from(&priv_key))
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"{}"))))
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let payload = serde_json::json!({"error": message});
    json_response(status, &payload)
}

fn handle_jwt(req: JwtIssueRequest, cfg: &IssuerConfig) -> Result<TokenResponse, String> {
    let now = Utc::now().timestamp();
    let ttl = req.ttl_seconds.unwrap_or(3600).max(1);
    let exp = now + ttl;
    let subject = req
        .subject
        .or(req.client_id.clone())
        .unwrap_or_else(|| "client_1".to_string());

    #[derive(Serialize)]
    struct Claims {
        sub: String,
        exp: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        grants: Option<Vec<JwtGrant>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        denies: Option<Vec<JwtGrant>>,
        iss: Option<String>,
        aud: Option<String>,
        client_id: Option<String>,
    }

    let no_default_roles = req.no_default_roles.unwrap_or(cfg.jwt_no_default_roles);
    let roles = if no_default_roles {
        req.roles
    } else {
        req.roles.or_else(|| Some(vec!["admin".to_string()]))
    };

    let no_default_grants = req.no_default_grants.unwrap_or(cfg.jwt_no_default_grants);
    let grants = if no_default_grants {
        req.grants
    } else {
        req.grants.or_else(|| {
            let topic = format!("sensors/{subject}/temp");
            Some(vec![
                JwtGrant {
                    op: "publish".to_string(),
                    res: topic.clone(),
                },
                JwtGrant {
                    op: "subscribe".to_string(),
                    res: topic,
                },
            ])
        })
    };

    let denies = req.denies;

    let claims = Claims {
        sub: subject,
        exp,
        roles,
        grants,
        denies,
        iss: req.issuer.or_else(|| cfg.jwt_default_issuer.clone()),
        aud: req.audience.or_else(|| cfg.jwt_default_audience.clone()),
        client_id: req.client_id,
    };

    let token = encode(&Header::new(cfg.jwt_alg), &claims, &cfg.jwt_key)
        .map_err(|e| format!("jwt encode failed: {e}"))?;

    Ok(TokenResponse {
        token,
        exp,
        issued_at: now,
        alg: cfg.jwt_alg_label.clone(),
    })
}

/// Build a Biscuit token from the request, returning the serialized bytes, expiry, and issued-at timestamp.
///
/// This helper centralizes the fact-building logic shared between `/biscuit` and `/biscuit/binary` endpoints.
fn build_biscuit_core(
    req: &BiscuitIssueRequest,
    cfg: &IssuerConfig,
) -> Result<(Vec<u8>, i64, i64), String> {
    let now = Utc::now().timestamp();
    let ttl = req.ttl_seconds.unwrap_or(3600).max(1);
    let exp = now + ttl;
    let client_id = req.client_id.as_deref().unwrap_or("client_1");
    let default_topic = format!("sensors/{client_id}/temp");
    let topic = req.topic.as_deref().unwrap_or(&default_topic);

    let topic = escape_datalog_str(topic);
    let publish_fact = format!("right(\"publish\", \"{topic}\")");
    let subscribe_fact = format!("right(\"subscribe\", \"{topic}\")");
    let expires_fact = format!("expires_at({exp})");
    let mut builder = Biscuit::builder()
        .fact(publish_fact.as_str())
        .map_err(|e| format!("biscuit fact publish: {e}"))?
        .fact(subscribe_fact.as_str())
        .map_err(|e| format!("biscuit fact subscribe: {e}"))?
        .fact(expires_fact.as_str())
        .map_err(|e| format!("biscuit fact expires_at: {e}"))?;

    if let Some(roles) = &req.roles {
        for role in roles {
            let role = escape_datalog_str(role);
            let role_fact = format!("role(\"{role}\")");
            builder = builder
                .fact(role_fact.as_str())
                .map_err(|e| format!("biscuit fact role: {e}"))?;
        }
    }

    if let Some(denies) = &req.denies {
        for deny in denies {
            let op = escape_datalog_str(&deny.op);
            let res = escape_datalog_str(&deny.res);
            let deny_fact = format!("deny(\"{op}\", \"{res}\")");
            builder = builder
                .fact(deny_fact.as_str())
                .map_err(|e| format!("biscuit fact deny: {e}"))?;
        }
    }

    let biscuit = builder
        .build(&cfg.biscuit_keypair)
        .map_err(|e| format!("biscuit build: {e}"))?;

    let check_src = format!("check if time($t), $t < {exp}");
    let block = BlockBuilder::new()
        .check(check_src.as_str())
        .map_err(|e| format!("biscuit check: {e}"))?
        .fact(expires_fact.as_str())
        .map_err(|e| format!("biscuit fact expires_at: {e}"))?;

    let biscuit = biscuit
        .append(block)
        .map_err(|e| format!("biscuit append: {e}"))?;
    let bytes = biscuit
        .to_vec()
        .map_err(|e| format!("biscuit encode: {e}"))?;

    Ok((bytes, exp, now))
}

fn handle_biscuit(req: BiscuitIssueRequest, cfg: &IssuerConfig) -> Result<TokenResponse, String> {
    let (bytes, exp, now) = build_biscuit_core(&req, cfg)?;
    let token = general_purpose::URL_SAFE_NO_PAD.encode(&bytes);

    Ok(TokenResponse {
        token,
        exp,
        issued_at: now,
        alg: "Biscuit".to_string(),
    })
}

/// Generate a Biscuit token and return it in binary format (raw Protobuf)
/// for MQTT v5 AUTH packet transport without `Base64URL` overhead.
fn handle_biscuit_binary(
    req: BiscuitIssueRequest,
    cfg: &IssuerConfig,
) -> Result<BinaryTokenResponse, String> {
    let (bytes, exp, now) = build_biscuit_core(&req, cfg)?;

    // Return raw binary data (base64-encoded for JSON transport, but represents raw Protobuf)
    let size_bytes = bytes.len();
    let data_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&bytes);

    Ok(BinaryTokenResponse {
        data_b64,
        exp,
        issued_at: now,
        alg: "Biscuit".to_string(),
        size_bytes,
    })
}

async fn handle_request(
    req: Request<Incoming>,
    cfg: Arc<IssuerConfig>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let url = req.uri().path().to_string();

    if method == Method::GET && url == "/health" {
        return Ok(json_response(
            StatusCode::OK,
            &serde_json::json!({"ok": true}),
        ));
    }

    if method != Method::POST {
        return Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
        ));
    }

    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                &format!("read body failed: {err}"),
            ));
        }
    };
    if body.len() > MAX_BODY_BYTES {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload too large",
        ));
    }

    let res: Result<TokenResponse, (StatusCode, String)> = match url.as_str() {
        "/jwt" => {
            let parsed: Result<JwtIssueRequest, _> = serde_json::from_slice(&body);
            match parsed {
                Ok(req) => {
                    handle_jwt(req, &cfg).map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))
                }
                Err(e) => Err((StatusCode::BAD_REQUEST, format!("invalid json: {e}"))),
            }
        }
        "/biscuit" => {
            let parsed: Result<BiscuitIssueRequest, _> = serde_json::from_slice(&body);
            match parsed {
                Ok(req) => handle_biscuit(req, &cfg)
                    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err)),
                Err(e) => Err((StatusCode::BAD_REQUEST, format!("invalid json: {e}"))),
            }
        }
        "/biscuit/binary" => {
            let parsed: Result<BiscuitIssueRequest, _> = serde_json::from_slice(&body);
            match parsed {
                Ok(req) => {
                    match handle_biscuit_binary(req, &cfg) {
                        Ok(binary_resp) => {
                            // Return as JSON with base64-encoded data
                            let body =
                                serde_json::to_vec(&binary_resp).unwrap_or_else(|_| b"{}".to_vec());
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap_or_else(|_| {
                                    Response::new(Full::new(Bytes::from_static(b"{}")))
                                }));
                        }
                        Err(err) => Err((StatusCode::INTERNAL_SERVER_ERROR, err)),
                    }
                }
                Err(e) => Err((StatusCode::BAD_REQUEST, format!("invalid json: {e}"))),
            }
        }
        _ => Err((StatusCode::NOT_FOUND, "not found".to_string())),
    };

    let response = match res {
        Ok(payload) => json_response(StatusCode::OK, &payload),
        Err((status, err)) => error_response(status, &err),
    };

    Ok(response)
}

async fn serve_connection<S>(stream: S, cfg: Arc<IssuerConfig>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| handle_request(req, Arc::clone(&cfg)));
    if let Err(e) = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await
    {
        eprintln!("http serve error: {e}");
    }
}

#[tokio::main]
async fn main() {
    let host = env_default("TOKEN_ISSUER_HOST", "0.0.0.0");
    let port = env_default("TOKEN_ISSUER_PORT", "8082");
    let allow_default_keys = env_flag("TOKEN_ISSUER_ALLOW_DEFAULT_KEYS");
    let jwt_no_default_roles = env_flag("JWT_NO_DEFAULT_ROLES");
    let jwt_no_default_grants = env_flag("JWT_NO_DEFAULT_GRANTS");
    let tls_enabled = env_flag("TOKEN_ISSUER_TLS");

    let (jwt_alg, jwt_key, jwt_alg_label, jwt_default_issuer, jwt_default_audience) =
        match load_jwt_key(allow_default_keys) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("token-issuer config error: {err}");
                std::process::exit(1);
            }
        };

    let biscuit_keypair = match load_biscuit_keypair(allow_default_keys) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("token-issuer config error: {err}");
            std::process::exit(1);
        }
    };

    let cfg = IssuerConfig {
        host: host.clone(),
        port: port.parse().unwrap_or(8082),
        jwt_alg,
        jwt_key,
        jwt_alg_label,
        jwt_default_issuer,
        jwt_default_audience,
        biscuit_keypair,
        jwt_no_default_roles,
        jwt_no_default_grants,
        tls_config: match load_tls_config(tls_enabled) {
            Ok(cfg) => cfg,
            Err(err) => {
                eprintln!("token-issuer tls config error: {err}");
                std::process::exit(1);
            }
        },
    };

    let addr = format!("{}:{}", cfg.host, cfg.port);
    let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        eprintln!("failed to bind token issuer on {addr}: {e}");
        std::process::exit(1);
    });
    let cfg = Arc::new(cfg);
    let tls_acceptor = cfg.tls_config.clone().map(TlsAcceptor::from);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };

        if let Some(acceptor) = tls_acceptor.clone() {
            let cfg = Arc::clone(&cfg);
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => serve_connection(tls_stream, cfg).await,
                    Err(e) => eprintln!("tls accept failed: {e}"),
                }
            });
        } else {
            let cfg = Arc::clone(&cfg);
            tokio::spawn(async move {
                serve_connection(stream, cfg).await;
            });
        }
    }
}
