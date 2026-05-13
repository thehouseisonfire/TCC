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

fn is_simple_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn non_empty_owned(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

#[derive(Debug, Deserialize)]
struct BiscuitIssueRequest {
    client_id: Option<String>,
    topic: Option<String>,
    identity_fact_predicate: Option<String>,
    identity_fact_value: Option<String>,
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

/// Binary token response for MQTT transport (raw Protobuf, no `Base64URL`)
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

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
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

#[derive(Debug)]
enum IssueResponse {
    Token(TokenResponse),
    Binary(BinaryTokenResponse),
}

#[derive(Debug)]
enum IssueError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl IssueError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    fn into_response_parts(self) -> (StatusCode, String) {
        match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message),
            Self::Internal(message) => (StatusCode::INTERNAL_SERVER_ERROR, message),
        }
    }
}

struct JwtIdentityClaims {
    subject: String,
    client_id: Option<String>,
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

fn resolve_jwt_identity_claims(req: &JwtIssueRequest) -> JwtIdentityClaims {
    let subject = non_empty_owned(req.subject.clone())
        .or_else(|| non_empty_owned(req.client_id.clone()))
        .unwrap_or_else(|| "client_1".to_string());

    JwtIdentityClaims {
        subject,
        client_id: non_empty_owned(req.client_id.clone()),
    }
}

fn build_jwt_claims(req: JwtIssueRequest, cfg: &IssuerConfig, now: i64) -> JwtClaims {
    let ttl = req.ttl_seconds.unwrap_or(3600).max(1);
    let exp = now + ttl;
    let identity = resolve_jwt_identity_claims(&req);
    let subject = identity.subject;

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

    JwtClaims {
        sub: subject,
        exp,
        roles,
        grants,
        denies,
        iss: req.issuer.or_else(|| cfg.jwt_default_issuer.clone()),
        aud: req.audience.or_else(|| cfg.jwt_default_audience.clone()),
        client_id: identity.client_id,
    }
}

fn handle_jwt(req: JwtIssueRequest, cfg: &IssuerConfig) -> Result<TokenResponse, String> {
    let now = Utc::now().timestamp();
    let claims = build_jwt_claims(req, cfg, now);
    let exp = claims.exp;
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
) -> Result<(Vec<u8>, i64, i64), IssueError> {
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
        .map_err(|e| IssueError::internal(format!("biscuit fact publish: {e}")))?
        .fact(subscribe_fact.as_str())
        .map_err(|e| IssueError::internal(format!("biscuit fact subscribe: {e}")))?
        .fact(expires_fact.as_str())
        .map_err(|e| IssueError::internal(format!("biscuit fact expires_at: {e}")))?;

    match (
        req.identity_fact_predicate.as_deref(),
        req.identity_fact_value.as_deref(),
    ) {
        (Some(predicate), Some(value)) => {
            if !is_simple_identifier(predicate) {
                return Err(IssueError::bad_request(format!(
                    "invalid Biscuit identity fact predicate: {predicate}"
                )));
            }
            if value.is_empty() {
                return Err(IssueError::bad_request(
                    "Biscuit identity fact value must not be empty",
                ));
            }
            let predicate = escape_datalog_str(predicate);
            let value = escape_datalog_str(value);
            let identity_fact = format!("{predicate}(\"{value}\")");
            builder = builder
                .fact(identity_fact.as_str())
                .map_err(|e| IssueError::internal(format!("biscuit fact identity: {e}")))?;
        }
        (Some(_), None) => {
            return Err(IssueError::bad_request(
                "Biscuit identity fact invalid: identity_fact_value is required",
            ));
        }
        (None, Some(_)) => {
            return Err(IssueError::bad_request(
                "Biscuit identity fact invalid: identity_fact_predicate is required",
            ));
        }
        (None, None) => {}
    }

    if let Some(roles) = &req.roles {
        for role in roles {
            let role = escape_datalog_str(role);
            let role_fact = format!("role(\"{role}\")");
            builder = builder
                .fact(role_fact.as_str())
                .map_err(|e| IssueError::internal(format!("biscuit fact role: {e}")))?;
        }
    }

    if let Some(denies) = &req.denies {
        for deny in denies {
            let op = escape_datalog_str(&deny.op);
            let res = escape_datalog_str(&deny.res);
            let deny_fact = format!("deny(\"{op}\", \"{res}\")");
            builder = builder
                .fact(deny_fact.as_str())
                .map_err(|e| IssueError::internal(format!("biscuit fact deny: {e}")))?;
        }
    }

    let biscuit = builder
        .build(&cfg.biscuit_keypair)
        .map_err(|e| IssueError::internal(format!("biscuit build: {e}")))?;

    let check_src = format!("check if time($t), $t < {exp}");
    let block = BlockBuilder::new()
        .check(check_src.as_str())
        .map_err(|e| IssueError::internal(format!("biscuit check: {e}")))?
        .fact(expires_fact.as_str())
        .map_err(|e| IssueError::internal(format!("biscuit fact expires_at: {e}")))?;

    let biscuit = biscuit
        .append(block)
        .map_err(|e| IssueError::internal(format!("biscuit append: {e}")))?;
    let bytes = biscuit
        .to_vec()
        .map_err(|e| IssueError::internal(format!("biscuit encode: {e}")))?;

    Ok((bytes, exp, now))
}

fn handle_biscuit(
    req: &BiscuitIssueRequest,
    cfg: &IssuerConfig,
) -> Result<TokenResponse, IssueError> {
    let (bytes, exp, now) = build_biscuit_core(req, cfg)?;
    let token = general_purpose::URL_SAFE_NO_PAD.encode(&bytes);

    Ok(TokenResponse {
        token,
        exp,
        issued_at: now,
        alg: "Biscuit".to_string(),
    })
}

/// Generate a Biscuit token and return it in binary format (raw Protobuf)
/// for MQTT transport without `Base64URL` overhead.
fn handle_biscuit_binary(
    req: &BiscuitIssueRequest,
    cfg: &IssuerConfig,
) -> Result<BinaryTokenResponse, IssueError> {
    let (bytes, exp, now) = build_biscuit_core(req, cfg)?;

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

fn issue_request(url: &str, body: &[u8], cfg: &IssuerConfig) -> Result<IssueResponse, IssueError> {
    match url {
        "/jwt" => {
            let req: JwtIssueRequest = serde_json::from_slice(body)
                .map_err(|e| IssueError::bad_request(format!("invalid json: {e}")))?;
            let response = handle_jwt(req, cfg).map_err(IssueError::internal)?;
            Ok(IssueResponse::Token(response))
        }
        "/biscuit" => {
            let req: BiscuitIssueRequest = serde_json::from_slice(body)
                .map_err(|e| IssueError::bad_request(format!("invalid json: {e}")))?;
            let response = handle_biscuit(&req, cfg)?;
            Ok(IssueResponse::Token(response))
        }
        "/biscuit/binary" => {
            let req: BiscuitIssueRequest = serde_json::from_slice(body)
                .map_err(|e| IssueError::bad_request(format!("invalid json: {e}")))?;
            let response = handle_biscuit_binary(&req, cfg)?;
            Ok(IssueResponse::Binary(response))
        }
        _ => Err(IssueError::NotFound("not found".to_string())),
    }
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

    let response = match issue_request(url.as_str(), &body, &cfg) {
        Ok(IssueResponse::Token(payload)) => json_response(StatusCode::OK, &payload),
        Ok(IssueResponse::Binary(payload)) => json_response(StatusCode::OK, &payload),
        Err(err) => {
            let (status, message) = err.into_response_parts();
            error_response(status, &message)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::{AuthorizerBuilder, PublicKey};

    fn test_cfg() -> IssuerConfig {
        let (jwt_alg, jwt_key, jwt_alg_label, jwt_default_issuer, jwt_default_audience) =
            load_jwt_key(true).expect("default JWT key should load");
        let biscuit_keypair =
            load_biscuit_keypair(true).expect("default Biscuit keypair should load");
        IssuerConfig {
            host: "127.0.0.1".to_string(),
            port: 8082,
            jwt_alg,
            jwt_key,
            jwt_alg_label,
            jwt_default_issuer,
            jwt_default_audience,
            biscuit_keypair,
            jwt_no_default_roles: false,
            jwt_no_default_grants: false,
            tls_config: None,
        }
    }

    fn decode_jwt_claims(token: &str) -> JwtClaims {
        let payload = token
            .split('.')
            .nth(1)
            .expect("JWT payload should be present");
        let bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("JWT payload should decode");
        serde_json::from_slice(&bytes).expect("JWT claims should parse")
    }

    fn parse_biscuit(bytes: &[u8], cfg: &IssuerConfig) -> Biscuit {
        let public_key = PublicKey::from_bytes(
            &cfg.biscuit_keypair.public().to_bytes(),
            biscuit_auth::Algorithm::Ed25519,
        )
        .expect("public key should parse");
        Biscuit::from(bytes, public_key).expect("Biscuit should parse")
    }

    fn biscuit_identity_values(biscuit: &Biscuit, predicate: &str) -> Vec<(String,)> {
        let mut authorizer = AuthorizerBuilder::new()
            .build(biscuit)
            .expect("authorizer should build");
        authorizer
            .query_all(format!("data($id) <- {predicate}($id)").as_str())
            .expect("identity query should succeed")
    }

    fn issue_status(path: &str, body: &serde_json::Value, cfg: &IssuerConfig) -> StatusCode {
        let bytes = serde_json::to_vec(body).expect("body should serialize");
        let err = issue_request(path, &bytes, cfg).expect_err("request should fail");
        err.into_response_parts().0
    }

    #[test]
    fn jwt_subject_is_issued_without_client_id_claim() {
        let cfg = test_cfg();
        let response = handle_jwt(
            JwtIssueRequest {
                client_id: None,
                subject: Some("client_7".to_string()),
                roles: Some(vec!["reader".to_string()]),
                grants: None,
                denies: None,
                ttl_seconds: Some(60),
                issuer: None,
                audience: None,
                no_default_roles: Some(false),
                no_default_grants: Some(true),
            },
            &cfg,
        )
        .expect("JWT should be issued");

        let claims = decode_jwt_claims(&response.token);
        assert_eq!(claims.sub, "client_7");
        assert_eq!(claims.client_id, None);
    }

    #[test]
    fn jwt_subject_and_client_id_are_emitted_when_requested() {
        let cfg = test_cfg();
        let response = handle_jwt(
            JwtIssueRequest {
                client_id: Some("client_7".to_string()),
                subject: Some("client_7".to_string()),
                roles: Some(vec!["reader".to_string()]),
                grants: None,
                denies: None,
                ttl_seconds: Some(60),
                issuer: None,
                audience: None,
                no_default_roles: Some(false),
                no_default_grants: Some(true),
            },
            &cfg,
        )
        .expect("JWT should be issued");

        let claims = decode_jwt_claims(&response.token);
        assert_eq!(claims.sub, "client_7");
        assert_eq!(claims.client_id.as_deref(), Some("client_7"));
    }

    #[test]
    fn jwt_subject_and_client_id_do_not_require_global_match() {
        let cfg = test_cfg();
        let response = handle_jwt(
            JwtIssueRequest {
                client_id: Some("client_8".to_string()),
                subject: Some("client_7".to_string()),
                roles: Some(vec!["reader".to_string()]),
                grants: None,
                denies: None,
                ttl_seconds: Some(60),
                issuer: None,
                audience: None,
                no_default_roles: Some(false),
                no_default_grants: Some(true),
            },
            &cfg,
        )
        .expect("JWT should be issued");

        let claims = decode_jwt_claims(&response.token);
        assert_eq!(claims.sub, "client_7");
        assert_eq!(claims.client_id.as_deref(), Some("client_8"));
    }

    #[test]
    fn biscuit_identity_fact_is_added_when_requested() {
        let cfg = test_cfg();
        let (bytes, _, _) = build_biscuit_core(
            &BiscuitIssueRequest {
                client_id: Some("client_7".to_string()),
                topic: None,
                identity_fact_predicate: Some("client_id".to_string()),
                identity_fact_value: Some("client_7".to_string()),
                roles: None,
                denies: None,
                ttl_seconds: Some(60),
            },
            &cfg,
        )
        .expect("Biscuit should be issued");

        let biscuit = parse_biscuit(&bytes, &cfg);
        let identities = biscuit_identity_values(&biscuit, "client_id");
        assert_eq!(identities, vec![("client_7".to_string(),)]);
    }

    #[test]
    fn biscuit_identity_fact_requires_both_fields() {
        let cfg = test_cfg();
        let err = build_biscuit_core(
            &BiscuitIssueRequest {
                client_id: Some("client_7".to_string()),
                topic: None,
                identity_fact_predicate: Some("client_id".to_string()),
                identity_fact_value: None,
                roles: None,
                denies: None,
                ttl_seconds: Some(60),
            },
            &cfg,
        )
        .expect_err("partial Biscuit identity fact input must fail");
        let (status, message) = err.into_response_parts();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("identity_fact_value is required"));
    }

    #[test]
    fn biscuit_request_reports_missing_identity_value_as_bad_request() {
        let cfg = test_cfg();
        let status = issue_status(
            "/biscuit",
            &serde_json::json!({
                "client_id": "client_7",
                "identity_fact_predicate": "client_id"
            }),
            &cfg,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn biscuit_request_reports_invalid_identity_predicate_as_bad_request() {
        let cfg = test_cfg();
        let status = issue_status(
            "/biscuit",
            &serde_json::json!({
                "client_id": "client_7",
                "identity_fact_predicate": "client-id",
                "identity_fact_value": "client_7"
            }),
            &cfg,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn biscuit_binary_request_reports_missing_identity_predicate_as_bad_request() {
        let cfg = test_cfg();
        let status = issue_status(
            "/biscuit/binary",
            &serde_json::json!({
                "client_id": "client_7",
                "identity_fact_value": "client_7"
            }),
            &cfg,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn biscuit_binary_request_reports_empty_identity_value_as_bad_request() {
        let cfg = test_cfg();
        let status = issue_status(
            "/biscuit/binary",
            &serde_json::json!({
                "client_id": "client_7",
                "identity_fact_predicate": "client_id",
                "identity_fact_value": ""
            }),
            &cfg,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn legacy_jwt_and_biscuit_requests_keep_default_behavior() {
        let cfg = test_cfg();
        let jwt_response = handle_jwt(
            JwtIssueRequest {
                client_id: Some("client_1".to_string()),
                subject: None,
                roles: None,
                grants: None,
                denies: None,
                ttl_seconds: Some(60),
                issuer: None,
                audience: None,
                no_default_roles: None,
                no_default_grants: Some(true),
            },
            &cfg,
        )
        .expect("legacy JWT request should still work");
        let jwt_claims = decode_jwt_claims(&jwt_response.token);
        assert_eq!(jwt_claims.sub, "client_1");
        assert_eq!(jwt_claims.client_id.as_deref(), Some("client_1"));

        let (bytes, _, _) = build_biscuit_core(
            &BiscuitIssueRequest {
                client_id: Some("client_1".to_string()),
                topic: None,
                identity_fact_predicate: None,
                identity_fact_value: None,
                roles: None,
                denies: None,
                ttl_seconds: Some(60),
            },
            &cfg,
        )
        .expect("legacy Biscuit request should still work");
        let biscuit = parse_biscuit(&bytes, &cfg);
        let identities = biscuit_identity_values(&biscuit, "client_id");
        assert!(identities.is_empty());
    }
}
