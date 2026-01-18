use base64::{engine::general_purpose, Engine as _};
use biscuit_auth::{Biscuit, BlockBuilder, KeyPair, PrivateKey};
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::SecretKey;
use pkcs8::{EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};
use std::env;
use tiny_http::{Header as TinyHeader, Method, Response, Server, SslConfig, StatusCode};

// Type aliases to reduce complexity
type JwtKeyResult = Result<(Algorithm, EncodingKey, String, Option<String>, Option<String>), String>;

const DEFAULT_EC_SK_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const DEFAULT_BISCUIT_SK_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
struct JwtIssueRequest {
    client_id: Option<String>,
    subject: Option<String>,
    roles: Option<Vec<String>>,
    ttl_seconds: Option<i64>,
    issuer: Option<String>,
    audience: Option<String>,
    no_default_roles: Option<bool>,
}

fn load_tls_config(enabled: bool) -> Result<Option<SslConfig>, String> {
    if !enabled {
        return Ok(None);
    }
    let cert_path = env::var("TOKEN_ISSUER_TLS_CERT")
        .map_err(|_| "TOKEN_ISSUER_TLS_CERT required when TOKEN_ISSUER_TLS is enabled".to_string())?;
    let key_path = env::var("TOKEN_ISSUER_TLS_KEY")
        .map_err(|_| "TOKEN_ISSUER_TLS_KEY required when TOKEN_ISSUER_TLS is enabled".to_string())?;
    let cert = std::fs::read(&cert_path)
        .map_err(|e| format!("failed to read {cert_path}: {e}"))?;
    let key = std::fs::read(&key_path)
        .map_err(|e| format!("failed to read {key_path}: {e}"))?;
    Ok(Some(SslConfig {
        certificate: cert,
        private_key: key,
    }))
}

fn escape_datalog_str(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Debug, Deserialize)]
struct BiscuitIssueRequest {
    client_id: Option<String>,
    topic: Option<String>,
    ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    token: String,
    exp: i64,
    issued_at: i64,
    alg: String,
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
    biscuit_base64url: bool,
    tls_config: Option<SslConfig>,
}

fn env_default(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_flag(name: &str) -> bool {
    matches!(env::var(name).as_deref(), Ok("1") | Ok("true") | Ok("TRUE"))
}

fn parse_hex_key(hex_key: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(hex_key).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != expected_len {
        return Err(format!("expected {expected_len} bytes, got {}", bytes.len()));
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
                    return Err("JWT_EC_PRIVATE_KEY_HEX must be set (default key disallowed)"
                        .to_string());
                }
                eprintln!("warning: using default JWT_EC_PRIVATE_KEY_HEX (benchmark-only)");
            }
            let bytes = parse_hex_key(&hex_key, 32)?;
            let secret = SecretKey::from_slice(&bytes).map_err(|e| format!("invalid EC key: {e}"))?;
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
            return Err("BISCUIT_ROOT_PRIVATE_KEY_HEX must be set (default key disallowed)"
                .to_string());
        }
        eprintln!("warning: using default BISCUIT_ROOT_PRIVATE_KEY_HEX (benchmark-only)");
    }
    let bytes = parse_hex_key(&hex_key, 32)?;
    let priv_key = PrivateKey::from_bytes(&bytes, biscuit_auth::Algorithm::Ed25519)
        .map_err(|e| format!("invalid Biscuit key: {e}"))?;
    Ok(KeyPair::from(&priv_key))
}


fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(payload).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::from_data(body);
    resp = resp.with_status_code(status);
    resp.add_header(TinyHeader::from_bytes("Content-Type", "application/json").unwrap());
    resp
}

fn error_response(status: StatusCode, message: &str) -> Response<std::io::Cursor<Vec<u8>>> {
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
        roles: Option<Vec<String>>,
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

    let claims = Claims {
        sub: subject,
        exp,
        roles,
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

fn handle_biscuit(req: BiscuitIssueRequest, cfg: &IssuerConfig) -> Result<TokenResponse, String> {
    let now = Utc::now().timestamp();
    let ttl = req.ttl_seconds.unwrap_or(3600).max(1);
    let exp = now + ttl;
    let client_id = req.client_id.unwrap_or_else(|| "client_1".to_string());
    let topic = req
        .topic
        .unwrap_or_else(|| format!("sensors/{client_id}/temp"));

    let topic = escape_datalog_str(&topic);
    let publish_fact = format!("right(\"publish\", \"{topic}\")");
    let subscribe_fact = format!("right(\"subscribe\", \"{topic}\")");
    let biscuit = Biscuit::builder()
        .fact(publish_fact.as_str())
        .map_err(|e| format!("biscuit fact publish: {e}"))?
        .fact(subscribe_fact.as_str())
        .map_err(|e| format!("biscuit fact subscribe: {e}"))?
        .build(&cfg.biscuit_keypair)
        .map_err(|e| format!("biscuit build: {e}"))?;

    let check_src = format!("check if time($t), $t < {exp}");
    let block = BlockBuilder::new()
        .check(check_src.as_str())
        .map_err(|e| format!("biscuit check: {e}"))?;

    let biscuit = biscuit.append(block).map_err(|e| format!("biscuit append: {e}"))?;
    let bytes = biscuit.to_vec().map_err(|e| format!("biscuit encode: {e}"))?;
    let token = if cfg.biscuit_base64url {
        general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
    } else {
        general_purpose::STANDARD.encode(&bytes)
    };

    Ok(TokenResponse {
        token,
        exp,
        issued_at: now,
        alg: "Biscuit".to_string(),
    })
}

fn main() {
    let host = env_default("TOKEN_ISSUER_HOST", "0.0.0.0");
    let port = env_default("TOKEN_ISSUER_PORT", "8082");
    let allow_default_keys = env_flag("TOKEN_ISSUER_ALLOW_DEFAULT_KEYS");
    let jwt_no_default_roles = env_flag("JWT_NO_DEFAULT_ROLES");
    let biscuit_base64url = env_flag("BISCUIT_BASE64URL");
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
        biscuit_base64url,
        tls_config: match load_tls_config(tls_enabled) {
            Ok(cfg) => cfg,
            Err(err) => {
                eprintln!("token-issuer tls config error: {err}");
                std::process::exit(1);
            }
        },
    };

    let addr = format!("{}:{}", cfg.host, cfg.port);
    let server = if let Some(tls_cfg) = cfg.tls_config.clone() {
        Server::https(&addr, tls_cfg).unwrap_or_else(|e| {
            eprintln!("failed to bind token issuer (TLS) on {addr}: {e}");
            std::process::exit(1);
        })
    } else {
        Server::http(&addr).unwrap_or_else(|e| {
            eprintln!("failed to bind token issuer on {addr}: {e}");
            std::process::exit(1);
        })
    };

    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        let url = request.url().to_string();

        if method == Method::Get && url == "/health" {
            let response = json_response(StatusCode(200), &serde_json::json!({"ok": true}));
            let _ = request.respond(response);
            continue;
        }

        if method != Method::Post {
            let response = error_response(StatusCode(405), "method not allowed");
            let _ = request.respond(response);
            continue;
        }

        let mut body = Vec::new();
        if let Err(e) = request.as_reader().read_to_end(&mut body) {
            let response = error_response(StatusCode(400), &format!("read body failed: {e}"));
            let _ = request.respond(response);
            continue;
        }
        if body.len() > MAX_BODY_BYTES {
            let response = error_response(StatusCode(413), "payload too large");
            let _ = request.respond(response);
            continue;
        }

        let res = match url.as_str() {
            "/jwt" => {
                let parsed: Result<JwtIssueRequest, _> = serde_json::from_slice(&body);
                match parsed {
                    Ok(req) => handle_jwt(req, &cfg),
                    Err(e) => Err(format!("invalid json: {e}")),
                }
            }
            "/biscuit" => {
                let parsed: Result<BiscuitIssueRequest, _> = serde_json::from_slice(&body);
                match parsed {
                    Ok(req) => handle_biscuit(req, &cfg),
                    Err(e) => Err(format!("invalid json: {e}")),
                }
            }
            _ => Err("not found".to_string()),
        };

        let response = match res {
            Ok(payload) => json_response(StatusCode(200), &payload),
            Err(err) if err == "not found" => error_response(StatusCode(404), &err),
            Err(err) => error_response(StatusCode(400), &err),
        };

        let _ = request.respond(response);
    }
}
