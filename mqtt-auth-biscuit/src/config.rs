use crate::policy::{PolicyBackendConfig, PolicyMode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::ffi::CStr;
use std::fs;

#[derive(Clone)]
pub struct JwtConfig {
    pub decoding_key: DecodingKey,
    pub validation: Validation,
    pub allow_hs256_fallback: bool,
}

#[derive(Clone)]
pub struct BiscuitConfig {
    pub root_public_key: biscuit_auth::PublicKey,
}

#[derive(Clone)]
pub struct PluginConfig {
    pub jwt: JwtConfig,
    pub biscuit: BiscuitConfig,
    pub policy: PolicyBackendConfig,
    pub cache_ttl_seconds: u64,
    pub ext_auth_method: Option<String>,
}

fn opt_kv(opt: *mut crate::MosquittoOpt) -> Option<(String, String)> {
    if opt.is_null() {
        return None;
    }
    unsafe {
        let k = (*opt).key;
        let v = (*opt).value;
        if k.is_null() || v.is_null() {
            return None;
        }
        let key = CStr::from_ptr(k).to_string_lossy().into_owned();
        let val = CStr::from_ptr(v).to_string_lossy().into_owned();
        Some((key, val))
    }
}

pub fn parse_options(
    options: *mut crate::MosquittoOpt,
    option_count: i32,
) -> Result<PluginConfig, String> {
    let mut jwt_alg = "HS256".to_string();
    let mut jwt_key_file: Option<String> = None;
    let mut jwt_hmac_secret: Option<String> = None;
    let mut jwt_issuer: Option<String> = None;
    let mut jwt_audience: Option<String> = None;

    let mut biscuit_root_key_hex: Option<String> = None;
    let mut biscuit_root_private_key_hex: Option<String> = None;

    let mut policy_mode = PolicyMode::TokenOnly;
    let mut sqlite_path: Option<String> = None;
    let mut http_url: Option<String> = None;

    let mut cache_ttl_seconds: u64 = 3600;
    let mut ext_auth_method: Option<String> = Some("token".to_string());

    for i in 0..option_count {
        let opt_ptr = unsafe { options.add(i as usize) };
        let Some((key, value)) = opt_kv(opt_ptr) else {
            continue;
        };

        match key.as_str() {
            "jwt_alg" => jwt_alg = value,
            "jwt_key_file" => jwt_key_file = Some(value),
            "jwt_hmac_secret" => jwt_hmac_secret = Some(value),
            "jwt_issuer" => jwt_issuer = Some(value),
            "jwt_audience" => jwt_audience = Some(value),
            "biscuit_root_key_hex" => biscuit_root_key_hex = Some(value),
            "biscuit_root_private_key_hex" => biscuit_root_private_key_hex = Some(value),
            "policy_mode" => {
                policy_mode = match value.as_str() {
                    "token" => PolicyMode::TokenOnly,
                    "sqlite" => PolicyMode::Sqlite,
                    "http" => PolicyMode::Http,
                    "hybrid" => PolicyMode::Hybrid,
                    _ => return Err(format!("Invalid policy_mode: {value}")),
                }
            }
            "sqlite_path" => sqlite_path = Some(value),
            "http_url" => http_url = Some(value),
            "cache_ttl_seconds" => {
                cache_ttl_seconds = value
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid cache_ttl_seconds: {e}"))?;
            }
            "ext_auth_method" => ext_auth_method = Some(value),
            _ => {}
        }
    }

    let alg = match jwt_alg.as_str() {
        "HS256" => Algorithm::HS256,
        "RS256" => Algorithm::RS256,
        "ES256" => Algorithm::ES256,
        _ => return Err(format!("Unsupported jwt_alg: {jwt_alg}")),
    };

    let decoding_key = match alg {
        Algorithm::HS256 => {
            let secret = jwt_hmac_secret
                .ok_or_else(|| "jwt_hmac_secret is required for HS256".to_string())?;
            DecodingKey::from_secret(secret.as_bytes())
        }
        Algorithm::RS256 => {
            let path =
                jwt_key_file.ok_or_else(|| "jwt_key_file is required for RS256".to_string())?;
            let pem = fs::read(path).map_err(|e| format!("Failed reading jwt_key_file: {e}"))?;
            DecodingKey::from_rsa_pem(&pem)
                .map_err(|e| format!("Invalid RSA public key PEM: {e}"))?
        }
        Algorithm::ES256 => {
            let path =
                jwt_key_file.ok_or_else(|| "jwt_key_file is required for ES256".to_string())?;
            let pem = fs::read(path).map_err(|e| format!("Failed reading jwt_key_file: {e}"))?;
            DecodingKey::from_ec_pem(&pem).map_err(|e| format!("Invalid EC public key PEM: {e}"))?
        }
        _ => return Err("Unsupported jwt_alg".to_string()),
    };

    let mut validation = Validation::new(alg);
    if let Some(iss) = jwt_issuer {
        validation.set_issuer(&[iss]);
    }
    if let Some(aud) = jwt_audience {
        validation.set_audience(&[aud]);
    }

    let biscuit_root_public_key = match (biscuit_root_key_hex, biscuit_root_private_key_hex) {
        (Some(pub_hex), _) => {
            let bytes =
                hex::decode(pub_hex).map_err(|e| format!("Invalid biscuit_root_key_hex: {e}"))?;
            if bytes.len() != 32 {
                return Err("biscuit_root_key_hex must decode to exactly 32 bytes".to_string());
            }
            biscuit_auth::PublicKey::from_bytes(&bytes, biscuit_auth::Algorithm::Ed25519)
                .map_err(|e| format!("Invalid biscuit root public key: {e}"))?
        }
        (None, Some(priv_hex)) => {
            let bytes = hex::decode(priv_hex)
                .map_err(|e| format!("Invalid biscuit_root_private_key_hex: {e}"))?;
            if bytes.len() != 32 {
                return Err(
                    "biscuit_root_private_key_hex must decode to exactly 32 bytes".to_string(),
                );
            }
            let priv_key =
                biscuit_auth::PrivateKey::from_bytes(&bytes, biscuit_auth::Algorithm::Ed25519)
                    .map_err(|e| format!("Invalid biscuit root private key: {e}"))?;
            let keypair = biscuit_auth::KeyPair::from(&priv_key);
            keypair.public()
        }
        (None, None) => {
            return Err(
                "biscuit_root_key_hex or biscuit_root_private_key_hex is required".to_string(),
            );
        }
    };

    let policy = PolicyBackendConfig {
        mode: policy_mode,
        sqlite_path,
        http_url,
    };

    Ok(PluginConfig {
        jwt: JwtConfig {
            decoding_key,
            validation,
            allow_hs256_fallback: false,
        },
        biscuit: BiscuitConfig {
            root_public_key: biscuit_root_public_key,
        },
        policy,
        cache_ttl_seconds,
        ext_auth_method,
    })
}
