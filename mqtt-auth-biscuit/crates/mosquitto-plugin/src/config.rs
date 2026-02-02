use crate::policy::{PolicyBackendConfig, PolicyMode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::collections::HashSet;
use std::ffi::CStr;
#[cfg(not(miri))]
use std::fs;
use thiserror::Error;

const MIN_HTTP_TIMEOUT_SECONDS: u64 = 1;
const MAX_HTTP_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Configuration errors using thiserror for better error handling
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("JWT algorithm is required")]
    MissingJwtAlgorithm,

    #[error("JWT key file is required for algorithm {0}")]
    MissingJwtKey(String),

    #[error("Invalid JWT algorithm: {0}")]
    InvalidJwtAlgorithm(String),

    #[error("Failed to read JWT key file '{path}': {source}")]
    JwtKeyFileError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Invalid JWT public key PEM: {0}")]
    InvalidJwtPem(String),

    #[error("Invalid biscuit root key hex: {0}")]
    InvalidBiscuitKeyHex(String),

    #[error("Biscuit root key must be exactly 32 bytes, got {0}")]
    InvalidBiscuitKeyLength(usize),

    #[error("Invalid biscuit root public key: {0}")]
    InvalidBiscuitPublicKey(String),

    #[error("Failed to read biscuit public key file '{path}': {source}")]
    BiscuitKeyFileError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Biscuit root public key is required")]
    MissingBiscuitKey,

    #[error("Invalid biscuit role fact predicate: {0}")]
    InvalidBiscuitRoleFact(String),

    #[allow(dead_code)]
    #[error("Invalid policy mode: {0}")]
    InvalidPolicyMode(String),

    #[allow(dead_code)]
    #[error("Invalid cache TTL seconds: {0}")]
    InvalidCacheTtl(String),
}

#[derive(Clone)]
pub struct JwtConfig {
    pub decoding_key: DecodingKey,
    pub validation: Validation,
}

#[derive(Clone)]
pub struct BiscuitConfig {
    pub root_public_key: biscuit_auth::PublicKey,
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

#[derive(Clone)]
pub struct PluginConfig {
    pub jwt: JwtConfig,
    pub biscuit: BiscuitConfig,
    pub policy: PolicyBackendConfig,
    pub cache_ttl_seconds: u64,
    pub ext_auth_method: Option<String>,
    pub role_username_prefix: String,
    pub biscuit_role_fact: String,
}

/// Builder for PluginConfig with fluent interface and validation
pub struct PluginConfigBuilder {
    jwt_alg: Option<String>,
    jwt_key_file: Option<String>,
    jwt_issuer: Option<String>,
    jwt_audience: Option<String>,
    biscuit_root_key_file: Option<String>,
    policy_mode: Option<PolicyMode>,
    sqlite_path: Option<String>,
    http_url: Option<String>,
    http_ca_file: Option<String>,
    http_tls_insecure: Option<bool>,
    http_timeout_seconds: Option<u64>,
    http_max_response_bytes: Option<u64>,
    dynamic_security_url: Option<String>,
    dynamic_security_username: Option<String>,
    dynamic_security_password: Option<String>,
    dynamic_security_reload_interval_seconds: Option<u64>,
    cache_ttl_seconds: Option<u64>,
    ext_auth_method: Option<String>,
    role_username_prefix: Option<String>,
    biscuit_role_fact: Option<String>,
}

impl Default for PluginConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginConfigBuilder {
    pub fn new() -> Self {
        Self {
            jwt_alg: None,
            jwt_key_file: None,
            jwt_issuer: None,
            jwt_audience: None,
            biscuit_root_key_file: None,
            policy_mode: None,
            sqlite_path: None,
            http_url: None,
            http_ca_file: None,
            http_tls_insecure: None,
            http_timeout_seconds: None,
            http_max_response_bytes: None,
            dynamic_security_url: None,
            dynamic_security_username: None,
            dynamic_security_password: None,
            dynamic_security_reload_interval_seconds: None,
            cache_ttl_seconds: None,
            ext_auth_method: None,
            role_username_prefix: None,
            biscuit_role_fact: None,
        }
    }

    pub fn jwt_algorithm(mut self, alg: impl Into<String>) -> Self {
        self.jwt_alg = Some(alg.into());
        self
    }

    pub fn jwt_key_file(mut self, path: impl Into<String>) -> Self {
        self.jwt_key_file = Some(path.into());
        self
    }

    pub fn jwt_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.jwt_issuer = Some(issuer.into());
        self
    }

    pub fn jwt_audience(mut self, audience: impl Into<String>) -> Self {
        self.jwt_audience = Some(audience.into());
        self
    }

    pub fn biscuit_root_key_file(mut self, path: impl Into<String>) -> Self {
        self.biscuit_root_key_file = Some(path.into());
        self
    }

    pub fn policy_mode(mut self, mode: PolicyMode) -> Self {
        self.policy_mode = Some(mode);
        self
    }

    pub fn sqlite_path(mut self, path: impl Into<String>) -> Self {
        self.sqlite_path = Some(path.into());
        self
    }

    pub fn http_url(mut self, url: impl Into<String>) -> Self {
        self.http_url = Some(url.into());
        self
    }

    pub fn http_ca_file(mut self, path: impl Into<String>) -> Self {
        self.http_ca_file = Some(path.into());
        self
    }

    pub fn http_tls_insecure(mut self, enabled: bool) -> Self {
        self.http_tls_insecure = Some(enabled);
        self
    }

    pub fn http_timeout_seconds(mut self, seconds: u64) -> Self {
        self.http_timeout_seconds = Some(seconds);
        self
    }

    pub fn http_max_response_bytes(mut self, bytes: u64) -> Self {
        self.http_max_response_bytes = Some(bytes);
        self
    }

    pub fn dynamic_security_url(mut self, url: impl Into<String>) -> Self {
        self.dynamic_security_url = Some(url.into());
        self
    }

    pub fn dynamic_security_username(mut self, username: impl Into<String>) -> Self {
        self.dynamic_security_username = Some(username.into());
        self
    }

    pub fn dynamic_security_password(mut self, password: impl Into<String>) -> Self {
        self.dynamic_security_password = Some(password.into());
        self
    }

    pub fn dynamic_security_reload_interval_seconds(mut self, seconds: u64) -> Self {
        self.dynamic_security_reload_interval_seconds = Some(seconds);
        self
    }

    pub fn cache_ttl_seconds(mut self, ttl: u64) -> Self {
        self.cache_ttl_seconds = Some(ttl);
        self
    }

    pub fn ext_auth_method(mut self, method: impl Into<String>) -> Self {
        self.ext_auth_method = Some(method.into());
        self
    }

    pub fn role_username_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.role_username_prefix = Some(prefix.into());
        self
    }

    pub fn biscuit_role_fact(mut self, fact: impl Into<String>) -> Self {
        self.biscuit_role_fact = Some(fact.into());
        self
    }

    pub fn build(self) -> Result<PluginConfig, ConfigError> {
        let jwt_alg = self.jwt_alg.ok_or(ConfigError::MissingJwtAlgorithm)?;

        let alg = match jwt_alg.as_str() {
            "ES256" => Algorithm::ES256,
            _ => return Err(ConfigError::InvalidJwtAlgorithm(jwt_alg)),
        };

        let jwt_key_file = self
            .jwt_key_file
            .ok_or_else(|| ConfigError::MissingJwtKey(jwt_alg.clone()))?;

        #[cfg(not(miri))]
        let decoding_key = match alg {
            Algorithm::ES256 => {
                let pem = fs::read(&jwt_key_file).map_err(|e| ConfigError::JwtKeyFileError {
                    path: jwt_key_file,
                    source: e,
                })?;
                DecodingKey::from_ec_pem(&pem)
                    .map_err(|e| ConfigError::InvalidJwtPem(e.to_string()))?
            }
            _ => return Err(ConfigError::InvalidJwtAlgorithm(jwt_alg)),
        };

        #[cfg(miri)]
        let decoding_key = {
            let _ = jwt_key_file;
            DecodingKey::from_secret(b"miri_dummy_key".as_slice())
        };

        let mut validation = Validation::new(alg);
        if let Some(iss) = self.jwt_issuer {
            validation.iss = Some(HashSet::from([iss]));
        }
        if let Some(aud) = self.jwt_audience {
            validation.aud = Some(HashSet::from([aud]));
        }

        let pub_hex = match self.biscuit_root_key_file {
            #[cfg(not(miri))]
            Some(path) => {
                let raw = fs::read_to_string(&path)
                    .map_err(|e| ConfigError::BiscuitKeyFileError { path, source: e })?;
                raw.trim().to_string()
            }
            #[cfg(miri)]
            Some(_) => {
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()
            }
            None => return Err(ConfigError::MissingBiscuitKey),
        };
        let bytes =
            hex::decode(pub_hex).map_err(|e| ConfigError::InvalidBiscuitKeyHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(ConfigError::InvalidBiscuitKeyLength(bytes.len()));
        }
        let biscuit_root_public_key =
            biscuit_auth::PublicKey::from_bytes(&bytes, biscuit_auth::Algorithm::Ed25519)
                .map_err(|e| ConfigError::InvalidBiscuitPublicKey(e.to_string()))?;

        let policy = PolicyBackendConfig {
            mode: self.policy_mode.unwrap_or(PolicyMode::TokenOnly),
            sqlite_path: self.sqlite_path,
            http_url: self.http_url,
            http_ca_file: self.http_ca_file,
            http_tls_insecure: self.http_tls_insecure.unwrap_or(false),
            http_timeout_seconds: self.http_timeout_seconds.unwrap_or(2),
            http_max_response_bytes: self.http_max_response_bytes.unwrap_or(64 * 1024),
            dynamic_security_url: self.dynamic_security_url,
            dynamic_security_reload_interval_seconds: self.dynamic_security_reload_interval_seconds,
            dynamic_security_username: self.dynamic_security_username,
            dynamic_security_password: self.dynamic_security_password,
        };

        let cache_ttl_seconds = self.cache_ttl_seconds.unwrap_or(3600);

        let biscuit_role_fact = self.biscuit_role_fact.unwrap_or_else(|| "role".to_string());
        if !is_simple_identifier(&biscuit_role_fact) {
            return Err(ConfigError::InvalidBiscuitRoleFact(biscuit_role_fact));
        }

        Ok(PluginConfig {
            jwt: JwtConfig {
                decoding_key,
                validation,
            },
            biscuit: BiscuitConfig {
                root_public_key: biscuit_root_public_key,
            },
            policy,
            cache_ttl_seconds,
            ext_auth_method: self.ext_auth_method.or_else(|| Some("token".to_string())),
            role_username_prefix: self
                .role_username_prefix
                .unwrap_or_else(|| "role:".to_string()),
            biscuit_role_fact,
        })
    }
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
    let mut builder = PluginConfigBuilder::new();

    if option_count < 0 {
        return Err("Invalid option_count".to_string());
    }
    if option_count > 0 && options.is_null() {
        return Err("Invalid options pointer".to_string());
    }

    for i in 0..option_count {
        let opt_ptr = unsafe { options.add(i as usize) };
        let Some((key, value)) = opt_kv(opt_ptr) else {
            continue;
        };

        builder = match key.as_str() {
            "jwt_alg" => builder.jwt_algorithm(value),
            "jwt_key_file" => builder.jwt_key_file(value),
            "jwt_issuer" => builder.jwt_issuer(value),
            "jwt_audience" => builder.jwt_audience(value),
            "biscuit_root_key_file" => builder.biscuit_root_key_file(value),
            "policy_mode" => {
                let mode = match value.as_str() {
                    "token" => PolicyMode::TokenOnly,
                    "static_acl" => PolicyMode::StaticAcl,
                    "static_acl_strict" => PolicyMode::StaticAclStrict,
                    "sqlite" => PolicyMode::Sqlite,
                    "http" => PolicyMode::Http,
                    "hybrid" => PolicyMode::Hybrid,
                    "dynamic_security" => PolicyMode::DynamicSecurity,
                    _ => return Err(format!("Invalid policy_mode: {value}")),
                };
                builder.policy_mode(mode)
            }
            "sqlite_path" => builder.sqlite_path(value),
            "http_url" => builder.http_url(value),
            "http_ca_file" => builder.http_ca_file(value),
            "http_tls_insecure" => {
                let enabled = value
                    .parse::<bool>()
                    .map_err(|e| format!("Invalid http_tls_insecure: {e}"))?;
                builder.http_tls_insecure(enabled)
            }
            "http_timeout_seconds" => {
                let seconds = value
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid http_timeout_seconds: {e}"))?;
                if seconds < MIN_HTTP_TIMEOUT_SECONDS {
                    return Err("http_timeout_seconds must be >= 1".to_string());
                }
                builder.http_timeout_seconds(seconds)
            }
            "http_max_response_bytes" => {
                let bytes = value
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid http_max_response_bytes: {e}"))?;
                if bytes == 0 {
                    return Err("http_max_response_bytes must be > 0".to_string());
                }
                if bytes > MAX_HTTP_RESPONSE_BYTES {
                    return Err(format!(
                        "http_max_response_bytes must be <= {MAX_HTTP_RESPONSE_BYTES}"
                    ));
                }
                builder.http_max_response_bytes(bytes)
            }
            "dynamic_security_url" => builder.dynamic_security_url(value),
            "dynamic_security_username" => builder.dynamic_security_username(value),
            "dynamic_security_password" => builder.dynamic_security_password(value),
            "dynamic_security_reload_interval_seconds" => {
                let seconds = value.parse::<u64>().map_err(|e| {
                    format!("Invalid dynamic_security_reload_interval_seconds: {e}")
                })?;
                builder.dynamic_security_reload_interval_seconds(seconds)
            }
            "cache_ttl_seconds" => {
                let ttl = value
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid cache_ttl_seconds: {e}"))?;
                builder.cache_ttl_seconds(ttl)
            }
            "ext_auth_method" => builder.ext_auth_method(value),
            "role_username_prefix" => builder.role_username_prefix(value),
            "biscuit_role_fact" => builder.biscuit_role_fact(value),
            _ => builder,
        };
    }

    builder.build().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, PluginConfigBuilder};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rejects_invalid_biscuit_role_fact() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let result = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .biscuit_role_fact("role($x)")
            .build();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidBiscuitRoleFact(_))
        ));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn accepts_valid_biscuit_role_fact() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let result = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .biscuit_role_fact("device_role")
            .build();

        assert!(result.is_ok());
    }
}
