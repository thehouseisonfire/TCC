use crate::policy::{PolicyBackendConfig, PolicyMode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::collections::HashSet;
use std::ffi::CStr;
#[cfg(not(miri))]
use std::fs;
use thiserror::Error;

const MIN_HTTP_TIMEOUT_SECONDS: u64 = 1;
const MAX_HTTP_RESPONSE_BYTES: u64 = 1024 * 1024;
const DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS: u64 = 25;
const MIN_BISCUIT_AUTHORIZER_MAX_TIME_MS: u64 = 1;

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
    pub sqlite_seed_demo_rules: bool,
    pub cache_ttl_seconds: u64,
    pub allow_anonymous_no_token: bool,
    pub acl_read_full_authz: bool,
    pub control_notify_topic_prefix: String,
    pub ext_auth_method: Option<String>,
    pub role_username_prefix: String,
    pub biscuit_role_fact: String,
    pub biscuit_authorizer_profile: BiscuitAuthorizerProfile,
    pub biscuit_authorizer_max_time_ms: u64,
    pub biscuit_transport: BiscuitTransportMode,
}

/// Transport mode for Biscuit tokens
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BiscuitTransportMode {
    /// Base64URL encoding (CONNECT password compatible, ~33% size overhead)
    Base64Url,
    /// Native Protobuf binary (MQTT v5 AUTH packet only, no overhead)
    Mqtt5AuthData,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BiscuitAuthorizerProfile {
    Simple,
    Rbac,
    Contextual,
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
    sqlite_seed_demo_rules: Option<bool>,
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
    allow_anonymous_no_token: Option<bool>,
    acl_read_full_authz: Option<bool>,
    control_notify_topic_prefix: Option<String>,
    ext_auth_method: Option<String>,
    role_username_prefix: Option<String>,
    biscuit_role_fact: Option<String>,
    biscuit_authorizer_profile: Option<BiscuitAuthorizerProfile>,
    biscuit_authorizer_max_time_ms: Option<u64>,
    biscuit_transport: Option<BiscuitTransportMode>,
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
            sqlite_seed_demo_rules: None,
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
            allow_anonymous_no_token: None,
            acl_read_full_authz: None,
            control_notify_topic_prefix: None,
            ext_auth_method: None,
            role_username_prefix: None,
            biscuit_role_fact: None,
            biscuit_authorizer_profile: None,
            biscuit_authorizer_max_time_ms: None,
            biscuit_transport: None,
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

    pub fn sqlite_seed_demo_rules(mut self, enabled: bool) -> Self {
        self.sqlite_seed_demo_rules = Some(enabled);
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

    pub fn allow_anonymous_no_token(mut self, enabled: bool) -> Self {
        self.allow_anonymous_no_token = Some(enabled);
        self
    }

    pub fn acl_read_full_authz(mut self, enabled: bool) -> Self {
        self.acl_read_full_authz = Some(enabled);
        self
    }

    pub fn control_notify_topic_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.control_notify_topic_prefix = Some(prefix.into());
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

    pub fn biscuit_authorizer_profile(mut self, profile: BiscuitAuthorizerProfile) -> Self {
        self.biscuit_authorizer_profile = Some(profile);
        self
    }

    pub fn biscuit_authorizer_max_time_ms(mut self, millis: u64) -> Self {
        self.biscuit_authorizer_max_time_ms = Some(millis);
        self
    }

    pub fn biscuit_transport(mut self, mode: BiscuitTransportMode) -> Self {
        self.biscuit_transport = Some(mode);
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

        let biscuit_transport = self
            .biscuit_transport
            .unwrap_or(BiscuitTransportMode::Base64Url);
        let biscuit_authorizer_profile = self
            .biscuit_authorizer_profile
            .unwrap_or(BiscuitAuthorizerProfile::Simple);
        let biscuit_authorizer_max_time_ms = self
            .biscuit_authorizer_max_time_ms
            .unwrap_or(DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS);
        let control_notify_topic_prefix = self
            .control_notify_topic_prefix
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("system_notification")
            .to_string();

        Ok(PluginConfig {
            jwt: JwtConfig {
                decoding_key,
                validation,
            },
            biscuit: BiscuitConfig {
                root_public_key: biscuit_root_public_key,
            },
            policy,
            sqlite_seed_demo_rules: self.sqlite_seed_demo_rules.unwrap_or(false),
            cache_ttl_seconds,
            allow_anonymous_no_token: self.allow_anonymous_no_token.unwrap_or(false),
            acl_read_full_authz: self.acl_read_full_authz.unwrap_or(false),
            control_notify_topic_prefix,
            ext_auth_method: self.ext_auth_method.or_else(|| Some("token".to_string())),
            role_username_prefix: self
                .role_username_prefix
                .unwrap_or_else(|| "role:".to_string()),
            biscuit_role_fact,
            biscuit_authorizer_profile,
            biscuit_authorizer_max_time_ms,
            biscuit_transport,
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
            "sqlite_seed_demo_rules" => {
                let enabled = value
                    .parse::<bool>()
                    .map_err(|e| format!("Invalid sqlite_seed_demo_rules: {e}"))?;
                builder.sqlite_seed_demo_rules(enabled)
            }
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
            "allow_anonymous_no_token" => {
                let enabled = value
                    .parse::<bool>()
                    .map_err(|e| format!("Invalid allow_anonymous_no_token: {e}"))?;
                builder.allow_anonymous_no_token(enabled)
            }
            "acl_read_full_authz" => {
                let enabled = value
                    .parse::<bool>()
                    .map_err(|e| format!("Invalid acl_read_full_authz: {e}"))?;
                builder.acl_read_full_authz(enabled)
            }
            "control_notify_topic_prefix" => builder.control_notify_topic_prefix(value),
            "ext_auth_method" => builder.ext_auth_method(value),
            "role_username_prefix" => builder.role_username_prefix(value),
            "biscuit_role_fact" => builder.biscuit_role_fact(value),
            "biscuit_authorizer_profile" => {
                let profile = match value.as_str() {
                    "simple" => BiscuitAuthorizerProfile::Simple,
                    "rbac" => BiscuitAuthorizerProfile::Rbac,
                    "contextual" => BiscuitAuthorizerProfile::Contextual,
                    _ => {
                        return Err(format!(
                            "Invalid biscuit_authorizer_profile: {value}. Use 'simple', 'rbac' or 'contextual'"
                        ));
                    }
                };
                builder.biscuit_authorizer_profile(profile)
            }
            "biscuit_authorizer_max_time_ms" => {
                let millis = value
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid biscuit_authorizer_max_time_ms: {e}"))?;
                if millis < MIN_BISCUIT_AUTHORIZER_MAX_TIME_MS {
                    return Err("biscuit_authorizer_max_time_ms must be >= 1".to_string());
                }
                builder.biscuit_authorizer_max_time_ms(millis)
            }
            "biscuit_transport" => {
                let mode = match value.as_str() {
                    "base64url" => BiscuitTransportMode::Base64Url,
                    "mqtt5_auth_data" => BiscuitTransportMode::Mqtt5AuthData,
                    _ => {
                        return Err(format!(
                            "Invalid biscuit_transport: {value}. Use 'base64url' or 'mqtt5_auth_data'"
                        ));
                    }
                };
                builder.biscuit_transport(mode)
            }
            _ => builder,
        };
    }

    builder.build().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{BiscuitAuthorizerProfile, ConfigError, PluginConfigBuilder, parse_options};
    use crate::MosquittoOpt;
    use std::ffi::CString;

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

    #[test]
    #[cfg_attr(miri, ignore)]
    fn defaults_biscuit_authorizer_profile_to_simple() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let config = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .build()
            .expect("config should build");

        assert_eq!(
            config.biscuit_authorizer_profile,
            BiscuitAuthorizerProfile::Simple
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn defaults_biscuit_authorizer_max_time_ms_to_25() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let config = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .build()
            .expect("config should build");

        assert_eq!(config.biscuit_authorizer_max_time_ms, 25);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn parse_options_supports_biscuit_authorizer_profile() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let cstrings: Vec<CString> = vec![
            CString::new("jwt_alg").unwrap(),
            CString::new("ES256").unwrap(),
            CString::new("jwt_key_file").unwrap(),
            CString::new(jwt_pub_pem).unwrap(),
            CString::new("biscuit_root_key_file").unwrap(),
            CString::new(biscuit_root_key_file).unwrap(),
            CString::new("biscuit_authorizer_profile").unwrap(),
            CString::new("contextual").unwrap(),
        ];
        let mut opts = vec![
            MosquittoOpt {
                key: cstrings[0].as_ptr().cast_mut(),
                value: cstrings[1].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[2].as_ptr().cast_mut(),
                value: cstrings[3].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[4].as_ptr().cast_mut(),
                value: cstrings[5].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[6].as_ptr().cast_mut(),
                value: cstrings[7].as_ptr().cast_mut(),
            },
        ];

        let config = parse_options(
            opts.as_mut_ptr(),
            i32::try_from(opts.len()).expect("opts len fits i32"),
        )
        .expect("config parse");
        assert_eq!(
            config.biscuit_authorizer_profile,
            BiscuitAuthorizerProfile::Contextual
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn parse_options_rejects_invalid_biscuit_authorizer_profile() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let cstrings: Vec<CString> = vec![
            CString::new("jwt_alg").unwrap(),
            CString::new("ES256").unwrap(),
            CString::new("jwt_key_file").unwrap(),
            CString::new(jwt_pub_pem).unwrap(),
            CString::new("biscuit_root_key_file").unwrap(),
            CString::new(biscuit_root_key_file).unwrap(),
            CString::new("biscuit_authorizer_profile").unwrap(),
            CString::new("unknown").unwrap(),
        ];
        let mut opts = vec![
            MosquittoOpt {
                key: cstrings[0].as_ptr().cast_mut(),
                value: cstrings[1].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[2].as_ptr().cast_mut(),
                value: cstrings[3].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[4].as_ptr().cast_mut(),
                value: cstrings[5].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[6].as_ptr().cast_mut(),
                value: cstrings[7].as_ptr().cast_mut(),
            },
        ];

        match parse_options(
            opts.as_mut_ptr(),
            i32::try_from(opts.len()).expect("opts len fits i32"),
        ) {
            Ok(_) => panic!("must fail"),
            Err(err) => assert!(err.contains("Invalid biscuit_authorizer_profile")),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn parse_options_supports_biscuit_authorizer_max_time_ms() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let cstrings: Vec<CString> = vec![
            CString::new("jwt_alg").unwrap(),
            CString::new("ES256").unwrap(),
            CString::new("jwt_key_file").unwrap(),
            CString::new(jwt_pub_pem).unwrap(),
            CString::new("biscuit_root_key_file").unwrap(),
            CString::new(biscuit_root_key_file).unwrap(),
            CString::new("biscuit_authorizer_max_time_ms").unwrap(),
            CString::new("50").unwrap(),
        ];
        let mut opts = vec![
            MosquittoOpt {
                key: cstrings[0].as_ptr().cast_mut(),
                value: cstrings[1].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[2].as_ptr().cast_mut(),
                value: cstrings[3].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[4].as_ptr().cast_mut(),
                value: cstrings[5].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[6].as_ptr().cast_mut(),
                value: cstrings[7].as_ptr().cast_mut(),
            },
        ];

        let config = parse_options(
            opts.as_mut_ptr(),
            i32::try_from(opts.len()).expect("opts len fits i32"),
        )
        .expect("config parse");
        assert_eq!(config.biscuit_authorizer_max_time_ms, 50);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn parse_options_rejects_zero_biscuit_authorizer_max_time_ms() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let cstrings: Vec<CString> = vec![
            CString::new("jwt_alg").unwrap(),
            CString::new("ES256").unwrap(),
            CString::new("jwt_key_file").unwrap(),
            CString::new(jwt_pub_pem).unwrap(),
            CString::new("biscuit_root_key_file").unwrap(),
            CString::new(biscuit_root_key_file).unwrap(),
            CString::new("biscuit_authorizer_max_time_ms").unwrap(),
            CString::new("0").unwrap(),
        ];
        let mut opts = vec![
            MosquittoOpt {
                key: cstrings[0].as_ptr().cast_mut(),
                value: cstrings[1].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[2].as_ptr().cast_mut(),
                value: cstrings[3].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[4].as_ptr().cast_mut(),
                value: cstrings[5].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[6].as_ptr().cast_mut(),
                value: cstrings[7].as_ptr().cast_mut(),
            },
        ];

        match parse_options(
            opts.as_mut_ptr(),
            i32::try_from(opts.len()).expect("opts len fits i32"),
        ) {
            Ok(_) => panic!("must fail"),
            Err(err) => assert!(err.contains("biscuit_authorizer_max_time_ms must be >= 1")),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn defaults_allow_anonymous_no_token_to_false() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let config = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .build()
            .expect("config should build");

        assert!(!config.allow_anonymous_no_token);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn accepts_allow_anonymous_no_token_true() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let config = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .allow_anonymous_no_token(true)
            .build()
            .expect("config should build");

        assert!(config.allow_anonymous_no_token);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn defaults_acl_read_full_authz_to_false() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let config = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .build()
            .expect("config should build");

        assert!(!config.acl_read_full_authz);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn accepts_acl_read_full_authz_true() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let config = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .acl_read_full_authz(true)
            .build()
            .expect("config should build");

        assert!(config.acl_read_full_authz);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn defaults_sqlite_seed_demo_rules_to_false() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let config = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .build()
            .expect("config should build");

        assert!(!config.sqlite_seed_demo_rules);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn accepts_sqlite_seed_demo_rules_true() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let config = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .sqlite_seed_demo_rules(true)
            .build()
            .expect("config should build");

        assert!(config.sqlite_seed_demo_rules);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn parse_options_supports_sqlite_seed_demo_rules() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let cstrings: Vec<CString> = vec![
            CString::new("jwt_alg").unwrap(),
            CString::new("ES256").unwrap(),
            CString::new("jwt_key_file").unwrap(),
            CString::new(jwt_pub_pem).unwrap(),
            CString::new("biscuit_root_key_file").unwrap(),
            CString::new(biscuit_root_key_file).unwrap(),
            CString::new("sqlite_seed_demo_rules").unwrap(),
            CString::new("true").unwrap(),
        ];
        let mut opts = vec![
            MosquittoOpt {
                key: cstrings[0].as_ptr().cast_mut(),
                value: cstrings[1].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[2].as_ptr().cast_mut(),
                value: cstrings[3].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[4].as_ptr().cast_mut(),
                value: cstrings[5].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[6].as_ptr().cast_mut(),
                value: cstrings[7].as_ptr().cast_mut(),
            },
        ];

        let config = parse_options(
            opts.as_mut_ptr(),
            i32::try_from(opts.len()).expect("opts len fits i32"),
        )
        .expect("config parse");
        assert!(config.sqlite_seed_demo_rules);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn parse_options_supports_acl_read_full_authz() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let cstrings: Vec<CString> = vec![
            CString::new("jwt_alg").unwrap(),
            CString::new("ES256").unwrap(),
            CString::new("jwt_key_file").unwrap(),
            CString::new(jwt_pub_pem).unwrap(),
            CString::new("biscuit_root_key_file").unwrap(),
            CString::new(biscuit_root_key_file).unwrap(),
            CString::new("acl_read_full_authz").unwrap(),
            CString::new("true").unwrap(),
        ];
        let mut opts = vec![
            MosquittoOpt {
                key: cstrings[0].as_ptr().cast_mut(),
                value: cstrings[1].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[2].as_ptr().cast_mut(),
                value: cstrings[3].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[4].as_ptr().cast_mut(),
                value: cstrings[5].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[6].as_ptr().cast_mut(),
                value: cstrings[7].as_ptr().cast_mut(),
            },
        ];

        let config = parse_options(
            opts.as_mut_ptr(),
            i32::try_from(opts.len()).expect("opts len fits i32"),
        )
        .expect("config parse");
        assert!(config.acl_read_full_authz);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn defaults_control_notify_topic_prefix() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let config = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .build()
            .expect("config should build");

        assert_eq!(config.control_notify_topic_prefix, "system_notification");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn parse_options_supports_control_notify_topic_prefix() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let cstrings: Vec<CString> = vec![
            CString::new("jwt_alg").unwrap(),
            CString::new("ES256").unwrap(),
            CString::new("jwt_key_file").unwrap(),
            CString::new(jwt_pub_pem).unwrap(),
            CString::new("biscuit_root_key_file").unwrap(),
            CString::new(biscuit_root_key_file).unwrap(),
            CString::new("control_notify_topic_prefix").unwrap(),
            CString::new("system_notify").unwrap(),
        ];
        let mut opts = vec![
            MosquittoOpt {
                key: cstrings[0].as_ptr().cast_mut(),
                value: cstrings[1].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[2].as_ptr().cast_mut(),
                value: cstrings[3].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[4].as_ptr().cast_mut(),
                value: cstrings[5].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[6].as_ptr().cast_mut(),
                value: cstrings[7].as_ptr().cast_mut(),
            },
        ];

        let config = parse_options(
            opts.as_mut_ptr(),
            i32::try_from(opts.len()).expect("opts len fits i32"),
        )
        .expect("config parse");
        assert_eq!(config.control_notify_topic_prefix, "system_notify");
    }
}
