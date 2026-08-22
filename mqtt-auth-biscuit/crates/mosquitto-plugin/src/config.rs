use crate::policy::{PolicyBackendConfig, PolicyMode};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::collections::HashSet;
use std::ffi::CStr;
#[cfg(not(miri))]
use std::fs;
use std::num::ParseIntError;
use std::str::{FromStr, ParseBoolError};
use thiserror::Error;

const MIN_HTTP_TIMEOUT_SECONDS: u64 = 1;
const MAX_HTTP_RESPONSE_BYTES: u64 = 1024 * 1024;
const DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS: u64 = 25;
const MIN_BISCUIT_AUTHORIZER_MAX_TIME_MS: u64 = 1;

/// Configuration errors using thiserror for better error handling
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Invalid option_count")]
    InvalidOptionCount,

    #[error("Invalid options pointer")]
    InvalidOptionsPointer,

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

    #[error("Invalid identity binding mode: {0}")]
    InvalidIdentityBindingMode(String),

    #[error("Invalid biscuit client_id fact predicate: {0}")]
    InvalidBiscuitClientIdFact(String),

    #[allow(dead_code)]
    #[error("Invalid policy mode: {0}")]
    InvalidPolicyMode(String),

    #[allow(dead_code)]
    #[error("Invalid cache TTL seconds: {0}")]
    InvalidCacheTtl(String),

    #[error("Invalid {option}: {source}")]
    InvalidBooleanOption {
        option: &'static str,
        #[source]
        source: ParseBoolError,
    },

    #[error("Invalid {option}: {source}")]
    InvalidIntegerOption {
        option: &'static str,
        #[source]
        source: ParseIntError,
    },

    #[error("{option} must be >= {minimum}")]
    OptionBelowMinimum { option: &'static str, minimum: u64 },

    #[error("{option} must be > 0")]
    OptionMustBePositive { option: &'static str },

    #[error("{option} must be <= {maximum}")]
    OptionAboveMaximum { option: &'static str, maximum: u64 },

    #[error("Invalid biscuit_authorizer_profile: {value}. Use 'simple', 'rbac' or 'contextual'")]
    InvalidBiscuitAuthorizerProfile { value: String },

    #[error(
        "biscuit_transport={value} is no longer supported; Biscuit now uses raw bytes on MQTT transport"
    )]
    UnsupportedBiscuitTransport { value: String },
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityBindingMode {
    Off,
    Strict,
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
    pub jwt_identity_binding: IdentityBindingMode,
    pub biscuit_identity_binding: IdentityBindingMode,
    pub sqlite_seed_demo_rules: bool,
    pub cache_ttl_seconds: u64,
    pub benchmark_diagnostics: bool,
    pub allow_anonymous_no_token: bool,
    pub acl_read_full_authz: bool,
    pub control_notify_topic_prefix: String,
    pub ext_auth_method: Option<String>,
    pub role_username_prefix: String,
    pub biscuit_role_fact: String,
    pub biscuit_client_id_fact: String,
    pub biscuit_authorizer_profile: BiscuitAuthorizerProfile,
    pub biscuit_authorizer_max_time_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BiscuitAuthorizerProfile {
    Simple,
    Rbac,
    Contextual,
}

impl FromStr for BiscuitAuthorizerProfile {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "simple" => Ok(Self::Simple),
            "rbac" => Ok(Self::Rbac),
            "contextual" => Ok(Self::Contextual),
            _ => Err(ConfigError::InvalidBiscuitAuthorizerProfile {
                value: value.to_string(),
            }),
        }
    }
}

/// Builder for `PluginConfig` with fluent interface and validation
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
    dynamic_security_reload_interval_seconds: Option<u64>,
    cache_ttl_seconds: Option<u64>,
    benchmark_diagnostics: Option<bool>,
    allow_anonymous_no_token: Option<bool>,
    acl_read_full_authz: Option<bool>,
    control_notify_topic_prefix: Option<String>,
    ext_auth_method: Option<String>,
    role_username_prefix: Option<String>,
    biscuit_role_fact: Option<String>,
    jwt_identity_binding: Option<IdentityBindingMode>,
    biscuit_identity_binding: Option<IdentityBindingMode>,
    biscuit_client_id_fact: Option<String>,
    biscuit_authorizer_profile: Option<BiscuitAuthorizerProfile>,
    biscuit_authorizer_max_time_ms: Option<u64>,
}

impl Default for PluginConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginConfigBuilder {
    pub const fn new() -> Self {
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
            dynamic_security_reload_interval_seconds: None,
            cache_ttl_seconds: None,
            benchmark_diagnostics: None,
            allow_anonymous_no_token: None,
            acl_read_full_authz: None,
            control_notify_topic_prefix: None,
            ext_auth_method: None,
            role_username_prefix: None,
            biscuit_role_fact: None,
            jwt_identity_binding: None,
            biscuit_identity_binding: None,
            biscuit_client_id_fact: None,
            biscuit_authorizer_profile: None,
            biscuit_authorizer_max_time_ms: None,
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

    pub const fn policy_mode(mut self, mode: PolicyMode) -> Self {
        self.policy_mode = Some(mode);
        self
    }

    pub fn sqlite_path(mut self, path: impl Into<String>) -> Self {
        self.sqlite_path = Some(path.into());
        self
    }

    pub const fn sqlite_seed_demo_rules(mut self, enabled: bool) -> Self {
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

    pub const fn http_tls_insecure(mut self, enabled: bool) -> Self {
        self.http_tls_insecure = Some(enabled);
        self
    }

    pub const fn http_timeout_seconds(mut self, seconds: u64) -> Self {
        self.http_timeout_seconds = Some(seconds);
        self
    }

    pub const fn http_max_response_bytes(mut self, bytes: u64) -> Self {
        self.http_max_response_bytes = Some(bytes);
        self
    }

    pub fn dynamic_security_url(mut self, url: impl Into<String>) -> Self {
        self.dynamic_security_url = Some(url.into());
        self
    }

    pub const fn dynamic_security_reload_interval_seconds(mut self, seconds: u64) -> Self {
        self.dynamic_security_reload_interval_seconds = Some(seconds);
        self
    }

    pub const fn cache_ttl_seconds(mut self, ttl: u64) -> Self {
        self.cache_ttl_seconds = Some(ttl);
        self
    }

    pub const fn benchmark_diagnostics(mut self, enabled: bool) -> Self {
        self.benchmark_diagnostics = Some(enabled);
        self
    }

    pub const fn allow_anonymous_no_token(mut self, enabled: bool) -> Self {
        self.allow_anonymous_no_token = Some(enabled);
        self
    }

    pub const fn acl_read_full_authz(mut self, enabled: bool) -> Self {
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

    pub const fn jwt_identity_binding(mut self, mode: IdentityBindingMode) -> Self {
        self.jwt_identity_binding = Some(mode);
        self
    }

    pub const fn biscuit_identity_binding(mut self, mode: IdentityBindingMode) -> Self {
        self.biscuit_identity_binding = Some(mode);
        self
    }

    pub fn biscuit_client_id_fact(mut self, fact: impl Into<String>) -> Self {
        self.biscuit_client_id_fact = Some(fact.into());
        self
    }

    pub const fn biscuit_authorizer_profile(mut self, profile: BiscuitAuthorizerProfile) -> Self {
        self.biscuit_authorizer_profile = Some(profile);
        self
    }

    pub const fn biscuit_authorizer_max_time_ms(mut self, millis: u64) -> Self {
        self.biscuit_authorizer_max_time_ms = Some(millis);
        self
    }

    pub fn build(self) -> Result<PluginConfig, ConfigError> {
        let jwt_alg = self.jwt_alg.ok_or(ConfigError::MissingJwtAlgorithm)?;
        let alg = parse_jwt_algorithm(&jwt_alg)?;
        let decoding_key = build_decoding_key(
            alg,
            self.jwt_key_file
                .ok_or_else(|| ConfigError::MissingJwtKey(jwt_alg.clone()))?,
            &jwt_alg,
        )?;
        let validation = build_validation(alg, self.jwt_issuer, self.jwt_audience);

        let biscuit_root_public_key =
            read_biscuit_root_public_key(self.biscuit_root_key_file.as_deref())?;

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
        };

        let cache_ttl_seconds = self.cache_ttl_seconds.unwrap_or(3600);

        let biscuit_role_fact = self.biscuit_role_fact.unwrap_or_else(|| "role".to_string());
        if !is_simple_identifier(&biscuit_role_fact) {
            return Err(ConfigError::InvalidBiscuitRoleFact(biscuit_role_fact));
        }
        let biscuit_client_id_fact = self
            .biscuit_client_id_fact
            .unwrap_or_else(|| "client_id".to_string());
        if !is_simple_identifier(&biscuit_client_id_fact) {
            return Err(ConfigError::InvalidBiscuitClientIdFact(
                biscuit_client_id_fact,
            ));
        }

        let biscuit_authorizer_profile = self
            .biscuit_authorizer_profile
            .unwrap_or(BiscuitAuthorizerProfile::Simple);
        let biscuit_authorizer_max_time_ms = self
            .biscuit_authorizer_max_time_ms
            .unwrap_or(DEFAULT_BISCUIT_AUTHORIZER_MAX_TIME_MS);
        let control_notify_topic_prefix =
            normalize_control_notify_topic_prefix(self.control_notify_topic_prefix.as_deref());

        Ok(PluginConfig {
            jwt: JwtConfig {
                decoding_key,
                validation,
            },
            biscuit: BiscuitConfig {
                root_public_key: biscuit_root_public_key,
            },
            policy,
            jwt_identity_binding: self
                .jwt_identity_binding
                .unwrap_or(IdentityBindingMode::Off),
            biscuit_identity_binding: self
                .biscuit_identity_binding
                .unwrap_or(IdentityBindingMode::Off),
            sqlite_seed_demo_rules: self.sqlite_seed_demo_rules.unwrap_or(false),
            cache_ttl_seconds,
            benchmark_diagnostics: self.benchmark_diagnostics.unwrap_or(false),
            allow_anonymous_no_token: self.allow_anonymous_no_token.unwrap_or(false),
            acl_read_full_authz: self.acl_read_full_authz.unwrap_or(false),
            control_notify_topic_prefix,
            ext_auth_method: self.ext_auth_method.or_else(|| Some("token".to_string())),
            role_username_prefix: self
                .role_username_prefix
                .unwrap_or_else(|| "role:".to_string()),
            biscuit_role_fact,
            biscuit_client_id_fact,
            biscuit_authorizer_profile,
            biscuit_authorizer_max_time_ms,
        })
    }
}

fn parse_jwt_algorithm(jwt_alg: &str) -> Result<Algorithm, ConfigError> {
    match jwt_alg {
        "ES256" => Ok(Algorithm::ES256),
        _ => Err(ConfigError::InvalidJwtAlgorithm(jwt_alg.to_string())),
    }
}

fn build_decoding_key(
    alg: Algorithm,
    jwt_key_file: String,
    jwt_alg: &str,
) -> Result<DecodingKey, ConfigError> {
    #[cfg(not(miri))]
    {
        match alg {
            Algorithm::ES256 => {
                let pem =
                    fs::read(&jwt_key_file).map_err(|source| ConfigError::JwtKeyFileError {
                        path: jwt_key_file,
                        source,
                    })?;
                DecodingKey::from_ec_pem(&pem)
                    .map_err(|err| ConfigError::InvalidJwtPem(err.to_string()))
            }
            _ => Err(ConfigError::InvalidJwtAlgorithm(jwt_alg.to_string())),
        }
    }

    #[cfg(miri)]
    {
        let _ = (alg, jwt_key_file, jwt_alg);
        Ok(DecodingKey::from_secret(b"miri_dummy_key".as_slice()))
    }
}

fn build_validation(
    alg: Algorithm,
    jwt_issuer: Option<String>,
    jwt_audience: Option<String>,
) -> Validation {
    let mut validation = Validation::new(alg);
    if let Some(iss) = jwt_issuer {
        validation.iss = Some(HashSet::from([iss]));
    }
    if let Some(aud) = jwt_audience {
        validation.aud = Some(HashSet::from([aud]));
    }
    validation
}

fn read_biscuit_root_public_key(
    biscuit_root_key_file: Option<&str>,
) -> Result<biscuit_auth::PublicKey, ConfigError> {
    let pub_hex = match biscuit_root_key_file {
        #[cfg(not(miri))]
        Some(path) => {
            let raw =
                fs::read_to_string(path).map_err(|source| ConfigError::BiscuitKeyFileError {
                    path: path.to_string(),
                    source,
                })?;
            raw.trim().to_string()
        }
        #[cfg(miri)]
        Some(_) => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        None => return Err(ConfigError::MissingBiscuitKey),
    };

    let bytes =
        hex::decode(pub_hex).map_err(|err| ConfigError::InvalidBiscuitKeyHex(err.to_string()))?;
    if bytes.len() != 32 {
        return Err(ConfigError::InvalidBiscuitKeyLength(bytes.len()));
    }

    biscuit_auth::PublicKey::from_bytes(&bytes, biscuit_auth::Algorithm::Ed25519)
        .map_err(|err| ConfigError::InvalidBiscuitPublicKey(err.to_string()))
}

fn normalize_control_notify_topic_prefix(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("system_notification")
        .to_string()
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
) -> Result<PluginConfig, ConfigError> {
    let mut builder = PluginConfigBuilder::new();

    if option_count < 0 {
        return Err(ConfigError::InvalidOptionCount);
    }
    if option_count > 0 && options.is_null() {
        return Err(ConfigError::InvalidOptionsPointer);
    }

    let option_count =
        usize::try_from(option_count).map_err(|_| ConfigError::InvalidOptionCount)?;
    for i in 0..option_count {
        let opt_ptr = unsafe { options.add(i) };
        let Some((key, value)) = opt_kv(opt_ptr) else {
            continue;
        };
        builder = apply_option(builder, key.as_str(), value)?;
    }

    builder.build()
}

fn apply_option(
    builder: PluginConfigBuilder,
    key: &str,
    value: String,
) -> Result<PluginConfigBuilder, ConfigError> {
    match key {
        "jwt_alg" => Ok(builder.jwt_algorithm(value)),
        "jwt_key_file" => Ok(builder.jwt_key_file(value)),
        "jwt_issuer" => Ok(builder.jwt_issuer(value)),
        "jwt_audience" => Ok(builder.jwt_audience(value)),
        "biscuit_root_key_file" => Ok(builder.biscuit_root_key_file(value)),
        "policy_mode" => Ok(builder.policy_mode(
            value
                .parse::<PolicyMode>()
                .map_err(|err| ConfigError::InvalidPolicyMode(err.to_string()))?,
        )),
        "sqlite_path" => Ok(builder.sqlite_path(value)),
        "sqlite_seed_demo_rules" => Ok(
            builder.sqlite_seed_demo_rules(parse_bool_option("sqlite_seed_demo_rules", &value)?)
        ),
        "http_url" => Ok(builder.http_url(value)),
        "http_ca_file" => Ok(builder.http_ca_file(value)),
        "http_tls_insecure" => {
            Ok(builder.http_tls_insecure(parse_bool_option("http_tls_insecure", &value)?))
        }
        "http_timeout_seconds" => Ok(builder.http_timeout_seconds(parse_min_u64_option(
            "http_timeout_seconds",
            &value,
            MIN_HTTP_TIMEOUT_SECONDS,
        )?)),
        "http_max_response_bytes" => Ok(builder.http_max_response_bytes(parse_bounded_u64_option(
            "http_max_response_bytes",
            &value,
            1,
            MAX_HTTP_RESPONSE_BYTES,
        )?)),
        "dynamic_security_url" => Ok(builder.dynamic_security_url(value)),
        "dynamic_security_reload_interval_seconds" => Ok(builder
            .dynamic_security_reload_interval_seconds(parse_u64_option(
                "dynamic_security_reload_interval_seconds",
                &value,
            )?)),
        "cache_ttl_seconds" => {
            Ok(builder.cache_ttl_seconds(parse_u64_option("cache_ttl_seconds", &value)?))
        }
        "benchmark_diagnostics" => {
            Ok(builder.benchmark_diagnostics(parse_bool_option("benchmark_diagnostics", &value)?))
        }
        "allow_anonymous_no_token" => Ok(builder
            .allow_anonymous_no_token(parse_bool_option("allow_anonymous_no_token", &value)?)),
        "acl_read_full_authz" => {
            Ok(builder.acl_read_full_authz(parse_bool_option("acl_read_full_authz", &value)?))
        }
        "control_notify_topic_prefix" => Ok(builder.control_notify_topic_prefix(value)),
        "ext_auth_method" => Ok(builder.ext_auth_method(value)),
        "role_username_prefix" => Ok(builder.role_username_prefix(value)),
        "biscuit_role_fact" => Ok(builder.biscuit_role_fact(value)),
        "jwt_identity_binding" => {
            Ok(builder.jwt_identity_binding(parse_identity_binding_mode(&value)?))
        }
        "biscuit_identity_binding" => {
            Ok(builder.biscuit_identity_binding(parse_identity_binding_mode(&value)?))
        }
        "biscuit_client_id_fact" => Ok(builder.biscuit_client_id_fact(value)),
        "biscuit_authorizer_profile" => {
            Ok(builder.biscuit_authorizer_profile(value.parse::<BiscuitAuthorizerProfile>()?))
        }
        "biscuit_authorizer_max_time_ms" => {
            Ok(builder.biscuit_authorizer_max_time_ms(parse_min_u64_option(
                "biscuit_authorizer_max_time_ms",
                &value,
                MIN_BISCUIT_AUTHORIZER_MAX_TIME_MS,
            )?))
        }
        "biscuit_transport" => Err(ConfigError::UnsupportedBiscuitTransport { value }),
        _ => Ok(builder),
    }
}

fn parse_bool_option(option: &'static str, value: &str) -> Result<bool, ConfigError> {
    value
        .parse::<bool>()
        .map_err(|source| ConfigError::InvalidBooleanOption { option, source })
}

fn parse_identity_binding_mode(value: &str) -> Result<IdentityBindingMode, ConfigError> {
    match value {
        "off" => Ok(IdentityBindingMode::Off),
        "strict" => Ok(IdentityBindingMode::Strict),
        _ => Err(ConfigError::InvalidIdentityBindingMode(value.to_string())),
    }
}

fn parse_u64_option(option: &'static str, value: &str) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .map_err(|source| ConfigError::InvalidIntegerOption { option, source })
}

fn parse_min_u64_option(
    option: &'static str,
    value: &str,
    minimum: u64,
) -> Result<u64, ConfigError> {
    let parsed = parse_u64_option(option, value)?;
    if parsed < minimum {
        return Err(ConfigError::OptionBelowMinimum { option, minimum });
    }
    Ok(parsed)
}

fn parse_bounded_u64_option(
    option: &'static str,
    value: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ConfigError> {
    let parsed = parse_u64_option(option, value)?;
    if parsed == 0 {
        return Err(ConfigError::OptionMustBePositive { option });
    }
    if parsed < minimum {
        return Err(ConfigError::OptionBelowMinimum { option, minimum });
    }
    if parsed > maximum {
        return Err(ConfigError::OptionAboveMaximum { option, maximum });
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::{
        BiscuitAuthorizerProfile, ConfigError, IdentityBindingMode, PluginConfigBuilder,
        parse_options,
    };
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
    fn rejects_invalid_biscuit_client_id_fact() {
        let jwt_pub_pem = format!("{}/../../docker/jwt_public.pem", env!("CARGO_MANIFEST_DIR"));
        let biscuit_root_key_file = format!(
            "{}/../../docker/biscuit_public.key",
            env!("CARGO_MANIFEST_DIR")
        );

        let result = PluginConfigBuilder::new()
            .jwt_algorithm("ES256")
            .jwt_key_file(jwt_pub_pem)
            .biscuit_root_key_file(biscuit_root_key_file)
            .biscuit_client_id_fact("client-id")
            .build();

        assert!(matches!(
            result,
            Err(ConfigError::InvalidBiscuitClientIdFact(_))
        ));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn defaults_identity_binding_modes_and_biscuit_client_id_fact() {
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

        assert_eq!(config.jwt_identity_binding, IdentityBindingMode::Off);
        assert_eq!(config.biscuit_identity_binding, IdentityBindingMode::Off);
        assert_eq!(config.biscuit_client_id_fact, "client_id");
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
    fn parse_options_supports_identity_binding_modes_and_biscuit_client_id_fact() {
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
            CString::new("jwt_identity_binding").unwrap(),
            CString::new("strict").unwrap(),
            CString::new("biscuit_identity_binding").unwrap(),
            CString::new("off").unwrap(),
            CString::new("biscuit_client_id_fact").unwrap(),
            CString::new("device_id").unwrap(),
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
            MosquittoOpt {
                key: cstrings[8].as_ptr().cast_mut(),
                value: cstrings[9].as_ptr().cast_mut(),
            },
            MosquittoOpt {
                key: cstrings[10].as_ptr().cast_mut(),
                value: cstrings[11].as_ptr().cast_mut(),
            },
        ];

        let config = parse_options(
            opts.as_mut_ptr(),
            i32::try_from(opts.len()).expect("opts len fits i32"),
        )
        .expect("config parse");
        assert_eq!(config.jwt_identity_binding, IdentityBindingMode::Strict);
        assert_eq!(config.biscuit_identity_binding, IdentityBindingMode::Off);
        assert_eq!(config.biscuit_client_id_fact, "device_id");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn parse_options_rejects_invalid_identity_binding_mode() {
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
            CString::new("jwt_identity_binding").unwrap(),
            CString::new("maybe").unwrap(),
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
            Err(err) => assert!(err.to_string().contains("Invalid identity binding mode")),
        }
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
            Err(err) => assert!(
                err.to_string()
                    .contains("Invalid biscuit_authorizer_profile")
            ),
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
            Err(err) => {
                assert!(
                    err.to_string()
                        .contains("biscuit_authorizer_max_time_ms must be >= 1")
                );
            }
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
