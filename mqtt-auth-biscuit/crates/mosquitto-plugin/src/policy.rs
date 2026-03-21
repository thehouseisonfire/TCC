use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyMode {
    TokenOnly,
    StaticAcl,
    StaticAclStrict,
    Sqlite,
    Http,
    Hybrid,
    DynamicSecurity,
}

#[derive(Debug, Error)]
#[error("Invalid policy_mode: {value}")]
pub struct ParsePolicyModeError {
    value: String,
}

impl FromStr for PolicyMode {
    type Err = ParsePolicyModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "token" => Ok(Self::TokenOnly),
            "static_acl" => Ok(Self::StaticAcl),
            "static_acl_strict" => Ok(Self::StaticAclStrict),
            "sqlite" => Ok(Self::Sqlite),
            "http" => Ok(Self::Http),
            "hybrid" => Ok(Self::Hybrid),
            "dynamic_security" => Ok(Self::DynamicSecurity),
            _ => Err(ParsePolicyModeError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PolicyBackendConfig {
    pub mode: PolicyMode,
    pub sqlite_path: Option<String>,
    pub http_url: Option<String>,
    pub http_ca_file: Option<String>,
    pub http_tls_insecure: bool,
    pub http_timeout_seconds: u64,
    pub http_max_response_bytes: u64,
    pub dynamic_security_url: Option<String>,
    pub dynamic_security_reload_interval_seconds: Option<u64>,
}
