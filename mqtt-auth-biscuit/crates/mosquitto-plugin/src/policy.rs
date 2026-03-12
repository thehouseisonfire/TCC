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
