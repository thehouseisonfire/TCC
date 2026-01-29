#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyMode {
    TokenOnly,
    StaticAcl,
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
    pub dynamic_security_url: Option<String>,
    pub dynamic_security_reload_interval_seconds: Option<u64>,
    pub dynamic_security_username: Option<String>,
    pub dynamic_security_password: Option<String>,
}
