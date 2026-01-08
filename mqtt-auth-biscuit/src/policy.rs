#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyMode {
    TokenOnly,
    Sqlite,
    Http,
}

#[derive(Clone, Debug)]
pub struct PolicyBackendConfig {
    pub mode: PolicyMode,
    pub sqlite_path: Option<String>,
    pub http_url: Option<String>,
}
