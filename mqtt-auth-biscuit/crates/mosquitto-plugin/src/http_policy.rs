use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::client::conn::http2::Builder as Http2Builder;
use hyper::client::conn::http2::SendRequest;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Deserialize;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use webpki_roots::TLS_SERVER_ROOTS;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthzResponse {
    allow: bool,
}

fn build_tls_config(
    ca_file: Option<&str>,
    tls_insecure: bool,
) -> Result<Arc<ClientConfig>, String> {
    let mut root_store = RootCertStore::empty();
    if let Some(path) = ca_file {
        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|e| format!("parse CA file failed: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse CA file failed: {e}"))?;
        for cert in certs {
            let cert: CertificateDer<'static> = cert;
            root_store
                .add(cert)
                .map_err(|e| format!("invalid CA cert: {e}"))?;
        }
    } else {
        root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    }

    // SECURITY: tls_insecure disables certificate verification and is intended
    // only for controlled benchmark environments.
    if tls_insecure {
        #[derive(Debug)]
        struct NoVerifier;
        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Err(rustls::Error::PeerIncompatible(
                    rustls::PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig,
                ))
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::ED25519]
            }
        }

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug)]
pub struct HttpCheckParams<'a> {
    pub http_url: &'a str,
    pub client_id: &'a str,
    pub topic: &'a str,
    pub access: i32,
    pub token: Option<&'a str>,
    pub tls_config: TlsConfig<'a>,
    pub timeout_seconds: u64,
    pub max_response_bytes: u64,
}

#[derive(Debug)]
pub struct TlsConfig<'a> {
    pub ca_file: Option<&'a str>,
    pub tls_insecure: bool,
}

/// Connection key for pooling: (host, port, is_tls)
type ConnKey = (String, u16, bool);

/// Pooled HTTP/2 connection with background task handle
struct PooledConnection {
    sender: SendRequest<Full<Bytes>>,
    _conn_handle: JoinHandle<std::result::Result<(), hyper::Error>>,
}

/// Global connection pool for HTTP/2 connection reuse.
/// Thread-safe with interior mutability for connection reuse across requests.
static CONNECTION_POOL: std::sync::OnceLock<Mutex<HashMap<ConnKey, PooledConnection>>> =
    std::sync::OnceLock::new();

// Thread-local Tokio runtime to avoid per-request runtime creation overhead.
// Each Mosquitto worker thread gets its own runtime instance.
thread_local! {
    static HTTP_RUNTIME: RefCell<Runtime> = RefCell::new(
        Runtime::new().expect("failed to create HTTP runtime")
    );
}

/// Synchronous wrapper for HTTP/2 request using hyper with connection pooling.
/// Uses a thread-local runtime and reuses HTTP/2 connections for efficiency.
pub fn check_http(params: HttpCheckParams) -> Result<bool, String> {
    HTTP_RUNTIME.with(|rt| rt.borrow().block_on(check_http_pooled(params)))
}
/// Check HTTP authorization using connection pooling for HTTP/2 multiplexing.
/// Reuses existing connections when available, creating new ones only when necessary.
async fn check_http_pooled(params: HttpCheckParams<'_>) -> Result<bool, String> {
    let (scheme, rest) = if let Some(url) = params.http_url.strip_prefix("https://") {
        ("https", url)
    } else if let Some(url) = params.http_url.strip_prefix("http://") {
        ("http", url)
    } else {
        return Err("Only http:// or https:// URLs are supported".to_string());
    };

    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };

    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = split_host_port(host_port, default_port)?;

    // Build request body
    let mut payload = serde_json::Map::from_iter([
        (
            "client_id".to_string(),
            Value::String(params.client_id.to_string()),
        ),
        ("topic".to_string(), Value::String(params.topic.to_string())),
        ("access".to_string(), Value::Number(params.access.into())),
    ]);
    if let Some(t) = params.token {
        payload.insert("token".to_string(), Value::String(t.to_string()));
    }
    let body_bytes = serde_json::to_vec(&Value::Object(payload))
        .map_err(|e| format!("http json encode failed: {e}"))?;

    let max_bytes = usize::try_from(params.max_response_bytes)
        .map_err(|_| "http max response bytes too large".to_string())?;

    let conn_key = (host.clone(), port, scheme == "https");

    // Try to get existing connection from pool
    let pool = CONNECTION_POOL.get_or_init(|| Mutex::new(HashMap::new()));
    let existing_sender = {
        let pool_guard = pool.lock().map_err(|_| "connection pool poisoned")?;
        pool_guard.get(&conn_key).map(|conn| conn.sender.clone())
    };

    let mut sender = if let Some(sender) = existing_sender {
        sender
    } else {
        // Create new connection and pool it
        let pooled_conn = create_pooled_connection(
            &host,
            port,
            scheme,
            params.tls_config.ca_file,
            params.tls_config.tls_insecure,
            params.timeout_seconds,
        )
        .await?;

        let sender = pooled_conn.sender.clone();
        pool.lock()
            .map_err(|_| "connection pool poisoned")?
            .insert(conn_key, pooled_conn);
        sender
    };

    // Build and send request
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body_bytes.len())
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|e| format!("http request build failed: {e}"))?;

    let response = timeout(
        Duration::from_secs(params.timeout_seconds),
        sender.send_request(request),
    )
    .await
    .map_err(|_| "http2 request timeout".to_string())?
    .map_err(|e| format!("http2 request failed: {e}"))?;

    // Check status
    if response.status().as_u16() != 200 {
        return Err(format!("http non-200 response: {}", response.status()));
    }

    // Collect body with size limit
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("http body read failed: {e}"))?;

    let body_bytes = body.to_bytes();
    if body_bytes.len() > max_bytes {
        return Err("http response too large".to_string());
    }

    // Parse JSON response
    let authz: AuthzResponse = serde_json::from_slice(&body_bytes)
        .map_err(|e| format!("http invalid json: {e}"))?;

    Ok(authz.allow)
}

/// Create a pooled HTTP/2 connection with background task.
async fn create_pooled_connection(
    host: &str,
    port: u16,
    scheme: &str,
    ca_file: Option<&str>,
    tls_insecure: bool,
    timeout_seconds: u64,
) -> Result<PooledConnection, String> {
    // Resolve address and connect
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("http resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "http resolve failed: no addresses".to_string())?;

    let tcp_stream = timeout(
        Duration::from_secs(timeout_seconds),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| "http connect timeout".to_string())?
    .map_err(|e| format!("http connect failed: {e}"))?;

    if scheme == "https" {
        let server_name: ServerName<'static> = ServerName::try_from(host.to_string())
            .map_err(|_| "invalid TLS server name".to_string())?;
        let tls_config = build_tls_config(ca_file, tls_insecure)?;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let tls_stream: TlsStream<TcpStream> = timeout(
            Duration::from_secs(timeout_seconds),
            connector.connect(server_name, tcp_stream),
        )
        .await
        .map_err(|_| "tls handshake timeout".to_string())?
        .map_err(|e| format!("tls connect failed: {e}"))?;

        let (sender, conn) = Http2Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(tls_stream))
            .await
            .map_err(|e| format!("http2 tls handshake failed: {e}"))?;

        let conn_handle = tokio::spawn(conn);

        Ok(PooledConnection {
            sender,
            _conn_handle: conn_handle,
        })
    } else {
        let (sender, conn) = Http2Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(tcp_stream))
            .await
            .map_err(|e| format!("http2 handshake failed: {e}"))?;

        let conn_handle = tokio::spawn(conn);

        Ok(PooledConnection {
            sender,
            _conn_handle: conn_handle,
        })
    }
}

fn split_host_port(host_port: &str, default_port: u16) -> Result<(String, u16), String> {
    if host_port.starts_with('[') {
        let end = host_port
            .find(']')
            .ok_or_else(|| "invalid host".to_string())?;
        let host = &host_port[1..end];
        let rest = &host_port[end + 1..];
        if rest.is_empty() {
            return Ok((host.to_string(), default_port));
        }
        let port_str = rest
            .strip_prefix(':')
            .ok_or_else(|| "invalid host".to_string())?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| "invalid port".to_string())?;
        return Ok((host.to_string(), port));
    }

    if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| "invalid port".to_string())?;
        return Ok((host.to_string(), port));
    }

    Ok((host_port.to_string(), default_port))
}
