use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::client::conn::http2::Builder as Http2Builder;
use hyper::client::conn::http2::SendRequest;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use rustls::client::ClientSessionStore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Deserialize;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
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

/// TLS session store implementation that enables session resumption across connections.
///
/// This stores TLS 1.3 session tickets in memory keyed by server name, allowing
/// subsequent connections to the same host to resume the TLS session without
/// a full handshake, reducing latency for HTTP policy checks.
#[derive(Debug)]
struct CachedClientSessionStore {
    cache: Arc<
        Mutex<
            HashMap<
                rustls::pki_types::ServerName<'static>,
                rustls::client::Tls13ClientSessionValue,
            >,
        >,
    >,
}

impl CachedClientSessionStore {
    fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ClientSessionStore for CachedClientSessionStore {
    fn set_kx_hint(
        &self,
        _server_name: rustls::pki_types::ServerName<'static>,
        _group: rustls::NamedGroup,
    ) {
        // Key exchange hints not cached - TLS 1.3 handles this internally
    }

    fn kx_hint(
        &self,
        _server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::NamedGroup> {
        None
    }

    fn insert_tls13_ticket(
        &self,
        server_name: rustls::pki_types::ServerName<'static>,
        ticket: rustls::client::Tls13ClientSessionValue,
    ) {
        // Store the session ticket for later resumption
        if let Ok(mut guard) = self.cache.lock() {
            guard.insert(server_name, ticket);
        }
    }

    fn take_tls13_ticket(
        &self,
        server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        // Retrieve and remove the session ticket (single-use)
        // Convert to owned 'static key for HashMap lookup
        let owned_name = server_name.to_owned();
        self.cache
            .lock()
            .ok()
            .and_then(|mut guard| guard.remove(&owned_name))
    }

    fn set_tls12_session(
        &self,
        _server_name: rustls::pki_types::ServerName<'static>,
        _session: rustls::client::Tls12ClientSessionValue,
    ) {
        // TLS 1.2 session resumption not implemented - TLS 1.3 preferred
    }

    fn tls12_session(
        &self,
        _server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _server_name: &rustls::pki_types::ServerName<'_>) {
        // TLS 1.2 removal not needed
    }
}

/// TLS config cache key.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct TlsConfigKey {
    ca_file: Option<String>,
    tls_insecure: bool,
}

/// Build TLS config with session resumption enabled.
fn build_tls_config_with_resumption(
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

    // Build config with modern defaults and session resumption
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Enable session resumption with per-config store
    // Sessions are cached per-ClientConfig instance, enabling resumption
    // across connections to the same host in the connection pool.
    let session_store = Arc::new(CachedClientSessionStore::new());
    config.resumption = rustls::client::Resumption::store(session_store);

    Ok(Arc::new(config))
}

/// Cache TLS configs to ensure session resumption can work across pooled connections.
static TLS_CONFIG_CACHE: OnceLock<tokio::sync::Mutex<HashMap<TlsConfigKey, Arc<ClientConfig>>>> =
    OnceLock::new();

async fn get_tls_config(
    ca_file: Option<&str>,
    tls_insecure: bool,
) -> Result<Arc<ClientConfig>, String> {
    let key = TlsConfigKey {
        ca_file: ca_file.map(std::string::ToString::to_string),
        tls_insecure,
    };

    let cache = TLS_CONFIG_CACHE.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));
    let mut guard = cache.lock().await;
    if let Some(config) = guard.get(&key) {
        return Ok(Arc::clone(config));
    }

    let config = build_tls_config_with_resumption(ca_file, tls_insecure)?;
    guard.insert(key, Arc::clone(&config));
    Ok(config)
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

/// Connection key for pooling: (host, port, `is_tls`)
type ConnKey = (String, u16, bool);

/// DNS cache entry with timestamp for TTL enforcement.
struct DnsEntry {
    addr: SocketAddr,
    created_at: Instant,
}

/// Type aliases for complex static types
type DnsCache = Mutex<HashMap<(String, u16), DnsEntry>>;
type BufferPool = Mutex<Vec<Vec<u8>>>;

/// DNS cache with TTL to avoid repeated lookups.
static DNS_CACHE: OnceLock<DnsCache> = OnceLock::new();
const DNS_CACHE_TTL_SECONDS: u64 = 60;

/// Pooled HTTP/2 connection with concurrent stream support via `poll_ready`.
///
/// Each connection manages a single HTTP/2 connection. To enable parallel
/// request initiation, we store multiple connections per endpoint and use
/// `poll_ready` to find one with available HTTP/2 stream capacity.
struct PooledConnection {
    id: usize,
    /// The sender for this HTTP/2 connection.
    /// Wrapped in Mutex to allow mutable access for `poll_ready/send_request`.
    sender: tokio::sync::Mutex<SendRequest<Full<Bytes>>>,
    /// Background connection task handle. Must be kept alive for the connection
    /// to remain open. Dropping it would shut down the connection.
    _conn_handle: JoinHandle<std::result::Result<(), hyper::Error>>,
}

/// Connection pool storage using `tokio::sync::Mutex` for async-safe locking.
///
/// `tokio::sync::Mutex` is used instead of `std::sync::Mutex` because the guard
/// is held across await points during `poll_ready` checks. This allows proper
/// async yielding instead of blocking the runtime thread.
type ConnectionPool = tokio::sync::Mutex<HashMap<ConnKey, Vec<Arc<PooledConnection>>>>;

/// Global connection pool for HTTP/2 connection reuse with parallel initiation.
///
/// ## Concurrency Model (`poll_ready` variant)
///
/// The pool operates with a "find available connection" strategy:
///
/// 1. **Multiple connections per endpoint**: Each `ConnKey` maps to a `Vec<PooledConnection>`,
///    allowing multiple HTTP/2 connections to the same host when stream limits are reached.
///
/// 2. **Non-blocking acquisition**: When a request needs a connection, it iterates through
///    the Vec and tries `poll_ready` on each until finding one with capacity.
///
/// 3. **On-demand scaling**: If all connections are at capacity (`poll_ready` returns Pending),
///    a new connection is spawned (up to `MAX_POOL_SIZE` total per endpoint).
///
/// 4. **Per-connection serialization**: Each `PooledConnection` has a `tokio::sync::Mutex`
///    around its `SendRequest`. This is held only for `poll_ready` + `send_request`,
///    which is immediate (returns a future, doesn't wait for response).
///
/// ### Why This Enables Parallelism
///
/// Unlike the previous design that serialized ALL requests through one Mutex,
/// this design serializes only per-connection. With N connections, you can
/// have N concurrent `send_request` calls in flight, each initiating streams
/// on their respective HTTP/2 connections.
///
/// HTTP/2 stream multiplexing then allows ~100 concurrent streams per connection
/// (per `SETTINGS_MAX_CONCURRENT_STREAMS`), giving ~N×100 total concurrent requests.
static CONNECTION_POOL: OnceLock<ConnectionPool> = OnceLock::new();
static CONNECTION_ID_GEN: AtomicUsize = AtomicUsize::new(1);

/// Maximum number of connections to keep in the pool.
const MAX_POOL_SIZE: usize = 25;

/// Buffer pool for request body serialization.
///
/// ## Buffer Pooling vs `serde_json::to_vec` Trade-off Analysis
///
/// The buffer pool exists to reduce allocation pressure during HTTP authorization
/// requests. Here's the analysis of whether it's justified:
///
/// ### What `serde_json::to_vec` does internally
/// - Creates a `Vec<u8>` with default capacity (typically 0 or small)
/// - Grows the Vec as JSON is serialized (typically 1-2 reallocations for small payloads)
/// - Returns the fully serialized bytes
/// - The Vec is dropped after use, returning memory to the allocator
///
/// ### HTTP Policy Request Characteristics
/// - Request body size: ~150-500 bytes (typical MQTT authz payload with `client_id`, topic, token)
/// - Request frequency: One per MQTT PUBLISH/SUBSCRIBE when HTTP policy mode is enabled
/// - Peak throughput: Potentially thousands of requests/second in benchmark scenarios
///
/// ### Buffer Pool Benefits
/// 1. **Reduces allocator pressure**: Reusing 256-byte buffers avoids frequent
///    malloc/free cycles during high-throughput benchmarks
/// 2. **Predictable latency**: Eliminates potential allocator slow paths (sbrk/mmap)
///    during request serialization
/// 3. **Zero-allocation hot path**: When pool has available buffers, serialization
///    requires no heap allocation (just `Vec::extend`)
///
/// ### Buffer Pool Costs
/// 1. **Code complexity**: Additional ~30 lines + global state
/// 2. **Memory overhead**: MAX 20 buffers × 256 bytes = 5KB (negligible)
/// 3. **Mutex contention**: Buffer acquire/release is under the same Mutex as pool,
///    but contention is brief (O(1) Vec push/pop)
///
/// ### Verdict: KEEP the buffer pool
///
/// Justification:
/// - HTTP policy mode is specifically for **H₃ hypothesis validation** (Biscuit vs JWT
///   in complex authorization scenarios). Measurement stability is critical.
/// - The pool eliminates a variable (allocator behavior) that could introduce noise
///   in latency measurements, especially important when comparing against external
///   HTTP service latency (200ms-1000ms range per ARTICLE.MD).
/// - 5KB fixed overhead is acceptable for the measurement stability gain.
/// - Both JWT and Biscuit benefit equally from this optimization when HTTP policy
///   mode is active, preserving fair comparison.
///
/// ### When to remove
/// If HTTP policy backend is deprecated or if profiling shows buffer pool is not
/// on the hot path, simplify by using `serde_json::to_vec` directly.
static BUFFER_POOL: OnceLock<BufferPool> = OnceLock::new();
const BUFFER_POOL_MAX_SIZE: usize = 20;
const BUFFER_INITIAL_CAPACITY: usize = 256;

/// Get a buffer from the pool or create a new one.
fn acquire_buffer() -> Vec<u8> {
    let pool = BUFFER_POOL.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut pool_guard) = pool.lock()
        && let Some(buf) = pool_guard.pop()
    {
        return buf;
    }
    Vec::with_capacity(BUFFER_INITIAL_CAPACITY)
}

/// Return a buffer to the pool (clears but retains capacity).
fn release_buffer(mut buf: Vec<u8>) {
    buf.clear();
    if buf.capacity() > BUFFER_INITIAL_CAPACITY * 4 {
        // Don't keep excessively large buffers
        return;
    }
    let pool = BUFFER_POOL.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut pool_guard) = pool.lock()
        && pool_guard.len() < BUFFER_POOL_MAX_SIZE
    {
        pool_guard.push(buf);
    }
}

/// Serialize JSON value to a pooled buffer.
fn serialize_to_buffer(value: &Value) -> Result<Vec<u8>, String> {
    let mut buf = acquire_buffer();
    if let Err(e) = serde_json::to_writer(&mut buf, value) {
        release_buffer(buf);
        return Err(format!("http json encode failed: {e}"));
    }
    Ok(buf)
}

/// Resolve host:port to `SocketAddr` with caching and TTL.
fn resolve_with_cache(host: &str, port: u16) -> Result<SocketAddr, String> {
    let cache_key = (host.to_string(), port);
    let dns_cache = DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    // Try to get from cache first
    {
        let cache_guard = dns_cache
            .lock()
            .map_err(|_| "dns cache poisoned".to_string())?;
        if let Some(entry) = cache_guard.get(&cache_key)
            && entry.created_at.elapsed() < Duration::from_secs(DNS_CACHE_TTL_SECONDS)
        {
            return Ok(entry.addr);
        }
        // TTL expired, will refresh below
    }

    // Perform DNS lookup
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("http resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "http resolve failed: no addresses".to_string())?;

    // Store in cache
    let mut cache_guard = dns_cache
        .lock()
        .map_err(|_| "dns cache poisoned".to_string())?;
    cache_guard.insert(
        cache_key,
        DnsEntry {
            addr,
            created_at: Instant::now(),
        },
    );

    Ok(addr)
}

/// Parameters for creating a new pooled connection.
///
/// Grouped into a struct to reduce function argument count without
/// hurting performance (passed by reference, no allocation overhead).
struct ConnectionParams<'a> {
    host: &'a str,
    port: u16,
    scheme: &'a str,
    ca_file: Option<&'a str>,
    tls_insecure: bool,
    timeout_seconds: u64,
}

/// Acquire a connection with available capacity using `poll_ready`.
///
/// Iterates through existing connections for the endpoint, checking each with
/// `poll_ready` until finding one that can accept a new request. If all are at
/// capacity, creates a new connection (up to `MAX_POOL_SIZE` per endpoint).
///
/// Returns a cloned sender (`SendRequest` is Clone) and its connection id for later removal if dead.
async fn acquire_connection_with_capacity(
    conn_key: &ConnKey,
    pool: &ConnectionPool,
    params: &ConnectionParams<'_>,
) -> Result<(SendRequest<Full<Bytes>>, usize), String> {
    let mut existing = Vec::new();
    {
        let pool_guard = pool.lock().await;
        if let Some(connections) = pool_guard.get(conn_key) {
            existing = connections.clone();
        }
    }

    // Try existing connections first (non-blocking).
    for conn in &existing {
        if let Ok(mut guard) = conn.sender.try_lock() {
            let ready_future = std::future::poll_fn(|cx| guard.poll_ready(cx));
            match tokio::time::timeout(Duration::from_millis(10), ready_future).await {
                Ok(Ok(())) => {
                    let sender = guard.clone();
                    drop(guard);
                    return Ok((sender, conn.id));
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
    }

    // Brief backoff to reduce churn on momentary contention.
    if !existing.is_empty() && existing.len() < MAX_POOL_SIZE {
        tokio::time::sleep(Duration::from_millis(2)).await;
        for conn in &existing {
            if let Ok(mut guard) = conn.sender.try_lock() {
                let ready_future = std::future::poll_fn(|cx| guard.poll_ready(cx));
                match tokio::time::timeout(Duration::from_millis(10), ready_future).await {
                    Ok(Ok(())) => {
                        let sender = guard.clone();
                        drop(guard);
                        return Ok((sender, conn.id));
                    }
                    Ok(Err(_)) | Err(_) => continue,
                }
            }
        }
    }

    // If pool is at capacity, wait for the first connection instead of creating more.
    if existing.len() >= MAX_POOL_SIZE {
        let conn = existing
            .first()
            .ok_or_else(|| "connection pool empty".to_string())?;
        let mut guard = conn.sender.lock().await;
        let ready_future = std::future::poll_fn(|cx| guard.poll_ready(cx));
        tokio::time::timeout(Duration::from_millis(50), ready_future)
            .await
            .map_err(|_| "sender readiness timeout".to_string())?
            .map_err(|e| format!("sender not ready: {e}"))?;
        let sender = guard.clone();
        drop(guard);
        return Ok((sender, conn.id));
    }

    // All existing connections busy or none exist - create new connection.
    let pooled_conn = create_pooled_connection(params).await?;

    // Extract sender before adding to pool.
    let sender = pooled_conn.sender.lock().await.clone();

    // Add to pool.
    let mut pool_guard = pool.lock().await;
    let connections = pool_guard.entry(conn_key.clone()).or_insert_with(Vec::new);
    if connections.len() >= MAX_POOL_SIZE {
        connections.remove(0);
    }

    let id = pooled_conn.id;
    connections.push(pooled_conn);

    Ok((sender, id))
}

/// Send request with timeout using the provided sender.
///
/// The sender is already cloned and ready to use. Just polls for capacity
/// and sends the request, then awaits the response.
async fn send_request_with_timeout(
    sender: &mut SendRequest<Full<Bytes>>,
    request: Request<Full<Bytes>>,
    timeout_duration: Duration,
) -> Result<hyper::Response<hyper::body::Incoming>, String> {
    // Wait for sender to be ready (has capacity for new stream)
    tokio::time::timeout(
        timeout_duration,
        std::future::poll_fn(|cx| sender.poll_ready(cx)),
    )
    .await
    .map_err(|_| "sender readiness timeout".to_string())?
    .map_err(|e| format!("sender not ready: {e}"))?;

    // Send request - returns ResponseFuture
    let response_future = sender.send_request(request);

    // Await the actual response with timeout
    tokio::time::timeout(timeout_duration, response_future)
        .await
        .map_err(|_| "http response timeout".to_string())?
        .map_err(|e| format!("response error: {e}"))
}

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
/// Implements connection health checking with transparent retry on dead connections.
async fn check_http_pooled(params: HttpCheckParams<'_>) -> Result<bool, String> {
    let (scheme, rest) = if let Some(url) = params.http_url.strip_prefix("https://") {
        ("https", url)
    } else if let Some(url) = params.http_url.strip_prefix("http://") {
        ("http", url)
    } else {
        return Err("Only http:// or https:// URLs are supported".to_string());
    };

    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };

    let default_port = if scheme == "https" { 443 } else { 80 };
    let (host, port) = split_host_port(host_port, default_port)?;

    // Build request body (store payload for potential retry)
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
    let payload_clone = payload.clone();
    let body_bytes = serialize_to_buffer(&Value::Object(payload))?;
    let body_len = body_bytes.len();

    let max_bytes = usize::try_from(params.max_response_bytes)
        .map_err(|_| "http max response bytes too large".to_string())?;

    let conn_key = (host.clone(), port, scheme == "https");

    // Ensure http:// paths remain plaintext by ignoring any TLS config.
    let (ca_file, tls_insecure) = if scheme == "https" {
        (params.tls_config.ca_file, params.tls_config.tls_insecure)
    } else {
        (None, false)
    };

    let pool = CONNECTION_POOL.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()));

    // Acquire a connection with available capacity using poll_ready.
    // This allows parallel request initiation across multiple connections.
    let conn_params = ConnectionParams {
        host: &host,
        port,
        scheme,
        ca_file,
        tls_insecure,
        timeout_seconds: params.timeout_seconds,
    };
    let (mut sender, conn_id) =
        acquire_connection_with_capacity(&conn_key, pool, &conn_params).await?;

    // Build and send request
    let request = Request::builder()
        .method("POST")
        .uri(&path)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body_len)
        .body(Full::new(Bytes::from(body_bytes.clone())))
        .map_err(|e| format!("http request build failed: {e}"))?;

    // Send request using the acquired connection
    let response_result = send_request_with_timeout(
        &mut sender,
        request,
        Duration::from_secs(params.timeout_seconds),
    )
    .await;

    let response = match response_result {
        Ok(resp) => resp,
        Err(e) => {
            // Connection might be dead, try to detect and retry once
            let err_str = e.clone();
            if is_connection_error(&err_str) {
                // Remove dead connection from pool
                let mut pool_guard = pool.lock().await;
                if let Some(connections) = pool_guard.get_mut(&conn_key)
                    && let Some(pos) = connections.iter().position(|conn| conn.id == conn_id)
                {
                    connections.remove(pos);
                }

                // Create fresh connection for retry
                let retry_conn = create_pooled_connection(&conn_params).await?;

                // Extract sender and add to pool
                let mut fresh_sender = retry_conn.sender.lock().await.clone();
                let mut pool_guard = pool.lock().await;
                pool_guard
                    .entry(conn_key)
                    .or_insert_with(Vec::new)
                    .push(retry_conn);

                // Retry request once (rebuild body from payload_clone)
                let retry_body = serialize_to_buffer(&Value::Object(payload_clone))?;
                let retry_request = Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(CONTENT_TYPE, "application/json")
                    .header(CONTENT_LENGTH, retry_body.len())
                    .body(Full::new(Bytes::from(retry_body)))
                    .map_err(|e| format!("http request build failed: {e}"))?;

                send_request_with_timeout(
                    &mut fresh_sender,
                    retry_request,
                    Duration::from_secs(params.timeout_seconds),
                )
                .await
                .map_err(|e| format!("http2 request failed on retry: {e}"))?
            } else {
                return Err(format!("http2 request failed: {e}"));
            }
        }
    };

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
    let authz: AuthzResponse =
        serde_json::from_slice(&body_bytes).map_err(|e| format!("http invalid json: {e}"))?;

    Ok(authz.allow)
}

/// Create a pooled HTTP/2 connection with background task.
async fn create_pooled_connection(
    params: &ConnectionParams<'_>,
) -> Result<Arc<PooledConnection>, String> {
    // Resolve address using cached DNS lookup
    let addr = resolve_with_cache(params.host, params.port)?;

    let tcp_stream = timeout(
        Duration::from_secs(params.timeout_seconds),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| "http connect timeout".to_string())?
    .map_err(|e| format!("http connect failed: {e}"))?;

    if params.scheme == "https" {
        let server_name: ServerName<'static> = ServerName::try_from(params.host.to_string())
            .map_err(|_| "invalid TLS server name".to_string())?;
        let tls_config = get_tls_config(params.ca_file, params.tls_insecure).await?;
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let tls_stream: TlsStream<TcpStream> = timeout(
            Duration::from_secs(params.timeout_seconds),
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

        Ok(Arc::new(PooledConnection {
            id: CONNECTION_ID_GEN.fetch_add(1, Ordering::Relaxed),
            sender: tokio::sync::Mutex::new(sender),
            _conn_handle: conn_handle,
        }))
    } else {
        let (sender, conn) = Http2Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(tcp_stream))
            .await
            .map_err(|e| format!("http2 handshake failed: {e}"))?;

        let conn_handle = tokio::spawn(conn);

        Ok(Arc::new(PooledConnection {
            id: CONNECTION_ID_GEN.fetch_add(1, Ordering::Relaxed),
            sender: tokio::sync::Mutex::new(sender),
            _conn_handle: conn_handle,
        }))
    }
}

fn is_connection_error(err_str: &str) -> bool {
    let conn_error_patterns = [
        "connection reset",
        "connection refused",
        "broken pipe",
        "not connected",
        "os error 104",
        "os error 111",
        "os error 32",
    ];
    let lower = err_str.to_lowercase();
    conn_error_patterns.iter().any(|pat| lower.contains(pat))
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
