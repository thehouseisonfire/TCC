# HTTP/2 Migration Plan for Mosquitto Auth Plugin

This document outlines a **complete migration from HTTP/1.1 to HTTP/2** for all HTTP-based communication in this project. **HTTP/1.1 support will be removed entirely.** This is a hard cutover, not a gradual transition.

All HTTP-based components must use HTTP/2. No HTTP/1.1 fallback. No dual-stack. No gradual migration.

## Scope

All HTTP-based components must use HTTP/2:

- Token issuer service (Rust, currently hyper HTTP/1.1)
- HTTP policy backend client in the Mosquitto plugin (Rust, currently raw TCP + HTTP/1.1)
- Authz server (Python, currently http.server HTTP/1.1)
- Benchmark harness HTTP clients (Python)
- Docker Compose/TLS configuration for HTTP endpoints

## Phase 0: Inventory & Constraints

### 0.1 Identify HTTP entrypoints (current)

- **Token issuer**: hyper server using `http1::Builder` and ALPN `http/1.1`.
- **Plugin HTTP policy client**: raw `TcpStream`, manual HTTP/1.1 request formatting.
- **Authz server**: Python `HTTPServer` (HTTP/1.1 only).
- **Benchmarks**: any HTTP calls to authz/token issuer in Python scripts.

### 0.2 Constraints

- Mosquitto plugin is synchronous and should remain so (no global Tokio runtime).
- Benchmarks must remain deterministic and reproducible.
- TLS is optional; cleartext HTTP/2 (h2c) must be supported for test scenarios.
- No changes to auth semantics or payload formats unless required by HTTP/2 libraries.

## Phase 1: Token Issuer (Rust, HTTP/2 server)

### 1.1 Update dependencies

**File**: `mqtt-auth-biscuit/crates/token-issuer/Cargo.toml`

- Enable HTTP/2 in hyper/hyper-util:
  - `hyper = { version = "1", features = ["full"] }` (already)
  - `hyper-util = { version = "0.1", features = ["tokio"] }` (already)
  - Add `hyper::server::conn::http2` usage in code
- Ensure `tokio-rustls` and `rustls` remain for TLS + ALPN

### 1.2 Serve HTTP/2

**File**: `mqtt-auth-biscuit/crates/token-issuer/src/main.rs`

- Replace `http1::Builder::new()` with `http2::Builder::new()`.
- Set TLS ALPN to `h2` **only** when TLS is enabled (no `http/1.1` fallback).
- Support `h2c` (cleartext HTTP/2) on non-TLS ports for test scenarios.
- Confirm request handler is HTTP/2-compatible (no change to body handling expected).

**Example adjustments**:

- In TLS config (when enabled):
  - `config.alpn_protocols = vec![b"h2".to_vec()];`
  - No fallback protocols; HTTP/2 is the only supported protocol.
- For cleartext mode (h2c), use HTTP/2 directly without TLS handshake.

### 1.3 Test token issuer

- Add a simple HTTP/2 health check client (e.g., `curl --http2` inside container).
- Validate issuing endpoints still return identical JSON payloads.

## Phase 2: Mosquitto Plugin HTTP Policy Client (Rust)

### 2.1 Replace raw HTTP/1.1 client

**File**: `mqtt-auth-biscuit/crates/mosquitto-plugin/src/http_policy.rs`

The current client hardcodes HTTP/1.1 framing. Replace with an HTTP/2-capable client library that supports **synchronous** usage.

**Options (choose one)**:

1. **reqwest + blocking**
   - Pros: simplest interface, built-in HTTP/2.
   - Cons: heavier dependency, uses Tokio internally.
2. **hyper client with a dedicated runtime thread**
   - Pros: explicit control, HTTP/2 support.
   - Cons: more complex, requires background runtime.
3. **h2 crate + custom transport**
   - Pros: minimal, explicit.
   - Cons: significant implementation effort.

**Recommended**: option 2 to keep explicit control and avoid reqwest pulling in global runtime behavior.

### 2.2 Implement request path (HTTP/2)

- Create a dedicated background Tokio runtime in the plugin (single thread).
- Use `hyper::client::conn::http2` over TLS (rustls) for each request.
- Preserve existing JSON payload and response validation.
- Respect `http_timeout_seconds` and `http_max_response_bytes`.

### 2.3 Configuration changes

- No change to config schema required; `http_url` accepts both `http://` (h2c) and `https://` (TLS + h2).
- HTTP/1.1 URLs will be rejected at runtime.

## Phase 3: Benchmarks & Clients

### 3.1 Identify HTTP clients

- Search benchmarks for any direct HTTP calls to token issuer/authz.
- Replace with HTTP/2-capable clients.

### 3.2 Python HTTP/2 client

- Use `httpx[http2]` or `httpcore[http2]` for benchmark calls.
- Ensure TLS verification is consistent with Docker certs.

## Phase 4: Docker & TLS Alignment

### 4.1 Update docker-compose

- Ensure authz + token-issuer expose TLS ports.
- Mount certs into containers.
- Update environment variables to enforce TLS and HTTP/2.

### 4.2 Certificates

- Add a local CA and issue certs for `authz` and `token-issuer`.
- Distribute CA to plugin container (for rustls verification).

## Phase 5: Validation Matrix

### 5.1 Functional parity

- Token issuance works (JWT + Biscuit)
- Authz allow/deny behaviors are unchanged
- Hybrid HTTP fallback works as before (if still required)

### 5.2 Performance parity

- Compare latency/throughput before/after HTTP/2 migration
- Note that HTTP/2 multiplexing may reduce connection setup overhead

### 5.3 Security verification

- TLS validation enforced unless explicitly disabled in benchmark mode
- ALPN negotiation verified (`h2`)

## Phase 6: Cleanup

- Remove HTTP/1.1-only code paths (manual request builder, http.server).
- Update documentation to reflect HTTP/2-only architecture.
- Ensure all scripts and configs reference the new ports and TLS settings.

## Suggested Execution Order

1. Token issuer: enable HTTP/2 server + TLS ALPN
2. Authz server: migrate to HTTP/2-capable Python server
3. Plugin HTTP client: replace raw HTTP/1.1 with HTTP/2 client
4. Benchmarks: update HTTP clients
5. Docker/TLS alignment
6. Validate + document results
