# HTTP/3 Migration Plan for Mosquitto Auth Plugin

This document outlines the complete migration from HTTP/1.1 to HTTP/3 (QUIC). **HTTP/1.1 support will be removed entirely.** This is a hard cutover, not a gradual transition.

## Overview

All HTTP-based communication will use HTTP/3 over QUIC:
- Token issuer service (was HTTP/1.1, now HTTP/3 only)
- HTTP policy backend (was HTTP/1.1 TCP, now HTTP/3 QUIC)
- Authz server (was Python http.server, now Rust quiche)
- Benchmark harness (was httpx HTTP/1.1, now httpx[http3])

**No HTTP/1.1 fallback. No dual-stack. No gradual migration.**

## Phase 1: Dependencies & Infrastructure

### Crate I/O Model Distinction

| Crate | New I/O Model | Notes |
|-------|---------------|-------|
| `token-issuer` | Async (quiche + tokio) | Replace hyper with quiche |
| `mosquitto-plugin` | Synchronous (mio + quiche) | No tokio; dedicated thread for QUIC event loop |
| `benchmarks` | Python (httpx[http3]) | Single HTTP/3 client |

### 1.1 Add QUIC/HTTP3 Dependencies
**Files**: `crates/mosquitto-plugin/Cargo.toml`, `crates/token-issuer/Cargo.toml`

- Add `quiche = "0.24"` (Cloudflare's QUIC implementation)
- Add `mio = "1.0"` for event loop (required for quiche's state machine)
- **Remove**: `hyper`, `hyper-util`, `http-body-util`, `tokio-rustls` from token-issuer
- **Remove**: TCP-based HTTP client code in plugin (delete `http_policy.rs`)

### 1.2 Update Build Configuration
**Files**: `crates/mosquitto-plugin/build.rs` (create if absent)

- Configure linking for QUIC libraries
- Ensure C ABI compatibility preserved for Mosquitto FFI
- No feature flags for HTTP/1.1 (no `http1` fallback)

## Phase 2: QUIC Client Implementation (Plugin)

### 2.1 Replace HTTP Policy with QUIC Policy
**File**: `crates/mosquitto-plugin/src/http_policy.rs` → rewrite entirely

**Delete**: All HTTP/1.1 code (TCP sockets, manual HTTP parsing, `send/recv` HTTP/1.1 requests)

**New Implementation**:
- `QuicClient` struct wrapping UDP socket + quiche `Connection` state
- Connection pool for reuse across authz requests
- UDP socket management with mio (bind, register, poll readable/writable)
- Manual QUIC handshake via `quiche::Connection::send()` / `recv()` loop
- ALPN negotiation ("h3") via quiche config
- TLS 1.3 internal to QUIC (no separate rustls for client)

### 2.2 HTTP/3 Request/Response via quiche h3 module
**Same file**: `crates/mosquitto-plugin/src/http_policy.rs`

Components:
- HTTP/3 frame encoding/decoding using quiche's `h3` module
- QPACK via quiche's `h3::qpack`
- Manual stream management via `quiche::Connection::stream_send()` / `stream_recv()`
- Response buffering and reassembly from partial stream reads
- Timeout via mio poll + duration check

### 2.3 Sync Bridge for FFI
**New file**: `crates/mosquitto-plugin/src/quic_runtime.rs`

Challenge: Mosquitto callbacks are synchronous, QUIC requires event loop.
Solution:
- Spawn dedicated thread with mio poll loop for QUIC I/O
- Use channels (`std::sync::mpsc`) for request/response
- Quiche drives state machine; thread handles packet I/O + timeouts

Implementation:
- `QuicheRuntime` struct holding mio `Poll`, UDP socket, quiche `Connection`
- `blocking_request(url, body, timeout)` sends request over channel, blocks on response
- Background thread loops: mio poll → quiche timer → recv/send packets → stream data

## Phase 3: Policy Backend Cutover

### 3.1 Replace Policy Mode
**File**: `crates/mosquitto-plugin/src/config.rs`

**Remove**:
- `PolicyMode::Http` (HTTP/1.1)
- `http_url`, `http_ca_file`, `http_tls_insecure`, `http_timeout_seconds`, `http_max_response_bytes` config options

**Rename/Replace with**:
- `PolicyMode::Http` now means HTTP/3 (reuse enum variant, change implementation)
- Config options: `http_url` (now requires `https://` scheme for HTTP/3), `http_timeout_seconds`, etc.

### 3.2 Update Authz Dispatch
**File**: `crates/mosquitto-plugin/src/authz.rs`

**Remove**: All HTTP/1.1 branches (`http_policy::check_http` calls)

**Replace with**:
```rust
PolicyMode::Http => {
    let Some(url) = params.http_url else {
        return AuthzOutcome::Denied;
    };
    // Call quic_runtime::blocking_request(...)
}
```

### 3.3 Delete Legacy HTTP/1.1 Code
**Files to delete/modify**:
- Delete `http_policy.rs` parser functions for HTTP/1.1 responses
- Delete manual HTTP/1.1 request formatting (`POST ... HTTP/1.1`)
- Delete TCP stream-based TLS code (replaced with QUIC's internal TLS)

## Phase 4: Token Issuer Rewrite (HTTP/3 Only)

### 4.1 Replace Hyper with Quiche HTTP/3 Server
**File**: `crates/token-issuer/src/main.rs` — complete rewrite

**Delete**:
- `hyper` server code
- `tokio-rustls` (TLS now inside QUIC)
- `http-body-util` (quiche handles framing)
- HTTP/1.1 request routing

**New Implementation**:
- `mio::Poll` + UDP socket for packet I/O
- `quiche::Config` for QUIC handshake setup
- `quiche::h3::Connection` for HTTP/3 request/response handling
- Manual event loop: poll → recv packets → process h3 events → send responses
- Same endpoints: `/jwt`, `/biscuit`, `/health`
- Same JSON request/response format

### 4.2 Update Cargo.toml
**File**: `crates/token-issuer/Cargo.toml`

**Remove**:
```toml
hyper = { version = "1.5", features = ["full"] }
hyper-util = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
tokio-rustls = "0.26"
```

**Keep**:
- `tokio` (for async runtime, but not for HTTP)
- Add `quiche = "0.24"`
- Add `mio = "1.0"`

## Phase 5: Authz Server Rewrite (Rust)

### 5.1 Replace Python http.server
**Delete**: `docker/authz_server.py`

**Create**: `docker/authz_server.rs` (new Rust binary in project)

Requirements:
- Same endpoints: `POST /authorize`, `POST /config`, `GET /health`
- Same JSON request/response format
- Same delay/fail injection behavior via config
- HTTP/3 only using quiche's `h3` module
- mio-based event loop (no tokio needed for this service)

### 5.2 Update Docker
**File**: `docker/docker-compose.yml`

- Replace `authz` service Python image with Rust binary
- UDP port mapping: `4433:4433/udp` (QUIC uses UDP)
- Remove Python dependencies for authz service
- Environment variables for delay/fail mode (same as before)

## Phase 6: Benchmark Harness Cutover

### 6.1 Update Load Generator
**File**: `benchmarks/loadgen.py`

**Remove**: HTTP/1.1 token issuance code paths

**Replace**:
- Install `httpx[http3]` (HTTP/3 support)
- All token requests use HTTP/3
- Remove `--http3` CLI flag (no longer optional, always HTTP/3)

### 6.2 Update Scenario Runner
**File**: `benchmarks/run_scenarios.py`

**Remove**: `JWT-HTTP-200MS`, `JWT-HTTP-1000MS`, `BIS-HTTP-200MS` (HTTP/1.1 variants)

**Rename**:
- `JWT-HTTP3-200MS` → `JWT-HTTP-200MS` (HTTP/3 is now "HTTP")
- All scenarios use HTTP/3 authz service
- Metrics: track HTTP/3 latency, connection establishment time

### 6.3 Netem Updates
**File**: `docker/netem_entrypoint.sh`

- UDP traffic shaping (not just TCP)
- QUIC is sensitive to packet loss/reordering—document expected behavior
- MTU considerations for QUIC packetization

## Phase 7: Testing & Validation

### 7.1 Unit Tests
**File**: `crates/mosquitto-plugin/src/http_policy.rs` (updated tests)

- Mock QUIC server for testing (using quiche)
- Timeout handling verification
- Connection pool behavior
- Error propagation

### 7.2 Integration Tests
**File**: `tests/http3_integration.rs`

- Full flow: plugin → HTTP/3 authz → response
- Token issuer HTTP/3 endpoint testing
- No HTTP/1.1 fallback tests (doesn't exist)

### 7.3 Delete HTTP/1.1 Test Scenarios
**File**: `benchmarks/run_scenarios.py`

- Remove all HTTP/1.1 vs HTTP/3 comparison scenarios
- All tests now assume HTTP/3 only

## Phase 8: Documentation & Deployment

### 8.1 Configuration Documentation
**File**: `docs/HTTP3_CONFIG.md` (replaces old HTTP config docs)

- Mosquitto config options for HTTP/3 (no HTTP/1.1 options)
- Token issuer environment variables
- Authz server setup (Rust binary, not Python)
- Troubleshooting (firewall UDP, ALPN issues)
- **Migration note**: HTTP/1.1 no longer supported

### 8.2 Docker Updates
**Files**:
- `docker/Dockerfile.mosquitto` (add QUIC deps)
- `docker/Dockerfile.authz` (Rust-based, replaces Python)
- `docker/docker-compose.yml` (single compose, no variants)

### 8.3 README Updates
**File**: `README.md`

- HTTP/3 is the only supported HTTP transport
- No HTTP/1.1 fallback
- Known limitations: UDP firewall requirements

## Implementation Order (Hard Cutover)

1. **Phase 1**: Add quiche + mio, remove hyper/hyper-util/http-body-util
2. **Phase 4**: Token issuer H3 (complete rewrite, delete hyper code)
3. **Phase 2**: Rewrite `http_policy.rs` for QUIC (delete HTTP/1.1 code)
4. **Phase 3**: Update policy dispatch, delete legacy config options
5. **Phase 5**: Authz server Rust rewrite (delete Python)
6. **Phase 6**: Benchmark harness cutover (delete HTTP/1.1 paths)
7. **Phase 7 + 8**: Testing, docs, deployment

## Risk Assessment (Hard Cutover)

| Risk | Impact | Mitigation |
|------|--------|-----------|
| UDP firewall blocking | Deployment failure | Document UDP port requirements prominently |
| QUIC library bugs | System downtime | Extensive testing before production |
| Performance regression | Worse than HTTP/1.1 | Benchmark thoroughly, rollback plan (git revert) |
| Client incompatibility | Cannot connect | N/A — internal services only, control the stack |

## Success Criteria (HTTP/3 Only)

- [ ] All HTTP traffic uses HTTP/3 (verify: no TCP/80 or TCP/443 traffic for authz)
- [ ] HTTP/1.1 code removed (verify: no "HTTP/1.1" strings in source)
- [ ] Token issuer serves HTTP/3 only (verify: ALPN "h3" only)
- [ ] Authz server is Rust binary (verify: no Python authz service)
- [ ] Latency acceptable (within 10% of previous HTTP/1.1 or better)
- [ ] All tests pass with HTTP/3 only
