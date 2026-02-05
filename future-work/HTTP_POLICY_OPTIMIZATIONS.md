# Future HTTP Policy Optimizations

This document tracks potential performance improvements for the HTTP policy backend that are not yet implemented. These optimizations would provide incremental gains beyond the current thread-local runtime and HTTP/2 connection pooling.

## Minor Optimizations (Easy Wins)

### DNS Caching

**Current behavior:** Every HTTP request resolves `host:port` via `ToSocketAddrs`, performing a fresh DNS lookup.

**Optimization:** Cache `SocketAddr` results in a small LRU cache keyed by `(host, port)`.

**Expected impact:** 5-50ms reduction per request (depends on DNS latency to authz server).

**Implementation sketch:**
```rust
static DNS_CACHE: OnceLock<Mutex<LruCache<(String, u16), SocketAddr>>> = OnceLock::new();
```

**Considerations:**
- TTL for cached entries (30-60s reasonable for internal Docker networks)
- IPv6 vs IPv4 preference stability

---

### Connection Health Checking

**Current behavior:** If a pooled connection dies (server idle timeout, network blip), the request fails with a connection error.

**Optimization:** Detect stale/dead connections on failure and transparently retry once with a fresh connection.

**Expected impact:** Improved reliability under connection churn; marginal latency improvement.

**Implementation sketch:**
- On `send_request` error, check if error is connection-related
- Remove dead connection from pool
- Create new connection and retry request
- Only retry once to avoid infinite loops

**Considerations:**
- Distinguish between retryable (connection reset) vs non-retryable (authz denied) errors
- Avoid double-execution of non-idempotent operations (not applicable here since authz checks are idempotent reads)

---

### Pool Size Limits

**Current behavior:** Connection pool grows unbounded per unique `(host, port, tls)` endpoint. Connections to rarely-used endpoints stay in memory forever.

**Optimization:** Add LRU eviction or max-size limits to the connection pool.

**Expected impact:** Memory stability for long-running processes with many authz backend endpoints.

**Implementation sketch:**
- Add `LruCache<ConnKey, ()>` alongside the HashMap
- Evict oldest connections when pool exceeds capacity
- Spawn cleanup task or do lazy eviction on insert

**Considerations:**
- Trade-off: Eviction means losing warm connections
- Probably overkill for research use case (single authz endpoint)

---

## Moderate Optimizations (Architecture Changes)

### HTTP/2 Concurrent Stream Multiplexing

**Current behavior:** One request at a time per pooled connection. Requests are serialized even though HTTP/2 supports multiple concurrent streams.

**Optimization:** Allow multiple concurrent in-flight requests per HTTP/2 connection.

**Expected impact:** Significant throughput improvement under high concurrency (many parallel MQTT clients). Latency reduction under load due to reduced connection creation.

**Implementation sketch:**
- Wrap `SendRequest` in an Arc/Mutex or use channels for request queuing
- Spawn dedicated connection management task
- Implement request-response matching (HTTP/2 stream IDs handle this automatically)

**Considerations:**
- More complex: need to handle request/response pairing
- Potential head-of-line blocking if one request is slow
- Might require `Semaphore` to limit concurrent streams per connection (server may have limits)

---

### Buffer Pooling

**Current behavior:** `body_bytes` (request) and response buffers are freshly allocated via `Bytes::from` and `to_bytes()`.

**Optimization:** Pool reusable `Bytes` buffers to reduce allocator pressure.

**Expected impact:** Reduced GC pressure (though Rust uses deterministic drop, not GC). Marginal latency improvement for high-throughput scenarios.

**Implementation sketch:**
```rust
static BUFFER_POOL: OnceLock<Mutex<Vec<Vec<u8>>>> = OnceLock::new();
```
- Borrow buffer from pool, use for serialization, return on drop

**Considerations:**
- HTTP bodies are small (JSON with client_id, topic, access); allocation overhead is minimal
- Complexity may not justify gains

---

### TLS Session Resumption

**Current behavior:** Every new TLS connection performs full handshake (certificate exchange, key agreement).

**Optimization:** Enable TLS session resumption (session tickets or session IDs) for faster handshakes when creating *new* pooled connections.

**Expected impact:** 1-2 RTT reduction for TLS handshake when establishing new connections (e.g., after pool miss or eviction).

**Implementation sketch:**
- Configure `ClientConfig` with `enable_secret_extraction` for session tickets
- Cache session tickets in pool alongside connections
- Reuse session ticket when establishing new connection to same endpoint

**Considerations:**
- Requires authz server to support session tickets (most modern TLS implementations do)
- Security: session ticket lifetime vs. forward secrecy trade-offs

---

## Overkill (Probably Not Worth It)

### TCP Keepalive / Socket Tuning

**Current behavior:** `TcpStream` uses OS defaults for keepalive, buffer sizes, etc.

**Optimization:** Explicit TCP tuning (keepalive intervals, buffer sizes, NODELAY).

**Assessment:** HTTP/2's own flow control and the connection pooling already handle most efficiency concerns. OS defaults are usually reasonable for this workload.

---

### Pre-emptive Connection Warming

**Current behavior:** First request to a backend pays connection establishment cost.

**Optimization:** Open connections to backends before first request (eager connection creation).

**Assessment:** Over-complexity for research use case. Would need health checking, retry logic, and background tasks. Better to optimize the on-demand path.

---

## Recommendations

For **research/validation** purposes: Current optimizations are sufficient.

For **production hardening** (if this becomes production code):
1. **DNS caching** - Easy win, minimal code complexity
2. **Connection health retry** - Reliability improvement
3. **TLS session resumption** - Noticeable improvement for TLS scenarios with connection churn

The **HTTP/2 multiplexing** optimization would be the next major architectural improvement if load testing reveals connection-per-request as a bottleneck, but this requires significant refactoring and careful handling of concurrent request/response matching.
