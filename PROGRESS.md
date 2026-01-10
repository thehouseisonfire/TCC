# Project Progress Tracker

**Project**: Eclipse Mosquitto Auth Biscuit Plugin (Rust)\
**Started**: 2026-01-04\
**Last Updated**: 2026-01-09\
**Current Focus**: Reproducible benchmark/scenario harness aligned with
`ARTICLE.MD`

---

## Executive Summary

This repository contains a Mosquitto authentication/authorization plugin
implemented in Rust that supports:

- JWT and Biscuit token authentication
- MQTT v5 enhanced auth (server-side support via Mosquitto callbacks)
- Authorization via:
  - token-only evaluation
  - SQLite policy backend
  - external HTTP policy/introspection
  - hybrid HTTP-preferred with token-only fallback on HTTP failure

The Docker + benchmark stack is now set up to run the experimental scenarios
described in `ARTICLE.MD`, including a controllable HTTP authz service and a
`netem` helper for MTU/latency/loss experiments.

---

## What Is Implemented (Current State)

### 1) Mosquitto Rust Plugin (Core)

- **Authentication**
  - JWT verification and claim validation
  - Biscuit verification via Datalog authorizer checks
  - Session caching (TTL + LRU)
- **Authorization backends**
  - Token-only (baseline)
  - SQLite policy backend
  - HTTP policy backend
  - Hybrid backend: HTTP policy when available, with token-only fallback on HTTP
    errors/timeouts

**Notes**:

- **JWT algorithm baseline**: the current deterministic benchmark token set uses
  **HS256** (symmetric). This is convenient for reproducibility, but it is not a
  perfectly fair cryptographic comparison against Biscuit (which uses asymmetric
  signatures).
- **Cryptographic Backend**: JWT verification uses `aws_lc_rs` (C/Assembly
  optimized via AWS-LC), representing a production-grade baseline. In contrast,
  Biscuit uses the pure-Rust `ed25519-dalek`. This asymmetry is intentional to
  test Biscuit against an industry-standard optimized implementation.
- **Biscuit verification per authorization check**: Biscuit authorization
  currently cryptographically verifies and runs the Biscuit token policies
  during authorization checks (e.g., ACL checks / message authorization), rather
  than cryptographically verifying it only once per session, and only evaluating
  policies. In contrast, JWT is only cryptographically verified once.

**Key files**:

- `mqtt-auth-biscuit/src/lib.rs` (plugin init/cleanup + Mosquitto callback
  wiring)
- `mqtt-auth-biscuit/src/auth.rs` (token parsing + verification dispatch)
- `mqtt-auth-biscuit/src/jwt_handler.rs` (JWT verification)
- `mqtt-auth-biscuit/src/biscuit_handler.rs` (Biscuit verification)
- `mqtt-auth-biscuit/src/authz.rs` (authorization logic + policy mode dispatch)
- `mqtt-auth-biscuit/src/http_policy.rs` (HTTP policy client)
- `mqtt-auth-biscuit/src/sqlite_policy.rs` (SQLite policy backend)
- `mqtt-auth-biscuit/src/cache.rs` (session cache)

### 2) Docker Orchestration (Reproducible Environment)

- Mosquitto broker container with the compiled plugin mounted
- Prometheus + cAdvisor for container resource telemetry
- HTTP authz service (`authz`) used for introspection/latency/failure scenarios
- `netem` helper container joined to Mosquitto network namespace for tc/MTU
  shaping

**Key files**:

- `mqtt-auth-biscuit/docker/docker-compose.yml`
- `mqtt-auth-biscuit/docker/prometheus.yml`
- `mqtt-auth-biscuit/docker/Dockerfile.mosquitto`
- `mqtt-auth-biscuit/docker/Dockerfile.authz`
- `mqtt-auth-biscuit/docker/authz_server.py`
- `mqtt-auth-biscuit/docker/Dockerfile.netem`
- `mqtt-auth-biscuit/docker/netem_entrypoint.sh`

### 3) Token Generation (Deterministic, Scenario-Ready)

`gen-tokens` generates a fixed set of tokens into `benchmarks/tokens.json`:

- **JWT**: baseline, short-lived, and padded variants (for MTU/fragmentation
  stress)
- **Biscuit**: baseline plus multi-block (1/5/25 blocks), delegated/attenuated
  example, and short-lived variant

**Key files**:

- `mqtt-auth-biscuit/benchmarks/gen_tokens.rs`
- Output: `mqtt-auth-biscuit/benchmarks/tokens.json`

### 4) Benchmark/Scenario Harness

There are two benchmark entrypoints now:

- `benchmarks/metrics_collector.py`
  - Single-run style script (legacy-style benchmark runner)
- `benchmarks/run_scenarios.py`
  - Scenario battery orchestrator (Docker control + authz config + netem
    config + run + metrics snapshot)

Load generation is driven by:

- `benchmarks/loadgen.py`
  - Multi-client MQTT publisher with latency stats and throughput
  - Supports a `sync_connect` option for thundering-herd style connection spikes

MQTT v5 reauthentication microbenchmark:

- `benchmarks/mqtt5_auth_client.py`
  - Raw-socket MQTT5 client that measures CONNECT and subsequent `AUTH` latency
    (reauth)

---

## Scenario Coverage (Implemented)

The harness includes scenarios aligned to the proposal themes:

- **Baseline token-only**: JWT vs Biscuit
- **Policy complexity**: Biscuit block count scaling (e.g., 1/5/25)
- **External authorization**: HTTP authz latency and failure injection
- **Hybrid contingency**: HTTP preferred, fallback on HTTP failure
- **Network impairment**:
  - MTU sweeps including very small MTU to induce fragmentation
  - Optional delay/loss shaping via `tc netem`
- **Lifecycle and herd behavior**:
  - short cache TTL configuration
  - synchronized connect bursts
- **MQTT v5 reauthentication**:
  - microbenchmark uses MQTT5 `AUTH` packet flow

---

## Outputs and Artifacts

### Scenario runner outputs

`benchmarks/run_scenarios.py` writes per-scenario JSON to:

- `mqtt-auth-biscuit/benchmarks/results/<SCENARIO_ID>.json`

Each file contains:

- **Latency percentiles** (p50/p95/p99 where applicable) from the load generator
- **Throughput** summary from the load generator
- **Error reporting** (connect/publish failures)
- **Resource snapshot** collected via Prometheus/cAdvisor (container CPU/memory)

---

## Validation Status

### Build/syntax

- Rust plugin builds in release mode (historically validated)
- Python benchmark scripts syntax-checked successfully:
  - `benchmarks/run_scenarios.py`
  - `benchmarks/mqtt5_auth_client.py`

### Important note on “execution vs implementation”

The harness and scenarios are implemented and wired, but **the project still
needs an end-to-end execution pass** (run the full scenario suite on the target
machine and record the first results/known issues).

---

## Roadmap (Next Steps)

### Phase 6: Benchmark Execution (Next Immediate Work)

- [ ] **6.1 Run a smoke test for the full scenario runner**
  - Goal: ensure Docker services start reliably, scenarios run, results JSON is
    produced.
  - Command sequence:
    - `cargo build --release`
    - `cargo run --release --bin gen-tokens`
    - `docker-compose -f docker/docker-compose.yml up --build -d`
    - `python3 benchmarks/run_scenarios.py`
  - Deliverable: results JSON files + a short log of any failures.

- [ ] **6.2 Resource monitoring verification**
  - Goal: confirm Prometheus snapshots are populated (CPU + memory for mosquitto
    container).
  - Deliverable: scenario outputs include non-error `resources` snapshots.

- [ ] **6.3 Fairness alignment: add asymmetric JWT baseline**
  - Goal: add a JWT test baseline using an **asymmetric** algorithm (e.g.,
    RS256/ES256) and rerun the key scenarios to compare with Biscuit under
    similar cryptographic assumptions.
  - Deliverable: updated token generation + Mosquitto config option(s) + at
    least one scenario run captured with the asymmetric JWT baseline.

### Phase 7: Data Analysis & Validation

- [ ] **7.1 Aggregate results**
  - Collect scenario JSONs and generate a summary table (latency p50/p95/p99,
    throughput, errors, CPU/memory).
- [ ] **7.2 Validate hypotheses / identify crossover points**
  - Identify when Biscuit becomes more/less expensive than JWT under:
    - MTU constraints
    - policy complexity (block count)
    - external authz latency/failure

### Phase 8: Optional Enhancements (Only If Needed)

- [ ] **8.1 Add a single “one-command reproducibility” script**
  - e.g. `./run_benchmarks.sh` wrapping build, token generation, compose
    up/down, scenario run.
- [ ] **8.2 Improve reporting quality**
  - Produce a consolidated `summary.json` and optionally CSV for plotting.
- [ ] **8.3 Make docker-compose invocation robust across environments**
  - Some systems use `docker compose` instead of `docker-compose`.
  - If this becomes an issue, adapt runner to detect and use the available CLI.

- [ ] **8.4 Add Dynamic Security module comparison**
  - Goal: add a benchmark mode/scenario that uses Mosquitto’s Dynamic Security
    module as an authorization source for comparison.
  - Deliverable: at least one scenario run captured with Dynamic Security
    enabled, comparable to the existing token-only/SQLite/HTTP/hybrid cases.

- [ ] **8.5 Avoid per-message Biscuit re-verification (if needed for performance
      isolation)**
  - Goal: avoid re-verifying/deserializing the Biscuit token on every
    authorization check.
  - Deliverable: a documented change (and rerun) showing the impact on
    authorization latency/CPU.

---

## Known Risks / Things to Watch

- **Docker permissions**: `tc netem` requires `CAP_NET_ADMIN` (already
  configured in compose).
- **MTU edge cases**: very low MTU can cause unexpected behavior depending on
  Docker networking and host kernel.
- **HTTP fallback semantics**: hybrid mode relies on HTTP failures being treated
  as errors (non-200 => error) to trigger fallback.

## Research Footnotes

### MQTT v5 AUTH Packet Implementation

**Context**: The research design requires measuring broker-side token
verification latency during MQTT v5 enhanced authentication flows, specifically
re-authentication via `AUTH` packets (reason code `0x19`) for token renewal
without disconnection.

**Implementation Decision**: Paho Python does not provide a straightforward
public API for programmatically sending `AUTH` packets after connection
establishment. The library supports enhanced authentication during the initial
CONNECT/CONNACK handshake but lacks methods like `send_auth()` or
`reauthenticate()` for triggering mid-session re-authentication.

**Workaround**: `benchmarks/mqtt5_auth_client.py` implements a minimal
raw-socket MQTT5 client that:

- Sends `CONNECT` with Authentication Method/Data
- After connection establishment, sends an `AUTH` packet with updated token data
- Measures connect latency and reauth latency separately

**Impact on Research Validity**:

- **Broker-side measurements remain accurate**: The plugin's token verification
  logic is independent of client transport implementation. Both JWT and Biscuit
  tokens are tested under identical client conditions, preserving comparative
  validity
- **Improved isolation**: Raw socket control provides more precise timing
  measurements by eliminating Paho's internal state management overhead,
  actually **strengthening** the isolation of broker-side processing costs.
- **No hypothesis compromise**: The hypothesis focus on broker-side functional
  viability, cryptographic verification costs, and policy evaluation latency—all
  measured server-side and unaffected by client implementation details.

---

## Session Notes (2026-01-09)

- Implemented scenario harness and docker stack additions required by
  `ARTICLE.MD`.
- Added MQTT5 reauthentication microbenchmark client.
- Updated benchmark docs to cover the new entrypoints.
