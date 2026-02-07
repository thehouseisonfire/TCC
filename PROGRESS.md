# Project Progress Tracker

**Project**: Eclipse Mosquitto Auth Biscuit Plugin (Rust)\
**Started**: 2026-01-04\
**Last Updated**: 2026-01-23\
**Current Focus**: Reproducible benchmark/scenario harness aligned with
`ARTICLE.MD`

---

## 1) Executive Summary

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

## 2) Architecture & Crate Map

### 2.1 Logical Roles (ARTICLE.MD Terminology)

- **Token Issuer (implemented)**: the `token-issuer` service is the only
  component that may ever hold **private signing keys** (JWT ES256 private key
  material) and **Biscuit root private key material**. It runs as a standalone
  HTTP service for refresh scenarios and is wired in Docker Compose.
- **PDP (scenario-only)**: the existing `authz` HTTP service is an
  authorization/introspection **Policy Decision Point** used only for the
  external-policy benchmark scenarios; it is not a Token Issuer.
- **PEP**: Mosquitto + this plugin acts as the **Policy Enforcement Point** and
  must only hold **public verification keys**.

### 2.2 Crates

- `mosquitto-plugin`: core authn/authz logic, callback wiring, policy backends
- `token-issuer`: JWT/Biscuit issuance service for refresh scenarios
- `benchmarks`: token generation + scenario runner + load generator

### 2.3 Infrastructure

- Docker orchestration for Mosquitto + support services
- Prometheus + cAdvisor for telemetry
- `netem` helper for MTU/latency/loss experiments

---

## 3) What Is Implemented (Current State)

### 3.1 Mosquitto Rust Plugin (Core)

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
  - Dynamic Security (file-backed): current implementation replays a local
    `dynamic-security.json` snapshot (not the live Mosquitto dynsec module/API).

**Key files**:

- `mqtt-auth-biscuit/crates/mosquitto-plugin/src/lib.rs` (plugin init/cleanup +
  Mosquitto callback wiring)
- `mqtt-auth-biscuit/crates/mosquitto-plugin/src/auth.rs` (token parsing +
  verification dispatch)
- `mqtt-auth-biscuit/crates/mosquitto-plugin/src/jwt_handler.rs` (JWT
  verification)
- `mqtt-auth-biscuit/crates/mosquitto-plugin/src/biscuit_handler.rs` (Biscuit
  verification)
- `mqtt-auth-biscuit/crates/mosquitto-plugin/src/authz.rs` (authorization
  logic + policy mode dispatch)
- `mqtt-auth-biscuit/crates/mosquitto-plugin/src/http_policy.rs` (HTTP policy
  client)
- `mqtt-auth-biscuit/crates/mosquitto-plugin/src/sqlite_policy.rs` (SQLite
  policy backend)
- `mqtt-auth-biscuit/crates/mosquitto-plugin/src/cache.rs` (session cache)

### 3.2 Token Generation & Issuance (Deterministic + Online)

`gen-tokens` generates a fixed set of tokens into `benchmarks/tokens.json`:

- **JWT**: baseline, short-lived, and padded variants (for MTU/fragmentation
  stress)
- **Biscuit**: baseline plus multi-block (1/5/25 blocks), delegated/attenuated
  example, and short-lived variant

**Key files**:

- `mqtt-auth-biscuit/crates/benchmarks/src/main.rs` (crate name: `gen-tokens`)
- Output: `mqtt-auth-biscuit/benchmarks/tokens.json`

**Current limitation**:

- Tokens are still generated **offline** for deterministic baseline runs, while
  the **Token Issuer** service is used for refresh scenarios.
- In `gen-tokens` (`crates/benchmarks/src/main.rs`), the JWT private signing key
  exists only in the generator process memory at runtime; only the public
  verification key is written to `docker/jwt_public.pem` for the broker/PEP.
- In `gen-tokens`, the Biscuit root private key exists only in the generator
  process memory at runtime; the public key is written to
  `docker/biscuit_public.key` (hex-encoded) for the broker/PEP. The plugin reads
  this file via the `biscuit_root_key_file` config option; no remaining hex
  config is needed.

### 3.3 Benchmark/Scenario Harness

There are two benchmark entrypoints now:

- `benchmarks/metrics_collector.py`
  - Single-run style script (legacy-style benchmark runner)
  - Use for quick, manual spot checks (e.g., simple latency sanity checks)
  - Prefer `run_scenarios.py` for all reproducible research runs/results
- `benchmarks/run_scenarios.py`
  - Scenario battery orchestrator (Docker control + authz config + netem
    config + run + metrics snapshot)

Load generation is driven by:

- `benchmarks/loadgen.py`
  - Multi-client MQTT publisher with latency stats and throughput
  - Supports a `sync_connect` option for thundering-herd style connection spikes

MQTT v5 reauthentication microbenchmark:

- `benchmarks/mqtt_auth_client.py`
  - Raw-socket MQTT5 client that measures CONNECT and subsequent `AUTH` latency
    (reauth)

### 3.4 Docker Orchestration & Observability

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

---

## 4) Benchmark Design (Formerly BENCHMARK_PLAN.md)

### Objectives

1. Compare latency of connection establishment (CONNECT/CONNACK) between JWT and
   Biscuit.
2. Evaluate authorization latency for PUBLISH/SUBSCRIBE operations.
3. Measure CPU and memory consumption of the Mosquitto broker under various
   loads.
4. Assess the impact of token size on network throughput.

### Test Matrix (Planned vs Implemented)

| Scenario ID                   | Token Type | Operation        | Clients | Planned QoS | Implemented QoS | Status         |
| ----------------------------- | ---------- | ---------------- | ------- | ----------- | --------------- | -------------- |
| BASE-01                       | None       | Pub/Sub          | 100     | 0           | 1               | ✅ Implemented |
| JWT-01                        | JWT        | Pub/Sub          | 100     | 1           | 1               | ✅ Implemented |
| BIS-01                        | Biscuit    | Pub/Sub          | 100     | 1           | 1               | ✅ Implemented |
| POLICY-COMPLEX-1              | Biscuit    | Pub/Sub          | 50      | 1           | 1               | ✅ Implemented |
| POLICY-COMPLEX-5              | Biscuit    | Pub/Sub          | 50      | 1           | 1               | ✅ Implemented |
| POLICY-COMPLEX-25             | Biscuit    | Pub/Sub          | 50      | 1           | 1               | ✅ Implemented |
| POLICY-COMPLEX-LOW            | Biscuit    | Pub/Sub          | 50      | 1           | 1               | ✅ Implemented |
| POLICY-COMPLEX-MED            | Biscuit    | Pub/Sub          | 50      | 1           | 1               | ✅ Implemented |
| POLICY-COMPLEX-HIGH           | Biscuit    | Pub/Sub          | 50      | 1           | 1               | ✅ Implemented |
| JWT-HTTP-200MS                | JWT        | HTTP Authz       | 50      | 1           | 1               | ✅ Implemented |
| JWT-HTTP-1000MS               | JWT        | HTTP Authz       | 50      | 1           | 1               | ✅ Implemented |
| HYBRID-AUTHZ-DOWN             | JWT        | Hybrid           | 50      | 1           | 1               | ✅ Implemented |
| MTU-200-JWT                   | JWT        | MTU/Frag         | 50      | 1           | 1               | ✅ Implemented |
| BIS-HTTP-200MS                | Biscuit    | HTTP Authz       | 50      | 1           | 1               | ✅ Implemented |
| JWT-HTTP-200MS-LOSS1          | JWT        | HTTP Loss        | 50      | 1           | 1               | ✅ Implemented |
| JWT-HTTP-200MS-LOSS5          | JWT        | HTTP Loss        | 50      | 1           | 1               | ✅ Implemented |
| MQTT5-REAUTH-JWT              | JWT        | Reauth           | 1       | 1           | 1               | ✅ Implemented |
| MQTT5-REAUTH-BISCUIT          | Biscuit    | Reauth           | 1       | 1           | 1               | ✅ Implemented |
| THUNDERING-HERD               | Biscuit    | Connection Burst | 50      | 1           | 1               | ✅ Implemented |
| DELEGATION-TEMP-ONLY          | Biscuit    | Delegation       | 50      | 1           | 1               | ✅ Implemented |
| LIFECYCLE-JWT-SHORT-RECONNECT | JWT        | Lifecycle        | 50      | 1           | 1               | ✅ Implemented |
| LIFECYCLE-BIS-SHORT-RECONNECT | Biscuit    | Lifecycle        | 50      | 1           | 1               | ✅ Implemented |
| MTU-500/1500/9000             | Both       | MTU/Frag         | 50      | 1           | 1               | ✅ Implemented |

### Metrics Collection

- **Latency**: Measured from client-side using `paho-mqtt`.
- **Resource Usage**: Tracked via `docker stats` and Prometheus.
- **Throughput**: Measured in messages per second (mps).

### Reproducibility

- All tests run within the provided `docker compose` environment.
- Tokens are generated using the `gen-tokens` tool with deterministic keys.
- Network conditions (latency/loss) emulated via `tc` on the bridge network.

---

## 5) Scenario Coverage (Implemented)

The harness includes scenarios aligned to the proposal themes:

- **Baseline token-only**: JWT vs Biscuit
- **Policy complexity**: Biscuit block count scaling (1/5/25) and Datalog rule complexity (LOW/MED/HIGH)
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

### 5.1 Missing Scenario IDs (gap list)

Below are scenario IDs that are **not yet present** in `run_scenarios.py` and
map directly to the open issues/coverage gaps above.

- [ ] **DYNSEC-BASE** (Dynamic Security baseline parity)
- [ ] **DYNSEC-CHURN** (Dynamic Security with policy updates)
- [ ] **DYNSEC-READ-FANOUT** (Dynamic Security + `ACL_READ` fan-out checks)
- [ ] **STATIC-ACL-BASE** (Static ACL baseline with `ACL_WRITE`/`ACL_SUBSCRIBE`)
- [ ] **STATIC-ACL-READ** (Static ACL with `ACL_READ` disabled or documented)
- [ ] **STATIC-ACL-MATRIX** (Static ACL parity across JWT/Biscuit scenarios)
- [ ] **ACL-WRITE-MATRIX** (Explicit `ACL_WRITE` coverage per policy mode)
- [ ] **ACL-SUBSCRIBE-MATRIX** (Explicit `ACL_SUBSCRIBE` coverage per policy mode)
- [ ] **ACL-READ-MATRIX** (Explicit `ACL_READ` coverage per policy mode)
- [ ] **CONTROL-KICK-REAUTH** (Control-plane kick/re-auth flow)
- [ ] **CONTROL-READ-NOTIFY** (Control-plane `ACL_READ` + notify flow)
- [ ] **FANOUT-SCALE** (1 publisher + N subscribers to measure fan-out cost)
- [ ] **SQLITE-CHURN-READ** (SQLite churn + `ACL_READ` enforcement)
- [ ] **QOS0-BASE-01** (BASE-01 with QoS 0)
- [ ] **QOS2-JWT** / **QOS2-BISCUIT** (QoS 2 scenarios)
- [ ] **QOS-MIXED** (Mixed QoS workload)

---

## 6) Outputs and Artifacts

### Scenario runner outputs

`benchmarks/run_scenarios.py` writes per-scenario JSON to:

- `mqtt-auth-biscuit/benchmarks/results/<SCENARIO_ID>.json`

Each file contains:

- **Latency percentiles** (p50/p95/p99 where applicable) from the load generator
- **Throughput** summary from the load generator
- **Error reporting** (connect/publish failures)
- **Resource snapshot** collected via Prometheus/cAdvisor (container CPU/memory)

---

## 7) Validation Status

### Build/syntax

- Rust plugin builds in release mode (historically validated)
- Python benchmark scripts syntax-checked successfully:
  - `benchmarks/run_scenarios.py`
  - `benchmarks/mqtt_auth_client.py`

### Important note on "execution vs implementation"

The harness and scenarios are implemented and wired, but **the project still
needs an end-to-end execution pass** (run the full scenario suite on the target
machine and record the first results/known issues).

---

## 8 Authorization Enforcement Matrix

### Static policies (no runtime changes)

**Backends**: Static ACL, Dynamic Security, SQLite, HTTP endpoint.

| Hook | Required? | Notes |
| --- | --- | --- |
| `ACL_READ` | Optional | Can be skipped if `ACL_SUBSCRIBE` is authoritative and policies are static; still needed for fan-out enforcement if you want per-message checking. |
| `ACL_WRITE` | ✅ | Check policy (Biscuit Datalog; JWT via the backend under test). |
| `ACL_SUBSCRIBE` | ✅ | Check policy (Biscuit Datalog; JWT via the backend under test). |
| `EVT_CONTROL` | N/A | Only relevant if `$CONTROL/<feature>/v1` is explicitly used. |

### Dynamic policies — ACL_READ enforcement version

**Backends**: Dynamic Security, SQLite.

| Hook | Required? | Notes |
| --- | --- | --- |
| `ACL_READ` | ✅ | Enforce dynamic policy changes for existing subscribers (fan-out checks). |
| `ACL_WRITE` | ✅ | Check policy (Biscuit Datalog + backend query; JWT backend query). |
| `ACL_SUBSCRIBE` | ✅ | Check policy (Biscuit Datalog + backend query; JWT backend query). |
| `EVT_CONTROL` | N/A | Dynamic enforcement handled via `ACL_CHECK` only. |

### Dynamic policies — CONTROL-triggered enforcement version

**Backends**: Dynamic Security.

| Hook | Required? | Notes |
| --- | --- | --- |
| `ACL_READ` | Conditional | Test both variants: **(A)** kick/re-auth affected clients on policy change (no `ACL_READ`), **(B)** keep sessions and deny fan-out with `ACL_READ`, plus publish a warning (e.g., `system_notification/<client_id>`) so clients learn privileges were reduced. |
| `ACL_WRITE` | ✅ | Check policy (Biscuit Datalog + backend query; JWT backend query). |
| `ACL_SUBSCRIBE` | ✅ | Check policy (Biscuit Datalog + backend query; JWT backend query). |
| `EVT_CONTROL` | ✅ | Authorize control-plane requests and trigger cache invalidation / kick or notification flow. |

---

## 9) Open Issues (Next Steps, Grouped)

### **Priority List**
1. Issue 8.2: Containerized benchmark topology
2. Issue 13: emqtt-bench integration
3. Issue 15: tcpdump fragmentation analysis
4. Issue 17: comprehensive QoS
5. Issue 21: Expand Biscuit authorizer (if current template insufficient)
6. Issue 22: Strengthen SQLite RBAC (if policies too simple)
7. Issue 23: Proactive client reauthentication
8. Issue 24: Multi-step enhanced auth decision
9. Issue 25: Optional ACL_READ full authz flag
10. Issue 28: Verify static-policy coverage
11. Issue 29: Anonymous flow scenario
12. Issue 30: Dynamic-policy ACL_READ fan-out
13. Issue 31: Control-triggered kick/re-auth
14. Issue 32: Control-triggered ACL_READ + notify
15. Issue 33: Enhance HTTP policy expressiveness for parity
16. Issue 35: Add Dynamic Security command payloads to CONTROL scenarios
17. Issue 36: Add interleaved control message support for data plane + control plane testing

---

#### A) Policy Source Parity

- [ ] **Issue 8.2: Containerized benchmark topology (client-per-container +
     service separation)**
  - Goal: strengthen experimental isolation and fidelity by running benchmark
    clients in containers (optionally one container per client) and ensuring
    each major logical component is separated into the appropriate container(s)
    for the scenario.
  - Rationale: the current load generator runs as a host process with many
    threads/clients, which is acceptable for many comparisons but can introduce
    host scheduling noise and makes it harder to claim "N independent IoT nodes"
    when discussing external validity.
  - Deliverable:
    - A containerized load generator image (Python + paho-mqtt) that can be
      invoked by the scenario runner
    - Support for two benchmark client modes:
      - single loadgen container simulating N clients (baseline)
      - one container per client (high-fidelity topology) with deterministic
        naming (e.g., `client_1..client_N`)
    - Docker resource controls for client containers (cpuset, cpu/memory limits)
      to prevent benchmark noise from affecting Mosquitto measurements
    - Scenario runner support to launch/teardown client containers per scenario
      and collect client-side outputs deterministically
    - Documentation of the measurement trade-offs between the modes and guidance
      for which scenarios require client-per-container to improve realism

- [ ] **Issue 13: Add emqtt-bench as container orchestrating load generator**
  - Goal: integrate `emqtt-bench` as an alternative to custom Python
    implementation, designed to orchestrate multiple client containers for
    better isolation.
  - Rationale: The ARTICLE.MD methodology specifically mentions
    industry-standard MQTT benchmarking tools, and `emqtt-bench` provides
    comprehensive capabilities while aligning with Issue 8.2's
    client-per-container architecture.
  - Current state: No `emqtt-bench` integration exists; only custom Python
    `loadgen.py` is used.
  - Deliverable:
    - Add `--loadgen` flag to `benchmarks/run_scenarios.py` to select between:
      - `custom` (current Python implementation)
      - `emqtt-bench` (orchestrating multiple client containers)
    - Docker service definition for `emqtt-bench` orchestrator container
    - Client container template that can be spawned by emqtt-bench
    - Parameter mapping from scenario configuration to emqtt-bench command-line
      interface
    - Output parsing to normalize results format for consistent JSON output
    - At least one scenario run captured with emqtt-bench orchestrating N client
      containers
    - Comparison analysis between custom single-host and emqtt-bench
      containerized approaches

- [ ] **Issue 15: Add packet-level analysis with tcpdump for fragmentation
     studies**
  - Goal: integrate `tcpdump` capture capabilities to analyze TCP fragmentation
    behavior during MTU stress tests.
  - Rationale: ARTICLE.MD specifically mentions fragmentation analysis, and
    packet-level data is essential for understanding how token size affects
    network behavior under MTU constraints.
  - Current state: No `tcpdump` service or capture integration exists.
  - Deliverable:
    - Add `tcpdump` service to docker-compose.yml with appropriate capabilities
    - Packet capture integration for MTU scenarios (200B, 500B, 1500B, 9000B)
    - Automated packet analysis to count fragments, retransmissions, and delays
    - Packet analysis results included in scenario outputs
    - Correlation of fragmentation data with latency/throughput metrics

- [ ] **Issue 17: Implement comprehensive QoS configuration and mixing
    features**
  - Goal: Add support for different QoS levels (0, 1, 2) and mixed QoS workloads
    to enable comprehensive performance analysis across quality of service
    levels.
  - Current gap: All scenarios currently use QoS 1 exclusively, despite
    BENCHMARK_PLAN.md specifying QoS 0 for BASE-01 and missing QoS 2 testing
    entirely (scenarios rely on `--qos` CLI arg, default 1).
  - Code pointers: `loadgen.py` supports `--qos` but `run_scenarios.py` and
    `metrics_collector.py` hardcode QoS 1; BASE-01 scenario does not override to QoS 0.
  - Rationale: QoS levels significantly impact MQTT broker behavior and token
    verification overhead:
    - QoS 0: Fire-and-forget, minimal broker state
    - QoS 1: At-least-once delivery with acknowledgments
    - QoS 2: Exactly-once delivery with four-step handshake
  - Deliverable (implementation complete; execution pending):
    - [x] Update `loadgen.py` to support QoS distribution configuration (e.g., 60%
      QoS 0, 30% QoS 1, 10% QoS 2)
    - [x] Add scenario-specific QoS configuration in `run_scenarios.py`
    - [x] Fix BASE-01 scenario to use QoS 0 as planned
    - [x] Add dedicated QoS 2 scenarios for both JWT and Biscuit
    - [x] Add mixed QoS workload scenarios to test realistic IoT traffic patterns
    - [x] Update `metrics_collector.py` to support configurable QoS
    - [ ] Add QoS-specific performance analysis and reporting
    - [ ] At least one scenario run captured for each QoS level and mixed
      configurations

- [ ] **Issue 22: Strengthen `seed_demo_rules` (RBAC), make it optional, and add
    runtime policy churn scenarios**
  - Goal: Turn SQLite demo seeding into a realistic RBAC policy set, allow it to
    be turned off, and add scenarios where policies change periodically at
    runtime.
  - Current issue: seeding is unconditional when `PolicyMode::Sqlite` is used,
    and policies are too simple for RBAC fairness studies (see
    `sqlite_policy.rs`).
  - Deliverable:
    - Add a configuration flag to enable/disable demo seeding (e.g.,
      `sqlite_seed_demo_rules=true|false`)
    - Extend SQLite schema and seeding to include RBAC-like structure
      (users/roles/role_acls), plus more realistic topic/action grants
    - Add a benchmark scenario where SQLite rules are updated deterministically
      during the run (e.g., every N seconds), to simulate dynamic policy updates
    - Ensure scenarios document when policy churn is enabled and how it affects
      cache validity

- [ ] **Issue 33: Enhance HTTP policy expressiveness for parity with token-based
    authorization**
  - Goal: Improve HTTP policy backend to support complex authorization rules
    comparable to JWT/Biscuit token policies, enabling fair policy complexity
    comparisons.
  - Current issue: HTTP policy only supports simple topic prefix matching and
    lacks operation-specific, client-specific, and deny rule support, making it
    less expressive than token-based policies (see `docker/authz_server.py`).
  - Note: HTTP policy complexity scenarios are the recommended parity path for
    JWT policy complexity comparisons, since JWT grants are otherwise limited to
    flat `op/res` matches in token-only mode.
  - Deliverable:
    - Extend HTTP policy server to support:
      - Operation-specific rules (different policies for publish/subscribe/read)
      - Client/role-based access control using JWT claims or client ID
      - Deny rules that override allow rules
      - Complex topic patterns beyond simple prefix matching
    - Add HTTP policy complexity scenarios (HTTP-POLICY-SIMPLE, HTTP-POLICY-MED,
      HTTP-POLICY-COMPLEX) to test policy evaluation cost vs token-based
    - Update scenario documentation to reflect HTTP policy capabilities and
      limitations
    - Ensure HTTP policy scenarios can be compared directly against equivalent
      JWT/Biscuit policy scenarios

- [ ] **Issue 21: Strengthen Biscuit authorizer template complexity**
  - Goal: Expand the Biscuit authorizer template beyond the minimal
    `right(op,res)` match to represent more realistic policy complexity (while
    preserving request-context injection and Biscuit scoping constraints).
  - Rationale: current template is too "thin" and may under-represent the
    cost/benefit of Biscuit's Datalog evaluation compared to intended research
    scenarios.
  - Deliverable:
    - Add configurable authorizer "profiles" (e.g., `simple`, `rbac`,
      `contextual`) or a template file option
    - Include policies with:
      - role membership / derived permissions
      - topic prefix/wildcard patterns
      - time-based constraints using authorizer-provided `time(...)`
    - Add at least one scenario that measures increasing authorizer complexity
      at constant token size

#### F) Matrix Coverage (Benchmark Verification)

- [ ] **Issue 22: Expiry enforcement in ACL_CHECK with disconnect (no reason codes)**
  - Goal: On expired tokens, rely on `MOSQ_EVT_ACL_CHECK` to deny access and
    forcibly disconnect the client, since ACL checks do not support MQTT v5
    reason codes/strings for explicit expiry signaling.
  - Current state: `ACL_CHECK` returns `MOSQ_ERR_ACL_DENIED` on
    `AuthzOutcome::Expired` but does **not** disconnect the client.
  - Constraints:
    - Do not send or depend on reason codes in ACL checks.
    - Avoid full token signature verification in `ACL_CHECK`; only validate
      expiry and policy evaluation (authz). Cryptographic verification should
      remain in auth/enhanced-auth entrypoints.
  - Deliverable:
    - Add explicit disconnect path when `AuthzOutcome::Expired` is returned in
      `ACL_CHECK` (document which Mosquitto API is used).
    - Document rationale: ACL_CHECK is the authoritative access gate; expiry
      means immediate disconnect without reason codes.

- [ ] **Issue 23: Proactive client reauthentication before expiry**
  - Goal: Clients refresh tokens proactively and initiate MQTT v5 reauth at
    least one minute before token expiration, minimizing ACL denials.
  - Deliverable:
    - Client-side refresh timer logic using the token `exp` claim.
    - Request a new token from the Token Issuer and send an AUTH packet with
      fresh credentials at least 60 seconds before expiry.
    - Update benchmark clients/scenarios to exercise proactive refresh flow.

- [ ] **Issue 24: Decide whether multi-step `MOSQ_EVT_EXT_AUTH_CONTINUE` is in
     research scope**
  - Goal: Determine whether implementing true multi-step enhanced authentication
    (state machine across multiple AUTH packets) is required for the paper's
    hypotheses, or whether the single-step "token refresh" model is sufficient.
  - Notes:
    - Current implementation treats enhanced auth as single-step (CONTINUE
      delegates to START).
    - Multi-step flows add state-management complexity that may not affect
      JWT-vs-Biscuit comparison unless explicitly tested.
  - Deliverable:
    - Document a decision: in-scope vs out-of-scope, with justification tied to
      hypotheses/metrics
    - If in-scope:
      - Implement multi-step auth state handling (per client/session) and add at
        least one scenario measuring multi-step overhead

- [ ] **Issue 25: Optional full authz on ACL_READ behind a flag (default expiry-only)**
  - Goal: Support full authorization checks on `MOSQ_EVT_ACL_CHECK` +
    `MOSQ_ACL_READ` behind a config flag (disabled by default) to avoid
    per-subscriber performance penalties in high fan-out scenarios.
  - Rationale: Full Datalog/HTTP/SQLite checks on every read can be too costly;
    default behavior should only validate token expiry for read fan-out, while
    leaving the full authz path available for correctness experiments.
  - Deliverable:
    - Add a config option (e.g., `acl_read_full_authz`) defaulting to false.
    - When false, `ACL_READ` only validates expiry (no full authz).
    - When true, run full authz checks and document the expected performance hit.

- [ ] **Issue 28: Verify static-policy benchmark coverage (ACL_SUBSCRIBE/WRITE)**
  - Goal: Confirm scenarios exist for static policies where `ACL_SUBSCRIBE` and
    `ACL_WRITE` are enforced, and `ACL_READ` is either disabled or documented
    when used.
  - Deliverable:
    - Inventory scenarios for Static ACL, Dynamic Security, SQLite, HTTP

- [ ] **Issue 29: Add anonymous flow scenario via anonymousGroup policy**
  - Goal: Enable and benchmark anonymous MQTT clients using Mosquitto’s
    `allow_anonymous true` with a Dynamic Security `anonymousGroup` policy.
  - Rationale: Demonstrates how Dynamic Security can enforce policies for
    unauthenticated clients, useful for public/telemetry use cases and to
    validate that the authz plugin correctly handles `None` usernames.
  - Current state: Plugin now supports optional usernames in DynamicSecurity
    checks; broker configs and a minimal anonymousGroup fixture are in place.
  - Deliverables:
    - Add `ANON-BASE` scenario to `benchmarks/run_scenarios.py` using
      `mosquitto_anon.conf` and `dynamic-security-anon.json`.
    - Clients connect without username/password and publish/subscribe to
      `public/announce`.
    - Verify authorization decisions (allow/deny) match the anonymousGroup
      policy.
    - Capture latency/throughput metrics for anonymous access vs token-based.
    - Document when anonymous flows are realistic and their security trade-offs.

- [ ] **Issue 30: Verify dynamic-policy coverage with ACL_READ fan-out checks**
  - Goal: Ensure dynamic policy scenarios enforce changes via `ACL_READ` for
    existing subscribers (fan-out), not just on subscribe.
  - Deliverable:
    - Scenario(s) for Dynamic Security with `ACL_READ` checks enabled
    - Scenario(s) for SQLite with policy churn + `ACL_READ` checks enabled
    - Results include subscriber counts to observe scaling effects

- [ ] **Issue 31: Verify control-triggered dynamic enforcement (kick/re-auth)**
  - Goal: Implement/control scenarios where `$CONTROL/.../v1` triggers
    enforcement via kicking/re-auth (no `ACL_READ` fan-out checks).
  - Deliverable:
    - Control message publisher used during scenario
    - Evidence of client re-auth or reconnect behavior

- [ ] **Issue 32: Verify control-triggered dynamic enforcement (ACL_READ + notify)**
  - Goal: Implement/control scenarios where `$CONTROL/.../v1` triggers cache
    invalidation and clients are informed via a notification topic while
    `ACL_READ` denies fan-out.
  - Deliverable:
    - Notification topic publishing (e.g., `system_notification/<client_id>`)
    - Scenario capturing denial after privilege reduction

- [ ] **Issue 36: Add interleaved control message support for data plane + control plane testing**
  - **Goal**: Implement support for publishing control messages interleaved with data messages (e.g., publish N data messages, then 1 control message, repeat) to measure control plane latency under active data plane load.
  - **Rationale**: Current CONTROL scenarios test control plane in isolation (CONTROL-OVERHEAD) or batch policy churn (CONTROL-CHURN), but do not capture the realistic scenario where control messages (policy updates, reauthentication triggers) must be processed while ongoing data traffic continues. This enables measurement of broker behavior under mixed data+control plane stress.
  - **Current state**: The `--control-after-messages` CLI option was defined in `loadgen.py` but never implemented; it has been removed to avoid technical debt. The feature needs fresh implementation with proper design.
  - **Deliverable**:
    - Add `--control-after-messages` CLI option to `loadgen.py` with proper implementation in `_run_worker()`
    - Track message counter during data publishing; pause/resume data flow to send control messages at specified intervals
    - Handle interaction with rate limiting (`--rate`) to ensure interleaving works correctly with throttled publishing
    - Add interleaved CONTROL scenarios to `run_scenarios.py` (e.g., `INTERLEAVED-CONTROL-DATA-JWT`, `INTERLEAVED-CONTROL-DATA-BISCUIT`)
    - Capture separate metrics for:
      - Data message latency (baseline under interleaved control)
      - Control message latency (measured while data flow active)
      - Control message injection delay (time to pause/resume data flow)
    - Document in RUNNING_BENCHMARKS.md the methodology for interleaved testing and interpretation of results

---

## 9) Completed Issues (Backlog)

- [x] **Issue 1: Add Dynamic Security module comparison**
  - **Completed**: Full Dynamic Security module implementation with JSON-based policy loading, role-based access control, and comprehensive ACL support. Added anonymous access, benchmark scenarios, and Docker configurations. Provides production-grade comparison against token-based approaches.

- [x] **Issue 2: Add static ACLs as PDP source of truth (backend)**
  - **Completed**: Implemented hybrid static ACL compounding with Mosquitto's built‑in ACLs. Added role-to-synthetic-username mapping for JWT/Biscuit tokens, configured plugin to allow when the token authorizes and defer to native ACL checks when the token denies (`StaticAcl` OR semantics), and created benchmark scenarios. **Pivot**: Instead of plugin-loaded ACL files, uses Mosquitto's native `acl_file` with compound authorization (token allow OR ACL allow). Removed plugin-side static ACL backend. Updated Docker configs and sample ACL files for role-based usernames and fallback patterns.

- [x] **Issue 3: Implement proper JWT access logic (replace demo token-only authz)**
  - **Completed**: Replaced demo JWT token-only checks with structured grants
    schema (`grants` + `denies`) and access-aware enforcement (`publish`,
    `subscribe`, `read` with `ACL_READ` fallback to `subscribe`). Token issuer
    and deterministic token generator updated to mint the new schema. **Note:**
    scenario run capture is pending due to current runner bug.

- [x] **Issue 3.1: Add explicit deny semantics for token-only policy model**
  - **Completed**: Added `denies` to JWT claims and Biscuit `deny(op, res)`
    facts, enforced deny-over-allow precedence for token-only authorization,
    and added tests + documentation covering ACL_READ/ACL_SUBSCRIBE behavior.

- [x] **Issue 4: Harden HTTP policy backend for benchmark validity**
  - Summary: Made HTTP backend robust and well-specified for experiments. Added configurable timeout (`http_timeout_seconds`) and response size limits (`http_max_response_bytes`), documented request/response schema and hybrid fallback semantics in RUNNING_BENCHMARKS.md and README.md. Enforced strict JSON parsing, content-type validation, 200-only responses, and TLS support with insecure mode for testing.

- [x] **Issue 5: Avoid per-message Biscuit re-verification**
  - Summary: Cache parsed Biscuit at authentication time and reuse it for ACL checks, avoiding per-message cryptographic verification while preserving per-request Datalog evaluation. Authorization now mirrors JWT behavior (verify once, evaluate policies per message).
  - Note: benchmark rerun + documentation update still pending to quantify latency/CPU impact.

- [x] **Issue 6: Implement online attenuation capabilities for MQTT clients**
  - Summary: Added client-side Biscuit attenuation tooling, integrated it into
    loadgen/scenarios with metrics, and documented attenuation patterns.

- [x] **Issue 7: Fix delegation scenario simulation vs actual client delegation**
  - Summary: Implemented runtime client-to-client delegation with MQTT handoff,
    added a handoff token and scenarios, and captured delegation metrics.

- [x] **Issue 8: Implement a long-running Token Issuer service (JWT + Biscuit)**
  - Summary: Complete token issuer service with HTTP endpoints for JWT/Biscuit
    issuance, proper security separation, Docker integration, and token refresh
    support in benchmark scenarios.

- [x] **Issue 8.1: Implement comprehensive TLS support for all network
    communications**
  - Summary: TLS support implemented for all external network paths (MQTT, Token
    Issuer, Authz PDP, Prometheus/cAdvisor UIs). Internal Prometheus-cAdvisor
    scraping remains HTTP-only as TLS would provide minimal security benefit for
    internal Docker network traffic.

- [x] **Issue 9: Document and analyze scenario policies** — **COMPLETED 2026-02-03**
  - **Summary**: Created comprehensive `SCENARIO_POLICIES.md` documenting all authorization policies across test scenarios. Established JWT/Biscuit parity with MQTT wildcard matching in token-only mode, analyzed policy complexity fairness (block-chain vs Datalog complexity), documented 7 scenario categories (baseline, complexity, HTTP, static ACL, dynamic security, lifecycle, biscuit-only), identified 4 parity gaps, and provided 5 recommendations for research-valid comparisons. All deliverables completed including policy-to-scenario mapping, fairness analysis, and cross-referenced file index.

- [x] **Issue 11: MIRI verification for FFI memory safety**
  - Summary: MIRI CI + tests cover FFI pointer safety and lifecycle invariants.

- [x] **Issue 12: Kani verification for critical FFI functions**
  - Summary: Kani proofs for init/cleanup + all callbacks (null safety,
    lifetimes).

- [x] **Issue 14: Add iperf3 baseline (throughput interpretation)** — **COMPLETED 2026-02-06**
  - **Summary**: Implemented `iperf3` integration to measure nominal channel capacity as specified in ARTICLE.MD methodology. Added `iperf3` service to docker-compose.yml, created `benchmarks/iperf3_baseline.py` module with measurement, parsing, and validity checking functions. Integrated automated baseline measurement into `run_scenarios.py` with CLI options (`--iperf3/--no-iperf3`, `--iperf3-host`, `--iperf3-port`, `--iperf3-duration`, `--iperf3-streams`, `--iperf3-min-mbps`). Network capacity data included in scenario results JSON under `network_baseline` field with throughput, RTT, retransmits, and validity assessment. Warns when network constraints may affect test validity.

- [x] **Issue 16: Add host-targeted kernel-level performance profiling with perf** — **COMPLETED 2026-02-06**
  - **Summary**: Implemented comprehensive `perf` integration for detailed CPU performance analysis of containerized Mosquitto during token verification and policy evaluation.
  - **Deliverables**:
    - `benchmarks/perf_profiler.py`: Complete perf profiling module with host-level capabilities
      - Container PID discovery mechanism for targeting Mosquitto process
      - Hardware event collection (cycles, instructions, cache-misses)
      - CPI (cycles per instruction) and cache miss rate calculation
      - Support for call graph recording with `perf record`
      - Automatic perf binary detection (handles versioned perf_5.x, perf_6.x)
    - Integration with `run_scenarios.py`:
      - `--perf` flag to enable profiling
      - `--perf-duration`, `--perf-sample-rate`, `--perf-events` configuration
      - `--perf-scenarios` for selective profiling
      - Default profiling for key scenarios (BASE-01, JWT-01, BIS-01, POLICY-COMPLEX-*)
    - Results included in scenario JSON output with structured perf data
    - `benchmarks/PERF_PROFILING.md`: Comprehensive documentation with methodology, interpretation guide, and troubleshooting
  - **Research Alignment**: Enables H₂/H₃ validation by quantifying computational costs of JWT vs Biscuit verification at instruction level, complementing container-level metrics with PMU hardware counters.

- [x] **Issue 17: Implement comprehensive QoS configuration and mixing features**
  - **Completed**: Added full QoS 0/1/2 support with configurable per-scenario QoS levels and mixed QoS workload distribution.
  - **Summary**: Implemented QoS distribution parsing (`0:0.6,1:0.3,2:0.1` format) in `loadgen.py` with weighted random selection for realistic traffic patterns. Added `--qos-distribution` CLI option and `qos_distribution` field to `WorkerConfig`. Fixed `BASE-01` to use QoS 0 as required. Added new scenarios: `QOS0-BASE-01`, `QOS2-JWT`, `QOS2-BISCUIT`, `QOS-MIXED-JWT`, `QOS-MIXED-BISCUIT` (60% QoS 0, 30% QoS 1, 10% QoS 2). Updated `metrics_collector.py` to support configurable QoS. Subscribe operations use effective QoS (max of distribution) to ensure reliable fan-out delivery. All QoS infrastructure is ready for experimental runs.

- [x] **Issue 18: Avoid Base64URL encoding for Biscuit tokens where possible (use native Protobuf format)** — **COMPLETED 2026-02-06**
  - **Summary**: Implemented native Protobuf transport for Biscuit tokens via MQTT v5 AUTH packets, avoiding ~33% Base64URL overhead while maintaining CONNECT password compatibility.
  - **Deliverables**:
    - Added `biscuit_transport` config option with two modes: `base64url` (default, CONNECT compatible) and `mqtt5_auth_data` (native binary Protobuf for MQTT v5 AUTH packets)
    - Updated `auth.rs` with `authenticate_binary()` method supporting both transport modes
    - Updated `ext_auth_start_callback` in `lib.rs` to use binary authentication for AUTH packets
    - Added `/biscuit/binary` endpoint to token-issuer for raw binary token generation
    - Updated `mqtt_auth_client.py` with `--binary` flag for binary transport testing
    - Added `MQTT5-REAUTH-BISCUIT-BINARY` scenario demonstrating native Protobuf transport
  - **Technical Details**: Biscuit's native `Biscuit::to_vec()` produces Protobuf-encoded bytes; Base64URL inflates size by ~33%; binary transport only available for MQTT v5 AUTH packets (not CONNECT password); JWT tokens remain text-based
  - **Research Alignment**: Enables fair MTU/fragmentation comparisons by eliminating encoding bias between JWT (text-based) and Biscuit (binary-capable) token formats

- [x] **Issue 19: Validate ACL_READ fan-out authorization cost measurement**
  - **Summary**: Verified `acl_check_callback` correctly handles `MOSQ_ACL_READ` (0x01) for per-subscriber delivery authorization using `evt.client` as subscriber identity. Added 6 benchmark scenarios (`ACL-READ-FANOUT-10/50/100` for JWT and Biscuit) with 1 publisher + N subscribers on shared topic. Added `fanout_metrics` output capturing `subscriber_count`, `message_count`, and `acl_read_cost_per_subscriber_ms` calculated from receive latencies. Enables H₂/H₃ validation of per-subscriber authorization scaling costs.

- [x] **Issue 20: Define CONTROL callback semantics + enforcement paths** — **COMPLETED 2026-02-06**
  - **Summary**: Implemented complete `MOSQ_EVT_CONTROL` callback with proper control-plane semantics, topic gating, and comprehensive documentation.
  - **Deliverables**:
    - **Topic gating**: Added `$CONTROL/` prefix check with `MOSQ_ERR_PLUGIN_DEFER` for non-control topics
    - **Dedicated access flag**: Uses `MOSQ_ACL_CONTROL` (0x08) for control-plane authorization
    - **Comprehensive documentation**: Added detailed rustdoc covering authorization flow and enforcement variants
    - **Benchmark scenarios**: Added 4 CONTROL scenarios (KICK-REAUTH and ACL-READ-NOTIFY variants for JWT/Biscuit)
    - **Unit tests**: Added `control_callback_defers_non_control_topics` test
  - **Code Pointers**: @/home/eagle/TCC2/mqtt-auth-biscuit/crates/mosquitto-plugin/src/lib.rs#1001-1141

- [x] **Issue 20.1: Verify ACL_CHECK subtype handling across policy modes**
  - **Summary**: Added `MOSQ_ACL_CONTROL` constant (0x08) for control-plane access; fixed `control_callback` hardcoded `access: 2` → `MOSQ_ACL_CONTROL`; updated `access_to_operation()` to map 0x08 → "control"; added comprehensive unit tests for all ACL subtypes (READ/WRITE/SUBSCRIBE/CONTROL) with priority ordering (WRITE > SUBSCRIBE > CONTROL > READ), bitmask combinations, and edge cases. All 7 policy modes verified to correctly handle distinct ACL subtypes.

- [x] **Issue 27: Cache Biscuit expiry via min `expires_at` fact (remove brittle parsing)**
  - Summary: Replaced brittle error-message parsing with structured Datalog query to extract the minimum `expires_at` from Biscuit tokens. Updated `TokenType::Biscuit` to cache the expiry timestamp per session, clamped cache TTL to token expiry with a 5-minute fallback, and rejected already-expired tokens at auth time. Token issuer and benchmark generators now embed `expires_at` facts in authority and attenuation blocks to support stable expiry extraction.

- [x] **Issue 34: Implement real LRU eviction in `SessionCache`**
  - Summary: Enforced cache capacity with true LRU eviction, added capacity tracking, edge case handling, and comprehensive unit tests.

- [x] **Issue 35: Add Dynamic Security command payloads to CONTROL scenarios** — **COMPLETED 2026-02-06**
  - **Summary**: Added Dynamic Security JSON command payloads to CONTROL scenarios, creating separate CONTROL-OVERHEAD (authorization only) and CONTROL-CHURN (actual policy modifications) scenario variants.
  - **Deliverables**:
    - Created `benchmarks/dynsec_commands.py` module with Dynamic Security command generators (createRole, deleteRole, addGroupClient, etc.)
    - Extended `loadgen.py` with CONTROL message publishing support (CLI options: --control-topic, --control-payload, --control-payload-file, --control-mode, --control-repeat)
    - Renamed existing scenarios to CONTROL-OVERHEAD-* (authorization overhead only)
    - Added new CONTROL-CHURN-* scenarios with actual policy modifications (CREATE-ROLE, GROUP-CLIENT, ACL-MODIFY variants for JWT/Biscuit)
    - Updated `run_scenarios.py` with control scenario configuration and _run_loadgen integration
    - Added documentation in RUNNING_BENCHMARKS.md explaining scenario differences and CLI usage
    - JWT/Biscuit parity maintained for both overhead and churn scenarios
  - **Research Alignment**: Enables measurement of both authorization overhead and end-to-end policy churn costs, supporting H1 (functional viability) and H2/H3 (performance comparison) validation

---

### 11) Last Phase: Data Analysis & Validation

- [ ] **Aggregate results**
  - Collect scenario JSONs and generate a summary table (latency p50/p95/p99,
    throughput, errors, CPU/memory).
- [ ] **Validate hypotheses / identify crossover points**
  - Identify when Biscuit becomes more/less expensive than JWT under:
    - MTU constraints
    - policy complexity (block count)
    - external authz latency/failure

---

## 12) Known Risks / Things to Watch

- **Docker permissions**: `tc netem` requires `CAP_NET_ADMIN` (already
  configured in compose).
- **MTU edge cases**: very low MTU can cause unexpected behavior depending on
  Docker networking and host kernel.
- **HTTP fallback semantics**: hybrid mode relies on HTTP failures being treated
  as errors (non-200 => error) to trigger fallback.

---

## 13) Dependency Optimization Note

Optimize dependency features in `Cargo.toml` by disabling unused default
features to ensure accurate performance measurements. This should be done
**before** running benchmarks to:

- Measure realistic binary sizes for production deployments
- Avoid performance overhead from unused features
- Ensure fair JWT vs Biscuit comparison with optimal configurations
- Document any features needed for specific benchmark scenarios

---

## 14) Research Footnotes

### Biscuit parsing cache vs per-message verification

- **Decision**: Parse/verify Biscuit tokens once during authentication, cache the parsed token in session state, and reuse it for per-message authorization checks.
- **Rationale**: JWT verification is already performed once at auth time; per-message Biscuit re-verification would bias latency/CPU comparisons. Caching preserves fairness while still running Datalog authorization for each ACL check.
- **Validity guardrail**: Only cryptographic verification is cached; policy evaluation still occurs on every request (ACL defers to authorizer), preserving per-message cost measurement and policy semantics.

### Why `netem` runs in a separate container with `network_mode: service:mosquitto`

- **Least privilege**: Traffic shaping needs `CAP_NET_ADMIN`. By running `netem`
  in a separate container that joins the Mosquitto network namespace, we avoid
  granting the broker container elevated capabilities.
- **Clean separation**: The broker image stays minimal (no `iproute2` or shaping
  scripts). Impairments are toggled via environment variables without rebuilding
  the broker.
- **Precise targeting**: `network_mode: service:mosquitto` ensures `tc qdisc`
  commands affect the broker's interfaces directly, not a dummy NIC.

### Why `cadvisor` is separate from Prometheus

- **Isolation of failure domains**: If cAdvisor or Prometheus restarts/crashes,
  the other remains available.
- **Security boundary**: cAdvisor requires sensitive host mounts (`/sys`,
  `/var/lib/docker`); Prometheus does not. Combining them expands the
  container's attack surface unnecessarily.
- **Clarity and reproducibility**: Explicit services make the measurement
  pipeline easier to reason about and match common deployment patterns.
- **Operational simplicity**: Both tools are maintained as upstream images;
  merging would require a custom image and adds operational overhead.

### MQTT v5 AUTH Packet Implementation

**Context**: The research design requires measuring broker-side token
verification latency during MQTT v5 enhanced authentication flows, specifically
reauthentication via `AUTH` packets (reason code `0x19`) for token renewal
without disconnection.

**Implementation Decision**: Paho Python does not provide a straightforward
public API for programmatically sending `AUTH` packets after connection
establishment. The library supports enhanced authentication during the initial
CONNECT/CONNACK handshake but lacks methods like `send_auth()` or
`reauthenticate()` for triggering mid-session re-authentication.

**Workaround**: `benchmarks/mqtt_auth_client.py` implements a minimal raw-socket
MQTT5 client that:

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
  viability, cryptographic verification costs, and policy evaluation latency
  are measured server-side and unaffected by client implementation details.

### JWT Algorithm and Cryptographic Backend Choices

**Context**: The benchmark design requires fair comparison between JWT and
Biscuit token verification under realistic production conditions while
maintaining research validity.

**Implementation Decision**:

- **JWT algorithm baseline**: the current deterministic benchmark token set uses
  **ES256** (asymmetric, P-256). The keypair is deterministically generated by
  `benchmarks/gen_tokens.rs`, and only the **public key** is mounted into the
  Mosquitto container (`docker/jwt_public.pem`).
- **Cryptographic Backend**:
  - JWT verification uses `jsonwebtoken` with the `aws_lc_rs` backend
    (C/Assembly optimized via AWS-LC), representing a production-grade baseline.
    Given it requires a C compiler, the plugin shared library is pre-built on
    host and copied to container, eliminating need for the tools in Docker.
  - Biscuit verification uses `biscuit-auth` (Ed25519). The underlying signature
    verification is pure-Rust (via `ed25519-dalek` in the Biscuit stack). This
    asymmetry (optimized JWT backend vs pure-Rust Biscuit backend) is
    intentional to test Biscuit against an industry-standard optimized
    implementation.

- **JWT expiration enforcement**: JWT `exp` is verified on each authorization
  decision (ACL/message/control), even when using cached session state.

**Impact on Research Validity**:

- **Production-representative JWT baseline**: Using AWS-LC optimized backend
  provides a realistic industry-standard JWT performance baseline rather than a
  pure-Rust implementation that would artificially favor Biscuit.
- **Fair cryptographic comparison**: ES256 (P-256) and Ed25519 are both modern
  elliptic curve schemes with comparable security levels, ensuring the
  comparison focuses on token format and policy evaluation rather than
  cryptographic strength.
- **Consistent expiration handling**: Enforcing JWT expiration on every
  authorization decision matches the Biscuit approach where policies are
  evaluated per-request, maintaining fairness in comparison.
