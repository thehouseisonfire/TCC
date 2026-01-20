# Project Progress Tracker

**Project**: Eclipse Mosquitto Auth Biscuit Plugin (Rust)\
**Started**: 2026-01-04\
**Last Updated**: 2026-01-19\
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

### 8) Open Issues (Next Steps, Grouped)

#### A) Policy Source Parity

- [ ] **Issue 1: Add Dynamic Security module comparison**
  - Goal: Implement Mosquitto's Dynamic Security module as an authorization
    source to provide a comprehensive comparison against token-based approaches.
  - Current gap: ARTICLE.MD mentions "Dynamic ACLs (via the Dynamic Security
    module)" as a policy source, but current implementation lacks this native
    Mosquitto authorization mechanism.
  - Rationale: Dynamic Security is Mosquitto's built-in role-based access
    control system that provides runtime management of users, roles, and ACLs
    via MQTT control messages or HTTP API, representing a production-grade
    alternative to external policy backends.
  - Deliverable:
    - Add `DynamicSecurity` variant to `PolicyMode` enum in `src/policy.rs`
    - Implement Dynamic Security client integration in
      `src/dynamic_security_policy.rs` using Mosquitto's HTTP API or control
      message interface
    - Update plugin configuration to support `dynamic_security_url` and
      `dynamic_security_username/password` options
    - Create Dynamic Security setup scripts for benchmark scenarios
      (user/role/ACL provisioning matching test patterns)
    - Add Dynamic Security scenarios to `benchmarks/run_scenarios.py` with
      comparable load patterns to existing policy modes
    - At least one scenario run captured with Dynamic Security enabled,
      including latency measurements for authorization checks via the Dynamic
      Security API. The scenario should be configurable to measure the impact of
      runtime management of users, roles, and ACLs, perhaps with a special
      client pushing periodic, deterministic ACL changes.
    - Performance comparison analysis between Dynamic Security and token-based
      authorization modes

- [ ] **Issue 2: Add static ACLs as PDP source of truth**
  - Goal: implement native Mosquitto static ACL file support as a policy source
    to align with the evaluation matrix proposed in ARTICLE.MD (line 59).
  - Current gap: ARTICLE.MD explicitly mentions testing against "static ACLs
    native to Mosquitto" as a PDP source, but current implementation only
    supports token-only, SQLite, HTTP, and hybrid modes.
  - Deliverable:
    - Add `StaticAcl` variant to `PolicyMode` enum in `src/policy.rs`
    - Implement ACL file parsing and evaluation logic in
      `src/static_acl_policy.rs`
    - Update plugin configuration to support `acl_file` option in Mosquitto
      config
    - Add static ACL scenarios to `benchmarks/run_scenarios.py` comparable to
      existing policy modes (token-only, SQLite, HTTP, hybrid)
    - Create sample ACL files for benchmark scenarios matching the test patterns
    - At least one scenario run captured with static ACL mode enabled

- [ ] **Issue 3: Implement proper JWT access logic (replace demo token-only
     authz)**
  - Goal: replace the current heuristic JWT token-only authorization rules with
    a policy model that is comparable to Biscuit rights (e.g., encode
    topic/action grants as structured claims, or route JWT through SQLite/HTTP
    for fine-grained checks).
  - Deliverable:
    - Updated claim schema + token generator support
    - Updated `authz.rs` JWT enforcement that matches the chosen schema
    - At least one scenario run captured showing the new JWT mode

- [ ] **Issue 4: Harden HTTP policy backend for benchmark validity**
  - Goal: make the HTTP backend robust and well-specified for experiments.
  - Deliverable:
    - Clear request/response schema (documented) and stricter parsing
    - Configurable timeouts and error semantics (what triggers hybrid fallback)
    - Optional support for HTTPS (if required by the environment)

#### B) Benchmark Fidelity & Tooling

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
  - Notes / scope:
    - This should be implemented as an optional benchmark mode (not mandatory
      for all runs), so results can be compared between "host loadgen" and
      "containerized clients".
    - This issue is about benchmark topology only; Token Issuer separation is
      handled by Issue 8, and external authorization PDP separation is already
      modeled by the `authz` container.
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

- [ ] **Issue 14: Add network baseline capacity measurement with iperf3**
  - Goal: implement `iperf3` integration to measure nominal channel capacity as
    specified in ARTICLE.MD methodology.
  - Rationale: Establishing baseline network capacity before experiments is
    essential for interpreting throughput results and ensuring fair comparisons.
  - Deliverable:
    - Add `iperf3` service to docker-compose.yml for network capacity
      measurement
    - Automated baseline measurement step in scenario runner before each test
      batch
    - Network capacity data included in scenario results JSON
    - Ability to detect and report when network constraints affect test validity

- [ ] **Issue 15: Add packet-level analysis with tcpdump for fragmentation
     studies**
  - Goal: integrate `tcpdump` capture capabilities to analyze TCP fragmentation
    behavior during MTU stress tests.
  - Rationale: ARTICLE.MD specifically mentions fragmentation analysis, and
    packet-level data is essential for understanding how token size affects
    network behavior under MTU constraints.
  - Deliverable:
    - Add `tcpdump` service to docker-compose.yml with appropriate capabilities
    - Packet capture integration for MTU scenarios (200B, 500B, 1500B, 9000B)
    - Automated packet analysis to count fragments, retransmissions, and delays
    - Packet analysis results included in scenario outputs
    - Correlation of fragmentation data with latency/throughput metrics

- [ ] **Issue 16: Add host-targeted kernel-level performance profiling with
     perf**
  - Goal: integrate `perf` for detailed CPU performance analysis of
    containerized Mosquitto process during token verification and policy
    evaluation.
  - Rationale: Container-level metrics may miss important CPU performance
    characteristics; host-targeted `perf` provides instruction-level profiling
    needed for understanding computational costs of JWT vs Biscuit verification
    while maintaining container isolation.
  - Deliverable:
    - Host-level `perf` installation and configuration script
    - Container PID discovery mechanism to find Mosquitto process within
      container
    - Performance profiling integration for key scenarios (baseline, policy
      complexity)
    - CPU cycle, instruction, and cache miss data collection targeting
      containerized process
    - Performance profiling data included in scenario results
    - Analysis correlating perf data with token type and policy complexity
    - Documentation of profiling methodology for reproducibility

- [ ] **Issue 17: Implement comprehensive QoS configuration and mixing
     features**
  - Goal: Add support for different QoS levels (0, 1, 2) and mixed QoS workloads
    to enable comprehensive performance analysis across quality of service
    levels.
  - Current gap: All scenarios currently use QoS 1 exclusively, despite
    BENCHMARK_PLAN.md specifying QoS 0 for BASE-01 and missing QoS 2 testing
    entirely.
  - Rationale: QoS levels significantly impact MQTT broker behavior and token
    verification overhead:
    - QoS 0: Fire-and-forget, minimal broker state
    - QoS 1: At-least-once delivery with acknowledgments
    - QoS 2: Exactly-once delivery with four-step handshake
  - Deliverable:
    - Update `loadgen.py` to support QoS distribution configuration (e.g., 60%
      QoS 0, 30% QoS 1, 10% QoS 2)
    - Add scenario-specific QoS configuration in `run_scenarios.py`
    - Fix BASE-01 scenario to use QoS 0 as planned
    - Add dedicated QoS 2 scenarios for both JWT and Biscuit
    - Add mixed QoS workload scenarios to test realistic IoT traffic patterns
    - Update `metrics_collector.py` to support configurable QoS
    - Add QoS-specific performance analysis and reporting
    - At least one scenario run captured for each QoS level and mixed
      configurations

#### C) Biscuit/JWT Fairness & Policy Complexity

- [ ] **Issue 5: Avoid per-message Biscuit re-verification**
  - Goal: avoid re-verifying/deserializing the Biscuit token on every
    authorization check to match JWT behavior (verify once, evaluate policies
    only).
  - Current issue: Biscuit verification cryptographically verifies and runs
    policies during each authorization check, while JWT is only verified once
    per session.
  - Deliverable: a documented change (and rerun) showing the impact on
    authorization latency/CPU.

- [ ] **Issue 9: Document and analyze scenario policies**
  - Goal: create comprehensive documentation of all Biscuit and JWT policies
    used across test scenarios to ensure fair comparison and research validity.
  - Current issue: Biscuit uses production-grade Datalog policies while JWT uses
    demo-like string matching, creating an unfair comparison.
  - More advanced and intricate policies should be proposed for biscuit, and JWT
    should be tested as both holding intricate policies and basic role
    affirmations, of which the PDP will derive permissions at each request
  - Deliverable:
    - `SCENARIO_POLICIES.md` documenting all authorization policies per scenario
    - Analysis of policy complexity and fairness between JWT and Biscuit
      implementations
    - Recommendations for policy alignment to ensure valid benchmark comparisons
    - Mapping of each scenario to its specific policy rules and expected
      behaviors

- [ ] **Issue 18: Avoid Base64 encoding for Biscuit tokens (use native bytes /
     Protobuf wire format)**
  - Goal: Stop wrapping Biscuit tokens in Base64 for transport where possible,
    using the token's native binary serialization.
  - Investigation note: confirm whether `biscuit-auth` serialization
    (`Biscuit::to_vec`) is already Protobuf-encoded on the wire (expected), and
    whether Base64 is currently only a _transport_ layer artifact.
  - Rationale: Base64 inflates size and may bias MTU/fragmentation experiments
    and JWT-vs-Biscuit parity.
  - Deliverable:
    - Confirm the underlying Biscuit serialization format used by `biscuit-auth`
      (and document it)
    - Add a transport mode option for Biscuit credentials:
      - `biscuit_transport=base64` (current behavior, CONNECT password
        compatible)
      - `biscuit_transport=mqtt5_auth_data` (binary auth data for MQTT v5
        enhanced auth)
    - Update `auth.rs` parsing to support the selected transport mode without
      changing token semantics
    - Ensure the token issuing HTTP endpoint is updated to use the selected
      transport mode for the Biscuit token, instead of the JSON payload it uses
      for both token types
    - Add at least one scenario that exercises the binary transport path for
      Biscuit (and documents parity constraints vs JWT)

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

- [ ] **Issue 22: Strengthen `seed_demo_rules` (RBAC), make it optional, and add
     runtime policy churn scenarios**
  - Goal: Turn SQLite demo seeding into a realistic RBAC policy set, allow it to
    be turned off, and add scenarios where policies change periodically at
    runtime.
  - Current issue: seeding is unconditional when `PolicyMode::Sqlite` is used,
    and policies are too simple for RBAC fairness studies.
  - Deliverable:
    - Add a configuration flag to enable/disable demo seeding (e.g.,
      `sqlite_seed_demo_rules=true|false`)
    - Extend SQLite schema and seeding to include RBAC-like structure
      (users/roles/role_acls), plus more realistic topic/action grants
    - Add a benchmark scenario where SQLite rules are updated deterministically
      during the run (e.g., every N seconds), to simulate dynamic policy updates
    - Ensure scenarios document when policy churn is enabled and how it affects
      cache validity

#### D) Client-Side Attenuation & Delegation

- [ ] **Issue 6: Implement online attenuation capabilities for MQTT clients**
  - Goal: enable MQTT clients to perform runtime biscuit attenuation and
    delegation, moving beyond pre-generated tokens to dynamic rights
    restriction.
  - Current limitation: clients can only use pre-attenuated tokens from
    `gen_tokens.rs`; they cannot create new attenuation blocks or delegate
    rights at runtime.
  - Deliverable:
    - Client library/API for biscuit attenuation (add blocks, restrict rights,
      delegate)
    - Integration with MQTT client workflows to support dynamic token
      modification
    - Benchmark scenarios that test client-side attenuation performance and
      behavior
    - Documentation of attenuation patterns and use cases for IoT deployments

- [ ] **Issue 7: Fix delegation scenario simulation vs actual client
     delegation**
  - Goal: replace the simulated delegation in `gen_tokens.rs` with true
    client-to-client delegation.
  - Current issue: the "delegation" scenario uses pre-attenuated tokens created
    by the token generator, not actual master clients attenuating rights for
    worker clients.
  - Deliverable:
    - Real master client implementation that can attenuate and delegate tokens
      to workers
    - Worker client logic to receive and use delegated tokens
    - Updated delegation benchmark scenario with actual client-side delegation
    - Performance comparison between simulated and real delegation flows

#### E) Correctness & Semantics

- [ ] **Issue 10: Expiry-aware client signaling via MQTT v5 enhanced auth**
  - Goal: when access fails due to token expiry, make the broker/PEP signal this
    distinctly from generic policy denial, enabling clients to trigger a token
    refresh + reauthentication flow.
  - Deliverable:
    - Broker-side differentiation between "expired" vs "denied" outcomes
    - MQTT v5 `AUTH`-based reauthentication flow with explicit reason reporting
      (reason code / reason string) suitable for automated clients

- [ ] **Issue 19: Implement/validate `MOSQ_EVT_MESSAGE` fan-out per subscriber
     authorization**
  - Goal: Ensure outbound message authorization is evaluated _per subscriber
    delivery_ and is not accidentally reduced to a publish-only check.
  - Current gap: the project wires `MOSQ_EVT_MESSAGE`, but does not explicitly
    validate subscriber fan-out semantics or measure its scaling effect.
  - Deliverable:
    - Confirm Mosquitto semantics: `MOSQ_EVT_MESSAGE` is invoked once per
      subscriber in the outbound flow (identify whether `evt.client` is the
      subscriber)
    - Ensure the callback uses the subscriber identity/topic context correctly
    - Add at least one benchmark scenario with 1 publisher and N subscribers to
      demonstrate per-subscriber fan-out cost
    - Add a results field capturing subscriber count and observed scaling trend

- [ ] **Issue 20: Fix MESSAGE/CONTROL callback semantics (not publish-only)**
  - Goal: Make `MOSQ_EVT_MESSAGE` and `MOSQ_EVT_CONTROL` authorization decisions
    reflect the correct operation/access semantics rather than hardcoding
    publish.
  - Current issue: `message_callback` and `control_callback` currently pass
    `access=2` unconditionally.
  - Deliverable:
    - Define correct access semantics for MESSAGE and CONTROL callbacks (publish
      vs subscribe vs control-plane)
    - Replace hardcoded `access` values with correct values derived from
      Mosquitto event data / API expectations
    - Add targeted scenarios for:
      - subscribe-deny enforcement on outbound delivery (MESSAGE)
      - control-topic enforcement behavior (CONTROL)

- [ ] **Issue 23: Implement real LRU eviction in `SessionCache`**
  - Goal: Enforce cache capacity with true LRU eviction (not just TTL + recency
    tracking).
  - Current issue: `SessionCache` tracks LRU access but does not evict when
    capacity is exceeded.
  - Deliverable:
    - On insert, if capacity exceeded, evict least-recently-used key from both
      LRU and backing map
    - Add a minimal test/verification to confirm eviction behavior
      deterministically

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

---

## 9) Completed Issues (Backlog)

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

- [x] **Issue 11: MIRI verification for FFI memory safety**
  - Summary: MIRI CI + tests cover FFI pointer safety and lifecycle invariants.

- [x] **Issue 12: Kani verification for critical FFI functions**
  - Summary: Kani proofs for init/cleanup + all callbacks (null safety,
    lifetimes).

- [-] **Issue 25: Add configurable parity scenarios and token size alignment (half implemented)**
  - Goal: Implement configurable scenario flags to ensure fair JWT vs Biscuit
    comparisons by controlling token size, claim structure, and encoding parity.
  - Current gaps identified in code review:
    - JWT issuance includes default `roles: ["admin"]` while Biscuit issues only
      rights facts, creating token size asymmetry in refresh scenarios
    - Biscuit uses Base64 standard encoding while JWT uses Base64URL,
      potentially affecting MTU/fragmentation behavior
    - Token refresh latency is excluded from connect metrics, hiding lifecycle
      costs
  - Status update:
    - Implemented: `token-issuer` parity flags for `--jwt-no-default-roles` and
      `--biscuit-base64url`, and scenario runner plumbing to pass them through.
  - Deliverable:
    - Add CLI flags to `token-issuer` for parity modes:
      - ✅ `--jwt-no-default-roles` to match Biscuit minimal rights
      - ✅ `--biscuit-base64url` to match JWT URL-safe encoding
      - `--pad-to-size` to align token byte sizes for MTU tests
    - Update `run_scenarios.py` to accept parity configuration flags and pass
      them to token-issuer (✅ done for the two flags above)
    - Add `token_refresh_ms` metric to `loadgen.py` to capture refresh latency
      separately from connect latency
    - Create documentation of parity modes and their impact on experimental
      validity
    - Add at least one scenario run demonstrating parity-aligned token
      comparison

---

### 10) Last Phase: Data Analysis & Validation

- [ ] **Aggregate results**
  - Collect scenario JSONs and generate a summary table (latency p50/p95/p99,
    throughput, errors, CPU/memory).
- [ ] **Validate hypotheses / identify crossover points**
  - Identify when Biscuit becomes more/less expensive than JWT under:
    - MTU constraints
    - policy complexity (block count)
    - external authz latency/failure

---

## 11) Known Risks / Things to Watch

- **Docker permissions**: `tc netem` requires `CAP_NET_ADMIN` (already
  configured in compose).
- **MTU edge cases**: very low MTU can cause unexpected behavior depending on
  Docker networking and host kernel.
- **HTTP fallback semantics**: hybrid mode relies on HTTP failures being treated
  as errors (non-200 => error) to trigger fallback.

---

## 12) Dependency Optimization Note

Optimize dependency features in `Cargo.toml` by disabling unused default
features to ensure accurate performance measurements. This should be done
**before** running benchmarks to:

- Measure realistic binary sizes for production deployments
- Avoid performance overhead from unused features
- Ensure fair JWT vs Biscuit comparison with optimal configurations
- Document any features needed for specific benchmark scenarios

---

## 13) Research Footnotes

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
