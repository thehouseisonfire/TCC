# Project Progress Tracker

**Project**: Eclipse Mosquitto Auth Biscuit Plugin (Rust)\
**Started**: 2026-01-04\
**Last Updated**: 2026-05-17\

---

## 1) Executive Summary

This repository contains a Mosquitto authentication/authorization plugin
implemented in Rust that supports:

- JWT and Biscuit token authentication
- MQTT v5 enhanced auth (server-side support via Mosquitto callbacks)
- Authorization via:
  - token-only evaluation
  - static ACL compound authorization
  - Dynamic Security snapshot/runtime policy backend
  - SQLite policy backend
  - external HTTP policy/introspection
  - hybrid HTTP-preferred with token-only fallback on HTTP failure

The Docker + benchmark stack is now set up to run the experimental scenarios
described in `ARTICLE.md`, including a controllable HTTP authz service and a
`netem` helper for MTU/latency/loss experiments.

---

## 2) Architecture & Crate Map

### 2.1 Logical Roles (`ARTICLE.md` Terminology)

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

- `authz-server`: HTTP authorization/introspection service.
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

### 3.5 HTTP Authz Benchmark Baseline

- The authz-server benchmark reset baseline is now intentionally neutral:
  `authz_profile=custom` with empty rules, which means default deny.
- HTTP and hybrid scenarios are expected to apply their intended profile or
  custom rules explicitly after `/config/reset`.
- Legacy prefix-based startup/reset behavior has been removed from the
  benchmarked authz path so latency/failure slices measure the modern rule
  engine rather than a compatibility branch.

**Key files**:

- `mqtt-auth-biscuit/docker/docker-compose.yml`
- `mqtt-auth-biscuit/docker/prometheus.yml`
- `mqtt-auth-biscuit/docker/Dockerfile.mosquitto`
- `mqtt-auth-biscuit/docker/Dockerfile.authz`
- `mqtt-auth-biscuit/crates/authz-server/src/main.rs`
- `mqtt-auth-biscuit/docker/Dockerfile.netem`
- `mqtt-auth-biscuit/docker/netem_entrypoint.sh`

---

## 4) Benchmark Design And Policy Specs

To avoid duplication, the canonical benchmark/scenario policy specification now lives in
`SCENARIO_POLICIES.md`.

- Benchmark objectives and scenario-to-policy mapping: `SCENARIO_POLICIES.md#2-scenario-to-policy-mapping`
- Enforcement semantics and policy source behavior: `SCENARIO_POLICIES.md#1-policy-sources-what-decides-access`
- Reference file index for scenario/policy implementation: `SCENARIO_POLICIES.md#4-reference-file-index`

This file (`PROGRESS.md`) keeps status, implementation progress, and execution backlog.

---

## 5) Outputs And Artifacts

### Scenario Runner Outputs

`benchmarks/run_scenarios.py` writes per-scenario JSON to:

- `mqtt-auth-biscuit/benchmarks/results/<SCENARIO_ID>.json`

Each file contains:

- **Latency percentiles** (p50/p95/p99 where applicable) from the load generator
- **Throughput** summary from the load generator
- **Error reporting** (connect/publish failures)
- **Resource snapshot** collected via Prometheus/cAdvisor (container CPU/memory)

---

## 6) Validation Status

### Build/Syntax

- Rust plugin builds in release mode (historically validated)
- Python benchmark scripts syntax-checked successfully:
  - `benchmarks/run_scenarios.py`
  - `benchmarks/mqtt_auth_client.py`

### Historical Execution Status (2026-02-23)

End-to-end execution was performed for the Issue 33 parity slice:

- HTTP policy parity matrix:
  - `HTTP-PROFILE-SIMPLE-JWT`, `HTTP-PROFILE-MED-JWT`,
    `HTTP-PROFILE-COMPLEX-JWT`
  - `HTTP-PROFILE-SIMPLE-BISCUIT`, `HTTP-PROFILE-MED-BISCUIT`,
    `HTTP-PROFILE-COMPLEX-BISCUIT`
- Complexity comparator scenarios:
  - `TOKEN-COMPLEXITY-DATALOG-LOW-BISCUIT`, `TOKEN-COMPLEXITY-DATALOG-MED-BISCUIT`, `TOKEN-COMPLEXITY-DATALOG-HIGH-BISCUIT`

Artifacts produced:

- Per-scenario results in `mqtt-auth-biscuit/benchmarks/results/*.json`
- Comparison summaries:
  - `mqtt-auth-biscuit/benchmarks/results/http_policy_comparison_profile_parity.csv`
  - `mqtt-auth-biscuit/benchmarks/results/http_policy_comparison_profile_parity.json`
  - `mqtt-auth-biscuit/benchmarks/results/policy_complexity_comparison_profile_parity.csv`
  - `mqtt-auth-biscuit/benchmarks/results/policy_complexity_comparison_profile_parity.json`

Runner reliability fixes applied during this execution pass:

- `benchmarks/loadgen.py`: fixed percentile helper to handle NumPy arrays
  safely (avoids ambiguous truth-value error).
- `benchmarks/run_scenarios.py`:
  - fixed summary path handoff to aggregator (absolute paths now used),
    eliminating `benchmarks/results/benchmarks/results/...` failures.
  - added backward-compatible token alias fallback
    (`jwt_admin -> jwt`, `biscuit_admin -> biscuit`) so older fixtures run
    without manual compatibility files.

Authz benchmark hygiene updates applied after this pass:

- `authz-server` no longer exposes the legacy prefix-allow compatibility mode in
  benchmark configuration; reset/startup baseline is `custom` + empty rules.
- HTTP latency/failure and hybrid fallback scenarios now apply explicit
  rule-engine profiles (`simple`) rather than inheriting implicit startup
  behavior.

---

## 7) Policy Parity Gaps (Tracking)

Source of truth for the detailed policy mapping is `SCENARIO_POLICIES.md`.
The actionable parity gaps are tracked here as backlog items:

1. Token-only wildcard/filter parity is implemented; preserve this in new scenarios.
2. Static ACL scenarios now use roles-only tokens to isolate ACL cost
   (implemented in Issue 28; preserve this invariant in new scenarios).
3. SQLite policy now uses RBAC tables (`users/roles/user_roles/role_acls`) with
   deterministic churn helpers; preserve this parity-grade model in new scenarios
   (implemented in Issue 22).
4. `TOKEN-COMPLEXITY-*` naming must stay explicit about which complexity axis is being stressed
   (`chain_length` vs Datalog complexity; tracked by Issue 33; Issue 21 now
   adds separate authorizer-template scenarios).
5. Dynamic-security parity should continue to prefer policy-source isolation
   (roles-only token variants; tracked by Issue 28/31/32).

Cross-link: `SCENARIO_POLICIES.md#3-fairness-and-alignment-tracking`.

---

## 8) Open Issues

### Priority List
1. Issue 42: Bump Mosquitto image to 2.1.3-alpine when published
---

#### A) Dependency Tracking

- [ ] **Issue 42: Bump Mosquitto image to 2.1.3-alpine when published**
  - Blocked as of 2026-05-17: `eclipse-mosquitto:2.1.3-alpine` is not yet on Docker Hub.
  - Reason: we need a feature from Mosquitto 2.1.3.

---

## 9) Completed Issues (Backlog)

- [x] **Issue 41: Containerized benchmark topology (client-per-container +
     service separation)** — **COMPLETED 2026-05-15**
  - **Summary**: Added a containerized Rust `mqtt-loadgen` image/service and
    made `run_scenarios.py` default to `container-single`, with `host` retained
    for compatibility and `container-per-client` available for high-fidelity
    topology slices.
  - **Coverage**: Added deterministic client container naming/identity offsets
    (`client_1..client_N`) for standard publish/control runs, Docker resource
    controls for loadgen containers, internal Docker service routing, and result
    metadata documenting topology mode and resource settings.
  - **Research Alignment**: Keeps strict JWT/Biscuit identity-bound parity
    provisioning through the Token Issuer while improving isolation between
    benchmark clients, broker, PDP, issuer, and observability services.

- [x] **Issue 23: Proactive client reauthentication before expiry** — **COMPLETED 2026-05-13**
  - **Summary**: Added timer-driven proactive refresh to the Rust MQTT v5 load
    generator. Clients now fetch Token Issuer credentials with expiry metadata,
    trigger tracked MQTT v5 `AUTH` reauthentication before `exp` minus the
    configured margin (default 60 seconds), and continue the same MQTT session.
  - **Coverage**: Added JWT and Biscuit lifecycle scenarios
    (`TOKEN-LIFECYCLE-PROACTIVE-REAUTH-*`) plus runtime continuity assertions
    (`session_continuity_ok`, proactive attempt/success/failure counts, and
    expiry-denial count).
  - **Research Alignment**: Keeps JWT as text and Biscuit as raw binary MQTT
    authentication data, preserving token transport parity while measuring
    lifecycle renewal cost without expiry-driven reconnect bias.

- [x] **Issue 1: Add Dynamic Security module comparison**
  - **Completed**: Full Dynamic Security module implementation with JSON-based policy loading, role-based access control, and comprehensive ACL support. Added anonymous access, benchmark scenarios, and Docker configurations. Provides production-grade comparison against token-based approaches.

- [x] **Issue 2: Add static ACLs as PDP source of truth (backend)**
  - **Completed**: Implemented hybrid static ACL compounding with Mosquitto's built‑in ACLs. Added role-to-synthetic-username mapping for JWT/Biscuit tokens, configured plugin to allow when the token authorizes and defer to native ACL checks when the token denies (`StaticAcl` OR semantics), and created benchmark scenarios. **Pivot**: Instead of plugin-loaded ACL files, uses Mosquitto's native `acl_file` with compound authorization (token allow OR ACL allow). Removed plugin-side static ACL backend. Updated Docker configs and sample ACL files for role-based usernames and fallback patterns.

- [x] **Issue 3: Implement proper JWT access logic (replace demo token-only authz)**
  - **Completed**: Replaced demo JWT token-only checks with structured grants
    schema (`grants` + `denies`) and access-aware enforcement (`publish`,
    `subscribe`, `read` with `ACL_READ` fallback to `subscribe`). Token issuer
    and deterministic token generator updated to mint the new schema.

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
  - **Summary**: Implemented `iperf3` integration to measure nominal channel capacity as specified in `ARTICLE.md` methodology. Added `iperf3` service to docker-compose.yml, created `benchmarks/iperf3_baseline.py` module with measurement, parsing, and validity checking functions. Integrated automated baseline measurement into `run_scenarios.py` with CLI options (`--iperf3/--no-iperf3`, `--iperf3-host`, `--iperf3-port`, `--iperf3-duration`, `--iperf3-streams`, `--iperf3-min-mbps`). Network capacity data included in scenario results JSON under `network_baseline` field with throughput, RTT, retransmits, and validity assessment. Warns when network constraints may affect test validity.

- [x] **Issue 15: Add packet-level analysis with tcpdump for fragmentation studies**
  - **Completed**: Integrated tcpdump capture and automated packet analysis for MTU stress test scenarios.
  - **Summary**: Added tcpdump service to docker-compose.yml with NET_ADMIN/NET_RAW capabilities and network_mode: service:mosquitto for packet capture on the broker interface. Created `benchmarks/packet_analysis.py` with complete pcap parsing (tcpdump JSON output), fragmentation detection, retransmission counting, inter-packet timing analysis (p50/p95/p99), and token size correlation metrics. Auto-activation for MTU scenarios (200B, 500B, 1500B, 9000B) with pcap files saved to `benchmarks/results/pcap/<scenario_id>.pcap`. CLI options: `--tcpdump`, `--tcpdump-filter`, `--tcpdump-duration`, `--tcpdump-output-dir`, `--tcpdump-analyze`. Analysis results included in scenario JSON under `packet_analysis_result` with metrics: fragment_count, retransmission_count, inter_packet_deltas_ms, tcp_streams, fragmentation_stats, token_size_correlation. Follows same integration patterns as iperf3 baseline and perf profiling.

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
      - Default profiling for key scenarios (BASELINE-NO-AUTH, TOKEN-BASELINE-JWT, TOKEN-BASELINE-BISCUIT, TOKEN-COMPLEXITY-*)
    - Results included in scenario JSON output with structured perf data
    - `benchmarks/PERF_PROFILING.md`: Comprehensive documentation with methodology, interpretation guide, and troubleshooting
  - **Research Alignment**: Enables H₂/H₃ validation by quantifying computational costs of JWT vs Biscuit verification at instruction level, complementing container-level metrics with PMU hardware counters.

- [x] **Issue 17: Implement comprehensive QoS configuration and mixing features**
  - **Summary**: Added full QoS 0/1/2 support with per-QoS latency tracking. Implemented QoS distribution parsing (`0:0.6,1:0.3,2:0.1` format) in `loadgen.py` with `--qos-distribution` CLI option. `WorkerResult` now tracks `publish_ms_by_qos` per level; `aggregate_results.py` reports per-QoS statistics in JSON and CSV. Added scenarios: `QOS0-BASELINE-NO-AUTH`, `TOKEN-QOS2-JWT`, `TOKEN-QOS2-BISCUIT`, `TOKEN-QOS-MIXED-JWT`, `TOKEN-QOS-MIXED-BISCUIT`. Enables H₂/H₃ validation of latency differences across QoS levels.

- [x] **Issue 18: Avoid Base64URL encoding for Biscuit tokens where possible (use native Protobuf format)** — **COMPLETED 2026-02-06**
  - **Summary**: Native Protobuf transport for Biscuit tokens is now used across MQTT transport. Initial authentication uses raw Biscuit bytes in `CONNECT.password` (via Mosquitto's password-length fix), and MQTT v5 reauthentication uses raw Authentication Data.
  - **Deliverables**:
    - Updated the plugin FFI for `MOSQ_EVT_BASIC_AUTH` to consume `password_len`
    - Migrated Biscuit authentication in `auth.rs` to raw serialized bytes for both basic auth and enhanced auth
    - Removed the old `biscuit_transport` plugin option
    - Added `/biscuit/binary` endpoint to token-issuer for raw binary token generation
    - Updated MQTT benchmark/integration clients to pass raw Biscuit bytes at the MQTT boundary while still allowing Base64URL in JSON/file wrappers
    - Updated MQTT v5 reauth scenarios to use binary Authentication Data for Biscuit
  - **Technical Details**: Biscuit's native `Biscuit::to_vec()` produces Protobuf-encoded bytes; Base64URL inflates size by ~33%; JWT tokens remain text-based, while Biscuit now stays binary on MQTT transport and is only Base64URL-wrapped for text-only tooling surfaces
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
  - **Code Pointers**: `mqtt-auth-biscuit/crates/mosquitto-plugin/src/lib.rs`

- [x] **Issue 20.1: Verify ACL_CHECK subtype handling across policy modes**
  - **Summary**: Added `MOSQ_ACL_CONTROL` constant (0x08) for control-plane access; fixed `control_callback` hardcoded `access: 2` → `MOSQ_ACL_CONTROL`; updated `access_to_operation()` to map 0x08 → "control"; added comprehensive unit tests for all ACL subtypes (READ/WRITE/SUBSCRIBE/CONTROL) with priority ordering (WRITE > SUBSCRIBE > CONTROL > READ), bitmask combinations, and edge cases. All 7 policy modes verified to correctly handle distinct ACL subtypes.

- [x] **Issue 21: Strengthen Biscuit authorizer template complexity** — **COMPLETED 2026-03-03**
  - **Summary**: Added configurable Biscuit authorizer profiles and explicit
    benchmark scenarios that isolate plugin-side authorizer-template complexity
    while keeping token size constant.
  - **Implemented**:
    - Added plugin option `plugin_opt_biscuit_authorizer_profile` with values
      `simple` (default), `rbac`, `contextual`.
    - Extended Biscuit authorization engine in
      `crates/mosquitto-plugin/src/biscuit_handler.rs`:
      - `simple`: direct `right/deny` evaluation.
      - `rbac`: role-derived `role_right/role_deny` plus direct `right/deny`.
      - `contextual`: strict role + active-window
        (`role_active_from/role_active_until`) evaluation for allows; direct
        `right` is ignored, while direct `deny` remains enforced.
    - Wired profile selection through plugin config and ACL/control authz
      dispatch.
    - Added deterministic token fixture `biscuit_authorizer_template` in
      `gen-tokens` for constant-token-size authorizer-template runs.
    - Added dedicated scenarios in `benchmarks/run_scenarios.py`:
      - `TOKEN-AUTHORIZER-PROFILE-SIMPLE-BISCUIT`
      - `TOKEN-AUTHORIZER-PROFILE-RBAC-BISCUIT`
      - `TOKEN-AUTHORIZER-PROFILE-CONTEXTUAL-BISCUIT`
    - Added dedicated Mosquitto configs (plain + TLS):
      - `docker/mosquitto_biscuit_authz_{simple,rbac,contextual}.conf`
      - `docker/tls/mosquitto_biscuit_authz_{simple,rbac,contextual}.conf`
    - Added benchmark scenario-shape coverage test:
      `benchmarks/test_biscuit_authorizer_template_coverage.py`.
  - **Research Alignment**: closes the gap where plugin-side Biscuit authorizer
    logic was too thin to represent intended Datalog policy complexity costs in
    Issue 21 scenarios.

- [x] **Issue 22: Strengthen `seed_demo_rules` (RBAC), make it optional, and add
    runtime policy churn scenarios** — **COMPLETED 2026-03-02**
  - Summary:
    - Added plugin option `sqlite_seed_demo_rules=true|false` (default `false`);
      SQLite seeding is now explicit/opt-in.
    - Upgraded SQLite policy backend to RBAC schema
      (`users/roles/user_roles/role_acls/role_deny_acls`) with role priorities
      and deny-over-allow precedence; legacy `acl` fallback remains only when no
      RBAC identity exists for the client.
    - Strengthened demo seeding with realistic role/topic/action grants
      (publish/subscribe/read/control).
    - Added deterministic periodic SQLite churn scenarios
      (`SQLITE-RBAC-CHURN-JWT`, `SQLITE-RBAC-CHURN-BISCUIT`) using
      `sqlite_toggle_read`.
    - Added deep representative SQLite scenarios for conflict and control
      families (`SQLITE-RBAC-DEEP-CONFLICT-*`, `SQLITE-RBAC-DEEP-CONTROL-*`)
      using profile-aware seeding and `sqlite_toggle_private_deny`.
    - Extended scenario/loadgen metadata and docs with churn cadence and
      cache-validity interpretation for strict `ACL_READ` runs.

- [x] **Issue 24: Decide whether to benchmark multi-step `MOSQ_EVT_EXT_AUTH_CONTINUE` state machine**
  - **Decision**: Out of scope for current research.
  - **Justification**: Current hypotheses/metrics compare JWT vs Biscuit
    viability/performance and lifecycle token refresh cost; they do not require
    multi-step enhanced-auth choreography.
  - **Implementation note**: Keep intentional single-step semantics
    (`EXT_AUTH_CONTINUE` delegates to `EXT_AUTH_START`) and preserve regression
    tests that lock this behavior.

- [x] **Issue 25: Optional full authz on ACL_READ behind a flag (default expiry-only)** — **COMPLETED 2026-02-25**
  - **Summary**: Added `acl_read_full_authz` plugin config option (default `false`) to control `MOSQ_ACL_READ` fan-out behavior. When disabled, ACL read checks use expiry-only validation for cached sessions; when enabled, the plugin executes full authorization (token/SQLite/HTTP/hybrid/dynamic-security paths) for each read. Added unit tests for config parsing/defaults, expiry helper behavior, and ACL callback fast-path semantics (`ACL_READ` allow on unexpired cached token, strict behavior when enabled, no bypass for `ACL_WRITE`, and expired-token denial). Added operator documentation to `benchmarks/RUNNING_BENCHMARKS.md`.

- [x] **Issue 28: Verify static-policy benchmark coverage (ACL_SUBSCRIBE/WRITE)** — **COMPLETED 2026-02-25**
  - **Summary**: Corrected static-policy scenario design so ACL-file enforcement
    is measured without token-rule bias. Added role-only static fixtures for
    JWT/Biscuit and rewired static scenarios to use writer/reader role tokens
    by path (`ACL_WRITE` publish, `ACL_SUBSCRIBE` fanout subscribe). Explicitly
    documented static-mode `ACL_READ` handling via
    `plugin_opt_acl_read_full_authz false` in static Mosquitto configs.
  - **Validation Additions**: Added benchmark scenario coverage tests and a
    plugin unit test proving the `ACL_READ` fast path does not bypass full
    authorization for `ACL_SUBSCRIBE`.

- [x] **Issue 27: Cache Biscuit expiry via min `expires_at` fact (remove brittle parsing)**
  - Summary: Replaced brittle error-message parsing with structured Datalog query to extract the minimum `expires_at` from Biscuit tokens. Updated `TokenType::Biscuit` to cache the expiry timestamp per session, clamped cache TTL to token expiry with a 5-minute fallback, and rejected already-expired tokens at auth time. Token issuer and benchmark generators now embed `expires_at` facts in authority and attenuation blocks to support stable expiry extraction.

- [x] **Issue 29: Anonymous flow scenario via anonymousGroup policy**
  - **Completed**: Enabled anonymous MQTT clients using Mosquitto's `allow_anonymous true` with Dynamic Security `anonymousGroup` policy. Added `allow_anonymous_no_token=true` config option and `DYNAMIC-SECURITY-ANONYMOUS-BASELINE` scenario with proper plugin defer logic for no-token clients.

- [x] **Issue 30: Verify dynamic-policy coverage with ACL_READ fan-out checks** — **COMPLETED 2026-02-26**
  - **Summary**: Added deterministic mid-run fan-out churn scenarios that
    enforce policy changes for already-subscribed clients through strict
    `ACL_READ` authorization (`plugin_opt_acl_read_full_authz true`) for both
    Dynamic Security and SQLite.
  - **Deliverables**:
    - New strict configs:
      - `docker/mosquitto_dynsec_acl_read.conf` (+ TLS variant)
      - `docker/mosquitto_sqlite_acl_read.conf` (+ TLS variant)
    - New scenario matrix with subscriber scaling (10/50/100), JWT+Biscuit:
      - `DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-{JWT|BISCUIT}-{10|50|100}`
      - `SQLITE-ACL-READ-FANOUT-CHURN-{JWT|BISCUIT}-{10|50|100}`
    - Deterministic fan-out orchestration in `loadgen.py`:
      subscriber-ready barrier, mid-run churn trigger, and pre/post-churn
      receive counters in `fanout_churn` result metadata.
    - Dynamic-security churn snapshot:
      `docker/dynamic-security-fanout-read-deny-unpinned.json` (subscribe retained,
      fan-out read removed).
    - SQLite churn helpers in `benchmarks/policy_churn.py`:
      deterministic fan-out seed + `ACL_READ` revoke during active runs.
    - Coverage tests:
      - `benchmarks/test_acl_read_fanout_churn_coverage.py`
      - `benchmarks/test_policy_churn.py`

- [x] **Issue 31: Verify control-triggered dynamic enforcement (kick/re-auth)** — **COMPLETED 2026-03-01**
  - **Summary**: Implemented plugin-side handling of Dynamic Security control
    `disableClient` commands in `MOSQ_EVT_CONTROL`, with immediate runtime
    enforcement via cache eviction + forced client kick (`with_will=false`).
  - **Deliverables**:
    - Control payload processing in `control_callback` for
      `$CONTROL/dynamic-security/v1` after successful control authorization.
    - Dynamic-security runtime mutation path in
      `dynamic_security_policy/` (`mod.rs`, `mutation.rs`, `persist.rs`) for
      `disableClient`, with best-effort file persistence to keep behavior
      stable across reload windows.
    - Session cache explicit removal API (`SessionCache::remove`) used by
      control-triggered enforcement before kicking affected clients.
    - Session-index stale pruning against live cache state to prevent unbounded
      username/client-id accumulation under normal churn and avoid stale target
      kick attempts during `disableClient` enforcement.
    - New broker integration assertions:
      control-triggered kick, reconnect with fresh token, and denied
      post-change subscribe lifecycle for both JWT and Biscuit.
    - Updated operator documentation in
      `benchmarks/RUNNING_BENCHMARKS.md` with Issue 31 focused invocation.

- [x] **Issue 32: Verify control-triggered dynamic enforcement (ACL_READ + notify)**
  - Summary: Implemented and verified notify-oriented control enforcement
    scenarios for Dynamic Security, including notification fan-out coverage and
    post-change `ACL_READ` denial behavior.
  - Completed evidence:
    - `CONTROL-OVERHEAD-ACL-READ-NOTIFY-*` covers the notification fan-out
      control path.
    - `DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-*` publishes a Dynamic
      Security control command during active fan-out and verifies post-control
      read denial.
    - `DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-*` verifies immediate
      runtime enforcement for disabled subscriber identities.
    - Broker integration coverage in `tests/integration/test_runtime_enforcement.py`
      validates control-triggered notification/denial behavior against a real
      Mosquitto process.

- [x] **Issue 33: Enhance HTTP policy expressiveness for parity with token-based
    authorization**
  - Summary: Improved HTTP policy backend to support complex authorization rules
    comparable to JWT/Biscuit token policies, enabling fair policy complexity
    comparisons.
  - Implemented:
    - Extended HTTP policy backend in `crates/authz-server/src/main.rs` with:
      - Operation-specific matching (`publish|subscribe|read|control`)
      - Client/role-based matching (client ID map + JWT `roles` extraction)
      - Deny-over-allow precedence
      - MQTT wildcard topic filter matching (`+`, `#`) with invalid-filter guard
      - Built-in profiles (`simple`, `med`, `complex`) and custom rules
    - Added HTTP policy complexity scenarios in
      `benchmarks/run_scenarios.py`:
      - `HTTP-PROFILE-SIMPLE-JWT`, `HTTP-PROFILE-MED-JWT`,
        `HTTP-PROFILE-COMPLEX-JWT`
      - `HTTP-PROFILE-SIMPLE-BISCUIT`, `HTTP-PROFILE-MED-BISCUIT`,
        `HTTP-PROFILE-COMPLEX-BISCUIT`
    - Updated `SCENARIO_POLICIES.md` to document HTTP policy capabilities and
      scenario mapping.

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

- [x] **Issue 36: Add interleaved control message support for data plane + control plane testing** — **COMPLETED 2026-02-07**
  - **Summary**: Implemented interleaved control message publishing to measure control plane latency under active data plane load.
  - **Deliverables**:
    - Added `--control-after-messages` CLI option to `loadgen.py` with full implementation in `_run_worker()`
    - Added `control_after_messages` field to `WorkerConfig` and `control_injection_delay_ms` to `WorkerResult`
    - Implemented message counter tracking that injects control messages after every N data messages
    - Added `CONTROL-INTERLEAVED-DATA-JWT` and `CONTROL-INTERLEAVED-DATA-BISCUIT` scenarios to `run_scenarios.py`
    - Captured three key metrics: data message latency (`publish`), control message latency (`control`), and control injection delay (`control_injection_delay`)
    - Added comprehensive documentation in RUNNING_BENCHMARKS.md with usage examples and research interpretation notes
  - **Research Alignment**: Enables measurement of broker behavior under realistic mixed data+control plane workloads, supporting H2/H3 validation by quantifying control plane overhead during active data traffic.

- [x] **Issue 37: Add `ACL_READ` fan-out authorization scenarios across policy profiles** — **COMPLETED 2026-03-03**
  - **Summary**: Added strict `ACL_READ` fan-out scenario coverage for token-only,
    HTTP policy profiles (`simple|med|complex`), and hybrid policy profiles
    (`simple|med|complex`) with subscriber scaling slices (10/50/100) and
    broker runtime integration assertions.
  - **Deliverables**:
    - New strict scenario families in `benchmarks/run_scenarios.py`:
      - `TOKEN-ACL-READ-FANOUT-STRICT-ALLOW-{JWT|BISCUIT}-{10,50,100}`
      - `TOKEN-ACL-READ-FANOUT-STRICT-DENY-{JWT|BISCUIT}-10`
      - `HTTP-ACL-READ-FANOUT-STRICT-{SIMPLE|MED|COMPLEX}-{ALLOW|DENY}-{JWT|BISCUIT}-10`
      - `HTTP-ACL-READ-FANOUT-STRICT-MED-ALLOW-{JWT|BISCUIT}-{50,100}`
      - `HYBRID-ACL-READ-FANOUT-STRICT-{SIMPLE|MED|COMPLEX}-{ALLOW|DENY}-{JWT|BISCUIT}-10`
      - `HYBRID-ACL-READ-FANOUT-STRICT-MED-ALLOW-{JWT|BISCUIT}-{50,100}`
    - New strict Mosquitto configs:
      - `docker/mosquitto_http_acl_read.conf` (+ TLS variant)
      - `docker/mosquitto_hybrid_acl_read.conf` (+ TLS variant)
    - Profile-aware fan-out allow/deny HTTP authz payload helper and
      canonical scenario IDs with no compatibility aliases.
    - Result metadata now records:
      `policy_source`, `authz_profile`, `acl_read_enforcement`, and
      `subscriber_count` per scenario run.
    - Broker integration coverage in
      `tests/integration/test_acl_read_profiles_matrix.py`:
      strict token fan-out allow/deny semantics, full HTTP/hybrid tier matrix
      (`simple|med|complex`) for JWT and Biscuit, runtime fan-out scaling
      assertions (`ci_heavy` on 50/100) with JWT at 10/50/100 and Biscuit at
      10/50 (100 marked `xfail` due CI CONNACK saturation), and strict SQLite
      read-revoke enforcement.
    - Scenario-shape coverage in
      `benchmarks/test_acl_read_profile_matrix_coverage.py`.

- [x] **Issue 38: Expiry enforcement in ACL_CHECK with disconnect (no reason codes)** — **COMPLETED 2026-02-27**
  - **Summary**: `MOSQ_EVT_ACL_CHECK` now enforces immediate disconnect on
    `AuthzOutcome::Expired` by calling `mosquitto_kick_client_by_clientid`
    (`with_will=false`) and returning `MOSQ_ERR_ACL_DENIED`.
  - **Rationale/Constraints Preserved**:
    - No MQTT reason codes/strings are used in ACL callbacks.
    - `ACL_CHECK` remains expiry/authz-only; cryptographic token verification
      stays in basic/enhanced auth entrypoints.
  - **Validation**: Added unit coverage for JWT and Biscuit expired-token
    branches, including both ACL read fast path and full-authz path, plus
    assertions that non-expired deny paths do not trigger disconnect.

- [x] **Issue 39: Add broker-level integration assertions for runtime enforcement semantics** — **COMPLETED 2026-02-28**
  - **Summary**: Added deterministic broker-level `pytest` integration coverage
    against real Mosquitto + plugin runtime semantics.
  - **Deliverables**:
    - New suite + fixtures:
      - `tests/integration/test_runtime_enforcement.py`
      - `tests/integration/conftest.py`
      - `broker_integration` marker in `pytest.ini`
    - Runtime assertions across JWT/Biscuit and strict/non-strict read modes:
      expiry disconnect in `ACL_CHECK`, negative controls (no false disconnects),
      reconnect lifecycle, and `with_will=false` kick/LWT suppression behavior.
    - Control-plane and churn validation:
      `$CONTROL` workflow + notification behavior, and fan-out churn enforcement
      at subscriber scales 10/50/100.
    - Protocol/transport coverage:
      basic auth + MQTT v5 enhanced auth over TCP and TLS.
    - Supporting plugin fixes and tests:
      dynamic-security control access mapping, cache removal support, control
      request context in authorization params, and expiry disconnect grace
      handling for deterministic runtime enforcement.
    - Operator documentation:
      run commands, timing bounds, and flake-control strategy in
      `benchmarks/RUNNING_BENCHMARKS.md`.

- [x] **Issue 40: Execute control-plane and runtime flow tests in CI** — **COMPLETED 2026-03-02**
  - **Summary**: CI now executes benchmark flow unit tests and broker runtime
    enforcement suites with a bounded PR path and a full nightly/manual path.
  - **Deliverables**:
    - CI workflow updates in `.github/workflows/ci-benchmarks.yml`:
      - `benchmark-flow-tests` runs benchmark flow/runtime-shape tests
        (`test_loadgen_*`, scenario coverage tests, and policy churn checks)
      - `broker-runtime-fast` runs
        `pytest -m "broker_integration and not ci_heavy"` on PR/push
      - `broker-runtime-full` runs
        `pytest -m broker_integration` on nightly schedule and manual dispatch
    - Marker split for runtime suite:
      - New `ci_heavy` marker in `mqtt-auth-biscuit/pytest.ini`
      - Heavy slices marked in
        `tests/integration/test_runtime_enforcement.py` (TLS-heavy and
        high fan-out variants)
    - Failure artifact capture:
      - `tests/integration/conftest.py` now supports
        `RUNTIME_ENFORCEMENT_ARTIFACT_DIR=/path` to persist
        Mosquitto/Authz/Token-Issuer
        logs and compose context for failed CI runs
    - Documentation update:
      - `benchmarks/RUNNING_BENCHMARKS.md` now documents fast/full marker
        commands, CI mapping, artifact capture, and expected runtime bounds.

- [x] **Issue 43: Align identity-binding documentation with runnable scenario semantics** — **COMPLETED 2026-04-04**
  - **Summary**: Updated the research/operator docs to match the implemented
    identity-binding behavior exactly instead of the earlier global-JWT-binding
    assumption.
  - **Deliverables**:
    - Documented the three harness semantic classes:
      `capability` (`jwt=off`, `biscuit=off`),
      `mixed` (`jwt=strict`, `biscuit=off`), and
      `parity_identity_bound` (`jwt=strict`, `biscuit=strict`).
    - Recorded the current inventory split:
      control-plane reauth/churn and `SQLITE-RBAC-DEEP-CONTROL-*` are `mixed`;
      single-client HTTP `-PARITY-` variants and multi-client HTTP/Hybrid
      strict fan-out `-PARITY-` variants are the runnable
      `parity_identity_bound` scenarios;
      the remaining families stay `capability`.
    - Clarified that Biscuit attenuation/delegation scenarios are intentionally
      not parity scenarios.
    - Clarified that runnable multi-client parity now depends on per-client
      strict provisioning at startup, while shared tokens remain valid for
      capability scenarios that intentionally model bearer reuse.
    - Documented that strict Biscuit binding uses a dedicated identity fact
      predicate, defaults to `client_id`, and must stay aligned between
      issued tokens and generated Mosquitto plugin config when a scenario
      overrides it via `biscuit_client_id_fact`.

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

## 11) Known Risks / Things To Watch

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

### Dynamic Security Control Durability Semantics

- **Decision**: The Dynamic Security control path now favors **runtime
  availability** over strict durability when `dynamic-security.json` is not
  writable.
- **Behavior**:
  - Valid control commands still apply to in-memory policy state even if dynsec
    JSON persistence fails.
  - Persistence failure is surfaced as a **warning** on the successful control
    result and logged by the control callback, rather than treated as a hard
    post-commit failure.
  - Failed-persist structural mutations (`createRole`, `deleteRole`,
    `createGroup`, `deleteGroup`, `addGroupClient`, `removeGroupClient`) are
    kept in a process-local pending queue and re-applied after reloads so live
    enforcement remains stable during the current broker process lifetime.
  - Pending persistence is retried opportunistically on later control commands.
  - This state is **not durable across broker restart** until a later
    successful file write commits the queued mutations.
- **Research relevance**: This preserves control-plane functionality and
  resilience under degraded local-dependency conditions, which better matches
  the thesis focus on availability and contingency behavior. Baseline benchmark
  runs that use writable temp dynsec files will not normally exercise this path,
  so it should be treated as a deliberate failure-mode scenario rather than part
  of the main throughput/latency matrix.

### Biscuit Parsing Cache Vs Per-Message Verification

- **Decision**: Parse/verify Biscuit tokens once during authentication, cache the parsed token in session state, and reuse it for per-message authorization checks.
- **Rationale**: JWT verification is already performed once at auth time; per-message Biscuit re-verification would bias latency/CPU comparisons. Caching preserves fairness while still running Datalog authorization for each ACL check.
- **Validity guardrail**: Only cryptographic verification is cached; policy evaluation still occurs on every request (ACL defers to authorizer), preserving per-message cost measurement and policy semantics.

### Why `netem` Runs In A Separate Container With `network_mode: service:mosquitto`

- **Least privilege**: Traffic shaping needs `CAP_NET_ADMIN`. By running `netem`
  in a separate container that joins the Mosquitto network namespace, we avoid
  granting the broker container elevated capabilities.
- **Clean separation**: The broker image stays minimal (no `iproute2` or shaping
  scripts). Impairments are toggled via environment variables without rebuilding
  the broker.
- **Precise targeting**: `network_mode: service:mosquitto` ensures `tc qdisc`
  commands affect the broker's interfaces directly, not a dummy NIC.

### Why `cadvisor` Is Separate From Prometheus

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

**Implementation Decision**: Paho Python did not provide a straightforward
public API for programmatically sending `AUTH` packets after connection
establishment. The library supports enhanced authentication during the initial
CONNECT/CONNACK handshake but lacks methods like `send_auth()` or
`reauthenticate()` for triggering mid-session re-authentication.

**Current implementation**: `benchmarks/mqtt_auth_client.py` is a compatibility
wrapper that invokes the Rust `mqtt-auth-client` binary from the benchmark
crate. The Rust client:

- Sends `CONNECT` with Authentication Method/Data
- After connection establishment, sends an `AUTH` packet with updated token data
- Measures connect latency and reauth latency separately

**Impact on Research Validity**:

- **Broker-side measurements remain accurate**: The plugin's token verification
  logic is independent of client transport implementation. Both JWT and Biscuit
  tokens are tested under identical client conditions, preserving comparative
  validity
- **Improved isolation**: The dedicated Rust client avoids Paho's missing
  mid-session `AUTH` API and keeps the client transport implementation
  consistent with the Rust benchmark load-generation stack.
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

### Cached-Read Notify-Only Enforcement Limitation

**Context**: The plugin supports a notify-only control-enforcement path for
read-access revocations, intended for comparison against kick/re-auth behavior.

**Operational Limitation**:

- When `plugin_opt_acl_read_full_authz false` is used, `MOSQ_ACL_READ` for
  cached sessions performs expiry-only validation rather than full dynamic
  policy re-evaluation.
- In that configuration, notify-only revocation commands do **not** immediately
  revoke already-subscribed cached readers at the broker.
- Effective enforcement for those sessions becomes:
  - client-assisted, if the client reacts to the control-notify topic and
    refreshes its subscriptions/session state
  - eventual, on reconnect/resubscribe
  - immediate only when using kick-based enforcement or
    `plugin_opt_acl_read_full_authz true`

**Research Interpretation**:

- Results collected under notify-only enforcement with
  `acl_read_full_authz = false` must be interpreted as measuring a
  lower-overhead, lower-disruption, but not fully immediate revocation mode.
- This is a deliberate tradeoff of the cached-read fast path, not evidence that
  the control command failed to update in-memory policy state.
