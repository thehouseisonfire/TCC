# Running MQTT Auth Benchmarks

This guide explains how to run the benchmarks for the JWT and Biscuit
authentication plugin.

**Important Note**: This implementation supports **MQTT v5 only**.
MQTT v3.1 is not implemented and is out of scope for these benchmarks.

Policy semantics, parity constraints, and scenario meaning are documented in:
- `../../SCENARIO_POLICIES.md`
- `../../PROGRESS.md` (gap tracking and implementation status)

## Prerequisites

- **Rust**: For building the plugin and token generator.
- **Docker & Docker Compose**: For running the test environment.
- **Python 3**: For running the benchmark scripts.
  - Install dependencies: `uv pip install -r benchmarks/requirements.txt`

## One-Command Run (Recommended)

From the repository root, you can run the full workflow (build, token generation,
scenario run, cleanup) with:

```bash
python3 run_benchmarks.py
```

To run a subset of scenarios or enable TLS, pass flags through:

```bash
python3 run_benchmarks.py --scenarios TOKEN-BASELINE-JWT,TOKEN-BASELINE-BISCUIT
python3 run_benchmarks.py --tls
```

## Step 1: Build the Plugin

The Mosquitto plugin must be built in release mode:

```bash
cargo build --release -p mosquitto-auth-biscuit
```

This generates `target/release/libmosquitto_auth_biscuit.so`.

> [!IMPORTANT]
> Current benchmark runs require a Mosquitto build that includes
> `MOSQ_EVT_BASIC_AUTH.password_len` for binary `CONNECT` passwords. Older
> brokers are unsupported with the current plugin and may fail later as
> misleading password-authentication errors instead of failing cleanly at
> startup. Use the custom source-build path documented in
> [`../../BUILD-MOSQUITTO.md`](../../BUILD-MOSQUITTO.md) when the official
> image does not yet contain the required commit.

## Step 2: Generate Tokens

The benchmarking suite uses predefined tokens. Generate them with:

```bash
cargo run -p gen-tokens
```

This will create/update `benchmarks/tokens.json` and write `docker/biscuit_public.key` for the Mosquitto plugin.

The Docker Mosquitto configuration is pre-wired to the deterministic keys used
by `gen-tokens` (see `docker/mosquitto.conf`).

### Token Policy Note

Token claim/fact schema and deny-over-allow semantics are defined in
`../../SCENARIO_POLICIES.md` (`## 1` and `## 2.1`).

### Client-Side (Online) Attenuation

To exercise **online attenuation** (client-side block append), use the new
`biscuit-attenuate` helper and the `TOKEN-ATTENUATION-CLIENT-BISCUIT` scenario.

**Requirement:** build the helper before running benchmarks:
`cargo build -p gen-tokens --bin biscuit-attenuate`.

`biscuit-attenuate` takes a base64 Biscuit token and appends an attenuation
block with checks or deny facts. It mirrors how a constrained MQTT client would
restrict a token before connecting.

Example (deny publish + restrict to a single topic + add TTL):

```bash
cargo run -p gen-tokens --bin biscuit-attenuate -- \
  --token "<B64_TOKEN>" \
  --public-key-file docker/biscuit_public.key \
  --deny publish:sensors/client_1/temp \
  --restrict-topic sensors/client_1/temp \
  --restrict-op publish \
  --ttl-seconds 300
```

Scenario IDs and parity classification for attenuation/delegation and
policy-complexity runs are documented in `../../SCENARIO_POLICIES.md` (`## 2.2`
and `## 2.7`).

### Client-to-Client Delegation

The delegation benchmark now exercises **real client-side delegation** instead
of pre-generated delegated tokens.

- `TOKEN-DELEGATION-TEMP-ONLY-BISCUIT` uses a base Biscuit token and delegates a restricted
  token per client at runtime (topic + operation + TTL). Delegation latency and
  resulting token length are recorded as `delegation` metrics.
- `TOKEN-DELEGATION-HANDOFF-BISCUIT` adds a broker-mediated handoff: a master client delegates
  tokens, then publishes them to `delegation/handoff` over MQTT. Workers
  subscribe with a handoff token (`biscuit_delegation_handoff` from
  `tokens.json`) to receive their delegated token before connecting with their
  actual publish credentials. The default handoff uses QoS 1 with retained
  messages.
- `TOKEN-DELEGATION-SIMULATED-BISCUIT` keeps the previous pre-generated delegated token to
  compare runtime delegation against the simulated baseline.

Handoff-specific knobs (loadgen):

- `--biscuit-delegate-handoff-qos` (default: 1)
- `--biscuit-delegate-handoff-no-retain` (disable retained handoff messages)

Default grants are added by the token issuer for `publish`/`subscribe` on
`sensors/{subject}/temp` unless `no_default_grants` (request) or
`JWT_NO_DEFAULT_GRANTS=1` (env) is set.

**MTU note:** the `grants` claim increases JWT size. If you are running MTU
fragmentation scenarios, record whether default grants are enabled (or disable
them with `--token-issuer-no-default-grants`) so that JWT size shifts are
explicit in the results. If you use `jwt_deny` or `biscuit_deny`, capture their
token lengths in the MTU run metadata so deny overhead is visible in the
fragmentation analysis.

The deterministic token bundle (`benchmarks/tokens.json`) includes a
`jwt_grants_schema` marker that records the default grant template for the
generated JWTs.

The bundle also includes `jwt_deny` and `biscuit_deny` deterministic tokens to
exercise deny-over-allow behavior in a controlled way.

## Step 3: Start the Environment

Start the Mosquitto broker and metrics collector (Prometheus) using Docker
Compose:

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

> [!NOTE]
> The `--build` flag ensures that the plugin is copied into the Docker image
> correctly.
>
> Resource snapshots in `benchmarks/run_scenarios.py` now fail fast if
> Prometheus returns empty CPU or memory vectors. Keep `mosquitto`,
> `metrics-collector`, and `cadvisor` running for benchmark executions that
> collect resource telemetry.

## Step 4: Run Benchmarks

You can run the benchmark script to measure latency and throughput:

```bash
python3 benchmarks/metrics_collector.py
```

### Static ACL Scenarios (Compound Gate with Two Authorization Sources)

Static ACL policy semantics and parity constraints are centralized in
`../../SCENARIO_POLICIES.md` (`## 2.4`).

Relevant plugin options (set in `mosquitto_*.conf`):

- `plugin_opt_role_username_prefix` (default: `role:`)
- `plugin_opt_biscuit_role_fact` (default: `role`, must be a simple predicate identifier like `role` or `device_role`)
- `plugin_opt_biscuit_authorizer_profile` (default: `simple`; allowed: `simple`, `rbac`, `contextual`)
- `plugin_opt_biscuit_authorizer_max_time_ms` (default: `25`; must be `>= 1`; caps Biscuit authorizer runtime per evaluation to avoid false denials under host contention)
- `plugin_opt_acl_read_full_authz false` in static configs (documents expiry-only `ACL_READ` fan-out behavior for static-policy runs)
- StaticAcl bias warnings are intentionally conservative diagnostics. For Biscuit, warning inspection is profile-aware (`simple`: direct `right`; `rbac`/`contextual`: derived `role_right` grants), and indicates token grant shape risk in StaticAcl mode rather than a definitive allow/deny result for the current request.

Ensure the ACL file (`docker/static-acl.conf`) uses the same role names.

### Biscuit Authorizer Template Profiles (Issue 21)

Token-only Biscuit scenarios can now select plugin-side authorizer complexity with:

- `plugin_opt_biscuit_authorizer_profile simple`:
  direct `right/deny` evaluation baseline.
- `plugin_opt_biscuit_authorizer_profile rbac`:
  includes role-derived rights/denies (`role_right`, `role_deny`).
- `plugin_opt_biscuit_authorizer_profile contextual`:
  strict contextual profile with role-derived allows/denies gated by
  `role_active_from/role_active_until`; direct `right(...)` is ignored while
  direct `deny(...)` is always enforced.

Dedicated scenarios for this axis:

- `TOKEN-AUTHORIZER-PROFILE-SIMPLE-BISCUIT`
- `TOKEN-AUTHORIZER-PROFILE-RBAC-BISCUIT`
- `TOKEN-AUTHORIZER-PROFILE-CONTEXTUAL-BISCUIT`

Static scenario ACL coverage:
- `STATIC-ACL-PUBLISH-JWT`, `STATIC-ACL-PUBLISH-BISCUIT`: publish path (`ACL_WRITE`) with writer role tokens.
- `STATIC-ACL-FANOUT-JWT`, `STATIC-ACL-FANOUT-BISCUIT`: subscribe path (`ACL_SUBSCRIBE`) with reader subscribers and writer publisher; fan-out delivery invokes `ACL_READ` as documented above.
- Static scenarios are wired to role-only token fixtures so ACL file rules remain authoritative.

### ACL_READ Fan-out Mode (`acl_read_full_authz`)

`MOSQ_ACL_READ` fan-out checks can be configured with:

- `plugin_opt_acl_read_full_authz false` (default): expiry-only checks for cached sessions on `ACL_READ`; optimized for high fan-out throughput experiments.
- `plugin_opt_acl_read_full_authz true`: run full authorization on `ACL_READ` (token/HTTP/SQLite/dynamic policy path), useful for correctness and churn-focused experiments.

Example:

```conf
plugin_opt_acl_read_full_authz true
```

Trade-off:
- `false` minimizes per-subscriber callback cost.
- `true` enforces full policy semantics per delivery and may significantly increase CPU/latency as subscriber count grows.

### Issue 30: Dynamic-Policy `ACL_READ` Fan-Out Churn Coverage

These scenarios validate that policy changes are enforced for **already subscribed**
clients during fan-out delivery (`MOSQ_ACL_READ`), not just at subscribe time.

Dynamic Security (strict `ACL_READ`):
- `DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-10/50/100`
- `DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-10/50/100`
- Uses `mosquitto_dynsec_acl_read.conf` (`plugin_opt_acl_read_full_authz true`)
- Seeds baseline from `dynamic-security-fanout-read-allow-unpinned.json`
  so one subscriber username can authorize all declared fan-out clients
- Mid-run churn swaps to `dynamic-security-fanout-read-deny-unpinned.json`
  after message 5

SQLite (strict `ACL_READ`):
- `SQLITE-ACL-READ-FANOUT-CHURN-JWT-10/50/100`
- `SQLITE-ACL-READ-FANOUT-CHURN-BISCUIT-10/50/100`
- Uses `mosquitto_sqlite_acl_read.conf` (`policy_mode=sqlite`,
  `plugin_opt_acl_read_full_authz true`,
  `plugin_opt_sqlite_seed_demo_rules false`)
- Seeds fan-out SQLite RBAC rows before each run and revokes reader-role
  `ACL_READ` grant mid-run after message 5

Deterministic cadence details:
- SQLite fan-out scenarios reseed policy state at the start of each repeat.
- Churn triggers exactly when publisher `sequence_id == fanout_churn_after_messages`.
- Delivery accounting uses pre/post buckets: pre is `< after_messages`, post is
  `>= after_messages`.
- With strict `ACL_READ`, post-churn delivery drops are used as cache-validity
  signal that runtime policy changes are not masked by session cache state.

### Issue 37: Strict `ACL_READ` Fan-Out Across Policy Profiles

Issue 37 extends strict fan-out coverage beyond dynamic-policy churn scenarios so
`ACL_READ` comparisons include token-only, HTTP profile tiers, and hybrid profile
tiers.

Strict config files:
- `mosquitto_integration_acl_read_full.conf` (token mode)
- `mosquitto_http_acl_read.conf` (`policy_mode=http`)
- `mosquitto_hybrid_acl_read.conf` (`policy_mode=hybrid`)
- TLS variants under `docker/tls/` are available via `-TLS` scenario suffixes.

Scenario families:
- Token strict fan-out:
  - `TOKEN-ACL-READ-FANOUT-STRICT-ALLOW-{JWT|BISCUIT}-{10,50,100}`
  - `TOKEN-ACL-READ-FANOUT-STRICT-DENY-{JWT|BISCUIT}-10`
- HTTP strict fan-out:
  - `HTTP-ACL-READ-FANOUT-STRICT-{SIMPLE|MED|COMPLEX}-{ALLOW|DENY}-{JWT|BISCUIT}-10`
  - `HTTP-ACL-READ-FANOUT-STRICT-MED-ALLOW-{JWT|BISCUIT}-{50,100}`
- Hybrid strict fan-out:
  - `HYBRID-ACL-READ-FANOUT-STRICT-{SIMPLE|MED|COMPLEX}-{ALLOW|DENY}-{JWT|BISCUIT}-10`
  - `HYBRID-ACL-READ-FANOUT-STRICT-MED-ALLOW-{JWT|BISCUIT}-{50,100}`

Result metadata now records strict fan-out context per run:
- `scenario_config.policy_source`
- `scenario_config.authz_profile`
- `scenario_config.acl_read_enforcement`
- `scenario_config.subscriber_count`

### Issue 22: Periodic SQLite RBAC Churn Scenarios

- `SQLITE-RBAC-CHURN-JWT`
- `SQLITE-RBAC-CHURN-BISCUIT`

These scenarios run strict `ACL_READ` fan-out with deterministic periodic SQLite
policy updates (`sqlite_toggle_read`) to simulate runtime RBAC churn during an
active data-plane stream. Default cadence: first churn at message 4, then every
4 messages, up to 4 churn events.

### Issue 22: Deep SQLite RBAC Profiles

- `SQLITE-RBAC-DEEP-CONFLICT-JWT`
- `SQLITE-RBAC-DEEP-CONFLICT-BISCUIT`
- `SQLITE-RBAC-DEEP-CONTROL-JWT`
- `SQLITE-RBAC-DEEP-CONTROL-BISCUIT`

Deep profiles add:
- Explicit deny-over-allow conflicts at the same priority tier.
- Multi-role assignments with priority-tier precedence.
- Control/admin topic family coverage (`$CONTROL/#`, `system/notifications/#`)
  with mixed allow/deny grants.

Deep conflict scenarios use `sqlite_toggle_private_deny` to periodically toggle
private-topic deny rows and observe deterministic authorization transitions under
strict `ACL_READ`.

Example run:

```bash
python3 benchmarks/run_scenarios.py \
  --scenarios SQLITE-RBAC-DEEP-CONFLICT-JWT,SQLITE-RBAC-DEEP-CONTROL-BISCUIT
```

Validation signal in scenario result JSON (`runs[].loadgen.fanout_churn`):
- `triggered=true`
- `received_pre_churn > 0`
- `received_post_churn` drops below `expected_post_churn`

### Anonymous Flow Scenario (DYNAMIC-SECURITY-ANONYMOUS-BASELINE)

Policy rationale and security trade-offs are documented in
`../../SCENARIO_POLICIES.md` (`## 2.8`).

**Usage:**
```bash
python3 benchmarks/run_scenarios.py --scenarios DYNAMIC-SECURITY-ANONYMOUS-BASELINE
```

This run uses `docker/mosquitto_anon.conf` and `docker/dynamic-security-anon.json`.

Anonymous flow is explicitly gated by plugin config:

- `plugin_opt_allow_anonymous_no_token true`

In this mode, clients with no token/password are admitted by Mosquitto
(`allow_anonymous true`) and authorized by Dynamic Security `anonymousGroup`
policy during ACL checks.

### Smoke Test

Run a lightweight health check + single publish for JWT and Biscuit:

```bash
python3 benchmarks/smoke_test.py
```

TLS smoke test:

```bash
bash docker/tls/generate_certs.sh
python3 benchmarks/smoke_test.py --tls
```

### Issue 39 Broker Integration Assertions

Issue 39 adds a dedicated `pytest` integration suite that validates runtime
enforcement against a real Mosquitto process with the Rust plugin loaded.

Test location:
- `tests/integration/test_runtime_enforcement.py`

Marker:
- `broker_integration`
- `ci_heavy`

Run the fast local suite (matches PR/push CI runtime coverage):

```bash
cd mqtt-auth-biscuit
pytest -m "broker_integration and not ci_heavy" \
  tests/integration/test_runtime_enforcement.py -vv -s
```

Run all Issue 39 broker integration assertions:

```bash
cd mqtt-auth-biscuit
pytest -m broker_integration tests/integration/test_runtime_enforcement.py -vv -s
```

Run only the benchmark flow unit tests used by CI:

```bash
cd mqtt-auth-biscuit
pytest \
  benchmarks/test_loadgen_worker_suback.py \
  benchmarks/test_loadgen_fanout_sync.py \
  benchmarks/test_acl_read_fanout_churn_coverage.py \
  benchmarks/test_static_acl_coverage.py \
  benchmarks/test_authz_config_state.py \
  benchmarks/test_policy_churn.py -q
```

CI-compatible invocations:

```bash
cd mqtt-auth-biscuit
DOCKER_COMPOSE_BIN="docker compose" \
pytest -m "broker_integration and not ci_heavy" tests/integration -vv -s

DOCKER_COMPOSE_BIN="docker compose" \
pytest -m broker_integration tests/integration -vv -s
```

What this suite asserts:
- Expiry enforcement in `ACL_CHECK` for JWT and Biscuit with both
  `acl_read_full_authz=false` and `acl_read_full_authz=true`
- No false disconnect on non-expired deny paths (`ACL_READ`, `ACL_WRITE`,
  `ACL_SUBSCRIBE`) and connected allow paths
- Reconnect with a fresh token after forced expiry disconnect
- Broker log evidence for `with_will=false` kick semantics
- Basic auth and MQTT v5 enhanced auth entrypoints
- Plain TCP and TLS broker modes
- Control-triggered `disableClient` kick enforcement with reconnect + denied
  post-change subscribe lifecycle (Issue 31)
- Fan-out churn runtime enforcement under strict `ACL_READ` dynamic-security
  configuration

CI split and expected runtime:
- `pull_request`/`push` runs:
  - benchmark flow unit tests above
  - `pytest -m "broker_integration and not ci_heavy" ...`
- Nightly (`schedule`) and manual (`workflow_dispatch`) runs:
  - `pytest -m broker_integration ...` (full suite including heavy cases)
- Typical timing on GitHub-hosted runners:
  - Benchmark flow unit tests: usually < 1 minute
  - Fast runtime suite: usually single-digit to low-teens minutes (cache-sensitive)
  - Full runtime suite: often higher teens to 30+ minutes (cache/load-sensitive)

Failure artifact capture:
- Set `RUNTIME_ENFORCEMENT_ARTIFACT_DIR=/path/to/out` when running locally to persist:
  - `mosquitto.log`, `authz.log`, `token-issuer.log`
  - `docker-compose-ps.txt`, `docker-compose-config.txt`
  - `context.json` and failed test node IDs
- CI uploads this artifact directory on broker-integration failures.

Timing bounds and flake-control strategy:
- Docker bring-up + service readiness bounded to `60s`
- Client connect/reauth waits bounded to `10s`
- Expiry disconnect assertion bounded to `8s`
- Message delivery assertions bounded to `4-5s`
- Dynamic policy churn settle window uses `1.4s` before post-churn assertions
- If host load is high, rerun the marker suite once before classifying as a
  regression

You can also run the full scenario battery from `ARTICLE.MD` (MTU sweep, thundering herd, policy complexity, HTTP introspection latency/loss, hybrid contingency, and MQTT reauthentication):

```bash
python3 benchmarks/run_scenarios.py
```

### TLS-Enabled Runs

To measure TLS overhead across all network paths (MQTT, token issuer, authz HTTP, Prometheus):

```bash
bash docker/tls/generate_certs.sh
docker compose -f docker/docker-compose.yml -f docker/docker-compose.tls.yml up --build -d
python3 benchmarks/run_scenarios.py --tls
```

Optional TLS flags:

- `--tls-ca-file <path>`: custom CA bundle (default: `docker/tls/ca.pem`)
- `--tls-insecure`: disable certificate verification for local testing (obviously not recommended for production)

For the microbenchmark or single-run metrics collector over TLS:

```bash
python3 benchmarks/mqtt_auth_client.py --token1 "<token>" --token2 "<token>" --tls
python3 benchmarks/metrics_collector.py --tls --port 8883
```

To select a different Mosquitto configuration for a run (e.g. HTTP policy or hybrid policy), set `MOSQUITTO_CONF`:

```bash
MOSQUITTO_CONF=docker/mosquitto_http.conf python3 benchmarks/run_scenarios.py
```

### HTTP Policy Backend Schema (HTTP/Hybrid Modes)

> [!IMPORTANT]
> The authz-server requires **HTTP/2** (h2c for cleartext, h2 for TLS). Clients must support HTTP/2 prior knowledge (no HTTP/1.1 upgrade). Ensure your HTTP client library supports HTTP/2 before running HTTP policy scenarios.

#### Authz-server environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTHZ_MAX_CONNS` | Maximum concurrent HTTP/2 connections (backpressure limit) | `1024` |

When `policy_mode` is `http` or `hybrid`, the plugin POSTs JSON to the policy endpoint:

```json
{
  "client_id": "client_1",
  "topic": "sensors/client_1/temp",
  "access": 2,
  "token": "<optional JWT string>"
}
```

- `access` is the numeric Mosquitto ACL access value (e.g., 1 = subscribe, 2 = publish, 3 = read).
- `token` is only included for JWT requests; Biscuit requests omit it.

The endpoint must respond with **HTTP 200** and `Content-Type: application/json`:

```json
{ "allow": true }
```

Any non-200 status, invalid JSON, missing/invalid content-type, or oversized response is treated as an error.

#### Hybrid fallback semantics

In `hybrid` mode, HTTP errors trigger **token-only** evaluation. An explicit `allow=false` response is still a denial (no fallback).

#### Plugin options (HTTP)

```conf
plugin_opt_http_url <http(s)://host:port/path>
plugin_opt_http_ca_file <path/to/ca.pem>
plugin_opt_http_tls_insecure <true|false>
plugin_opt_http_timeout_seconds <u64>
plugin_opt_http_max_response_bytes <u64>
```

Defaults:

- `http_timeout_seconds`: `2` (min: `1`)
- `http_max_response_bytes`: `65536` (max: `1048576`)

For the MQTT `AUTH` reauthentication microbenchmark only:

```bash
python3 benchmarks/mqtt_auth_client.py --token1 "<token>" --token2 "<token>"
```

You can also monitor resource usage via:

- **Prometheus**: `http://localhost:9090`
- **Docker Stats**: `docker stats`

If resource snapshots fail because vectors are empty, validate telemetry wiring
with:

```bash
python3 benchmarks/verify_prometheus.py
```

## Network Baseline Measurement (iperf3)

The scenario runner includes automatic network capacity measurement using `iperf3` to establish a baseline before each test batch. This helps interpret throughput results and ensures fair comparisons across scenarios.

### How It Works

1. **Automatic measurement**: Before each scenario runs, the runner starts an `iperf3` client that measures network capacity between the host and the Docker network.
2. **Retry logic**: If the first measurement fails, the runner automatically retries up to 2 times with a brief delay.
3. **Validity checking**: The runner compares measured throughput against a configurable minimum threshold and warns if network constraints may affect test validity.
4. **Data inclusion**: Network baseline data is included in each scenario's result JSON under the `network_baseline` field.

### iperf3 CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--iperf3` / `--no-iperf3` | Enable/disable baseline measurement | `True` (enabled) |
| `--iperf3-host` | iperf3 server hostname | `localhost` |
| `--iperf3-port` | iperf3 server port | `5201` |
| `--iperf3-duration` | Test duration in seconds | `5` |
| `--iperf3-streams` | Number of parallel streams | `4` |
| `--iperf3-min-mbps` | Minimum expected throughput in Mbps | `100.0` |

### Usage Examples

Run with default iperf3 baseline (enabled by default):
```bash
python3 benchmarks/run_scenarios.py --scenarios BASELINE-NO-AUTH,TOKEN-BASELINE-JWT
```

Disable iperf3 baseline (faster startup, no network validation):
```bash
python3 benchmarks/run_scenarios.py --no-iperf3
```

Adjust minimum expected throughput for constrained environments:
```bash
python3 benchmarks/run_scenarios.py --iperf3-min-mbps 10.0
```

### Result Structure

The `network_baseline` field in scenario results contains:

```json
{
  "network_baseline": {
    "enabled": true,
    "config": {
      "host": "localhost",
      "port": 5201,
      "duration": 5,
      "streams": 4,
      "min_mbps": 100.0
    },
    "result": {
      "throughput": {
        "megabits_per_second": 985.42,
        "bytes_per_second": 123177500.0
      },
      "bytes_transferred": 615887500,
      "tcp": {
        "retransmits": 0,
        "rtt_ms": 0.25
      }
    },
    "validity": {
      "valid": true,
      "checks": {
        "throughput_sufficient": true,
        "loss_acceptable": true
      },
      "metrics": {
        "throughput_mbps": 985.42,
        "expected_min_mbps": 100.0
      },
      "warnings": []
    }
  }
}
```

### Docker Compose

The `iperf3` service is defined in `docker/docker-compose.yml` and starts automatically with the scenario runner. The server listens on port 5201 and requires `NET_ADMIN` capability for traffic shaping compatibility.

## CONTROL Scenarios (Dynamic Security)

The benchmark suite includes two categories of CONTROL scenarios that exercise Mosquitto's Dynamic Security plugin via the `$CONTROL/dynamic-security/v1` topic:

### CONTROL-OVERHEAD Scenarios

These scenarios measure authorization overhead only - they publish to `$CONTROL/dynamic-security/v1` without actual command payloads:

- `CONTROL-OVERHEAD-KICK-REAUTH-JWT` - JWT admin control-plane authorization
- `CONTROL-OVERHEAD-KICK-REAUTH-BISCUIT` - Biscuit admin control-plane authorization
- `CONTROL-OVERHEAD-ACL-READ-NOTIFY-JWT` - JWT control with fanout notifications
- `CONTROL-OVERHEAD-ACL-READ-NOTIFY-BISCUIT` - Biscuit control with fanout notifications

### CONTROL-CHURN Scenarios (Issue 35)

These scenarios exercise actual Dynamic Security policy modifications via JSON command payloads:

- `CONTROL-CHURN-CREATE-ROLE-JWT/BISCUIT` - Create and delete roles dynamically
- `CONTROL-CHURN-GROUP-CLIENT-JWT/BISCUIT` - Add/remove clients from groups
- `CONTROL-CHURN-ACL-MODIFY-JWT/BISCUIT` - Modify role ACLs dynamically

Command payloads are generated using the `dynsec_commands.py` module and include operations like:

```json
{
  "commands": [
    {"command": "createRole", "rolename": "dynamic_role_abc123", "acls": [...]},
    {"command": "addGroupClient", "groupname": "sensors", "username": "client_1"},
    {"command": "deleteRole", "rolename": "dynamic_role_abc123"}
  ]
}
```

### CLI Options For Control Messages

The `loadgen.py` script supports direct control message testing:

```bash
# Publish a control message with custom payload
python3 benchmarks/loadgen.py \
  --control-mode \
  --control-topic '$CONTROL/dynamic-security/v1' \
  --control-payload '{"commands":[{"command":"createRole","rolename":"test"}]}' \
  --control-repeat 3

# Load payload from file
python3 benchmarks/loadgen.py \
  --control-mode \
  --control-payload-file /path/to/commands.json \
  --username admin \
  --password "$(cat admin_token.txt)"
```

## INTERLEAVED-CONTROL Scenarios (Issue 36)

These scenarios measure **control plane latency under active data plane load** by publishing control messages interleaved with regular data messages. Unlike CONTROL-OVERHEAD (control-only) and CONTROL-CHURN (batch policy churn), these scenarios simulate realistic mixed workloads where control messages (policy updates, reauthentication triggers) must be processed while ongoing data traffic continues.

### Scenario Configuration

- `CONTROL-INTERLEAVED-DATA-JWT` - JWT tokens with interleaved control messages
- `CONTROL-INTERLEAVED-DATA-BISCUIT` - Biscuit tokens with interleaved control messages

Default configuration publishes **1 control message after every 10 data messages** (`--control-after-messages 10`).

### How Interleaving Works

1. Clients publish data messages to their normal topic (`sensors/{client_id}/temp`)
2. After every N data messages (configured by `control_after_messages`), a control message is injected
3. The control message is published to `$CONTROL/dynamic-security/v1` with a Dynamic Security command
4. Both data and control message latencies are tracked separately

### Metrics Captured

Interleaved scenarios capture four key metrics:

1. **Data message latency** (`publish` in results): Baseline latency under mixed load
2. **Control message latency** (`control` in results): Network round-trip time for control operations (now populated from interleaved mode)
3. **Control injection delay** (`control_injection_delay` in results): Total time to pause/resume data flow including serialization and publish
4. **Control synchronization overhead**: Difference between injection delay and publish latency (computed as `control_injection_delay - control`)

Example output structure:

```json
{
  "inputs": {
    "control": {
      "topic": "$CONTROL/dynamic-security/v1",
      "mode": false,
      "after_messages": 10,
      "qos": 1
    }
  },
  "publish": {
    "count": 500,
    "mean_ms": 5.2,
    "p99_ms": 12.3
  },
  "control": {
    "count": 50,
    "mean_ms": 8.7,
    "p99_ms": 18.5
  },
  "control_injection_delay": {
    "count": 50,
    "mean_ms": 1.1,
    "p99_ms": 2.3
  }
}
```

### CLI Options For Interleaved Control

```bash
# Run interleaved scenario via run_scenarios.py
python3 benchmarks/run_scenarios.py --scenarios CONTROL-INTERLEAVED-DATA-JWT

# Direct loadgen usage with interleaved control
python3 benchmarks/loadgen.py \
  --username jwt \
  --password "$(cat jwt_token.txt)" \
  --control-topic '$CONTROL/dynamic-security/v1' \
  --control-payload '{"commands":[{"command":"getClient","username":"admin"}]}' \
  --control-after-messages 5 \
  --messages 100
```

### Research Notes

- **Control overhead**: Compare `control.mean_ms` between `INTERLEAVED-CONTROL-*` and `CONTROL-OVERHEAD-*` to measure the impact of concurrent data traffic
- **Data impact**: Compare `publish.mean_ms` between baseline (`TOKEN-BASELINE-JWT`, `TOKEN-BASELINE-BISCUIT`) and interleaved scenarios to quantify data plane degradation
- **Injection efficiency**: `control_injection_delay` should remain low (<5ms); high values indicate broker contention

## Step 5: Cleanup

When finished, stop the environment:

```bash
docker compose -f docker/docker-compose.yml down
```

## Packet Capture and Fragmentation Analysis (Issue 15)

The benchmark suite includes automated packet capture using `tcpdump` to analyze TCP fragmentation behavior during MTU stress tests. This feature is automatically enabled for MTU scenarios (NETWORK-MTU-200-JWT, NETWORK-MTU-500-BISCUIT-CHAIN-25, etc.) to provide quantitative insights into how token size affects network-level fragmentation.

### How It Works

1. **Automatic activation**: tcpdump is automatically started for any scenario with an MTU configuration (`netem: {mtu: N}`)
2. **Capture filter**: By default captures MQTT traffic on ports 1883 (plaintext) and 8883 (TLS)
3. **Pcap storage**: Capture files are saved to `benchmarks/results/pcap/<scenario_id>.pcap`
4. **Automated analysis**: After scenario completion, pcap files are analyzed for fragmentation metrics

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--tcpdump` / `--no-tcpdump` | Enable/disable packet capture | `True` |
| `--tcpdump-filter` | Custom tcpdump filter expression | `port 1883 or port 8883` |
| `--tcpdump-duration` | Max capture duration in seconds | `300` |
| `--tcpdump-output-dir` | Directory for pcap files | `benchmarks/results/pcap` |
| `--tcpdump-analyze` / `--no-tcpdump-analyze` | Enable/disable pcap analysis | `True` |

### Usage Examples

Run with default tcpdump capture (auto-enabled for MTU scenarios):
```bash
python3 benchmarks/run_scenarios.py --scenarios NETWORK-MTU-200-JWT,NETWORK-MTU-500-BISCUIT-CHAIN-25
```

Disable packet capture entirely:
```bash
python3 benchmarks/run_scenarios.py --no-tcpdump
```

Capture only, skip analysis (faster for bulk captures):
```bash
python3 benchmarks/run_scenarios.py --no-tcpdump-analyze
```

Custom filter to capture all traffic:
```bash
python3 benchmarks/run_scenarios.py --tcpdump-filter "tcp"
```

### Metrics Captured

Packet analysis results are included in scenario output JSON under `packet_analysis_result`:

```json
{
  "packet_analysis_result": {
    "enabled": true,
    "pcap_file": "benchmarks/results/pcap/NETWORK-MTU-200-JWT.pcap",
    "metrics": {
      "total_packets": 1250,
      "total_bytes": 456780,
      "fragment_count": 42,
      "retransmission_count": 3,
      "tcp_packets": 1200,
      "ip_packets": 1250
    },
    "inter_packet_deltas_ms": {
      "p50_ms": 1.234,
      "p95_ms": 5.678,
      "p99_ms": 12.345,
      "mean_ms": 2.345,
      "max_ms": 45.678,
      "min_ms": 0.123
    },
    "tcp_streams": {
      "192.168.1.10:54321-192.168.1.20:1883": {
        "src_ip": "192.168.1.10",
        "src_port": 54321,
        "dst_ip": "192.168.1.20",
        "dst_port": 1883,
        "packets": 625,
        "bytes": 228390,
        "fragments": 21,
        "retransmissions": 1
      }
    },
    "fragmentation_stats": {
      "fragments_detected": 42,
      "fragmented_packets": 28,
      "max_fragment_chain": 3,
      "avg_fragment_size": 180.5,
      "min_fragment_size": 150,
      "max_fragment_size": 200,
      "token_size_bytes": 1256,
      "expected_fragments": 7
    },
    "token_size_correlation": {
      "token_bytes": 1256,
      "mtu_configured": 200,
      "fragmentation_ratio": 0.0336,
      "bytes_per_fragment": 29.9,
      "packets_per_token_estimate": 9.42
    }
  }
}
```

### Research Interpretation

- **Fragmentation ratio**: Higher ratios indicate more network overhead from token transmission
- **Bytes per fragment**: Lower values suggest inefficient fragmentation (more headers per data)
- **Retransmissions**: Under MTU stress, retransmissions indicate network congestion or packet loss
- **Token size correlation**: Directly relates token size to network fragmentation costs

This data supports ARTICLE.MD's fragmentation hypothesis (H₂/H₃ validation) by quantifying the network-level impact of token size under varying MTU constraints.
