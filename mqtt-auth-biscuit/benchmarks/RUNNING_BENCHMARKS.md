# Running MQTT Auth benchmarks

This guide explains how to run the benchmarks for the JWT and Biscuit
authentication plugin.

**Important Note**: This implementation supports **MQTT v5 only**. MQTT v3.1 is not implemented and will not be analyzed in these benchmarks.

## Prerequisites

- **Rust**: For building the plugin and token generator.
- **Docker & Docker Compose**: For running the test environment.
- **Python 3**: For running the benchmark scripts.
  - Install dependencies: `uv pip install -r benchmarks/requirements.txt`

## One-command run (recommended)

From the repository root, you can run the full workflow (build, token generation,
scenario run, cleanup) with:

```bash
python3 run_benchmarks.py
```

To run a subset of scenarios or enable TLS, pass flags through:

```bash
python3 run_benchmarks.py --scenarios JWT-01,BIS-01
python3 run_benchmarks.py --tls
```

## Step 1: Build the Plugin

The Mosquitto plugin must be built in release mode:

```bash
cargo build --release -p mosquitto-auth-biscuit
```

This generates `target/release/libmosquitto_auth_biscuit.so`.

## Step 2: Generate Tokens

The benchmarking suite uses predefined tokens. Generate them with:

```bash
cargo run -p gen-tokens --bin gen-tokens
```

This will create/update `benchmarks/tokens.json` and write `docker/biscuit_public.key` for the Mosquitto plugin.

The Docker Mosquitto configuration is pre-wired to the deterministic keys used
by `gen-tokens` (see `docker/mosquitto.conf`).

### JWT grants schema (token-only authz)

Token-only JWT authorization relies on a `grants` claim. Each grant defines the
MQTT operation (`publish`, `subscribe`, or `read`) and a topic filter using
standard MQTT wildcards (`+`, `#`).

Example issuer request payload:

```json
{
  "client_id": "client_1",
  "roles": ["admin", "sensor"],
  "grants": [
    {"op": "publish", "res": "sensors/client_1/temp"},
    {"op": "subscribe", "res": "sensors/client_1/+"}
  ],
  "denies": [
    {"op": "read", "res": "sensors/client_1/humidity"}
  ]
}
```

The resulting JWT claim set embeds `roles`, `grants`, and `denies`. For Biscuit,
`roles` are emitted as `role("<name>")` facts, `grants` as `right("<op>", "<res>")`,
and `denies` as `deny("<op>", "<res>")` facts.

Optional deny rules can be provided under `denies`, using the same `op`/`res`
shape. Deny rules take precedence over allow rules (deny-over-allow), so a
matching deny will reject access even if a grant matches. If no `read` rule is
present for a topic, the plugin falls back to matching `subscribe` grants for
`ACL_READ` checks.

Biscuit parity: `deny("op", "res")` facts are evaluated before allow rules, and
`deny("subscribe", ...)` blocks `ACL_READ` when the read operation is evaluated
via the subscribe fallback.

Attenuation note: clients may append `deny` facts in attenuation blocks to
further restrict rights. The `BIS-DENY-ATTENUATED` scenario uses a token where
the deny is in an appended block to exercise this path.

### Client-side (online) attenuation

To exercise **online attenuation** (client-side block append), use the new
`biscuit-attenuate` helper and the `BIS-ATTENUATE-CLIENT` scenario.

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

Scenario coverage:

- `BIS-ATTENUATE-CLIENT` performs the same attenuation automatically inside the
  load generator before each client connects, measuring attenuation latency and
  token length growth in the scenario results.
- `BIS-ATTENUATE-TTL` tests a TTL-only attenuation block.
- `BIS-ATTENUATE-DENY` adds a deny fact plus a resource check (template-driven
  on the client id).
- `BIS-ATTENUATE-OP-ONLY` restricts only the operation without a topic check.
- `POLICY-COMPLEX-1/5/25` exercise empty-block chain length (signature chain overhead).
- `POLICY-COMPLEX-LOW/MED/HIGH` exercise richer Datalog rules (role/group, scoped ownership,
  capability, region/device constraints) with the same topic/operation to isolate authorizer
  evaluation cost.

Scenario outputs include a `policy_complexity.kind` marker for these runs (currently
`"datalog"`) to distinguish them from block-chain length scenarios in downstream analysis.

**Analysis note:** attenuation/delegation scenarios are Biscuit-only capability
tests. Scenario outputs include `capability_flags.biscuit_only=true` to mark
them as non-parity comparisons in downstream analysis.

### Client-to-client delegation

The delegation benchmark now exercises **real client-side delegation** instead
of pre-generated delegated tokens.

- `DELEGATION-TEMP-ONLY` uses a base Biscuit token and delegates a restricted
  token per client at runtime (topic + operation + TTL). Delegation latency and
  resulting token length are recorded as `delegation` metrics.
- `DELEGATION-HANDOFF` adds a broker-mediated handoff: a master client delegates
  tokens, then publishes them to `delegation/handoff` over MQTT. Workers
  subscribe with a handoff token (`biscuit_delegation_handoff` from
  `tokens.json`) to receive their delegated token before connecting with their
  actual publish credentials. The default handoff uses QoS 1 with retained
  messages.
- `DELEGATION-SIMULATED` keeps the previous pre-generated delegated token to
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

## Step 4: Run Benchmarks

You can run the benchmark script to measure latency and throughput:

```bash
python3 benchmarks/metrics_collector.py
```

### Static ACL scenarios (compound gate with two authorization sources)

Static ACL scenarios (`STATIC-ACL-*`) use a **compound gate** with **two authorization sources**:

1. **Token-side policies** (JWT claims or Biscuit Datalog rules) are evaluated first.
2. **Mosquitto’s native ACL file** is evaluated second, using a synthetic username derived from the token’s role.

**Resolution model (StaticAcl = OR):**
- If the token **allows**, the plugin returns `MOSQ_ERR_SUCCESS` and Mosquitto **does not** consult the ACL.
- If the token **denies**, the plugin returns `MOSQ_ERR_PLUGIN_DEFER` so the ACL file decides.

**Control-plane note:** the same OR resolution is applied in `MOSQ_EVT_CONTROL` for StaticAcl runs (token allow short-circuits ACL; token deny defers to ACL).

This means authorization decisions come from **two sources of truth**:
- The token can grant access even when the ACL would deny.
- The ACL can still grant access when the token does not include an allow rule.

For fair benchmark comparison, static ACL tokens should carry only role identity (JWT `roles` claim or Biscuit `role(<value>)` fact) without extra policy rules. This isolates ACL cost while still validating each token format. If you want stricter-than-ACL behavior, add extra facts/rules to the token.

**Role selection simplification**: static ACL scenarios are designed for **single-role tokens**. If multiple roles are present, the plugin prefers `admin` first and otherwise the first non-empty role. Avoid multi-role tokens in `STATIC-ACL-*` runs to prevent ambiguity.

Relevant plugin options (set in `mosquitto_*.conf`):

- `plugin_opt_role_username_prefix` (default: `role:`)
- `plugin_opt_biscuit_role_fact` (default: `role`, must be a simple predicate identifier like `role` or `device_role`)

Ensure the ACL file (`docker/static-acl.conf`) uses the same role names.

### Smoke test

Run a lightweight health check + single publish for JWT and Biscuit:

```bash
python3 benchmarks/smoke_test.py
```

TLS smoke test:

```bash
bash docker/tls/generate_certs.sh
python3 benchmarks/smoke_test.py --tls
```

You can also run the full scenario battery from `ARTICLE.MD` (MTU sweep, thundering herd, policy complexity, HTTP introspection latency/loss, hybrid contingency, and MQTT reauthentication):

```bash
python3 benchmarks/run_scenarios.py
```

### TLS-enabled runs

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

### HTTP policy backend schema (HTTP/Hybrid modes)

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

## Network Baseline Measurement (iperf3)

The scenario runner includes automatic network capacity measurement using `iperf3` to establish a baseline before each test batch. This helps interpret throughput results and ensures fair comparisons across scenarios.

### How it works

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
python3 benchmarks/run_scenarios.py --scenarios BASE-01,JWT-01
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

### CLI Options for Control Messages

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

- `INTERLEAVED-CONTROL-DATA-JWT` - JWT tokens with interleaved control messages
- `INTERLEAVED-CONTROL-DATA-BISCUIT` - Biscuit tokens with interleaved control messages

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

### CLI Options for Interleaved Control

```bash
# Run interleaved scenario via run_scenarios.py
python3 benchmarks/run_scenarios.py --scenarios INTERLEAVED-CONTROL-DATA-JWT

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
- **Data impact**: Compare `publish.mean_ms` between baseline (`JWT-01`, `BIS-01`) and interleaved scenarios to quantify data plane degradation
- **Injection efficiency**: `control_injection_delay` should remain low (<5ms); high values indicate broker contention

## Step 5: Cleanup

When finished, stop the environment:

```bash
docker compose -f docker/docker-compose.yml down
```

## Packet Capture and Fragmentation Analysis (Issue 15)

The benchmark suite includes automated packet capture using `tcpdump` to analyze TCP fragmentation behavior during MTU stress tests. This feature is automatically enabled for MTU scenarios (MTU-200-JWT, MTU-500-BIS-25, etc.) to provide quantitative insights into how token size affects network-level fragmentation.

### How it works

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
python3 benchmarks/run_scenarios.py --scenarios MTU-200-JWT,MTU-500-BIS-25
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
    "pcap_file": "benchmarks/results/pcap/MTU-200-JWT.pcap",
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
