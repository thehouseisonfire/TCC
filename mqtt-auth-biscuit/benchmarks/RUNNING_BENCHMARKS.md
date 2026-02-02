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

For the MQTT `AUTH` reauthentication microbenchmark only:

```bash
python3 benchmarks/mqtt_auth_client.py --token1 "<token>" --token2 "<token>"
```

You can also monitor resource usage via:

- **Prometheus**: `http://localhost:9090`
- **Docker Stats**: `docker stats`

## Step 5: Cleanup

When finished, stop the environment:

```bash
docker compose -f docker/docker-compose.yml down
```
