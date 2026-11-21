# Running MQTT Auth Benchmarks

Run selected MQTT 5 scenarios with the repository wrapper or the Python
scenario runner. See the [full run plan](../../RUN.md) for the nominal
matrices and the [final dataset](../../SEMANTIC-VERIFIED.md#final-dataset-and-provenance)
for the completed campaign.

- [Scenario policies and comparison classes](../../SCENARIO_POLICIES.md)
- [Benchmark host provisioning](../../infra/README.md)

## Authz Baseline

For HTTP and hybrid benchmarks, the authz-server reset baseline is intentionally
neutral:

- `authz_profile=custom`
- empty `rules`
- default deny

Each scenario applies its profile or custom rules after `/config/reset`.

## Scenario Semantics

The scenario registry now classifies runnable scenarios explicitly:

| `semantic_class` | JWT binding | Biscuit binding | Meaning |
| --- | --- | --- | --- |
| `capability` | `off` | `off` | Bearer/capability semantics. Shared-token reuse is valid when the scenario declares it. |
| `mixed` | `strict` | `off` | JWT is identity-bound, Biscuit is not. These scenarios are intentionally not parity. |
| `parity_identity_bound` | `strict` | `strict` | The only class that may claim equivalent identity semantics. |

Strict Biscuit binding uses a dedicated identity fact predicate. The default is
`client_id`; if a scenario overrides it via `biscuit_client_id_fact`, the token
issuer request and generated Mosquitto plugin config must use the same
predicate.

Current inventory rules:

- Single-client HTTP parity lives in `HTTP-LATENCY-200MS-PARITY-*` and
  `HTTP-PROFILE-{SIMPLE,MED,COMPLEX}-PARITY-*`.
- Multi-client parity lives in the generated strict fan-out `-PARITY-` families
  for HTTP and hybrid `ACL_READ` scenarios.
- The non-`PARITY` strict fan-out families remain `capability`; they still use
  shared-token multi-client semantics and therefore must not be described as
  identity-bound parity.
- Biscuit attenuation/delegation scenarios are intentionally `capability`, not
  parity.
- Runnable multi-client parity now depends on per-client strict provisioning at
  startup. Static scenarios select a strict credential profile; lifecycle
  scenarios obtain one token per MQTT client identity from the Token Issuer.

## Credential Profiles

`gen-tokens` writes schema-v2 `benchmarks/password-map.json` containing
per-client equivalents of the reusable JWT and Biscuit fixtures. Profile names
match fixture semantics, including deny, fan-out, static-role, delegation,
complexity, and strict identity-bound variants. Fan-out scenarios select
subscriber and publisher profiles independently.

Complex Datalog profiles also carry structural semantic metadata. The load
generator reports the selected profile and validates the declared Datalog level
for every client. Schema-v1 maps are rejected with an instruction to regenerate
tokens so complexity runs cannot silently use unattested credentials.

Loadgen result inputs expose `credential_attestations` by actual credential
role. `clients` covers standard workers or fan-out subscribers, while
`fanout_publisher` separately identifies the publisher profile. Combined and
merged fan-out results contain both roles, including the number of credentials
validated for each, so different subscriber and publisher profiles are not
conflated.

Every scenario declares one credential mode:

- `per_client`: resolve `client_N` and `fanout_publisher` from explicit profiles.
- `issuer`: obtain initial and refreshed per-client credentials from Token Issuer.
- `shared`: retain identical bytes because sharing is part of the benchmark.
- `none`: unauthenticated scenarios.

Shared mode is restricted to MQTT5 two-token sequences, the authorizer-template
matrix that intentionally holds token bytes constant, and documented non-parity
strict fan-out bearer tests. Other authenticated scenarios use per-client
credentials.

The full bundle is generated up to `GEN_TOKENS_MAX_CLIENTS` (default `10000`).
Lower this value for local development when the complete 10,000-client fixture
set is unnecessary.

The full family-to-class mapping is the source-of-truth table in
`../../SCENARIO_POLICIES.md`.

## Prerequisites

- **Rust**: For building the plugin and token generator.
- **Docker & Docker Compose**: For running the test environment.
- **Python 3.14.2 + uv 0.9.17**: For running the benchmark scripts.
  - Install dependencies: `uv sync --locked`
- **iperf3**: For network baseline measurement (client-side). The server runs in Docker; the `iperf3` binary must be installed on the host. Install with `sudo apt-get install iperf3`.
- **openssl**: Required for TLS certificate generation (needed when running TLS-enabled scenarios). Install with `sudo apt-get install openssl`.

## Run selected scenarios

From the repository root, the wrapper builds the plugin, generates tokens,
runs the selected scenarios, and cleans up Compose services.

```bash
./scripts/run-benchmarks --scenarios TOKEN-BASELINE-JWT,TOKEN-BASELINE-BISCUIT \
  --out benchmarks/results-token-baseline --exclusive-out
```

Use `./scripts/run-benchmarks --help` for the wrapper's options. Running
without `--scenarios` lists the available IDs after setup. The direct runner
can list IDs without the wrapper's build and token generation.

Except for repository-root wrapper commands, run the examples below from
`mqtt-auth-biscuit/`. The direct runner exposes options for perf, iperf3,
and tcpdump. Use `--help` for the full list.

```bash
uv run --locked python -m benchmarks.run_scenarios --help
```

`--workload-shape` accepts `matrix`, `fixed-clients`, `fixed-messages`,
`fixed`, or `all` (default). A fixed-client workload still varies
`--messages` when the scenario leaves that axis open.

## Result directories

The wrapper resolves relative `--out` paths from `mqtt-auth-biscuit/`.
`--exclusive-out` claims a new directory before workloads begin and preserves
partial results if the run fails. Record the batch coordinates, repetition,
command, source freeze, and hashes outside the fresh destination. The runner
writes one JSON per scenario and JSON/CSV summaries for the invocation.

Capture and profiling paths default to `benchmarks/results/pcap` and
`benchmarks/results/perf`. With a custom `--out`, set
`--tcpdump-output-dir` or `--perf-output-dir` on the direct runner to give
those artifacts a distinct path for each batch. The default capture mode
captures MTU scenarios, which require both capture and analysis.

## Frozen Docker images

From the repository root, use `COMPOSE_PROFILES='*' ./scripts/freeze-images`
to build and record the image IDs and Compose hashes in
`mqtt-auth-biscuit/docker/image-freeze.json`. Use `./scripts/save-images`
to archive the images and `./scripts/check-images` to verify the local IDs.
For reproduction from an existing freeze, restore its manifest and load its
image archive. Pass `--no-build-images` to the wrapper or direct runner to
use the verified local images. `--skip-build` skips only the wrapper's
host-side Rust build.

## Generate benchmark credentials

The [plugin setup](../README.md) describes the build and deterministic fixture
generation steps. The generator writes `benchmarks/tokens.json`,
`benchmarks/password-map.json`, and the broker's public keys under `docker/`.

### Token Policy Note

Token claim/fact schema and deny-over-allow semantics are defined in
`../../SCENARIO_POLICIES.md` (`## 1` and `## 2.1`).

For HTTP/hybrid scenarios, the scenario registry in `benchmarks/run_scenarios.py`
is the source of truth for which authz profile or custom rules get applied to
the external PDP before timing begins.

### Client-Side (Online) Attenuation

The `TOKEN-ATTENUATION-COMBINED-BISCUIT`,
`TOKEN-ATTENUATION-SUBSCRIBE-DENY-BISCUIT`, and
`TOKEN-ATTENUATION-PUBLISH-ONLY-BISCUIT` scenarios exercise online attenuation.
The Rust `mqtt-loadgen` path performs Biscuit attenuation in-process and then
probes the attenuated subscribe restriction, so the run fails if the broker
ignores the appended capability or deny. Reported `attenuation` and `delegation`
timings exclude subprocess startup overhead.

The standalone `biscuit-attenuate` binary remains available as a thin CLI
wrapper around the same shared attenuation function for manual token inspection.

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

### Explicit Publish-Path Authorization Stress

Dedicated high-volume publish-path stress scenarios:

- `TOKEN-PUBLISH-STRESS-JWT`
- `TOKEN-PUBLISH-STRESS-BISCUIT`

These scenarios pin the workload at 25 clients and 1000 messages per client on
the standard token-only publish path. They exist to make steady-state
per-publish authorization cost explicit instead of depending on caller-supplied
`--messages`. They also pin `client_count`, so benchmark matrix runs that vary
`--clients` / `--messages` should not include them.

### Biscuit Local-Datalog Stress

Dedicated fixed-workload local-Datalog stress scenarios:

- `TOKEN-DATALOG-STRESS-LOW-BISCUIT`
- `TOKEN-DATALOG-STRESS-MED-BISCUIT`
- `TOKEN-DATALOG-STRESS-HIGH-BISCUIT`

These reuse the existing low/med/high complex Biscuit fixtures but pin the
workload at 25 clients and 1000 messages per client. They exist to make the
local token-evaluation cost of richer Biscuit rules explicit under heavy
publish traffic.

### Biscuit Composability Stress

Dedicated fixed-workload composability scenarios:

- `TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-{MED,HIGH}-BISCUIT`
- `TOKEN-COMPOSABILITY-DELEGATED-DATALOG-{MED,HIGH}-BISCUIT`

These pin the workload at 25 clients, 1000 QoS 1 messages per client, and the
medium/high complex Biscuit profiles. The attenuated variants derive and use a
token locally. The delegated variants use a separate delegator, transfer one
derived credential per delegatee over the broker-mediated handoff path, and
require the delegatees to publish with the received credentials. Results must
attest all derivations, handoff deliveries, restricted publishes, and denied
subscription probes.

Reconnect variants:

- `TOKEN-PUBLISH-STRESS-RECONNECT-JWT`
- `TOKEN-PUBLISH-STRESS-RECONNECT-BISCUIT`

These use the same pinned QoS 1 25x1000 publish workload, but run 6 repeated
connect/publish/disconnect cycles with a 1-second pause between runs and fresh
issuer-backed credentials from `mosquitto_shortcache.conf`. They measure the
combination of full reconnect authentication overhead and sustained publish-path
authorization cost. They use full reconnects, not MQTT v5 in-session reauth.

Each run records one successful issuer response per client with issuance and
expiry metadata plus a SHA-256 token fingerprint (never the credential itself).
The runner requires fingerprints to change across all six repetitions and
validates broker-side authentication, token-validation, and session-cache
counter deltas for every run.

### HTTP Authorization Complexity Stress

Dedicated high-volume HTTP policy-evaluation stress scenarios:

- `HTTP-AUTHZ-COMPLEXITY-SIMPLE-{JWT|BISCUIT}`
- `HTTP-AUTHZ-COMPLEXITY-MED-{JWT|BISCUIT}`
- `HTTP-AUTHZ-COMPLEXITY-COMPLEX-{JWT|BISCUIT}`

These also pin the workload at 25 clients and 1000 messages per client. They
reuse the existing HTTP `simple` / `med` / `complex` authz profiles so the
complexity axis is PDP rule evaluation rather than token structure. Like the
token publish-stress family, they should be run as targeted slices instead of
being mixed into client/message matrix sweeps.

Successful runs require one external PDP decision for every publish, all
decisions to use the selected profile, and zero policy denials or injected
failures. Results include total rules examined and rules examined per request.

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

The `TOKEN-COMPOSABILITY-DELEGATED-DATALOG-*` scenarios use the broker-mediated
handoff path and start from the medium/high complex Datalog fixtures. This keeps
them operationally distinct from local attenuation.

Handoff-specific knobs (loadgen):

- `--biscuit-delegate-handoff-qos` (default: 1)
- `--biscuit-delegate-handoff-no-retain` (disable retained handoff messages)
- `--biscuit-delegate-handoff-role combined|delegator|delegatee` (default:
  `combined`)
- `--biscuit-delegate-handoff-nonce` for role-aware cross-container handoff
- `--biscuit-delegate-handoff-ready-dir` for structured delegatee readiness
- `--biscuit-delegate-handoff-ready-timeout-seconds` (default: 120)

With `--client-topology container-per-client`,
`TOKEN-DELEGATION-HANDOFF-BISCUIT` runs one delegator container and one
delegatee container per MQTT client. Delegatees subscribe first using the
handoff token, write readiness files, then accept only handoff payloads matching
their `client_id` and the runner-provided nonce. The delegator emits no
measured connects, so merged results report `container_count = clients + 1`
while `connect.count = clients`; this asymmetry is intentional, not an
accounting leak.

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

## Scenario configuration

The scenario runner starts the Compose services for each workload. It uses
Prometheus and cAdvisor to collect CPU and memory metrics and rejects missing
required resource snapshots.

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

### HTTP/Hybrid Scenario Configuration

HTTP and hybrid scenarios should always declare one of:

- `authz_profile: "simple" | "med" | "complex"`
- `authz_profile: "custom"` with explicit `rules`

Current baseline latency/failure slices use the `simple` profile explicitly so
they exercise the rule engine rather than any implicit startup behavior.

If an HTTP/hybrid scenario forgets to apply policy, the neutral reset state will
deny requests. This is intentional and helps surface misconfigured benchmarks
early.

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

Semantic interpretation:
- The base families above are `capability` (`jwt_identity_binding=off`,
  `biscuit_identity_binding=off`) even though `ACL_READ` enforcement is strict.
  They are valid read-path authorization benchmarks, but not identity-bound
  parity scenarios.
- Identity-bound parity is provided by the generated `-PARITY-` variants of the
  HTTP/Hybrid strict `ACL_READ` fan-out families. Those runs set both binding
  modes to `strict`.
- For multi-client `-PARITY-` runs, the scenario password is intentionally left
  blank so Rust `mqtt-loadgen` provisions one token per client identity via the
  token issuer. Reusing a shared token would contradict the parity semantics.
- Token-backed strict fan-out stays outside parity: startup-issued tokens do not
  preserve the source fixture's explicit fan-out allow/deny claims, so those
  runs remain `capability` scenarios.

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
uv run --locked python -m benchmarks.run_scenarios \
  --scenarios-arg SQLITE-RBAC-DEEP-CONFLICT-JWT,SQLITE-RBAC-DEEP-CONTROL-BISCUIT
```

Validation signal in scenario result JSON (`runs[].loadgen.fanout_churn`):
- `triggered=true`
- `phases[]` records exact expected and observed deliveries for each policy epoch
- allow phases receive every expected delivery and deny phases receive none

### Anonymous Flow Scenario (DYNAMIC-SECURITY-ANONYMOUS-BASELINE)

Policy rationale and security trade-offs are documented in
`../../SCENARIO_POLICIES.md` (`## 2.9`).

**Usage:**
```bash
uv run --locked python -m benchmarks.run_scenarios --scenarios-arg DYNAMIC-SECURITY-ANONYMOUS-BASELINE
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
uv run --locked python benchmarks/smoke_test.py
```

TLS smoke test:

```bash
bash docker/tls/generate_certs.sh
uv run --locked python benchmarks/smoke_test.py --tls
```

### Broker integration tests

From the repository root, run the broker integration tests against a real
Mosquitto process with the plugin loaded:

```bash
uv run --locked --group dev pytest -m "broker_integration and not ci_heavy" \
  mqtt-auth-biscuit/tests/integration -vv
```

Use `-m broker_integration` to include heavier cases. The suite checks
authentication, expiry, policy enforcement, and fanout over TCP and TLS.
Set `RUNTIME_ENFORCEMENT_ARTIFACT_DIR` to retain failure logs and Compose
diagnostics. See the [CI workflow](../../.github/workflows/ci-benchmarks.yml)
for the current test selection.

### TLS-Enabled Runs

To measure TLS overhead across externally accessed network paths (MQTT, token
issuer, authz HTTP, and the Prometheus query API):

```bash
bash docker/tls/generate_certs.sh
uv run --locked python -m benchmarks.run_scenarios \
  --scenarios-arg TOKEN-BASELINE-JWT-TLS,TOKEN-BASELINE-BISCUIT-TLS \
  --out benchmarks/results-token-baseline-tls --exclusive-out
```

Optional TLS flags:

- `--tls-ca-file <path>`: custom CA bundle (default: `docker/tls/ca.pem`)
- `--tls-insecure`: disable certificate verification for local testing (obviously not recommended for production)

The canonical Phase 2 preflight deliberately uses `--tls-insecure`. Its `-TLS`
scenarios validate encrypted transport and TLS endpoint wiring, not certificate
chain, hostname, expiry, or trust-store validation. Those properties are outside
the benchmark scenario contract.

Prometheus continues to scrape cAdvisor over HTTP on the private Compose
network. cAdvisor is not exposed through a TLS endpoint in this configuration;
only Prometheus's externally accessed query API uses TLS.

For the microbenchmark or single-run metrics collector over TLS:

```bash
uv run --locked python benchmarks/mqtt_auth_client.py --token1 "<token>" --token2 "<token>" --token1-topic "sensors/<client_id>/before" --token2-topic "sensors/<client_id>/after" --tls
uv run --locked python benchmarks/metrics_collector.py --tls --port 8883
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
uv run --locked python benchmarks/mqtt_auth_client.py --token1 "<token>" --token2 "<token>" --token1-topic "sensors/<client_id>/before" --token2-topic "sensors/<client_id>/after"
```

You can also monitor resource usage via:

- **Prometheus (plaintext stack)**: `http://localhost:9090`
- **Prometheus (TLS stack)**: `https://localhost:9443`
- **Docker Stats**: `docker stats`

If resource snapshots fail because vectors are empty, validate telemetry wiring
with:

```bash
uv run --locked python benchmarks/verify_prometheus.py
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
uv run --locked python -m benchmarks.run_scenarios --scenarios-arg BASELINE-NO-AUTH,TOKEN-BASELINE-JWT
```

Disable iperf3 baseline (faster startup, no network validation):
```bash
uv run --locked python -m benchmarks.run_scenarios --scenarios-arg TOKEN-BASELINE-JWT --no-iperf3
```

Adjust minimum expected throughput for constrained environments:
```bash
uv run --locked python -m benchmarks.run_scenarios --scenarios-arg TOKEN-BASELINE-JWT --iperf3-min-mbps 10.0
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

The benchmark suite exercises Mosquitto's Dynamic Security plugin through
`$CONTROL/dynamic-security/v1`. Every command workload subscribes to the
response topic, correlates responses with commands, and fails on missing or
application-level error responses.

### CONTROL-ENFORCEMENT Scenarios

These workloads apply a command while fan-out traffic is active and validate
the resulting policy effect:

- `CONTROL-ENFORCEMENT-KICK-JWT/BISCUIT` - disable active subscribers and require delivery to stop
- `CONTROL-ENFORCEMENT-ACL-READ-NOTIFY-JWT/BISCUIT` - revoke read access, require delivery to stop, and require one notification per subscriber

Both families validate the allow-before/deny-after delivery phases in addition
to command responses.

### CONTROL-CHURN Scenarios (Issue 35)

These scenarios exercise actual Dynamic Security policy modifications via JSON command payloads:

- `CONTROL-CHURN-CREATE-ROLE-JWT/BISCUIT` - Create and delete roles dynamically
- `CONTROL-CHURN-GROUP-CLIENT-JWT/BISCUIT` - Add/remove clients from groups
- `CONTROL-CHURN-ACL-MODIFY-JWT/BISCUIT` - Modify role ACLs dynamically
- `CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-JWT/BISCUIT` - Group membership churn against a generated large dynsec state
- `CONTROL-CHURN-NOOP-GROUP-CLIENT-JWT/BISCUIT` - Idempotent membership updates against pre-seeded dynsec state
- `CONTROL-CHURN-REPEAT-SAME-ENTITY-JWT/BISCUIT` - Repeated mutations against one shared dynsec entity
- `CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-JWT/BISCUIT` - Repeated mutations against worker-specific dynsec entities
- `CONTROL-CHURN-CONCURRENT-CONTROLLERS-JWT/BISCUIT` - Multi-controller contention against worker-specific dynsec entities

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

`control_payload` supports recursive `{client_id}` expansion before each worker publishes. That lets one scenario template generate worker-local dynsec entities without shipping a separate payload file per client.

The ACL-read fan-out churn matrix also includes mutation-driven dynsec variants that publish control commands during live fan-out traffic:

- `DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT/BISCUIT-{10,50,100}`
- `DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT/BISCUIT-{10,50,100}`

These use `fanout_churn_kind=dynamic_security_control` and publish the configured control payload from the fan-out controller instead of swapping the dynsec JSON file on disk.

### CLI Options For Control Messages

Python orchestrates scenarios and invokes the Rust `mqtt-loadgen` client for all
MQTT benchmark execution. `benchmarks/loadgen.py` remains only as a
compatibility wrapper around Rust `mqtt-loadgen`; direct control-message testing
can use either entrypoint:

```bash
# Publish a control message with custom payload
cargo run --locked -p gen-tokens --bin mqtt-loadgen -- \
  --control-mode \
  --control-topic '$CONTROL/dynamic-security/v1' \
  --control-payload '{"commands":[{"command":"createRole","rolename":"test"}]}' \
  --control-repeat 3

# Load payload from file
cargo run --locked -p gen-tokens --bin mqtt-loadgen -- \
  --control-mode \
  --control-payload-file /path/to/commands.json \
  --username admin \
  --password "$(cat admin_token.txt)"
```

### Client Container Topology (Issue 41)

`run_scenarios.py` runs MQTT benchmark clients in Docker by default:

- `--client-topology container-single` (default): one loadgen container simulates
  `N` MQTT clients. This preserves the established load shape while isolating
  the generator from the host process namespace.
- `--client-topology container-per-client`: launches deterministic one-client
  containers named `client_1..client_N` for standard publish/control scenarios,
  improving topology fidelity for “independent IoT node” claims.
- `--client-topology host`: legacy compatibility mode for local debugging.

Client resource controls are configured with `--client-cpus`,
`--client-memory`, and optional `--client-cpuset`. Containerized clients use
Docker service names (`mosquitto`, `token-issuer`) inside `mqtt-net`; host-side
orchestration, Prometheus queries, and authz configuration still use localhost
ports.

Use `container-single` for most matrix runs where broker/plugin isolation is the
main concern. Use `container-per-client` for thundering-herd, strict
identity-bound, and topology-fidelity slices. Capability scenarios may still
reuse shared tokens when declared; strict parity scenarios continue to provision
one JWT/Biscuit per `client_id` through the Token Issuer.

Fan-out and Biscuit delegation handoff scenarios use explicit split-role
orchestration under `container-per-client`: subscribers/delegatees are started
first, the runner waits for structured readiness, then the publisher/delegator
role is launched. Use `container-single` for broad matrix runs and
`container-per-client` for topology-fidelity slices.

Fan-out delivery latency is carried in the versioned payload using
`CLOCK_MONOTONIC_RAW`, not wall-clock time or process-relative `Instant`
origins. Split publisher/subscriber containers must run on the same Linux host
without custom time-namespace offsets; the result merger verifies that every
role attests the expected clock source and payload version.

### Synchronized Connect Bursts

`TOKEN-THUNDERING-HERD-JWT` and `TOKEN-THUNDERING-HERD-BISCUIT` enable
`sync_connect`, which is a two-phase barrier:

1. **Connect phase** - every participant waits until all others are ready, then
   all begin establishing MQTT connections together.
2. **Publish phase** - each process holds its measured publish workload until
   every participant has reported ready *after* its CONNACK(s). Only then does
   the runner release the publish gate, so all participants publish
   concurrently. This prevents early connecters from saturating the broker's
   connection event loop while slower clients are still connecting.

Topology behavior:

- `container-single`: Rust `mqtt-loadgen` uses in-process gates across its
  worker tasks for both phases; the publish gate releases only after every local
  client has connected.
- `container-per-client`: `run_scenarios.py` starts one loadgen container per
  MQTT client, ensures the `sync-barrier` Compose service is running, and
  coordinates both phases as distinct barrier runs (the publish phase reuses the
  connect run id with a `-publish` suffix).
- `host`: uses the same in-process gates as direct local loadgen execution.

The external barrier is intentionally a runner-managed implementation detail.
Operators normally select it only by choosing `--client-topology
container-per-client`; direct loadgen barrier flags are reserved for diagnostics.

Result JSON includes a `sync_connect` section with the connect-phase barrier
mode, participant count, ready count, release timestamp, maximum ready skew,
client wait summary, and any `sync_barrier_*` errors, plus a nested
`publish_barrier` object with the same fields for the publish phase (and
`sync_publish_barrier_*` errors). Fan-out split-role runs, Biscuit delegation
handoff, and reauth-storm runs have dedicated coordination paths and
intentionally reject incompatible `sync_connect` combinations.

### Reconnect-and-Publish Lifecycle Bursts

`TOKEN-LIFECYCLE-RECONNECT-PUBLISH-JWT` and
`TOKEN-LIFECYCLE-RECONNECT-PUBLISH-BISCUIT` model auth-heavy full reconnect
workloads by running 25 clients through 6 repeated connect/publish/disconnect
cycles, with 25 messages per client per cycle and fresh issuer-backed
credentials on each run.

These scenarios use the standard loadgen session path rather than MQTT v5
reauth. Each repeat performs a full CONNECT handshake, publishes the configured
workload, disconnects, sleeps briefly, and then starts the next run. This keeps
the measurement focused on reconnect authentication cost under sustained publish
activity.

## CONTROL-INTERLEAVED-DATA Scenarios (Issue 36)

These scenarios measure **control plane latency under active data plane load**
by publishing control messages interleaved with regular data messages. Unlike
CONTROL-ENFORCEMENT (fan-out policy effects) and CONTROL-CHURN (batch policy
churn), these scenarios isolate mixed workloads where control commands must be
processed while data traffic continues.

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
uv run --locked python -m benchmarks.run_scenarios --scenarios-arg CONTROL-INTERLEAVED-DATA-JWT

# Direct loadgen usage with interleaved control
cargo run --locked -p gen-tokens --bin mqtt-loadgen -- \
  --username jwt \
  --password "$(cat jwt_token.txt)" \
  --control-topic '$CONTROL/dynamic-security/v1' \
  --control-payload '{"commands":[{"command":"getClient","username":"admin"}]}' \
  --control-after-messages 5 \
  --messages 100
```

### Research Notes

- **Control latency**: Compare `control_response.mean_ms` across `CONTROL-INTERLEAVED-DATA-*` and `CONTROL-CHURN-*`; `control.mean_ms` records transport acknowledgement separately
- **Data impact**: Compare `publish.mean_ms` between baseline (`TOKEN-BASELINE-JWT`, `TOKEN-BASELINE-BISCUIT`) and interleaved scenarios to quantify data plane degradation
- **Injection efficiency**: `control_injection_delay` should remain low (<5ms); high values indicate broker contention

## Manual Compose cleanup

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
uv run --locked python -m benchmarks.run_scenarios --scenarios-arg NETWORK-MTU-200-JWT,NETWORK-MTU-500-BISCUIT-CHAIN-25
```

MTU scenarios require capture and analysis. Use `--tcpdump-filter` to
adjust the filter while retaining the MQTT traffic needed for validation.

### Capture validation and metrics

The result JSON stores packet analysis under `packet_analysis_result`:

| Field | Meaning |
| --- | --- |
| `metrics` | Packet and byte counts, fragment and retransmission counts, maximum observed IP packet size, and capture timestamps |
| `workload_interval_coverage` | MQTT packet, payload, and TCP session counts for each measured interval |
| `tcp_streams` | Statistics by TCP endpoint pair |
| `fragmentation_stats`, `token_size_correlation` | Fragment counts and MTU/token-size estimates |

The runner checks that each measured interval contains MQTT payload traffic
and covers the expected number of client connections. The interval counter
distinguishes successive TCP sessions that reuse an endpoint pair and
deduplicates retransmitted SYN packets. The maximum observed IP packet size
must fit the effective MTU.

IP fragment counts and TCP retransmissions describe the capture. The
token-size estimates approximate network overhead, while TLS and concurrent
traffic can also contribute packets. Use the scenario's workload and transport
settings when comparing captures.
