# Mosquitto Auth Biscuit Plugin

A Rust plugin for the Eclipse Mosquitto MQTT broker that natively supports
both JWT and Biscuit tokens, intended as a reproducible research prototype.

## Features

- **Fast and Secure**: Implemented in Rust with a thread-safe LRU cache.
- **HTTP/2 Native**: All HTTP communication uses HTTP/2 (h2c or h2 with TLS).
- **Flexible Authorization**: Supports both standard JWT claims and powerful
  Biscuit Datalog policies.
- **MQTT 5.0 Ready**: Built for modern MQTT environments. **Note: Only MQTT v5 is supported - MQTT v3.1 is not implemented.**
- **Containerized**: Ready-to-use Docker environment for testing and deployment.

## Getting Started

### Prerequisites

- Rust (v1.93+)
- Docker and Docker Compose
- Mosquitto development headers (provided in source if missing)

### Building

```bash
cargo build --release -p mosquitto-auth-biscuit
```

The plugin will be generated at `target/release/libmosquitto_auth_biscuit.so`.

#### Developer feature flags

- `expiry_stats`: enable Biscuit expiry extraction metrics logged at plugin cleanup.
  Example: `cargo build -p mosquitto-auth-biscuit --features expiry_stats`

### Running with Docker

```bash
docker compose -f docker/docker-compose.yml up --build
```

### Generating Tokens

```bash
cargo run --release -p gen-tokens
```

### JWT grant schema

JWTs can carry structured `grants` for token-only authorization. Each grant
defines the MQTT operation (`publish`, `subscribe`, or `read`) and a topic
filter using standard MQTT wildcards (`+`, `#`).

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

Evaluation order (token-only):
1. Apply deny rules (`deny`/`denies`) for the requested operation (with `read`
   falling back to `subscribe` when no explicit read rule is present).
2. If no deny matches, apply allow rules (`right`/`grants`) using the same
   operation mapping.
3. Default is deny when no allow matches.

Subscribe/read semantics:
- `subscribe` implies `read` for all messages on the topic filter.
- `read` rules are used as explicit exceptions or refinements. Example: grant
  `subscribe` to a topic, then add a `read` deny rule for messages
  with particular contexts (e.g. the time it was sent or the sender)
 
Biscuit policy parity: `deny("op", "res")` facts are evaluated before allow rules, and
`deny("subscribe", ...)` blocks `ACL_READ` when the read operation is evaluated
via the subscribe fallback.

### HTTP policy backend options

When using `policy_mode=http` or `policy_mode=hybrid`, the plugin can be tuned:

- `plugin_opt_http_timeout_seconds <u64>`: request timeout (default: 2, min: 1)
- `plugin_opt_http_max_response_bytes <u64>`: max response size (default: 65536, max: 1048576)
- `plugin_opt_http_ca_file <path>`: CA bundle for HTTPS
- `plugin_opt_http_tls_insecure <true|false>`: disable cert verification (testing only)

The endpoint must respond with `{ "allow": true|false }` and HTTP 200.

Clients may also attenuate Biscuits by appending `deny` facts in new blocks. A
deny added in an attenuation block further restricts the token (never expands
rights) and is enforced by the same deny-over-allow rules as issuer facts.

Example client-side attenuation (Rust):

```rust
use biscuit_auth::{Biscuit, BlockBuilder, PublicKey};

fn attenuate_with_deny(token_b64: &str, public_key: &PublicKey) -> Biscuit {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(token_b64)
        .expect("token base64");
    let biscuit = Biscuit::from(&bytes, public_key).expect("token parse");
    let deny_block = BlockBuilder::new()
        .fact("deny(\"read\", \"sensors/client_1/temp\")")
        .expect("deny fact");
    biscuit.append(deny_block).expect("append")
}
```

By default, the token issuer adds grants for `publish`/`subscribe` on
`sensors/{subject}/temp` unless `no_default_grants` is set in the request or
`JWT_NO_DEFAULT_GRANTS=1` is set in the environment.

## Benchmarking

See [benchmarks/RUNNING_BENCHMARKS.md](benchmarks/RUNNING_BENCHMARKS.md) for how
to execute the scenario battery.

The main entrypoint is:

`benchmarks/run_scenarios.py`

For running the benchmark scripts:
  - Install dependencies: `uv pip install -r benchmarks/requirements.txt`

`benchmarks/metrics_collector.py` remains available as a legacy single-run
collector.

## License

MIT
