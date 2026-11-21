# Mosquitto Auth Biscuit Plugin

This Rust research plugin authenticates MQTT 5 clients with JWT or Biscuit.
It supports token-only authorization, static ACLs, Dynamic Security, SQLite,
and HTTP/2 policy decisions with optional local fallback.

## Build the plugin

From `mqtt-auth-biscuit/`, using the repository-pinned Rust toolchain:

```bash
cargo build --locked --release -p mosquitto-auth-biscuit
```

The library is written to `target/release/libmosquitto_auth_biscuit.so`.
The optional `expiry_stats` feature logs Biscuit expiry-extraction metrics
at plugin cleanup.

## Run the local broker

```bash
cargo run --locked -p gen-tokens --bin gen-tokens
docker compose -f docker/docker-compose.yml up --build
```

Compose builds the broker and plugin from source using the
[custom Mosquitto image](../BUILD-MOSQUITTO.md). The token generator prepares
the benchmark fixtures.

## Benchmark and policy guides

- [Workspace quick start](../README.md#quick-start) for a small JWT/Biscuit comparison.
- [Benchmark runbook](benchmarks/RUNNING_BENCHMARKS.md) for scenario, topology, and output options.
- [Scenario policies](../SCENARIO_POLICIES.md) for enforcement and parity semantics.

## License

MIT
