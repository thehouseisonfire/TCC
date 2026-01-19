# Mosquitto Auth Biscuit Plugin

A Rust plugin for the Eclipse Mosquitto MQTT broker that natively supports
both JWT and Biscuit tokens, intended as a reproducible research prototype.

## Features

- **Fast and Secure**: Implemented in Rust with a thread-safe LRU cache.
- **Flexible Authorization**: Supports both standard JWT claims and powerful
  Biscuit Datalog policies.
- **MQTT 5.0 Ready**: Built for modern MQTT environments. **Note: Only MQTT v5 is supported - MQTT v3.1 is not implemented.**
- **Containerized**: Ready-to-use Docker environment for testing and deployment.

## Getting Started

### Prerequisites

- Rust (v1.92+)
- Docker and Docker Compose
- Mosquitto development headers (provided in source if missing)

### Building

```bash
cargo build --release -p mosquitto-auth-biscuit
```

The plugin will be generated at `target/release/libmosquitto_auth_biscuit.so`.

### Running with Docker

```bash
docker compose -f docker/docker-compose.yml up --build
```

### Generating Tokens

```bash
cargo run --release -p gen-tokens
```

## Benchmarking

See [benchmarks/RUNNING_BENCHMARKS.md](benchmarks/RUNNING_BENCHMARKS.md) for how
to execute the scenario battery.

The main entrypoint is:

`benchmarks/run_scenarios.py`

`benchmarks/metrics_collector.py` remains available as a legacy single-run
collector.

## License

MIT
