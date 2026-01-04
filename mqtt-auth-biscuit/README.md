# Mosquitto Auth Biscuit Plugin

A production-grade Rust plugin for the Eclipse Mosquitto MQTT broker that
natively supports both JWT and Biscuit tokens.

## Features

- **Fast and Secure**: Implemented in Rust with a thread-safe LRU cache.
- **Flexible Authorization**: Supports both standard JWT claims and powerful
  Biscuit Datalog policies.
- **MQTT 5.0 Ready**: Built for modern MQTT environments.
- **Containerized**: Ready-to-use Docker environment for testing and deployment.

## Getting Started

### Prerequisites

- Rust (v1.92+)
- Docker and Docker Compose
- Mosquitto development headers (provided in source if missing)

### Building

```bash
cargo build --release
```

The plugin will be generated at `target/release/libmosquitto_auth_biscuit.so`.

### Running with Docker

```bash
cd docker
docker-compose up --build
```

### Generating Tokens

```bash
cargo run --release --bin gen-tokens
```

## Benchmarking

See [benchmarks/BENCHMARK_PLAN.md](benchmarks/BENCHMARK_PLAN.md) for detailed
test scenarios and the Python-based metrics collector
`benchmarks/metrics_collector.py`.

## License

MIT
