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

- Rust 1.93.1
- Docker and Docker Compose
- Python 3.14.2 + `uv 0.9.17`

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

## Policy And Scenarios

To keep this README concise, policy semantics and scenario parity details are centralized in:

- [`../SCENARIO_POLICIES.md`](../SCENARIO_POLICIES.md)

Progress tracking, open gaps, and implementation status are tracked in:

- [`../PROGRESS.md`](../PROGRESS.md)

## Benchmarking

See [benchmarks/RUNNING_BENCHMARKS.md](benchmarks/RUNNING_BENCHMARKS.md) for how
to execute the scenario battery.

For HTTP/hybrid benchmarking, the external authz server now resets to a neutral
rule-engine baseline (`authz_profile=custom`, empty rules, default deny).
Scenarios must apply an explicit profile or custom rule set; benchmark semantics
are no longer inherited from implicit startup behavior.

The top-level benchmark workflow entrypoint is:

`../scripts/run-benchmarks`

The direct scenario-runner module is:

`uv run --locked python -m benchmarks.run_scenarios`

The repo-level workflow wrapper is now Rust, but scenario orchestration,
Docker-state handling, and result aggregation still live in Python under
`benchmarks.run_scenarios`. The MQTT benchmark client implementation is Rust
`mqtt-loadgen`; `benchmarks/loadgen.py` is only a compatibility wrapper that
forwards to that Rust binary.

Use `../scripts/run-benchmarks --scenarios ...` for the stable wrapper
interface. Use the direct module form when you need runner-only flags such as
`--perf`, `--iperf3-*`, `--tcpdump-*`, `--client-topology`, or `--out`:

```bash
uv run --locked python -m benchmarks.run_scenarios --scenarios-arg ...
```

For running the benchmark scripts:
  - Install dependencies: `uv sync --locked`

`benchmarks/metrics_collector.py` remains available as a legacy single-run
collector.

## License

MIT
