# MQTT Authorization Benchmark

A reproducible research workspace for comparing MQTT authorization mechanisms,
with a focus on JWT and Biscuit tokens. The repository contains a Rust
authorization plugin for Eclipse Mosquitto, a scenario-driven benchmark suite,
MQTT load-generation clients, Docker fixtures, and infrastructure for preparing
a controlled benchmark host.

The plugin is a research prototype and currently supports MQTT 5 only.

## Repository layout

| Path | Purpose |
| --- | --- |
| [`mqtt-auth-biscuit/`](mqtt-auth-biscuit/) | Mosquitto plugin, token issuer, authorization server, Docker environment, and benchmark orchestration |
| [`rumqtt/`](rumqtt/) | Vendored MQTT client and benchmark workspace |
| [`tools/`](tools/) | Rust implementations of repository-level helper commands |
| [`scripts/`](scripts/) | Stable operator-facing wrappers for the helper tools |
| [`infra/`](infra/) | Terraform and Ansible automation for a reproducible benchmark host |

## Prerequisites

- Rust 1.93.1 (pinned by [`rust-toolchain.toml`](rust-toolchain.toml))
- Python 3.14.2 (pinned by [`.python-version`](.python-version))
- [`uv`](https://docs.astral.sh/uv/) 0.9.17
- Docker with the Compose plugin
- `iperf3` for network measurements (the client runs on the host)

Terraform and Ansible are only required when provisioning a dedicated benchmark
host.

## Quick start

Install the pinned Python dependencies from the repository root:

```bash
uv sync --locked
```

Build the plugin and generate the benchmark token fixtures:

```bash
cargo build \
  --locked \
  --release \
  --manifest-path mqtt-auth-biscuit/Cargo.toml \
  -p mosquitto-auth-biscuit

cargo run \
  --locked \
  --manifest-path mqtt-auth-biscuit/Cargo.toml \
  -p gen-tokens \
  --bin gen-tokens
```

The plugin library is written to
`mqtt-auth-biscuit/target/release/libmosquitto_auth_biscuit.so`.

Start the local broker and supporting services:

```bash
docker compose \
  -f mqtt-auth-biscuit/docker/docker-compose.yml \
  up --build
```

For benchmark execution, use the repository-level wrapper:

```bash
./scripts/run-benchmarks --help
```

See the
[benchmark runbook](mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md) before
starting a scenario run; it documents scenario selection, topology, output,
packet capture, and performance-measurement options.

## Development

Run the root helper-tool tests:

```bash
cargo test --locked --workspace
```

Run the plugin workspace tests:

```bash
cargo test --locked --manifest-path mqtt-auth-biscuit/Cargo.toml
```

Run Python unit and smoke tests:

```bash
./run_python_tests.sh
```

The script uses Docker-backed tests when bridge networking is available and
otherwise runs the non-Docker subset locally. CI can require Docker bridge
support by setting `PYTHON_TESTS_REQUIRE_DOCKER_BRIDGE=1`.

Run formatting, linting, type checking, and pin validation:

```bash
cargo fmt --all --manifest-path Cargo.toml -- --check
cargo fmt --all --manifest-path mqtt-auth-biscuit/Cargo.toml -- --check
uv run --locked --group dev ruff check .
uv run --locked --group dev mypy mqtt-auth-biscuit
./scripts/check-pins
```

## Documentation

- [Plugin overview and local Docker setup](mqtt-auth-biscuit/README.md)
- [Benchmark execution guide](mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md)
- [Scenario policy semantics](SCENARIO_POLICIES.md)
- [Full benchmark run plan](RUN.md)
- [Benchmark host infrastructure](infra/README.md)
- [Custom Mosquitto build](BUILD-MOSQUITTO.md)
- [Research context](ARTICLE.md)
- [Project status](PROGRESS.md)

Generated tokens, private key material, local benchmark results, live
inventories, and environment-specific Docker state should remain local and must
not be committed.
