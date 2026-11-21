# MQTT Authorization Benchmark

A reproducible research workspace for comparing MQTT authorization mechanisms,
with a focus on JWT and Biscuit tokens. The repository contains a Rust
authorization plugin for Eclipse Mosquitto, a scenario-driven benchmark suite,
MQTT load-generation clients, Docker fixtures, and infrastructure for preparing
a controlled benchmark host.

The plugin is a research prototype for MQTT 5. The final campaign closed with
**4,101 accepted results**. The [semantic verification record](SEMANTIC-VERIFIED.md)
points to the analysis index and explains the scope of the completed campaign.

## Repository layout

| Path | Purpose |
| --- | --- |
| [`mqtt-auth-biscuit/`](mqtt-auth-biscuit/) | Mosquitto plugin, token issuer, authorization server, Docker environment, and benchmark orchestration |
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

Run a small JWT/Biscuit comparison with the repository wrapper:

```bash
./scripts/run-benchmarks --scenarios TOKEN-BASELINE-JWT,TOKEN-BASELINE-BISCUIT \
  --clients 2 --messages 10 \
  --out benchmarks/results-quickstart --exclusive-out
```

The wrapper builds the plugin, generates benchmark credentials, manages the
Docker services, and writes the scenario JSON and summaries to
`mqtt-auth-biscuit/benchmarks/results-quickstart/`. Use a fresh output path
for each run. See the [benchmark runbook](mqtt-auth-biscuit/benchmarks/RUNNING_BENCHMARKS.md)
for TLS, topology, packet capture, and profiling.

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
./scripts/check-docs
```

## Documentation

See the [documentation index](DOCUMENTATION.md) for plugin setup, research
methodology, host provisioning, and verification.

Generated tokens, private key material, local benchmark results, live
inventories, and environment-specific Docker state should remain local and must
not be committed.
