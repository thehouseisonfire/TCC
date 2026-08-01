# Repository Guidelines

## Project Structure & Module Organization

This is a reproducible MQTT authorization benchmark workspace. Root Rust helper binaries live in `tools/*` and are exposed through `scripts/`. The main plugin project is `mqtt-auth-biscuit/`, with Rust crates in `crates/`, Python benchmark orchestration and tests in `benchmarks/`, Docker fixtures in `docker/`, and runtime integration tests in `tests/integration/`. `rumqtt/` is a vendored MQTT benchmark/client workspace. Infrastructure automation lives under `infra/ansible/` and `infra/terraform/`.

## Build, Test, and Development Commands

- `uv sync --locked`: install the pinned Python 3.14.2 dev environment.
- `cargo test --locked --workspace`: run tests for the root helper-tool workspace.
- `cargo test --locked --manifest-path mqtt-auth-biscuit/Cargo.toml`: run the plugin workspace tests.
- `cargo fmt --all --manifest-path Cargo.toml -- --check`: check formatting for root Rust tools.
- `cargo fmt --all --manifest-path mqtt-auth-biscuit/Cargo.toml -- --check`: check plugin Rust formatting.
- `uv run --locked --group dev ruff check .`: run Python lint checks.
- `uv run --locked --group dev mypy mqtt-auth-biscuit`: type-check Python benchmark code.
- `./run_python_tests.sh`: run Python unit and smoke tests; starts Docker Compose when available.
- `./scripts/check-pins`: audit pinned toolchain and package versions.

## Coding Style & Naming Conventions

Rust uses `rustfmt` from `rust-toolchain.toml` and Clippy with pedantic/nursery checks for `mqtt-auth-biscuit`. Keep Rust modules in `snake_case`; package names use kebab-case. Python uses Ruff (linting + formatting) with 100-character lines, Python 3.14 syntax, sorted imports, and `snake_case` names. Prefer typed Python functions because mypy checks untyped definitions.

## Testing Guidelines

Place Python tests near benchmark code as `mqtt-auth-biscuit/benchmarks/test_*.py`, or under `mqtt-auth-biscuit/tests/integration/` for broker-backed behavior. Use pytest markers from `mqtt-auth-biscuit/pytest.ini`: `broker_integration` for real Mosquitto/plugin tests and `ci_heavy` for expensive full-run cases. Keep Docker-dependent tests tolerant of local Docker bridge availability unless CI requires it.

## Commit & Pull Request Guidelines

Recent commits use short summaries such as `bump deps` and `update docs`; follow that concise style and keep subjects focused. Before opening a PR, run the relevant Rust, Python, and pin-audit checks above. PR descriptions should state the change, list validation commands, link related issues, and include benchmark output or screenshots when results, dashboards, or generated artifacts change.

## Security & Configuration Tips

Do not commit regenerated secrets, local benchmark results, or environment-specific Docker state. Token samples and public keys are fixtures; treat new private material as local-only. Keep version pins synchronized across `pyproject.toml`, `uv.lock`, `Cargo.lock`, Terraform locks, and package-lock metadata.
