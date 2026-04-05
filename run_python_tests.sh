#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$SCRIPT_DIR/mqtt-auth-biscuit"
COMPOSE_BIN=${DOCKER_COMPOSE_BIN:-"docker compose"}
COMPOSE_FILES=("-f" "$WORKDIR/docker/docker-compose.yml")
SERVICES=(mosquitto authz netem metrics-collector cadvisor token-issuer)
CAPABILITY_OUT_DIR=$(mktemp -d /tmp/python-tests-capability.XXXXXX)
PARITY_OUT_DIR=$(mktemp -d /tmp/python-tests-parity.XXXXXX)
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-python-tests}"
export RESOURCE_SNAPSHOT_COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME"

cleanup() {
  $COMPOSE_BIN "${COMPOSE_FILES[@]}" down
  rm -rf "$CAPABILITY_OUT_DIR" "$PARITY_OUT_DIR"
}
trap cleanup EXIT

$COMPOSE_BIN "${COMPOSE_FILES[@]}" up --build -d "${SERVICES[@]}"

(cd "$WORKDIR" && cargo run --locked -p gen-tokens --bin gen-tokens)

PYTHONPATH="$WORKDIR" \
  uv run --locked --group dev pytest "$WORKDIR/benchmarks/test_qos_distribution.py" \
  "$WORKDIR/benchmarks/test_runner_startup_readiness.py" \
  "$WORKDIR/benchmarks/test_resource_snapshot.py" \
  "$WORKDIR/benchmarks/test_packet_analysis.py" \
  "$WORKDIR/benchmarks/test_scenario_semantics.py" \
  "$WORKDIR/benchmarks/test_loadgen_strict_provisioning.py"

PYTHONPATH="$WORKDIR" uv run --locked python "$WORKDIR/benchmarks/smoke_test.py" --no-docker

(
  cd "$WORKDIR" &&
    PYTHONPATH="$WORKDIR" uv run --locked python -m benchmarks.run_scenarios \
      --tokens-path benchmarks/tokens.json \
      --out "$CAPABILITY_OUT_DIR" \
      --clients 1 \
      --messages 1 \
      --scenarios-arg TOKEN-BASELINE-JWT \
      --no-iperf3 \
      --no-tcpdump \
      --log-level INFO
)

(
  cd "$WORKDIR" &&
    PYTHONPATH="$WORKDIR" uv run --locked python -m benchmarks.run_scenarios \
      --tokens-path benchmarks/tokens.json \
      --out "$PARITY_OUT_DIR" \
      --clients 1 \
      --messages 1 \
      --scenarios-arg HTTP-LATENCY-200MS-PARITY-JWT \
      --no-iperf3 \
      --no-tcpdump \
      --log-level INFO
)

# Clean up generated files to prevent pre-commit hook from failing
rm -f "$WORKDIR/benchmarks/tokens.json"
