#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$SCRIPT_DIR/mqtt-auth-biscuit"
COMPOSE_BIN=${DOCKER_COMPOSE_BIN:-"docker compose"}
COMPOSE_FILES=("-f" "$WORKDIR/docker/docker-compose.yml")
SERVICES=(mosquitto authz netem metrics-collector cadvisor token-issuer)
CAPABILITY_OUT_DIR=$(mktemp -d /tmp/python-tests-capability.XXXXXX)
PARITY_OUT_DIR=$(mktemp -d /tmp/python-tests-parity.XXXXXX)
TOKEN_BACKUP=$(mktemp /tmp/python-tests-tokens.XXXXXX)
TOKEN_FILE="$WORKDIR/benchmarks/tokens.json"
TOKEN_FILE_EXISTED=0
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-python-tests}"
export RESOURCE_SNAPSHOT_COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME"

cleanup() {
  $COMPOSE_BIN "${COMPOSE_FILES[@]}" down
  if [ "$TOKEN_FILE_EXISTED" -eq 1 ]; then
    cp "$TOKEN_BACKUP" "$TOKEN_FILE"
  else
    rm -f "$TOKEN_FILE"
  fi
  rm -rf "$CAPABILITY_OUT_DIR" "$PARITY_OUT_DIR" "$TOKEN_BACKUP"
}
trap cleanup EXIT

if [ -f "$TOKEN_FILE" ]; then
  cp "$TOKEN_FILE" "$TOKEN_BACKUP"
  TOKEN_FILE_EXISTED=1
fi

$COMPOSE_BIN "${COMPOSE_FILES[@]}" up --build -d "${SERVICES[@]}"

(cd "$WORKDIR" && cargo run --locked -p gen-tokens --bin gen-tokens)

PYTHONPATH="$WORKDIR" \
  uv run --locked --group dev pytest \
  "$WORKDIR/benchmarks/test_loadgen_wrapper.py" \
  "$WORKDIR/benchmarks/test_runner_startup_readiness.py" \
  "$WORKDIR/benchmarks/test_resource_snapshot.py" \
  "$WORKDIR/benchmarks/test_packet_analysis.py" \
  "$WORKDIR/benchmarks/test_scenario_semantics.py"

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
