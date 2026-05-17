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
REQUIRE_DOCKER_BRIDGE="${PYTHON_TESTS_REQUIRE_DOCKER_BRIDGE:-${CI:-0}}"
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

docker_bridge_available() {
  local output
  if ! output="$(docker run --rm alpine:3.23.3 true 2>&1)"; then
    cat >&2 <<EOF
Docker bridge networking is unavailable; skipping Docker-backed benchmark
smoke tests in this local pre-commit run.

Docker reported:
$output
EOF
    if [ -r /proc/config.gz ] && zgrep -q '^CONFIG_VETH=m' /proc/config.gz; then
      if [ ! -d "/usr/lib/modules/$(uname -r)" ] && [ ! -d "/lib/modules/$(uname -r)" ]; then
        cat >&2 <<EOF

The running kernel is $(uname -r), but its module directory is missing.
The veth driver is modular on this kernel, so Docker cannot attach
containers to bridge networks until the matching kernel modules are
installed or the machine is rebooted into an installed kernel.
EOF
      fi
    fi
    return 1
  fi
  return 0
}

run_non_docker_python_tests() {
  PYTHONPATH="$WORKDIR" \
    uv run --locked --group dev pytest \
    "$WORKDIR/benchmarks/test_loadgen_wrapper.py" \
    "$WORKDIR/benchmarks/test_runner_startup_readiness.py" \
    "$WORKDIR/benchmarks/test_packet_analysis.py" \
    "$WORKDIR/benchmarks/test_scenario_semantics.py"
}

if [ -f "$TOKEN_FILE" ]; then
  cp "$TOKEN_FILE" "$TOKEN_BACKUP"
  TOKEN_FILE_EXISTED=1
fi

if ! docker_bridge_available; then
  run_non_docker_python_tests
  if [ "$REQUIRE_DOCKER_BRIDGE" = "1" ] || [ "$REQUIRE_DOCKER_BRIDGE" = "true" ]; then
    echo "Docker bridge networking is required in this environment." >&2
    exit 1
  fi
  exit 0
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
