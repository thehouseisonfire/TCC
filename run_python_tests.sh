#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$SCRIPT_DIR/mqtt-auth-biscuit"
COMPOSE_BIN=${DOCKER_COMPOSE_BIN:-"docker compose"}
COMPOSE_FILES=("-f" "$WORKDIR/docker/docker-compose.yml")
SERVICES=(mosquitto authz netem metrics-collector cadvisor token-issuer)

cleanup() {
  $COMPOSE_BIN "${COMPOSE_FILES[@]}" down
}
trap cleanup EXIT

$COMPOSE_BIN "${COMPOSE_FILES[@]}" up --build -d "${SERVICES[@]}"

(cd "$WORKDIR" && cargo run -p gen-tokens --bin gen-tokens)

PYTHONPATH="$WORKDIR" \
  pytest "$WORKDIR/benchmarks/test_qos_distribution.py" \
  "$WORKDIR/benchmarks/test_resource_snapshot.py"

PYTHONPATH="$WORKDIR" python3 "$WORKDIR/benchmarks/smoke_test.py" --no-docker

# Clean up generated files to prevent pre-commit hook from failing
rm -f "$WORKDIR/benchmarks/tokens.json"
