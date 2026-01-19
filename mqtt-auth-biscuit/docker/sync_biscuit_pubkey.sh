#!/usr/bin/env bash
set -euo pipefail

TOKENS_JSON="${1:-/home/eagle/TCC2/mqtt-auth-biscuit/benchmarks/tokens.json}"
MOSQUITTO_CONF="${2:-/home/eagle/TCC2/mqtt-auth-biscuit/docker/mosquitto.conf}"

if [[ ! -f "$TOKENS_JSON" ]]; then
  echo "tokens.json not found: $TOKENS_JSON" >&2
  exit 1
fi

if [[ ! -f "$MOSQUITTO_CONF" ]]; then
  echo "mosquitto.conf not found: $MOSQUITTO_CONF" >&2
  exit 1
fi

SUDO_CMD=()
if [[ ! -w "$MOSQUITTO_CONF" ]]; then
  if [[ "${SYNC_USE_SUDO:-0}" == "1" ]]; then
    SUDO_CMD=(sudo -E)
  else
    echo "mosquitto.conf not writable: $MOSQUITTO_CONF" >&2
    echo "Re-run with SYNC_USE_SUDO=1 if sudo is allowed." >&2
    exit 1
  fi
fi

TOKENS_JSON="$TOKENS_JSON" MOSQUITTO_CONF="$MOSQUITTO_CONF" "${SUDO_CMD[@]}" python3 - <<'PY'
import json
import os
import pathlib
import sys

tokens_path = pathlib.Path(os.environ["TOKENS_JSON"])
conf_path = pathlib.Path(os.environ["MOSQUITTO_CONF"])

with tokens_path.open("r", encoding="utf-8") as f:
    data = json.load(f)

pubkey = data.get("biscuit_root_key_hex")
if not pubkey:
    print("biscuit_root_key_hex missing in tokens.json", file=sys.stderr)
    sys.exit(1)

lines = conf_path.read_text(encoding="utf-8").splitlines()
key_line = f"plugin_opt_biscuit_root_key_hex {pubkey}"
updated = False

for idx, line in enumerate(lines):
    if line.strip().startswith("plugin_opt_biscuit_root_key_hex "):
        lines[idx] = key_line
        updated = True
        break

if not updated:
    lines.append(key_line)

conf_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Updated {conf_path} with biscuit_root_key_hex")
PY
