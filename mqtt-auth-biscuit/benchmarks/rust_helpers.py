"""Resolution of benchmark helper binaries without accepting stale build artifacts."""

from __future__ import annotations

import os
import shutil


def resolve_rust_helper(binary: str) -> list[str]:
    """Return an explicit override or a Cargo command that freshness-checks the binary."""
    env_name = f"MQTT_AUTH_BISCUIT_{binary.upper().replace('-', '_')}"
    if override := os.environ.get(env_name):
        return [override]
    cargo = shutil.which("cargo")
    if cargo is None:
        raise SystemExit(f"Missing required command: cargo (needed to run {binary})")
    return [cargo, "run", "--locked", "-p", "gen-tokens", "--bin", binary, "--"]
