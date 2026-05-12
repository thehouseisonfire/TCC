import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _resolve_rust_helper(binary: str) -> list[str]:
    env_name = f"MQTT_AUTH_BISCUIT_{binary.upper().replace('-', '_')}"
    if override := os.environ.get(env_name):
        return [override]
    for profile in ("release", "debug"):
        candidate = REPO_ROOT / "target" / profile / binary
        if candidate.exists():
            return [str(candidate)]
    cargo = shutil.which("cargo")
    if cargo is None:
        raise SystemExit(f"Missing required command: cargo (needed to run {binary})")
    return [cargo, "run", "--locked", "-p", "gen-tokens", "--bin", binary, "--"]


def main() -> None:
    completed = subprocess.run(
        _resolve_rust_helper("mqtt-auth-client") + sys.argv[1:],
        cwd=REPO_ROOT,
        check=False,
        text=True,
    )
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
