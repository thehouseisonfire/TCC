#!/usr/bin/env python3
import argparse
import atexit
import os
import shlex
import shutil
import subprocess
import sys
from typing import List

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORKDIR = os.path.join(SCRIPT_DIR, "mqtt-auth-biscuit")


def require_cmd(cmd: str) -> None:
    if shutil.which(cmd) is None:
        raise SystemExit(f"Missing required command: {cmd}")


def check_paho() -> None:
    try:
        import paho.mqtt.client  # noqa: F401
    except Exception as exc:
        raise SystemExit(
            "Missing dependency 'paho-mqtt'. Install it with: pip install paho-mqtt"
        ) from exc


def detect_compose_bin(override: str | None) -> List[str]:
    if override:
        return shlex.split(override)
    if shutil.which("docker") and subprocess.run(
        ["docker", "compose", "version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    raise SystemExit("Docker Compose not found. Install docker compose or docker-compose.")


def compose_args(compose_files: List[str]) -> List[str]:
    args: List[str] = []
    for file in compose_files:
        args.extend(["-f", file])
    return args


def run(cmd: List[str], cwd: str | None = None, env: dict | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run build, token generation, and scenario benchmarks.")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-tokens", action="store_true")
    parser.add_argument("--scenarios")
    parser.add_argument("--clients")
    parser.add_argument("--messages")
    parser.add_argument("--qos")
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--tls-insecure", action="store_true")
    parser.add_argument("--tls-ca-file")
    parser.add_argument("--token-issuer-no-default-roles", action="store_true")
    parser.add_argument("--biscuit-base64url", action="store_true")
    parser.add_argument("--token-refresh-codes")
    parser.add_argument("--compose-bin")
    parser.add_argument("--no-cleanup", action="store_true")
    args = parser.parse_args()

    if not os.path.isdir(WORKDIR):
        raise SystemExit(f"Expected mqtt-auth-biscuit directory at {WORKDIR}")

    require_cmd("cargo")
    check_paho()

    compose_bin = detect_compose_bin(args.compose_bin)
    compose_files = ["docker/docker-compose.yml"]
    if args.tls:
        compose_files.append("docker/docker-compose.tls.yml")

    def cleanup() -> None:
        if args.no_cleanup:
            return
        print("🧹 Cleaning up Docker services...")
        cmd = compose_bin + compose_args(compose_files) + ["down"]
        subprocess.run(cmd, cwd=WORKDIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    atexit.register(cleanup)

    print(f"✅ Using docker compose: {' '.join(compose_bin)}")

    if not args.skip_build:
        print("🔧 Building plugin...")
        run(["cargo", "build", "--release", "-p", "mosquitto-auth-biscuit"], cwd=WORKDIR)
    else:
        print("⚠️  Skipping build (per --skip-build)")

    if not args.skip_tokens:
        print("🔑 Generating tokens...")
        run(["cargo", "run", "-p", "gen-tokens"], cwd=WORKDIR)
    else:
        print("⚠️  Skipping token generation (per --skip-tokens)")

    run_args: List[str] = []
    if args.scenarios:
        run_args += ["--scenarios", args.scenarios]
    if args.clients:
        run_args += ["--clients", args.clients]
    if args.messages:
        run_args += ["--messages", args.messages]
    if args.qos:
        run_args += ["--qos", args.qos]
    if args.tls:
        run_args.append("--tls")
    if args.tls_insecure:
        run_args.append("--tls-insecure")
    if args.tls_ca_file:
        run_args += ["--tls-ca-file", args.tls_ca_file]
    if args.token_issuer_no_default_roles:
        run_args.append("--token-issuer-no-default-roles")
    if args.biscuit_base64url:
        run_args.append("--biscuit-base64url")
    if args.token_refresh_codes:
        run_args += ["--token-refresh-codes", args.token_refresh_codes]

    print("🚀 Running scenarios...")
    env = os.environ.copy()
    env["DOCKER_COMPOSE_BIN"] = " ".join(compose_bin)
    run(["python3", "benchmarks/run_scenarios.py", *run_args], cwd=WORKDIR, env=env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
