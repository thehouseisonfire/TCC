#!/usr/bin/env python3
import atexit
import os
import shlex
import shutil
import subprocess
import sys
import time

import typer

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORKDIR = os.path.join(SCRIPT_DIR, "mqtt-auth-biscuit")
BENCHMARKS_DIR = os.path.join(WORKDIR, "benchmarks")
if WORKDIR not in sys.path:
    sys.path.append(WORKDIR)

from benchmarks.logging_utils import get_logger, setup_logging  # noqa: E402

logger = get_logger(__name__)
app = typer.Typer(add_completion=False)


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


def detect_compose_bin(override: str | None) -> list[str]:
    if override:
        return shlex.split(override)
    if (
        shutil.which("docker")
        and subprocess.run(
            ["docker", "compose", "version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    ):
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    raise SystemExit("Docker Compose not found. Install docker compose or docker-compose.")


def compose_args(compose_files: list[str]) -> list[str]:
    args: list[str] = []
    for file in compose_files:
        args.extend(["-f", file])
    return args


def run(cmd: list[str], cwd: str | None = None, env: dict | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


@app.command()
def main(
    skip_build: bool = False,
    skip_tokens: bool = False,
    scenarios: str | None = None,
    clients: str | None = None,
    messages: str | None = None,
    qos: str | None = None,
    tls: bool = False,
    tls_insecure: bool = False,
    tls_ca_file: str | None = None,
    token_issuer_no_default_roles: bool = False,
    biscuit_base64url: bool = False,
    token_refresh_codes: str | None = None,
    compose_bin: str | None = None,
    no_cleanup: bool = False,
    log_level: str = typer.Option("INFO", "--log-level"),
) -> None:
    setup_logging(log_level)

    if not os.path.isdir(WORKDIR):
        raise SystemExit(f"Expected mqtt-auth-biscuit directory at {WORKDIR}")

    require_cmd("cargo")
    check_paho()

    compose_cmd = detect_compose_bin(compose_bin)
    compose_files = ["docker/docker-compose.yml"]
    if tls:
        compose_files.append("docker/docker-compose.tls.yml")

    def cleanup() -> None:
        if no_cleanup:
            return
        logger.info("Cleaning up Docker services...")
        cmd = compose_cmd + compose_args(compose_files) + ["down"]
        subprocess.run(cmd, cwd=WORKDIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    atexit.register(cleanup)

    logger.info("Using docker compose: %s", " ".join(compose_cmd))

    if not skip_build:
        logger.info("Building plugin...")
        run(["cargo", "build", "--release", "-p", "mosquitto-auth-biscuit"], cwd=WORKDIR)
    else:
        logger.info("Skipping build (per --skip-build)")

    if not skip_tokens:
        logger.info("Generating tokens...")
        token_env = os.environ.copy()
        token_env["GEN_TOKENS_FIXED_NOW"] = str(int(time.time()))
        run(
            ["cargo", "run", "-p", "gen-tokens", "--bin", "gen-tokens"],
            cwd=WORKDIR,
            env=token_env,
        )
    else:
        logger.info("Skipping token generation (per --skip-tokens)")

    run_args: list[str] = []
    if scenarios:
        run_args += ["--scenarios-arg", scenarios]
    if clients:
        run_args += ["--clients", clients]
    if messages:
        run_args += ["--messages", messages]
    if qos:
        run_args += ["--qos", qos]
    if tls:
        run_args.append("--tls")
    if tls_insecure:
        run_args.append("--tls-insecure")
    if tls_ca_file:
        run_args += ["--tls-ca-file", tls_ca_file]
    if token_issuer_no_default_roles:
        run_args.append("--token-issuer-no-default-roles")
    if biscuit_base64url:
        run_args.append("--biscuit-base64url")
    if token_refresh_codes:
        run_args += ["--token-refresh-codes", token_refresh_codes]

    logger.info("Running scenarios...")
    env = os.environ.copy()
    env["DOCKER_COMPOSE_BIN"] = " ".join(compose_cmd)
    run(["python3", "benchmarks/run_scenarios.py", *run_args], cwd=WORKDIR, env=env)


if __name__ == "__main__":
    app()
