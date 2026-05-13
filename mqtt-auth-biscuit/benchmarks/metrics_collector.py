import base64
import json
import os
import shutil
import statistics
import subprocess
from pathlib import Path

import typer

from benchmarks.logging_utils import get_logger, setup_logging

logger = get_logger(__name__)
app = typer.Typer(add_completion=False)
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


def _decode_biscuit_token(token: str) -> str:
    padding = "=" * (-len(token) % 4)
    base64.urlsafe_b64decode(token + padding)
    return "b64:" + token


def _run_loadgen(
    host: str,
    port: int,
    username: str,
    password: str,
    topic: str,
    message_count: int,
    qos: int,
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
) -> list[float]:
    cmd = [
        *_resolve_rust_helper("mqtt-loadgen"),
        "--host",
        host,
        "--port",
        str(port),
        "--username",
        username,
        "--password",
        password,
        "--topic",
        topic,
        "--clients",
        "1",
        "--messages",
        str(message_count),
        "--qos",
        str(qos),
        "--json",
    ]
    if tls_enabled:
        cmd.append("--tls")
    if tls_ca_file:
        cmd.extend(["--tls-ca-file", tls_ca_file])
    if tls_insecure:
        cmd.append("--tls-insecure")
    completed = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    raw_publish_ms = payload.get("raw_publish_ms")
    if isinstance(raw_publish_ms, list):
        return [float(value) / 1000.0 for value in raw_publish_ms]
    publish = payload.get("publish") or {}
    count = int(publish.get("count") or 0)
    mean = float(publish.get("mean_ms") or 0.0)
    return [mean / 1000.0] * count


@app.command()
def main(
    host: str = "localhost",
    port: int = 1883,
    tls: bool = False,
    tls_ca_file: str | None = None,
    tls_insecure: bool = False,
    messages: int = 100,
    qos: int = 1,
    log_level: str = typer.Option("INFO", "--log-level"),
):
    setup_logging(log_level)
    with open("benchmarks/tokens.json", encoding="utf-8") as f:
        tokens = json.load(f)

    results = {}
    for token_type in ["jwt", "biscuit"]:
        logger.info("Benchmarking %s...", token_type)
        password = tokens[token_type]
        if token_type == "biscuit":
            password = _decode_biscuit_token(password)
        latencies = _run_loadgen(
            host,
            port,
            token_type,
            password,
            "sensors/client_1/temp",
            message_count=messages,
            qos=qos,
            tls_enabled=tls,
            tls_ca_file=tls_ca_file,
            tls_insecure=tls_insecure,
        )
        if latencies:
            results[token_type] = {
                "median": statistics.median(latencies) * 1000,
                "mean": statistics.mean(latencies) * 1000,
                "stdev": statistics.stdev(latencies) * 1000 if len(latencies) > 1 else 0,
            }
        else:
            results[token_type] = {"median": 0, "mean": 0, "stdev": 0}

    with open("benchmarks/results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    logger.info("Results saved to benchmarks/results.json")


if __name__ == "__main__":
    app()
