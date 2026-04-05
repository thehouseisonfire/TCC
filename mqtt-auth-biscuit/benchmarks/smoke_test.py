import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import typer

from benchmarks.logging_utils import get_logger, setup_logging

REPO_ROOT = Path(__file__).resolve().parents[1]
RAW_BISCUIT_MARKER = "b64:"


def _compose_bin():
    return os.environ.get("DOCKER_COMPOSE_BIN", "docker compose")


def _compose(args: list[str], compose_files: list[str]):
    file_args: list[str] = []
    for path in compose_files:
        file_args.extend(["-f", path])
    cmd = _compose_bin().split(" ") + file_args + args
    subprocess.check_call(cmd, cwd=REPO_ROOT)


logger = get_logger(__name__)
app = typer.Typer(add_completion=False)


def _python_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    repo_pythonpath = str(REPO_ROOT)
    current_pythonpath = env.get("PYTHONPATH")
    if current_pythonpath:
        paths = current_pythonpath.split(os.pathsep)
        if repo_pythonpath not in paths:
            env["PYTHONPATH"] = os.pathsep.join([repo_pythonpath, current_pythonpath])
    else:
        env["PYTHONPATH"] = repo_pythonpath
    return env


def _http_client(
    ca_file: str | None,
    insecure: bool,
    h2_prior_knowledge: bool = False,
) -> httpx.Client:
    verify: bool | str = True
    if insecure:
        verify = False
    elif ca_file:
        verify = ca_file
    transport = httpx.HTTPTransport(http1=False, http2=True)
    return httpx.Client(verify=verify, timeout=5.0, transport=transport)


def _http_get(
    url: str,
    ca_file: str | None,
    insecure: bool,
    h2_prior_knowledge: bool = False,
):
    with _http_client(ca_file, insecure, h2_prior_knowledge=h2_prior_knowledge) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.status_code, resp.text


def _health_check(name: str, base_url: str, ca_file: str | None, insecure: bool):
    status, body = _http_get(
        base_url.rstrip("/") + "/health",
        ca_file,
        insecure,
        h2_prior_knowledge=True,
    )
    if status != 200:
        raise SystemExit(f"{name} health check failed: HTTP {status}")
    try:
        payload = json.loads(body)
        if not payload.get("ok"):
            raise SystemExit(f"{name} health check failed: {payload}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{name} health check returned non-JSON body") from exc


def _run_loadgen(
    username: str,
    password: str,
    host: str,
    port: int,
    clients: int,
    messages: int,
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
):
    cmd = [
        sys.executable,
        "benchmarks/loadgen.py",
        "--host",
        host,
        "--port",
        str(port),
        "--username",
        username,
        "--password",
        password,
        "--clients",
        str(clients),
        "--messages",
        str(messages),
        "--topic",
        "sensors/{client_id}/temp",
        "--qos",
        "1",
        "--message-size",
        "0",
        "--json",
    ]
    if tls_enabled:
        cmd.append("--tls")
    if tls_ca_file:
        cmd.extend(["--tls-ca-file", tls_ca_file])
    if tls_insecure:
        cmd.append("--tls-insecure")
    out = subprocess.check_output(
        cmd,
        cwd=REPO_ROOT,
        text=True,
        env=_python_subprocess_env(),
    )
    return json.loads(out)


def _run_mqtt5_auth(
    host: str,
    port: int,
    token1: str,
    token2: str,
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
):
    cmd = [
        sys.executable,
        "benchmarks/mqtt_auth_client.py",
        "--host",
        host,
        "--port",
        str(port),
        "--auth-method",
        "token",
        "--token1",
        token1,
        "--token2",
        token2,
    ]
    if tls_enabled:
        cmd.append("--tls")
    if tls_ca_file:
        cmd.extend(["--tls-ca-file", tls_ca_file])
    if tls_insecure:
        cmd.append("--tls-insecure")
    out = subprocess.check_output(
        cmd,
        cwd=REPO_ROOT,
        text=True,
        env=_python_subprocess_env(),
    )
    return json.loads(out)


@app.command()
def main(
    tokens: str = "benchmarks/tokens.json",
    clients: int = 1,
    messages: int = 1,
    no_docker: bool = False,
    skip_mqtt5_auth: bool = False,
    tls: bool = False,
    tls_ca_file: str | None = None,
    tls_insecure: bool = False,
    authz_base: str | None = None,
    issuer_base: str | None = None,
    mqtt_host: str | None = None,
    log_level: str = typer.Option("INFO", "--log-level"),
):
    setup_logging(log_level)

    tls_ca = tls_ca_file or ("docker/tls/ca.pem" if tls else None)
    if tls and tls_ca and not (REPO_ROOT / tls_ca).exists():
        raise SystemExit(
            f"TLS enabled but CA file not found at {tls_ca}. Run docker/tls/generate_certs.sh"
        )

    compose_files = ["docker/docker-compose.yml"]
    if tls:
        compose_files.append("docker/docker-compose.tls.yml")

    if not no_docker:
        _compose(
            [
                "up",
                "--build",
                "-d",
                "mosquitto",
                "authz",
                "netem",
                "metrics-collector",
                "cadvisor",
                "token-issuer",
            ],
            compose_files,
        )
        time.sleep(1)

    tokens_path = REPO_ROOT / tokens
    with tokens_path.open(encoding="utf-8") as f:
        tokens_data: dict[str, object] = json.load(f)

    authz_base = authz_base or ("https://localhost:8443" if tls else "http://localhost:8081")
    issuer_base = issuer_base or ("https://localhost:8444" if tls else "http://localhost:8082")
    mqtt_host = mqtt_host or "localhost"
    mqtt_port = 8883 if tls else 1883

    _health_check("authz", authz_base, tls_ca, tls_insecure)
    _health_check("token-issuer", issuer_base, tls_ca, tls_insecure)

    results = {
        "tls": {
            "enabled": tls,
            "ca_file": tls_ca,
            "insecure": tls_insecure,
        },
        "loadgen": {},
    }

    results["loadgen"]["jwt"] = _run_loadgen(
        "jwt",
        str(tokens_data["jwt"]),
        mqtt_host,
        mqtt_port,
        clients,
        messages,
        tls,
        tls_ca,
        tls_insecure,
    )
    results["loadgen"]["biscuit"] = _run_loadgen(
        "biscuit",
        f"{RAW_BISCUIT_MARKER}{tokens_data['biscuit']}",
        mqtt_host,
        mqtt_port,
        clients,
        messages,
        tls,
        tls_ca,
        tls_insecure,
    )

    if not skip_mqtt5_auth:
        results["mqtt5_auth"] = _run_mqtt5_auth(
            mqtt_host,
            mqtt_port,
            str(tokens_data["jwt"]),
            str(tokens_data["jwt"]),
            tls,
            tls_ca,
            tls_insecure,
        )

    typer.echo(json.dumps(results, indent=2))


if __name__ == "__main__":
    app()
