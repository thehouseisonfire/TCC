import argparse
import json
import os
import ssl
import subprocess
import time
import urllib.request


def _compose_bin():
    return os.environ.get("DOCKER_COMPOSE_BIN", "docker compose")


def _compose(args: list[str], compose_files: list[str]):
    file_args: list[str] = []
    for path in compose_files:
        file_args.extend(["-f", path])
    cmd = _compose_bin().split(" ") + file_args + args
    subprocess.check_call(cmd, cwd=os.path.dirname(os.path.dirname(__file__)))


def _ssl_context(ca_file: str | None, insecure: bool) -> ssl.SSLContext | None:
    if not insecure and not ca_file:
        return None
    ctx = ssl.create_default_context(cafile=ca_file)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_get(url: str, ca_file: str | None, insecure: bool):
    ctx = _ssl_context(ca_file, insecure)
    with urllib.request.urlopen(url, timeout=5, context=ctx) as resp:
        return resp.status, resp.read().decode("utf-8")


def _health_check(name: str, base_url: str, ca_file: str | None, insecure: bool):
    status, body = _http_get(base_url.rstrip("/") + "/health", ca_file, insecure)
    if status != 200:
        raise SystemExit(f"{name} health check failed: HTTP {status}")
    try:
        payload = json.loads(body)
        if not payload.get("ok"):
            raise SystemExit(f"{name} health check failed: {payload}")
    except json.JSONDecodeError:
        raise SystemExit(f"{name} health check returned non-JSON body")


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
        "python3",
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
    out = subprocess.check_output(cmd, cwd=os.path.dirname(os.path.dirname(__file__)))
    return json.loads(out.decode("utf-8"))


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
        "python3",
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
    out = subprocess.check_output(cmd, cwd=os.path.dirname(os.path.dirname(__file__)))
    return json.loads(out.decode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tokens", default="benchmarks/tokens.json")
    ap.add_argument("--clients", type=int, default=1)
    ap.add_argument("--messages", type=int, default=1)
    ap.add_argument("--no-docker", action="store_true")
    ap.add_argument("--skip-mqtt5-auth", action="store_true")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--tls-ca-file")
    ap.add_argument("--tls-insecure", action="store_true")
    ap.add_argument("--authz-base", help="Override Authz base URL")
    ap.add_argument("--issuer-base", help="Override Token Issuer base URL")
    ap.add_argument("--mqtt-host", help="Override MQTT broker host")
    args = ap.parse_args()

    repo_root = os.path.dirname(os.path.dirname(__file__))
    tls_ca = args.tls_ca_file or ("docker/tls/ca.pem" if args.tls else None)
    if args.tls and tls_ca and not os.path.exists(os.path.join(repo_root, tls_ca)):
        raise SystemExit(
            f"TLS enabled but CA file not found at {tls_ca}. Run docker/tls/generate_certs.sh"
        )

    compose_files = ["docker/docker-compose.yml"]
    if args.tls:
        compose_files.append("docker/docker-compose.tls.yml")

    if not args.no_docker:
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

    tokens_path = os.path.join(repo_root, args.tokens)
    with open(tokens_path, "r", encoding="utf-8") as f:
        tokens = json.load(f)

    authz_base = args.authz_base or (
        "https://localhost:8443" if args.tls else "http://localhost:8081"
    )
    issuer_base = args.issuer_base or (
        "https://localhost:8444" if args.tls else "http://localhost:8082"
    )
    mqtt_host = args.mqtt_host or "localhost"
    mqtt_port = 8883 if args.tls else 1883

    _health_check("authz", authz_base, tls_ca, args.tls_insecure)
    _health_check("token-issuer", issuer_base, tls_ca, args.tls_insecure)

    results = {
        "tls": {
            "enabled": args.tls,
            "ca_file": tls_ca,
            "insecure": args.tls_insecure,
        },
        "loadgen": {},
    }

    results["loadgen"]["jwt"] = _run_loadgen(
        "jwt",
        tokens["jwt"],
        mqtt_host,
        mqtt_port,
        args.clients,
        args.messages,
        args.tls,
        tls_ca,
        args.tls_insecure,
    )
    results["loadgen"]["biscuit"] = _run_loadgen(
        "biscuit",
        tokens["biscuit"],
        mqtt_host,
        mqtt_port,
        args.clients,
        args.messages,
        args.tls,
        tls_ca,
        args.tls_insecure,
    )

    if not args.skip_mqtt5_auth:
        results["mqtt5_auth"] = _run_mqtt5_auth(
            mqtt_host,
            mqtt_port,
            tokens.get("jwt_short", tokens["jwt"]),
            tokens["jwt"],
            args.tls,
            tls_ca,
            args.tls_insecure,
        )

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
