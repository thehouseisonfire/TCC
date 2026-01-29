import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request


def _read_tokens(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _compose_bin():
    return os.environ.get("DOCKER_COMPOSE_BIN", "docker compose")


def _compose(
    args: list[str],
    extra_env: dict | None = None,
    compose_files: list[str] | None = None,
):
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    files = compose_files or ["docker/docker-compose.yml"]
    file_args: list[str] = []
    for path in files:
        file_args.extend(["-f", path])
    cmd = _compose_bin().split(" ") + file_args + args
    subprocess.check_call(cmd, cwd=os.path.dirname(os.path.dirname(__file__)), env=env)


def _ssl_context(ca_file: str | None, insecure: bool) -> ssl.SSLContext | None:
    if not insecure and not ca_file:
        return None
    ctx = ssl.create_default_context(cafile=ca_file)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _authz_config(
    authz_url: str,
    delay_ms: int | None = None,
    fail_mode: str | None = None,
    fail_rate: float | None = None,
    ca_file: str | None = None,
    insecure: bool = False,
):
    body = {}
    if delay_ms is not None:
        body["delay_ms"] = delay_ms
    if fail_mode is not None:
        body["fail_mode"] = fail_mode
    if fail_rate is not None:
        body["fail_rate"] = fail_rate

    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        authz_url.rstrip("/") + "/config",
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    ctx = _ssl_context(ca_file, insecure)
    with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


# Prometheus query templates
CURRENT_DOCKER_COMPOSE_CPU_QUERY = 'sum(rate(container_cpu_usage_seconds_total{container_label_com_docker_compose_service="mosquitto"}[30s]))'
CURRENT_DOCKER_COMPOSE_MEM_QUERY = 'max(container_memory_working_set_bytes{container_label_com_docker_compose_service="mosquitto"})'


def _prom_query(base_url: str, query: str, ca_file: str | None, insecure: bool):
    url = (
        base_url.rstrip("/")
        + "/api/v1/query?query="
        + urllib.parse.quote(query, safe="")
    )
    ctx = _ssl_context(ca_file, insecure)
    with urllib.request.urlopen(url, timeout=5, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _resource_snapshot(
    base_url: str, ca_file: str | None, insecure: bool, cpu_query_type: str = "instant"
):
    """
    Capture resource snapshot from Prometheus.

    Args:
        base_url: Prometheus base URL
        ca_file: TLS CA file path
        insecure: Skip TLS verification
        cpu_query_type: "instant" for immediate values, "rate" for rate over time
    """
    import subprocess

    # Get mosquitto container ID dynamically
    try:
        result = subprocess.run(
            ["docker", "inspect", "docker-mosquitto-1", "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        container_id = result.stdout.strip()[
            :12
        ]  # Use first 12 chars for regex matching (Docker ID prefix convention)
    except Exception:
        # Fallback: try to find container by name in metrics
        container_id = "mosquitto"

    # Use container ID-based queries instead of Docker Compose labels
    if cpu_query_type == "rate":
        cpu_q = f'sum(rate(container_cpu_usage_seconds_total{{id=~".*{container_id}.*"}}[30s]))'
    else:  # instant (default)
        cpu_q = f'container_cpu_usage_seconds_total{{id=~".*{container_id}.*"}}'

    mem_q = f'max(container_memory_working_set_bytes{{id=~".*{container_id}.*"}})'

    snap = {
        "prometheus": {
            "cpu": _prom_query(base_url, cpu_q, ca_file, insecure),
            "memory": _prom_query(base_url, mem_q, ca_file, insecure),
        }
    }
    return snap


def _run_loadgen(
    tokens: dict,
    host: str,
    port: int,
    username: str,
    password: str,
    fanout_publisher_username: str | None,
    fanout_publisher_password: str | None,
    clients: int,
    messages: int,
    topic: str,
    mode: str | None,
    fanout_topic: str | None,
    qos: int,
    message_size: int,
    sync_connect: bool,
    token_issuer_url: str | None,
    token_issuer_kind: str | None,
    token_issuer_ttl: int | None,
    token_issuer_no_default_roles: bool,
    token_refresh_codes: str | None,
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
        topic,
        "--qos",
        str(qos),
        "--message-size",
        str(message_size),
        "--json",
    ]
    if sync_connect:
        cmd.append("--sync-connect")
    if mode:
        cmd.extend(["--mode", mode])
    if fanout_topic:
        cmd.extend(["--fanout-topic", fanout_topic])
    if fanout_publisher_username:
        cmd.extend(["--fanout-publisher-username", fanout_publisher_username])
    if fanout_publisher_password:
        cmd.extend(["--fanout-publisher-password", fanout_publisher_password])
    if token_issuer_url:
        cmd.extend(["--token-issuer-url", token_issuer_url])
    if token_issuer_kind:
        cmd.extend(["--token-issuer-kind", token_issuer_kind])
    if token_issuer_ttl is not None:
        cmd.extend(["--token-issuer-ttl", str(token_issuer_ttl)])
    if token_issuer_no_default_roles:
        cmd.append("--token-issuer-no-default-roles")
    if token_refresh_codes:
        cmd.extend(["--token-refresh-codes", token_refresh_codes])
    if tls_enabled:
        cmd.append("--tls")
    if tls_ca_file:
        cmd.extend(["--tls-ca-file", tls_ca_file])
    if tls_insecure:
        cmd.append("--tls-insecure")

    out = subprocess.check_output(cmd, cwd=os.path.dirname(os.path.dirname(__file__)))
    return json.loads(out.decode("utf-8"))


def _apply_dynsec_config(source_path: str):
    repo_root = os.path.dirname(os.path.dirname(__file__))
    src = os.path.join(repo_root, source_path)
    dest = os.path.join(repo_root, "docker", "dynamic-security.json")
    shutil.copyfile(src, dest)
    tls_dest = os.path.join(repo_root, "docker", "tls", "dynamic-security.json")
    if os.path.exists(os.path.dirname(tls_dest)):
        shutil.copyfile(src, tls_dest)


def _expand_tls_matrix(scenarios: dict[str, dict]) -> dict[str, dict]:
    expanded: dict[str, dict] = {}
    for scenario_id, scenario in scenarios.items():
        expanded[scenario_id] = scenario
        if scenario_id.endswith("-TLS"):
            continue
        tls_scenario = scenario.copy()
        tls_scenario["tls"] = True
        expanded[f"{scenario_id}-TLS"] = tls_scenario
    return expanded


def _write_result(out_dir: str, name: str, payload: dict):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return path


def _ensure_paho_mqtt():
    try:
        import paho.mqtt.client as _  # noqa: F401
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Missing dependency 'paho-mqtt'. Install it with: pip install paho-mqtt"
        ) from exc


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
    p = argparse.ArgumentParser()
    p.add_argument("--tokens", default="benchmarks/tokens.json")
    p.add_argument("--out", default="benchmarks/results")
    p.add_argument("--clients", type=int, default=50)
    p.add_argument("--messages", type=int, default=20)
    p.add_argument("--qos", type=int, default=1)
    p.add_argument("--scenarios", help="Comma-separated list of scenario IDs to run")
    p.add_argument("--token-issuer-no-default-roles", action="store_true")
    p.add_argument("--biscuit-base64url", action="store_true")
    p.add_argument(
        "--token-refresh-codes", default=os.environ.get("TOKEN_REFRESH_CODES")
    )
    p.add_argument(
        "--tls", action="store_true", help="Enable TLS for all supported services"
    )
    p.add_argument(
        "--tls-insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    p.add_argument("--tls-ca-file", help="CA bundle path for TLS verification")
    p.add_argument(
        "--summary-json",
        default="summary.json",
        help="Summary JSON filename (relative to --out)",
    )
    p.add_argument(
        "--summary-csv",
        default="summary.csv",
        help="Summary CSV filename (relative to --out)",
    )
    p.add_argument(
        "--no-summary-csv", action="store_true", help="Disable CSV summary output"
    )
    args = p.parse_args()

    tokens = _read_tokens(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), args.tokens)
    )

    scenarios = []
    tls_enabled = args.tls
    tls_insecure = args.tls_insecure
    tls_ca = args.tls_ca_file or ("docker/tls/ca.pem" if tls_enabled else None)
    if (
        tls_enabled
        and tls_ca
        and not os.path.exists(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), tls_ca)
        )
    ):
        raise SystemExit(
            f"TLS enabled but CA file not found at {tls_ca}. Run docker/tls/generate_certs.sh"
        )
    if args.scenarios:
        scenario_ids = [s.strip() for s in args.scenarios.split(",")]
        # Define available scenarios mapping
        available_scenarios = {
            "BASE-01": {
                "mosquitto_conf": "./mosquitto_base.conf",
                "username": "",
                "password": "",
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-01": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "BIS-01": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "POLICY-COMPLEX-1": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "POLICY-COMPLEX-5": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit_5"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "POLICY-COMPLEX-25": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit_25"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "STATIC-ACL-JWT": {
                "mosquitto_conf": "./mosquitto_static.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "STATIC-ACL-BIS": {
                "mosquitto_conf": "./mosquitto_static.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "STATIC-ACL-FANOUT": {
                "mosquitto_conf": "./mosquitto_static.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "fanout_publisher_username": "jwt",
                "fanout_publisher_password": tokens["jwt"],
                "topic": "fanout/broadcast",
                "mode": "fanout",
                "fanout_topic": "fanout/broadcast",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "STATIC-ACL-FANOUT-BIS": {
                "mosquitto_conf": "./mosquitto_static.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "fanout_publisher_username": "biscuit",
                "fanout_publisher_password": tokens["biscuit"],
                "topic": "fanout/broadcast",
                "mode": "fanout",
                "fanout_topic": "fanout/broadcast",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-HTTP-200MS": {
                "mosquitto_conf": "./mosquitto_http.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 200, "fail_mode": "none"},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-HTTP-1000MS": {
                "mosquitto_conf": "./mosquitto_http.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 1000, "fail_mode": "none"},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "HYBRID-AUTHZ-DOWN": {
                "mosquitto_conf": "./mosquitto_hybrid.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 0, "fail_mode": "always"},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "MTU-200-JWT": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"mtu": 200},
                "message_size": 0,
            },
            "BIS-HTTP-200MS": {
                "mosquitto_conf": "./mosquitto_http.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 200, "fail_mode": "none"},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-HTTP-200MS-LOSS1": {
                "mosquitto_conf": "./mosquitto_http.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 200, "fail_mode": "rate", "fail_rate": 0.01},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-HTTP-200MS-LOSS5": {
                "mosquitto_conf": "./mosquitto_http.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 200, "fail_mode": "rate", "fail_rate": 0.05},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "MQTT5-REAUTH-JWT": {
                "mosquitto_conf": "./mosquitto.conf",
                "authz": None,
                "netem": {"clear": True},
                "mqtt5_auth": {"token1": tokens["jwt_short"], "token2": tokens["jwt"]},
            },
            "MQTT5-REAUTH-BISCUIT": {
                "mosquitto_conf": "./mosquitto.conf",
                "authz": None,
                "netem": {"clear": True},
                "mqtt5_auth": {
                    "token1": tokens["biscuit_short"],
                    "token2": tokens["biscuit"],
                },
            },
            "THUNDERING-HERD": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "restart_mosquitto": True,
                "sync_connect": True,
            },
            "DELEGATION-TEMP-ONLY": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit_delegated"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "LIFECYCLE-JWT-SHORT-RECONNECT": {
                "mosquitto_conf": "./mosquitto_shortcache.conf",
                "username": "jwt",
                "password": tokens["jwt_short"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "repeat": 3,
                "sleep_between": 2,
                "token_refresh": {"kind": "jwt", "ttl_seconds": 5},
            },
            "LIFECYCLE-BIS-SHORT-RECONNECT": {
                "mosquitto_conf": "./mosquitto_shortcache.conf",
                "username": "biscuit",
                "password": tokens["biscuit_short"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "repeat": 3,
                "sleep_between": 2,
                "token_refresh": {"kind": "biscuit", "ttl_seconds": 5},
            },
            "DYNSEC-BASE": {
                "mosquitto_conf": "./mosquitto_dynsec.conf",
                "username": "dynsec_client_1",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "dynsec_config": "docker/dynamic-security.json",
            },
            "DYNSEC-CHURN": {
                "mosquitto_conf": "./mosquitto_dynsec.conf",
                "username": "dynsec_client_1",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "repeat": 2,
                "sleep_between": 2,
                "dynsec_churn": [
                    "docker/dynamic-security.json",
                    "docker/dynamic-security-churn.json",
                ],
            },
            "DYNSEC-READ-FANOUT": {
                "mosquitto_conf": "./mosquitto_dynsec.conf",
                "username": "dynsec_client_1",
                "password": tokens["jwt"],
                "fanout_publisher_username": "dynsec_publisher",
                "fanout_publisher_password": tokens["jwt"],
                "topic": "fanout/broadcast",
                "mode": "fanout",
                "fanout_topic": "fanout/broadcast",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "dynsec_config": "docker/dynamic-security.json",
            },
            "DYNSEC-READ-FANOUT-CHURN": {
                "mosquitto_conf": "./mosquitto_dynsec.conf",
                "username": "dynsec_client_1",
                "password": tokens["jwt"],
                "fanout_publisher_username": "dynsec_publisher",
                "fanout_publisher_password": tokens["jwt"],
                "topic": "fanout/broadcast",
                "mode": "fanout",
                "fanout_topic": "fanout/broadcast",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "repeat": 2,
                "sleep_between": 2,
                "dynsec_churn": [
                    "docker/dynamic-security.json",
                    "docker/dynamic-security-fanout-churn.json",
                ],
            },
        }

        # Add dynamic MTU scenarios
        for mtu in [500, 1500, 9000]:
            available_scenarios[f"MTU-{mtu}-BIS-25"] = {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit_25"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"mtu": mtu},
                "message_size": 0,
            }
            available_scenarios[f"MTU-{mtu}-JWT"] = {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"mtu": mtu},
                "message_size": 0,
            }

        available_scenarios = _expand_tls_matrix(available_scenarios)

        # Select requested scenarios
        for scenario_id in scenario_ids:
            if scenario_id in available_scenarios:
                scenario = available_scenarios[scenario_id].copy()
                scenario["id"] = scenario_id
                scenarios.append(scenario)
            else:
                print(f"Warning: Unknown scenario '{scenario_id}', skipping")
    else:
        print(
            "No scenarios specified. Use --scenarios to specify which scenarios to run."
        )
        print("Available scenarios:")
        print(
            "BASE-01, JWT-01, BIS-01, POLICY-COMPLEX-1, POLICY-COMPLEX-5, POLICY-COMPLEX-25"
        )
        print("JWT-HTTP-200MS, JWT-HTTP-1000MS, HYBRID-AUTHZ-DOWN, MTU-200-JWT")
        print("BIS-HTTP-200MS, JWT-HTTP-200MS-LOSS1, JWT-HTTP-200MS-LOSS5")
        print(
            "MQTT5-REAUTH-JWT, MQTT5-REAUTH-BISCUIT, THUNDERING-HERD, DELEGATION-TEMP-ONLY"
        )
        print("LIFECYCLE-JWT-SHORT-RECONNECT, LIFECYCLE-BIS-SHORT-RECONNECT")
        print("MTU-500-BIS-25, MTU-1500-BIS-25, MTU-9000-BIS-25")
        print("MTU-500-JWT, MTU-1500-JWT, MTU-9000-JWT")
        print("DYNSEC-BASE, DYNSEC-CHURN, DYNSEC-READ-FANOUT")
        print("DYNSEC-READ-FANOUT-CHURN")
        print("STATIC-ACL-JWT, STATIC-ACL-BIS, STATIC-ACL-FANOUT, STATIC-ACL-FANOUT-BIS")
        print("Append -TLS to any scenario id for TLS variants.")
        return

    if any("mqtt5_auth" not in s for s in scenarios):
        _ensure_paho_mqtt()

    for s in scenarios:
        scenario_tls = bool(s.get("tls")) or tls_enabled
        mosq_conf = s["mosquitto_conf"]
        if scenario_tls:
            mosq_conf = mosq_conf.replace("./", "./tls/")
        extra_env = {"MOSQUITTO_CONF": mosq_conf}
        authz_base = (
            "https://localhost:8443" if scenario_tls else "http://localhost:8081"
        )
        prom_base = (
            "https://localhost:9443" if scenario_tls else "http://localhost:9090"
        )
        token_issuer_base = (
            "https://localhost:8444" if scenario_tls else "http://localhost:8082"
        )
        mqtt_host = "localhost"
        mqtt_port = 8883 if scenario_tls else 1883
        compose_files = ["docker/docker-compose.yml"]
        if scenario_tls:
            compose_files.append("docker/docker-compose.tls.yml")

        netem = s.get("netem")
        if netem:
            if netem.get("clear"):
                extra_env.update(
                    {
                        "NETEM_CLEAR": "1",
                        "NETEM_MTU": "",
                        "NETEM_DELAY_MS": "",
                        "NETEM_LOSS_PCT": "",
                        "NETEM_RATE_KBIT": "",
                    }
                )
            if "mtu" in netem:
                extra_env.update({"NETEM_CLEAR": "1", "NETEM_MTU": str(netem["mtu"])})
            if "delay_ms" in netem:
                extra_env.update(
                    {"NETEM_CLEAR": "1", "NETEM_DELAY_MS": str(netem["delay_ms"])}
                )
            if "loss_pct" in netem:
                extra_env.update(
                    {"NETEM_CLEAR": "1", "NETEM_LOSS_PCT": str(netem["loss_pct"])}
                )

        extra_env.update(
            {
                "TOKEN_ISSUER_ALLOW_DEFAULT_KEYS": os.environ.get(
                    "TOKEN_ISSUER_ALLOW_DEFAULT_KEYS", "1"
                ),
                "JWT_NO_DEFAULT_ROLES": "1"
                if args.token_issuer_no_default_roles
                else "0",
                "BISCUIT_BASE64URL": "1" if args.biscuit_base64url else "0",
            }
        )

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
            extra_env=extra_env,
            compose_files=compose_files,
        )
        time.sleep(1)

        if s.get("authz") is not None:
            cfg = s["authz"]
            _authz_config(
                authz_base,
                delay_ms=cfg.get("delay_ms"),
                fail_mode=cfg.get("fail_mode"),
                fail_rate=cfg.get("fail_rate"),
                ca_file=tls_ca,
                insecure=tls_insecure,
            )

        repeats = int(s.get("repeat", 1))
        token_len = len(s.get("password", "")) if s.get("password") else 0
        out_payload = {
            "scenario": s["id"],
            "token_len": token_len,
            "tls": {
                "enabled": scenario_tls,
                "ca_file": tls_ca,
                "insecure": tls_insecure,
            },
            "parity": {
                "token_issuer_no_default_roles": args.token_issuer_no_default_roles,
                "biscuit_base64url": args.biscuit_base64url,
                "token_refresh_codes": args.token_refresh_codes,
            },
            "runs": [],
        }

        if s.get("restart_mosquitto"):
            _compose(["restart", "mosquitto"], extra_env=extra_env)
            time.sleep(1)

        for idx in range(repeats):
            if s.get("dynsec_config"):
                _apply_dynsec_config(s["dynsec_config"])
            elif s.get("dynsec_churn"):
                churn_list = s["dynsec_churn"]
                _apply_dynsec_config(churn_list[idx % len(churn_list)])
            if s.get("mqtt5_auth") is not None:
                cfg = s["mqtt5_auth"]
                res = _run_mqtt5_auth(
                    mqtt_host,
                    mqtt_port,
                    cfg["token1"],
                    cfg["token2"],
                    scenario_tls,
                    tls_ca,
                    tls_insecure,
                )
            else:
                token_refresh = s.get("token_refresh") or {}
                res = _run_loadgen(
                    tokens=tokens,
                    host=mqtt_host,
                    port=mqtt_port,
                    username=s.get("username", ""),
                    password=s.get("password", ""),
                    fanout_publisher_username=s.get("fanout_publisher_username"),
                    fanout_publisher_password=s.get("fanout_publisher_password"),
                    clients=args.clients,
                    messages=args.messages,
                    topic=s.get("topic", "sensors/{client_id}/temp"),
                    mode=s.get("mode"),
                    fanout_topic=s.get("fanout_topic"),
                    qos=args.qos,
                    message_size=int(s.get("message_size", 0)),
                    sync_connect=bool(s.get("sync_connect", False)),
                    token_issuer_url=token_issuer_base if token_refresh else None,
                    token_issuer_kind=token_refresh.get("kind"),
                    token_issuer_ttl=token_refresh.get("ttl_seconds"),
                    token_issuer_no_default_roles=args.token_issuer_no_default_roles,
                    token_refresh_codes=args.token_refresh_codes,
                    tls_enabled=scenario_tls,
                    tls_ca_file=tls_ca,
                    tls_insecure=tls_insecure,
                )
            # Small delay to ensure container metrics are available after loadgen
            time.sleep(2)
            try:
                snap = _resource_snapshot(prom_base, tls_ca, tls_insecure)
            except Exception as e:
                snap = {"error": str(e)}

            out_payload["runs"].append({"loadgen": res, "resources": snap})
            if s.get("sleep_between"):
                time.sleep(float(s["sleep_between"]))

        path = _write_result(args.out, s["id"], out_payload)
        print(f"wrote {path}")

    summary_json = args.summary_json
    if not os.path.isabs(summary_json):
        summary_json = os.path.join(args.out, summary_json)
    summary_csv = args.summary_csv
    if not os.path.isabs(summary_csv):
        summary_csv = os.path.join(args.out, summary_csv)

    agg_cmd = [
        "python3",
        "benchmarks/aggregate_results.py",
        "--input",
        args.out,
        "--out-json",
        summary_json,
    ]
    if args.no_summary_csv:
        agg_cmd.append("--no-csv")
    else:
        agg_cmd.extend(["--out-csv", summary_csv])
    try:
        subprocess.check_call(agg_cmd, cwd=os.path.dirname(os.path.dirname(__file__)))
    except subprocess.CalledProcessError as exc:
        print(
            f"warning: aggregation failed ({exc}); scenario results preserved",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
