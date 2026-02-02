import json
import os
import shutil
import subprocess
import time

import httpx
import typer
from pydantic import BaseModel, ConfigDict

from logging_utils import get_logger, setup_logging


def _read_tokens(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


logger = get_logger(__name__)
app = typer.Typer(add_completion=False)


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


def _http_client(ca_file: str | None, insecure: bool) -> httpx.Client:
    verify: bool | str = True
    if insecure:
        verify = False
    elif ca_file:
        verify = ca_file
    return httpx.Client(verify=verify, timeout=5.0)


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

    with _http_client(ca_file, insecure) as client:
        resp = client.post(
            authz_url.rstrip("/") + "/config",
            json=body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()


# Prometheus query templates
CURRENT_DOCKER_COMPOSE_CPU_QUERY = 'sum(rate(container_cpu_usage_seconds_total{container_label_com_docker_compose_service="mosquitto"}[30s]))'
CURRENT_DOCKER_COMPOSE_MEM_QUERY = 'max(container_memory_working_set_bytes{container_label_com_docker_compose_service="mosquitto"})'


def _prom_query(base_url: str, query: str, ca_file: str | None, insecure: bool):
    with _http_client(ca_file, insecure) as client:
        resp = client.get(
            base_url.rstrip("/") + "/api/v1/query",
            params={"query": query},
        )
        resp.raise_for_status()
        return resp.json()


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
    token_issuer_no_default_grants: bool,
    token_refresh_codes: str | None,
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
    biscuit_attenuate: bool,
    biscuit_attenuate_denies: list[str] | None,
    biscuit_attenuate_checks: list[str] | None,
    biscuit_attenuate_topic: str | None,
    biscuit_attenuate_op: str | None,
    biscuit_attenuate_ttl: int | None,
    biscuit_public_key_hex: str | None,
    biscuit_public_key_file: str | None,
    biscuit_base64url: bool,
    biscuit_attenuate_bin: str | None,
    biscuit_delegate: bool,
    biscuit_delegate_denies: list[str] | None,
    biscuit_delegate_checks: list[str] | None,
    biscuit_delegate_topic: str | None,
    biscuit_delegate_op: str | None,
    biscuit_delegate_ttl: int | None,
    biscuit_delegate_public_key_hex: str | None,
    biscuit_delegate_public_key_file: str | None,
    biscuit_delegate_base64url: bool,
    biscuit_delegate_bin: str | None,
    biscuit_delegate_handoff: bool,
    biscuit_delegate_handoff_topic: str | None,
    biscuit_delegate_handoff_token: str | None,
    biscuit_delegate_handoff_qos: int | None,
    biscuit_delegate_handoff_retain: bool | None,
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
    if token_issuer_no_default_grants:
        cmd.append("--token-issuer-no-default-grants")
    if token_refresh_codes:
        cmd.extend(["--token-refresh-codes", token_refresh_codes])
    if tls_enabled:
        cmd.append("--tls")
    if tls_ca_file:
        cmd.extend(["--tls-ca-file", tls_ca_file])
    if tls_insecure:
        cmd.append("--tls-insecure")
    if biscuit_attenuate:
        cmd.append("--biscuit-attenuate")
    for deny in biscuit_attenuate_denies or []:
        cmd.extend(["--biscuit-attenuate-deny", deny])
    for check in biscuit_attenuate_checks or []:
        cmd.extend(["--biscuit-attenuate-check", check])
    if biscuit_attenuate_topic:
        cmd.extend(["--biscuit-attenuate-topic", biscuit_attenuate_topic])
    if biscuit_attenuate_op:
        cmd.extend(["--biscuit-attenuate-op", biscuit_attenuate_op])
    if biscuit_attenuate_ttl is not None:
        cmd.extend(["--biscuit-attenuate-ttl", str(biscuit_attenuate_ttl)])
    if biscuit_public_key_hex:
        cmd.extend(["--biscuit-public-key-hex", biscuit_public_key_hex])
    if biscuit_public_key_file:
        cmd.extend(["--biscuit-public-key-file", biscuit_public_key_file])
    if biscuit_base64url:
        cmd.append("--biscuit-base64url")
    if biscuit_attenuate_bin:
        cmd.extend(["--biscuit-attenuate-bin", biscuit_attenuate_bin])
    if biscuit_delegate:
        cmd.append("--biscuit-delegate")
    for deny in biscuit_delegate_denies or []:
        cmd.extend(["--biscuit-delegate-deny", deny])
    for check in biscuit_delegate_checks or []:
        cmd.extend(["--biscuit-delegate-check", check])
    if biscuit_delegate_topic:
        cmd.extend(["--biscuit-delegate-topic", biscuit_delegate_topic])
    if biscuit_delegate_op:
        cmd.extend(["--biscuit-delegate-op", biscuit_delegate_op])
    if biscuit_delegate_ttl is not None:
        cmd.extend(["--biscuit-delegate-ttl", str(biscuit_delegate_ttl)])
    if biscuit_delegate_public_key_hex:
        cmd.extend(["--biscuit-delegate-public-key-hex", biscuit_delegate_public_key_hex])
    if biscuit_delegate_public_key_file:
        cmd.extend(["--biscuit-delegate-public-key-file", biscuit_delegate_public_key_file])
    if biscuit_delegate_base64url:
        cmd.append("--biscuit-delegate-base64url")
    if biscuit_delegate_bin:
        cmd.extend(["--biscuit-delegate-bin", biscuit_delegate_bin])
    if biscuit_delegate_handoff:
        cmd.append("--biscuit-delegate-handoff")
    if biscuit_delegate_handoff_topic:
        cmd.extend(["--biscuit-delegate-handoff-topic", biscuit_delegate_handoff_topic])
    if biscuit_delegate_handoff_token:
        cmd.extend(["--biscuit-delegate-handoff-token", biscuit_delegate_handoff_token])
    if biscuit_delegate_handoff_qos is not None:
        cmd.extend(["--biscuit-delegate-handoff-qos", str(biscuit_delegate_handoff_qos)])
    if biscuit_delegate_handoff_retain is False:
        cmd.append("--biscuit-delegate-handoff-no-retain")

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


class ScenarioModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str | None = None
    mosquitto_conf: str | None = None
    username: str | None = None
    password: str | None = None
    topic: str | None = None


@app.command()
def main(
    tokens: str = "benchmarks/tokens.json",
    out: str = "benchmarks/results",
    clients: int = 50,
    messages: int = 20,
    qos: int = 1,
    scenarios_arg: str | None = None,
    token_issuer_no_default_roles: bool = False,
    token_issuer_no_default_grants: bool = False,
    biscuit_base64url: bool = False,
    token_refresh_codes: str | None = typer.Option(
        None, envvar="TOKEN_REFRESH_CODES"
    ),
    tls: bool = False,
    tls_insecure: bool = False,
    tls_ca_file: str | None = None,
    summary_json: str = "summary.json",
    summary_csv: str = "summary.csv",
    no_summary_csv: bool = False,
    log_level: str = typer.Option("INFO", "--log-level"),
):
    setup_logging(log_level)

    tokens = _read_tokens(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), tokens)
    )

    scenarios = []
    tls_enabled = tls
    tls_ca = tls_ca_file or ("docker/tls/ca.pem" if tls_enabled else None)
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
    if scenarios_arg:
        scenario_ids = [s.strip() for s in scenarios_arg.split(",")]
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
            "JWT-DENY": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "jwt",
                "password": tokens["jwt_deny"],
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
            "BIS-DENY-ATTENUATED": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit_deny"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "BIS-ATTENUATE-CLIENT": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "biscuit_attenuate": {
                    "denies": ["publish:sensors/{client_id}/temp"],
                    "ttl_seconds": 300,
                    "topic": "sensors/{client_id}/temp",
                    "op": "publish",
                },
            },
            "BIS-ATTENUATE-TTL": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "biscuit_attenuate": {"ttl_seconds": 120},
            },
            "BIS-ATTENUATE-DENY": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "biscuit_attenuate": {
                    "denies": ["subscribe:sensors/{client_id}/temp"],
                    "checks": ["resource(\"sensors/{client_id}/temp\")"],
                },
            },
            "BIS-ATTENUATE-OP-ONLY": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "biscuit_attenuate": {"op": "publish"},
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
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "biscuit_delegate": {
                    "topic": "sensors/{client_id}/temp",
                    "op": "publish",
                    "ttl_seconds": 300,
                },
            },
            "DELEGATION-HANDOFF": {
                "mosquitto_conf": "./mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
                "biscuit_delegate": {
                    "topic": "sensors/{client_id}/temp",
                    "op": "publish",
                    "ttl_seconds": 300,
                    "handoff": {
                        "topic": "delegation/handoff",
                        "token": tokens["biscuit_delegation_handoff"],
                        "qos": 1,
                        "retain": True,
                    },
                },
            },
            "DELEGATION-SIMULATED": {
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
                    "docker/dynamic-security-alt.json",
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

        for scenario in available_scenarios.values():
            scenario.setdefault(
                "token_issuer_no_default_roles", token_issuer_no_default_roles
            )
            scenario.setdefault(
                "token_issuer_no_default_grants", token_issuer_no_default_grants
            )

        available_scenarios = _expand_tls_matrix(available_scenarios)

        # Select requested scenarios
        for scenario_id in scenario_ids:
            if scenario_id in available_scenarios:
                scenario = available_scenarios[scenario_id].copy()
                scenario["id"] = scenario_id
                scenarios.append(ScenarioModel.model_validate(scenario).model_dump())
            else:
                logger.warning("Unknown scenario '%s', skipping", scenario_id)
    else:
        logger.info(
            "No scenarios specified. Use --scenarios to specify which scenarios to run."
        )
        logger.info("Available scenarios:")
        logger.info(
            "BASE-01, JWT-01, BIS-01, BIS-ATTENUATE-CLIENT, BIS-ATTENUATE-TTL, BIS-ATTENUATE-DENY, BIS-ATTENUATE-OP-ONLY, POLICY-COMPLEX-1, POLICY-COMPLEX-5, POLICY-COMPLEX-25"
        )
        logger.info("JWT-HTTP-200MS, JWT-HTTP-1000MS, HYBRID-AUTHZ-DOWN, MTU-200-JWT")
        logger.info("BIS-HTTP-200MS, JWT-HTTP-200MS-LOSS1, JWT-HTTP-200MS-LOSS5")
        logger.info(
            "MQTT5-REAUTH-JWT, MQTT5-REAUTH-BISCUIT, THUNDERING-HERD, DELEGATION-TEMP-ONLY, DELEGATION-HANDOFF, DELEGATION-SIMULATED"
        )
        logger.info("LIFECYCLE-JWT-SHORT-RECONNECT, LIFECYCLE-BIS-SHORT-RECONNECT")
        logger.info("MTU-500-BIS-25, MTU-1500-BIS-25, MTU-9000-BIS-25")
        logger.info("MTU-500-JWT, MTU-1500-JWT, MTU-9000-JWT")
        logger.info("DYNSEC-BASE, DYNSEC-CHURN, DYNSEC-READ-FANOUT")
        logger.info("DYNSEC-READ-FANOUT-CHURN")
        logger.info(
            "STATIC-ACL-JWT, STATIC-ACL-BIS, STATIC-ACL-FANOUT, STATIC-ACL-FANOUT-BIS"
        )
        logger.info("Append -TLS to any scenario id for TLS variants.")
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

        token_issuer_no_default_grants = s.get(
            "token_issuer_no_default_grants", token_issuer_no_default_grants
        )
        token_issuer_no_default_roles = s.get(
            "token_issuer_no_default_roles", token_issuer_no_default_roles
        )
        extra_env.update(
            {
                "TOKEN_ISSUER_ALLOW_DEFAULT_KEYS": os.environ.get(
                    "TOKEN_ISSUER_ALLOW_DEFAULT_KEYS", "1"
                ),
                "JWT_NO_DEFAULT_ROLES": "1" if token_issuer_no_default_roles else "0",
                "JWT_NO_DEFAULT_GRANTS": "1"
                if token_issuer_no_default_grants
                else "0",
                "BISCUIT_BASE64URL": "1" if biscuit_base64url else "0",
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
        token_issuer_no_default_grants = s.get(
            "token_issuer_no_default_grants", token_issuer_no_default_grants
        )
        token_issuer_no_default_roles = s.get(
            "token_issuer_no_default_roles", token_issuer_no_default_roles
        )
        token_schema = tokens.get("jwt_grants_schema")
        token_schema_version = token_schema.get("version") if token_schema else None
        token_denies_schema = tokens.get("jwt_denies_schema")
        token_denies_schema_version = (
            token_denies_schema.get("version") if token_denies_schema else None
        )
        grants_default_enabled = None
        if s.get("username") == "jwt" and token_schema is not None:
            grants_default_enabled = not token_issuer_no_default_grants

        biscuit_only = bool(s.get("biscuit_attenuate") or s.get("biscuit_delegate"))
        out_payload = {
            "scenario": s["id"],
            "token_len": token_len,
            "token_schema": token_schema,
            "token_metadata": {
                "jwt_grants_schema_version": token_schema_version,
                "jwt_default_grants_enabled": grants_default_enabled,
                "jwt_denies_schema_version": token_denies_schema_version,
            },
            "tls": {
                "enabled": scenario_tls,
                "ca_file": tls_ca,
                "insecure": tls_insecure,
            },
            "parity": {
                "token_issuer_no_default_roles": token_issuer_no_default_roles,
                "token_issuer_no_default_grants": token_issuer_no_default_grants,
                "biscuit_base64url": biscuit_base64url,
                "token_refresh_codes": token_refresh_codes,
            },
            "capability_flags": {
                "biscuit_only": biscuit_only,
            },
            "attenuation": s.get("biscuit_attenuate"),
            "delegation": s.get("biscuit_delegate"),
            "scenario_config": {
                "clients": clients,
                "messages": messages,
                "qos": qos,
                "token_issuer_no_default_roles": token_issuer_no_default_roles,
                "token_issuer_no_default_grants": token_issuer_no_default_grants,
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
                    clients=clients,
                    messages=messages,
                    topic=s.get("topic", "sensors/{client_id}/temp"),
                    mode=s.get("mode"),
                    fanout_topic=s.get("fanout_topic"),
                    qos=qos,
                    message_size=int(s.get("message_size", 0)),
                    sync_connect=bool(s.get("sync_connect", False)),
                    token_issuer_url=token_issuer_base if token_refresh else None,
                    token_issuer_kind=token_refresh.get("kind"),
                    token_issuer_ttl=token_refresh.get("ttl_seconds"),
                    token_issuer_no_default_roles=token_issuer_no_default_roles,
                    token_issuer_no_default_grants=token_issuer_no_default_grants,
                    token_refresh_codes=token_refresh_codes,
                    tls_enabled=scenario_tls,
                    tls_ca_file=tls_ca,
                    tls_insecure=tls_insecure,
                    biscuit_attenuate=bool(s.get("biscuit_attenuate")),
                    biscuit_attenuate_denies=(
                        s.get("biscuit_attenuate", {}).get("denies")
                        if s.get("biscuit_attenuate")
                        else None
                    ),
                    biscuit_attenuate_checks=(
                        s.get("biscuit_attenuate", {}).get("checks")
                        if s.get("biscuit_attenuate")
                        else None
                    ),
                    biscuit_attenuate_topic=(
                        s.get("biscuit_attenuate", {}).get("topic")
                        if s.get("biscuit_attenuate")
                        else None
                    ),
                    biscuit_attenuate_op=(
                        s.get("biscuit_attenuate", {}).get("op")
                        if s.get("biscuit_attenuate")
                        else None
                    ),
                    biscuit_attenuate_ttl=(
                        s.get("biscuit_attenuate", {}).get("ttl_seconds")
                        if s.get("biscuit_attenuate")
                        else None
                    ),
                    biscuit_public_key_hex=s.get("biscuit_public_key_hex"),
                    biscuit_public_key_file=s.get(
                        "biscuit_public_key_file", "docker/biscuit_public.key"
                    ),
                    biscuit_base64url=biscuit_base64url,
                    biscuit_attenuate_bin=s.get("biscuit_attenuate_bin"),
                    biscuit_delegate=bool(s.get("biscuit_delegate")),
                    biscuit_delegate_denies=(
                        s.get("biscuit_delegate", {}).get("denies")
                        if s.get("biscuit_delegate")
                        else None
                    ),
                    biscuit_delegate_checks=(
                        s.get("biscuit_delegate", {}).get("checks")
                        if s.get("biscuit_delegate")
                        else None
                    ),
                    biscuit_delegate_topic=(
                        s.get("biscuit_delegate", {}).get("topic")
                        if s.get("biscuit_delegate")
                        else None
                    ),
                    biscuit_delegate_op=(
                        s.get("biscuit_delegate", {}).get("op")
                        if s.get("biscuit_delegate")
                        else None
                    ),
                    biscuit_delegate_ttl=(
                        s.get("biscuit_delegate", {}).get("ttl_seconds")
                        if s.get("biscuit_delegate")
                        else None
                    ),
                    biscuit_delegate_public_key_hex=s.get("biscuit_public_key_hex"),
                    biscuit_delegate_public_key_file=s.get(
                        "biscuit_public_key_file", "docker/biscuit_public.key"
                    ),
                    biscuit_delegate_base64url=biscuit_base64url,
                    biscuit_delegate_bin=s.get("biscuit_delegate_bin"),
                    biscuit_delegate_handoff=bool(
                        s.get("biscuit_delegate", {}).get("handoff")
                        if s.get("biscuit_delegate")
                        else False
                    ),
                    biscuit_delegate_handoff_topic=(
                        s.get("biscuit_delegate", {}).get("handoff", {}).get("topic")
                        if s.get("biscuit_delegate")
                        else None
                    ),
                    biscuit_delegate_handoff_token=(
                        s.get("biscuit_delegate", {}).get("handoff", {}).get("token")
                        if s.get("biscuit_delegate")
                        else None
                    ),
                    biscuit_delegate_handoff_qos=(
                        s.get("biscuit_delegate", {}).get("handoff", {}).get("qos")
                        if s.get("biscuit_delegate")
                        else None
                    ),
                    biscuit_delegate_handoff_retain=(
                        s.get("biscuit_delegate", {}).get("handoff", {}).get("retain")
                        if s.get("biscuit_delegate")
                        else None
                    ),
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

        path = _write_result(out, s["id"], out_payload)
        logger.info("Wrote %s", path)

    summary_json_path = summary_json
    if not os.path.isabs(summary_json_path):
        summary_json_path = os.path.join(out, summary_json_path)
    summary_csv_path = summary_csv
    if not os.path.isabs(summary_csv_path):
        summary_csv_path = os.path.join(out, summary_csv_path)

    agg_cmd = [
        "python3",
        "benchmarks/aggregate_results.py",
        "--input",
        out,
        "--out-json",
        summary_json_path,
    ]
    if no_summary_csv:
        agg_cmd.append("--no-csv")
    else:
        agg_cmd.extend(["--out-csv", summary_csv_path])
    try:
        subprocess.check_call(agg_cmd, cwd=os.path.dirname(os.path.dirname(__file__)))
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "Aggregation failed (%s); scenario results preserved",
            exc,
        )


if __name__ == "__main__":
    app()
