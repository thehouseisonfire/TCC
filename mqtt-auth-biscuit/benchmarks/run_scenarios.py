import argparse
import json
import os
import subprocess
import time
import urllib.parse
import urllib.request


def _read_tokens(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _compose_bin():
    return os.environ.get("DOCKER_COMPOSE_BIN", "docker compose")


def _compose(args: list[str], extra_env: dict | None = None):
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    cmd = _compose_bin().split(" ") + ["-f", "docker/docker-compose.yml"] + args
    subprocess.check_call(cmd, cwd=os.path.dirname(os.path.dirname(__file__)), env=env)


def _authz_config(delay_ms: int | None = None, fail_mode: str | None = None, fail_rate: float | None = None):
    body = {}
    if delay_ms is not None:
        body["delay_ms"] = delay_ms
    if fail_mode is not None:
        body["fail_mode"] = fail_mode
    if fail_rate is not None:
        body["fail_rate"] = fail_rate

    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        "http://localhost:8081/config",
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _prom_query(query: str):
    url = "http://localhost:9090/api/v1/query?query=" + urllib.parse.quote(query, safe="")
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _resource_snapshot():
    cpu_q = 'sum(rate(container_cpu_usage_seconds_total{container_label_com_docker_compose_service="mosquitto"}[30s]))'
    mem_q = 'max(container_memory_working_set_bytes{container_label_com_docker_compose_service="mosquitto"})'
    snap = {
        "prometheus": {
            "cpu": _prom_query(cpu_q),
            "memory": _prom_query(mem_q),
        }
    }
    return snap


def _run_loadgen(
    tokens: dict,
    username: str,
    password: str,
    clients: int,
    messages: int,
    topic: str,
    qos: int,
    message_size: int,
    sync_connect: bool,
    token_issuer_url: str | None,
    token_issuer_kind: str | None,
    token_issuer_ttl: int | None,
    token_issuer_no_default_roles: bool,
    token_refresh_codes: str | None,
):
    cmd = [
        "python3",
        "benchmarks/loadgen.py",
        "--host",
        "localhost",
        "--port",
        "1883",
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
    if token_issuer_url:
        cmd.extend(["--token-issuer-url", token_issuer_url])
    if token_issuer_kind:
        cmd.extend(["--token-issuer-kind", token_issuer_kind])
    if token_issuer_ttl is not None:
        cmd.extend(["--token-issuer-ttl", str(token_issuer_ttl)])
    if token_issuer_pad_to_size is not None:
        cmd.extend(["--token-issuer-pad-to-size", str(token_issuer_pad_to_size)])
    if token_issuer_no_default_roles:
        cmd.append("--token-issuer-no-default-roles")
    if token_refresh_codes:
        cmd.extend(["--token-refresh-codes", token_refresh_codes])

    out = subprocess.check_output(cmd, cwd=os.path.dirname(os.path.dirname(__file__)))
    return json.loads(out.decode("utf-8"))


def _write_result(out_dir: str, name: str, payload: dict):
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return path


def _run_mqtt5_auth(token1: str, token2: str):
    cmd = [
        "python3",
        "benchmarks/mqtt_auth_client.py",
        "--host",
        "localhost",
        "--port",
        "1883",
        "--auth-method",
        "token",
        "--token1",
        token1,
        "--token2",
        token2,
    ]
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
    p.add_argument("--token-refresh-codes", default=os.environ.get("TOKEN_REFRESH_CODES"))
    args = p.parse_args()

    tokens = _read_tokens(os.path.join(os.path.dirname(os.path.dirname(__file__)), args.tokens))

    scenarios = []
    if args.scenarios:
        scenario_ids = [s.strip() for s in args.scenarios.split(",")]
        # Define available scenarios mapping
        available_scenarios = {
            "BASE-01": {
                "mosquitto_conf": "docker/mosquitto_base.conf",
                "username": "",
                "password": "",
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-01": {
                "mosquitto_conf": "docker/mosquitto.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "BIS-01": {
                "mosquitto_conf": "docker/mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "POLICY-COMPLEX-1": {
                "mosquitto_conf": "docker/mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "POLICY-COMPLEX-5": {
                "mosquitto_conf": "docker/mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit_5"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "POLICY-COMPLEX-25": {
                "mosquitto_conf": "docker/mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit_25"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-HTTP-200MS": {
                "mosquitto_conf": "docker/mosquitto_http.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 200, "fail_mode": "none"},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-HTTP-1000MS": {
                "mosquitto_conf": "docker/mosquitto_http.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 1000, "fail_mode": "none"},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "HYBRID-AUTHZ-DOWN": {
                "mosquitto_conf": "docker/mosquitto_hybrid.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 0, "fail_mode": "always"},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "MTU-200-JWT": {
                "mosquitto_conf": "docker/mosquitto.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"mtu": 200},
                "message_size": 0,
            },
            "BIS-HTTP-200MS": {
                "mosquitto_conf": "docker/mosquitto_http.conf",
                "username": "biscuit",
                "password": tokens["biscuit"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 200, "fail_mode": "none"},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-HTTP-200MS-LOSS1": {
                "mosquitto_conf": "docker/mosquitto_http.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 200, "fail_mode": "rate", "fail_rate": 0.01},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "JWT-HTTP-200MS-LOSS5": {
                "mosquitto_conf": "docker/mosquitto_http.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": {"delay_ms": 200, "fail_mode": "rate", "fail_rate": 0.05},
                "netem": {"clear": True},
                "message_size": 0,
            },
            "MQTT5-REAUTH-JWT": {
                "mosquitto_conf": "docker/mosquitto.conf",
                "authz": None,
                "netem": {"clear": True},
                "mqtt5_auth": {"token1": tokens["jwt_short"], "token2": tokens["jwt"]},
            },
            "MQTT5-REAUTH-BISCUIT": {
                "mosquitto_conf": "docker/mosquitto.conf",
                "authz": None,
                "netem": {"clear": True},
                "mqtt5_auth": {"token1": tokens["biscuit_short"], "token2": tokens["biscuit"]},
            },
            "THUNDERING-HERD": {
                "mosquitto_conf": "docker/mosquitto.conf",
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
                "mosquitto_conf": "docker/mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit_delegated"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"clear": True},
                "message_size": 0,
            },
            "LIFECYCLE-JWT-SHORT-RECONNECT": {
                "mosquitto_conf": "docker/mosquitto_shortcache.conf",
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
                "mosquitto_conf": "docker/mosquitto_shortcache.conf",
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
        }
        
        # Add dynamic MTU scenarios
        for mtu in [500, 1500, 9000]:
            available_scenarios[f"MTU-{mtu}-BIS-25"] = {
                "mosquitto_conf": "docker/mosquitto.conf",
                "username": "biscuit",
                "password": tokens["biscuit_25"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"mtu": mtu},
                "message_size": 0,
            }
            available_scenarios[f"MTU-{mtu}-JWT"] = {
                "mosquitto_conf": "docker/mosquitto.conf",
                "username": "jwt",
                "password": tokens["jwt"],
                "topic": "sensors/{client_id}/temp",
                "authz": None,
                "netem": {"mtu": mtu},
                "message_size": 0,
            }
        
        # Select requested scenarios
        for scenario_id in scenario_ids:
            if scenario_id in available_scenarios:
                scenario = available_scenarios[scenario_id].copy()
                scenario["id"] = scenario_id
                scenarios.append(scenario)
            else:
                print(f"Warning: Unknown scenario '{scenario_id}', skipping")
    else:
        print("No scenarios specified. Use --scenarios to specify which scenarios to run.")
        print("Available scenarios:")
        print("BASE-01, JWT-01, BIS-01, POLICY-COMPLEX-1, POLICY-COMPLEX-5, POLICY-COMPLEX-25")
        print("JWT-HTTP-200MS, JWT-HTTP-1000MS, HYBRID-AUTHZ-DOWN, MTU-200-JWT")
        print("BIS-HTTP-200MS, JWT-HTTP-200MS-LOSS1, JWT-HTTP-200MS-LOSS5")
        print("MQTT5-REAUTH-JWT, MQTT5-REAUTH-BISCUIT, THUNDERING-HERD, DELEGATION-TEMP-ONLY")
        print("LIFECYCLE-JWT-SHORT-RECONNECT, LIFECYCLE-BIS-SHORT-RECONNECT")
        print("MTU-500-BIS-25, MTU-1500-BIS-25, MTU-9000-BIS-25")
        print("MTU-500-JWT, MTU-1500-JWT, MTU-9000-JWT")
        return

    for s in scenarios:
        mosq_conf = s["mosquitto_conf"]
        extra_env = {"MOSQUITTO_CONF": mosq_conf}

        netem = s.get("netem")
        if netem:
            if netem.get("clear"):
                extra_env.update({"NETEM_CLEAR": "1", "NETEM_MTU": "", "NETEM_DELAY_MS": "", "NETEM_LOSS_PCT": "", "NETEM_RATE_KBIT": ""})
            if "mtu" in netem:
                extra_env.update({"NETEM_CLEAR": "1", "NETEM_MTU": str(netem["mtu"])})
            if "delay_ms" in netem:
                extra_env.update({"NETEM_CLEAR": "1", "NETEM_DELAY_MS": str(netem["delay_ms"])})
            if "loss_pct" in netem:
                extra_env.update({"NETEM_CLEAR": "1", "NETEM_LOSS_PCT": str(netem["loss_pct"])})

        extra_env.update({
            "TOKEN_ISSUER_ALLOW_DEFAULT_KEYS": os.environ.get("TOKEN_ISSUER_ALLOW_DEFAULT_KEYS", "1"),
            "JWT_NO_DEFAULT_ROLES": "1" if args.token_issuer_no_default_roles else "0",
            "BISCUIT_BASE64URL": "1" if args.biscuit_base64url else "0",
        })

        _compose([
            "up",
            "--build",
            "-d",
            "mosquitto",
            "authz",
            "netem",
            "metrics-collector",
            "cadvisor",
            "token-issuer",
        ], extra_env=extra_env)
        time.sleep(1)

        if s.get("authz") is not None:
            cfg = s["authz"]
            _authz_config(delay_ms=cfg.get("delay_ms"), fail_mode=cfg.get("fail_mode"), fail_rate=cfg.get("fail_rate"))

        repeats = int(s.get("repeat", 1))
        token_len = len(s.get("password", "")) if s.get("password") else 0
        out_payload = {
            "scenario": s["id"],
            "token_len": token_len,
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

        for _ in range(repeats):
            if s.get("mqtt5_auth") is not None:
                cfg = s["mqtt5_auth"]
                res = _run_mqtt5_auth(cfg["token1"], cfg["token2"])
            else:
                token_refresh = s.get("token_refresh") or {}
                res = _run_loadgen(
                    tokens=tokens,
                    username=s.get("username", ""),
                    password=s.get("password", ""),
                    clients=args.clients,
                    messages=args.messages,
                    topic=s.get("topic", "sensors/{client_id}/temp"),
                    qos=args.qos,
                    message_size=int(s.get("message_size", 0)),
                    sync_connect=bool(s.get("sync_connect", False)),
                    token_issuer_url="http://localhost:8082" if token_refresh else None,
                    token_issuer_kind=token_refresh.get("kind"),
                    token_issuer_ttl=token_refresh.get("ttl_seconds"),
                    token_issuer_no_default_roles=args.token_issuer_no_default_roles,
                    token_refresh_codes=args.token_refresh_codes,
                )
            try:
                snap = _resource_snapshot()
            except Exception as e:
                snap = {"error": str(e)}

            out_payload["runs"].append({"loadgen": res, "resources": snap})
            if s.get("sleep_between"):
                time.sleep(float(s["sleep_between"]))

        path = _write_result(args.out, s["id"], out_payload)
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
