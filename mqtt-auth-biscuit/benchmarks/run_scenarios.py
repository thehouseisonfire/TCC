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
    mqtt5: bool,
    message_size: int,
    sync_connect: bool,
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
    if mqtt5:
        cmd.append("--mqtt5")
    if sync_connect:
        cmd.append("--sync-connect")

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
        "benchmarks/mqtt5_auth_client.py",
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
    args = p.parse_args()

    tokens = _read_tokens(os.path.join(os.path.dirname(os.path.dirname(__file__)), args.tokens))

    scenarios = []

    scenarios.append({
        "id": "BASE-01",
        "mosquitto_conf": "docker/mosquitto_base.conf",
        "username": "",
        "password": "",
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "JWT-01",
        "mosquitto_conf": "docker/mosquitto.conf",
        "username": "jwt",
        "password": tokens["jwt"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "BIS-01",
        "mosquitto_conf": "docker/mosquitto.conf",
        "username": "biscuit",
        "password": tokens["biscuit"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "POLICY-COMPLEX-1",
        "mosquitto_conf": "docker/mosquitto.conf",
        "username": "biscuit",
        "password": tokens["biscuit"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "POLICY-COMPLEX-5",
        "mosquitto_conf": "docker/mosquitto.conf",
        "username": "biscuit",
        "password": tokens["biscuit_5"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "POLICY-COMPLEX-25",
        "mosquitto_conf": "docker/mosquitto.conf",
        "username": "biscuit",
        "password": tokens["biscuit_25"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "JWT-HTTP-200MS",
        "mosquitto_conf": "docker/mosquitto_http.conf",
        "username": "jwt",
        "password": tokens["jwt"],
        "topic": "sensors/{client_id}/temp",
        "authz": {"delay_ms": 200, "fail_mode": "none"},
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "JWT-HTTP-1000MS",
        "mosquitto_conf": "docker/mosquitto_http.conf",
        "username": "jwt",
        "password": tokens["jwt"],
        "topic": "sensors/{client_id}/temp",
        "authz": {"delay_ms": 1000, "fail_mode": "none"},
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "HYBRID-AUTHZ-DOWN",
        "mosquitto_conf": "docker/mosquitto_hybrid.conf",
        "username": "jwt",
        "password": tokens["jwt"],
        "topic": "sensors/{client_id}/temp",
        "authz": {"delay_ms": 0, "fail_mode": "always"},
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "MTU-200-JWT-8K",
        "mosquitto_conf": "docker/mosquitto.conf",
        "username": "jwt",
        "password": tokens["jwt_pad_8k"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"mtu": 200},
        "message_size": 0,
    })

    for mtu in [500, 1500, 9000]:
        scenarios.append({
            "id": f"MTU-{mtu}-BIS-25",
            "mosquitto_conf": "docker/mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_25"],
            "topic": "sensors/{client_id}/temp",
            "authz": None,
            "netem": {"mtu": mtu},
            "message_size": 0,
        })

    scenarios.append({
        "id": "BIS-HTTP-200MS",
        "mosquitto_conf": "docker/mosquitto_http.conf",
        "username": "biscuit",
        "password": tokens["biscuit"],
        "topic": "sensors/{client_id}/temp",
        "authz": {"delay_ms": 200, "fail_mode": "none"},
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "JWT-HTTP-200MS-LOSS1",
        "mosquitto_conf": "docker/mosquitto_http.conf",
        "username": "jwt",
        "password": tokens["jwt"],
        "topic": "sensors/{client_id}/temp",
        "authz": {"delay_ms": 200, "fail_mode": "rate", "fail_rate": 0.01},
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "JWT-HTTP-200MS-LOSS5",
        "mosquitto_conf": "docker/mosquitto_http.conf",
        "username": "jwt",
        "password": tokens["jwt"],
        "topic": "sensors/{client_id}/temp",
        "authz": {"delay_ms": 200, "fail_mode": "rate", "fail_rate": 0.05},
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "MQTT5-REAUTH-JWT",
        "mosquitto_conf": "docker/mosquitto.conf",
        "authz": None,
        "netem": {"clear": True},
        "mqtt5_auth": {"token1": tokens["jwt_short"], "token2": tokens["jwt"]},
    })

    scenarios.append({
        "id": "MQTT5-REAUTH-BISCUIT",
        "mosquitto_conf": "docker/mosquitto.conf",
        "authz": None,
        "netem": {"clear": True},
        "mqtt5_auth": {"token1": tokens["biscuit_short"], "token2": tokens["biscuit"]},
    })

    for mtu in [500, 1500, 9000]:
        scenarios.append({
            "id": f"MTU-{mtu}-JWT-8K",
            "mosquitto_conf": "docker/mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt_pad_8k"],
            "topic": "sensors/{client_id}/temp",
            "authz": None,
            "netem": {"mtu": mtu},
            "message_size": 0,
        })

    scenarios.append({
        "id": "MTU-200-BIS-25",
        "mosquitto_conf": "docker/mosquitto.conf",
        "username": "biscuit",
        "password": tokens["biscuit_25"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"mtu": 200},
        "message_size": 0,
    })

    scenarios.append({
        "id": "THUNDERING-HERD",
        "mosquitto_conf": "docker/mosquitto.conf",
        "username": "biscuit",
        "password": tokens["biscuit"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
        "restart_mosquitto": True,
        "sync_connect": True,
    })

    scenarios.append({
        "id": "DELEGATION-TEMP-ONLY",
        "mosquitto_conf": "docker/mosquitto.conf",
        "username": "biscuit",
        "password": tokens["biscuit_delegated"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
    })

    scenarios.append({
        "id": "LIFECYCLE-JWT-SHORT-RECONNECT",
        "mosquitto_conf": "docker/mosquitto_shortcache.conf",
        "username": "jwt",
        "password": tokens["jwt_short"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
        "repeat": 3,
        "sleep_between": 2,
    })

    scenarios.append({
        "id": "LIFECYCLE-BIS-SHORT-RECONNECT",
        "mosquitto_conf": "docker/mosquitto_shortcache.conf",
        "username": "biscuit",
        "password": tokens["biscuit_short"],
        "topic": "sensors/{client_id}/temp",
        "authz": None,
        "netem": {"clear": True},
        "message_size": 0,
        "repeat": 3,
        "sleep_between": 2,
    })

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

        _compose(["up", "--build", "-d", "mosquitto", "authz", "netem", "metrics-collector", "cadvisor"], extra_env=extra_env)
        time.sleep(1)

        if s.get("authz") is not None:
            cfg = s["authz"]
            _authz_config(delay_ms=cfg.get("delay_ms"), fail_mode=cfg.get("fail_mode"), fail_rate=cfg.get("fail_rate"))

        repeats = int(s.get("repeat", 1))
        out_payload = {"scenario": s["id"], "runs": []}

        if s.get("restart_mosquitto"):
            _compose(["restart", "mosquitto"], extra_env=extra_env)
            time.sleep(1)

        for _ in range(repeats):
            if s.get("mqtt5_auth") is not None:
                cfg = s["mqtt5_auth"]
                res = _run_mqtt5_auth(cfg["token1"], cfg["token2"])
            else:
                res = _run_loadgen(
                    tokens=tokens,
                    username=s.get("username", ""),
                    password=s.get("password", ""),
                    clients=args.clients,
                    messages=args.messages,
                    topic=s.get("topic", "sensors/{client_id}/temp"),
                    qos=args.qos,
                    mqtt5=False,
                    message_size=int(s.get("message_size", 0)),
                    sync_connect=bool(s.get("sync_connect", False)),
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
