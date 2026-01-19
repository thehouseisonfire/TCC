import argparse
import json
import os
import queue
import ssl
import threading
import time
import urllib.request
from dataclasses import dataclass
from statistics import mean, median

try:
    import paho.mqtt.client as mqtt
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency 'paho-mqtt'. Install it with: pip install paho-mqtt"
    ) from exc


def _percentile(sorted_vals, p):
    if not sorted_vals:
        return None
    if p <= 0:
        return sorted_vals[0]
    if p >= 100:
        return sorted_vals[-1]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def _summarize_ms(vals):
    if not vals:
        return {"count": 0}
    s = sorted(vals)
    return {
        "count": len(vals),
        "min_ms": s[0],
        "p50_ms": _percentile(s, 50),
        "p95_ms": _percentile(s, 95),
        "p99_ms": _percentile(s, 99),
        "max_ms": s[-1],
        "mean_ms": mean(vals),
        "median_ms": median(vals),
    }


@dataclass
class WorkerConfig:
    host: str
    port: int
    client_id: str
    username: str
    password: str
    topic: str
    qos: int
    message_count: int
    message_size: int
    protocol: int
    sync_connect: bool
    token_issuer_url: str | None
    token_issuer_kind: str | None
    token_issuer_ttl: int | None
    token_issuer_no_default_roles: bool
    token_refresh_codes: set[int]
    tls_enabled: bool
    tls_ca_file: str | None
    tls_insecure: bool


@dataclass
class WorkerResult:
    client_id: str
    connect_ms: float | None
    publish_ms: list[float]
    token_refresh_ms: float | None
    token_refresh_len: int | None
    errors: list[str]


def _mk_payload(size: int) -> bytes:
    if size <= 0:
        return b""
    return b"A" * size


def _fetch_token(
    issuer_url: str,
    kind: str,
    client_id: str,
    topic: str,
    ttl: int | None,
    no_default_roles: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
) -> str:
    payload = {"client_id": client_id, "ttl_seconds": ttl}
    if kind == "biscuit":
        payload["topic"] = topic
    if no_default_roles:
        payload["no_default_roles"] = True

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        issuer_url.rstrip("/") + f"/{kind}",
        method="POST",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    ctx = None
    if issuer_url.startswith("https://"):
        ctx = ssl.create_default_context(cafile=tls_ca_file)
        if tls_insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    token = body.get("token")
    if not token:
        raise ValueError("token issuer response missing token")
    return token


def _run_worker(cfg: WorkerConfig, start_evt: threading.Event, out_q: queue.Queue):
    errors: list[str] = []
    publish_ms: list[float] = []
    connect_ms = None
    token_refresh_ms = None
    token_refresh_len = None

    def attempt_connect(password: str):
        userdata = {
            "connected": False,
            "connect_start": 0.0,
            "connect_done": 0.0,
            "disconnected": False,
            "connect_reason": None,
        }

        def on_connect(client, ud, flags, reason_code, properties=None):
            ud["connect_reason"] = reason_code
            if reason_code == 0:
                ud["connected"] = True
                ud["connect_done"] = time.perf_counter()

        def on_disconnect(client, ud, disconnect_flags, reason_code, properties=None):
            ud["disconnected"] = True

        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=cfg.client_id,
            protocol=cfg.protocol,
        )
        client.user_data_set(userdata)
        client.username_pw_set(cfg.username, password)
        if cfg.tls_enabled:
            if cfg.tls_ca_file:
                client.tls_set(ca_certs=cfg.tls_ca_file)
            else:
                client.tls_set()
            if cfg.tls_insecure:
                client.tls_insecure_set(True)
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect

        if cfg.sync_connect:
            start_evt.wait()

        try:
            userdata["connect_start"] = time.perf_counter()
            client.connect(cfg.host, cfg.port, 30)
        except Exception as e:
            return None, f"connect_failed:{e}", None, None

        client.loop_start()

        t_deadline = time.time() + 10
        while not userdata["connected"] and userdata["connect_reason"] is None and time.time() < t_deadline:
            time.sleep(0.01)

        if not userdata["connected"]:
            reason = userdata["connect_reason"]
            try:
                client.loop_stop()
            except Exception:
                pass
            try:
                client.disconnect()
            except Exception:
                pass
            if reason is None:
                return None, "connect_timeout", reason, userdata
            return None, f"connect_denied:{reason}", reason, userdata

        return client, None, None, userdata

    password = cfg.password
    token_refreshed = False
    client = None
    userdata = None

    for _ in range(2):
        client, err, reason, connect_userdata = attempt_connect(password)
        if client is not None:
            userdata = connect_userdata
            break

        if token_refreshed:
            errors.append(err)
            out_q.put(WorkerResult(cfg.client_id, None, [], token_refresh_ms, token_refresh_len, errors))
            return

        if cfg.token_issuer_url and cfg.token_issuer_kind and reason in cfg.token_refresh_codes:
            try:
                t_refresh_start = time.perf_counter()
                password = _fetch_token(
                    cfg.token_issuer_url,
                    cfg.token_issuer_kind,
                    cfg.client_id,
                    cfg.topic,
                    cfg.token_issuer_ttl,
                    cfg.token_issuer_no_default_roles,
                    cfg.tls_ca_file,
                    cfg.tls_insecure,
                )
                token_refresh_ms = (time.perf_counter() - t_refresh_start) * 1000.0
                token_refresh_len = len(password)
                token_refreshed = True
                continue
            except Exception as e:
                errors.append(f"token_refresh_failed:{e}")
                out_q.put(WorkerResult(cfg.client_id, None, [], token_refresh_ms, token_refresh_len, errors))
                return

        errors.append(err)
        out_q.put(WorkerResult(cfg.client_id, None, [], token_refresh_ms, token_refresh_len, errors))
        return

    if userdata is None:
        errors.append("connect_failed")
        out_q.put(WorkerResult(cfg.client_id, None, [], token_refresh_ms, token_refresh_len, errors))
        return

    connect_ms = (userdata["connect_done"] - userdata["connect_start"]) * 1000.0

    if not cfg.sync_connect:
        start_evt.wait()

    payload = _mk_payload(cfg.message_size)

    for _ in range(cfg.message_count):
        try:
            t0 = time.perf_counter()
            info = client.publish(cfg.topic, payload, qos=cfg.qos)
            info.wait_for_publish(timeout=10)
            t1 = time.perf_counter()
            publish_ms.append((t1 - t0) * 1000.0)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                errors.append(f"publish_rc:{info.rc}")
        except Exception as e:
            errors.append(f"publish_failed:{e}")
            break

    try:
        client.disconnect()
    except Exception:
        pass

    t_deadline = time.time() + 5
    while not userdata["disconnected"] and time.time() < t_deadline:
        time.sleep(0.01)

    try:
        client.loop_stop()
    except Exception:
        pass

    out_q.put(WorkerResult(cfg.client_id, connect_ms, publish_ms, token_refresh_ms, token_refresh_len, errors))


def run_load(
    host: str,
    port: int,
    username: str,
    password: str,
    topic_template: str,
    clients: int,
    message_count: int,
    qos: int,
    message_size: int,
    protocol: int,
    sync_connect: bool,
    token_issuer_url: str | None,
    token_issuer_kind: str | None,
    token_issuer_ttl: int | None,
    token_issuer_no_default_roles: bool,
    token_refresh_codes: set[int],
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
):
    start_evt = threading.Event()
    out_q: queue.Queue = queue.Queue()

    threads: list[threading.Thread] = []

    for i in range(clients):
        client_id = f"client_{i+1}"
        topic = topic_template.format(client_id=client_id)
        cfg = WorkerConfig(
            host=host,
            port=port,
            client_id=client_id,
            username=username,
            password=password,
            topic=topic,
            qos=qos,
            message_count=message_count,
            message_size=message_size,
            protocol=protocol,
            sync_connect=sync_connect,
            token_issuer_url=token_issuer_url,
            token_issuer_kind=token_issuer_kind,
            token_issuer_ttl=token_issuer_ttl,
            token_issuer_no_default_roles=token_issuer_no_default_roles,
            token_refresh_codes=token_refresh_codes,
            tls_enabled=tls_enabled,
            tls_ca_file=tls_ca_file,
            tls_insecure=tls_insecure,
        )
        t = threading.Thread(target=_run_worker, args=(cfg, start_evt, out_q), daemon=True)
        threads.append(t)

    for t in threads:
        t.start()

    time.sleep(0.2)
    t_start = time.perf_counter()
    start_evt.set()

    results: list[WorkerResult] = []
    for _ in threads:
        results.append(out_q.get())

    for t in threads:
        t.join(timeout=1)

    t_end = time.perf_counter()

    connect_lat = [r.connect_ms for r in results if r.connect_ms is not None]
    publish_lat = [x for r in results for x in r.publish_ms]
    refresh_lat = [r.token_refresh_ms for r in results if r.token_refresh_ms is not None]
    refresh_len = [r.token_refresh_len for r in results if r.token_refresh_len is not None]

    errors = [e for r in results for e in r.errors]

    duration_s = max(1e-9, t_end - t_start)
    throughput_mps = len(publish_lat) / duration_s

    return {
        "inputs": {
            "host": host,
            "port": port,
            "username": username,
            "clients": clients,
            "message_count": message_count,
            "qos": qos,
            "message_size": message_size,
            "protocol": "mqttv5",
            "token_issuer_url": token_issuer_url,
            "token_issuer_kind": token_issuer_kind,
            "token_issuer_no_default_roles": token_issuer_no_default_roles,
            "token_refresh_codes": sorted(token_refresh_codes),
        },
        "connect": _summarize_ms(connect_lat),
        "token_refresh": _summarize_ms(refresh_lat),
        "token_refresh_len": _summarize_ms(refresh_len),
        "publish": _summarize_ms(publish_lat),
        "throughput_mps": throughput_mps,
        "errors": errors,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=os.environ.get("MQTT_HOST", "localhost"))
    p.add_argument("--port", type=int, default=int(os.environ.get("MQTT_PORT", "1883")))
    p.add_argument("--username", default=os.environ.get("MQTT_USERNAME", "jwt"))
    p.add_argument("--password", default=os.environ.get("MQTT_PASSWORD", ""))
    p.add_argument("--topic", default=os.environ.get("MQTT_TOPIC", "sensors/{client_id}/temp"))
    p.add_argument("--clients", type=int, default=int(os.environ.get("MQTT_CLIENTS", "10")))
    p.add_argument("--messages", type=int, default=int(os.environ.get("MQTT_MESSAGES", "50")))
    p.add_argument("--qos", type=int, default=int(os.environ.get("MQTT_QOS", "1")))
    p.add_argument("--message-size", type=int, default=int(os.environ.get("MQTT_MESSAGE_SIZE", "0")))
    p.add_argument("--sync-connect", action="store_true")
    p.add_argument("--token-issuer-url", default=os.environ.get("TOKEN_ISSUER_URL"))
    p.add_argument("--token-issuer-kind", default=os.environ.get("TOKEN_ISSUER_KIND"))
    p.add_argument("--token-issuer-ttl", type=int, default=os.environ.get("TOKEN_ISSUER_TTL"))
    p.add_argument("--token-issuer-no-default-roles", action="store_true")
    p.add_argument(
        "--token-refresh-codes",
        default=os.environ.get("TOKEN_REFRESH_CODES", "5,135"),
        help="Comma-separated MQTT v5 reason codes that should trigger token refresh (e.g., 5/0x87 = Not authorized)",
    )
    p.add_argument("--tls", action="store_true")
    p.add_argument("--tls-ca-file")
    p.add_argument("--tls-insecure", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    protocol = mqtt.MQTTv5  # MQTT v5 only

    token_refresh_codes = set()
    for part in str(args.token_refresh_codes).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            token_refresh_codes.add(int(part, 0))
        except ValueError:
            raise SystemExit(f"invalid token refresh code: {part}")

    res = run_load(
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        topic_template=args.topic,
        clients=args.clients,
        message_count=args.messages,
        qos=args.qos,
        message_size=args.message_size,
        protocol=protocol,
        sync_connect=args.sync_connect,
        token_issuer_url=args.token_issuer_url,
        token_issuer_kind=args.token_issuer_kind,
        token_issuer_ttl=args.token_issuer_ttl,
        token_issuer_no_default_roles=args.token_issuer_no_default_roles,
        token_refresh_codes=token_refresh_codes,
        tls_enabled=args.tls,
        tls_ca_file=args.tls_ca_file,
        tls_insecure=args.tls_insecure,
    )

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(res)


if __name__ == "__main__":
    main()
