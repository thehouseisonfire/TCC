import argparse
import json
import os
import queue
import threading
import time
from dataclasses import dataclass
from statistics import mean, median

import paho.mqtt.client as mqtt


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


@dataclass
class WorkerResult:
    client_id: str
    connect_ms: float | None
    publish_ms: list[float]
    errors: list[str]


def _mk_payload(size: int) -> bytes:
    if size <= 0:
        return b""
    return b"A" * size


def _run_worker(cfg: WorkerConfig, start_evt: threading.Event, out_q: queue.Queue):
    errors: list[str] = []
    publish_ms: list[float] = []
    connect_ms = None

    def on_connect(client, userdata, flags, reason_code, properties=None):
        userdata["connected"] = True
        userdata["connect_done"] = time.perf_counter()

    def on_disconnect(client, userdata, reason_code, properties=None):
        userdata["disconnected"] = True

    userdata = {"connected": False, "connect_start": 0.0, "connect_done": 0.0, "disconnected": False}

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=cfg.client_id,
        protocol=cfg.protocol,
    )
    client.user_data_set(userdata)
    client.username_pw_set(cfg.username, cfg.password)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

    if cfg.sync_connect:
        start_evt.wait()

    try:
        userdata["connect_start"] = time.perf_counter()
        client.connect(cfg.host, cfg.port, 30)
    except Exception as e:
        errors.append(f"connect_failed:{e}")
        out_q.put(WorkerResult(cfg.client_id, None, [], errors))
        return

    client.loop_start()

    t_deadline = time.time() + 10
    while not userdata["connected"] and time.time() < t_deadline:
        time.sleep(0.01)

    if not userdata["connected"]:
        errors.append("connect_timeout")
        try:
            client.loop_stop()
        except Exception:
            pass
        try:
            client.disconnect()
        except Exception:
            pass
        out_q.put(WorkerResult(cfg.client_id, None, [], errors))
        return

    connect_ms = (userdata["connect_done"] - userdata["connect_start"]) * 1000.0

    if not cfg.sync_connect:
        start_evt.wait()

    payload = _mk_payload(cfg.message_size)

    for i in range(cfg.message_count):
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

    out_q.put(WorkerResult(cfg.client_id, connect_ms, publish_ms, errors))


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
            "protocol": "mqttv5" if protocol == mqtt.MQTTv5 else "mqttv311",
        },
        "connect": _summarize_ms(connect_lat),
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
    p.add_argument("--mqtt5", action="store_true")
    p.add_argument("--sync-connect", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    protocol = mqtt.MQTTv5 if args.mqtt5 else mqtt.MQTTv311

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
    )

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(res)


if __name__ == "__main__":
    main()
