import contextlib
import json
import os
import queue
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, cast

import httpx
import numpy as np
import typer

try:
    import paho.mqtt.client as mqtt
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing dependency 'paho-mqtt'. Install it with: pip install paho-mqtt"
    ) from exc

from benchmarks.logging_utils import get_logger, setup_logging

logger = get_logger(__name__)
app = typer.Typer(add_completion=False)
BISCUIT_ATTENUATE_DENY_OPTION = typer.Option(None, "--biscuit-attenuate-deny")
BISCUIT_ATTENUATE_CHECK_OPTION = typer.Option(None, "--biscuit-attenuate-check")
BISCUIT_DELEGATE_DENY_OPTION = typer.Option(None, "--biscuit-delegate-deny")
BISCUIT_DELEGATE_CHECK_OPTION = typer.Option(None, "--biscuit-delegate-check")


def _percentile(values, p):
    if not values:
        return None
    return float(np.percentile(values, p))


def _summarize_ms(vals):
    if not vals:
        return {"count": 0}
    arr = np.array(vals, dtype=float)
    return {
        "count": int(arr.size),
        "min_ms": float(np.min(arr)),
        "p50_ms": _percentile(arr, 50),
        "p95_ms": _percentile(arr, 95),
        "p99_ms": _percentile(arr, 99),
        "max_ms": float(np.max(arr)),
        "mean_ms": float(np.mean(arr)),
        "median_ms": float(np.median(arr)),
    }


def _parse_qos_distribution(raw: str | None) -> list[tuple[int, float]] | None:
    if raw is None:
        return None
    entries: list[tuple[int, float]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"invalid qos distribution entry: {part}")
        qos_str, weight_str = part.split(":", 1)
        qos = int(qos_str.strip())
        if qos not in (0, 1, 2):
            raise ValueError(f"invalid qos value: {qos}")
        weight = float(weight_str.strip())
        if weight <= 0:
            raise ValueError(f"invalid qos weight: {weight}")
        entries.append((qos, weight))
    if not entries:
        return None
    total = sum(weight for _, weight in entries)
    if total <= 0:
        raise ValueError("qos distribution weights must sum to a positive value")
    return [(qos, weight / total) for qos, weight in entries]


def _choose_qos(
    default_qos: int,
    distribution: list[tuple[int, float]] | None,
    rng: np.random.Generator,
) -> int:
    if not distribution:
        return default_qos
    qos_values = [qos for qos, _ in distribution]
    qos_weights = [weight for _, weight in distribution]
    return int(rng.choice(qos_values, p=qos_weights))


def _effective_subscribe_qos(
    default_qos: int,
    distribution: list[tuple[int, float]] | None,
) -> int:
    if not distribution:
        return default_qos
    # For fan-out reads, subscribe at the highest QoS in the mix to avoid
    # downgrading deliveries when publishers use higher QoS levels.
    return max(qos for qos, _ in distribution)


@dataclass
class WorkerConfig:
    host: str
    port: int
    client_id: str
    username: str
    password: str
    topic: str
    qos: int
    qos_distribution: list[tuple[int, float]] | None
    message_count: int
    message_size: int
    protocol: int
    sync_connect: bool
    token_issuer_url: str | None
    token_issuer_kind: str | None
    token_issuer_ttl: int | None
    token_issuer_no_default_roles: bool
    token_issuer_no_default_grants: bool
    token_refresh_codes: set[int]
    tls_enabled: bool
    tls_ca_file: str | None
    tls_insecure: bool
    mode: str
    subscribe_topic: str | None
    expect_messages: int
    biscuit_attenuate: bool
    biscuit_attenuate_denies: list[str]
    biscuit_attenuate_checks: list[str]
    biscuit_attenuate_topic: str | None
    biscuit_attenuate_operation: str | None
    biscuit_attenuate_ttl: int | None
    biscuit_public_key_hex: str | None
    biscuit_public_key_file: str | None
    biscuit_attenuate_bin: str | None
    biscuit_delegate: bool
    biscuit_delegate_denies: list[str]
    biscuit_delegate_checks: list[str]
    biscuit_delegate_topic: str | None
    biscuit_delegate_operation: str | None
    biscuit_delegate_ttl: int | None
    biscuit_delegate_public_key_hex: str | None
    biscuit_delegate_public_key_file: str | None
    biscuit_delegate_bin: str | None
    biscuit_delegate_handoff: bool
    biscuit_delegate_handoff_topic: str | None
    biscuit_delegate_handoff_token: str | None
    biscuit_delegate_handoff_qos: int
    biscuit_delegate_handoff_retain: bool
    biscuit_delegate_handoff_nonce: str | None
    delegation_ms: float | None
    delegation_len: int | None
    control_topic: str | None
    control_payload: dict[str, Any] | None
    control_mode: bool
    control_repeat: int
    control_qos: int
    # Issue 36: Interleaved control message support
    control_after_messages: int


@dataclass
class WorkerResult:
    client_id: str
    connect_ms: float | None
    publish_ms: list[float]
    receive_ms: list[float]
    token_refresh_ms: float | None
    token_refresh_len: int | None
    delegation_ms: float | None
    delegation_len: int | None
    attenuation_ms: float | None
    attenuation_len: int | None
    errors: list[str]
    # CONTROL message metrics
    control_publish_ms: list[float]
    control_errors: list[str]
    # Issue 36: Interleaved control metrics
    control_injection_delay_ms: list[float]


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
    no_default_grants: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
) -> str:
    payload = {"client_id": client_id, "ttl_seconds": ttl}
    if kind == "biscuit":
        payload["topic"] = topic
    if no_default_roles:
        payload["no_default_roles"] = True
    if no_default_grants:
        payload["no_default_grants"] = True

    verify: bool | str = True
    if tls_insecure:
        verify = False
    elif tls_ca_file:
        verify = tls_ca_file
    transport = httpx.HTTPTransport(http1=False, http2=True)
    with httpx.Client(verify=verify, timeout=5.0, transport=transport) as client:
        resp = client.post(
            issuer_url.rstrip("/") + f"/{kind}",
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        body = resp.json()
    token = body.get("token")
    if not token:
        raise ValueError("token issuer response missing token")
    return token


def _resolve_attenuate_cmd(custom_bin: str | None) -> list[str]:
    if custom_bin:
        return [custom_bin]
    env_bin = os.environ.get("BISCUIT_ATTENUATE_BIN")
    if env_bin:
        return [env_bin]
    repo_root = os.path.dirname(os.path.dirname(__file__))
    for candidate in [
        os.path.join(repo_root, "target", "release", "biscuit-attenuate"),
        os.path.join(repo_root, "target", "debug", "biscuit-attenuate"),
    ]:
        if os.path.exists(candidate):
            return [candidate]
    raise FileNotFoundError(
        "biscuit-attenuate binary not found; build it first "
        "(cargo build -p gen-tokens --bin biscuit-attenuate)"
    )


def _build_biscuit_attenuate_cmd(
    token: str,
    *,
    custom_bin: str | None,
    public_key_hex: str | None,
    public_key_file: str | None,
    restrict_topic: str | None,
    restrict_operation: str | None,
    ttl_seconds: int | None,
    denies: list[str],
    checks: list[str],
) -> list[str]:
    cmd = _resolve_attenuate_cmd(custom_bin)
    cmd.extend(["--token", token])
    if public_key_hex:
        cmd.extend(["--public-key-hex", public_key_hex])
    if public_key_file:
        cmd.extend(["--public-key-file", public_key_file])
    if restrict_topic:
        cmd.extend(["--restrict-topic", restrict_topic])
    if restrict_operation:
        cmd.extend(["--restrict-op", restrict_operation])
    if ttl_seconds is not None:
        cmd.extend(["--ttl-seconds", str(ttl_seconds)])
    for deny in denies:
        cmd.extend(["--deny", deny])
    for check in checks:
        cmd.extend(["--check", check])
    return cmd


def _attenuate_biscuit_token(token: str, cfg: WorkerConfig) -> tuple[str, float, int]:
    cmd = _build_biscuit_attenuate_cmd(
        token,
        custom_bin=cfg.biscuit_attenuate_bin,
        public_key_hex=cfg.biscuit_public_key_hex,
        public_key_file=cfg.biscuit_public_key_file,
        restrict_topic=cfg.biscuit_attenuate_topic,
        restrict_operation=cfg.biscuit_attenuate_operation,
        ttl_seconds=cfg.biscuit_attenuate_ttl,
        denies=cfg.biscuit_attenuate_denies,
        checks=cfg.biscuit_attenuate_checks,
    )

    t0 = time.perf_counter()
    output = subprocess.check_output(
        cmd,
        cwd=os.path.dirname(os.path.dirname(__file__)),
    ).decode("utf-8")
    t1 = time.perf_counter()
    token_out = output.strip()
    if not token_out:
        raise ValueError("attenuation produced empty token")
    return token_out, (t1 - t0) * 1000.0, len(token_out)


def _delegate_biscuit_token(
    token: str,
    *,
    custom_bin: str | None,
    public_key_hex: str | None,
    public_key_file: str | None,
    restrict_topic: str | None,
    restrict_operation: str | None,
    ttl_seconds: int | None,
    denies: list[str],
    checks: list[str],
) -> tuple[str, float, int]:
    cmd = _build_biscuit_attenuate_cmd(
        token,
        custom_bin=custom_bin,
        public_key_hex=public_key_hex,
        public_key_file=public_key_file,
        restrict_topic=restrict_topic,
        restrict_operation=restrict_operation,
        ttl_seconds=ttl_seconds,
        denies=denies,
        checks=checks,
    )

    t0 = time.perf_counter()
    output = subprocess.check_output(
        cmd,
        cwd=os.path.dirname(os.path.dirname(__file__)),
    ).decode("utf-8")
    t1 = time.perf_counter()
    token_out = output.strip()
    if not token_out:
        raise ValueError("delegation produced empty token")
    return token_out, (t1 - t0) * 1000.0, len(token_out)


def _publish_delegated_tokens(
    host: str,
    port: int,
    username: str,
    password: str,
    tokens_by_client: dict[str, str],
    topic: str,
    qos: int,
    retain: bool,
    nonce: str | None,
    protocol: int,
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
) -> list[str]:
    errors: list[str] = []
    client = cast(Any, mqtt.Client)(
        client_id="delegation_master",
        protocol=cast(Any, protocol),
        callback_api_version=cast(Any, mqtt.CallbackAPIVersion.VERSION2),
    )
    client.username_pw_set(username, password)
    if tls_enabled:
        if tls_ca_file:
            client.tls_set(ca_certs=tls_ca_file)
        else:
            client.tls_set()
        if tls_insecure:
            client.tls_insecure_set(True)

    try:
        client.connect(host, port, 30)
    except Exception as e:
        return [f"delegation_master_connect_failed:{e}"]

    client.loop_start()
    time.sleep(0.2)

    for client_id, token in tokens_by_client.items():
        payload = json.dumps({"client_id": client_id, "token": token, "nonce": nonce}).encode(
            "utf-8"
        )
        try:
            info = client.publish(topic, payload, qos=qos, retain=retain)
            info.wait_for_publish(timeout=10)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                errors.append(f"delegation_master_publish_rc:{info.rc}")
        except Exception as e:
            errors.append(f"delegation_master_publish_failed:{e}")

    with contextlib.suppress(Exception):
        client.disconnect()
    with contextlib.suppress(Exception):
        client.loop_stop()
    return errors


def _receive_delegated_token(
    cfg: WorkerConfig,
    timeout_s: float = 10.0,
) -> str:
    token_holder: dict[str, str | None] = {"token": None}
    errors: list[str] = []
    event = threading.Event()

    def on_message(client, ud, msg):
        try:
            payload = json.loads((msg.payload or b"").decode("utf-8"))
        except Exception:
            return
        if payload.get("client_id") != cfg.client_id:
            return
        if (
            cfg.biscuit_delegate_handoff_nonce
            and payload.get("nonce") != cfg.biscuit_delegate_handoff_nonce
        ):
            return
        token = payload.get("token")
        if token:
            token_holder["token"] = token
            event.set()

    client = cast(Any, mqtt.Client)(
        client_id=f"handoff_{cfg.client_id}",
        protocol=cast(Any, cfg.protocol),
        callback_api_version=cast(Any, mqtt.CallbackAPIVersion.VERSION2),
    )
    client.user_data_set(token_holder)
    client.username_pw_set(cfg.username, cfg.biscuit_delegate_handoff_token)
    if cfg.tls_enabled:
        if cfg.tls_ca_file:
            client.tls_set(ca_certs=cfg.tls_ca_file)
        else:
            client.tls_set()
        if cfg.tls_insecure:
            client.tls_insecure_set(True)
    client.on_message = on_message

    try:
        client.connect(cfg.host, cfg.port, 30)
    except Exception as e:
        raise ValueError(f"delegation_handoff_connect_failed:{e}") from e

    client.loop_start()
    try:
        topic = cfg.biscuit_delegate_handoff_topic
        if topic is None:
            raise ValueError("biscuit_delegate_handoff_topic is required")
        res, _ = client.subscribe(topic, qos=cfg.biscuit_delegate_handoff_qos)
        if res != mqtt.MQTT_ERR_SUCCESS:
            errors.append(f"delegation_handoff_subscribe_rc:{res}")
    except Exception as e:
        errors.append(f"delegation_handoff_subscribe_failed:{e}")

    event.wait(timeout_s)
    with contextlib.suppress(Exception):
        client.disconnect()
    with contextlib.suppress(Exception):
        client.loop_stop()

    if errors:
        raise ValueError(",".join(errors))
    token = token_holder["token"]
    if not token:
        raise ValueError("delegation_handoff_timeout")
    return token


def _run_worker(cfg: WorkerConfig, start_evt: threading.Event, out_q: queue.Queue):
    errors: list[str] = []
    publish_ms: list[float] = []
    receive_ms: list[float] = []
    connect_ms = None
    qos_rng = np.random.default_rng()
    token_refresh_ms = None
    token_refresh_len = None
    delegation_ms = cfg.delegation_ms
    delegation_len = cfg.delegation_len
    attenuation_ms = None
    attenuation_len = None

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

        def on_message(client, ud, msg):
            if cfg.mode != "fanout":
                return
            payload = msg.payload or b""
            try:
                prefix = payload.split(b"|", 1)[0]
                sent_ts = float(prefix.decode("utf-8"))
                receive_ms.append((time.perf_counter() - sent_ts) * 1000.0)
            except Exception:
                errors.append("message_parse_failed")

        client = cast(Any, mqtt.Client)(
            client_id=cfg.client_id,
            protocol=cast(Any, cfg.protocol),
            callback_api_version=cast(Any, mqtt.CallbackAPIVersion.VERSION2),
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
        client.on_message = on_message

        if cfg.sync_connect:
            start_evt.wait()

        try:
            userdata["connect_start"] = time.perf_counter()
            client.connect(cfg.host, cfg.port, 30)
        except Exception as e:
            return None, f"connect_failed:{e}", None, None

        client.loop_start()

        t_deadline = time.time() + 10
        while (
            not userdata["connected"]
            and userdata["connect_reason"] is None
            and time.time() < t_deadline
        ):
            time.sleep(0.01)

        if not userdata["connected"]:
            reason = userdata["connect_reason"]
            with contextlib.suppress(Exception):
                client.loop_stop()
            with contextlib.suppress(Exception):
                client.disconnect()
            if reason is None:
                return None, "connect_timeout", reason, userdata
            return None, f"connect_denied:{reason}", reason, userdata

        return client, None, None, userdata

    password = cfg.password
    token_refreshed = False
    client = None
    userdata = None

    if cfg.biscuit_attenuate:
        try:
            password, attenuation_ms, attenuation_len = _attenuate_biscuit_token(password, cfg)
        except Exception as e:
            errors.append(f"attenuation_failed:{e}")
            logger.exception("Biscuit attenuation failed", exc_info=e)
            out_q.put(
                WorkerResult(
                    cfg.client_id,
                    None,
                    [],
                    [],
                    token_refresh_ms,
                    token_refresh_len,
                    delegation_ms,
                    delegation_len,
                    attenuation_ms,
                    attenuation_len,
                    errors,
                )
            )
            return

    if cfg.biscuit_delegate_handoff:
        try:
            password = _receive_delegated_token(cfg)
        except Exception as e:
            errors.append(str(e))
            logger.exception("Delegation handoff failed", exc_info=e)
            out_q.put(
                WorkerResult(
                    cfg.client_id,
                    None,
                    [],
                    [],
                    token_refresh_ms,
                    token_refresh_len,
                    delegation_ms,
                    delegation_len,
                    attenuation_ms,
                    attenuation_len,
                    errors,
                )
            )
            return

    for _ in range(2):
        client, err, reason, connect_userdata = attempt_connect(password)
        if client is not None:
            userdata = connect_userdata
            break

        if token_refreshed:
            errors.append(err)
            out_q.put(
                WorkerResult(
                    cfg.client_id,
                    None,
                    [],
                    [],
                    token_refresh_ms,
                    token_refresh_len,
                    delegation_ms,
                    delegation_len,
                    attenuation_ms,
                    attenuation_len,
                    errors,
                )
            )
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
                    cfg.token_issuer_no_default_grants,
                    cfg.tls_ca_file,
                    cfg.tls_insecure,
                )
                token_refresh_ms = (time.perf_counter() - t_refresh_start) * 1000.0
                token_refresh_len = len(password)
                token_refreshed = True
                continue
            except Exception as e:
                errors.append(f"token_refresh_failed:{e}")
                logger.exception("Token refresh failed", exc_info=e)
                out_q.put(
                    WorkerResult(
                        cfg.client_id,
                        None,
                        [],
                        [],
                        token_refresh_ms,
                        token_refresh_len,
                        delegation_ms,
                        delegation_len,
                        attenuation_ms,
                        attenuation_len,
                        errors,
                        [],
                        [],
                    )
                )
                return

        errors.append(err)
        out_q.put(
            WorkerResult(
                cfg.client_id,
                None,
                [],
                [],
                token_refresh_ms,
                token_refresh_len,
                delegation_ms,
                delegation_len,
                attenuation_ms,
                attenuation_len,
                errors,
                [],
                [],
            )
        )
        return

    if userdata is None or client is None:
        errors.append("connect_failed")
        out_q.put(
            WorkerResult(
                cfg.client_id,
                None,
                [],
                [],
                token_refresh_ms,
                token_refresh_len,
                delegation_ms,
                delegation_len,
                attenuation_ms,
                attenuation_len,
                errors,
                [],
                [],
            )
        )
        return

    connect_ms = (userdata["connect_done"] - userdata["connect_start"]) * 1000.0

    if not cfg.sync_connect:
        start_evt.wait()

    # CONTROL message publishing support
    control_publish_ms: list[float] = []
    control_errors: list[str] = []

    if cfg.control_mode and cfg.control_topic and cfg.control_payload:
        for _ in range(cfg.control_repeat):
            try:
                t0 = time.perf_counter()
                payload = json.dumps(cfg.control_payload).encode()
                info = client.publish(
                    cfg.control_topic,
                    payload,
                    qos=cfg.control_qos,
                )
                info.wait_for_publish(timeout=10)
                t1 = time.perf_counter()
                control_publish_ms.append((t1 - t0) * 1000.0)
                if info.rc != mqtt.MQTT_ERR_SUCCESS:
                    control_errors.append(f"control_publish_rc:{info.rc}")
            except Exception as e:
                control_errors.append(f"control_publish_failed:{e}")
                break

    if cfg.mode == "fanout":
        if not cfg.subscribe_topic:
            errors.append("fanout_missing_topic")
        else:
            try:
                subscribe_qos = _effective_subscribe_qos(cfg.qos, cfg.qos_distribution)
                res, _ = client.subscribe(cfg.subscribe_topic, qos=subscribe_qos)
                if res != mqtt.MQTT_ERR_SUCCESS:
                    errors.append(f"subscribe_rc:{res}")
            except Exception as e:
                errors.append(f"subscribe_failed:{e}")

        start_evt.wait()
        deadline = time.time() + max(10.0, cfg.expect_messages * 0.2)
        while len(receive_ms) < cfg.expect_messages and time.time() < deadline:
            time.sleep(0.01)
    else:
        payload = _mk_payload(cfg.message_size)
        message_counter = 0
        # Issue 36: Interleaved control message support
        interleave_enabled = (
            cfg.control_after_messages > 0
            and cfg.control_topic
            and cfg.control_payload
            and not cfg.control_mode
        )
        control_injection_delay_ms: list[float] = []

        for _ in range(cfg.message_count):
            # Issue 36: Check if we need to inject a control message
            if interleave_enabled and message_counter >= cfg.control_after_messages:
                injection_start = time.perf_counter()
                try:
                    ctrl_payload = json.dumps(cfg.control_payload).encode()
                    t0 = time.perf_counter()
                    info = client.publish(cfg.control_topic, ctrl_payload, qos=cfg.control_qos)
                    info.wait_for_publish(timeout=10)
                    t1 = time.perf_counter()
                    control_publish_ms.append((t1 - t0) * 1000.0)
                    if info.rc != mqtt.MQTT_ERR_SUCCESS:
                        control_errors.append(f"control_publish_rc:{info.rc}")
                except Exception as e:
                    control_errors.append(f"control_publish_failed:{e}")
                injection_end = time.perf_counter()
                control_injection_delay_ms.append((injection_end - injection_start) * 1000.0)
                message_counter = 0

            try:
                t0 = time.perf_counter()
                publish_qos = _choose_qos(cfg.qos, cfg.qos_distribution, qos_rng)
                info = client.publish(cfg.topic, payload, qos=publish_qos)
                info.wait_for_publish(timeout=10)
                t1 = time.perf_counter()
                publish_ms.append((t1 - t0) * 1000.0)
                message_counter += 1
                if info.rc != mqtt.MQTT_ERR_SUCCESS:
                    errors.append(f"publish_rc:{info.rc}")
            except Exception as e:
                errors.append(f"publish_failed:{e}")
                break

    with contextlib.suppress(Exception):
        client.disconnect()

    t_deadline = time.time() + 5
    while not userdata["disconnected"] and time.time() < t_deadline:
        time.sleep(0.01)

    with contextlib.suppress(Exception):
        client.loop_stop()

    out_q.put(
        WorkerResult(
            cfg.client_id,
            connect_ms,
            publish_ms,
            receive_ms,
            token_refresh_ms,
            token_refresh_len,
            cfg.delegation_ms,
            cfg.delegation_len,
            attenuation_ms,
            attenuation_len,
            errors,
            control_publish_ms,
            control_errors,
            control_injection_delay_ms,
        )
    )


def _run_fanout_publisher(
    host: str,
    port: int,
    username: str,
    password: str,
    client_id: str,
    topic: str,
    message_count: int,
    qos: int,
    qos_distribution: list[tuple[int, float]] | None,
    message_size: int,
    protocol: int,
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
):
    publish_ms: list[float] = []
    errors: list[str] = []
    qos_rng = np.random.default_rng()

    client = cast(Any, mqtt.Client)(
        client_id=client_id,
        protocol=cast(Any, protocol),
        callback_api_version=cast(Any, mqtt.CallbackAPIVersion.VERSION2),
    )
    client.username_pw_set(username, password)
    if tls_enabled:
        if tls_ca_file:
            client.tls_set(ca_certs=tls_ca_file)
        else:
            client.tls_set()
        if tls_insecure:
            client.tls_insecure_set(True)

    try:
        client.connect(host, port, 30)
    except Exception as e:
        return publish_ms, [f"fanout_connect_failed:{e}"]

    client.loop_start()
    time.sleep(0.2)

    for _ in range(message_count):
        try:
            sent_ts = time.perf_counter()
            payload = f"{sent_ts:.9f}|".encode()
            if message_size > len(payload):
                payload += b"A" * (message_size - len(payload))
            t0 = time.perf_counter()
            publish_qos = _choose_qos(qos, qos_distribution, qos_rng)
            info = client.publish(topic, payload, qos=publish_qos)
            info.wait_for_publish(timeout=10)
            t1 = time.perf_counter()
            publish_ms.append((t1 - t0) * 1000.0)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                errors.append(f"fanout_publish_rc:{info.rc}")
        except Exception as e:
            errors.append(f"fanout_publish_failed:{e}")
            break

    with contextlib.suppress(Exception):
        client.disconnect()
    with contextlib.suppress(Exception):
        client.loop_stop()

    return publish_ms, errors


def run_load(
    host: str,
    port: int,
    username: str,
    password: str,
    fanout_publisher_username: str | None,
    fanout_publisher_password: str | None,
    topic_template: str,
    clients: int,
    message_count: int,
    qos: int,
    qos_distribution: list[tuple[int, float]] | None,
    message_size: int,
    protocol: int,
    sync_connect: bool,
    token_issuer_url: str | None,
    token_issuer_kind: str | None,
    token_issuer_ttl: int | None,
    token_issuer_no_default_roles: bool,
    token_issuer_no_default_grants: bool,
    token_refresh_codes: set[int],
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
    mode: str = "publish",
    fanout_topic: str | None = None,
    biscuit_attenuate: bool = False,
    biscuit_attenuate_denies: list[str] | None = None,
    biscuit_attenuate_checks: list[str] | None = None,
    biscuit_attenuate_topic: str | None = None,
    biscuit_attenuate_operation: str | None = None,
    biscuit_attenuate_ttl: int | None = None,
    biscuit_public_key_hex: str | None = None,
    biscuit_public_key_file: str | None = None,
    biscuit_attenuate_bin: str | None = None,
    biscuit_delegate: bool = False,
    biscuit_delegate_denies: list[str] | None = None,
    biscuit_delegate_checks: list[str] | None = None,
    biscuit_delegate_topic: str | None = None,
    biscuit_delegate_operation: str | None = None,
    biscuit_delegate_ttl: int | None = None,
    biscuit_delegate_public_key_hex: str | None = None,
    biscuit_delegate_public_key_file: str | None = None,
    biscuit_delegate_bin: str | None = None,
    biscuit_delegate_handoff: bool = False,
    biscuit_delegate_handoff_topic: str | None = None,
    biscuit_delegate_handoff_token: str | None = None,
    biscuit_delegate_handoff_qos: int | None = 1,
    biscuit_delegate_handoff_no_retain: bool = False,
    # CONTROL message parameters
    control_topic: str | None = None,
    control_payload: dict[str, Any] | None = None,
    control_mode: bool = False,
    control_repeat: int = 1,
    control_qos: int = 1,
    # Issue 36: Interleaved control message parameter
    control_after_messages: int = 0,
):
    start_evt = threading.Event()
    out_q: queue.Queue = queue.Queue()

    threads: list[threading.Thread] = []
    expected_results = clients

    attenuate_denies = biscuit_attenuate_denies or []
    attenuate_checks = biscuit_attenuate_checks or []
    delegate_denies = biscuit_delegate_denies or []
    delegate_checks = biscuit_delegate_checks or []
    handoff_topic = (
        biscuit_delegate_handoff_topic or "delegation/handoff" if biscuit_delegate_handoff else None
    )
    handoff_qos = biscuit_delegate_handoff_qos or 1
    handoff_retain = not biscuit_delegate_handoff_no_retain
    handoff_nonce = uuid.uuid4().hex if biscuit_delegate_handoff else None
    if biscuit_delegate_handoff and not biscuit_delegate_handoff_token:
        raise ValueError("biscuit_delegate_handoff_token is required")
    if biscuit_delegate_handoff and biscuit_delegate_handoff_topic is None:
        raise ValueError("biscuit_delegate_handoff_topic is required")

    delegated_tokens_by_client: dict[str, str] = {}
    for i in range(clients):
        client_id = f"client_{i + 1}"
        topic = topic_template.format(client_id=client_id)
        formatted_denies = [spec.format(client_id=client_id) for spec in attenuate_denies]
        formatted_checks = [spec.format(client_id=client_id) for spec in attenuate_checks]
        formatted_delegate_denies = [spec.format(client_id=client_id) for spec in delegate_denies]
        formatted_delegate_checks = [spec.format(client_id=client_id) for spec in delegate_checks]
        formatted_topic = (
            biscuit_attenuate_topic.format(client_id=client_id) if biscuit_attenuate_topic else None
        )
        formatted_delegate_topic = (
            biscuit_delegate_topic.format(client_id=client_id) if biscuit_delegate_topic else None
        )
        delegation_ms = None
        delegation_len = None
        delegated_password = password
        if biscuit_delegate:
            try:
                delegated_password, delegation_ms, delegation_len = _delegate_biscuit_token(
                    password,
                    custom_bin=biscuit_delegate_bin,
                    public_key_hex=biscuit_delegate_public_key_hex,
                    public_key_file=biscuit_delegate_public_key_file,
                    restrict_topic=formatted_delegate_topic,
                    restrict_operation=biscuit_delegate_operation,
                    ttl_seconds=biscuit_delegate_ttl,
                    denies=formatted_delegate_denies,
                    checks=formatted_delegate_checks,
                )
            except Exception as e:
                out_q.put(
                    WorkerResult(
                        client_id,
                        None,
                        [],
                        [],
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        [f"delegation_failed:{e}"],
                        [],
                        [],
                    )
                )
                continue
        if biscuit_delegate and biscuit_delegate_handoff:
            delegated_tokens_by_client[client_id] = delegated_password
            delegated_password = password
        cfg = WorkerConfig(
            host=host,
            port=port,
            client_id=client_id,
            username=username,
            password=delegated_password,
            topic=topic,
            qos=qos,
            qos_distribution=qos_distribution,
            message_count=message_count,
            message_size=message_size,
            protocol=protocol,
            sync_connect=sync_connect,
            token_issuer_url=token_issuer_url,
            token_issuer_kind=token_issuer_kind,
            token_issuer_ttl=token_issuer_ttl,
            token_issuer_no_default_roles=token_issuer_no_default_roles,
            token_issuer_no_default_grants=token_issuer_no_default_grants,
            token_refresh_codes=token_refresh_codes,
            tls_enabled=tls_enabled,
            tls_ca_file=tls_ca_file,
            tls_insecure=tls_insecure,
            mode=mode,
            subscribe_topic=fanout_topic,
            expect_messages=message_count if mode == "fanout" else 0,
            biscuit_attenuate=biscuit_attenuate,
            biscuit_attenuate_denies=formatted_denies,
            biscuit_attenuate_checks=formatted_checks,
            biscuit_attenuate_topic=formatted_topic,
            biscuit_attenuate_operation=biscuit_attenuate_operation,
            biscuit_attenuate_ttl=biscuit_attenuate_ttl,
            biscuit_public_key_hex=biscuit_public_key_hex,
            biscuit_public_key_file=biscuit_public_key_file,
            biscuit_attenuate_bin=biscuit_attenuate_bin,
            biscuit_delegate=biscuit_delegate,
            biscuit_delegate_denies=formatted_delegate_denies,
            biscuit_delegate_checks=formatted_delegate_checks,
            biscuit_delegate_topic=formatted_delegate_topic,
            biscuit_delegate_operation=biscuit_delegate_operation,
            biscuit_delegate_ttl=biscuit_delegate_ttl,
            biscuit_delegate_public_key_hex=biscuit_delegate_public_key_hex,
            biscuit_delegate_public_key_file=biscuit_delegate_public_key_file,
            biscuit_delegate_bin=biscuit_delegate_bin,
            biscuit_delegate_handoff=biscuit_delegate_handoff,
            biscuit_delegate_handoff_topic=handoff_topic,
            biscuit_delegate_handoff_token=biscuit_delegate_handoff_token,
            biscuit_delegate_handoff_qos=handoff_qos,
            biscuit_delegate_handoff_retain=handoff_retain,
            biscuit_delegate_handoff_nonce=handoff_nonce,
            delegation_ms=delegation_ms,
            delegation_len=delegation_len,
            control_topic=control_topic,
            control_payload=control_payload,
            control_mode=control_mode,
            control_repeat=control_repeat,
            control_qos=control_qos,
            control_after_messages=control_after_messages,
        )
        t = threading.Thread(target=_run_worker, args=(cfg, start_evt, out_q), daemon=True)
        threads.append(t)

    for t in threads:
        t.start()

    delegation_errors: list[str] = []
    if biscuit_delegate and biscuit_delegate_handoff and delegated_tokens_by_client:
        delegation_errors = _publish_delegated_tokens(
            host=host,
            port=port,
            username=username,
            password=biscuit_delegate_handoff_token or password,
            tokens_by_client=delegated_tokens_by_client,
            topic=handoff_topic or "delegation/handoff",
            qos=handoff_qos,
            retain=handoff_retain,
            nonce=handoff_nonce,
            protocol=protocol,
            tls_enabled=tls_enabled,
            tls_ca_file=tls_ca_file,
            tls_insecure=tls_insecure,
        )

    time.sleep(0.2)
    t_start = time.perf_counter()
    start_evt.set()

    fanout_publish_ms: list[float] = []
    fanout_errors: list[str] = []
    if mode == "fanout":
        publisher_username = fanout_publisher_username or username
        publisher_password = fanout_publisher_password or password
        fanout_publish_ms, fanout_errors = _run_fanout_publisher(
            host=host,
            port=port,
            username=publisher_username,
            password=publisher_password,
            client_id="fanout_publisher",
            topic=fanout_topic or "fanout/broadcast",
            message_count=message_count,
            qos=qos,
            qos_distribution=qos_distribution,
            message_size=message_size,
            protocol=protocol,
            tls_enabled=tls_enabled,
            tls_ca_file=tls_ca_file,
            tls_insecure=tls_insecure,
        )

    results: list[WorkerResult] = []
    for _ in range(expected_results):
        results.append(out_q.get())

    for t in threads:
        t.join(timeout=1)

    t_end = time.perf_counter()

    connect_lat = [r.connect_ms for r in results if r.connect_ms is not None]
    publish_lat = [x for r in results for x in r.publish_ms]
    receive_lat = [x for r in results for x in r.receive_ms]
    refresh_lat = [r.token_refresh_ms for r in results if r.token_refresh_ms is not None]
    refresh_lens = [r.token_refresh_len for r in results if r.token_refresh_len is not None]
    delegation_lat = [r.delegation_ms for r in results if r.delegation_ms is not None]
    delegation_lens = [r.delegation_len for r in results if r.delegation_len is not None]
    attenuation_lat = [r.attenuation_ms for r in results if r.attenuation_ms is not None]
    attenuation_lens = [r.attenuation_len for r in results if r.attenuation_len is not None]
    control_lat = [x for r in results for x in r.control_publish_ms]
    control_errs = [e for r in results for e in r.control_errors]
    # Issue 36: Aggregate control injection delay metrics
    control_injection_lat = [x for r in results for x in r.control_injection_delay_ms]

    errors = [e for r in results for e in r.errors]
    errors.extend(fanout_errors)
    errors.extend(delegation_errors)
    errors.extend(control_errs)

    duration_s = max(1e-9, t_end - t_start)
    publish_lat.extend(fanout_publish_ms)
    publish_throughput_mps = len(publish_lat) / duration_s
    receive_throughput_mps = len(receive_lat) / duration_s
    throughput_mps = publish_throughput_mps if mode != "fanout" else receive_throughput_mps

    qos_distribution_payload = None
    if qos_distribution:
        qos_distribution_payload = [
            {"qos": qos, "weight": weight} for qos, weight in qos_distribution
        ]
    return {
        "inputs": {
            "host": host,
            "port": port,
            "username": username,
            "fanout_publisher_username": fanout_publisher_username,
            "clients": clients,
            "message_count": message_count,
            "qos": qos,
            "qos_distribution": qos_distribution_payload,
            "message_size": message_size,
            "protocol": "mqttv5",
            "token_issuer_url": token_issuer_url,
            "token_issuer_kind": token_issuer_kind,
            "token_issuer_no_default_roles": token_issuer_no_default_roles,
            "token_issuer_no_default_grants": token_issuer_no_default_grants,
            "token_refresh_codes": sorted(token_refresh_codes),
            "mode": mode,
            "fanout_topic": fanout_topic,
            "biscuit_attenuate": biscuit_attenuate,
            "biscuit_attenuate_denies": attenuate_denies,
            "biscuit_attenuate_checks": attenuate_checks,
            "biscuit_attenuate_topic": biscuit_attenuate_topic,
            "biscuit_attenuate_operation": biscuit_attenuate_operation,
            "biscuit_attenuate_ttl": biscuit_attenuate_ttl,
            "biscuit_public_key_hex": biscuit_public_key_hex,
            "biscuit_public_key_file": biscuit_public_key_file,
            "biscuit_delegate": biscuit_delegate,
            "biscuit_delegate_denies": delegate_denies,
            "biscuit_delegate_checks": delegate_checks,
            "biscuit_delegate_topic": biscuit_delegate_topic,
            "biscuit_delegate_operation": biscuit_delegate_operation,
            "biscuit_delegate_ttl": biscuit_delegate_ttl,
            "biscuit_delegate_public_key_hex": biscuit_delegate_public_key_hex,
            "biscuit_delegate_public_key_file": biscuit_delegate_public_key_file,
            "biscuit_delegate_bin": biscuit_delegate_bin,
            "biscuit_delegate_handoff": biscuit_delegate_handoff,
            "biscuit_delegate_handoff_topic": handoff_topic,
            "biscuit_delegate_handoff_nonce": handoff_nonce,
            "control": {
                "topic": control_topic,
                "mode": control_mode,
                "payload": control_payload,
                "repeat": control_repeat,
                "qos": control_qos,
                # Issue 36: Interleaved control message configuration
                "after_messages": control_after_messages,
            },
        },
        "connect": _summarize_ms(connect_lat),
        "token_refresh": _summarize_ms(refresh_lat),
        "token_refresh_len": _summarize_ms(refresh_lens),
        "delegation": _summarize_ms(delegation_lat),
        "delegation_len": _summarize_ms(delegation_lens),
        "attenuation": _summarize_ms(attenuation_lat),
        "attenuation_len": _summarize_ms(attenuation_lens),
        "publish": _summarize_ms(publish_lat),
        "receive": _summarize_ms(receive_lat),
        "control": _summarize_ms(control_lat),
        # Issue 36: Control injection delay metrics
        "control_injection_delay": _summarize_ms(control_injection_lat),
        "throughput_mps": throughput_mps,
        "publish_throughput_mps": publish_throughput_mps,
        "receive_throughput_mps": receive_throughput_mps,
        "received_messages": {
            "count": len(receive_lat),
            "expected": message_count * clients if mode == "fanout" else 0,
        },
        "errors": errors,
    }


@app.command()
def main(
    host: str = typer.Option("localhost", envvar="MQTT_HOST"),
    port: int = typer.Option(1883, envvar="MQTT_PORT"),
    username: str = typer.Option("jwt", envvar="MQTT_USERNAME"),
    password: str = typer.Option("", envvar="MQTT_PASSWORD"),
    topic: str = typer.Option("sensors/{client_id}/temp", envvar="MQTT_TOPIC"),
    clients: int = typer.Option(10, envvar="MQTT_CLIENTS"),
    messages: int = typer.Option(50, envvar="MQTT_MESSAGES"),
    qos: int = typer.Option(1, envvar="MQTT_QOS"),
    qos_distribution: str | None = typer.Option(
        None,
        "--qos-distribution",
        envvar="MQTT_QOS_DISTRIBUTION",
        help="Comma-separated qos:weight entries (e.g. 0:0.6,1:0.3,2:0.1)",
    ),
    message_size: int = typer.Option(0, envvar="MQTT_MESSAGE_SIZE"),
    sync_connect: bool = False,
    token_issuer_url: str | None = typer.Option(None, envvar="TOKEN_ISSUER_URL"),
    token_issuer_kind: str | None = typer.Option(None, envvar="TOKEN_ISSUER_KIND"),
    token_issuer_ttl: int | None = typer.Option(None, envvar="TOKEN_ISSUER_TTL"),
    token_issuer_no_default_roles: bool = False,
    token_issuer_no_default_grants: bool = False,
    token_refresh_codes: str = typer.Option(
        "5,135",
        envvar="TOKEN_REFRESH_CODES",
        help=(
            "Comma-separated MQTT v5 reason codes that should trigger token refresh "
            "(e.g., 5/0x87 = Not authorized)"
        ),
    ),
    tls: bool = False,
    tls_ca_file: str | None = None,
    tls_insecure: bool = False,
    biscuit_attenuate: bool = False,
    biscuit_attenuate_deny: list[str] = BISCUIT_ATTENUATE_DENY_OPTION,
    biscuit_attenuate_check: list[str] = BISCUIT_ATTENUATE_CHECK_OPTION,
    biscuit_attenuate_topic: str | None = None,
    biscuit_attenuate_op: str | None = None,
    biscuit_attenuate_ttl: int | None = None,
    biscuit_public_key_hex: str | None = None,
    biscuit_public_key_file: str | None = None,
    biscuit_attenuate_bin: str | None = None,
    biscuit_delegate: bool = False,
    biscuit_delegate_deny: list[str] = BISCUIT_DELEGATE_DENY_OPTION,
    biscuit_delegate_check: list[str] = BISCUIT_DELEGATE_CHECK_OPTION,
    biscuit_delegate_topic: str | None = None,
    biscuit_delegate_op: str | None = None,
    biscuit_delegate_ttl: int | None = None,
    biscuit_delegate_public_key_hex: str | None = None,
    biscuit_delegate_public_key_file: str | None = None,
    biscuit_delegate_bin: str | None = None,
    biscuit_delegate_handoff: bool = False,
    biscuit_delegate_handoff_topic: str | None = None,
    biscuit_delegate_handoff_token: str | None = None,
    biscuit_delegate_handoff_qos: int = typer.Option(1, min=0, max=2),
    biscuit_delegate_handoff_no_retain: bool = False,
    # CONTROL message CLI options
    control_topic: str | None = typer.Option(
        None,
        "--control-topic",
        envvar="MQTT_CONTROL_TOPIC",
        help="Topic for control messages (default: $CONTROL/dynamic-security/v1)",
    ),
    control_payload: str | None = typer.Option(
        None,
        "--control-payload",
        envvar="MQTT_CONTROL_PAYLOAD",
        help="JSON payload string for control commands",
    ),
    control_payload_file: str | None = typer.Option(
        None,
        "--control-payload-file",
        envvar="MQTT_CONTROL_PAYLOAD_FILE",
        help="Path to JSON file containing control command payload",
    ),
    control_mode: bool = typer.Option(
        False,
        "--control-mode",
        envvar="MQTT_CONTROL_MODE",
        help="Enable control message mode (publish control messages instead of data)",
    ),
    control_repeat: int = typer.Option(
        1,
        "--control-repeat",
        envvar="MQTT_CONTROL_REPEAT",
        help="Number of control messages to publish",
    ),
    control_qos: int = typer.Option(
        1,
        "--control-qos",
        envvar="MQTT_CONTROL_QOS",
        help="QoS level for control messages (default: 1)",
    ),
    # Issue 36: Interleaved control message CLI option
    control_after_messages: int = typer.Option(
        0,
        "--control-after-messages",
        envvar="MQTT_CONTROL_AFTER_MESSAGES",
        help="Publish 1 control message after every N data messages "
        "(interleaved mode). 0 = disabled.",
    ),
    mode: str = typer.Option("publish", envvar="MQTT_MODE"),
    fanout_topic: str = typer.Option("fanout/broadcast", envvar="MQTT_FANOUT_TOPIC"),
    fanout_publisher_username: str | None = typer.Option(
        None, envvar="MQTT_FANOUT_PUBLISHER_USERNAME"
    ),
    fanout_publisher_password: str | None = typer.Option(
        None, envvar="MQTT_FANOUT_PUBLISHER_PASSWORD"
    ),
    json_output: bool = typer.Option(False, "--json"),
    log_level: str = typer.Option("INFO", "--log-level"),
):
    setup_logging(log_level)

    protocol = mqtt.MQTTv5  # MQTT v5 only

    parsed_refresh_codes = set()
    for part in str(token_refresh_codes).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            parsed_refresh_codes.add(int(part, 0))
        except ValueError as exc:
            raise typer.BadParameter(f"invalid token refresh code: {part}") from exc

    parsed_qos_distribution = None
    if qos_distribution:
        try:
            parsed_qos_distribution = _parse_qos_distribution(qos_distribution)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

    # Parse control payload from string or file
    parsed_control_payload: dict[str, Any] | None = None
    if control_payload:
        try:
            parsed_control_payload = json.loads(control_payload)
        except json.JSONDecodeError as exc:
            raise typer.BadParameter(f"Invalid control payload JSON: {exc}") from exc
    elif control_payload_file:
        try:
            with open(control_payload_file, encoding="utf-8") as f:
                parsed_control_payload = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            raise typer.BadParameter(f"Failed to load control payload file: {exc}") from exc

    # Default control topic if mode enabled but no topic specified
    if control_mode and not control_topic:
        control_topic = "$CONTROL/dynamic-security/v1"

    res = run_load(
        host=host,
        port=port,
        username=username,
        password=password,
        fanout_publisher_username=fanout_publisher_username,
        fanout_publisher_password=fanout_publisher_password,
        topic_template=topic,
        clients=clients,
        message_count=messages,
        qos=qos,
        qos_distribution=parsed_qos_distribution,
        message_size=message_size,
        protocol=protocol,
        sync_connect=sync_connect,
        token_issuer_url=token_issuer_url,
        token_issuer_kind=token_issuer_kind,
        token_issuer_ttl=token_issuer_ttl,
        token_issuer_no_default_roles=token_issuer_no_default_roles,
        token_issuer_no_default_grants=token_issuer_no_default_grants,
        token_refresh_codes=parsed_refresh_codes,
        tls_enabled=tls,
        tls_ca_file=tls_ca_file,
        tls_insecure=tls_insecure,
        mode=mode,
        fanout_topic=fanout_topic,
        biscuit_attenuate=biscuit_attenuate,
        biscuit_attenuate_denies=biscuit_attenuate_deny or [],
        biscuit_attenuate_checks=biscuit_attenuate_check or [],
        biscuit_attenuate_topic=biscuit_attenuate_topic,
        biscuit_attenuate_operation=biscuit_attenuate_op,
        biscuit_attenuate_ttl=biscuit_attenuate_ttl,
        biscuit_public_key_hex=biscuit_public_key_hex,
        biscuit_public_key_file=biscuit_public_key_file,
        biscuit_attenuate_bin=biscuit_attenuate_bin,
        biscuit_delegate=biscuit_delegate,
        biscuit_delegate_denies=biscuit_delegate_deny or [],
        biscuit_delegate_checks=biscuit_delegate_check or [],
        biscuit_delegate_topic=biscuit_delegate_topic,
        biscuit_delegate_operation=biscuit_delegate_op,
        biscuit_delegate_ttl=biscuit_delegate_ttl,
        biscuit_delegate_public_key_hex=biscuit_delegate_public_key_hex,
        biscuit_delegate_public_key_file=biscuit_delegate_public_key_file,
        biscuit_delegate_bin=biscuit_delegate_bin,
        biscuit_delegate_handoff=biscuit_delegate_handoff,
        biscuit_delegate_handoff_topic=biscuit_delegate_handoff_topic,
        biscuit_delegate_handoff_token=biscuit_delegate_handoff_token,
        biscuit_delegate_handoff_qos=biscuit_delegate_handoff_qos,
        biscuit_delegate_handoff_no_retain=biscuit_delegate_handoff_no_retain,
        control_topic=control_topic,
        control_payload=parsed_control_payload,
        control_mode=control_mode,
        control_repeat=control_repeat,
        control_qos=control_qos,
        # Issue 36: Interleaved control message parameter
        control_after_messages=control_after_messages,
    )

    if json_output:
        typer.echo(json.dumps(res, indent=2))
    else:
        typer.echo(res)


if __name__ == "__main__":
    app()
