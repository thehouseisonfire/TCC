from __future__ import annotations

import contextlib
import os
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import paho.mqtt.client as mqtt
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TLS_CA_FILE = REPO_ROOT / "docker" / "tls" / "ca.pem"
TLS_SERVER_CERT_FILE = REPO_ROOT / "docker" / "tls" / "server.pem"
TLS_SERVER_KEY_FILE = REPO_ROOT / "docker" / "tls" / "server.key"
DOCKER_COMPOSE_PROJECT = "issue39_integration"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _normalize_reason_code(reason_code: Any) -> int | None:
    if reason_code is None:
        return None
    value = getattr(reason_code, "value", reason_code)
    if callable(value):
        value = value()
    try:
        return int(value)
    except TypeError, ValueError:
        return None


def _wait_until(predicate: Any, timeout_s: float, step_s: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step_s)
    return False


def _wait_for_port(host: str, port: int, timeout_s: float = 30.0) -> None:
    def _probe() -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return True
            except OSError:
                return False

    if not _wait_until(_probe, timeout_s):
        raise RuntimeError(f"Timed out waiting for TCP {host}:{port}")


def _wait_for_http2_health(url: str, verify: bool | str, timeout_s: float = 30.0) -> None:
    transport = httpx.HTTPTransport(http1=False, http2=True, verify=verify)

    def _probe() -> bool:
        try:
            with httpx.Client(timeout=2.0, transport=transport) as client:
                resp = client.get(url)
                return resp.status_code == 200
        except Exception:
            return False

    if not _wait_until(_probe, timeout_s):
        raise RuntimeError(f"Timed out waiting for health endpoint: {url}")


@dataclass
class IssuedToken:
    token: str
    exp: int


@dataclass
class TokenIssuerClient:
    base_url: str
    verify: bool | str

    def _post_token(self, path: str, payload: dict[str, Any]) -> IssuedToken:
        transport = httpx.HTTPTransport(http1=False, http2=True, verify=self.verify)
        with httpx.Client(timeout=10.0, transport=transport) as client:
            resp = client.post(
                self.base_url.rstrip("/") + path,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            body = resp.json()
        return IssuedToken(token=str(body["token"]), exp=int(body["exp"]))

    def issue_jwt(
        self,
        *,
        client_id: str,
        ttl_seconds: int,
        grants: list[dict[str, str]] | None = None,
        denies: list[dict[str, str]] | None = None,
        no_default_grants: bool = True,
        no_default_roles: bool = True,
    ) -> IssuedToken:
        payload: dict[str, Any] = {
            "client_id": client_id,
            "ttl_seconds": ttl_seconds,
            "no_default_grants": no_default_grants,
            "no_default_roles": no_default_roles,
        }
        if grants is not None:
            payload["grants"] = grants
        if denies is not None:
            payload["denies"] = denies
        return self._post_token("/jwt", payload)

    def issue_biscuit(
        self,
        *,
        client_id: str,
        topic: str,
        ttl_seconds: int,
        denies: list[dict[str, str]] | None = None,
    ) -> IssuedToken:
        payload: dict[str, Any] = {
            "client_id": client_id,
            "topic": topic,
            "ttl_seconds": ttl_seconds,
        }
        if denies is not None:
            payload["denies"] = denies
        return self._post_token("/biscuit", payload)


@dataclass
class ComposeHarness:
    repo_root: Path
    compose_bin: list[str]
    current_tls: bool = False

    def _compose_files(self, tls: bool) -> list[str]:
        files = ["docker/docker-compose.yml"]
        if tls:
            files.append("docker/docker-compose.tls.yml")
        return files

    def _run_compose(
        self,
        args: list[str],
        *,
        tls: bool,
        extra_env: dict[str, str] | None = None,
        check: bool = True,
        capture_output: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["COMPOSE_PROJECT_NAME"] = DOCKER_COMPOSE_PROJECT
        if extra_env:
            env.update(extra_env)

        cmd = list(self.compose_bin)
        for compose_file in self._compose_files(tls):
            cmd.extend(["-f", compose_file])
        cmd.extend(args)
        return subprocess.run(
            cmd,
            cwd=self.repo_root,
            env=env,
            check=check,
            text=True,
            capture_output=capture_output,
        )

    def down(self) -> None:
        for tls in (False, True):
            with contextlib.suppress(Exception):
                self._run_compose(
                    ["down", "--remove-orphans", "--volumes"],
                    tls=tls,
                    check=False,
                )

    def _ensure_tls_assets(self) -> None:
        for path in (TLS_CA_FILE, TLS_SERVER_CERT_FILE, TLS_SERVER_KEY_FILE):
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists() and path.stat().st_size == 0:
                path.unlink()

        if not (
            TLS_CA_FILE.is_file()
            and TLS_SERVER_CERT_FILE.is_file()
            and TLS_SERVER_KEY_FILE.is_file()
        ):
            subprocess.run(
                ["bash", "docker/tls/generate_certs.sh"],
                cwd=self.repo_root,
                check=True,
            )

        for path in (TLS_CA_FILE, TLS_SERVER_CERT_FILE, TLS_SERVER_KEY_FILE):
            if not path.is_file() or path.stat().st_size == 0:
                raise RuntimeError(f"invalid TLS asset: {path}")
            os.chmod(path, 0o644)

    def up(self, *, mosquitto_conf: str, tls: bool) -> None:
        if tls:
            self._ensure_tls_assets()

        self.down()
        self._run_compose(
            ["up", "-d", "--build", "mosquitto", "token-issuer", "authz"],
            tls=tls,
            extra_env={"MOSQUITTO_CONF": mosquitto_conf},
        )
        self.current_tls = tls

        mqtt_port = 8883 if tls else 1883
        issuer_port = 8444 if tls else 8082
        _wait_for_port("127.0.0.1", mqtt_port, timeout_s=60.0)
        issuer_verify: bool | str = not tls
        issuer_url = f"{'https' if tls else 'http'}://localhost:{issuer_port}/health"
        _wait_for_http2_health(issuer_url, verify=issuer_verify, timeout_s=60.0)

    def token_issuer(self, *, tls: bool) -> TokenIssuerClient:
        port = 8444 if tls else 8082
        verify: bool | str = not tls
        base_url = f"{'https' if tls else 'http'}://localhost:{port}"
        return TokenIssuerClient(base_url=base_url, verify=verify)

    def logs(self, service: str = "mosquitto") -> str:
        out = self._run_compose(
            ["logs", "--no-color", service],
            tls=self.current_tls,
            check=False,
            capture_output=True,
        )
        return out.stdout or ""


@dataclass
class ObservedMqttClient:
    host: str
    port: int
    client_id: str
    username: str
    password: str
    tls: bool = False
    tls_ca_file: str | None = None
    tls_insecure: bool = False
    will_topic: str | None = None
    will_payload: str | bytes | None = None
    will_qos: int = 0
    will_retain: bool = False
    _messages: list[tuple[str, bytes]] = field(default_factory=list)
    _subacks: dict[int, list[int]] = field(default_factory=dict)
    _pubacks: dict[int, int | None] = field(default_factory=dict)
    connect_reason: int | None = None
    disconnect_reason: int | None = None

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._connect_done = threading.Event()
        self._disconnected = threading.Event()
        try:
            self._client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=self.client_id,
                protocol=mqtt.MQTTv5,
                reconnect_on_failure=False,
            )
        except TypeError:
            # Backward-compatible fallback for older paho versions.
            self._client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=self.client_id,
                protocol=mqtt.MQTTv5,
            )
        if self.will_topic is not None:
            self._client.will_set(
                topic=self.will_topic,
                payload=self.will_payload,
                qos=self.will_qos,
                retain=self.will_retain,
            )
        if self.username or self.password:
            self._client.username_pw_set(self.username, self.password)
        if self.tls:
            self._client.tls_set(ca_certs=self.tls_ca_file)
            if self.tls_insecure:
                self._client.tls_insecure_set(True)
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message
        self._client.on_subscribe = self._on_subscribe
        self._client.on_publish = self._on_publish

    def _on_connect(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        _connect_flags: Any,
        reason_code: Any,
        _properties: Any = None,
    ) -> None:
        self.connect_reason = _normalize_reason_code(reason_code)
        self._connect_done.set()

    def _on_disconnect(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        _disconnect_flags: Any,
        reason_code: Any,
        _properties: Any = None,
    ) -> None:
        self.disconnect_reason = _normalize_reason_code(reason_code)
        self._disconnected.set()

    def _on_message(self, _client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
        with self._lock:
            self._messages.append((msg.topic, msg.payload or b""))

    def _on_subscribe(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        mid: int,
        reason_codes: list[Any] | None,
        _properties: Any = None,
    ) -> None:
        codes = [_normalize_reason_code(code) or -1 for code in reason_codes or []]
        with self._lock:
            self._subacks[mid] = codes

    def _on_publish(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        mid: int,
        reason_code: Any,
        _properties: Any = None,
    ) -> None:
        with self._lock:
            self._pubacks[mid] = _normalize_reason_code(reason_code)

    @property
    def message_count(self) -> int:
        with self._lock:
            return len(self._messages)

    def message_count_for_topic(self, topic: str) -> int:
        with self._lock:
            return sum(1 for msg_topic, _ in self._messages if msg_topic == topic)

    def connect(self, timeout_s: float = 10.0) -> None:
        self._client.connect(self.host, self.port, 30)
        self._client.loop_start()
        if not self._connect_done.wait(timeout=timeout_s):
            raise AssertionError(f"{self.client_id}: timed out waiting for CONNACK")
        if self.connect_reason != 0:
            raise AssertionError(
                f"{self.client_id}: connect failed with reason {self.connect_reason}"
            )

    def subscribe(self, topic: str, qos: int = 1, timeout_s: float = 5.0) -> list[int]:
        rc, mid = self._client.subscribe(topic, qos=qos)
        if rc != mqtt.MQTT_ERR_SUCCESS:
            raise AssertionError(f"{self.client_id}: subscribe rc={rc}")
        if mid is None:
            raise AssertionError(f"{self.client_id}: subscribe returned no message id")

        if not _wait_until(lambda: mid in self._subacks, timeout_s):
            raise AssertionError(f"{self.client_id}: no SUBACK for mid={mid}")
        with self._lock:
            suback = self._subacks.get(mid)
        if suback is None:
            raise AssertionError(f"{self.client_id}: missing SUBACK payload for mid={mid}")
        return list(suback)

    def publish(
        self,
        topic: str,
        payload: str | bytes,
        qos: int = 1,
        timeout_s: float = 5.0,
    ) -> int | None:
        info = self._client.publish(topic, payload, qos=qos)
        if qos == 0:
            return None
        info.wait_for_publish(timeout=timeout_s)
        if not info.is_published():
            raise AssertionError(f"{self.client_id}: publish timed out for mid={info.mid}")
        return int(info.rc)

    def wait_for_messages(self, minimum: int, timeout_s: float = 5.0) -> bool:
        return _wait_until(lambda: self.message_count >= minimum, timeout_s)

    def wait_for_topic_messages(self, topic: str, minimum: int, timeout_s: float = 5.0) -> bool:
        return _wait_until(lambda: self.message_count_for_topic(topic) >= minimum, timeout_s)

    def wait_disconnected(self, timeout_s: float = 5.0) -> bool:
        return self._disconnected.wait(timeout=timeout_s)

    def assert_connected_for(self, duration_s: float) -> None:
        if not _wait_until(lambda: self._disconnected.is_set(), duration_s):
            return
        raise AssertionError(
            f"{self.client_id}: disconnected unexpectedly (reason={self.disconnect_reason})"
        )

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._client.disconnect()
        with contextlib.suppress(Exception):
            self._client.loop_stop()


@pytest.fixture(scope="session")
def compose_harness() -> Iterator[ComposeHarness]:
    if shutil.which("docker") is None:
        pytest.skip("Docker is required for broker integration tests")

    compose_cmd = os.environ.get("DOCKER_COMPOSE_BIN", "docker compose")
    compose_bin = shlex.split(compose_cmd)
    try:
        subprocess.run(
            [*compose_bin, "version"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        pytest.skip(f"Docker Compose is required for broker integration tests: {exc}")

    harness = ComposeHarness(repo_root=REPO_ROOT, compose_bin=compose_bin)
    harness.down()
    yield harness
    harness.down()


@pytest.fixture
def unique_suffix() -> str:
    return uuid.uuid4().hex[:8]


@pytest.fixture
def mqtt_client_factory() -> type[ObservedMqttClient]:
    return ObservedMqttClient
