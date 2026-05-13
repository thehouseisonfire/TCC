from __future__ import annotations

import base64
import contextlib
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TLS_CA_FILE = REPO_ROOT / "docker" / "tls" / "ca.pem"
TLS_SERVER_CERT_FILE = REPO_ROOT / "docker" / "tls" / "server.pem"
TLS_SERVER_KEY_FILE = REPO_ROOT / "docker" / "tls" / "server.key"
DYNSEC_CONFIG_FILE = REPO_ROOT / "docker" / "dynamic-security.json"
DOCKER_COMPOSE_PROJECT = "runtime_enforcement_semantics_integration"
RUNTIME_ENFORCEMENT_ARTIFACT_DIR_ENV = "RUNTIME_ENFORCEMENT_ARTIFACT_DIR"
_FAILED_NODEIDS: set[str] = set()
_OBSERVED_HELPER_BUILT = False

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


def _artifact_dir_from_env() -> Path | None:
    raw = os.environ.get(RUNTIME_ENFORCEMENT_ARTIFACT_DIR_ENV, "").strip()
    if not raw:
        return None
    return Path(raw)


@dataclass
class IssuedToken:
    token: str | bytes
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

    def _post_binary_token(self, path: str, payload: dict[str, Any]) -> IssuedToken:
        transport = httpx.HTTPTransport(http1=False, http2=True, verify=self.verify)
        with httpx.Client(timeout=10.0, transport=transport) as client:
            resp = client.post(
                self.base_url.rstrip("/") + path,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            body = resp.json()
        data_b64 = str(body["data_b64"])
        padding = "=" * (-len(data_b64) % 4)
        return IssuedToken(
            token=base64.urlsafe_b64decode(data_b64 + padding),
            exp=int(body["exp"]),
        )

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
        return self._post_binary_token("/biscuit/binary", payload)


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

    def _compose_output(self, args: list[str], *, tls: bool) -> str:
        out = self._run_compose(
            args,
            tls=tls,
            check=False,
            capture_output=True,
        )
        chunks: list[str] = []
        if out.stdout:
            chunks.append(out.stdout)
        if out.stderr:
            chunks.append("\n--- STDERR ---\n")
            chunks.append(out.stderr)
        return "".join(chunks)

    def write_runtime_artifacts(self, artifact_dir: Path, *, failed_nodeids: list[str]) -> None:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        context = {
            "compose_project": DOCKER_COMPOSE_PROJECT,
            "compose_bin": self.compose_bin,
            "current_tls": self.current_tls,
            "repo_root": str(self.repo_root),
            "failed_nodeids": failed_nodeids,
        }
        (artifact_dir / "context.json").write_text(
            json.dumps(context, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        (artifact_dir / "failed-nodeids.txt").write_text(
            ("\n".join(failed_nodeids) + "\n") if failed_nodeids else "",
            encoding="utf-8",
        )

        for name, args in (
            ("docker-compose-ps.txt", ["ps", "-a"]),
            ("docker-compose-config.txt", ["config"]),
        ):
            with contextlib.suppress(Exception):
                (artifact_dir / name).write_text(
                    self._compose_output(args, tls=self.current_tls),
                    encoding="utf-8",
                )

        for service in ("mosquitto", "authz", "token-issuer"):
            with contextlib.suppress(Exception):
                (artifact_dir / f"{service}.log").write_text(
                    self.logs(service=service),
                    encoding="utf-8",
                )


@dataclass
class ObservedMqttClient:
    host: str
    port: int
    client_id: str
    username: str
    password: str | bytes
    tls: bool = False
    tls_ca_file: str | None = None
    tls_insecure: bool = False
    will_topic: str | None = None
    will_payload: str | bytes | None = None
    will_qos: int = 0
    will_retain: bool = False
    connect_reason: int | None = None
    disconnect_reason: int | None = None

    def __post_init__(self) -> None:
        self._proc: subprocess.Popen[str] | None = None

    @staticmethod
    def _b64(value: str | bytes | None) -> str:
        if value is None:
            data = b""
        elif isinstance(value, bytes):
            data = value
        else:
            data = value.encode()
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    @staticmethod
    def _helper_path() -> Path:
        global _OBSERVED_HELPER_BUILT
        candidate = REPO_ROOT / "target" / "debug" / "observed-mqtt-client"
        if not _OBSERVED_HELPER_BUILT:
            subprocess.run(
                ["cargo", "build", "-p", "gen-tokens", "--bin", "observed-mqtt-client"],
                cwd=REPO_ROOT,
                check=True,
            )
            _OBSERVED_HELPER_BUILT = True
        if not candidate.exists():
            raise RuntimeError(f"observed-mqtt-client helper not found: {candidate}")
        return candidate

    def _ensure_proc(self) -> subprocess.Popen[str]:
        if self._proc is None or self._proc.poll() is not None:
            self._proc = subprocess.Popen(
                [str(self._helper_path())],
                cwd=REPO_ROOT,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        return self._proc

    def _request(self, payload: dict[str, Any]) -> Any:
        proc = self._ensure_proc()
        if proc.stdin is None or proc.stdout is None:
            raise AssertionError(f"{self.client_id}: helper pipes are unavailable")
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            stderr = proc.stderr.read() if proc.stderr is not None else ""
            raise AssertionError(f"{self.client_id}: helper exited unexpectedly: {stderr}")
        response = json.loads(line)
        if not response.get("ok"):
            raise AssertionError(f"{self.client_id}: {response.get('error')}")
        return response.get("value")

    @property
    def message_count(self) -> int:
        return int(self._request({"cmd": "message_count"}))

    def message_count_for_topic(self, topic: str) -> int:
        return int(self._request({"cmd": "message_count", "topic": topic}))

    def connect(self, timeout_s: float = 10.0) -> None:
        value = self._request(
            {
                "cmd": "connect",
                "host": self.host,
                "port": self.port,
                "client_id": self.client_id,
                "username": self.username,
                "password_b64": self._b64(self.password),
                "tls": self.tls,
                "tls_ca_file": self.tls_ca_file,
                "tls_insecure": self.tls_insecure,
                "will_topic": self.will_topic,
                "will_payload_b64": self._b64(self.will_payload),
                "will_qos": self.will_qos,
                "will_retain": self.will_retain,
            }
        )
        self.connect_reason = int(value["connect_reason"])
        if self.connect_reason != 0:
            raise AssertionError(
                f"{self.client_id}: connect failed with reason {self.connect_reason}"
            )

    def subscribe(self, topic: str, qos: int = 1, timeout_s: float = 5.0) -> list[int]:
        return list(
            self._request({"cmd": "subscribe", "topic": topic, "qos": qos, "timeout_s": timeout_s})
        )

    def publish(
        self,
        topic: str,
        payload: str | bytes,
        qos: int = 1,
        timeout_s: float = 5.0,
    ) -> int | None:
        value = self._request(
            {
                "cmd": "publish",
                "topic": topic,
                "payload_b64": self._b64(payload),
                "qos": qos,
                "retain": False,
                "timeout_s": timeout_s,
            }
        )
        return None if value is None else int(value)

    def wait_for_messages(self, minimum: int, timeout_s: float = 5.0) -> bool:
        return bool(
            self._request({"cmd": "wait_messages", "minimum": minimum, "timeout_s": timeout_s})
        )

    def wait_for_topic_messages(self, topic: str, minimum: int, timeout_s: float = 5.0) -> bool:
        return bool(
            self._request(
                {
                    "cmd": "wait_topic_messages",
                    "topic": topic,
                    "minimum": minimum,
                    "timeout_s": timeout_s,
                }
            )
        )

    def wait_disconnected(self, timeout_s: float = 5.0) -> bool:
        value = self._request({"cmd": "wait_disconnect", "timeout_s": timeout_s})
        self.disconnect_reason = value.get("reason")
        return bool(value.get("disconnected"))

    def assert_connected_for(self, duration_s: float) -> None:
        if not self.wait_disconnected(timeout_s=duration_s):
            return
        raise AssertionError(
            f"{self.client_id}: disconnected unexpectedly (reason={self.disconnect_reason})"
        )

    def close(self) -> None:
        if self._proc is None:
            return
        with contextlib.suppress(Exception):
            self._request({"cmd": "close"})
        with contextlib.suppress(Exception):
            self._proc.terminate()
            self._proc.wait(timeout=1.0)
        self._proc = None


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]):
    outcome = yield
    report = outcome.get_result()
    if report.failed and report.when in {"setup", "call", "teardown"}:
        _FAILED_NODEIDS.add(item.nodeid)


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
    _FAILED_NODEIDS.clear()
    harness.down()
    yield harness
    artifact_dir = _artifact_dir_from_env()
    try:
        if artifact_dir is not None:
            harness.write_runtime_artifacts(artifact_dir, failed_nodeids=sorted(_FAILED_NODEIDS))
    finally:
        harness.down()


@pytest.fixture(autouse=True)
def restore_dynsec_snapshot() -> Iterator[None]:
    baseline = DYNSEC_CONFIG_FILE.read_bytes() if DYNSEC_CONFIG_FILE.exists() else None
    yield
    if baseline is not None:
        DYNSEC_CONFIG_FILE.write_bytes(baseline)


@pytest.fixture
def unique_suffix() -> str:
    return uuid.uuid4().hex[:8]


@pytest.fixture
def mqtt_client_factory() -> type[ObservedMqttClient]:
    return ObservedMqttClient
