#!/usr/bin/env python3
"""Unit tests for strict per-client startup token provisioning."""

from __future__ import annotations

import base64
import json
import queue
import sys
import threading
from pathlib import Path
from typing import TypedDict

sys.path.append(str(Path(__file__).resolve().parents[1]))

from benchmarks import loadgen


class _RunLoadKwargs(TypedDict):
    host: str
    port: int
    username: str
    password: loadgen.MqttPassword
    fanout_publisher_username: str | None
    fanout_publisher_password: loadgen.MqttPassword | None
    topic_template: str
    clients: int
    message_count: int
    qos: int
    qos_distribution: list[tuple[int, float]] | None
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
    jwt_identity_binding: str
    biscuit_identity_binding: str
    biscuit_client_id_fact: str
    mode: str
    fanout_topic: str | None


def _empty_worker_result(client_id: str) -> loadgen.WorkerResult:
    return loadgen.WorkerResult(
        client_id=client_id,
        connect_ms=None,
        publish_ms=[],
        publish_ms_by_qos={0: [], 1: [], 2: []},
        receive_ms=[],
        token_refresh_ms=None,
        token_refresh_len=None,
        delegation_ms=None,
        delegation_len=None,
        attenuation_ms=None,
        attenuation_len=None,
        errors=[],
        control_publish_ms=[],
        control_errors=[],
        control_injection_delay_ms=[],
        receive_pre_churn=None,
        receive_post_churn=None,
    )


def _run_load_kwargs() -> _RunLoadKwargs:
    return {
        "host": "localhost",
        "port": 1883,
        "username": "jwt",
        "password": "shared-token",
        "fanout_publisher_username": None,
        "fanout_publisher_password": None,
        "topic_template": "sensors/{client_id}/temp",
        "clients": 3,
        "message_count": 0,
        "qos": 1,
        "qos_distribution": None,
        "message_size": 16,
        "protocol": 5,
        "sync_connect": False,
        "token_issuer_url": "http://issuer",
        "token_issuer_kind": "jwt",
        "token_issuer_ttl": None,
        "token_issuer_no_default_roles": False,
        "token_issuer_no_default_grants": False,
        "token_refresh_codes": set(),
        "jwt_identity_binding": "off",
        "biscuit_identity_binding": "off",
        "biscuit_client_id_fact": "client_id",
        "tls_enabled": False,
        "tls_ca_file": None,
        "tls_insecure": False,
        "mode": "publish",
        "fanout_topic": None,
    }


def _encode_fake_jwt(sub: str, client_id: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode("ascii")
    payload = (
        base64.urlsafe_b64encode(json.dumps({"sub": sub, "client_id": client_id}).encode("utf-8"))
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"{header}.{payload}.sig"


def _decode_fake_jwt_payload(token: str) -> dict[str, str]:
    _header, payload_b64, _sig = token.split(".")
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))


def test_strict_multi_client_jwt_startup_provisions_distinct_matching_tokens(
    monkeypatch,
) -> None:
    fetch_calls: list[dict[str, object]] = []
    worker_passwords: dict[str, loadgen.MqttPassword] = {}
    event_order: list[str] = []

    def fake_fetch_token(
        issuer_url: str,
        kind: str,
        client_id: str,
        topic: str,
        ttl: int | None,
        no_default_roles: bool,
        no_default_grants: bool,
        tls_ca_file: str | None,
        tls_insecure: bool,
        jwt_identity_binding: str = "off",
        biscuit_identity_binding: str = "off",
        biscuit_client_id_fact: str = "client_id",
    ) -> str:
        fetch_calls.append(
            {
                "issuer_url": issuer_url,
                "kind": kind,
                "client_id": client_id,
                "topic": topic,
                "ttl": ttl,
                "jwt_identity_binding": jwt_identity_binding,
                "biscuit_identity_binding": biscuit_identity_binding,
                "biscuit_client_id_fact": biscuit_client_id_fact,
            }
        )
        event_order.append(f"fetch:{client_id}")
        return _encode_fake_jwt(client_id, client_id)

    def fake_run_worker(
        cfg: loadgen.WorkerConfig,
        _start_evt: threading.Event,
        _fanout_publish_start_evt: threading.Event,
        out_q: queue.Queue,
    ) -> None:
        worker_passwords[cfg.client_id] = cfg.password
        event_order.append(f"worker:{cfg.client_id}")
        out_q.put(_empty_worker_result(cfg.client_id))

    monkeypatch.setattr(loadgen, "_fetch_token", fake_fetch_token)
    monkeypatch.setattr(loadgen, "_run_worker", fake_run_worker)
    monkeypatch.setattr(loadgen.time, "sleep", lambda _seconds: None)

    kwargs = _run_load_kwargs()
    kwargs["jwt_identity_binding"] = "strict"
    result = loadgen.run_load(**kwargs)

    assert [call["client_id"] for call in fetch_calls] == ["client_1", "client_2", "client_3"]
    assert event_order[:3] == ["fetch:client_1", "fetch:client_2", "fetch:client_3"]
    assert set(worker_passwords) == {"client_1", "client_2", "client_3"}
    assert len(set(worker_passwords.values())) == 3
    for client_id, token in worker_passwords.items():
        assert isinstance(token, str)
        payload = _decode_fake_jwt_payload(token)
        assert payload["sub"] == client_id
        assert payload["client_id"] == client_id
    assert result["inputs"]["strict_multi_client_startup_provisioning"] is True
    assert result["token_refresh"]["count"] == 0


def test_strict_multi_client_biscuit_startup_provisions_matching_identity_fact_requests(
    monkeypatch,
) -> None:
    fetch_calls: list[dict[str, object]] = []
    worker_passwords: dict[str, bytes] = {}

    def fake_fetch_token(
        issuer_url: str,
        kind: str,
        client_id: str,
        topic: str,
        ttl: int | None,
        no_default_roles: bool,
        no_default_grants: bool,
        tls_ca_file: str | None,
        tls_insecure: bool,
        jwt_identity_binding: str = "off",
        biscuit_identity_binding: str = "off",
        biscuit_client_id_fact: str = "client_id",
    ) -> bytes:
        fetch_calls.append(
            {
                "issuer_url": issuer_url,
                "kind": kind,
                "client_id": client_id,
                "topic": topic,
                "ttl": ttl,
                "jwt_identity_binding": jwt_identity_binding,
                "biscuit_identity_binding": biscuit_identity_binding,
                "biscuit_client_id_fact": biscuit_client_id_fact,
            }
        )
        return f"{biscuit_client_id_fact}:{client_id}".encode()

    def fake_run_worker(
        cfg: loadgen.WorkerConfig,
        _start_evt: threading.Event,
        _fanout_publish_start_evt: threading.Event,
        out_q: queue.Queue,
    ) -> None:
        assert isinstance(cfg.password, bytes)
        worker_passwords[cfg.client_id] = cfg.password
        out_q.put(_empty_worker_result(cfg.client_id))

    monkeypatch.setattr(loadgen, "_fetch_token", fake_fetch_token)
    monkeypatch.setattr(loadgen, "_run_worker", fake_run_worker)
    monkeypatch.setattr(loadgen.time, "sleep", lambda _seconds: None)

    kwargs = _run_load_kwargs()
    kwargs["username"] = "biscuit"
    kwargs["password"] = "shared-biscuit"
    kwargs["token_issuer_kind"] = "biscuit"
    kwargs["jwt_identity_binding"] = "off"
    kwargs["biscuit_identity_binding"] = "strict"
    kwargs["biscuit_client_id_fact"] = "device_id"
    result = loadgen.run_load(**kwargs)

    assert [call["client_id"] for call in fetch_calls] == ["client_1", "client_2", "client_3"]
    assert all(call["kind"] == "biscuit" for call in fetch_calls)
    assert all(call["biscuit_identity_binding"] == "strict" for call in fetch_calls)
    assert all(call["biscuit_client_id_fact"] == "device_id" for call in fetch_calls)
    assert worker_passwords == {
        "client_1": b"device_id:client_1",
        "client_2": b"device_id:client_2",
        "client_3": b"device_id:client_3",
    }
    assert result["inputs"]["biscuit_client_id_fact"] == "device_id"
    assert result["inputs"]["strict_multi_client_startup_provisioning"] is True


def test_capability_mode_keeps_shared_token_reuse_even_when_issuer_is_available(
    monkeypatch,
) -> None:
    worker_passwords: dict[str, loadgen.MqttPassword] = {}

    def fail_fetch_token(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("capability-mode startup should not fetch per-client tokens")

    def fake_run_worker(
        cfg: loadgen.WorkerConfig,
        _start_evt: threading.Event,
        _fanout_publish_start_evt: threading.Event,
        out_q: queue.Queue,
    ) -> None:
        worker_passwords[cfg.client_id] = cfg.password
        out_q.put(_empty_worker_result(cfg.client_id))

    monkeypatch.setattr(loadgen, "_fetch_token", fail_fetch_token)
    monkeypatch.setattr(loadgen, "_run_worker", fake_run_worker)
    monkeypatch.setattr(loadgen.time, "sleep", lambda _seconds: None)

    result = loadgen.run_load(**_run_load_kwargs())

    assert all(password == "shared-token" for password in worker_passwords.values())
    assert result["inputs"]["strict_multi_client_startup_provisioning"] is False


def test_strict_multi_client_fanout_startup_provisions_publisher_identity_token(
    monkeypatch,
) -> None:
    fetch_calls: list[dict[str, object]] = []
    worker_passwords: dict[str, loadgen.MqttPassword] = {}
    publisher_passwords: list[loadgen.MqttPassword] = []

    class FakeFanoutSubscribeBarrier:
        def __init__(self, expected: int):
            self.expected = expected
            self.ready = 0
            self.event = self

        def set_expected(self, expected: int) -> None:
            self.expected = expected

        def mark_ready(self) -> None:
            self.ready += 1

        def wait(self, timeout: float | None = None) -> bool:
            return self.ready >= self.expected

    def fake_fetch_token(
        issuer_url: str,
        kind: str,
        client_id: str,
        topic: str,
        ttl: int | None,
        no_default_roles: bool,
        no_default_grants: bool,
        tls_ca_file: str | None,
        tls_insecure: bool,
        jwt_identity_binding: str = "off",
        biscuit_identity_binding: str = "off",
        biscuit_client_id_fact: str = "client_id",
    ) -> str:
        fetch_calls.append(
            {
                "issuer_url": issuer_url,
                "kind": kind,
                "client_id": client_id,
                "topic": topic,
                "ttl": ttl,
                "jwt_identity_binding": jwt_identity_binding,
                "biscuit_identity_binding": biscuit_identity_binding,
                "biscuit_client_id_fact": biscuit_client_id_fact,
            }
        )
        return _encode_fake_jwt(client_id, client_id)

    def fake_run_worker(
        cfg: loadgen.WorkerConfig,
        _start_evt: threading.Event,
        _fanout_publish_start_evt: threading.Event,
        out_q: queue.Queue,
    ) -> None:
        worker_passwords[cfg.client_id] = cfg.password
        if cfg.fanout_subscribe_barrier is not None:
            cfg.fanout_subscribe_barrier.mark_ready()
        out_q.put(_empty_worker_result(cfg.client_id))

    def fake_run_fanout_publisher(**kwargs):
        publisher_passwords.append(kwargs["password"])
        return [], {0: [], 1: [], 2: []}, [], False

    monkeypatch.setattr(loadgen, "FanoutSubscribeBarrier", FakeFanoutSubscribeBarrier)
    monkeypatch.setattr(loadgen, "_fetch_token", fake_fetch_token)
    monkeypatch.setattr(loadgen, "_run_worker", fake_run_worker)
    monkeypatch.setattr(loadgen, "_run_fanout_publisher", fake_run_fanout_publisher)
    monkeypatch.setattr(loadgen.time, "sleep", lambda _seconds: None)

    kwargs = _run_load_kwargs()
    kwargs["jwt_identity_binding"] = "strict"
    kwargs["mode"] = "fanout"
    kwargs["clients"] = 2
    kwargs["message_count"] = 1
    kwargs["fanout_topic"] = "fanout/broadcast"
    result = loadgen.run_load(**kwargs)

    assert [call["client_id"] for call in fetch_calls] == [
        "client_1",
        "client_2",
        "fanout_publisher",
    ]
    assert set(worker_passwords) == {"client_1", "client_2"}
    assert len(publisher_passwords) == 1
    publisher_password = publisher_passwords[0]
    assert isinstance(publisher_password, str)
    publisher_payload = _decode_fake_jwt_payload(publisher_password)
    assert publisher_payload["sub"] == "fanout_publisher"
    assert publisher_payload["client_id"] == "fanout_publisher"
    assert result["inputs"]["strict_multi_client_startup_provisioning"] is True


def test_strict_multi_client_startup_fails_before_workers_without_token_issuer_url() -> None:
    kwargs = _run_load_kwargs()
    kwargs["jwt_identity_binding"] = "strict"
    kwargs["token_issuer_url"] = None

    try:
        loadgen.run_load(**kwargs)
    except ValueError as exc:
        assert "strict multi-client startup provisioning requires token_issuer_url" in str(exc)
    else:
        raise AssertionError("expected strict startup provisioning to fail without issuer URL")
