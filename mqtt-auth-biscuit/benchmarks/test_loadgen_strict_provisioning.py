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


def _argv_value(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def test_rust_loadgen_command_forwards_programmatic_transition_options(monkeypatch) -> None:
    monkeypatch.setattr(loadgen, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    kwargs = _run_load_kwargs()
    kwargs.pop("protocol")
    kwargs.update(
        {
            "password": b"primary-token",
            "fanout_publisher_username": "publisher",
            "fanout_publisher_password": b"publisher-token",
            "qos_distribution": [(0, 0.25), (1, 0.75)],
            "sync_connect": True,
            "token_issuer_ttl": 60,
            "token_issuer_no_default_roles": True,
            "token_issuer_no_default_grants": True,
            "token_refresh_codes": {0x87, 5},
            "tls_enabled": True,
            "tls_ca_file": "ca.pem",
            "tls_insecure": True,
            "jwt_identity_binding": "strict",
            "biscuit_identity_binding": "strict",
            "biscuit_client_id_fact": "cid",
            "mode": "fanout",
            "fanout_topic": "fanout/all",
            "biscuit_attenuate": True,
            "biscuit_attenuate_denies": ['check if topic("blocked")'],
            "biscuit_attenuate_checks": ['check if operation("read")'],
            "biscuit_attenuate_topic": "sensors/{client_id}/temp",
            "biscuit_attenuate_operation": "read",
            "biscuit_attenuate_ttl": 30,
            "biscuit_public_key_hex": "abcd",
            "biscuit_public_key_file": "pubkey.pem",
            "biscuit_attenuate_bin": "biscuit-attenuate",
            "biscuit_delegate": True,
            "biscuit_delegate_denies": ['check if topic("secret")'],
            "biscuit_delegate_checks": ['check if operation("write")'],
            "biscuit_delegate_topic": "delegated/{client_id}",
            "biscuit_delegate_operation": "write",
            "biscuit_delegate_ttl": 45,
            "biscuit_delegate_public_key_hex": "dcba",
            "biscuit_delegate_public_key_file": "delegate-pubkey.pem",
            "biscuit_delegate_bin": "delegate-bin",
            "biscuit_delegate_handoff": True,
            "biscuit_delegate_handoff_topic": "handoff/topic",
            "biscuit_delegate_handoff_token": b"handoff-token",
            "biscuit_delegate_handoff_qos": 2,
            "biscuit_delegate_handoff_no_retain": True,
            "control_topic": "$CONTROL/dynamic-security/v1",
            "control_payload": {"commands": [{"command": "noop"}]},
            "control_mode": True,
            "control_repeat": 3,
            "control_qos": 2,
            "control_after_messages": 4,
            "fanout_churn_kind": "dynamic_security_control",
            "fanout_churn_after_messages": 2,
            "fanout_churn_interval_messages": 3,
            "fanout_churn_max_events": 4,
            "fanout_churn_settle_ms": 50,
            "fanout_churn_dynamic_security_source": "dynsec.json",
            "fanout_churn_control_topic": "$CONTROL/dynamic-security/v1",
            "fanout_churn_control_payload": {"commands": [{"command": "deleteRole"}]},
            "fanout_churn_sqlite_db": "policy.db",
            "fanout_churn_sqlite_topic": "fanout/all",
            "fanout_churn_sqlite_subscribers": 3,
        }
    )

    argv = loadgen._rust_loadgen_cmd(**kwargs)

    assert argv[0] == "mqtt-loadgen"
    assert _argv_value(argv, "--password") == "b64:cHJpbWFyeS10b2tlbg"
    assert _argv_value(argv, "--fanout-publisher-password") == "b64:cHVibGlzaGVyLXRva2Vu"
    assert _argv_value(argv, "--qos-distribution") == "0:0.25,1:0.75"
    assert "--sync-connect" in argv
    assert _argv_value(argv, "--token-issuer-url") == "http://issuer"
    assert _argv_value(argv, "--token-issuer-kind") == "jwt"
    assert _argv_value(argv, "--token-issuer-ttl") == "60"
    assert "--token-issuer-no-default-roles" in argv
    assert "--token-issuer-no-default-grants" in argv
    assert _argv_value(argv, "--token-refresh-codes") == "5,135"
    assert _argv_value(argv, "--jwt-identity-binding") == "strict"
    assert _argv_value(argv, "--biscuit-identity-binding") == "strict"
    assert _argv_value(argv, "--biscuit-client-id-fact") == "cid"
    assert "--tls" in argv
    assert _argv_value(argv, "--tls-ca-file") == "ca.pem"
    assert "--tls-insecure" in argv
    assert "--biscuit-attenuate" in argv
    assert _argv_value(argv, "--biscuit-attenuate-deny") == 'check if topic("blocked")'
    assert _argv_value(argv, "--biscuit-attenuate-check") == 'check if operation("read")'
    assert _argv_value(argv, "--biscuit-attenuate-topic") == "sensors/{client_id}/temp"
    assert _argv_value(argv, "--biscuit-attenuate-op") == "read"
    assert _argv_value(argv, "--biscuit-attenuate-ttl") == "30"
    assert _argv_value(argv, "--biscuit-public-key-hex") == "abcd"
    assert _argv_value(argv, "--biscuit-public-key-file") == "pubkey.pem"
    assert _argv_value(argv, "--biscuit-attenuate-bin") == "biscuit-attenuate"
    assert "--biscuit-delegate" in argv
    assert _argv_value(argv, "--biscuit-delegate-deny") == 'check if topic("secret")'
    assert _argv_value(argv, "--biscuit-delegate-check") == 'check if operation("write")'
    assert _argv_value(argv, "--biscuit-delegate-topic") == "delegated/{client_id}"
    assert _argv_value(argv, "--biscuit-delegate-op") == "write"
    assert _argv_value(argv, "--biscuit-delegate-ttl") == "45"
    assert _argv_value(argv, "--biscuit-delegate-public-key-hex") == "dcba"
    assert _argv_value(argv, "--biscuit-delegate-public-key-file") == "delegate-pubkey.pem"
    assert _argv_value(argv, "--biscuit-delegate-bin") == "delegate-bin"
    assert "--biscuit-delegate-handoff" in argv
    assert _argv_value(argv, "--biscuit-delegate-handoff-topic") == "handoff/topic"
    assert _argv_value(argv, "--biscuit-delegate-handoff-token") == "b64:aGFuZG9mZi10b2tlbg"
    assert _argv_value(argv, "--biscuit-delegate-handoff-qos") == "2"
    assert "--biscuit-delegate-handoff-no-retain" in argv
    assert _argv_value(argv, "--control-topic") == "$CONTROL/dynamic-security/v1"
    assert json.loads(_argv_value(argv, "--control-payload")) == {
        "commands": [{"command": "noop"}]
    }
    assert "--control-mode" in argv
    assert _argv_value(argv, "--control-repeat") == "3"
    assert _argv_value(argv, "--control-qos") == "2"
    assert _argv_value(argv, "--control-after-messages") == "4"
    assert _argv_value(argv, "--fanout-churn-kind") == "dynamic_security_control"
    assert _argv_value(argv, "--fanout-churn-after-messages") == "2"
    assert _argv_value(argv, "--fanout-churn-interval-messages") == "3"
    assert _argv_value(argv, "--fanout-churn-max-events") == "4"
    assert _argv_value(argv, "--fanout-churn-settle-ms") == "50"
    assert _argv_value(argv, "--fanout-churn-dynamic-security-source") == "dynsec.json"
    assert _argv_value(argv, "--fanout-churn-control-topic") == "$CONTROL/dynamic-security/v1"
    assert json.loads(_argv_value(argv, "--fanout-churn-control-payload")) == {
        "commands": [{"command": "deleteRole"}]
    }
    assert _argv_value(argv, "--fanout-churn-sqlite-db") == "policy.db"
    assert _argv_value(argv, "--fanout-churn-sqlite-topic") == "fanout/all"
    assert _argv_value(argv, "--fanout-churn-sqlite-subscribers") == "3"


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
