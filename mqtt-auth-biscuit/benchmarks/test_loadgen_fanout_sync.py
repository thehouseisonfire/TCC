#!/usr/bin/env python3
"""Regression tests for fan-out startup synchronization and error handling."""

from __future__ import annotations

import queue
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import TypedDict

sys.path.append(str(Path(__file__).resolve().parents[1]))

from benchmarks import loadgen


class _FanoutKwargs(TypedDict):
    host: str
    port: int
    username: str
    password: str
    fanout_publisher_username: str | None
    fanout_publisher_password: str | None
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
    jwt_identity_binding: str
    biscuit_identity_binding: str
    biscuit_client_id_fact: str
    tls_enabled: bool
    tls_ca_file: str | None
    tls_insecure: bool
    mode: str
    fanout_topic: str | None


class _PublishedMessage(TypedDict):
    topic: str
    payload: bytes
    qos: int


def _empty_worker_result(client_id: str, errors: list[str] | None = None) -> loadgen.WorkerResult:
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
        errors=errors or [],
        control_publish_ms=[],
        control_errors=[],
        control_injection_delay_ms=[],
        receive_pre_churn=None,
        receive_post_churn=None,
    )


def _fanout_kwargs() -> _FanoutKwargs:
    return {
        "host": "localhost",
        "port": 1883,
        "username": "user",
        "password": "pass",
        "fanout_publisher_username": None,
        "fanout_publisher_password": None,
        "topic_template": "sensors/{client_id}/temp",
        "clients": 1,
        "message_count": 0,
        "qos": 1,
        "qos_distribution": None,
        "message_size": 16,
        "protocol": 5,
        "sync_connect": False,
        "token_issuer_url": None,
        "token_issuer_kind": None,
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
        "mode": "fanout",
        "fanout_topic": "fanout/broadcast",
    }


def test_fanout_defers_receive_start_until_publisher_invocation(monkeypatch) -> None:
    observed: dict[str, object] = {
        "start_evt": None,
        "publish_start_evt": None,
        "start_evt_set_during_wait": None,
        "publish_start_set_during_wait": None,
        "publish_start_set_at_publisher": None,
    }
    worker_seen = threading.Event()

    def fake_run_worker(
        cfg: loadgen.WorkerConfig,
        start_evt: threading.Event,
        publish_start_evt: threading.Event,
        out_q: queue.Queue,
    ):
        observed["start_evt"] = start_evt
        observed["publish_start_evt"] = publish_start_evt
        worker_seen.set()
        out_q.put(_empty_worker_result(cfg.client_id))

    class FakeFanoutSubscribeBarrier:
        def __init__(self, expected: int):
            self.expected = expected
            self.event = self

        def set_expected(self, expected: int) -> None:
            self.expected = expected

        def mark_ready(self) -> None:
            return

        def wait(self, timeout: float | None = None) -> bool:
            worker_seen.wait(timeout=1.0)
            start_evt = observed["start_evt"]
            publish_start_evt = observed["publish_start_evt"]
            assert isinstance(start_evt, threading.Event)
            assert isinstance(publish_start_evt, threading.Event)
            observed["start_evt_set_during_wait"] = start_evt.is_set()
            observed["publish_start_set_during_wait"] = publish_start_evt.is_set()
            return True

    def fake_run_fanout_publisher(**_kwargs):
        publish_start_evt = observed["publish_start_evt"]
        assert isinstance(publish_start_evt, threading.Event)
        observed["publish_start_set_at_publisher"] = publish_start_evt.is_set()
        return [], {0: [], 1: [], 2: []}, [], False

    monkeypatch.setattr(loadgen, "FanoutSubscribeBarrier", FakeFanoutSubscribeBarrier)
    monkeypatch.setattr(loadgen, "_run_worker", fake_run_worker)
    monkeypatch.setattr(loadgen.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(loadgen, "_run_fanout_publisher", fake_run_fanout_publisher)

    loadgen.run_load(**_fanout_kwargs())

    assert observed["start_evt_set_during_wait"] is True
    assert observed["publish_start_set_during_wait"] is False
    assert observed["publish_start_set_at_publisher"] is True


def test_fanout_timeout_aborts_publisher(monkeypatch) -> None:
    publisher_invocations = {"count": 0}

    def fake_run_worker(
        cfg: loadgen.WorkerConfig,
        _start_evt: threading.Event,
        _publish_start_evt: threading.Event,
        out_q: queue.Queue,
    ):
        worker_errors: list[str] = []
        if cfg.fanout_abort_evt is not None:
            cfg.fanout_abort_evt.wait(timeout=1.0)
            if cfg.fanout_abort_evt.is_set():
                worker_errors.append("fanout_receive_aborted:subscribe_ready_timeout")
        out_q.put(_empty_worker_result(cfg.client_id, errors=worker_errors))

    class FakeFanoutSubscribeBarrier:
        def __init__(self, expected: int):
            self.expected = expected
            self.event = self

        def set_expected(self, expected: int) -> None:
            self.expected = expected

        def mark_ready(self) -> None:
            return

        def wait(self, timeout: float | None = None) -> bool:
            return False

    monkeypatch.setattr(loadgen, "FanoutSubscribeBarrier", FakeFanoutSubscribeBarrier)
    monkeypatch.setattr(loadgen, "_run_worker", fake_run_worker)
    monkeypatch.setattr(loadgen.time, "sleep", lambda _seconds: None)

    def fake_run_fanout_publisher(**_kwargs):
        publisher_invocations["count"] += 1
        return [], {0: [], 1: [], 2: []}, ["fanout_publish_failed:test"], False

    monkeypatch.setattr(loadgen, "_run_fanout_publisher", fake_run_fanout_publisher)

    result = loadgen.run_load(**_fanout_kwargs())

    assert "fanout_subscribe_ready_timeout" in result["errors"]
    assert "fanout_receive_aborted:subscribe_ready_timeout" in result["errors"]
    assert "fanout_publish_failed:test" not in result["errors"]
    assert publisher_invocations["count"] == 0


def test_fanout_barrier_expected_uses_spawned_workers(monkeypatch) -> None:
    barrier_instances: list[FakeFanoutSubscribeBarrier] = []
    delegate_attempts = {"count": 0}

    class FakeFanoutSubscribeBarrier:
        def __init__(self, expected: int):
            self.expected = expected
            self.ready = 0
            self.event = self
            barrier_instances.append(self)

        def set_expected(self, expected: int) -> None:
            self.expected = expected

        def mark_ready(self) -> None:
            self.ready += 1

        def wait(self, timeout: float | None = None) -> bool:
            return self.ready >= self.expected

    def fake_delegate(*_args, **_kwargs):
        delegate_attempts["count"] += 1
        if delegate_attempts["count"] == 1:
            raise RuntimeError("delegate exploded")
        return "delegated-token", 1.0, len("delegated-token")

    def fake_run_worker(
        cfg: loadgen.WorkerConfig,
        _start_evt: threading.Event,
        _publish_start_evt: threading.Event,
        out_q: queue.Queue,
    ):
        if cfg.fanout_subscribe_barrier is not None:
            cfg.fanout_subscribe_barrier.mark_ready()
        out_q.put(_empty_worker_result(cfg.client_id))

    monkeypatch.setattr(loadgen, "FanoutSubscribeBarrier", FakeFanoutSubscribeBarrier)
    monkeypatch.setattr(loadgen, "_delegate_biscuit_token", fake_delegate)
    monkeypatch.setattr(loadgen, "_run_worker", fake_run_worker)
    monkeypatch.setattr(loadgen.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        loadgen,
        "_run_fanout_publisher",
        lambda **_kwargs: ([], {0: [], 1: [], 2: []}, [], False),
    )

    kwargs = _fanout_kwargs()
    kwargs["clients"] = 2
    result = loadgen.run_load(**kwargs, biscuit_delegate=True)

    assert barrier_instances
    assert barrier_instances[0].expected == 1
    assert "fanout_subscribe_ready_timeout" not in result["errors"]
    assert any(err.startswith("delegation_failed:") for err in result["errors"])


def test_fanout_churn_output_includes_periodic_cache_signals(monkeypatch) -> None:
    class FakeFanoutSubscribeBarrier:
        def __init__(self, expected: int):
            self.expected = expected
            self.event = self

        def set_expected(self, expected: int) -> None:
            self.expected = expected

        def mark_ready(self) -> None:
            return

        def wait(self, timeout: float | None = None) -> bool:
            return True

    def fake_run_worker(
        cfg: loadgen.WorkerConfig,
        _start_evt: threading.Event,
        _publish_start_evt: threading.Event,
        out_q: queue.Queue,
    ):
        out_q.put(_empty_worker_result(cfg.client_id))

    def fake_run_fanout_publisher(**kwargs):
        churn_cfg = kwargs.get("fanout_churn")
        assert churn_cfg is not None
        churn_cfg.applied_count = 2
        return [], {0: [], 1: [], 2: []}, [], True

    monkeypatch.setattr(loadgen, "FanoutSubscribeBarrier", FakeFanoutSubscribeBarrier)
    monkeypatch.setattr(loadgen, "_run_worker", fake_run_worker)
    monkeypatch.setattr(loadgen, "_run_fanout_publisher", fake_run_fanout_publisher)
    monkeypatch.setattr(loadgen.time, "sleep", lambda _seconds: None)

    kwargs = _fanout_kwargs()
    kwargs["clients"] = 2
    kwargs["message_count"] = 10
    result = loadgen.run_load(
        **kwargs,
        fanout_churn_kind="sqlite_toggle_read",
        fanout_churn_after_messages=2,
        fanout_churn_interval_messages=3,
        fanout_churn_max_events=4,
    )

    churn = result["fanout_churn"]
    assert churn["interval_messages"] == 3
    assert churn["max_events"] == 4
    assert churn["applied_events"] == 2
    assert churn["post_churn_delivery_ratio"] == 0.0
    assert churn["cache_validity_signal"] is True


def test_expand_client_placeholders_recurses_through_control_payloads() -> None:
    payload = {
        "commands": [
            {
                "command": "createRole",
                "rolename": "dynamic_role_{client_id}",
                "acls": [
                    {"topic": "test/{client_id}/#"},
                    {"topic": "metrics/{region}/#"},
                ],
            }
        ],
        "metadata": [
            "{client_id}",
            {"owner": "{client_id}", "literal": "{}", "scoped": "metrics/{region}/#"},
        ],
    }

    expanded = loadgen._expand_client_placeholders(payload, client_id="client_7")

    assert expanded["commands"][0]["rolename"] == "dynamic_role_client_7"
    assert expanded["commands"][0]["acls"][0]["topic"] == "test/client_7/#"
    assert expanded["commands"][0]["acls"][1]["topic"] == "metrics/{region}/#"
    assert expanded["metadata"] == [
        "client_7",
        {
            "owner": "client_7",
            "literal": "{}",
            "scoped": "metrics/{region}/#",
        },
    ]


def test_expand_client_placeholders_leaves_unrelated_control_topic_braces_unchanged() -> None:
    expanded = loadgen._expand_client_placeholders(
        "metrics/{region}/{client_id}/#",
        client_id="client_4",
    )

    assert expanded == "metrics/{region}/client_4/#"


def test_apply_fanout_churn_dynamic_security_control_publishes_configured_payload() -> None:
    published: _PublishedMessage = {"topic": "", "payload": b"", "qos": 0}

    class FakeClient:
        def publish(self, topic: str, payload: bytes, qos: int = 0) -> SimpleNamespace:
            published["topic"] = topic
            published["payload"] = payload
            published["qos"] = qos

            return SimpleNamespace(
                rc=loadgen.mqtt.MQTT_ERR_SUCCESS,
                wait_for_publish=lambda timeout=10: None,
            )

    cfg = loadgen.FanoutChurnConfig(
        kind="dynamic_security_control",
        after_messages=1,
        control_topic="$CONTROL/dynamic-security/v1",
        control_payload={"commands": [{"command": "disableClient", "username": "dynsec_client_1"}]},
    )

    error = loadgen._apply_fanout_churn(cfg, FakeClient())

    assert error is None
    assert published["topic"] == "$CONTROL/dynamic-security/v1"
    assert published["qos"] == 1
    assert b'"command": "disableClient"' in published["payload"]
