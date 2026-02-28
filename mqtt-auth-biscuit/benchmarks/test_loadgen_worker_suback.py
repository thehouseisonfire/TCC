#!/usr/bin/env python3
"""Unit tests for fan-out SUBACK-gated worker readiness."""

from __future__ import annotations

import os
import queue
import sys
import threading
from types import SimpleNamespace

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from benchmarks import loadgen


def _worker_cfg(barrier: loadgen.FanoutSubscribeBarrier) -> loadgen.WorkerConfig:
    return loadgen.WorkerConfig(
        host="localhost",
        port=1883,
        client_id="fanout_sub_1",
        username="reader",
        password="token",
        topic="ignored",
        qos=1,
        qos_distribution=None,
        message_count=0,
        message_size=16,
        protocol=5,
        sync_connect=False,
        token_issuer_url=None,
        token_issuer_kind=None,
        token_issuer_ttl=None,
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
        token_refresh_codes=set(),
        tls_enabled=False,
        tls_ca_file=None,
        tls_insecure=False,
        mode="fanout",
        subscribe_topic="fanout/broadcast",
        expect_messages=0,
        biscuit_attenuate=False,
        biscuit_attenuate_denies=[],
        biscuit_attenuate_checks=[],
        biscuit_attenuate_topic=None,
        biscuit_attenuate_operation=None,
        biscuit_attenuate_ttl=None,
        biscuit_public_key_hex=None,
        biscuit_public_key_file=None,
        biscuit_attenuate_bin=None,
        biscuit_delegate=False,
        biscuit_delegate_denies=[],
        biscuit_delegate_checks=[],
        biscuit_delegate_topic=None,
        biscuit_delegate_operation=None,
        biscuit_delegate_ttl=None,
        biscuit_delegate_public_key_hex=None,
        biscuit_delegate_public_key_file=None,
        biscuit_delegate_bin=None,
        biscuit_delegate_handoff=False,
        biscuit_delegate_handoff_topic=None,
        biscuit_delegate_handoff_token=None,
        biscuit_delegate_handoff_qos=0,
        biscuit_delegate_handoff_retain=False,
        biscuit_delegate_handoff_nonce=None,
        delegation_ms=None,
        delegation_len=None,
        control_topic=None,
        control_payload=None,
        control_mode=False,
        control_repeat=0,
        control_qos=0,
        control_after_messages=0,
        fanout_subscribe_barrier=barrier,
        fanout_churn_after_messages=0,
    )


def _patch_fake_mqtt(monkeypatch, *, suback_behavior: str) -> None:
    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.on_connect = None
            self.on_disconnect = None
            self.on_subscribe = None
            self.on_message = None
            self._userdata = None
            self._subscribe_mid = 73

        def user_data_set(self, userdata):
            self._userdata = userdata

        def username_pw_set(self, username, password):
            return None

        def tls_set(self, ca_certs=None):
            return None

        def tls_insecure_set(self, value):
            return None

        def connect(self, host, port, keepalive):
            return 0

        def loop_start(self):
            if self.on_connect is not None:
                self.on_connect(self, self._userdata, None, 0, None)

        def subscribe(self, topic, qos=0):
            if self.on_subscribe is not None:
                if suback_behavior == "success":
                    self.on_subscribe(self, self._userdata, self._subscribe_mid, [1], None)
                elif suback_behavior == "rejected":
                    self.on_subscribe(self, self._userdata, self._subscribe_mid, [128], None)
            return loadgen.mqtt.MQTT_ERR_SUCCESS, self._subscribe_mid

        def disconnect(self):
            if self.on_disconnect is not None:
                self.on_disconnect(self, self._userdata, None, 0, None)

        def loop_stop(self):
            return None

    monkeypatch.setattr(loadgen.mqtt, "Client", FakeClient)
    monkeypatch.setattr(
        loadgen.mqtt,
        "CallbackAPIVersion",
        SimpleNamespace(VERSION2=2),
    )
    monkeypatch.setattr(loadgen.mqtt, "MQTT_ERR_SUCCESS", 0)


def test_worker_marks_ready_only_after_successful_suback(monkeypatch) -> None:
    _patch_fake_mqtt(monkeypatch, suback_behavior="success")
    barrier = loadgen.FanoutSubscribeBarrier(expected=1)
    cfg = _worker_cfg(barrier)
    out_q: queue.Queue = queue.Queue()
    start_evt = threading.Event()
    publish_evt = threading.Event()
    start_evt.set()
    publish_evt.set()

    loadgen._run_worker(cfg, start_evt, publish_evt, out_q)

    result: loadgen.WorkerResult = out_q.get(timeout=1.0)
    assert barrier.ready == 1
    assert "fanout_suback_timeout" not in result.errors
    assert not any(err.startswith("fanout_suback_rejected:") for err in result.errors)


def test_worker_aborts_receive_when_fanout_timeout_is_signaled(monkeypatch) -> None:
    _patch_fake_mqtt(monkeypatch, suback_behavior="success")
    barrier = loadgen.FanoutSubscribeBarrier(expected=1)
    cfg = _worker_cfg(barrier)
    cfg.expect_messages = 1000
    abort_evt = threading.Event()
    abort_evt.set()
    cfg.fanout_abort_evt = abort_evt
    out_q: queue.Queue = queue.Queue()
    start_evt = threading.Event()
    start_evt.set()

    class FailingPublishStartEvent(threading.Event):
        def is_set(self) -> bool:
            return False

        def wait(self, timeout: float | None = None) -> bool:
            raise AssertionError("fanout publish start wait should not be called after abort")

    loadgen._run_worker(cfg, start_evt, FailingPublishStartEvent(), out_q)

    result: loadgen.WorkerResult = out_q.get(timeout=1.0)
    assert barrier.ready == 1
    assert "fanout_receive_aborted:subscribe_ready_timeout" in result.errors


def test_worker_does_not_mark_ready_without_suback(monkeypatch) -> None:
    _patch_fake_mqtt(monkeypatch, suback_behavior="none")
    barrier = loadgen.FanoutSubscribeBarrier(expected=1)
    cfg = _worker_cfg(barrier)
    out_q: queue.Queue = queue.Queue()
    start_evt = threading.Event()
    publish_evt = threading.Event()
    start_evt.set()
    publish_evt.set()

    # Accelerate timeout loops without waiting wall-clock 10 seconds.
    now = {"value": 0.0}

    def fast_time() -> float:
        now["value"] += 1.0
        return now["value"]

    monkeypatch.setattr(loadgen.time, "time", fast_time)

    loadgen._run_worker(cfg, start_evt, publish_evt, out_q)

    result: loadgen.WorkerResult = out_q.get(timeout=1.0)
    assert barrier.ready == 0
    assert "fanout_suback_timeout" in result.errors


def test_worker_suback_timeout_is_not_scaled_by_expected_messages(monkeypatch) -> None:
    _patch_fake_mqtt(monkeypatch, suback_behavior="none")
    barrier = loadgen.FanoutSubscribeBarrier(expected=1)
    cfg = _worker_cfg(barrier)
    cfg.expect_messages = 1000
    out_q: queue.Queue = queue.Queue()
    start_evt = threading.Event()
    publish_evt = threading.Event()
    start_evt.set()
    publish_evt.set()

    now = {"value": 0.0}
    suback_wait_calls = {"count": 0}

    def fast_time() -> float:
        now["value"] += 1.0
        return now["value"]

    class FastEvent:
        def wait(self, timeout: float | None = None) -> bool:
            suback_wait_calls["count"] += 1
            return False

        def set(self) -> None:
            return

        def clear(self) -> None:
            return

    monkeypatch.setattr(loadgen.time, "time", fast_time)
    monkeypatch.setattr(loadgen.threading, "Event", FastEvent)

    loadgen._run_worker(cfg, start_evt, publish_evt, out_q)

    result: loadgen.WorkerResult = out_q.get(timeout=1.0)
    assert barrier.ready == 0
    assert "fanout_suback_timeout" in result.errors
    assert suback_wait_calls["count"] < 20


def test_worker_does_not_mark_ready_on_suback_reject(monkeypatch) -> None:
    _patch_fake_mqtt(monkeypatch, suback_behavior="rejected")
    barrier = loadgen.FanoutSubscribeBarrier(expected=1)
    cfg = _worker_cfg(barrier)
    out_q: queue.Queue = queue.Queue()
    start_evt = threading.Event()
    publish_evt = threading.Event()
    start_evt.set()
    publish_evt.set()

    loadgen._run_worker(cfg, start_evt, publish_evt, out_q)

    result: loadgen.WorkerResult = out_q.get(timeout=1.0)
    assert barrier.ready == 0
    assert any(err.startswith("fanout_suback_rejected:") for err in result.errors)
