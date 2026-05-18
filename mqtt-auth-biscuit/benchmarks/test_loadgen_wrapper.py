#!/usr/bin/env python3
"""Tests for the Python wrapper around Rust mqtt-loadgen."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path
from typing import TypedDict

sys.path.append(str(Path(__file__).resolve().parents[1]))

from benchmarks import loadgen


class _RustLoadgenKwargs(TypedDict):
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
    sync_connect: bool
    token_issuer_url: str | None
    token_issuer_kind: str | None
    token_issuer_ttl: int | None
    token_issuer_no_default_roles: bool
    token_issuer_no_default_grants: bool
    token_refresh_codes: set[int]
    proactive_refresh: bool
    proactive_refresh_margin_seconds: int | None
    proactive_refresh_timeout_seconds: int | None
    proactive_refresh_assert_continuity: bool
    tls_enabled: bool
    tls_ca_file: str | None
    tls_insecure: bool
    jwt_identity_binding: str
    biscuit_identity_binding: str
    biscuit_client_id_fact: str
    mode: str
    fanout_topic: str | None


def _base_kwargs() -> _RustLoadgenKwargs:
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
        "sync_connect": False,
        "token_issuer_url": "http://issuer",
        "token_issuer_kind": "jwt",
        "token_issuer_ttl": None,
        "token_issuer_no_default_roles": False,
        "token_issuer_no_default_grants": False,
        "token_refresh_codes": set(),
        "proactive_refresh": False,
        "proactive_refresh_margin_seconds": None,
        "proactive_refresh_timeout_seconds": None,
        "proactive_refresh_assert_continuity": False,
        "jwt_identity_binding": "off",
        "biscuit_identity_binding": "off",
        "biscuit_client_id_fact": "client_id",
        "tls_enabled": False,
        "tls_ca_file": None,
        "tls_insecure": False,
        "mode": "publish",
        "fanout_topic": None,
    }


def _argv_value(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def test_rust_loadgen_command_forwards_programmatic_transition_options(monkeypatch) -> None:
    monkeypatch.setattr(loadgen, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    kwargs = _base_kwargs()
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
            "proactive_refresh": True,
            "proactive_refresh_margin_seconds": 60,
            "proactive_refresh_timeout_seconds": 10,
            "proactive_refresh_assert_continuity": True,
            "tls_enabled": True,
            "tls_ca_file": "ca.pem",
            "tls_insecure": True,
            "jwt_identity_binding": "strict",
            "biscuit_identity_binding": "strict",
            "biscuit_client_id_fact": "cid",
            "mode": "fanout",
            "fanout_topic": "fanout/all",
        }
    )

    argv = loadgen._rust_loadgen_cmd(
        **kwargs,
        biscuit_attenuate=True,
        biscuit_attenuate_denies=['check if topic("blocked")'],
        biscuit_attenuate_checks=['check if operation("read")'],
        biscuit_attenuate_topic="sensors/{client_id}/temp",
        biscuit_attenuate_operation="read",
        biscuit_attenuate_ttl=30,
        biscuit_public_key_hex="abcd",
        biscuit_public_key_file="pubkey.pem",
        biscuit_delegate=True,
        biscuit_delegate_denies=['check if topic("secret")'],
        biscuit_delegate_checks=['check if operation("write")'],
        biscuit_delegate_topic="delegated/{client_id}",
        biscuit_delegate_operation="write",
        biscuit_delegate_ttl=45,
        biscuit_delegate_public_key_hex="dcba",
        biscuit_delegate_public_key_file="delegate-pubkey.pem",
        biscuit_delegate_handoff=True,
        biscuit_delegate_handoff_topic="handoff/topic",
        biscuit_delegate_handoff_token=b"handoff-token",
        biscuit_delegate_handoff_qos=2,
        biscuit_delegate_handoff_no_retain=True,
        biscuit_delegate_handoff_role="delegatee",
        biscuit_delegate_handoff_nonce="run-1",
        biscuit_delegate_handoff_ready_dir="/workspace/benchmarks/results/.handoff",
        biscuit_delegate_handoff_ready_timeout_seconds=30,
        control_topic="$CONTROL/dynamic-security/v1",
        control_payload={"commands": [{"command": "noop"}]},
        control_mode=True,
        control_repeat=3,
        control_qos=2,
        control_after_messages=4,
        fanout_churn_kind="dynamic_security_control",
        fanout_churn_after_messages=2,
        fanout_churn_interval_messages=3,
        fanout_churn_max_events=4,
        fanout_churn_settle_ms=50,
        fanout_churn_dynamic_security_source="dynsec.json",
        fanout_churn_control_topic="$CONTROL/dynamic-security/v1",
        fanout_churn_control_payload={"commands": [{"command": "deleteRole"}]},
        fanout_churn_sqlite_db="policy.db",
        fanout_churn_sqlite_topic="fanout/all",
        fanout_churn_sqlite_subscribers=3,
        sync_connect_barrier_url="http://sync-barrier:8083",
        sync_connect_run_id="run-1",
        sync_connect_participant_id="client_1",
        sync_connect_participants=3,
        sync_connect_barrier_timeout_seconds=30,
    )

    assert argv[0] == "mqtt-loadgen"
    assert _argv_value(argv, "--password") == "b64:cHJpbWFyeS10b2tlbg"
    assert _argv_value(argv, "--fanout-publisher-password") == "b64:cHVibGlzaGVyLXRva2Vu"
    assert _argv_value(argv, "--qos-distribution") == "0:0.25,1:0.75"
    assert "--sync-connect" in argv
    assert _argv_value(argv, "--sync-connect-barrier-url") == "http://sync-barrier:8083"
    assert _argv_value(argv, "--sync-connect-run-id") == "run-1"
    assert _argv_value(argv, "--sync-connect-participant-id") == "client_1"
    assert _argv_value(argv, "--sync-connect-participants") == "3"
    assert _argv_value(argv, "--sync-connect-barrier-timeout-seconds") == "30"
    assert _argv_value(argv, "--token-issuer-url") == "http://issuer"
    assert _argv_value(argv, "--token-issuer-kind") == "jwt"
    assert _argv_value(argv, "--token-issuer-ttl") == "60"
    assert "--token-issuer-no-default-roles" in argv
    assert "--token-issuer-no-default-grants" in argv
    assert _argv_value(argv, "--token-refresh-codes") == "5,135"
    assert "--proactive-refresh" in argv
    assert _argv_value(argv, "--proactive-refresh-margin-seconds") == "60"
    assert _argv_value(argv, "--proactive-refresh-timeout-seconds") == "10"
    assert "--proactive-refresh-assert-continuity" in argv
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
    assert "--biscuit-delegate" in argv
    assert _argv_value(argv, "--biscuit-delegate-deny") == 'check if topic("secret")'
    assert _argv_value(argv, "--biscuit-delegate-check") == 'check if operation("write")'
    assert _argv_value(argv, "--biscuit-delegate-topic") == "delegated/{client_id}"
    assert _argv_value(argv, "--biscuit-delegate-op") == "write"
    assert _argv_value(argv, "--biscuit-delegate-ttl") == "45"
    assert _argv_value(argv, "--biscuit-delegate-public-key-hex") == "dcba"
    assert _argv_value(argv, "--biscuit-delegate-public-key-file") == "delegate-pubkey.pem"
    assert "--biscuit-delegate-handoff" in argv
    assert _argv_value(argv, "--biscuit-delegate-handoff-topic") == "handoff/topic"
    assert _argv_value(argv, "--biscuit-delegate-handoff-token") == "b64:aGFuZG9mZi10b2tlbg"
    assert _argv_value(argv, "--biscuit-delegate-handoff-qos") == "2"
    assert "--biscuit-delegate-handoff-no-retain" in argv
    assert _argv_value(argv, "--biscuit-delegate-handoff-role") == "delegatee"
    assert _argv_value(argv, "--biscuit-delegate-handoff-nonce") == "run-1"
    assert (
        _argv_value(argv, "--biscuit-delegate-handoff-ready-dir")
        == "/workspace/benchmarks/results/.handoff"
    )
    assert _argv_value(argv, "--biscuit-delegate-handoff-ready-timeout-seconds") == "30"
    assert _argv_value(argv, "--control-topic") == "$CONTROL/dynamic-security/v1"
    assert json.loads(_argv_value(argv, "--control-payload")) == {"commands": [{"command": "noop"}]}
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
    assert "--biscuit-attenuate-bin" not in argv
    assert "--biscuit-delegate-bin" not in argv


def test_loadgen_main_passes_cli_args_to_rust(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_run(cmd, *, cwd, check, text):
        calls.append({"cmd": cmd, "cwd": cwd, "check": check, "text": text})
        return subprocess.CompletedProcess(cmd, 7)

    monkeypatch.setattr(loadgen, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    monkeypatch.setattr(loadgen.subprocess, "run", fake_run)
    monkeypatch.setattr(loadgen.sys, "argv", ["loadgen.py", "--clients", "2"])

    assert loadgen.main() == 7
    assert calls == [
        {
            "cmd": ["mqtt-loadgen", "--clients", "2"],
            "cwd": loadgen.REPO_ROOT,
            "check": False,
            "text": True,
        }
    ]


def test_password_cli_arg_marks_binary_tokens() -> None:
    encoded = loadgen._password_cli_arg(b"\0binary")
    assert encoded == "b64:" + base64.urlsafe_b64encode(b"\0binary").rstrip(b"=").decode("ascii")
    assert loadgen._password_cli_arg("plain") == "plain"
