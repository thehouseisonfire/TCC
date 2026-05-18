#!/usr/bin/env python3
"""Compatibility wrapper for the Rust mqtt-loadgen benchmark client."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
RAW_BISCUIT_MARKER = "b64:"
MqttPassword = str | bytes


def _resolve_rust_helper(binary: str) -> list[str]:
    env_name = f"MQTT_AUTH_BISCUIT_{binary.upper().replace('-', '_')}"
    if override := os.environ.get(env_name):
        return [override]
    for profile in ("release", "debug"):
        candidate = REPO_ROOT / "target" / profile / binary
        if candidate.exists():
            return [str(candidate)]
    cargo = shutil.which("cargo")
    if cargo is None:
        raise SystemExit(f"Missing required command: cargo (needed to run {binary})")
    return [cargo, "run", "--locked", "-p", "gen-tokens", "--bin", binary, "--"]


def _password_cli_arg(password: MqttPassword) -> str:
    if isinstance(password, bytes):
        encoded = base64.urlsafe_b64encode(password).rstrip(b"=").decode("ascii")
        return f"{RAW_BISCUIT_MARKER}{encoded}"
    return password


def _rust_loadgen_cmd(
    *,
    host: str,
    port: int,
    username: str,
    password: MqttPassword,
    fanout_publisher_username: str | None,
    fanout_publisher_password: MqttPassword | None,
    topic_template: str,
    clients: int,
    message_count: int,
    qos: int,
    qos_distribution: list[tuple[int, float]] | None,
    message_size: int,
    sync_connect: bool,
    token_issuer_url: str | None,
    token_issuer_kind: str | None,
    token_issuer_ttl: int | None,
    token_issuer_no_default_roles: bool,
    token_issuer_no_default_grants: bool,
    token_refresh_codes: set[int],
    proactive_refresh: bool,
    proactive_refresh_margin_seconds: int | None,
    proactive_refresh_timeout_seconds: int | None,
    proactive_refresh_assert_continuity: bool,
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
    jwt_identity_binding: str,
    biscuit_identity_binding: str,
    biscuit_client_id_fact: str,
    mode: str,
    fanout_topic: str | None,
    fanout_role: str = "combined",
    fanout_ready_dir: str | None = None,
    fanout_ready_timeout_seconds: int = 120,
    biscuit_attenuate: bool = False,
    biscuit_attenuate_denies: list[str] | None = None,
    biscuit_attenuate_checks: list[str] | None = None,
    biscuit_attenuate_topic: str | None = None,
    biscuit_attenuate_operation: str | None = None,
    biscuit_attenuate_ttl: int | None = None,
    biscuit_public_key_hex: str | None = None,
    biscuit_public_key_file: str | None = None,
    biscuit_delegate: bool = False,
    biscuit_delegate_denies: list[str] | None = None,
    biscuit_delegate_checks: list[str] | None = None,
    biscuit_delegate_topic: str | None = None,
    biscuit_delegate_operation: str | None = None,
    biscuit_delegate_ttl: int | None = None,
    biscuit_delegate_public_key_hex: str | None = None,
    biscuit_delegate_public_key_file: str | None = None,
    biscuit_delegate_handoff: bool = False,
    biscuit_delegate_handoff_topic: str | None = None,
    biscuit_delegate_handoff_token: MqttPassword | None = None,
    biscuit_delegate_handoff_qos: int | None = None,
    biscuit_delegate_handoff_no_retain: bool = False,
    biscuit_delegate_handoff_role: str = "combined",
    biscuit_delegate_handoff_nonce: str | None = None,
    biscuit_delegate_handoff_ready_dir: str | None = None,
    biscuit_delegate_handoff_ready_timeout_seconds: int = 120,
    control_topic: str | None = None,
    control_payload: dict[str, Any] | None = None,
    control_mode: bool = False,
    control_repeat: int = 1,
    control_qos: int = 1,
    control_after_messages: int = 0,
    fanout_churn_kind: str | None = None,
    fanout_churn_after_messages: int = 0,
    fanout_churn_interval_messages: int = 0,
    fanout_churn_max_events: int = 1,
    fanout_churn_settle_ms: int = 0,
    fanout_churn_dynamic_security_source: str | None = None,
    fanout_churn_control_topic: str | None = None,
    fanout_churn_control_payload: dict[str, Any] | None = None,
    fanout_churn_sqlite_db: str | None = None,
    fanout_churn_sqlite_topic: str | None = None,
    fanout_churn_sqlite_subscribers: int | None = None,
    sync_connect_barrier_url: str | None = None,
    sync_connect_run_id: str | None = None,
    sync_connect_participant_id: str | None = None,
    sync_connect_participants: int | None = None,
    sync_connect_barrier_timeout_seconds: int | None = None,
) -> list[str]:
    cmd = [
        *_resolve_rust_helper("mqtt-loadgen"),
        "--host",
        host,
        "--port",
        str(port),
        "--username",
        username,
        "--password",
        _password_cli_arg(password),
        "--clients",
        str(clients),
        "--messages",
        str(message_count),
        "--topic",
        topic_template,
        "--qos",
        str(qos),
        "--message-size",
        str(message_size),
        "--mode",
        mode,
        "--fanout-topic",
        fanout_topic or "fanout/broadcast",
        "--fanout-role",
        fanout_role,
        "--token-refresh-codes",
        ",".join(str(code) for code in sorted(token_refresh_codes)),
        "--jwt-identity-binding",
        jwt_identity_binding,
        "--biscuit-identity-binding",
        biscuit_identity_binding,
        "--biscuit-client-id-fact",
        biscuit_client_id_fact,
        "--json",
    ]
    if qos_distribution:
        distribution = ",".join(f"{q}:{weight}" for q, weight in qos_distribution)
        cmd.extend(["--qos-distribution", distribution])
    if sync_connect:
        cmd.append("--sync-connect")
    if sync_connect_barrier_url:
        cmd.extend(["--sync-connect-barrier-url", sync_connect_barrier_url])
    if sync_connect_run_id:
        cmd.extend(["--sync-connect-run-id", sync_connect_run_id])
    if sync_connect_participant_id:
        cmd.extend(["--sync-connect-participant-id", sync_connect_participant_id])
    if sync_connect_participants is not None:
        cmd.extend(["--sync-connect-participants", str(sync_connect_participants)])
    if sync_connect_barrier_timeout_seconds is not None:
        cmd.extend(
            [
                "--sync-connect-barrier-timeout-seconds",
                str(sync_connect_barrier_timeout_seconds),
            ]
        )
    if fanout_publisher_username:
        cmd.extend(["--fanout-publisher-username", fanout_publisher_username])
    if fanout_publisher_password is not None:
        cmd.extend(["--fanout-publisher-password", _password_cli_arg(fanout_publisher_password)])
    if fanout_ready_dir:
        cmd.extend(["--fanout-ready-dir", fanout_ready_dir])
    if fanout_ready_timeout_seconds != 120:
        cmd.extend(["--fanout-ready-timeout-seconds", str(fanout_ready_timeout_seconds)])
    if tls_enabled:
        cmd.append("--tls")
    if tls_ca_file:
        cmd.extend(["--tls-ca-file", tls_ca_file])
    if tls_insecure:
        cmd.append("--tls-insecure")
    if control_topic:
        cmd.extend(["--control-topic", control_topic])
    if control_payload is not None:
        cmd.extend(["--control-payload", json.dumps(control_payload)])
    if control_mode:
        cmd.append("--control-mode")
    if control_repeat != 1:
        cmd.extend(["--control-repeat", str(control_repeat)])
    if control_qos != 1:
        cmd.extend(["--control-qos", str(control_qos)])
    if control_after_messages > 0:
        cmd.extend(["--control-after-messages", str(control_after_messages)])
    if token_issuer_url:
        cmd.extend(["--token-issuer-url", token_issuer_url])
    if token_issuer_kind:
        cmd.extend(["--token-issuer-kind", token_issuer_kind])
    if token_issuer_ttl is not None:
        cmd.extend(["--token-issuer-ttl", str(token_issuer_ttl)])
    if token_issuer_no_default_roles:
        cmd.append("--token-issuer-no-default-roles")
    if token_issuer_no_default_grants:
        cmd.append("--token-issuer-no-default-grants")
    if proactive_refresh:
        cmd.append("--proactive-refresh")
    if proactive_refresh_margin_seconds is not None:
        cmd.extend(["--proactive-refresh-margin-seconds", str(proactive_refresh_margin_seconds)])
    if proactive_refresh_timeout_seconds is not None:
        cmd.extend(["--proactive-refresh-timeout-seconds", str(proactive_refresh_timeout_seconds)])
    if proactive_refresh_assert_continuity:
        cmd.append("--proactive-refresh-assert-continuity")
    if biscuit_attenuate:
        cmd.append("--biscuit-attenuate")
    for deny in biscuit_attenuate_denies or []:
        cmd.extend(["--biscuit-attenuate-deny", deny])
    for check in biscuit_attenuate_checks or []:
        cmd.extend(["--biscuit-attenuate-check", check])
    if biscuit_attenuate_topic:
        cmd.extend(["--biscuit-attenuate-topic", biscuit_attenuate_topic])
    if biscuit_attenuate_operation:
        cmd.extend(["--biscuit-attenuate-op", biscuit_attenuate_operation])
    if biscuit_attenuate_ttl is not None:
        cmd.extend(["--biscuit-attenuate-ttl", str(biscuit_attenuate_ttl)])
    if biscuit_public_key_hex:
        cmd.extend(["--biscuit-public-key-hex", biscuit_public_key_hex])
    if biscuit_public_key_file:
        cmd.extend(["--biscuit-public-key-file", biscuit_public_key_file])
    if biscuit_delegate:
        cmd.append("--biscuit-delegate")
    for deny in biscuit_delegate_denies or []:
        cmd.extend(["--biscuit-delegate-deny", deny])
    for check in biscuit_delegate_checks or []:
        cmd.extend(["--biscuit-delegate-check", check])
    if biscuit_delegate_topic:
        cmd.extend(["--biscuit-delegate-topic", biscuit_delegate_topic])
    if biscuit_delegate_operation:
        cmd.extend(["--biscuit-delegate-op", biscuit_delegate_operation])
    if biscuit_delegate_ttl is not None:
        cmd.extend(["--biscuit-delegate-ttl", str(biscuit_delegate_ttl)])
    if biscuit_delegate_public_key_hex:
        cmd.extend(["--biscuit-delegate-public-key-hex", biscuit_delegate_public_key_hex])
    if biscuit_delegate_public_key_file:
        cmd.extend(["--biscuit-delegate-public-key-file", biscuit_delegate_public_key_file])
    if biscuit_delegate_handoff:
        cmd.append("--biscuit-delegate-handoff")
    if biscuit_delegate_handoff_topic:
        cmd.extend(["--biscuit-delegate-handoff-topic", biscuit_delegate_handoff_topic])
    if biscuit_delegate_handoff_token is not None:
        handoff_token = _password_cli_arg(biscuit_delegate_handoff_token)
        cmd.extend(["--biscuit-delegate-handoff-token", handoff_token])
    if biscuit_delegate_handoff_qos is not None and biscuit_delegate_handoff_qos != 1:
        cmd.extend(["--biscuit-delegate-handoff-qos", str(biscuit_delegate_handoff_qos)])
    if biscuit_delegate_handoff_no_retain:
        cmd.append("--biscuit-delegate-handoff-no-retain")
    if biscuit_delegate_handoff_role != "combined":
        cmd.extend(["--biscuit-delegate-handoff-role", biscuit_delegate_handoff_role])
    if biscuit_delegate_handoff_nonce:
        cmd.extend(["--biscuit-delegate-handoff-nonce", biscuit_delegate_handoff_nonce])
    if biscuit_delegate_handoff_ready_dir:
        cmd.extend(["--biscuit-delegate-handoff-ready-dir", biscuit_delegate_handoff_ready_dir])
    if biscuit_delegate_handoff_ready_timeout_seconds != 120:
        cmd.extend(
            [
                "--biscuit-delegate-handoff-ready-timeout-seconds",
                str(biscuit_delegate_handoff_ready_timeout_seconds),
            ]
        )
    if fanout_churn_kind:
        cmd.extend(["--fanout-churn-kind", fanout_churn_kind])
    if fanout_churn_after_messages > 0:
        cmd.extend(["--fanout-churn-after-messages", str(fanout_churn_after_messages)])
    if fanout_churn_interval_messages > 0:
        cmd.extend(["--fanout-churn-interval-messages", str(fanout_churn_interval_messages)])
    if fanout_churn_max_events != 1:
        cmd.extend(["--fanout-churn-max-events", str(fanout_churn_max_events)])
    if fanout_churn_settle_ms > 0:
        cmd.extend(["--fanout-churn-settle-ms", str(fanout_churn_settle_ms)])
    if fanout_churn_dynamic_security_source:
        cmd.extend(["--fanout-churn-dynamic-security-source", fanout_churn_dynamic_security_source])
    if fanout_churn_control_topic:
        cmd.extend(["--fanout-churn-control-topic", fanout_churn_control_topic])
    if fanout_churn_control_payload is not None:
        cmd.extend(["--fanout-churn-control-payload", json.dumps(fanout_churn_control_payload)])
    if fanout_churn_sqlite_db:
        cmd.extend(["--fanout-churn-sqlite-db", fanout_churn_sqlite_db])
    if fanout_churn_sqlite_topic:
        cmd.extend(["--fanout-churn-sqlite-topic", fanout_churn_sqlite_topic])
    if fanout_churn_sqlite_subscribers is not None:
        cmd.extend(["--fanout-churn-sqlite-subscribers", str(fanout_churn_sqlite_subscribers)])
    return cmd


def _run_rust_loadgen_cli() -> int:
    completed = subprocess.run(
        _resolve_rust_helper("mqtt-loadgen") + sys.argv[1:],
        cwd=REPO_ROOT,
        check=False,
        text=True,
    )
    return completed.returncode


def main() -> int:
    return _run_rust_loadgen_cli()


if __name__ == "__main__":
    raise SystemExit(main())
