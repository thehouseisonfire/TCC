from __future__ import annotations

import pytest

from benchmarks import rust_helpers


def test_resolve_rust_helper_uses_cargo_freshness_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MQTT_AUTH_BISCUIT_MQTT_AUTH_CLIENT", raising=False)
    monkeypatch.setattr(rust_helpers.shutil, "which", lambda command: f"/tools/{command}")

    assert rust_helpers.resolve_rust_helper("mqtt-auth-client") == [
        "/tools/cargo",
        "run",
        "--locked",
        "-p",
        "gen-tokens",
        "--bin",
        "mqtt-auth-client",
        "--",
    ]


def test_resolve_rust_helper_honors_explicit_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MQTT_AUTH_BISCUIT_MQTT_LOADGEN", "/opt/current/mqtt-loadgen")

    assert rust_helpers.resolve_rust_helper("mqtt-loadgen") == ["/opt/current/mqtt-loadgen"]


def test_resolve_rust_helper_requires_cargo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MQTT_AUTH_BISCUIT_MQTT_LOADGEN", raising=False)
    monkeypatch.setattr(rust_helpers.shutil, "which", lambda _command: None)

    with pytest.raises(SystemExit, match="Missing required command: cargo"):
        rust_helpers.resolve_rust_helper("mqtt-loadgen")
