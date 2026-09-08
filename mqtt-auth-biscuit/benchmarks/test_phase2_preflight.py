from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from benchmarks.phase2_preflight import (
    _current_broker_fixture_hash,
    _packet_metrics,
    _run,
    _verify,
    _verify_mtu_pair,
)
from benchmarks.run_scenarios import ScenarioConfig, _render_mosquitto_runtime_conf


def test_preflight_uses_client_correlatable_topology(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> None:
        captured["command"] = command
        captured.update(kwargs)

    monkeypatch.setattr("benchmarks.phase2_preflight.subprocess.run", fake_run)

    _run(tmp_path, ("NETWORK-MTU-200-JWT",), tls=False)

    command = captured["command"]
    assert isinstance(command, list)
    topology_index = command.index("--client-topology")
    assert command[topology_index + 1] == "container-per-client"
    assert captured["check"] is True


def _write_mtu_result(output: Path, mtu: int, payload_size: int) -> None:
    result = {
        "runs": [{"resources": {"cpu": 1}}],
        # This is configuration only and must never satisfy evidence checks.
        "packet_analysis": {"enabled": True, "config": {"analyze": True}},
        "packet_analysis_result": {
            "enabled": True,
            "metrics": {"max_tcp_payload_bytes": payload_size},
        },
    }
    (output / f"NETWORK-MTU-{mtu}-JWT.json").write_text(json.dumps(result))


def test_mtu_verification_reads_packet_analysis_result(tmp_path: Path) -> None:
    _write_mtu_result(tmp_path, 200, 148)
    _write_mtu_result(tmp_path, 1500, 512)

    result = json.loads((tmp_path / "NETWORK-MTU-200-JWT.json").read_text())
    metrics = _packet_metrics(result, "NETWORK-MTU-200-JWT")
    pair = _verify_mtu_pair(tmp_path)

    assert metrics["max_tcp_payload_bytes"] == 148
    assert pair["max_tcp_payload_mtu_200"] == 148
    assert pair["max_tcp_payload_mtu_1500"] == 512


@pytest.mark.parametrize(
    "packet_result",
    (
        None,
        {"enabled": False},
        {"enabled": True, "error": "capture failed"},
        {"enabled": True},
    ),
)
def test_mtu_verification_rejects_missing_or_failed_analysis(
    tmp_path: Path, packet_result: object
) -> None:
    result = {
        "runs": [{"resources": {}}],
        "packet_analysis": {"enabled": True},
        "packet_analysis_result": packet_result,
    }
    (tmp_path / "NETWORK-MTU-200-JWT.json").write_text(json.dumps(result))

    with pytest.raises(RuntimeError, match="packet"):
        _packet_metrics(result, "NETWORK-MTU-200-JWT")


def test_preflight_rejects_result_with_wrong_scenario_identity(tmp_path: Path) -> None:
    result = {"result_schema_version": 2, "scenario": "TOKEN-BASELINE-JWT"}
    (tmp_path / "BASELINE-NO-AUTH.json").write_text(json.dumps(result))

    with pytest.raises(RuntimeError, match="identity mismatch"):
        _verify(tmp_path, ("BASELINE-NO-AUTH",))


def test_generated_broker_fixture_hash_is_reconstructed_from_durable_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "mosquitto.conf"
    source.write_text(
        "plugin_opt_jwt_key_file jwt.pem\n"
        "plugin_opt_biscuit_root_key_file biscuit.pem\n"
        "plugin_opt_policy_mode token\n"
    )
    missing_generated = tmp_path / ".generated" / "mosquitto.conf"
    paths = {"./mosquitto.conf": source, "./.generated/mosquitto.conf": missing_generated}
    monkeypatch.setattr(
        "benchmarks.phase2_preflight._resolve_compose_path", lambda path: paths[path]
    )
    expected: ScenarioConfig = {
        "jwt_identity_binding": "strict",
        "biscuit_identity_binding": "off",
        "biscuit_client_id_fact": "device_id",
    }
    rendered = _render_mosquitto_runtime_conf(
        source.read_text(),
        jwt_identity_binding="strict",
        biscuit_identity_binding="off",
        biscuit_client_id_fact="device_id",
    )

    actual = _current_broker_fixture_hash(
        {
            "requested_path": "./mosquitto.conf",
            "effective_path": "./.generated/mosquitto.conf",
        },
        expected,
        "TOKEN-TLS",
    )

    assert actual == hashlib.sha256(rendered.encode()).hexdigest()
    assert not missing_generated.exists()
