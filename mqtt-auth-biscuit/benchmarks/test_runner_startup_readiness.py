from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, TypedDict

import pytest

from benchmarks import run_scenarios as rs
from benchmarks.perf_profiler import PerfConfig


def _resolved_mosquitto_healthcheck(
    compose_files: list[str],
    *,
    health_port: int | None = None,
) -> list[str]:
    env = os.environ.copy()
    if health_port is not None:
        env["MOSQUITTO_HEALTH_PORT"] = str(health_port)
    else:
        env.pop("MOSQUITTO_HEALTH_PORT", None)
    output = subprocess.check_output(
        rs._compose_cmd(["config", "--format", "json"], compose_files=compose_files),
        cwd=rs.REPO_ROOT,
        env=env,
        text=True,
    )
    payload = json.loads(output)
    return payload["services"]["mosquitto"]["healthcheck"]["test"]


def test_mosquitto_healthcheck_uses_plain_listener_by_default() -> None:
    assert _resolved_mosquitto_healthcheck(["docker/docker-compose.yml"]) == [
        "CMD-SHELL",
        "nc -z 127.0.0.1 1883",
    ]


def test_mosquitto_healthcheck_uses_tls_listener_with_tls_override() -> None:
    assert _resolved_mosquitto_healthcheck(
        ["docker/docker-compose.yml", "docker/docker-compose.tls.yml"]
    ) == [
        "CMD-SHELL",
        "nc -z 127.0.0.1 8883",
    ]


def test_mosquitto_healthcheck_honors_explicit_runner_port() -> None:
    assert _resolved_mosquitto_healthcheck(
        ["docker/docker-compose.yml", "docker/docker-compose.tls.yml"],
        health_port=9443,
    ) == [
        "CMD-SHELL",
        "nc -z 127.0.0.1 9443",
    ]


def test_tls_compose_keeps_cadvisor_on_private_http_network() -> None:
    output = subprocess.check_output(
        rs._compose_cmd(
            ["config", "--format", "json"],
            compose_files=["docker/docker-compose.yml", "docker/docker-compose.tls.yml"],
        ),
        cwd=rs.REPO_ROOT,
        text=True,
    )
    services = json.loads(output)["services"]
    prometheus = services["metrics-collector"]

    assert prometheus["user"] == "0:0"
    assert services["cadvisor"].get("command") is None
    assert services["cadvisor"].get("ports") is None
    assert all(
        volume["target"] not in {"/etc/cadvisor/server.pem", "/etc/cadvisor/server.key"}
        for volume in services["cadvisor"]["volumes"]
    )


def _sqlite_seed_scenario() -> rs.ScenarioConfig:
    return {
        "id": "SQLITE-SEED",
        "sqlite_seed_fanout": True,
        "sqlite_seed_db": "policy.db",
        "sqlite_seed_topic": "fanout/broadcast",
        "sqlite_seed_subscribers": 2,
        "sqlite_seed_profile": "fanout_basic",
    }


def test_sqlite_seed_replaces_readonly_fixture_before_broker_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "policy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE stale(value INTEGER)")
    db_path.chmod(0o444)
    monkeypatch.setattr(rs, "_resolve_repo_path", lambda _path: db_path)
    monkeypatch.setattr(rs.policy_churn, "_resolve_repo_path", lambda _path: db_path)

    rs._seed_sqlite_scenario_policy(
        _sqlite_seed_scenario(),
        default_clients=2,
        allow_replace=True,
    )

    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM user_roles").fetchone() == (3,)
    assert db_path.stat().st_mode & 0o777 == 0o666


def test_sqlite_reseed_preserves_live_database_inode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "policy.db"
    monkeypatch.setattr(rs, "_resolve_repo_path", lambda _path: db_path)
    monkeypatch.setattr(rs.policy_churn, "_resolve_repo_path", lambda _path: db_path)
    scenario = _sqlite_seed_scenario()

    rs._seed_sqlite_scenario_policy(scenario, default_clients=2, allow_replace=True)
    inode = db_path.stat().st_ino
    rs._seed_sqlite_scenario_policy(scenario, default_clients=2, allow_replace=False)

    assert db_path.stat().st_ino == inode


def test_compose_checked_includes_broker_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        rs,
        "_compose",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subprocess.CalledProcessError(1, ["docker", "compose"])
        ),
    )
    monkeypatch.setattr(rs, "_compose_diagnostics", lambda **_kwargs: "broker exited 1")

    with pytest.raises(RuntimeError, match="broker exited 1"):
        rs._compose_checked(
            ["up", "-d", "mosquitto"],
            extra_env={},
            compose_files=["docker/docker-compose.yml"],
            phase="core service startup",
        )


@pytest.mark.parametrize(
    ("result", "match"),
    [
        (
            {
                "errors": ["fanout_suback_rejected:135"],
                "publish": {"count": 0},
                "receive": {"count": 0},
            },
            "loadgen errors",
        ),
        (
            {"errors": [], "publish": {"count": 0}, "receive": {"count": 0}},
            "published 0/10",
        ),
        (
            {"errors": [], "publish": {"count": 10}, "receive": {"count": 0}},
            "received 0/100 deliveries",
        ),
    ],
)
def test_fanout_validation_rejects_invalid_benchmark_data(
    result: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(RuntimeError, match=match):
        rs._validate_result_contract(
            {
                "id": "SQLITE-RBAC-CHURN-JWT",
                "traffic_pattern": "fanout",
                "expected_delivery": "all",
            },
            result,
            message_count=10,
            client_count=10,
        )


@pytest.mark.parametrize(
    "setup_error",
    [
        "attenuation_failed:invalid token",
        "connect_denied:NotAuthorized",
        "connect_failed:client_7:connection refused",
        "delegation_failed:invalid block",
        "delegation_handoff_failed:client_8:missing token",
        "delegation_handoff_join_failed:task cancelled",
        "fanout_ready_write_failed:permission denied",
        "startup_provisioning_failed:client_9:issuer unavailable",
    ],
)
def test_fanout_validation_rejects_partial_subscriber_initialization(
    setup_error: str,
) -> None:
    with pytest.raises(RuntimeError, match="loadgen errors"):
        rs._validate_result_contract(
            {"id": "FANOUT", "traffic_pattern": "fanout", "expected_delivery": "all"},
            {
                "errors": [setup_error],
                "publish": {"count": 10},
                "receive": {"count": 90},
            },
            message_count=10,
            client_count=10,
        )


def test_fanout_validation_accepts_valid_churn_result() -> None:
    rs._validate_result_contract(
        {"id": "SQLITE-RBAC-CHURN-JWT", "traffic_pattern": "fanout", "expected_delivery": "all"},
        {
            "errors": [],
            "publish": {"count": 10},
            "receive": {"count": 200},
        },
        message_count=10,
        client_count=20,
    )


def test_restore_dynamic_security_baseline_removes_file_when_baseline_was_absent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dynamic_security_path = tmp_path / "dynamic-security.json"
    dynamic_security_path.write_text('{"clients":[]}', encoding="utf-8")
    monkeypatch.setattr(rs, "_resolve_repo_path", lambda _path: dynamic_security_path)

    rs._restore_dynamic_security_baseline(None)

    assert not dynamic_security_path.exists()


def test_dynamic_security_scenario_config_cleans_up_after_startup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []
    scenario: rs.ScenarioConfig = {
        "id": "DYNSEC-STARTUP-FAILURE",
        "mosquitto_conf": "./mosquitto.conf",
        "dynamic_security_generated_profile": "test-profile",
    }

    def generate(profile: str) -> str:
        calls.append(("generate", profile))
        return "/tmp/generated-dynsec.json"

    monkeypatch.setattr(rs, "_capture_dynamic_security_baseline", lambda: b"baseline")
    monkeypatch.setattr(rs, "_generate_dynamic_security_config", generate)
    monkeypatch.setattr(
        rs,
        "_apply_dynamic_security_config",
        lambda path: calls.append(("apply", path)),
    )
    monkeypatch.setattr(
        rs.policy_churn,
        "cleanup_dynsec_snapshot",
        lambda path: calls.append(("cleanup", path)),
    )
    monkeypatch.setattr(
        rs,
        "_restore_dynamic_security_baseline",
        lambda baseline: calls.append(("restore", baseline)),
    )

    with (
        pytest.raises(RuntimeError, match="compose startup failed"),
        rs._dynamic_security_scenario_config(scenario),
    ):
        raise RuntimeError("compose startup failed")

    assert calls == [
        ("generate", "test-profile"),
        ("apply", "/tmp/generated-dynsec.json"),
        ("cleanup", "/tmp/generated-dynsec.json"),
        ("restore", b"baseline"),
    ]


def test_dynamic_security_scenario_config_restarts_after_restoring_live_broker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    scenario: rs.ScenarioConfig = {
        "id": "DYNAMIC-SECURITY-CHURN",
        "mosquitto_conf": "./mosquitto_dynsec.conf",
        "dynamic_security_generated_profile": "dynsec_multi_client",
        "runtime_control_username": "admin",
    }
    monkeypatch.setattr(rs, "_capture_dynamic_security_baseline", lambda: b"baseline")
    monkeypatch.setattr(
        rs,
        "_generate_dynamic_security_config",
        lambda _profile: "/tmp/generated.json",
    )
    monkeypatch.setattr(rs, "_apply_dynamic_security_config", lambda _path: None)
    monkeypatch.setattr(rs.policy_churn, "cleanup_dynsec_snapshot", lambda _path: None)
    monkeypatch.setattr(
        rs,
        "_restore_dynamic_security_baseline",
        lambda _baseline: calls.append("restore"),
    )
    monkeypatch.setattr(
        rs,
        "_restart_mosquitto",
        lambda **_kwargs: calls.append("restart"),
    )

    with rs._dynamic_security_scenario_config(
        scenario,
        extra_env={"MOSQUITTO_CONF": "./mosquitto_dynsec.conf"},
        compose_files=["docker/docker-compose.yml"],
    ) as state:
        state.broker_started = True

    assert calls == ["restore", "restart"]


def test_generated_dynamic_security_is_reset_only_between_repeats(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(
        rs,
        "_apply_dynamic_security_config",
        lambda path: calls.append(("apply", path)),
    )
    monkeypatch.setattr(
        rs,
        "_restart_mosquitto",
        lambda **kwargs: calls.append(("restart", kwargs)),
    )
    extra_env: dict[str, str] = {"MOSQUITTO_CONF": "./mosquitto_dynsec.conf"}
    compose_files: list[str] = ["docker/docker-compose.yml"]
    host = "localhost"
    port = 1883

    rs._reset_generated_dynamic_security_between_repeats(
        0,
        "/tmp/seed.json",
        extra_env=extra_env,
        compose_files=compose_files,
        host=host,
        port=port,
    )
    rs._reset_generated_dynamic_security_between_repeats(
        1,
        "/tmp/seed.json",
        extra_env=extra_env,
        compose_files=compose_files,
        host=host,
        port=port,
    )
    rs._reset_generated_dynamic_security_between_repeats(
        2,
        None,
        extra_env=extra_env,
        compose_files=compose_files,
        host=host,
        port=port,
    )

    expected_kwargs = {
        "extra_env": extra_env,
        "compose_files": compose_files,
        "host": host,
        "port": port,
    }
    assert calls == [
        ("apply", "/tmp/seed.json"),
        ("restart", expected_kwargs),
    ]


def test_python_subprocess_env_prepends_repo_root(monkeypatch) -> None:
    monkeypatch.setenv("PYTHONPATH", "/tmp/existing")

    env = rs._python_subprocess_env()

    assert env["PYTHONPATH"].split(":")[0] == str(Path(rs.REPO_ROOT))
    assert "/tmp/existing" in env["PYTHONPATH"].split(":")


def test_python_subprocess_env_does_not_duplicate_repo_root(monkeypatch) -> None:
    repo_root = str(Path(rs.REPO_ROOT))
    monkeypatch.setenv("PYTHONPATH", f"{repo_root}:/tmp/existing")

    env = rs._python_subprocess_env()

    assert env["PYTHONPATH"].split(":").count(repo_root) == 1


def test_wait_for_service_health_retries_until_ok(monkeypatch) -> None:
    attempts = {"count": 0}

    def fake_health_check(name: str, base_url: str, ca_file: str | None, insecure: bool) -> None:
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError(f"{name} not ready")

    monkeypatch.setattr(rs, "_health_check", fake_health_check)
    monkeypatch.setattr(rs.time, "sleep", lambda _seconds: None)

    rs._wait_for_service_health("token-issuer", "http://localhost:8082", None, False)

    assert attempts["count"] == 3


@pytest.mark.parametrize(
    ("ca_file", "insecure", "expected_verify"),
    [
        (None, True, False),
        ("docker/tls/ca.pem", False, "docker/tls/ca.pem"),
    ],
)
def test_http2_client_configures_verification_on_transport(
    monkeypatch: pytest.MonkeyPatch,
    ca_file: str | None,
    insecure: bool,
    expected_verify: bool | str,
) -> None:
    transport = object()

    def fake_transport(**kwargs):  # noqa: ANN003, ANN202
        assert kwargs == {"http1": False, "http2": True, "verify": expected_verify}
        return transport

    def fake_client(**kwargs):  # noqa: ANN003, ANN202
        assert kwargs == {"timeout": 5.0, "transport": transport}
        return object()

    monkeypatch.setattr(rs.httpx, "HTTPTransport", fake_transport)
    monkeypatch.setattr(rs.httpx, "Client", fake_client)

    rs._http_client(ca_file, insecure)


def test_prometheus_query_uses_default_http_transport(monkeypatch) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {"status": "success", "data": {"result": []}}

    class FakeClient:
        def __init__(self, **kwargs) -> None:  # noqa: ANN003
            assert "transport" not in kwargs
            assert kwargs["verify"] is True
            assert kwargs["timeout"] == 5.0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
            return None

        def get(self, url: str, params: dict[str, str]):
            assert url == "http://localhost:9090/api/v1/query"
            assert params == {"query": "up"}
            return FakeResponse()

    monkeypatch.setattr(rs.httpx, "Client", FakeClient)

    result = rs._prom_query("http://localhost:9090", "up", None, False)

    assert result["status"] == "success"


def test_wait_for_non_empty_resource_snapshot_retries_until_valid(monkeypatch) -> None:
    attempts = {"count": 0}
    snapshot: dict[str, object] = {"prometheus": {"cpu": {}, "memory": {}}}

    def fake_resource_snapshot(*args, **kwargs):  # noqa: ANN001, ANN202
        return snapshot

    def fake_validate_resource_snapshot(
        snap: dict[str, object],
        *,
        scenario_id: str,
        run_index: int,
    ) -> None:
        assert snap is snapshot
        assert scenario_id == "STARTUP-READINESS"
        assert run_index == 0
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError("empty vectors")

    monkeypatch.setattr(rs, "_resource_snapshot", fake_resource_snapshot)
    monkeypatch.setattr(rs, "_validate_resource_snapshot", fake_validate_resource_snapshot)
    monkeypatch.setattr(rs.time, "sleep", lambda _seconds: None)

    returned = rs._wait_for_non_empty_resource_snapshot(
        "http://localhost:9090",
        None,
        False,
        compose_project_name="test-project",
    )

    assert returned is snapshot
    assert attempts["count"] == 3


def test_container_endpoint_config_keeps_host_mqtt_for_host_subprocesses() -> None:
    host_ca = str(rs._resolve_repo_path("docker/tls/ca.pem"))
    endpoints = rs._scenario_endpoint_config(
        client_topology_mode="container-single",
        scenario_tls=False,
        tls_ca=host_ca,
    )

    assert endpoints["host_mqtt_host"] == "localhost"
    assert endpoints["loadgen_mqtt_host"] == "mosquitto"
    assert endpoints["mqtt_port"] == 1883
    assert endpoints["loadgen_token_issuer_base"] == "http://token-issuer:8082"
    assert endpoints["loadgen_tls_ca"] == "/workspace/docker/tls/ca.pem"


def test_host_endpoint_config_uses_localhost_for_loadgen_and_mqtt5_auth() -> None:
    host_ca = str(rs._resolve_repo_path("docker/tls/ca.pem"))
    endpoints = rs._scenario_endpoint_config(
        client_topology_mode="host",
        scenario_tls=True,
        tls_ca=host_ca,
    )

    assert endpoints["host_mqtt_host"] == "localhost"
    assert endpoints["loadgen_mqtt_host"] == "localhost"
    assert endpoints["mqtt_port"] == 8883
    assert endpoints["loadgen_token_issuer_base"] == "https://localhost:8444"
    assert endpoints["loadgen_tls_ca"] == host_ca


def test_normalize_tcpdump_output_dir_returns_absolute_repo_path() -> None:
    path = rs._normalize_tcpdump_output_dir("benchmarks/results/pcap")

    assert path == str((Path(rs.REPO_ROOT) / "benchmarks/results/pcap").resolve())


def test_main_normalizes_output_directory_strings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}
    compose_calls: list[list[str]] = []
    scenario_id = "TEST-SCENARIO"
    tcpdump_output_dir = tmp_path / "pcap"
    perf_output_dir = tmp_path / "perf"

    class _ValidatedScenario:
        def __init__(self, payload: rs.ScenarioConfig) -> None:
            self._payload = payload

        def model_dump(self) -> rs.ScenarioConfig:
            return self._payload

    class _FakeScenarioModel:
        @staticmethod
        def model_validate(payload: rs.ScenarioConfig) -> _ValidatedScenario:
            return _ValidatedScenario(payload)

    scenario: rs.ScenarioConfig = {
        "id": scenario_id,
        "mosquitto_conf": "./mosquitto.conf",
        "netem": {"mtu": 1200},
    }

    monkeypatch.setattr(rs, "setup_logging", lambda _log_level: None)
    monkeypatch.setattr(
        rs,
        "check_perf_installation",
        lambda: {"installed": True, "version": "1"},
    )
    monkeypatch.setattr(
        rs,
        "check_pcap_parser_available",
        lambda: {"installed": True, "parser": "dpkt", "version": "1"},
    )
    monkeypatch.setattr(rs, "_read_tokens", lambda _path: {})
    monkeypatch.setattr(
        rs,
        "_build_available_scenarios",
        lambda *args, **kwargs: {scenario_id: scenario},
    )
    monkeypatch.setattr(rs, "_expand_tls_matrix", lambda available: available)
    monkeypatch.setattr(rs, "ScenarioModel", _FakeScenarioModel)
    monkeypatch.setattr(rs, "_require_requested_scenario_fixtures", lambda *_args: None)
    monkeypatch.setattr(rs, "_validate_scenario_credentials", lambda *_args: None)
    monkeypatch.setattr(
        rs,
        "_scenario_semantics_metadata",
        lambda *_args, **_kwargs: {
            "jwt_identity_binding": "off",
            "biscuit_identity_binding": "off",
        },
    )
    monkeypatch.setattr(
        rs,
        "_effective_mosquitto_runtime_conf",
        lambda mosq_conf, **_kwargs: mosq_conf,
    )
    monkeypatch.setattr(
        rs,
        "_scenario_endpoint_config",
        lambda **_kwargs: {
            "authz_base": "http://localhost:5000",
            "prom_base": "http://localhost:9090",
            "token_issuer_base": "http://localhost:8082",
            "loadgen_token_issuer_base": "http://localhost:8082",
            "host_mqtt_host": "localhost",
            "loadgen_mqtt_host": "localhost",
            "mqtt_port": 1883,
            "loadgen_tls_ca": None,
        },
    )

    def fake_compose(
        args: list[str],
        *,
        extra_env: dict[str, str] | None = None,
        compose_files: list[str] | None = None,
    ) -> None:
        compose_calls.append(args)
        captured["compose_extra_env"] = extra_env
        captured["compose_files"] = compose_files

    monkeypatch.setattr(rs, "_compose", fake_compose)
    monkeypatch.setattr(rs.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(rs, "_wait_for_mqtt_listener", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "_wait_for_service_health", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "_wait_for_prometheus_api", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "_wait_for_non_empty_resource_snapshot", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(rs, "run_baseline_with_retry", lambda **_kwargs: {})
    monkeypatch.setattr(rs, "check_network_validity", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(rs, "_capture_dynamic_security_baseline", lambda: {})
    monkeypatch.setattr(rs, "_restore_dynamic_security_baseline", lambda _baseline: None)
    monkeypatch.setattr(rs, "_validate_dynamic_security_alignment", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rs, "_resource_snapshot", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(rs, "_validate_resource_snapshot", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        rs,
        "_run_loadgen",
        lambda **_kwargs: {"errors": [], "publish": {"count": 1000}, "receive": {}},
    )

    def fake_profile(
        *,
        container_name: str,
        config: PerfConfig,
    ) -> dict[str, object]:
        captured["perf_container_name"] = container_name
        captured["perf_output_dir"] = config.output_dir
        return {"success": True}

    monkeypatch.setattr(rs, "profile_mosquitto_container", fake_profile)
    monkeypatch.setattr(rs, "format_perf_summary", lambda _result: "ok")
    monkeypatch.setattr(rs.subprocess, "check_call", lambda *args, **kwargs: None)

    rs.main(
        tokens_path="ignored.json",
        out=str(tmp_path / "results"),
        scenarios_arg=scenario_id,
        iperf3_enabled=False,
        perf_enabled=True,
        perf_scenarios=scenario_id,
        perf_output_dir=str(perf_output_dir),
        tcpdump_enabled=True,
        tcpdump_analyze=False,
        tcpdump_output_dir=str(tcpdump_output_dir),
    )

    compose_extra_env = captured["compose_extra_env"]
    assert isinstance(compose_extra_env, dict)
    assert compose_extra_env["MOSQUITTO_HEALTH_PORT"] == "1883"
    assert compose_extra_env["TCPDUMP_OUTPUT_DIR"] == str(tcpdump_output_dir.resolve())
    assert compose_calls[0] == ["rm", "-s", "-f", "netem", "tcpdump"]
    assert compose_calls[1][:4] == ["up", "--build", "-d", "mosquitto"]
    assert compose_calls[2] == ["up", "--build", "--no-deps", "-d", "netem", "tcpdump"]
    assert captured["perf_output_dir"] == str(perf_output_dir)
    result = json.loads((tmp_path / "results" / f"{scenario_id}.json").read_text())
    assert result["perf_profiling"]["config"]["callgraph"] is True
    assert result["packet_analysis"]["config"]["analyze"] is False


def test_resolve_mqtt5_auth_tokens_uses_static_tokens_when_present() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "TOKEN-MQTT5-REAUTH-JWT",
        "mqtt5_auth": {"token1": "token-one", "token2": "token-two"},
    }

    token1, token2 = rs._resolve_mqtt5_auth_tokens(
        "TOKEN-MQTT5-REAUTH-JWT",
        scenario,
        "http://issuer",
        ca_file=None,
        insecure=False,
    )

    assert token1 == "token-one"
    assert token2 == "token-two"


def test_resolve_mqtt5_auth_tokens_mints_fresh_runtime_tokens(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_issue(
        scenario_id: str,
        token_kind: rs.ScenarioTokenKind,
        token_issuer_base: str,
        *,
        token1_ttl_seconds: int,
        token2_ttl_seconds: int,
        ca_file: str | None,
        insecure: bool,
    ) -> tuple[str, str]:
        captured.update(
            {
                "scenario_id": scenario_id,
                "token_kind": token_kind,
                "token_issuer_base": token_issuer_base,
                "token1_ttl_seconds": token1_ttl_seconds,
                "token2_ttl_seconds": token2_ttl_seconds,
                "ca_file": ca_file,
                "insecure": insecure,
            }
        )
        return ("fresh-token-1", "fresh-token-2")

    monkeypatch.setattr(rs, "_issue_mqtt5_auth_tokens", fake_issue)
    scenario: rs.ScenarioConfig = {
        "id": "TOKEN-MQTT5-REAUTH-BISCUIT",
        "mqtt5_auth": {
            "kind": "biscuit",
            "token1_ttl_seconds": 90,
            "token2_ttl_seconds": 240,
        },
    }

    token1, token2 = rs._resolve_mqtt5_auth_tokens(
        "TOKEN-MQTT5-REAUTH-BISCUIT",
        scenario,
        "https://issuer",
        ca_file="docker/tls/ca.pem",
        insecure=True,
    )

    assert (token1, token2) == ("fresh-token-1", "fresh-token-2")
    assert captured == {
        "scenario_id": "TOKEN-MQTT5-REAUTH-BISCUIT",
        "token_kind": "biscuit",
        "token_issuer_base": "https://issuer",
        "token1_ttl_seconds": 90,
        "token2_ttl_seconds": 240,
        "ca_file": "docker/tls/ca.pem",
        "insecure": True,
    }


class _RunLoadgenKwargs(TypedDict):
    tokens: dict[str, Any]
    host: str
    port: int
    username: str
    password: str
    fanout_publisher_username: str | None
    fanout_publisher_password: str | None
    clients: int
    messages: int
    topic: str
    mode: str | None
    fanout_topic: str | None
    qos: int
    qos_distribution: str | None
    message_size: int
    sync_connect: bool
    token_issuer_url: str | None
    token_issuer_kind: str | None
    token_issuer_ttl: int | None
    token_issuer_no_default_roles: bool
    token_issuer_no_default_grants: bool
    token_refresh_codes: str | None
    proactive_refresh: bool
    proactive_refresh_margin_seconds: int | None
    proactive_refresh_timeout_seconds: int | None
    proactive_refresh_assert_continuity: bool
    reauth_storm: bool
    jwt_identity_binding: rs.IdentityBindingMode
    biscuit_identity_binding: rs.IdentityBindingMode
    biscuit_client_id_fact: str
    tls_enabled: bool
    tls_ca_file: str | None
    tls_insecure: bool
    biscuit_attenuate: bool
    biscuit_attenuate_denies: list[str] | None
    biscuit_attenuate_checks: list[str] | None
    biscuit_attenuate_topic: str | None
    biscuit_attenuate_op: str | None
    biscuit_attenuate_ttl: int | None
    biscuit_public_key_hex: str | None
    biscuit_public_key_file: str | None
    biscuit_delegate: bool
    biscuit_delegate_denies: list[str] | None
    biscuit_delegate_checks: list[str] | None
    biscuit_delegate_topic: str | None
    biscuit_delegate_op: str | None
    biscuit_delegate_ttl: int | None
    biscuit_delegate_public_key_hex: str | None
    biscuit_delegate_public_key_file: str | None
    biscuit_delegate_handoff: bool
    biscuit_delegate_handoff_topic: str | None
    biscuit_delegate_handoff_token: str | None
    biscuit_delegate_handoff_qos: int | None
    biscuit_delegate_handoff_retain: bool | None
    biscuit_delegate_handoff_ready_timeout_seconds: int | None


def _minimal_run_loadgen_kwargs() -> _RunLoadgenKwargs:
    return {
        "tokens": {},
        "host": "mosquitto",
        "port": 1883,
        "username": "jwt",
        "password": "token",
        "fanout_publisher_username": None,
        "fanout_publisher_password": None,
        "clients": 2,
        "messages": 3,
        "topic": "sensors/{client_id}/temp",
        "mode": None,
        "fanout_topic": None,
        "qos": 1,
        "qos_distribution": None,
        "message_size": 0,
        "sync_connect": False,
        "token_issuer_url": None,
        "token_issuer_kind": None,
        "token_issuer_ttl": None,
        "token_issuer_no_default_roles": False,
        "token_issuer_no_default_grants": False,
        "token_refresh_codes": None,
        "proactive_refresh": False,
        "proactive_refresh_margin_seconds": None,
        "proactive_refresh_timeout_seconds": None,
        "proactive_refresh_assert_continuity": False,
        "reauth_storm": False,
        "jwt_identity_binding": "off",
        "biscuit_identity_binding": "off",
        "biscuit_client_id_fact": "client_id",
        "tls_enabled": False,
        "tls_ca_file": None,
        "tls_insecure": False,
        "biscuit_attenuate": False,
        "biscuit_attenuate_denies": None,
        "biscuit_attenuate_checks": None,
        "biscuit_attenuate_topic": None,
        "biscuit_attenuate_op": None,
        "biscuit_attenuate_ttl": None,
        "biscuit_public_key_hex": None,
        "biscuit_public_key_file": None,
        "biscuit_delegate": False,
        "biscuit_delegate_denies": None,
        "biscuit_delegate_checks": None,
        "biscuit_delegate_topic": None,
        "biscuit_delegate_op": None,
        "biscuit_delegate_ttl": None,
        "biscuit_delegate_public_key_hex": None,
        "biscuit_delegate_public_key_file": None,
        "biscuit_delegate_handoff": False,
        "biscuit_delegate_handoff_topic": None,
        "biscuit_delegate_handoff_token": None,
        "biscuit_delegate_handoff_qos": None,
        "biscuit_delegate_handoff_retain": None,
        "biscuit_delegate_handoff_ready_timeout_seconds": None,
    }


def test_container_single_runs_loadgen_through_compose(monkeypatch) -> None:
    calls: list[list[str]] = []

    class Completed:
        stdout = '{"errors":[],"raw_publish_ms":[]}'

    def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN202
        calls.append(cmd)
        return Completed()

    monkeypatch.setattr(rs, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    monkeypatch.setattr(rs.subprocess, "run", fake_run)

    result = rs._run_loadgen(
        **_minimal_run_loadgen_kwargs(),
        client_topology="container-single",
        compose_files=["docker/docker-compose.yml"],
        compose_project_name="bench",
        scenario_id="TOKEN-BASELINE-JWT",
    )

    assert result["errors"] == []
    compose_call = calls[-1]
    assert compose_call[:6] == [
        "docker",
        "compose",
        "-f",
        "docker/docker-compose.yml",
        "-p",
        "bench",
    ]
    assert "run" in compose_call
    assert "loadgen" in compose_call
    assert compose_call[compose_call.index("--name") + 1] == "loadgen_bench_token_baseline_jwt_1"
    assert "--host" in compose_call
    assert compose_call[compose_call.index("--host") + 1] == "mosquitto"


def test_container_single_passes_explicit_password_map_profiles(monkeypatch) -> None:
    calls: list[list[str]] = []

    class Completed:
        stdout = '{"errors":[],"raw_publish_ms":[]}'

    def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN202
        calls.append(cmd)
        return Completed()

    monkeypatch.setattr(rs, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    monkeypatch.setattr(rs.subprocess, "run", fake_run)

    rs._run_loadgen(
        **_minimal_run_loadgen_kwargs(),
        password_map_path="benchmarks/password-map.json",
        password_map_profile="jwt_fanout_allow",
        fanout_publisher_password_map_profile="jwt_static_writer",
        client_topology="container-single",
        compose_files=["docker/docker-compose.yml"],
    )

    command = calls[-1]
    assert command[command.index("--password-map") + 1] == "benchmarks/password-map.json"
    assert command[command.index("--password-map-profile") + 1] == "jwt_fanout_allow"
    assert (
        command[command.index("--fanout-publisher-password-map-profile") + 1] == "jwt_static_writer"
    )


def test_loadgen_container_names_follow_compose_project_precedence(monkeypatch) -> None:
    monkeypatch.delenv("COMPOSE_PROJECT_NAME", raising=False)

    assert (
        rs._loadgen_container_name(
            compose_project_name=None,
            compose_files=["docker/docker-compose.yml"],
            scenario_id="TOKEN-BASELINE-JWT",
            run_index=0,
        )
        == "loadgen_docker_token_baseline_jwt_1"
    )

    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "ci-project")
    assert (
        rs._loadgen_container_name(
            compose_project_name=None,
            compose_files=["docker/docker-compose.yml"],
            scenario_id="TOKEN-BASELINE-JWT",
            run_index=0,
            client_index=1,
        )
        == "loadgen_ci_project_token_baseline_jwt_1_client_2"
    )

    assert (
        rs._loadgen_container_name(
            compose_project_name="explicit-project",
            compose_files=["docker/docker-compose.yml"],
            scenario_id="TOKEN-BASELINE-JWT",
            run_index=0,
            client_index=1,
        )
        == "loadgen_explicit_project_token_baseline_jwt_1_client_2"
    )


def test_compose_stdout_json_parser_ignores_container_status_lines() -> None:
    payload = rs._loads_json_from_compose_stdout(
        ' Container docker-loadgen-run Creating\n{"errors":[]}\n'
    )

    assert payload == {"errors": []}


def test_compose_stdout_json_parser_skips_non_json_braces() -> None:
    payload = rs._loads_json_from_compose_stdout(
        'status {not-json}\n Container docker-loadgen-run Created\n{"errors": []}\n'
    )

    assert payload == {"errors": []}


def test_container_per_client_assigns_deterministic_client_indices(monkeypatch) -> None:
    observed: list[list[str]] = []

    class FakeProcess:
        returncode = 0

        def __init__(self, cmd, **kwargs) -> None:  # noqa: ANN001
            observed.append(cmd)

        def communicate(self) -> tuple[str, str]:
            return (
                '{"connect":{"count":1,"mean_ms":1.0},'
                '"publish":{"count":0},"raw_publish_ms":[2.0],'
                '"raw_metrics":{"connect":[1.0],"publish":[2.0],"receive":[]},'
                '"errors":[],'
                '"throughput_mps":1.0,"publish_throughput_mps":1.0,'
                '"receive_throughput_mps":0.0}',
                "",
            )

    monkeypatch.setattr(rs, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    monkeypatch.setattr(rs.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(rs.subprocess, "Popen", FakeProcess)

    result = rs._run_loadgen(
        **_minimal_run_loadgen_kwargs(),
        client_topology="container-per-client",
        compose_project_name="bench",
        scenario_id="TOKEN-BASELINE-JWT",
    )

    assert len(observed) == 2
    assert observed[0][observed[0].index("--client-index-start") + 1] == "1"
    assert observed[1][observed[1].index("--client-index-start") + 1] == "2"
    first_name = observed[0][observed[0].index("--name") + 1]
    second_name = observed[1][observed[1].index("--name") + 1]
    assert first_name == "loadgen_bench_token_baseline_jwt_1_client_1"
    assert second_name == "loadgen_bench_token_baseline_jwt_1_client_2"
    assert result["topology"]["container_count"] == 2


def test_container_per_client_merge_aggregates_all_reported_metrics() -> None:
    first = {
        "inputs": {"clients": 1},
        "connect": {"count": 1, "mean_ms": 10.0},
        "publish": {"count": 1, "mean_ms": 1.0},
        "publish_qos_0": {"count": 1, "mean_ms": 1.0},
        "publish_qos_1": {"count": 0},
        "publish_qos_2": {"count": 0},
        "receive": {"count": 2, "mean_ms": 7.0},
        "token_refresh": {"count": 1, "mean_ms": 3.0},
        "token_refresh_len": {"count": 1, "mean_ms": 300.0},
        "proactive_refresh": {"count": 1, "mean_ms": 4.0},
        "proactive_refresh_len": {"count": 1, "mean_ms": 301.0},
        "qos_distribution_actual": {
            "qos_0_count": 1,
            "qos_1_count": 0,
            "qos_2_count": 0,
        },
        "received_messages": {"count": 2, "expected": 4},
        "proactive_refresh_attempts": 1,
        "proactive_refresh_successes": 1,
        "proactive_refresh_failures": 0,
        "expiry_denial_count": 0,
        "session_continuity_ok": True,
        "raw_publish_ms": [1.0],
        "raw_metrics": {
            "connect": [10.0],
            "publish": [1.0],
            "publish_qos_0": [1.0],
            "publish_qos_1": [],
            "publish_qos_2": [],
            "receive": [5.0, 9.0],
            "token_refresh": [3.0],
            "token_refresh_len": [300.0],
            "proactive_refresh": [4.0],
            "proactive_refresh_len": [301.0],
        },
        "errors": [],
        "throughput_mps": 10.0,
        "publish_throughput_mps": 10.0,
        "receive_throughput_mps": 20.0,
    }
    second = {
        **first,
        "publish_qos_0": {"count": 0},
        "publish_qos_1": {"count": 1, "mean_ms": 2.0},
        "receive": {"count": 3, "mean_ms": 9.0},
        "token_refresh": {"count": 2, "mean_ms": 5.0},
        "token_refresh_len": {"count": 2, "mean_ms": 320.0},
        "proactive_refresh": {"count": 2, "mean_ms": 6.0},
        "proactive_refresh_len": {"count": 2, "mean_ms": 321.0},
        "qos_distribution_actual": {
            "qos_0_count": 0,
            "qos_1_count": 1,
            "qos_2_count": 0,
        },
        "received_messages": {"count": 3, "expected": 4},
        "proactive_refresh_attempts": 2,
        "proactive_refresh_successes": 1,
        "proactive_refresh_failures": 1,
        "expiry_denial_count": 1,
        "session_continuity_ok": False,
        "raw_publish_ms": [2.0],
        "raw_metrics": {
            "connect": [12.0],
            "publish": [2.0],
            "publish_qos_0": [],
            "publish_qos_1": [2.0],
            "publish_qos_2": [],
            "receive": [7.0, 9.0, 11.0],
            "token_refresh": [4.0, 6.0],
            "token_refresh_len": [310.0, 330.0],
            "proactive_refresh": [5.0, 7.0],
            "proactive_refresh_len": [311.0, 331.0],
        },
        "errors": ["reauth_failed"],
        "throughput_mps": 11.0,
        "publish_throughput_mps": 11.0,
        "receive_throughput_mps": 21.0,
    }

    merged = rs._merge_per_client_loadgen_results([first, second], wall_duration_s=2.0)

    assert merged["inputs"]["clients"] == 2
    assert merged["publish"]["count"] == 2
    assert merged["publish_qos_0"]["count"] == 1
    assert merged["publish_qos_1"]["count"] == 1
    assert merged["receive"]["count"] == 5
    assert merged["receive"]["p95_ms"] == pytest.approx(10.6)
    assert merged["token_refresh"]["count"] == 3
    assert merged["proactive_refresh"]["count"] == 3
    assert merged["qos_distribution_actual"] == {
        "qos_0_count": 1,
        "qos_1_count": 1,
        "qos_2_count": 0,
    }
    assert merged["received_messages"] == {"count": 5, "expected": 8}
    assert merged["proactive_refresh_attempts"] == 3
    assert merged["proactive_refresh_successes"] == 2
    assert merged["proactive_refresh_failures"] == 1
    assert merged["expiry_denial_count"] == 1
    assert merged["session_continuity_ok"] is False
    assert merged["errors"] == ["reauth_failed"]
    assert merged["throughput_mps"] == 1.0
    assert merged["publish_throughput_mps"] == 1.0
    assert merged["receive_throughput_mps"] == 2.5
    assert merged["topology"]["wall_duration_s"] == 2.0


def test_reauth_storm_validation_accepts_complete_success() -> None:
    rs._validate_reauth_storm_result(
        "TOKEN-LIFECYCLE-REAUTH-STORM-JWT",
        {
            "reauth_storm": {
                "enabled": True,
                "attempts": 2,
                "successes": 2,
                "failures": 0,
                "session_continuity_ok": True,
            },
            "expiry_denial_count": 0,
            "session_continuity_ok": True,
        },
        client_count=2,
    )


@pytest.mark.parametrize(
    ("payload", "match"),
    (
        (
            {"reauth_storm": {"enabled": True, "attempts": 1, "successes": 1, "failures": 0}},
            "missed",
        ),
        (
            {"reauth_storm": {"enabled": True, "attempts": 2, "successes": 1, "failures": 0}},
            "successes",
        ),
        (
            {"reauth_storm": {"enabled": True, "attempts": 2, "successes": 2, "failures": 1}},
            "failures",
        ),
        (
            {
                "reauth_storm": {
                    "enabled": True,
                    "attempts": 2,
                    "successes": 2,
                    "failures": 0,
                },
                "expiry_denial_count": 1,
            },
            "expiry denials",
        ),
        (
            {
                "reauth_storm": {
                    "enabled": True,
                    "attempts": 2,
                    "successes": 2,
                    "failures": 0,
                    "session_continuity_ok": False,
                },
                "session_continuity_ok": True,
            },
            "continuity",
        ),
    ),
)
def test_reauth_storm_validation_rejects_incomplete_or_failed_runs(
    payload: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(RuntimeError, match=match):
        rs._validate_reauth_storm_result(
            "TOKEN-LIFECYCLE-REAUTH-STORM-JWT",
            payload,
            client_count=2,
        )


def test_fanout_readiness_wait_times_out_for_missing_subscribers(tmp_path) -> None:
    (tmp_path / "client_1.ready").write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="client_2.ready"):
        rs._wait_for_fanout_ready_files(tmp_path, clients=2, timeout_seconds=0)


def test_fanout_role_merge_recomputes_receive_expectations_and_churn() -> None:
    publisher = {
        "inputs": {"mode": "fanout", "clients": 2, "fanout_role": "publisher"},
        "publish": {"count": 4},
        "receive": {"count": 0},
        "raw_publish_ms": [1.0, 2.0, 3.0, 4.0],
        "raw_metrics": {"publish": [1.0, 2.0, 3.0, 4.0], "receive": []},
        "received_messages": {"count": 0, "expected": 8},
        "fanout_churn": {
            "enabled": True,
            "after_messages": 2,
            "triggered": True,
            "applied_events": 1,
        },
        "errors": [],
    }
    subscriber = {
        "inputs": {"mode": "fanout", "clients": 1, "fanout_role": "subscriber"},
        "publish": {"count": 0},
        "receive": {"count": 3},
        "raw_publish_ms": [],
        "raw_metrics": {"publish": [], "receive": [5.0, 6.0, 7.0]},
        "received_messages": {"count": 3, "expected": 4},
        "fanout_churn": {
            "enabled": True,
            "phases": [
                {"expected_deliveries": 2, "received_deliveries": 2},
                {"expected_deliveries": 2, "received_deliveries": 1},
            ],
        },
        "errors": [],
    }

    merged = rs._merge_fanout_role_loadgen_results(
        publisher=publisher,
        subscribers=[subscriber, subscriber],
        wall_duration_s=2.0,
        scenario_id="FANOUT",
        run_index=0,
        messages=4,
    )

    assert merged["received_messages"] == {"count": 6, "expected": 8}
    assert merged["fanout_churn"]["phases"] == [
        {"phase": 0, "expected_deliveries": 4, "received_deliveries": 4},
        {"phase": 1, "expected_deliveries": 4, "received_deliveries": 2},
    ]
    assert merged["topology"]["fanout_roles"] == {"publishers": 1, "subscribers": 2}


def test_container_per_client_cleans_up_siblings_on_failure(monkeypatch) -> None:
    instances: list[FakeProcess] = []
    docker_rm: list[str] = []

    class FakeProcess:
        def __init__(self, cmd, **kwargs) -> None:  # noqa: ANN001
            self.cmd = cmd
            self.returncode: int | None = None
            self.terminated = False
            instances.append(self)

        def communicate(self, timeout=None) -> tuple[str, str]:  # noqa: ANN001
            index = self.cmd[self.cmd.index("--client-index-start") + 1]
            if index == "1":
                self.returncode = 1
                return "", "boom"
            self.returncode = -15 if self.terminated else 0
            return "", ""

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.returncode = -9

    def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN202
        if cmd[:3] == ["docker", "rm", "-f"]:
            docker_rm.append(cmd[3])
        return None

    monkeypatch.setattr(rs, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    monkeypatch.setattr(rs.subprocess, "run", fake_run)
    monkeypatch.setattr(rs.subprocess, "Popen", FakeProcess)

    with pytest.raises(RuntimeError, match="loadgen_bench_token_baseline_jwt_1_client_1 failed"):
        rs._run_loadgen(
            **_minimal_run_loadgen_kwargs(),
            client_topology="container-per-client",
            compose_project_name="bench",
            scenario_id="TOKEN-BASELINE-JWT",
        )

    assert len(instances) == 2
    assert instances[1].terminated is True
    assert "client_1" not in docker_rm
    assert "client_2" not in docker_rm
    assert docker_rm.count("loadgen_bench_token_baseline_jwt_1_client_1") >= 1
    assert docker_rm.count("loadgen_bench_token_baseline_jwt_1_client_2") >= 1


def test_container_per_client_fanout_splits_subscriber_and_publisher_roles(monkeypatch) -> None:
    observed_popen: list[list[str]] = []
    observed_run: list[list[str]] = []

    class Completed:
        stdout = (
            '{"inputs":{"mode":"fanout","clients":2},'
            '"publish":{"count":2},"receive":{"count":0},'
            '"raw_publish_ms":[1.0,2.0],'
            '"raw_metrics":{"publish":[1.0,2.0],"receive":[]},'
            '"received_messages":{"count":0,"expected":4},'
            '"fanout_churn":{"enabled":false},'
            '"errors":[]}'
        )

    class FakeProcess:
        returncode = 0

        def __init__(self, cmd, **kwargs) -> None:  # noqa: ANN001
            self.cmd = cmd
            observed_popen.append(cmd)

        def communicate(self, timeout=None) -> tuple[str, str]:  # noqa: ANN001
            return (
                '{"inputs":{"mode":"fanout","clients":1},'
                '"publish":{"count":0},"receive":{"count":2},'
                '"raw_publish_ms":[],'
                '"raw_metrics":{"publish":[],"receive":[5.0,7.0]},'
                '"received_messages":{"count":2,"expected":2},'
                '"fanout_churn":{"enabled":false},'
                '"errors":[]}',
                "",
            )

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.returncode = -15

        def kill(self) -> None:
            self.returncode = -9

    def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN202
        observed_run.append(cmd)
        return Completed()

    monkeypatch.setattr(rs, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    monkeypatch.setattr(rs.subprocess, "run", fake_run)
    monkeypatch.setattr(rs.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(rs, "_wait_for_fanout_ready_files", lambda *args, **kwargs: None)

    kwargs = _minimal_run_loadgen_kwargs()
    kwargs["mode"] = "fanout"
    kwargs["messages"] = 2
    result = rs._run_loadgen(
        **kwargs,
        client_topology="container-per-client",
        compose_project_name="bench",
        scenario_id="TOKEN-ACL-READ-FANOUT-STRICT-ALLOW-JWT-10",
    )

    assert len(observed_popen) == 2
    assert all("--fanout-role" in cmd for cmd in observed_popen)
    assert all(cmd.count("--fanout-role") == 1 for cmd in observed_popen)
    assert {cmd[cmd.index("--fanout-role") + 1] for cmd in observed_popen} == {"subscriber"}
    publisher_calls = [cmd for cmd in observed_run if "--fanout-role" in cmd]
    assert publisher_calls[-1].count("--fanout-role") == 1
    assert publisher_calls[-1][publisher_calls[-1].index("--fanout-role") + 1] == "publisher"
    assert result["received_messages"] == {"count": 4, "expected": 4}
    assert result["topology"]["fanout_roles"] == {"publishers": 1, "subscribers": 2}


def test_container_per_client_delegation_handoff_splits_delegatee_and_delegator_roles(
    monkeypatch,
) -> None:
    observed_popen: list[list[str]] = []
    observed_run: list[list[str]] = []
    observed_ready_waits: list[dict[str, object]] = []

    class Completed:
        stdout = (
            '{"inputs":{"clients":2,"biscuit_delegate_handoff_role":"delegator"},'
            '"delegation":{"count":2},'
            '"delegation_handoff_publish":{"count":2},'
            '"publish":{"count":0},"receive":{"count":0},'
            '"raw_publish_ms":[],'
            '"raw_metrics":{"delegation":[1.0,2.0],'
            '"delegation_handoff_publish":[3.0,4.0],"publish":[],"receive":[]},'
            '"errors":[]}'
        )

    class FakeProcess:
        returncode = 0

        def __init__(self, cmd, **kwargs) -> None:  # noqa: ANN001
            self.cmd = cmd
            observed_popen.append(cmd)

        def communicate(self, timeout=None) -> tuple[str, str]:  # noqa: ANN001
            return (
                '{"inputs":{"clients":1,"biscuit_delegate_handoff_role":"delegatee"},'
                '"connect":{"count":1},'
                '"publish":{"count":1},'
                '"receive":{"count":0},'
                '"raw_publish_ms":[5.0],'
                '"raw_metrics":{"connect":[1.0],"publish":[5.0],"receive":[]},'
                '"errors":[]}',
                "",
            )

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.returncode = -15

        def kill(self) -> None:
            self.returncode = -9

    def fake_run(cmd, **kwargs):  # noqa: ANN001, ANN202
        observed_run.append(cmd)
        return Completed()

    monkeypatch.setattr(rs, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    monkeypatch.setattr(rs.subprocess, "run", fake_run)
    monkeypatch.setattr(rs.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(rs, "_delegation_handoff_run_id", lambda *_args: "handoff-run-1")

    def fake_wait_for_ready(*args, **kwargs) -> None:  # noqa: ANN001
        observed_ready_waits.append(kwargs)

    monkeypatch.setattr(rs, "_wait_for_delegation_handoff_ready_files", fake_wait_for_ready)

    kwargs = _minimal_run_loadgen_kwargs()
    kwargs["username"] = "biscuit"
    kwargs["biscuit_delegate"] = True
    kwargs["biscuit_delegate_handoff"] = True
    kwargs["biscuit_delegate_handoff_topic"] = "delegation/handoff"
    kwargs["biscuit_delegate_handoff_qos"] = 0
    kwargs["biscuit_delegate_handoff_retain"] = True
    kwargs["biscuit_delegate_handoff_ready_timeout_seconds"] = 17
    result = rs._run_loadgen(
        **kwargs,
        client_topology="container-per-client",
        compose_project_name="bench",
        scenario_id="TOKEN-DELEGATION-HANDOFF-BISCUIT",
    )

    assert len(observed_popen) == 2
    assert {cmd[cmd.index("--biscuit-delegate-handoff-role") + 1] for cmd in observed_popen} == {
        "delegatee"
    }
    assert {cmd[cmd.index("--biscuit-delegate-handoff-nonce") + 1] for cmd in observed_popen} == {
        "handoff-run-1"
    }
    assert {cmd[cmd.index("--biscuit-delegate-handoff-qos") + 1] for cmd in observed_popen} == {"0"}
    assert {
        cmd[cmd.index("--biscuit-delegate-handoff-ready-timeout-seconds") + 1]
        for cmd in observed_popen
    } == {"17"}
    delegator_calls = [cmd for cmd in observed_run if "--biscuit-delegate-handoff-role" in cmd]
    assert delegator_calls[-1][
        delegator_calls[-1].index("--biscuit-delegate-handoff-role") + 1
    ] == ("delegator")
    assert delegator_calls[-1][delegator_calls[-1].index("--biscuit-delegate-handoff-qos") + 1] == (
        "0"
    )
    assert (
        delegator_calls[-1][
            delegator_calls[-1].index("--biscuit-delegate-handoff-ready-timeout-seconds") + 1
        ]
        == "17"
    )
    assert observed_ready_waits[-1]["timeout_seconds"] == 17
    assert result["delegation"]["count"] == 2
    assert result["delegation_handoff_publish"]["count"] == 2
    assert result["publish"]["count"] == 2
    assert result["topology"]["delegation_handoff"]["delegatees"] == 2
    assert result["topology"]["delegation_handoff"]["qos"] == 0
    assert result["topology"]["delegation_handoff"]["run_id"] == "handoff-run-..."


def test_delegation_handoff_readiness_fails_fast_when_delegatee_exits(tmp_path) -> None:
    class ExitedProcess:
        returncode = 2

        def poll(self) -> int:
            return self.returncode

    with pytest.raises(RuntimeError, match="delegatee exited before readiness"):
        rs._wait_for_delegation_handoff_ready_files(
            tmp_path,
            clients=1,
            processes=[("loadgen_delegatee_1", ExitedProcess())],  # type: ignore[list-item]
            timeout_seconds=120,
        )


def test_delegation_handoff_merge_uses_benchmark_duration_for_throughput() -> None:
    delegator = {
        "inputs": {"clients": 2, "biscuit_delegate_handoff_role": "delegator"},
        "publish": {"count": 0},
        "receive": {"count": 0},
        "raw_publish_ms": [],
        "raw_metrics": {"publish": [], "receive": []},
        "errors": [],
    }
    delegatee = {
        "inputs": {"clients": 1, "biscuit_delegate_handoff_role": "delegatee"},
        "publish": {"count": 1},
        "receive": {"count": 0},
        "raw_publish_ms": [5.0],
        "raw_metrics": {"publish": [5.0], "receive": []},
        "errors": [],
    }

    merged = rs._merge_delegation_handoff_loadgen_results(
        delegator=delegator,
        delegatees=[delegatee, delegatee],
        wall_duration_s=100.0,
        benchmark_duration_s=2.0,
        scenario_id="TOKEN-DELEGATION-HANDOFF-BISCUIT",
        run_index=0,
        run_id="handoff-run-1",
        handoff_topic="delegation/handoff",
        handoff_qos=1,
        handoff_retain=True,
    )

    assert merged["publish"]["count"] == 2
    assert merged["publish_throughput_mps"] == pytest.approx(1.0)
    assert merged["topology"]["wall_duration_s"] == 100.0
    assert merged["topology"]["benchmark_duration_s"] == 2.0


def test_container_per_client_sync_connect_uses_cross_container_barrier(
    monkeypatch,
) -> None:
    observed: list[list[str]] = []

    class FakeProcess:
        returncode = 0

        def __init__(self, cmd, **kwargs) -> None:  # noqa: ANN001
            observed.append(cmd)

        def communicate(self) -> tuple[str, str]:
            return (
                '{"inputs":{"sync_connect":true},'
                '"connect":{"count":1,"mean_ms":1.0},'
                '"publish":{"count":0},"raw_publish_ms":[],'
                '"raw_metrics":{"connect":[1.0],"publish":[],"receive":[],'
                '"sync_connect_barrier_wait":[5.0]},'
                '"sync_connect":{"enabled":true,"barrier":"external","ready_count":1},'
                '"errors":[],'
                '"throughput_mps":0.0,"publish_throughput_mps":0.0,'
                '"receive_throughput_mps":0.0}',
                "",
            )

    monkeypatch.setattr(rs, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])
    monkeypatch.setattr(rs.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(rs.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(rs, "_sync_barrier_run_id", lambda scenario_id, run_index: "run-1")
    monkeypatch.setattr(rs, "_ensure_sync_barrier_service", lambda **kwargs: None)
    monkeypatch.setattr(
        rs,
        "_wait_for_sync_barrier_ready",
        lambda *args, **kwargs: {"ready_count": 2},
    )
    monkeypatch.setattr(
        rs,
        "_release_sync_barrier",
        lambda *args, **kwargs: {
            "ready_count": 2,
            "released_at_unix_ms": 1760000000000,
            "max_ready_skew_ms": 12.4,
        },
    )

    kwargs = _minimal_run_loadgen_kwargs()
    kwargs["sync_connect"] = True
    result = rs._run_loadgen(
        **kwargs,
        client_topology="container-per-client",
        compose_project_name="bench",
        scenario_id="TOKEN-CONNECT-BURST-JWT",
    )

    assert len(observed) == 2
    assert all("--sync-connect-barrier-url" in cmd for cmd in observed)
    assert {cmd[cmd.index("--sync-connect-participant-id") + 1] for cmd in observed} == {
        "client_1",
        "client_2",
    }
    assert result["sync_connect"]["barrier"] == "external"
    assert result["sync_connect"]["ready_count"] == 2
    assert result["sync_connect"]["max_ready_skew_ms"] == pytest.approx(12.4)
    assert result["sync_connect"]["client_wait"]["count"] == 2


def test_container_per_client_runtime_control_uses_one_coordinated_controller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher_commands: list[list[str]] = []
    run_commands: list[list[str]] = []

    class FakeProcess:
        returncode = 0

        def __init__(self, cmd, **kwargs) -> None:  # noqa: ANN001
            publisher_commands.append(cmd)

        def poll(self) -> None:
            return None

        def communicate(self) -> tuple[str, str]:
            return (
                '{"inputs":{"clients":1},"connect":{"count":1},'
                '"publish":{"count":2},"raw_publish_ms":[1.0,2.0],'
                '"raw_metrics":{"connect":[3.0],"publish":[1.0,2.0],'
                '"receive":[],"control":[],"policy_denial_count":1},'
                '"errors":[],"throughput_mps":1.0,'
                '"publish_throughput_mps":1.0,"receive_throughput_mps":0.0}',
                "",
            )

    class Completed:
        returncode = 0
        stdout = (
            '{"connect":{"count":1},"control":{"count":1},'
            '"raw_metrics":{"connect":[99.0],"control":[4.0]},'
            '"errors":[]}'
        )
        stderr = ""

    def fake_run(cmd, **kwargs):  # noqa: ANN001
        run_commands.append(cmd)
        return Completed()

    monkeypatch.setattr(rs.subprocess, "run", fake_run)
    monkeypatch.setattr(rs.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(rs, "_sync_barrier_run_id", lambda *_args: "runtime-run")
    monkeypatch.setattr(rs, "_ensure_sync_barrier_service", lambda **_kwargs: None)
    monkeypatch.setattr(
        rs,
        "_wait_for_sync_barrier_ready",
        lambda *_args, **_kwargs: {"ready_count": 2},
    )
    monkeypatch.setattr(
        rs,
        "_release_sync_barrier",
        lambda *_args, **_kwargs: {
            "ready_count": 2,
            "released_at_unix_ms": 1760000000000,
        },
    )

    args = [
        "--host",
        "mosquitto",
        "--port",
        "1883",
        "--username",
        "dynsec_client_1",
        "--password",
        "publisher-password",
        "--password-map-profile",
        "jwt",
        "--clients",
        "2",
        "--messages",
        "5",
        "--topic",
        "sensors/{client_id}/temp",
        "--qos",
        "1",
        "--message-size",
        "0",
        "--json",
        "--control-topic",
        "$CONTROL/dynamic-security/v1",
        "--control-payload",
        "{}",
        "--runtime-control-username",
        "admin",
        "--runtime-control-password",
        "admin-password",
        "--runtime-control-after-messages",
        "4",
        "--runtime-control-expect-denial",
    ]
    result = rs._run_loadgen_container_per_client(
        args,
        clients=2,
        service="loadgen",
        scenario_id="DYNAMIC-SECURITY-CHURN",
        run_index=0,
        compose_files=["docker/docker-compose.yml"],
        compose_project_name="bench",
        extra_env={},
        sync_connect=False,
        runtime_control=rs.PerClientRuntimeControl(
            username="admin",
            password="admin-password",
            after_messages=4,
            expect_denial=True,
        ),
    )

    assert len(publisher_commands) == 2
    assert all("--runtime-control-username" not in cmd for cmd in publisher_commands)
    assert all("--runtime-control-barrier-url" in cmd for cmd in publisher_commands)
    assert {
        cmd[cmd.index("--runtime-control-local-after-messages") + 1] for cmd in publisher_commands
    } == {"2"}
    controller_commands = [cmd for cmd in run_commands if "--control-mode" in cmd]
    assert len(controller_commands) == 1
    assert (
        controller_commands[0][controller_commands[0].index("--client-id") + 1]
        == "runtime-dynsec-controller"
    )
    assert "--password-map-profile" not in controller_commands[0]
    assert result["connect"]["count"] == 2
    assert result["raw_metrics"]["runtime_control_connect_ms"] == pytest.approx(99.0)
    assert result["control"]["count"] == 1
    assert result["policy_denial_count"] == 2
    assert result["runtime_control"]["local_quotas"] == [2, 2]


def test_runtime_control_quotas_preserve_exact_aggregate_threshold() -> None:
    assert rs._runtime_control_quotas(clients=3, after_messages=2) == [1, 1, 0]
    assert sum(rs._runtime_control_quotas(clients=4, after_messages=11)) == 11
