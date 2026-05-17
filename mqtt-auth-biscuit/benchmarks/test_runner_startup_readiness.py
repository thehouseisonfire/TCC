from __future__ import annotations

from pathlib import Path
from typing import Any, TypedDict

import pytest

from benchmarks import run_scenarios as rs


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
    endpoints = rs._scenario_endpoint_config(
        client_topology_mode="container-single",
        scenario_tls=False,
        tls_ca="docker/tls/ca.pem",
    )

    assert endpoints["host_mqtt_host"] == "localhost"
    assert endpoints["loadgen_mqtt_host"] == "mosquitto"
    assert endpoints["mqtt_port"] == 1883
    assert endpoints["loadgen_token_issuer_base"] == "http://token-issuer:8082"
    assert endpoints["loadgen_tls_ca"] == "/workspace/docker/tls/ca.pem"


def test_host_endpoint_config_uses_localhost_for_loadgen_and_mqtt5_auth() -> None:
    endpoints = rs._scenario_endpoint_config(
        client_topology_mode="host",
        scenario_tls=True,
        tls_ca="docker/tls/ca.pem",
    )

    assert endpoints["host_mqtt_host"] == "localhost"
    assert endpoints["loadgen_mqtt_host"] == "localhost"
    assert endpoints["mqtt_port"] == 8883
    assert endpoints["loadgen_token_issuer_base"] == "https://localhost:8444"
    assert endpoints["loadgen_tls_ca"] == "docker/tls/ca.pem"


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


def test_container_per_client_rejects_fanout_until_split_roles_exist(monkeypatch) -> None:
    monkeypatch.setattr(rs, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])

    kwargs = _minimal_run_loadgen_kwargs()
    kwargs["mode"] = "fanout"
    with pytest.raises(RuntimeError, match="not supported for fanout"):
        rs._run_loadgen(
            **kwargs,
            client_topology="container-per-client",
            scenario_id="TOKEN-ACL-READ-FANOUT-STRICT-ALLOW-JWT-10",
        )


def test_container_per_client_rejects_sync_connect_until_cross_container_barrier_exists(
    monkeypatch,
) -> None:
    monkeypatch.setattr(rs, "_resolve_rust_helper", lambda _binary: ["mqtt-loadgen"])

    kwargs = _minimal_run_loadgen_kwargs()
    kwargs["sync_connect"] = True
    with pytest.raises(RuntimeError, match="not supported for sync_connect"):
        rs._run_loadgen(
            **kwargs,
            client_topology="container-per-client",
            scenario_id="TOKEN-CONNECT-BURST-JWT",
        )
