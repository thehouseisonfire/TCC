from __future__ import annotations

from typing import Any, cast

import pytest

from benchmarks import run_scenarios as rs
from benchmarks.test_runner_startup_readiness import _minimal_run_loadgen_kwargs
from benchmarks.test_scenario_semantics import _scenario_registry

_PARTICIPANT_PAYLOAD = (
    '{"inputs":{"sync_connect":true},'
    '"connect":{"count":1,"mean_ms":1.0},'
    '"publish":{"count":0},"raw_publish_ms":[],'
    '"raw_metrics":{"connect":[1.0],"publish":[],"receive":[],'
    '"sync_connect_barrier_wait":[5.0],"sync_publish_barrier_wait":[7.0]},'
    '"sync_connect":{"enabled":true,"barrier":"external","ready_count":1},'
    '"errors":[],'
    '"throughput_mps":0.0,"publish_throughput_mps":0.0,'
    '"receive_throughput_mps":0.0}'
)


def _run_sync_cpc(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sync_connect: bool,
    qos: int = 1,
    wait_fn: Any = None,
    release_fn: Any = None,
) -> tuple[dict[str, Any], list[list[str]]]:
    observed: list[list[str]] = []

    class FakeProcess:
        returncode = 0

        def __init__(self, cmd, **kwargs) -> None:  # noqa: ANN001
            observed.append(cmd)

        def poll(self) -> None:
            return None

        def communicate(self) -> tuple[str, str]:
            return (_PARTICIPANT_PAYLOAD, "")

    monkeypatch.setattr(rs.subprocess, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(rs.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(
        rs, "_sync_barrier_run_id", lambda scenario_id, run_index: f"{scenario_id}-{run_index}"
    )
    monkeypatch.setattr(rs, "_ensure_sync_barrier_service", lambda **kwargs: None)
    monkeypatch.setattr(
        rs,
        "_wait_for_sync_barrier_ready",
        wait_fn if wait_fn is not None else (lambda *args, **kwargs: {"ready_count": 2}),
    )
    monkeypatch.setattr(
        rs,
        "_release_sync_barrier",
        release_fn
        if release_fn is not None
        else (
            lambda *args, **kwargs: {
                "ready_count": 2,
                "released_at_unix_ms": 1760000000000,
                "max_ready_skew_ms": 12.4,
            }
        ),
    )

    kwargs = _minimal_run_loadgen_kwargs()
    kwargs["sync_connect"] = sync_connect
    kwargs["qos"] = qos
    result = rs._run_loadgen(
        **kwargs,
        client_topology="container-per-client",
        compose_project_name="bench",
        scenario_id="HTTP-PROFILE-SIMPLE-BISCUIT",
    )
    return result, observed


def test_two_phase_helpers_use_distinct_run_ids_and_options() -> None:
    connect_args = rs._append_sync_barrier_args(
        ["mqtt-loadgen"],
        run_id="run-1",
        participant_id="client_1",
        participants=3,
    )
    publish_args = rs._append_sync_connect_publish_barrier_args(
        ["mqtt-loadgen"],
        run_id="run-1-publish",
        participant_id="client_1",
        participants=3,
    )
    assert "--sync-connect-barrier-url" in connect_args
    assert "--sync-connect-publish-barrier-url" not in connect_args
    assert "--sync-connect-publish-barrier-url" in publish_args
    assert "--sync-connect-barrier-url" not in publish_args
    assert (
        connect_args[connect_args.index("--sync-connect-run-id") + 1]
        != publish_args[publish_args.index("--sync-connect-publish-run-id") + 1]
    )


def test_publish_barrier_run_id_is_a_distinct_phase_of_the_connect_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rs, "_sync_barrier_run_id", lambda scenario_id, run_index: "run-1")
    assert rs._sync_connect_publish_barrier_run_id("SCENARIO", 0) == "run-1-publish"


def test_container_per_client_releases_publish_only_after_every_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str]] = []

    def fake_wait(run_id, **kwargs):  # noqa: ANN001
        events.append(("wait", f"{run_id}:{kwargs.get('phase')}"))
        return {"ready_count": 2}

    def fake_release(run_id, **kwargs):  # noqa: ANN001
        events.append(("release", run_id))
        return {
            "ready_count": 2,
            "released_at_unix_ms": 1760000000000,
            "max_ready_skew_ms": 12.4,
        }

    result, _ = _run_sync_cpc(
        monkeypatch, sync_connect=True, wait_fn=fake_wait, release_fn=fake_release
    )

    phases = [event for event in events if event[0] == "wait"]
    assert phases[0][1].endswith(":connect")
    assert phases[1][1].endswith(":publish")
    assert events.index(("release", "HTTP-PROFILE-SIMPLE-BISCUIT-0")) < events.index(
        ("wait", "HTTP-PROFILE-SIMPLE-BISCUIT-0-publish:publish")
    )
    publish = result["sync_connect"]["publish_barrier"]
    assert publish["barrier"] == "external"
    assert publish["run_id"] == "HTTP-PROFILE-SIMPLE-BISCUIT-0-publish"
    assert publish["ready_count"] == 2
    assert publish["max_ready_skew_ms"] == pytest.approx(12.4)
    assert publish["client_wait"]["count"] == 2


def test_container_per_client_qos_variants_share_connection_sync(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for qos in (0, 1, 2):
        _, observed = _run_sync_cpc(monkeypatch, sync_connect=True, qos=qos)
        assert observed
        for cmd in observed:
            assert "--sync-connect-barrier-url" in cmd
            assert "--sync-connect-publish-barrier-url" in cmd
            assert cmd[cmd.index("--qos") + 1] == str(qos)


def test_runtime_control_barrier_run_id_is_independent_of_both_sync_phases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []

    class FakeProcess:
        returncode = 0

        def __init__(self, cmd, **kwargs) -> None:  # noqa: ANN001
            observed.append(cmd)

        def poll(self) -> None:
            return None

        def communicate(self) -> tuple[str, str]:
            return (
                _PARTICIPANT_PAYLOAD,
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

    monkeypatch.setattr(rs.subprocess, "run", lambda *args, **kwargs: Completed())
    monkeypatch.setattr(rs.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(
        rs, "_sync_barrier_run_id", lambda scenario_id, run_index: f"{scenario_id}-{run_index}"
    )
    monkeypatch.setattr(rs, "_ensure_sync_barrier_service", lambda **kwargs: None)
    monkeypatch.setattr(
        rs, "_wait_for_sync_barrier_ready", lambda *args, **kwargs: {"ready_count": 2}
    )
    monkeypatch.setattr(
        rs,
        "_release_sync_barrier",
        lambda *args, **kwargs: {"ready_count": 2, "released_at_unix_ms": 1760000000000},
    )

    rs._run_loadgen_container_per_client(
        [
            "--host",
            "mosquitto",
            "--port",
            "1883",
            "--username",
            "jwt",
            "--password",
            "token",
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
            "2",
        ],
        clients=2,
        service="loadgen",
        scenario_id="HTTP-PROFILE-SIMPLE-BISCUIT",
        run_index=0,
        compose_files=["docker/docker-compose.yml"],
        compose_project_name="bench",
        extra_env={},
        sync_connect=True,
        runtime_control=rs.PerClientRuntimeControl(
            username="admin",
            password="admin-password",
            after_messages=2,
            expect_denial=False,
        ),
    )
    connect_ids = {
        cmd[cmd.index("--sync-connect-run-id") + 1]
        for cmd in observed
        if "--sync-connect-run-id" in cmd
    }
    publish_ids = {
        cmd[cmd.index("--sync-connect-publish-run-id") + 1]
        for cmd in observed
        if "--sync-connect-publish-run-id" in cmd
    }
    runtime_ids = {
        cmd[cmd.index("--runtime-control-run-id") + 1]
        for cmd in observed
        if "--runtime-control-run-id" in cmd
    }
    assert connect_ids == {"HTTP-PROFILE-SIMPLE-BISCUIT-0"}
    assert publish_ids == {"HTTP-PROFILE-SIMPLE-BISCUIT-0-publish"}
    assert runtime_ids == {"HTTP-PROFILE-SIMPLE-BISCUIT-runtime-control-0"}
    assert connect_ids.isdisjoint(publish_ids)
    assert publish_ids.isdisjoint(runtime_ids)


class _ExitedProcess:
    def __init__(self, payload: str, returncode: int = 1) -> None:
        self._payload = payload
        self.returncode = returncode

    def poll(self) -> int:
        return self.returncode

    def communicate(self) -> tuple[str, str]:
        return (self._payload, "")


def test_publish_phase_connect_failure_is_reported_as_a_connect_failure() -> None:
    payload = (
        '{"connect":{"count":0},"publish":{"count":0},'
        '"raw_metrics":{"connect":[],"publish":[]},'
        '"errors":["connect_failed:connect_timeout"]}'
    )
    processes = cast("list[tuple[str, Any]]", [("client_2", _ExitedProcess(payload))])
    with pytest.raises(RuntimeError, match="treating as a connect failure") as excinfo:
        rs._wait_for_sync_barrier_ready(
            "run-1-publish",
            participants=2,
            processes=processes,
            phase="publish",
            timeout_seconds=5.0,
        )
    assert "connect_failed:connect_timeout" in str(excinfo.value)


def test_publish_phase_timeout_names_the_publish_phase(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rs, "_sync_barrier_status", lambda run_id: None)

    class _LiveProcess:
        returncode = None

        def poll(self) -> None:
            return None

    with pytest.raises(RuntimeError, match="sync barrier publish readiness") as excinfo:
        rs._wait_for_sync_barrier_ready(
            "run-1-publish",
            participants=2,
            processes=cast("list[tuple[str, Any]]", [("client_1", _LiveProcess())]),
            phase="publish",
            timeout_seconds=0.05,
        )
    assert "run-1-publish" in str(excinfo.value)


def test_thundering_herd_keeps_simultaneous_connect_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        rs, "_sync_barrier_run_id", lambda scenario_id, run_index: f"{scenario_id}-{run_index}"
    )
    herd = _scenario_registry()["TOKEN-THUNDERING-HERD-JWT"]
    assert herd["sync_connect"] is True
    assert herd["restart_mosquitto"] is True

    result, _ = _run_sync_cpc(monkeypatch, sync_connect=True)
    connect = result["sync_connect"]
    assert connect["barrier"] == "external"
    assert connect["ready_count"] == 2
    assert connect["publish_barrier"]["ready_count"] == 2
    assert result["connect"]["count"] == 2
