#!/usr/bin/env python3
from __future__ import annotations

import os
import shlex
import subprocess
import time
import uuid
from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from benchmarks import run_scenarios as rs
from benchmarks.run_scenarios import _resource_snapshot, _validate_resource_snapshot

REPO_ROOT = Path(__file__).resolve().parents[1]
PROMETHEUS_BASE_URL = "http://localhost:9090"


def _compose_bin() -> list[str]:
    return shlex.split(os.environ.get("DOCKER_COMPOSE_BIN", "docker compose"))


def _compose(args: list[str], *, project_name: str, check: bool = True) -> None:
    env = os.environ.copy()
    env["COMPOSE_PROJECT_NAME"] = project_name
    cmd = _compose_bin() + ["-f", "docker/docker-compose.yml"] + args
    subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        check=check,
    )


def _wait_for_prometheus_api(timeout_seconds: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(
                    PROMETHEUS_BASE_URL.rstrip("/") + "/api/v1/query",
                    params={"query": "up"},
                )
                if resp.status_code == 200 and resp.json().get("status") == "success":
                    return
        except Exception:
            pass
        time.sleep(1.0)
    raise RuntimeError("timed out waiting for Prometheus query API to become ready")


def _wait_for_non_empty_snapshot(
    timeout_seconds: float = 45.0,
    *,
    compose_project_name: str | None = None,
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            snap = _resource_snapshot(
                PROMETHEUS_BASE_URL,
                None,
                False,
                compose_project_name=compose_project_name,
            )
            _validate_resource_snapshot(
                snap,
                scenario_id="RESOURCE-SNAPSHOT-TEST",
                run_index=0,
            )
            return snap
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(2.0)
    raise AssertionError(
        "timed out waiting for non-empty Prometheus vectors for mosquitto: " f"{last_error!r}"
    )


@pytest.fixture(scope="module")
def resource_stack() -> Generator[str]:
    reuse_project_name = os.environ.get("RESOURCE_SNAPSHOT_COMPOSE_PROJECT_NAME")
    if reuse_project_name:
        # Reuse an existing compose stack (e.g. pre-commit python-tests hook) to
        # avoid host port collisions from a second project binding 1883/9090/8080.
        started_here = False
        try:
            rs._compose_service_container_id(
                "mosquitto",
                compose_files=["docker/docker-compose.yml"],
                compose_project_name=reuse_project_name,
            )
        except RuntimeError:
            _compose(
                ["up", "-d", "mosquitto", "metrics-collector", "cadvisor"],
                project_name=reuse_project_name,
            )
            started_here = True

        try:
            _wait_for_prometheus_api()
            yield reuse_project_name
        finally:
            if started_here:
                _compose(
                    ["down", "--remove-orphans", "--volumes"],
                    project_name=reuse_project_name,
                    check=False,
                )
        return

    project_name = f"resource-snapshot-{uuid.uuid4().hex[:8]}"
    _compose(
        ["up", "-d", "mosquitto", "metrics-collector", "cadvisor"],
        project_name=project_name,
    )
    try:
        _wait_for_prometheus_api()
        yield project_name
    finally:
        _compose(
            ["down", "--remove-orphans", "--volumes"],
            project_name=project_name,
            check=False,
        )


def test_validate_resource_snapshot_rejects_empty_vectors() -> None:
    snap = {
        "prometheus": {
            "cpu": {"status": "success", "data": {"resultType": "vector", "result": []}},
            "memory": {"status": "success", "data": {"resultType": "vector", "result": []}},
        }
    }
    with pytest.raises(RuntimeError, match="result vector is empty"):
        _validate_resource_snapshot(snap, scenario_id="UNIT-TEST", run_index=0)


def test_resource_snapshot_collects_non_empty_cpu_and_memory(resource_stack: str) -> None:
    snap = _wait_for_non_empty_snapshot(compose_project_name=resource_stack)
    cpu = snap["prometheus"]["cpu"]["data"]["result"]
    memory = snap["prometheus"]["memory"]["data"]["result"]
    assert cpu
    assert memory


def test_resource_snapshot_fails_for_invalid_prometheus_url(monkeypatch) -> None:
    # Avoid depending on local Docker availability for this URL-path unit test.
    monkeypatch.setattr(
        rs,
        "_compose_service_container_id",
        lambda *args, **kwargs: "abcdef123456",
    )
    with pytest.raises(httpx.HTTPError):
        _resource_snapshot("http://localhost:9999", None, False)


def test_compose_service_container_id_uses_project_flag_and_running_filter(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_run(cmd, cwd, env, capture_output, text, check):  # noqa: ANN001
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["env"] = env
        assert capture_output is True
        assert text is True
        assert check is True
        return SimpleNamespace(stdout="abcdef1234567890\n")

    monkeypatch.setattr(rs.subprocess, "run", _fake_run)

    container_id = rs._compose_service_container_id(
        "mosquitto",
        compose_files=["docker/docker-compose.yml"],
        compose_project_name="resource-snapshot-test",
    )

    assert container_id == "abcdef123456"
    assert captured["cmd"] == [
        "docker",
        "compose",
        "-f",
        "docker/docker-compose.yml",
        "-p",
        "resource-snapshot-test",
        "ps",
        "--status",
        "running",
        "-q",
        "mosquitto",
    ]


def test_compose_service_container_id_fails_on_multiple_running_ids(monkeypatch) -> None:
    def _fake_run(*args, **kwargs):  # noqa: ANN002, ANN003
        return SimpleNamespace(stdout="abcdef1234567890\n1234567890abcdef\n")

    monkeypatch.setattr(rs.subprocess, "run", _fake_run)

    with pytest.raises(RuntimeError, match="Multiple running containers found"):
        rs._compose_service_container_id(
            "mosquitto",
            compose_files=["docker/docker-compose.yml"],
            compose_project_name="resource-snapshot-test",
        )


def test_compose_service_container_id_fails_when_no_running_id(monkeypatch) -> None:
    def _fake_run(*args, **kwargs):  # noqa: ANN002, ANN003
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(rs.subprocess, "run", _fake_run)

    with pytest.raises(RuntimeError, match="No running container found"):
        rs._compose_service_container_id(
            "mosquitto",
            compose_files=["docker/docker-compose.yml"],
            compose_project_name="resource-snapshot-test",
        )
