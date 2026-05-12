from __future__ import annotations

from pathlib import Path

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
