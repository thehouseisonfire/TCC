from __future__ import annotations

import pytest

from benchmarks import run_scenarios as rs


@pytest.mark.parametrize("source", ["http", "hybrid"])
@pytest.mark.parametrize(
    ("clients", "qos", "expected"),
    [
        (10, 1, 10),
        (10, 2, 10),
        (50, 1, 10),
        (50, 2, 10),
        (200, 1, 25),
        (200, 2, 25),
        (100, 1, 15),
        (101, 1, 16),
        (51, 2, 11),
        (0, 2, 10),
        (200, 0, 10),
    ],
)
def test_http_completion_rounds(source: str, clients: int, qos: int, expected: int) -> None:
    scenario: rs.ScenarioConfig = {"id": "test", "mosquitto_conf": f"mosquitto_{source}.conf"}
    budgets = rs._watchdog_metadata(scenario, clients, qos)
    assert budgets == {
        "publish_timeout_seconds": expected,
        "connect_timeout_seconds": 10,
        "keepalive_seconds": 60,
    }


@pytest.mark.parametrize("source", ["token", "static_acl", "dynamic_security", "sqlite", "none"])
@pytest.mark.parametrize("qos", [0, 1, 2])
def test_local_policy_budgets_unchanged(source: str, qos: int) -> None:
    scenario: rs.ScenarioConfig = {"id": "test", "policy_source": source}
    assert rs._publish_timeout_seconds(scenario, 200, qos) == 10


def test_delayed_budgets_and_single_publisher_fanout_unchanged() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "test",
        "policy_source": "http",
        "http_expected_delay_ms": 1000,
    }
    for qos in (0, 1, 2):
        assert rs._publish_timeout_seconds(scenario, 200, qos) == 415
    scenario = {"id": "test", "policy_source": "http", "traffic_pattern": "fanout"}
    assert rs._publish_timeout_seconds(scenario, 200, 2) == 10


def test_actual_qos_distribution_and_scenario_override() -> None:
    scenario: rs.ScenarioConfig = {"id": "test", "policy_source": "http", "qos": 2}
    assert rs._publish_timeout_seconds(scenario, 200) == 25
    assert rs._publish_timeout_seconds(scenario, 200, 0) == 10
    assert rs._publish_timeout_seconds(scenario, 200, 0, "0:0.9,1:0.1,2:0") == 25
    assert rs._publish_timeout_seconds(scenario, 200, 0, "0:0.9,2:0.1") == 25
