from __future__ import annotations

import pytest

from benchmarks import run_scenarios as rs


def _latency_scenario(
    delay_ms: int,
    scenario_id: str = "HTTP-LATENCY-1000MS-JWT",
) -> rs.ScenarioConfig:
    return {
        "id": scenario_id,
        "http_expected_delay_ms": delay_ms,
        "traffic_pattern": "per_client",
    }


def test_http_latency_cache_ttl_uses_full_workload_and_quiescence_budget() -> None:
    scenario = _latency_scenario(1000)

    # 50 * 1000 ms would be only one serialized client round (65 s); the full
    # 50 * 100 workload budget is 7,515 s using the existing quiescence basis.
    assert rs._session_cache_ttl_seconds(scenario, clients=50, messages=100) == 7515
    assert rs._session_cache_ttl_seconds(scenario, clients=200, messages=100) == 30015


def test_http_latency_cache_ttl_keeps_default_for_short_workloads() -> None:
    assert rs._session_cache_ttl_seconds(_latency_scenario(200), clients=50, messages=100) == 3600
    assert rs._session_cache_ttl_seconds(_latency_scenario(1000), clients=10, messages=100) == 3600


@pytest.mark.parametrize(
    ("clients", "messages", "delay_ms", "expected_ttl"),
    (
        (10, 10, 200, 3600),
        (10, 10, 1000, 3600),
        (10, 100, 200, 3600),
        (10, 100, 1000, 3600),
        (50, 10, 200, 3600),
        (50, 10, 1000, 3600),
        (50, 100, 200, 3600),
        (50, 100, 1000, 7515),
        (200, 10, 200, 3600),
        (200, 10, 1000, 3600),
        (200, 100, 200, 14015),
        (200, 100, 1000, 30015),
    ),
)
def test_http_latency_ttl_budget_table(
    clients: int, messages: int, delay_ms: int, expected_ttl: int
) -> None:
    assert (
        rs._session_cache_ttl_seconds(
            _latency_scenario(delay_ms), clients=clients, messages=messages
        )
        == expected_ttl
    )


def test_http_latency_ttl_does_not_change_non_latency_scenarios() -> None:
    scenario = _latency_scenario(1000, scenario_id="HTTP-PROFILE-SIMPLE-JWT")
    assert rs._session_cache_ttl_seconds(scenario, clients=200, messages=100) == 3600


def test_render_mosquitto_runtime_conf_overrides_only_requested_cache_ttl() -> None:
    base_conf = """listener 1883
plugin /mosquitto/plugins/libmosquitto_auth_biscuit.so
plugin_opt_jwt_key_file /mosquitto/config/jwt_public.pem
plugin_opt_biscuit_root_key_file /mosquitto/config/biscuit_public.key
plugin_opt_cache_ttl_seconds 3600
"""

    rendered = rs._render_mosquitto_runtime_conf(
        base_conf,
        jwt_identity_binding="off",
        biscuit_identity_binding="off",
        biscuit_client_id_fact="client_id",
        cache_ttl_seconds=7515,
    )

    assert rendered.count("plugin_opt_cache_ttl_seconds ") == 1
    assert "plugin_opt_cache_ttl_seconds 7515\n" in rendered
    assert "plugin_opt_jwt_identity_binding off\n" in rendered


def test_http_latency_ttl_preserves_workload_and_watchdog_contracts() -> None:
    scenario = _latency_scenario(1000)
    assert scenario["http_expected_delay_ms"] == 1000
    assert (
        rs._expected_publish_authorization_count(scenario, message_count=100, client_count=50)
        == 5000
    )
    assert rs._publish_timeout_seconds(scenario, 50) == 115
    assert rs._mqtt_keepalive_seconds(scenario, 50) == 65
    assert rs._qos0_quiescence_timeout_seconds(scenario, clients=50, expected_count=5000) == 7515


def test_http_latency_scenario_matrix_and_part2_inventory_are_unchanged() -> None:
    assert len(rs.PART2_SWEEP_COHORTS["matrix"]) == 22
    assert rs.part2_expected_slot_total() == 1512
