import json
import math
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from benchmarks import run_scenarios as rs


def _measured_result(
    connect_count: int,
    publish_count: int,
    receive_count: int = 0,
    control_count: int = 0,
) -> dict[str, Any]:
    connect = [1.0] * connect_count
    publish = [1.0] * publish_count
    receive = [1.0] * receive_count
    control = [1.0] * control_count
    return {
        "connect": rs._summary_from_values(connect),
        "publish": rs._summary_from_values(publish),
        "receive": rs._summary_from_values(receive),
        "control": rs._summary_from_values(control),
        "publish_qos_0": rs._summary_from_values([]),
        "publish_qos_1": rs._summary_from_values(publish),
        "publish_qos_2": rs._summary_from_values([]),
        "raw_metrics": {
            "connect": connect,
            "publish": publish,
            "receive": receive,
            "control": control,
            "publish_qos_0": [],
            "publish_qos_1": publish,
            "publish_qos_2": [],
        },
        "publish_throughput_mps": float(publish_count),
        "receive_throughput_mps": float(receive_count),
        "throughput_mps": float(receive_count),
    }


def test_broker_diagnostic_snapshot_queries_current_atomic_counters(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(command, **kwargs):  # noqa: ANN001
        captured["command"] = command
        captured["input"] = kwargs["input"]
        return SimpleNamespace(
            stdout=json.dumps(
                {
                    "authentication": {
                        "attempts": 4,
                        "successes": 4,
                        "cache_hits": 20,
                        "cache_misses": 2,
                    },
                    "authorization": {"policy_mode": "TokenOnly", "checks": 40},
                }
            )
        )

    monkeypatch.setattr(rs.subprocess, "run", fake_run)
    snapshot = rs._broker_diagnostic_snapshot(
        compose_files=["docker/docker-compose.yml"],
        compose_project_name="phase2",
        extra_env={},
    )

    assert captured["command"][-8:] == [
        "exec",
        "-T",
        "mosquitto",
        "nc",
        "-w",
        "2",
        "127.0.0.1",
        str(rs.BENCHMARK_DIAGNOSTICS_PORT),
    ]
    assert captured["input"] == "snapshot\n"
    assert snapshot["authentication"]["attempts"] == 4
    assert snapshot["authentication"]["cache_hits"] == 20
    assert snapshot["authentication"]["cache_misses"] == 2
    assert snapshot["authorization"]["checks"] == 40


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url, json=None, headers=None):
        self.calls.append({"url": url, "json": json, "headers": headers})
        return _FakeResponse(self.payload)


def _placeholder_tokens() -> dict[str, str]:
    source = Path(rs.__file__).read_text()
    keys = set(re.findall(r'tokens\["([^"]+)"\]', source))
    keys.update(re.findall(r'tokens\.get\("([^"]+)"', source))
    return {key: f"{key}-fixture" for key in keys}


def test_expected_authz_state_for_http_policy_complex():
    cfg = rs._http_profile_authz_config("complex")
    expected = rs._expected_authz_state(cfg, dict(rs.AUTHZ_BASELINE_STATE))
    assert expected["authz_profile"] == "complex"
    assert expected["rules_count"] == 10
    assert expected["client_roles_count"] == 3
    assert expected["jwt_identity_binding"] == "off"


def test_expected_authz_state_for_http_policy_med():
    cfg = rs._http_profile_authz_config("med")
    expected = rs._expected_authz_state(cfg, dict(rs.AUTHZ_BASELINE_STATE))
    assert expected["authz_profile"] == "med"
    assert expected["rules_count"] == 6
    assert expected["client_roles_count"] == 3
    assert expected["jwt_identity_binding"] == "off"


def test_expected_authz_state_for_none_uses_baseline():
    expected = rs._expected_authz_state(None, dict(rs.AUTHZ_BASELINE_STATE))
    assert expected == rs.AUTHZ_BASELINE_STATE


def test_profile_rule_counts_match_authz_profiles():
    assert rs.AUTHZ_PROFILE_RULE_COUNT["med"] == 6
    assert rs.AUTHZ_PROFILE_RULE_COUNT["complex"] == 10


def test_expected_authz_state_counts_profile_rules_plus_custom_rules():
    cfg: rs.AuthzConfig = {
        "authz_profile": "med",
        "rules": [{"effect": "allow", "ops": ["read"], "topics": ["#"]}],
        "client_roles": {"client_x": ["reader"]},
        "jwt_identity_binding": "strict",
    }
    expected = rs._expected_authz_state(cfg, dict(rs.AUTHZ_BASELINE_STATE))
    assert expected["rules_count"] == rs.AUTHZ_PROFILE_RULE_COUNT["med"] + 1
    assert expected["client_roles_count"] == 1
    assert expected["jwt_identity_binding"] == "strict"


def test_expected_authz_state_uses_runtime_baseline_for_non_default_startup():
    runtime_baseline = {
        "delay_ms": 0,
        "fail_mode": "none",
        "fail_rate": 0.0,
        "authz_profile": "simple",
        "rules_count": 0,
        "client_roles_count": 0,
        "jwt_identity_binding": "strict",
    }
    expected = rs._expected_authz_state(None, runtime_baseline)
    assert expected == runtime_baseline


def test_assert_authz_state_raises_on_mismatch():
    with pytest.raises(RuntimeError, match="Authz state mismatch"):
        rs._assert_authz_state(
            "JWT-HTTP-1000MS",
            "authz config apply",
            {**rs.AUTHZ_BASELINE_STATE, "authz_profile": "complex"},
            rs._expected_authz_state(None, dict(rs.AUTHZ_BASELINE_STATE)),
        )


def test_validated_authz_state_baseline_accepts_non_default_values():
    observed = {
        "delay_ms": 0,
        "fail_mode": "none",
        "fail_rate": 0,
        "authz_profile": "simple",
        "rules_count": 0,
        "client_roles_count": 0,
        "jwt_identity_binding": "off",
    }
    baseline = rs._validated_authz_state_baseline("JWT-HTTP-1000MS", "authz reset", observed)
    assert baseline["authz_profile"] == "simple"
    rs._assert_authz_state("JWT-HTTP-1000MS", "authz reset", observed, baseline)


def test_validated_authz_state_baseline_requires_numeric_fail_rate():
    observed = dict(rs.AUTHZ_BASELINE_STATE)
    observed["fail_rate"] = "not-a-number"
    with pytest.raises(RuntimeError, match="fail_rate is not numeric"):
        rs._validated_authz_state_baseline("JWT-HTTP-1000MS", "authz reset", observed)


def test_authz_reset_posts_reset_path(monkeypatch):
    fake = _FakeClient(payload=dict(rs.AUTHZ_BASELINE_STATE))

    def _fake_http_client(ca_file, insecure):
        assert ca_file is None
        assert insecure is False
        return fake

    monkeypatch.setattr(rs, "_http_client", _fake_http_client)
    out = rs._authz_reset("http://localhost:8081")
    assert out == rs.AUTHZ_BASELINE_STATE
    assert len(fake.calls) == 1
    assert fake.calls[0]["url"].endswith("/config/reset")


def test_external_policy_activity_requires_observed_authorization_requests():
    rs._validate_external_policy_activity("HTTP-PROFILE-SIMPLE-JWT", {"requests": 1})

    with pytest.raises(RuntimeError, match="handled no authorization requests"):
        rs._validate_external_policy_activity("HTTP-PROFILE-SIMPLE-JWT", {"requests": 0})


def test_external_policy_activity_requires_statistics():
    with pytest.raises(RuntimeError, match="statistics missing"):
        rs._validate_external_policy_activity("HTTP-PROFILE-SIMPLE-JWT", None)


def test_http_latency_and_hybrid_scenarios_explicitly_set_simple_profile():
    scenarios = rs._build_available_scenarios(
        _placeholder_tokens(),
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
    )
    scenario_ids = (
        "HTTP-LATENCY-200MS-JWT",
        "HTTP-LATENCY-1000MS-JWT",
        "HTTP-LATENCY-200MS-BISCUIT",
        "HTTP-FAILURE-INJECTION-200MS-1PCT-JWT",
        "HTTP-FAILURE-INJECTION-200MS-5PCT-JWT",
        "HYBRID-FALLBACK-AUTHZ-DOWN-JWT",
    )

    for scenario_id in scenario_ids:
        authz_config = scenarios[scenario_id]["authz_config"]
        assert authz_config is not None
        assert authz_config["authz_profile"] == "simple"


def test_render_mosquitto_runtime_conf_injects_identity_binding_options() -> None:
    base_conf = """listener 1883
allow_anonymous false

plugin /mosquitto/plugins/libmosquitto_auth_biscuit.so
plugin_opt_jwt_alg ES256
plugin_opt_jwt_key_file /mosquitto/config/jwt_public.pem
plugin_opt_biscuit_root_key_file /mosquitto/config/biscuit_public.key

plugin_opt_policy_mode http
plugin_opt_http_url http://authz:8081/authorize
plugin_opt_cache_ttl_seconds 3600
plugin_opt_ext_auth_method token
"""

    rendered = rs._render_mosquitto_runtime_conf(
        base_conf,
        jwt_identity_binding="strict",
        biscuit_identity_binding="off",
        biscuit_client_id_fact="client_id",
    )

    assert "plugin_opt_jwt_identity_binding strict\n" in rendered
    assert "plugin_opt_biscuit_identity_binding off\n" in rendered
    assert "plugin_opt_biscuit_client_id_fact client_id\n" in rendered
    assert "listener 1883\n" in rendered
    assert "plugin_opt_policy_mode http\n" in rendered
    assert rendered.count("plugin_opt_jwt_identity_binding ") == 1
    assert rendered.count("plugin_opt_biscuit_identity_binding ") == 1
    assert rendered.count("plugin_opt_biscuit_client_id_fact ") == 1


def test_render_mosquitto_runtime_conf_replaces_existing_biscuit_client_id_fact() -> None:
    base_conf = """listener 1883
plugin /mosquitto/plugins/libmosquitto_auth_biscuit.so
plugin_opt_jwt_key_file /mosquitto/config/jwt_public.pem
plugin_opt_biscuit_root_key_file /mosquitto/config/biscuit_public.key
plugin_opt_biscuit_client_id_fact old_fact
"""

    rendered = rs._render_mosquitto_runtime_conf(
        base_conf,
        jwt_identity_binding="off",
        biscuit_identity_binding="strict",
        biscuit_client_id_fact="device_id",
    )

    assert "plugin_opt_biscuit_client_id_fact old_fact\n" not in rendered
    assert "plugin_opt_biscuit_client_id_fact device_id\n" in rendered
    assert rendered.count("plugin_opt_biscuit_client_id_fact ") == 1


def test_effective_mosquitto_runtime_conf_keeps_base_config_path() -> None:
    assert (
        rs._effective_mosquitto_runtime_conf(
            "./mosquitto_base.conf",
            jwt_identity_binding="strict",
            biscuit_identity_binding="off",
            biscuit_client_id_fact="client_id",
        )
        == "./mosquitto_base.conf"
    )


def test_effective_mosquitto_runtime_conf_keeps_tls_base_config_path() -> None:
    assert (
        rs._effective_mosquitto_runtime_conf(
            "./tls/mosquitto_base.conf",
            jwt_identity_binding="strict",
            biscuit_identity_binding="off",
            biscuit_client_id_fact="client_id",
        )
        == "./tls/mosquitto_base.conf"
    )


def test_effective_scenario_message_count_crosses_fanout_churn_threshold() -> None:
    scenario: rs.ScenarioConfig = {
        "fanout_churn_kind": "dynamic_security_swap",
        "fanout_churn_after_messages": 5,
    }

    assert rs._effective_scenario_message_count(scenario, 5, effective_clients=5) == 6


def test_effective_scenario_message_count_covers_every_periodic_churn_event() -> None:
    scenario: rs.ScenarioConfig = {
        "fanout_churn_kind": "sqlite_toggle_read",
        "fanout_churn_after_messages": 4,
        "fanout_churn_interval_messages": 4,
        "fanout_churn_max_events": 4,
    }

    assert rs._effective_scenario_message_count(scenario, 10, effective_clients=50) == 17


def test_effective_scenario_message_count_reserves_runtime_control_denial_publish() -> None:
    scenario: rs.ScenarioConfig = {
        "runtime_control_after_messages": 10,
        "runtime_control_expect_denial": True,
    }

    assert rs._effective_scenario_message_count(scenario, 5, effective_clients=2) == 6
    assert rs._effective_scenario_message_count(scenario, 1, effective_clients=3) == 5


def test_dynamic_security_churn_contract_requires_exact_application_snapshot() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "DYNAMIC-SECURITY-CHURN",
        "runtime_control_after_messages": 10,
        "runtime_control_expect_denial": True,
    }
    result: dict[str, Any] = {
        **_measured_result(3, 10),
        "errors": [],
        "policy_denial_count": 3,
        "publish_outcomes": {
            "attempted": 13,
            "succeeded": 10,
            "failed": 3,
            "attempted_by_qos": {"qos_0": 0, "qos_1": 13, "qos_2": 0},
            "failed_by_qos": {"qos_0": 0, "qos_1": 3, "qos_2": 0},
        },
        "qos_distribution_actual": {
            "qos_0_count": 0,
            "qos_1_count": 10,
            "qos_2_count": 0,
        },
        "topology": {"mode": "container-per-client"},
        "runtime_control": {
            "enabled": True,
            "participants": 3,
            "ready_count": 3,
            "applied_after_successful_publishes": 10,
        },
    }
    result["raw_metrics"].update(
        {
            "runtime_control_applied_after_successful_publishes": 10,
            "runtime_control_connect_ms": 1.0,
            "control": [1.0],
        }
    )
    result["control"] = rs._summary_from_values([1.0])
    rs._validate_result_contract(scenario, result, message_count=10, client_count=3)

    result["runtime_control"]["applied_after_successful_publishes"] = 11
    with pytest.raises(RuntimeError, match="churn phase contract failed"):
        rs._validate_result_contract(scenario, result, message_count=10, client_count=3)

    result["runtime_control"]["applied_after_successful_publishes"] = 10
    result["raw_metrics"]["runtime_control_applied_after_successful_publishes"] = 9
    with pytest.raises(RuntimeError, match="churn phase contract failed"):
        rs._validate_result_contract(scenario, result, message_count=10, client_count=3)

    result["raw_metrics"]["runtime_control_applied_after_successful_publishes"] = 10
    del result["runtime_control"]
    with pytest.raises(RuntimeError, match="churn phase contract failed"):
        rs._validate_result_contract(scenario, result, message_count=10, client_count=3)


@pytest.mark.parametrize("topology_mode", ("host", "container-single"))
def test_dynamic_security_churn_contract_accepts_single_process_output(
    topology_mode: str,
) -> None:
    scenario: rs.ScenarioConfig = {
        "id": "DYNAMIC-SECURITY-CHURN",
        "runtime_control_after_messages": 10,
        "runtime_control_expect_denial": True,
    }
    result: dict[str, Any] = {
        **_measured_result(3, 10),
        "errors": [],
        "publish_outcomes": {
            "attempted": 13,
            "succeeded": 10,
            "failed": 3,
            "attempted_by_qos": {"qos_0": 0, "qos_1": 13, "qos_2": 0},
            "failed_by_qos": {"qos_0": 0, "qos_1": 3, "qos_2": 0},
        },
        "qos_distribution_actual": {
            "qos_0_count": 0,
            "qos_1_count": 10,
            "qos_2_count": 0,
        },
        "topology": {"mode": topology_mode},
    }
    result["raw_metrics"].update(
        {
            "runtime_control_applied_after_successful_publishes": 10,
            "runtime_control_connect_ms": 1.0,
            "policy_denial_count": 3,
            "control": [1.0],
        }
    )
    result["control"] = rs._summary_from_values([1.0])

    rs._validate_result_contract(scenario, result, message_count=10, client_count=3)


def test_result_contract_requires_enabled_churn_to_trigger() -> None:
    with pytest.raises(RuntimeError, match="fanout churn did not trigger"):
        rs._validate_result_contract(
            {
                "id": "DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-10",
                "traffic_pattern": "fanout",
                "delivery_contract": {"phases": ["all", "none"]},
            },
            {
                **_measured_result(11, 6, control_count=1),
                "errors": [],
                "fanout_churn": {
                    "enabled": True,
                    "triggered": False,
                    "applied_events": 0,
                },
            },
            message_count=6,
            client_count=10,
        )


def test_result_contract_requires_zero_delivery_in_deny_phase() -> None:
    with pytest.raises(RuntimeError, match="phase 1 expected no deliveries"):
        rs._validate_result_contract(
            {
                "id": "DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT-10",
                "traffic_pattern": "fanout",
                "delivery_contract": {"phases": ["all", "none"]},
            },
            {
                **_measured_result(11, 6, 60, 1),
                "errors": [],
                "fanout_churn": {
                    "enabled": True,
                    "triggered": True,
                    "applied_events": 1,
                    "control_count": 1,
                    "phases": [
                        {"expected_deliveries": 50, "received_deliveries": 50, "duration_ms": 1},
                        {"expected_deliveries": 10, "received_deliveries": 10, "duration_ms": 1},
                    ],
                },
                "control": {"count": 1},
            },
            message_count=6,
            client_count=10,
        )


def test_result_contract_requires_every_standard_worker_to_finish() -> None:
    with pytest.raises(RuntimeError, match="published 19/20 messages"):
        rs._validate_result_contract(
            {"id": "STANDARD"},
            {**_measured_result(2, 19), "errors": []},
            message_count=10,
            client_count=2,
        )


def test_result_contract_rejects_incomplete_toggle_sequence() -> None:
    with pytest.raises(RuntimeError, match="phase metadata is incomplete"):
        rs._validate_result_contract(
            {
                "id": "SQLITE-RBAC-CHURN-JWT",
                "traffic_pattern": "fanout",
                "delivery_contract": {"phases": ["all", "none", "all", "none", "all"]},
            },
            {
                **_measured_result(11, 5, control_count=1),
                "errors": [],
                "fanout_churn": {
                    "enabled": True,
                    "triggered": True,
                    "applied_events": 1,
                    "phases": [
                        {"expected_deliveries": 40, "received_deliveries": 40},
                        {"expected_deliveries": 10, "received_deliveries": 0},
                    ],
                },
            },
            message_count=5,
            client_count=10,
        )


def test_result_contract_rejects_missing_phase_after_applied_churn() -> None:
    with pytest.raises(RuntimeError, match="phase metadata is incomplete"):
        rs._validate_result_contract(
            {
                "id": "DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-10",
                "traffic_pattern": "fanout",
                "delivery_contract": {"phases": ["all", "none"]},
            },
            {
                **_measured_result(11, 6, control_count=1),
                "errors": [],
                "fanout_churn": {
                    "enabled": True,
                    "triggered": True,
                    "applied_events": 1,
                    "phases": [{"expected_deliveries": 50, "received_deliveries": 50}],
                },
            },
            message_count=6,
            client_count=10,
        )


def test_result_contract_allows_only_expected_disable_disconnects() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT-10",
        "traffic_pattern": "fanout",
        "allowed_error_prefixes": list(rs.EXPECTED_DISABLE_RECEIVE_ERROR_PREFIXES),
        "delivery_contract": {"phases": ["all", "none"]},
    }
    result: dict[str, Any] = {
        **_measured_result(11, 6, 50, 1),
        "errors": ["receive_failed:Mqtt state: Connection closed by peer abruptly"],
        "fanout_churn": {
            "enabled": True,
            "triggered": True,
            "applied_events": 1,
            "control_count": 1,
            "phases": [
                {"expected_deliveries": 50, "received_deliveries": 50, "duration_ms": 1},
                {"expected_deliveries": 10, "received_deliveries": 0, "duration_ms": 1},
            ],
        },
    }
    rs._validate_result_contract(scenario, result, message_count=6, client_count=10)

    result["errors"] = [
        "receive_failed:Mqtt state: Mqtt serialization/deserialization error: "
        "IO: Connection reset by peer (os error 104)"
    ]
    rs._validate_result_contract(scenario, result, message_count=6, client_count=10)

    result["errors"].append("fanout_publish_failed:NotAuthorized")
    with pytest.raises(RuntimeError, match="fanout_publish_failed:NotAuthorized"):
        rs._validate_result_contract(scenario, result, message_count=6, client_count=10)


def test_mqtt5_result_contract_validates_auth_without_publish_metrics() -> None:
    rs._validate_result_contract(
        {"id": "TOKEN-MQTT5-REAUTH-JWT", "mqtt5_auth": {"kind": "jwt"}},
        {
            "connect_ok": True,
            "connect_ms": 1.0,
            "reauth_ok": True,
            "reauth_ms": 2.0,
            "token1_sha256": "1" * 64,
            "token2_sha256": "2" * 64,
            "pre_reauth_publish_ok": True,
            "post_reauth_publish_ok": True,
            "post_reauth_old_topic_denied": True,
            "credential_attestation": {
                "source": "issuer",
                "token_kind": "jwt",
                "client_id": "client_auth",
                "token1_ttl_seconds": 180,
                "token2_ttl_seconds": 300,
                "token1_topic": "before",
                "token2_topic": "after",
            },
        },
        message_count=10,
        client_count=10,
    )


def test_mqtt5_result_contract_accepts_static_tokens_without_issuer_metadata() -> None:
    rs._validate_result_contract(
        {"id": "CUSTOM-MQTT5-AUTH", "mqtt5_auth": {"token1": "one", "token2": "two"}},
        {
            "connect_ok": True,
            "connect_ms": 1.0,
            "reauth_ok": True,
            "reauth_ms": 2.0,
            "token1_sha256": "1" * 64,
            "token2_sha256": "2" * 64,
            "pre_reauth_publish_ok": True,
            "post_reauth_publish_ok": True,
            "post_reauth_old_topic_denied": True,
            "credential_attestation": {
                "source": "static",
                "token_kind": None,
                "client_id": "client_auth",
                "token1_ttl_seconds": 0,
                "token2_ttl_seconds": 0,
                "token1_topic": "before",
                "token2_topic": "after",
            },
        },
        message_count=10,
        client_count=10,
    )


def test_mqtt5_result_contract_rejects_failed_reauthentication() -> None:
    with pytest.raises(RuntimeError, match="reauthentication failed: NotAuthorized"):
        rs._validate_result_contract(
            {"id": "TOKEN-MQTT5-REAUTH-JWT", "mqtt5_auth": {"kind": "jwt"}},
            {
                "connect_ok": True,
                "connect_ms": 1.0,
                "reauth_ok": False,
                "reauth_ms": 2.0,
                "reauth_error": "NotAuthorized",
            },
            message_count=10,
            client_count=10,
        )


@pytest.mark.parametrize(
    ("scenario_id", "delay_ms"),
    (("HTTP-LATENCY-200MS-JWT", 200), ("HTTP-LATENCY-1000MS-JWT", 1000)),
)
def test_http_latency_contract_requires_exact_backend_work(scenario_id: str, delay_ms: int) -> None:
    scenario: rs.ScenarioConfig = {
        "id": scenario_id,
        "http_expected_delay_ms": delay_ms,
    }
    result: dict[str, Any] = {
        **_measured_result(2, 6),
        "errors": [],
        "authz_stats": {
            "requests": 6,
            "policy_allows": 6,
            "policy_denies": 0,
            "injected_failures": 0,
            "profile_requests": {"simple": 6},
            "configured_delay_ms": delay_ms,
            "configured_profile": "simple",
            "configured_fail_mode": "none",
        },
    }
    rs._validate_result_contract(scenario, result, message_count=3, client_count=2)
    result["authz_stats"]["requests"] = 1
    with pytest.raises(RuntimeError, match="HTTP latency contract failed"):
        rs._validate_result_contract(scenario, result, message_count=3, client_count=2)


def test_hybrid_fallback_contract_requires_every_external_failure() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "HYBRID-FALLBACK-AUTHZ-DOWN-JWT",
        "hybrid_fallback_required": True,
    }
    result: dict[str, Any] = {
        **_measured_result(2, 4),
        "errors": [],
        "authz_stats": {
            "requests": 4,
            "injected_failures": 4,
            "policy_allows": 0,
            "policy_denies": 0,
            "configured_fail_mode": "always",
        },
    }
    rs._validate_result_contract(scenario, result, message_count=2, client_count=2)
    assert result["fallback_attestation"]["successful_fallbacks"] == 4
    result["authz_stats"]["injected_failures"] = 0
    with pytest.raises(RuntimeError, match="hybrid fallback contract failed"):
        rs._validate_result_contract(scenario, result, message_count=2, client_count=2)


def test_http_failure_contract_requires_complete_attempted_workload() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "HTTP-FAILURE-INJECTION-200MS-5PCT-JWT",
        "http_failure_rate": 0.05,
        "allowed_error_prefixes": ["publish_failed:"],
    }
    result: dict[str, Any] = {
        **_measured_result(2, 95),
        "errors": ["publish_failed:NotAuthorized"] * 5,
        "qos_distribution_actual": {
            "qos_0_count": 0,
            "qos_1_count": 95,
            "qos_2_count": 0,
        },
        "publish_outcomes": {
            "attempted": 100,
            "succeeded": 95,
            "failed": 5,
            "attempted_by_qos": {"qos_0": 0, "qos_1": 100, "qos_2": 0},
            "failed_by_qos": {"qos_0": 0, "qos_1": 5, "qos_2": 0},
        },
        "authz_stats": {
            "requests": 100,
            "injected_failures": 5,
            "policy_allows": 95,
            "policy_denies": 0,
            "configured_fail_mode": "rate",
            "configured_fail_rate": 0.05,
        },
    }
    rs._validate_result_contract(
        scenario, result, message_count=50, client_count=2, effective_qos=1
    )

    result["authz_stats"]["requests"] = 80
    with pytest.raises(RuntimeError, match="HTTP failure workload contract failed"):
        rs._validate_result_contract(
            scenario, result, message_count=50, client_count=2, effective_qos=1
        )


def test_result_contract_rejects_incomplete_publish_outcome_qos_accounting() -> None:
    scenario: rs.ScenarioConfig = {"id": "TOKEN-BASELINE-JWT"}
    result: dict[str, Any] = {
        **_measured_result(1, 2),
        "errors": [],
        "qos_distribution_actual": {
            "qos_0_count": 0,
            "qos_1_count": 2,
            "qos_2_count": 0,
        },
        "publish_outcomes": {
            "attempted": 3,
            "succeeded": 2,
            "failed": 1,
            "attempted_by_qos": {"qos_0": 0, "qos_1": 2, "qos_2": 0},
            "failed_by_qos": {"qos_0": 0, "qos_1": 1, "qos_2": 0},
        },
    }

    with pytest.raises(RuntimeError, match="inconsistent publish outcome QoS accounting"):
        rs._validate_result_contract(scenario, result, message_count=2, client_count=1)


def test_broker_path_contract_rejects_wrong_authorization_mode() -> None:
    scenario: rs.ScenarioConfig = {"id": "TOKEN-BASELINE-JWT"}
    result: dict[str, Any] = {
        "broker_auth_delta": {
            "attempts": 2,
            "successes": 2,
            "failures": 0,
            "jwt_validations": 1,
        },
        "broker_authz_delta": {"policy_mode": "TokenOnly", "checks": 1},
    }
    attestation = {
        "validated": True,
        "plugin_enabled": True,
        "policy_mode": "token",
        "benchmark_diagnostics": True,
        "benchmark_diagnostics_transport": "loopback_tcp_snapshot",
        "benchmark_diagnostics_port": rs.BENCHMARK_DIAGNOSTICS_PORT,
    }

    rs._validate_broker_path_contract(scenario, result, attestation, client_count=2)

    result["broker_authz_delta"]["policy_mode"] = "StaticAcl"
    with pytest.raises(RuntimeError, match="authorization path contract failed"):
        rs._validate_broker_path_contract(scenario, result, attestation, client_count=2)


def test_result_contract_rejects_wrong_connect_count_and_non_finite_latency() -> None:
    result = _measured_result(1, 2)
    result["errors"] = []
    with pytest.raises(RuntimeError, match="connect metric count"):
        rs._validate_result_contract(
            {"id": "TOKEN-BASELINE-JWT"}, result, message_count=1, client_count=2
        )

    result = _measured_result(2, 2)
    result["errors"] = []
    result["raw_metrics"]["connect"][0] = float("nan")
    with pytest.raises(RuntimeError, match="raw connect metric samples are invalid"):
        rs._validate_result_contract(
            {"id": "TOKEN-BASELINE-JWT"}, result, message_count=1, client_count=2
        )


def test_broker_path_contract_rejects_silent_missing_client_authentication() -> None:
    scenario: rs.ScenarioConfig = {"id": "TOKEN-BASELINE-JWT"}
    result: dict[str, Any] = {
        "broker_auth_delta": {
            "attempts": 1,
            "successes": 1,
            "failures": 0,
            "jwt_validations": 1,
        },
        "broker_authz_delta": {"policy_mode": "TokenOnly", "checks": 1},
    }
    attestation = {
        "validated": True,
        "plugin_enabled": True,
        "policy_mode": "token",
        "benchmark_diagnostics": True,
        "benchmark_diagnostics_transport": "loopback_tcp_snapshot",
        "benchmark_diagnostics_port": rs.BENCHMARK_DIAGNOSTICS_PORT,
    }
    with pytest.raises(RuntimeError, match="authentication path contract failed"):
        rs._validate_broker_path_contract(scenario, result, attestation, client_count=2)


def test_broker_path_contract_counts_delegation_handoff_sessions() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "TOKEN-DELEGATION-HANDOFF-BISCUIT",
        "biscuit_delegate": {
            "ttl_seconds": 300,
            "topic": "sensors/{client_id}/temp",
            "op": "publish",
            "handoff": {
                "topic": "delegation/handoff",
                "token": "biscuit_delegation_handoff-fixture",
                "qos": 1,
                "retain": True,
            },
        },
    }
    result: dict[str, Any] = {
        "broker_auth_delta": {
            "attempts": 5,
            "successes": 5,
            "failures": 0,
            "biscuit_validations": 5,
        },
        "broker_authz_delta": {"policy_mode": "TokenOnly", "checks": 1},
    }
    attestation = {
        "validated": True,
        "plugin_enabled": True,
        "policy_mode": "token",
        "benchmark_diagnostics": True,
        "benchmark_diagnostics_transport": "loopback_tcp_snapshot",
        "benchmark_diagnostics_port": rs.BENCHMARK_DIAGNOSTICS_PORT,
    }

    rs._validate_broker_path_contract(scenario, result, attestation, client_count=2)

    result["broker_auth_delta"]["attempts"] = 2
    result["broker_auth_delta"]["successes"] = 2
    with pytest.raises(RuntimeError, match="authentication path contract failed"):
        rs._validate_broker_path_contract(scenario, result, attestation, client_count=2)


def test_broker_path_contract_validates_anonymous_dynamic_security_defer() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "DYNAMIC-SECURITY-ANONYMOUS-BASELINE",
        "username": "",
        "password": "",
        "traffic_pattern": "fanout",
    }
    result: dict[str, Any] = {
        "broker_auth_delta": {
            "attempts": 3,
            "successes": 0,
            "failures": 0,
            "anonymous_deferrals": 3,
            "jwt_validations": 0,
            "biscuit_validations": 0,
        },
        "broker_authz_delta": {
            "policy_mode": "DynamicSecurity",
            "checks": 0,
            "allows": 0,
            "denies": 0,
            "expired": 0,
            "anonymous_checks": 22,
            "anonymous_allows": 22,
            "anonymous_denies": 0,
        },
    }
    attestation = {
        "validated": True,
        "plugin_enabled": True,
        "policy_mode": "dynamic_security",
        "allow_anonymous_no_token": True,
        "benchmark_diagnostics": True,
        "benchmark_diagnostics_transport": "loopback_tcp_snapshot",
        "benchmark_diagnostics_port": rs.BENCHMARK_DIAGNOSTICS_PORT,
    }

    rs._validate_broker_path_contract(scenario, result, attestation, client_count=2)

    result["broker_authz_delta"]["anonymous_checks"] = 0
    with pytest.raises(RuntimeError, match="anonymous Dynamic Security path contract failed"):
        rs._validate_broker_path_contract(scenario, result, attestation, client_count=2)


def _dynamic_security_url(conf_text: str) -> str | None:
    for line in conf_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("plugin_opt_dynamic_security_url"):
            return stripped.split(None, 1)[1]
    return None


def test_tls_mosquitto_confs_share_base_dynamic_security_url() -> None:
    tls_dir = rs._resolve_compose_path("./tls")
    compared = 0
    for tls_conf in sorted(tls_dir.glob("mosquitto_*.conf")):
        base_conf = rs._resolve_compose_path(tls_conf.name)
        if not base_conf.exists():
            continue
        tls_url = _dynamic_security_url(tls_conf.read_text(encoding="utf-8"))
        base_url = _dynamic_security_url(base_conf.read_text(encoding="utf-8"))
        assert tls_url == base_url, (
            f"{tls_conf.name} dynamic_security_url {tls_url!r} diverges from base {base_url!r}"
        )
        compared += 1
    assert compared > 0


def test_effective_mosquitto_runtime_conf_materializes_plugin_backed_config() -> None:
    generated_conf = rs._resolve_compose_path(
        ".generated/mosquitto.jwt-strict.biscuit-off.fact-client_id.conf"
    )
    if generated_conf.exists():
        generated_conf.unlink()

    try:
        rendered = rs._effective_mosquitto_runtime_conf(
            "./mosquitto.conf",
            jwt_identity_binding="strict",
            biscuit_identity_binding="off",
            biscuit_client_id_fact="client_id",
        )
        assert rendered == "./.generated/mosquitto.jwt-strict.biscuit-off.fact-client_id.conf"
        assert generated_conf.exists()
    finally:
        if generated_conf.exists():
            generated_conf.unlink()


def test_effective_mosquitto_runtime_conf_materializes_custom_biscuit_client_id_fact() -> None:
    generated_conf = rs._resolve_compose_path(
        ".generated/mosquitto.jwt-off.biscuit-strict.fact-device_id.conf"
    )
    if generated_conf.exists():
        generated_conf.unlink()

    try:
        rendered = rs._effective_mosquitto_runtime_conf(
            "./mosquitto.conf",
            jwt_identity_binding="off",
            biscuit_identity_binding="strict",
            biscuit_client_id_fact="device_id",
        )
        assert rendered == "./.generated/mosquitto.jwt-off.biscuit-strict.fact-device_id.conf"
        assert generated_conf.exists()
        assert "plugin_opt_biscuit_client_id_fact device_id\n" in generated_conf.read_text(
            encoding="utf-8"
        )
    finally:
        if generated_conf.exists():
            generated_conf.unlink()


def test_default_dynsec_snapshot_preserves_publish_and_fanout_baselines():
    # NOTE: Calls rs._resolve_repo_path, an internal helper. If that helper is
    # renamed, this test will fail at call time rather than via a typed interface.
    cfg = json.loads(
        rs._resolve_repo_path("docker/dynamic-security.json").read_text(encoding="utf-8")
    )
    clients = {client["username"]: client for client in cfg["clients"]}
    groups = {group["groupname"]: group for group in cfg["groups"]}
    roles = {role["rolename"]: role for role in cfg["roles"]}

    subscriber_roles = {
        role_ref["rolename"] for role_ref in clients["dynsec_client_1"].get("roles", [])
    }
    assert "sensor_writer" in subscriber_roles

    sensor_group_members = {
        client_ref["username"] for client_ref in groups["sensors"].get("clients", [])
    }
    assert "dynsec_client_1" in sensor_group_members

    fanout_writer_topics = {
        acl["topic"]
        for acl in roles["fanout_writer"].get("acls", [])
        if acl.get("acltype") == "publishClientSend" and acl.get("allow") is True
    }
    assert "fanout/broadcast" in fanout_writer_topics
    assert "$CONTROL/dynamic-security/v1" not in fanout_writer_topics


def test_publish_timeout_keeps_configured_delay_as_measured_variable() -> None:
    base: rs.ScenarioConfig = {"id": "BASELINE-NO-AUTH"}
    assert rs._publish_timeout_seconds(base, 10) == rs.BASE_PUBLISH_TIMEOUT_S
    assert rs._publish_timeout_seconds(base, 200) == rs.BASE_PUBLISH_TIMEOUT_S

    latency_200: rs.ScenarioConfig = {
        "id": "HTTP-LATENCY-200MS-JWT",
        "http_expected_delay_ms": 200,
    }
    latency_1000: rs.ScenarioConfig = {
        "id": "HTTP-LATENCY-1000MS-JWT",
        "http_expected_delay_ms": 1000,
    }
    # General scenario/runner rule: budget scales with configured delay and
    # effective clients to cover queueing behind serial broker authorizations.
    assert rs._publish_timeout_seconds(latency_200, 10) == 17
    assert rs._publish_timeout_seconds(latency_1000, 10) == 25
    assert rs._publish_timeout_seconds(latency_1000, 1) == 16
    # Synthetic delay proves this is not an ID-specific exception.
    synthetic: rs.ScenarioConfig = {"id": "SYNTHETIC", "http_expected_delay_ms": 500}
    assert rs._publish_timeout_seconds(synthetic, 4) == 17
    # Failure-injection cells declare no http_expected_delay_ms (it would trip
    # the no-failure latency contract); the budget comes from the explicit
    # http_timeout_budget_delay_ms metadata instead: 25 clients * 200 ms +
    # 15 s headroom = 20 s.
    failure_injection: rs.ScenarioConfig = {
        "id": "HTTP-FAILURE-INJECTION-200MS-1PCT-JWT",
        "http_timeout_budget_delay_ms": 200,
        "authz_config": {
            "delay_ms": 200,
            "fail_mode": "rate",
            "fail_rate": 0.01,
            "authz_profile": "simple",
        },
    }
    assert rs._publish_timeout_seconds(failure_injection, 25) == 20
    # Arbitrary authz_config.delay_ms alone must NOT inflate the budget: the
    # helper only honors explicit timeout metadata, so delayed scenarios
    # without such metadata (e.g. HTTP-LATENCY-200MS-BISCUIT, which declares
    # no http_expected_delay_ms) keep the frozen 10 s base.
    authz_delay_only: rs.ScenarioConfig = {
        "id": "HTTP-LATENCY-200MS-BISCUIT",
        "authz_config": {
            "delay_ms": 200,
            "fail_mode": "none",
            "authz_profile": "simple",
        },
    }
    assert rs._publish_timeout_seconds(authz_delay_only, 25) == rs.BASE_PUBLISH_TIMEOUT_S
    assert rs._publish_timeout_seconds(authz_delay_only, 1) == rs.BASE_PUBLISH_TIMEOUT_S
    # Explicit http_expected_delay_ms still takes precedence over the
    # timeout-budget metadata.
    both: rs.ScenarioConfig = {
        "id": "SYNTHETIC-BOTH",
        "http_expected_delay_ms": 200,
        "http_timeout_budget_delay_ms": 1000,
    }
    assert rs._publish_timeout_seconds(both, 10) == 17
    # The 1000 ms c10/m10 HOLD case: budget must exceed worst-case queued
    # latency (clients * delay) plus headroom, not just a single delay.
    budget = rs._publish_timeout_seconds(latency_1000, 10)
    assert budget > 10
    assert budget * 1000 > 10 * 1000 + rs.PUBLISH_TIMEOUT_HEADROOM_S * 1000 // 2


# Frozen effective-behavior reference for the Part 1 HTTP failure-injection HOLD.
_FROZEN_HOLD_HEAD = "234c2c4518bd45e16ef54f1999819a0350fbc505"

_FAILURE_INJECTION_HOLD_IDS = frozenset(
    {
        "HTTP-FAILURE-INJECTION-200MS-1PCT-JWT",
        "HTTP-FAILURE-INJECTION-200MS-1PCT-JWT-TLS",
        "HTTP-FAILURE-INJECTION-200MS-5PCT-JWT",
        "HTTP-FAILURE-INJECTION-200MS-5PCT-JWT-TLS",
    }
)

_FROZEN_HOLD_PROBE_CLIENTS = (1, 10, 25, 50)


def _frozen_hold_timeout_seconds(scenario: rs.ScenarioConfig, clients: int) -> int:
    """Replica of ``_publish_timeout_seconds`` at frozen HEAD 234c2c4.

    The frozen helper honored only ``http_expected_delay_ms`` and returned
    the historical 10 s base otherwise; it never inspected ``authz_config``
    delays or timeout-budget metadata (which did not exist yet).
    """
    delay_ms = scenario.get("http_expected_delay_ms") or 0
    if delay_ms <= 0:
        return rs.BASE_PUBLISH_TIMEOUT_S
    queued_s = (delay_ms / 1000.0) * max(clients, 1)
    return max(rs.BASE_PUBLISH_TIMEOUT_S, math.ceil(queued_s + rs.PUBLISH_TIMEOUT_HEADROOM_S))


def test_failure_injection_hold_blast_radius_matches_frozen_head() -> None:
    """Only the 4 failure-injection HOLD cells may change timeout/sync behavior.

    Enumerates the full expanded registry and compares effective
    connect/publish timeout budgets (across representative client counts) and
    ``sync_connect`` semantics against the frozen HEAD 234c2c4 reference. Any
    other effective difference fails the test.
    """
    base = rs._build_available_scenarios(
        _placeholder_tokens(),
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
    )
    expanded = rs._expand_tls_matrix(base)
    assert len(expanded) == 444

    differing: list[str] = []
    for scenario_id in sorted(expanded):
        scenario = expanded[scenario_id]
        frozen_view = cast(rs.ScenarioConfig, dict(scenario))
        frozen_view.pop("http_timeout_budget_delay_ms", None)
        if scenario_id in _FAILURE_INJECTION_HOLD_IDS:
            # The frozen base failure cells declared no connect barrier.
            frozen_view.pop("sync_connect", None)
        timeout_differs = any(
            rs._publish_timeout_seconds(scenario, clients)
            != _frozen_hold_timeout_seconds(frozen_view, clients)
            for clients in _FROZEN_HOLD_PROBE_CLIENTS
        )
        sync_differs = bool(scenario.get("sync_connect")) != bool(frozen_view.get("sync_connect"))
        if timeout_differs or sync_differs:
            differing.append(scenario_id)

    assert set(differing) == _FAILURE_INJECTION_HOLD_IDS

    # Pin the exact HOLD effect: sync barrier on, no latency-contract key,
    # explicit 200 ms budget metadata, 20 s outer budget at c25.
    for scenario_id in sorted(_FAILURE_INJECTION_HOLD_IDS):
        scenario = expanded[scenario_id]
        assert scenario["sync_connect"] is True
        assert scenario.get("http_expected_delay_ms") is None
        assert scenario.get("http_timeout_budget_delay_ms") == 200
        assert rs._publish_timeout_seconds(scenario, 25) == 20

    # Pin the frozen cells that must not move: the BISCUIT latency cells
    # already have canonical fixed-client results, so any timeout drift here
    # would contaminate provenance.
    for scenario_id in (
        "HTTP-LATENCY-200MS-BISCUIT",
        "HTTP-LATENCY-200MS-BISCUIT-TLS",
        "HTTP-LATENCY-200MS-PARITY-BISCUIT",
        "HTTP-LATENCY-200MS-PARITY-BISCUIT-TLS",
    ):
        scenario = expanded[scenario_id]
        assert scenario.get("http_timeout_budget_delay_ms") is None
        for clients in _FROZEN_HOLD_PROBE_CLIENTS:
            assert rs._publish_timeout_seconds(scenario, clients) == (rs.BASE_PUBLISH_TIMEOUT_S)
