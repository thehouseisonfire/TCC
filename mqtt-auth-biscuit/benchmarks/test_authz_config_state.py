import json
import re
from pathlib import Path
from typing import Any

import pytest

from benchmarks import run_scenarios as rs


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


def test_effective_scenario_message_count_reserves_runtime_control_denial_publish() -> None:
    scenario: rs.ScenarioConfig = {
        "runtime_control_after_messages": 10,
        "runtime_control_expect_denial": True,
    }

    assert rs._effective_scenario_message_count(scenario, 5, effective_clients=2) == 6


def test_result_contract_requires_enabled_churn_to_trigger() -> None:
    with pytest.raises(RuntimeError, match="fanout churn did not trigger"):
        rs._validate_result_contract(
            {
                "id": "DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-10",
                "traffic_pattern": "fanout",
                "delivery_contract": {"phases": ["all", "none"]},
            },
            {
                "errors": [],
                "publish": {"count": 6},
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
                "errors": [],
                "publish": {"count": 6},
                "fanout_churn": {
                    "enabled": True,
                    "triggered": True,
                    "applied_events": 1,
                    "phases": [
                        {"expected_deliveries": 50, "received_deliveries": 50},
                        {"expected_deliveries": 10, "received_deliveries": 10},
                    ],
                },
            },
            message_count=6,
            client_count=10,
        )


def test_result_contract_requires_every_standard_worker_to_finish() -> None:
    with pytest.raises(RuntimeError, match="published 19/20 messages"):
        rs._validate_result_contract(
            {"id": "STANDARD"},
            {"errors": [], "publish": {"count": 19}},
            message_count=10,
            client_count=2,
        )


def test_result_contract_validates_only_toggle_phases_exercised_by_short_run() -> None:
    rs._validate_result_contract(
        {
            "id": "SQLITE-RBAC-CHURN-JWT",
            "traffic_pattern": "fanout",
            "delivery_contract": {"phases": ["all", "none", "all", "none", "all"]},
        },
        {
            "errors": [],
            "publish": {"count": 5},
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
                "errors": [],
                "publish": {"count": 6},
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
        "errors": ["receive_failed:Mqtt state: Connection closed by peer abruptly"],
        "publish": {"count": 6},
        "fanout_churn": {
            "enabled": True,
            "triggered": True,
            "applied_events": 1,
            "phases": [
                {"expected_deliveries": 50, "received_deliveries": 50},
                {"expected_deliveries": 10, "received_deliveries": 0},
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
        {"connect_ok": True, "connect_ms": 1.0, "reauth_ok": True, "reauth_ms": 2.0},
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
