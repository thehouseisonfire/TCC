import json
import re
from pathlib import Path

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
        "HTTP-LATENCY-200MS-FAILURE-1PCT-JWT",
        "HTTP-LATENCY-200MS-FAILURE-5PCT-JWT",
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
    )

    assert "plugin_opt_jwt_identity_binding strict\n" in rendered
    assert "plugin_opt_biscuit_identity_binding off\n" in rendered
    assert "listener 1883\n" in rendered
    assert "plugin_opt_policy_mode http\n" in rendered
    assert rendered.count("plugin_opt_jwt_identity_binding ") == 1
    assert rendered.count("plugin_opt_biscuit_identity_binding ") == 1


def test_effective_mosquitto_runtime_conf_keeps_base_config_path() -> None:
    assert (
        rs._effective_mosquitto_runtime_conf(
            "./mosquitto_base.conf",
            jwt_identity_binding="strict",
            biscuit_identity_binding="off",
        )
        == "./mosquitto_base.conf"
    )


def test_effective_mosquitto_runtime_conf_keeps_tls_base_config_path() -> None:
    assert (
        rs._effective_mosquitto_runtime_conf(
            "./tls/mosquitto_base.conf",
            jwt_identity_binding="strict",
            biscuit_identity_binding="off",
        )
        == "./tls/mosquitto_base.conf"
    )


def test_effective_mosquitto_runtime_conf_materializes_plugin_backed_config() -> None:
    generated_conf = rs._resolve_compose_path(
        ".generated/mosquitto.jwt-strict.biscuit-off.conf"
    )
    if generated_conf.exists():
        generated_conf.unlink()

    try:
        rendered = rs._effective_mosquitto_runtime_conf(
            "./mosquitto.conf",
            jwt_identity_binding="strict",
            biscuit_identity_binding="off",
        )
        assert rendered == "./.generated/mosquitto.jwt-strict.biscuit-off.conf"
        assert generated_conf.exists()
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
