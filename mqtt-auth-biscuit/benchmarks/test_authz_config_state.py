import json

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


def test_expected_authz_state_for_http_policy_complex():
    cfg = rs._http_policy_authz_config("complex")
    expected = rs._expected_authz_state(cfg, dict(rs.AUTHZ_BASELINE_STATE))
    assert expected["policy_profile"] == "complex"
    assert expected["rules_count"] == 10
    assert expected["client_roles_count"] == 3
    assert expected["allow_mode"] == "topic_prefix"
    assert expected["topic_prefix"] == "sensors/"


def test_expected_authz_state_for_http_policy_med():
    cfg = rs._http_policy_authz_config("med")
    expected = rs._expected_authz_state(cfg, dict(rs.AUTHZ_BASELINE_STATE))
    assert expected["policy_profile"] == "med"
    assert expected["rules_count"] == 6
    assert expected["client_roles_count"] == 3
    assert expected["allow_mode"] == "topic_prefix"
    assert expected["topic_prefix"] == "sensors/"


def test_expected_authz_state_for_none_uses_baseline():
    expected = rs._expected_authz_state(None, dict(rs.AUTHZ_BASELINE_STATE))
    assert expected == rs.AUTHZ_BASELINE_STATE


def test_profile_rule_counts_match_authz_profiles():
    assert rs.AUTHZ_PROFILE_RULE_COUNT["med"] == 6
    assert rs.AUTHZ_PROFILE_RULE_COUNT["complex"] == 10


def test_expected_authz_state_counts_profile_rules_plus_custom_rules():
    cfg: rs.AuthzConfig = {
        "policy_profile": "med",
        "rules": [{"effect": "allow", "ops": ["read"], "topics": ["#"]}],
        "client_roles": {"client_x": ["reader"]},
    }
    expected = rs._expected_authz_state(cfg, dict(rs.AUTHZ_BASELINE_STATE))
    assert expected["rules_count"] == rs.AUTHZ_PROFILE_RULE_COUNT["med"] + 1
    assert expected["client_roles_count"] == 1


def test_expected_authz_state_uses_runtime_baseline_for_non_default_startup():
    runtime_baseline = {
        "delay_ms": 0,
        "fail_mode": "none",
        "fail_rate": 0.0,
        "allow_mode": "deny_all",
        "topic_prefix": "private/",
        "policy_profile": "simple",
        "rules_count": 0,
        "client_roles_count": 0,
    }
    expected = rs._expected_authz_state(None, runtime_baseline)
    assert expected == runtime_baseline


def test_assert_authz_state_raises_on_mismatch():
    with pytest.raises(RuntimeError, match="Authz state mismatch"):
        rs._assert_authz_state(
            "JWT-HTTP-1000MS",
            "authz config apply",
            {**rs.AUTHZ_BASELINE_STATE, "policy_profile": "complex"},
            rs._expected_authz_state(None, dict(rs.AUTHZ_BASELINE_STATE)),
        )


def test_validated_authz_state_baseline_accepts_non_default_values():
    observed = {
        "delay_ms": 0,
        "fail_mode": "none",
        "fail_rate": 0,
        "allow_mode": "deny_all",
        "topic_prefix": "private/",
        "policy_profile": "simple",
        "rules_count": 0,
        "client_roles_count": 0,
    }
    baseline = rs._validated_authz_state_baseline("JWT-HTTP-1000MS", "authz reset", observed)
    assert baseline["allow_mode"] == "deny_all"
    assert baseline["topic_prefix"] == "private/"
    assert baseline["policy_profile"] == "simple"
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
