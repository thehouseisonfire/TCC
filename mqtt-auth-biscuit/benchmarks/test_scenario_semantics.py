from __future__ import annotations

import re
from pathlib import Path

import pytest

from benchmarks import run_scenarios as rs


class _SelectedScenario(RuntimeError):
    pass


MULTI_CLIENT_FANOUT_PARITY_SCENARIOS = (
    "HTTP-ACL-READ-FANOUT-STRICT-MED-ALLOW-PARITY-JWT-50",
    "HTTP-ACL-READ-FANOUT-STRICT-COMPLEX-DENY-PARITY-BISCUIT-10",
    "HYBRID-ACL-READ-FANOUT-STRICT-MED-ALLOW-PARITY-BISCUIT-100",
    "HYBRID-ACL-READ-FANOUT-STRICT-SIMPLE-DENY-PARITY-JWT-10",
)


def _placeholder_tokens() -> dict[str, str]:
    source = Path(rs.__file__).read_text(encoding="utf-8")
    keys = set(re.findall(r'tokens\["([^"]+)"\]', source))
    keys.update(re.findall(r'tokens\.get\("([^"]+)"', source))
    return {key: f"{key}-fixture" for key in keys}


def _scenario_registry() -> dict[str, rs.ScenarioConfig]:
    return rs._build_available_scenarios(
        _placeholder_tokens(),
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
    )


def test_scenario_semantics_metadata_is_present_for_capability_and_mixed_families() -> None:
    scenarios = _scenario_registry()

    capability_metadata = rs._scenario_semantics_metadata(
        "TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-JWT-50",
        scenarios["TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-JWT-50"],
        default_clients=50,
    )
    assert capability_metadata == {
        "jwt_identity_binding": "off",
        "biscuit_identity_binding": "off",
        "semantic_class": "capability",
    }

    mixed_metadata = rs._scenario_semantics_metadata(
        "CONTROL-CHURN-CREATE-ROLE-JWT",
        scenarios["CONTROL-CHURN-CREATE-ROLE-JWT"],
        default_clients=50,
    )
    assert mixed_metadata == {
        "jwt_identity_binding": "strict",
        "biscuit_identity_binding": "off",
        "semantic_class": "mixed",
    }


@pytest.mark.parametrize(
    ("scenario_id", "expected_password"),
    (
        ("HTTP-LATENCY-200MS-PARITY-JWT", "jwt_strict_sub_client_id-fixture"),
        ("HTTP-LATENCY-200MS-PARITY-BISCUIT", "biscuit_strict_client_id-fixture"),
        ("HTTP-PROFILE-SIMPLE-PARITY-JWT", "jwt_strict_sub_client_id-fixture"),
        ("HTTP-PROFILE-SIMPLE-PARITY-BISCUIT", "biscuit_strict_client_id-fixture"),
        ("HTTP-PROFILE-MED-PARITY-JWT", "jwt_strict_sub_client_id-fixture"),
        ("HTTP-PROFILE-MED-PARITY-BISCUIT", "biscuit_strict_client_id-fixture"),
        ("HTTP-PROFILE-COMPLEX-PARITY-JWT", "jwt_strict_sub_client_id-fixture"),
        ("HTTP-PROFILE-COMPLEX-PARITY-BISCUIT", "biscuit_strict_client_id-fixture"),
    ),
)
def test_http_parity_variants_enable_strict_identity_binding_for_both_token_types(
    scenario_id: str,
    expected_password: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["client_count"] == 1
    assert scenario["password"] == expected_password
    assert rs._scenario_semantics_metadata(
        scenario_id,
        scenario,
        default_clients=50,
    ) == {
        "jwt_identity_binding": "strict",
        "biscuit_identity_binding": "strict",
        "semantic_class": "parity_identity_bound",
    }

    if scenario_id.endswith("-JWT"):
        authz_config = scenario["authz_config"]
        assert authz_config is not None
        assert authz_config["jwt_identity_binding"] == "strict"


@pytest.mark.parametrize(
    "scenario_id",
    (
        "TOKEN-DELEGATION-TEMP-ONLY-BISCUIT",
        "TOKEN-ATTENUATION-COMBINED-BISCUIT",
        "TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-MED-BISCUIT",
        "TOKEN-COMPOSABILITY-DELEGATED-DATALOG-HIGH-BISCUIT",
        "TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-BISCUIT-100",
    ),
)
def test_capability_scenarios_keep_identity_binding_disabled(scenario_id: str) -> None:
    scenarios = _scenario_registry()
    assert rs._scenario_semantics_metadata(
        scenario_id,
        scenarios[scenario_id],
        default_clients=50,
    ) == {
        "jwt_identity_binding": "off",
        "biscuit_identity_binding": "off",
        "semantic_class": "capability",
    }


@pytest.mark.parametrize(
    ("scenario_id", "kind"),
    (
        ("TOKEN-THUNDERING-HERD-JWT", "jwt"),
        ("TOKEN-THUNDERING-HERD-BISCUIT", "biscuit"),
    ),
)
def test_thundering_herd_scenarios_are_synchronized_connect_bursts(
    scenario_id: str,
    kind: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["sync_connect"] is True
    assert scenario["restart_mosquitto"] is True
    assert scenario["username"] == kind
    assert scenario["topic"] == "sensors/{client_id}/temp"


@pytest.mark.parametrize(
    ("scenario_id", "kind"),
    (
        ("TOKEN-LIFECYCLE-RECONNECT-PUBLISH-JWT", "jwt"),
        ("TOKEN-LIFECYCLE-RECONNECT-PUBLISH-BISCUIT", "biscuit"),
    ),
)
def test_reconnect_publish_lifecycle_scenarios_are_multi_client_auth_heavy_repeats(
    scenario_id: str,
    kind: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["repeat"] == 6
    assert scenario["sleep_between"] == 1
    assert scenario["client_count"] == 25
    assert scenario["message_count"] == 25
    assert scenario["token_refresh"] == {"kind": kind, "ttl_seconds": 30}
    assert scenario.get("traffic_pattern") is None
    assert scenario.get("authz_config") is None
    assert scenario.get("proactive_refresh") is None
    assert scenario.get("reauth_storm") is None


@pytest.mark.parametrize(
    ("scenario_id", "kind"),
    (
        ("TOKEN-PUBLISH-STRESS-JWT", "jwt"),
        ("TOKEN-PUBLISH-STRESS-BISCUIT", "biscuit"),
    ),
)
def test_publish_stress_scenarios_are_fixed_high_volume_publish_slices(
    scenario_id: str,
    kind: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["username"] == kind
    assert scenario["topic"] == "sensors/{client_id}/temp"
    assert scenario["client_count"] == 25
    assert scenario["message_count"] == 1000
    assert scenario["complexity_axis"] == "publish_authz"
    assert scenario["complexity_level"] == "baseline"
    assert scenario.get("token_refresh") is None
    assert scenario.get("traffic_pattern") is None
    assert scenario.get("authz_config") is None


@pytest.mark.parametrize(
    ("scenario_id", "kind"),
    (
        ("TOKEN-PUBLISH-STRESS-RECONNECT-JWT", "jwt"),
        ("TOKEN-PUBLISH-STRESS-RECONNECT-BISCUIT", "biscuit"),
    ),
)
def test_publish_stress_reconnect_scenarios_are_high_volume_repeated_full_reconnects(
    scenario_id: str,
    kind: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["username"] == kind
    assert scenario["topic"] == "sensors/{client_id}/temp"
    assert scenario["client_count"] == 25
    assert scenario["message_count"] == 1000
    assert scenario["repeat"] == 6
    assert scenario["sleep_between"] == 1
    assert scenario["token_refresh"] == {"kind": kind, "ttl_seconds": 30}
    assert scenario["complexity_axis"] == "publish_authz_reconnect"
    assert scenario["complexity_level"] == "baseline"
    assert scenario.get("traffic_pattern") is None
    assert scenario.get("authz_config") is None
    assert scenario.get("proactive_refresh") is None
    assert scenario.get("reauth_storm") is None


@pytest.mark.parametrize(
    ("scenario_id", "level", "profile"),
    (
        ("TOKEN-DATALOG-STRESS-LOW-BISCUIT", "low", "biscuit_complex_low"),
        ("TOKEN-DATALOG-STRESS-MED-BISCUIT", "med", "biscuit_complex_med"),
        ("TOKEN-DATALOG-STRESS-HIGH-BISCUIT", "high", "biscuit_complex_high"),
    ),
)
def test_datalog_stress_scenarios_are_fixed_high_volume_local_policy_slices(
    scenario_id: str,
    level: str,
    profile: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["username"] == "biscuit"
    assert scenario["topic"] == "sensors/{client_id}/temp"
    assert scenario["client_count"] == 25
    assert scenario["message_count"] == 1000
    assert scenario["complexity_axis"] == "datalog"
    assert scenario["complexity_level"] == level
    assert scenario["password_map_profile"] == profile
    assert scenario.get("biscuit_attenuate") is None
    assert scenario.get("biscuit_delegate") is None
    assert scenario.get("token_refresh") is None


@pytest.mark.parametrize(
    ("scenario_id", "level", "profile"),
    (
        (
            "TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-MED-BISCUIT",
            "med",
            "biscuit_complex_med",
        ),
        (
            "TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-HIGH-BISCUIT",
            "high",
            "biscuit_complex_high",
        ),
    ),
)
def test_composability_attenuated_datalog_scenarios_layer_runtime_restrictions(
    scenario_id: str,
    level: str,
    profile: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["username"] == "biscuit"
    assert scenario["topic"] == "sensors/{client_id}/temp"
    assert scenario["client_count"] == 25
    assert scenario["message_count"] == 1000
    assert scenario["complexity_axis"] == "datalog"
    assert scenario["complexity_level"] == level
    assert scenario["password_map_profile"] == profile
    assert scenario["biscuit_attenuate"] == {
        "ttl_seconds": 300,
        "topic": "sensors/{client_id}/temp",
        "op": "publish",
    }
    assert scenario.get("biscuit_delegate") is None
    assert scenario.get("token_refresh") is None


@pytest.mark.parametrize(
    ("scenario_id", "level", "profile"),
    (
        (
            "TOKEN-COMPOSABILITY-DELEGATED-DATALOG-MED-BISCUIT",
            "med",
            "biscuit_complex_med",
        ),
        (
            "TOKEN-COMPOSABILITY-DELEGATED-DATALOG-HIGH-BISCUIT",
            "high",
            "biscuit_complex_high",
        ),
    ),
)
def test_composability_delegated_datalog_scenarios_layer_runtime_delegation(
    scenario_id: str,
    level: str,
    profile: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["username"] == "biscuit"
    assert scenario["topic"] == "sensors/{client_id}/temp"
    assert scenario["client_count"] == 25
    assert scenario["message_count"] == 1000
    assert scenario["complexity_axis"] == "datalog"
    assert scenario["complexity_level"] == level
    assert scenario["password_map_profile"] == profile
    assert scenario["biscuit_delegate"] == {
        "ttl_seconds": 300,
        "topic": "sensors/{client_id}/temp",
        "op": "publish",
    }
    assert scenario.get("biscuit_delegate", {}).get("handoff") is None
    assert scenario.get("biscuit_attenuate") is None
    assert scenario.get("token_refresh") is None


@pytest.mark.parametrize(
    ("scenario_id", "kind", "level"),
    (
        ("HTTP-AUTHZ-COMPLEXITY-SIMPLE-JWT", "jwt", "simple"),
        ("HTTP-AUTHZ-COMPLEXITY-MED-JWT", "jwt", "med"),
        ("HTTP-AUTHZ-COMPLEXITY-COMPLEX-JWT", "jwt", "complex"),
        ("HTTP-AUTHZ-COMPLEXITY-SIMPLE-BISCUIT", "biscuit", "simple"),
        ("HTTP-AUTHZ-COMPLEXITY-MED-BISCUIT", "biscuit", "med"),
        ("HTTP-AUTHZ-COMPLEXITY-COMPLEX-BISCUIT", "biscuit", "complex"),
    ),
)
def test_http_authz_complexity_scenarios_are_fixed_high_volume_profile_runs(
    scenario_id: str,
    kind: str,
    level: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["mosquitto_conf"] == "./mosquitto_http.conf"
    assert scenario["username"] == kind
    assert scenario["topic"] == "sensors/{client_id}/temp"
    assert scenario["client_count"] == 25
    assert scenario["message_count"] == 1000
    assert scenario["complexity_axis"] == "http_profile"
    assert scenario["complexity_level"] == level
    authz_config = scenario["authz_config"]
    assert authz_config is not None
    assert authz_config["authz_profile"] == level
    assert scenario.get("token_refresh") is None
    assert scenario.get("traffic_pattern") is None


@pytest.mark.parametrize(
    ("scenario_id", "kind"),
    (
        ("TOKEN-LIFECYCLE-PROACTIVE-REAUTH-JWT", "jwt"),
        ("TOKEN-LIFECYCLE-PROACTIVE-REAUTH-BISCUIT", "biscuit"),
    ),
)
def test_proactive_reauth_lifecycle_scenarios_are_timer_driven(scenario_id: str, kind: str) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["proactive_refresh"] is True
    assert scenario["proactive_refresh_margin_seconds"] == 60
    assert scenario["proactive_refresh_assert_continuity"] is True
    assert scenario["token_refresh"] == {"kind": kind, "ttl_seconds": 75}
    assert scenario["client_count"] == 1


@pytest.mark.parametrize(
    ("scenario_id", "kind"),
    (
        ("TOKEN-LIFECYCLE-REAUTH-STORM-JWT", "jwt"),
        ("TOKEN-LIFECYCLE-REAUTH-STORM-BISCUIT", "biscuit"),
    ),
)
def test_reauth_storm_lifecycle_scenarios_are_focused_multi_client_slice(
    scenario_id: str,
    kind: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["reauth_storm"] is True
    assert scenario["proactive_refresh"] is True
    assert scenario["proactive_refresh_margin_seconds"] == 60
    assert scenario["proactive_refresh_assert_continuity"] is True
    assert scenario["token_refresh"] == {"kind": kind, "ttl_seconds": 75}
    assert scenario["client_count"] == 25
    assert scenario["message_count"] == 1
    assert scenario.get("traffic_pattern") is None
    assert scenario.get("authz_config") is None


@pytest.mark.parametrize(
    ("scenario_id", "username"),
    (
        ("TEST-STRICT-MULTI-CLIENT-JWT", "jwt"),
        ("TEST-STRICT-MULTI-CLIENT-BISCUIT", "biscuit"),
    ),
)
def test_multi_client_strict_scenarios_validate_when_per_client_provisioning_is_available(
    scenario_id: str,
    username: str,
) -> None:
    scenario: rs.ScenarioConfig = {
        "id": scenario_id,
        "username": username,
        "password": "shared-token",
        "topic": "sensors/{client_id}/temp",
        "client_count": 10,
        "jwt_identity_binding": "strict",
        "biscuit_identity_binding": "strict",
        "semantic_class": "parity_identity_bound",
    }

    assert rs._scenario_semantics_metadata(
        scenario_id,
        scenario,
        default_clients=50,
    ) == {
        "jwt_identity_binding": "strict",
        "biscuit_identity_binding": "strict",
        "semantic_class": "parity_identity_bound",
    }


def test_multi_client_strict_scenarios_fail_when_harness_cannot_determine_token_kind() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "TEST-STRICT-MULTI-CLIENT-UNKNOWN",
        "password": "shared-token",
        "topic": "sensors/{client_id}/temp",
        "client_count": 10,
        "jwt_identity_binding": "strict",
        "biscuit_identity_binding": "strict",
        "semantic_class": "parity_identity_bound",
    }

    with pytest.raises(ValueError, match="cannot determine how to provision"):
        rs._validate_scenario_semantics(
            scenario["id"],
            scenario,
            default_clients=50,
        )


def test_multi_client_capability_scenarios_may_reuse_shared_tokens_when_declared() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "TEST-CAPABILITY-SHARED-TOKEN-JWT",
        "username": "jwt",
        "password": "shared-token",
        "topic": "fanout/broadcast",
        "traffic_pattern": "fanout",
        "subscriber_count": 50,
        "jwt_identity_binding": "off",
        "biscuit_identity_binding": "off",
        "semantic_class": "capability",
    }

    assert rs._scenario_semantics_metadata(
        scenario["id"],
        scenario,
        default_clients=50,
    ) == {
        "jwt_identity_binding": "off",
        "biscuit_identity_binding": "off",
        "semantic_class": "capability",
    }


def test_every_scenario_declares_and_validates_credential_mode() -> None:
    scenarios = _scenario_registry()

    for scenario_id, scenario in scenarios.items():
        rs._validate_scenario_credentials(scenario_id, scenario)

    assert scenarios["TOKEN-BASELINE-JWT"]["password_map_profile"] == "jwt"
    assert scenarios["TOKEN-DENY-READ-JWT"]["credential_mode"] == "shared"
    assert scenarios["TOKEN-COMPLEXITY-CHAIN-25-BISCUIT"]["password_map_profile"] == "biscuit_25"
    assert scenarios["STATIC-ACL-FANOUT-JWT"]["password_map_profile"] == "jwt_static_reader"
    assert (
        scenarios["STATIC-ACL-FANOUT-JWT"]["fanout_publisher_password_map_profile"]
        == "jwt_static_writer"
    )
    assert scenarios["TOKEN-THUNDERING-HERD-JWT"]["credential_mode"] == "per_client"
    assert scenarios["TOKEN-LIFECYCLE-REAUTH-STORM-BISCUIT"]["credential_mode"] == "issuer"
    assert scenarios["TOKEN-LIFECYCLE-RECONNECT-PUBLISH-JWT"]["credential_mode"] == "issuer"
    assert scenarios["TOKEN-LIFECYCLE-RECONNECT-PUBLISH-BISCUIT"]["credential_mode"] == "issuer"
    assert scenarios["TOKEN-PUBLISH-STRESS-JWT"]["credential_mode"] == "per_client"
    assert scenarios["TOKEN-PUBLISH-STRESS-BISCUIT"]["credential_mode"] == "per_client"
    assert scenarios["TOKEN-PUBLISH-STRESS-RECONNECT-JWT"]["credential_mode"] == "issuer"
    assert scenarios["TOKEN-PUBLISH-STRESS-RECONNECT-BISCUIT"]["credential_mode"] == "issuer"
    assert scenarios["TOKEN-DATALOG-STRESS-LOW-BISCUIT"]["credential_mode"] == "per_client"
    assert (
        scenarios["TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-MED-BISCUIT"]["credential_mode"]
        == "per_client"
    )

    assert (
        scenarios["TOKEN-COMPOSABILITY-DELEGATED-DATALOG-HIGH-BISCUIT"]["credential_mode"]
        == "per_client"
    )
    assert scenarios["HTTP-AUTHZ-COMPLEXITY-SIMPLE-JWT"]["credential_mode"] == "per_client"
    assert scenarios["HTTP-AUTHZ-COMPLEXITY-COMPLEX-BISCUIT"]["credential_mode"] == "per_client"
    assert scenarios["TOKEN-AUTHORIZER-PROFILE-SIMPLE-BISCUIT"]["credential_mode"] == "shared"
    assert scenarios["TOKEN-ACL-READ-FANOUT-STRICT-ALLOW-JWT-50"]["credential_mode"] == "shared"
    assert (
        scenarios["HTTP-ACL-READ-FANOUT-STRICT-MED-ALLOW-PARITY-JWT-50"]["password_map_profile"]
        == "jwt_fanout_strict"
    )
    assert (
        scenarios["HTTP-LATENCY-200MS-PARITY-BISCUIT"]["password_map_profile"]
        == "biscuit_strict_client_id"
    )


def test_phase_one_deny_and_attenuation_scenarios_have_executable_contracts() -> None:
    scenarios = _scenario_registry()
    for scenario_id in ("TOKEN-DENY-READ-JWT", "TOKEN-ATTENUATED-DENY-BISCUIT"):
        scenario = scenarios[scenario_id]
        assert scenario["traffic_pattern"] == "fanout"
        assert scenario["acl_read_enforcement"] == "strict"
        assert scenario["delivery_contract"] == {"steady": "none"}
        assert scenario["fanout_publisher_password"] != scenario["password"]

    attenuation = scenarios["TOKEN-ATTENUATION-COMBINED-BISCUIT"]["biscuit_attenuate"]
    assert attenuation["denies"] == ["subscribe:sensors/{client_id}/temp"]
    assert attenuation["checks"] == ['resource("sensors/{client_id}/temp")']
    assert "op" not in attenuation


@pytest.mark.parametrize("scenario_id", MULTI_CLIENT_FANOUT_PARITY_SCENARIOS)
def test_multi_client_fanout_parity_variants_are_runnable_and_strict(
    scenario_id: str,
) -> None:
    scenarios = _scenario_registry()
    scenario = scenarios[scenario_id]

    assert scenario["password"] == ""
    assert scenario.get("fanout_publisher_password") == ""
    assert rs._scenario_semantics_metadata(
        scenario_id,
        scenario,
        default_clients=50,
    ) == {
        "jwt_identity_binding": "strict",
        "biscuit_identity_binding": "strict",
        "semantic_class": "parity_identity_bound",
    }


def test_multi_client_fanout_parity_variants_do_not_depend_on_strict_fixture_tokens() -> None:
    tokens = _placeholder_tokens()
    tokens.pop("jwt_strict_sub_client_id", None)
    tokens.pop("biscuit_strict_client_id", None)

    scenarios = rs._build_available_scenarios(
        tokens,
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
    )

    assert "HTTP-LATENCY-200MS-PARITY-JWT" not in scenarios
    assert "HTTP-LATENCY-200MS-PARITY-BISCUIT" not in scenarios
    assert "HTTP-ACL-READ-FANOUT-STRICT-MED-ALLOW-PARITY-JWT-50" in scenarios
    assert "HYBRID-ACL-READ-FANOUT-STRICT-SIMPLE-DENY-PARITY-BISCUIT-10" in scenarios


def test_token_acl_read_fanout_strict_scenarios_do_not_register_parity_variants() -> None:
    scenarios = _scenario_registry()

    assert "TOKEN-ACL-READ-FANOUT-STRICT-ALLOW-PARITY-JWT-50" not in scenarios
    assert "TOKEN-ACL-READ-FANOUT-STRICT-ALLOW-PARITY-BISCUIT-50" not in scenarios
    assert "TOKEN-ACL-READ-FANOUT-STRICT-DENY-PARITY-JWT-10" not in scenarios
    assert "TOKEN-ACL-READ-FANOUT-STRICT-DENY-PARITY-BISCUIT-10" not in scenarios


def test_multi_client_http_hybrid_jwt_parity_variants_enable_strict_authz_binding() -> None:
    scenarios = _scenario_registry()

    for scenario_id in (
        "HTTP-ACL-READ-FANOUT-STRICT-MED-ALLOW-PARITY-JWT-50",
        "HYBRID-ACL-READ-FANOUT-STRICT-SIMPLE-DENY-PARITY-JWT-10",
    ):
        authz_config = scenarios[scenario_id]["authz_config"]
        assert authz_config is not None
        assert authz_config["jwt_identity_binding"] == "strict"


def test_requested_http_hybrid_multi_client_parity_scenarios_do_not_require_strict_fixture_tokens() -> (  # noqa: E501
    None
):
    tokens = _placeholder_tokens()
    tokens.pop("jwt_strict_sub_client_id", None)
    tokens.pop("biscuit_strict_client_id", None)

    rs._require_requested_scenario_fixtures(
        "HTTP-ACL-READ-FANOUT-STRICT-MED-ALLOW-PARITY-JWT-50",
        tokens,
    )


def test_legacy_token_fixtures_do_not_register_parity_scenarios() -> None:
    legacy_tokens = _placeholder_tokens()
    legacy_tokens.pop("jwt_strict_sub_client_id", None)
    legacy_tokens.pop("biscuit_strict_client_id", None)

    scenarios = rs._build_available_scenarios(
        legacy_tokens,
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
    )

    assert "HTTP-LATENCY-200MS-PARITY-JWT" not in scenarios
    assert "HTTP-LATENCY-200MS-PARITY-BISCUIT" not in scenarios
    assert "HTTP-PROFILE-COMPLEX-PARITY-JWT" not in scenarios
    assert "HTTP-PROFILE-COMPLEX-PARITY-BISCUIT" not in scenarios


def test_partial_jwt_strict_fixture_registers_only_jwt_parity_scenarios() -> None:
    tokens = _placeholder_tokens()
    tokens.pop("biscuit_strict_client_id", None)

    scenarios = rs._build_available_scenarios(
        tokens,
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
    )

    assert "HTTP-LATENCY-200MS-PARITY-JWT" in scenarios
    assert "HTTP-PROFILE-COMPLEX-PARITY-JWT" in scenarios
    assert "HTTP-LATENCY-200MS-PARITY-BISCUIT" not in scenarios
    assert "HTTP-PROFILE-COMPLEX-PARITY-BISCUIT" not in scenarios


def test_partial_biscuit_strict_fixture_registers_only_biscuit_parity_scenarios() -> None:
    tokens = _placeholder_tokens()
    tokens.pop("jwt_strict_sub_client_id", None)

    scenarios = rs._build_available_scenarios(
        tokens,
        token_issuer_no_default_roles=False,
        token_issuer_no_default_grants=False,
    )

    assert "HTTP-LATENCY-200MS-PARITY-BISCUIT" in scenarios
    assert "HTTP-PROFILE-COMPLEX-PARITY-BISCUIT" in scenarios
    assert "HTTP-LATENCY-200MS-PARITY-JWT" not in scenarios
    assert "HTTP-PROFILE-COMPLEX-PARITY-JWT" not in scenarios


def test_requested_partial_fixture_parity_scenario_is_selectable(monkeypatch) -> None:
    tokens = _placeholder_tokens()
    tokens.pop("biscuit_strict_client_id", None)
    warnings: list[str] = []

    class _FakeLogger:
        def info(self, _msg: str, *args: object) -> None:
            return None

        def warning(self, msg: str, *args: object) -> None:
            warnings.append(msg % args if args else msg)

    def _fake_effective_mosquitto_runtime_conf(
        mosquitto_conf: str,
        *,
        jwt_identity_binding: rs.IdentityBindingMode,
        biscuit_identity_binding: rs.IdentityBindingMode,
        biscuit_client_id_fact: str,
    ) -> str:
        assert mosquitto_conf == "./mosquitto_http.conf"
        assert jwt_identity_binding == "strict"
        assert biscuit_identity_binding == "strict"
        assert biscuit_client_id_fact == "client_id"
        raise _SelectedScenario

    monkeypatch.setattr(rs, "setup_logging", lambda _log_level: None)
    monkeypatch.setattr(rs, "_read_tokens", lambda _path: tokens)
    monkeypatch.setattr(
        rs,
        "_effective_mosquitto_runtime_conf",
        _fake_effective_mosquitto_runtime_conf,
    )
    monkeypatch.setattr(rs, "logger", _FakeLogger())

    with pytest.raises(_SelectedScenario):
        rs.main(
            tokens_path="ignored.json",
            scenarios_arg="HTTP-LATENCY-200MS-PARITY-JWT",
            iperf3_enabled=False,
            tcpdump_enabled=False,
        )

    assert "Unknown scenario 'HTTP-LATENCY-200MS-PARITY-JWT', skipping" not in warnings


@pytest.mark.parametrize(
    ("scenario_id", "missing_key"),
    (
        ("HTTP-LATENCY-200MS-PARITY-JWT", "jwt_strict_sub_client_id"),
        ("HTTP-LATENCY-200MS-PARITY-BISCUIT", "biscuit_strict_client_id"),
    ),
)
def test_requested_parity_scenarios_require_strict_token_fixtures(
    scenario_id: str,
    missing_key: str,
) -> None:
    tokens = _placeholder_tokens()
    tokens.pop(missing_key, None)

    with pytest.raises(SystemExit, match=missing_key):
        rs._require_requested_scenario_fixtures(scenario_id, tokens)
