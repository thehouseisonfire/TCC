from __future__ import annotations

import re
from pathlib import Path

from benchmarks import run_scenarios as rs


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


def test_control_only_families_use_explicit_client_counts() -> None:
    scenarios = _scenario_registry()

    assert scenarios["CONTROL-OVERHEAD-KICK-REAUTH-JWT"]["client_count"] == 1
    assert scenarios["CONTROL-OVERHEAD-ACL-READ-NOTIFY-BISCUIT"]["client_count"] == 1
    assert scenarios["CONTROL-CHURN-CREATE-ROLE-JWT"]["client_count"] == 1
    assert scenarios["CONTROL-CHURN-GROUP-CLIENT-BISCUIT"]["client_count"] == 1
    assert scenarios["SQLITE-RBAC-DEEP-CONTROL-JWT"]["client_count"] == 1
    assert scenarios["SQLITE-RBAC-DEEP-CONTROL-BISCUIT"]["client_count"] == 1


def test_dynsec_control_families_use_generated_profiles_with_matching_principals() -> None:
    scenarios = _scenario_registry()

    assert (
        scenarios["CONTROL-OVERHEAD-KICK-REAUTH-JWT"]["dynamic_security_generated_profile"]
        == "control_admin_base"
    )
    assert (
        scenarios["CONTROL-OVERHEAD-ACL-READ-NOTIFY-BISCUIT"]["dynamic_security_generated_profile"]
        == "control_admin_base"
    )
    assert (
        scenarios["CONTROL-CHURN-CREATE-ROLE-JWT"]["dynamic_security_generated_profile"]
        == "control_admin_base"
    )
    assert (
        scenarios["CONTROL-INTERLEAVED-DATA-JWT"]["dynamic_security_generated_profile"]
        == "control_interleaved_base"
    )
    assert (
        scenarios["CONTROL-INTERLEAVED-DATA-BISCUIT"]["dynamic_security_generated_profile"]
        == "control_interleaved_base"
    )


def test_advanced_dynsec_control_churn_families_are_registered_with_expected_counts() -> None:
    scenarios = _scenario_registry()

    assert scenarios["CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-JWT"]["client_count"] == 1
    assert scenarios["CONTROL-CHURN-NOOP-GROUP-CLIENT-BISCUIT"]["client_count"] == 1
    assert scenarios["CONTROL-CHURN-REPEAT-SAME-ENTITY-JWT"]["client_count"] == 10
    assert scenarios["CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-BISCUIT"]["client_count"] == 10
    assert scenarios["CONTROL-CHURN-CONCURRENT-CONTROLLERS-JWT"]["client_count"] == 50


def test_advanced_dynsec_control_churn_profiles_and_repeat_settings_match_intent() -> None:
    scenarios = _scenario_registry()

    large_state = scenarios["CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-JWT"]
    assert large_state["control_repeat"] == 1
    assert large_state["dynamic_security_generated_profile"] == "large_state_control"
    assert "dynamic_security_config" not in large_state

    noop = scenarios["CONTROL-CHURN-NOOP-GROUP-CLIENT-JWT"]
    assert noop["control_repeat"] == 1
    assert noop["dynamic_security_generated_profile"] == "fanout_control_noop_group"
    assert noop["control_payload"]["commands"][0] == {
        "command": "addGroupClient",
        "groupname": "fanout_existing_readers",
        "username": "dynsec_client_1",
        "priority": 0,
    }

    same_entity = scenarios["CONTROL-CHURN-REPEAT-SAME-ENTITY-JWT"]
    assert same_entity["control_repeat"] == 3

    distinct = scenarios["CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-JWT"]
    assert distinct["control_repeat"] == 3
    assert distinct["control_payload"]["commands"][0]["rolename"] == "dynamic_role_{client_id}"

    concurrent = scenarios["CONTROL-CHURN-CONCURRENT-CONTROLLERS-BISCUIT"]
    assert concurrent["control_repeat"] == 1
    assert concurrent["control_payload"]["commands"][0]["rolename"] == "dynamic_role_{client_id}"


def test_control_notify_fanout_metrics_should_use_client_count_not_global_default() -> None:
    scenario = _scenario_registry()["CONTROL-OVERHEAD-ACL-READ-NOTIFY-JWT"]

    assert rs._effective_scenario_client_count(scenario, 25) == 1


def test_dynsec_alignment_accepts_generated_control_profiles() -> None:
    scenarios = _scenario_registry()

    for scenario_id in (
        "CONTROL-OVERHEAD-KICK-REAUTH-JWT",
        "CONTROL-CHURN-CREATE-ROLE-JWT",
        "CONTROL-INTERLEAVED-DATA-JWT",
    ):
        rs._validate_dynamic_security_alignment(
            scenario_id,
            scenarios[scenario_id],
            default_clients=10,
        )


def test_dynsec_alignment_rejects_missing_control_username() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "TEST-DYNSEC-MISSING-ADMIN",
        "username": "admin",
        "dynamic_security_config": "docker/dynamic-security.json",
    }

    try:
        rs._validate_dynamic_security_alignment(scenario["id"], scenario, default_clients=1)
    except ValueError as exc:
        assert "has no client for username 'admin'" in str(exc)
    else:
        raise AssertionError("expected missing admin dynsec validation error")


def test_dynsec_alignment_rejects_wrong_pinned_fanout_publisher_identity() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "TEST-DYNSEC-WRONG-PUBLISHER-PIN",
        "traffic_pattern": "fanout",
        "subscriber_count": 1,
        "username": "dynsec_client_1",
        "fanout_publisher_username": "dynsec_client_1",
        "dynamic_security_config": "docker/dynamic-security.json",
    }

    try:
        rs._validate_dynamic_security_alignment(scenario["id"], scenario, default_clients=1)
    except ValueError as exc:
        assert "benchmark expects 'fanout_publisher'" in str(exc)
    else:
        raise AssertionError("expected wrong fanout publisher pin validation error")


def test_dynamic_security_read_fanout_is_explicit_single_subscriber_and_passes_alignment() -> None:
    scenario = _scenario_registry()["DYNAMIC-SECURITY-READ-FANOUT"]

    assert scenario["subscriber_count"] == 1
    assert rs._effective_scenario_client_count(scenario, 10) == 1
    rs._validate_dynamic_security_alignment(
        "DYNAMIC-SECURITY-READ-FANOUT",
        scenario,
        default_clients=10,
    )
