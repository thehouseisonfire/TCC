"""Part 2 DYNAMIC-SECURITY-CHURN QoS-axis correction.

The churn scenario's ``runtime_control_expect_denial`` contract is only
client-observable at QoS 1 (PUBACK rc135) and QoS 2 (PUBREC rc135).  At QoS 0
there is no acknowledgement carrying the denial, so the result contract is
impossible to satisfy.  These tests pin the executable sweep contract: the
full matrix holds exactly 22 scenarios, and CHURN lives exactly once in a
dedicated QoS 1/2 cohort.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

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


def test_churn_is_not_in_full_matrix_cohort() -> None:
    assert "DYNAMIC-SECURITY-CHURN" not in rs.PART2_SWEEP_COHORTS["matrix"]


def test_full_matrix_cohort_has_exactly_22_scenarios() -> None:
    assert len(rs.PART2_SWEEP_COHORTS["matrix"]) == 22


def test_churn_is_present_exactly_once_in_dedicated_cohort() -> None:
    assert rs.PART2_SWEEP_COHORTS["churn"] == ("DYNAMIC-SECURITY-CHURN",)
    selected = [scenario_id for cohort in rs.PART2_SWEEP_COHORTS.values() for scenario_id in cohort]
    assert selected.count("DYNAMIC-SECURITY-CHURN") == 1


def test_churn_allowed_qos_is_exactly_1_and_2() -> None:
    assert rs.part2_allowed_qos("churn") == (1, 2)
    assert set(rs.PART2_SWEEP_COHORT_QOS["churn"]) == {1, 2}
    assert set(rs.PART2_SWEEP_COHORT_AXES["churn"]["qos"]) == {1, 2}


def test_churn_q0_is_excluded_structurally() -> None:
    assert 0 not in rs.PART2_SWEEP_COHORT_QOS["churn"]
    assert 0 not in rs.PART2_SWEEP_COHORT_AXES["churn"]["qos"]
    scenarios = _scenario_registry()
    churn = scenarios["DYNAMIC-SECURITY-CHURN"]
    with pytest.raises(RuntimeError, match="not client-observable"):
        rs._validate_part2_qos_for_scenario("DYNAMIC-SECURITY-CHURN", churn, 0)


def test_churn_q1_and_q2_are_included() -> None:
    assert 1 in rs.PART2_SWEEP_COHORT_QOS["churn"]
    assert 2 in rs.PART2_SWEEP_COHORT_QOS["churn"]
    scenarios = _scenario_registry()
    churn = scenarios["DYNAMIC-SECURITY-CHURN"]
    rs._validate_part2_qos_for_scenario("DYNAMIC-SECURITY-CHURN", churn, 1)
    rs._validate_part2_qos_for_scenario("DYNAMIC-SECURITY-CHURN", churn, 2)


def test_churn_clients_and_messages_remain_matrix_shaped() -> None:
    assert rs.PART2_SWEEP_COHORT_AXES["churn"]["clients"] == (10, 50, 200)
    assert rs.PART2_SWEEP_COHORT_AXES["churn"]["messages"] == (10, 100)


def test_part2_slot_total_is_exactly_1512() -> None:
    assert rs.part2_expected_slot_total() == 1512
    assert rs.part2_expected_slot_total(repetitions=3) == 1512
    # Mechanically validated per-cohort arithmetic:
    # 22*3*2*3*3=1188 matrix, 1*3*2*2*3=36 churn,
    # 3*3*2*1*3=54 fixed_qos, 2*1*2*1*3=12 fixed_clients_qos,
    # 2*1*1*1*3=6 reauth, 2*3*2*3*2*3=216 issuer.
    assert 1188 + 36 + 54 + 12 + 6 + 216 == 1512


def test_no_scenario_duplication_across_part2_cohorts() -> None:
    selected = [scenario_id for cohort in rs.PART2_SWEEP_COHORTS.values() for scenario_id in cohort]
    assert len(selected) == 32
    assert len(set(selected)) == len(selected)
    scenarios = _scenario_registry()
    rs._validate_part2_sweep_inventory(scenarios)


def test_fixed_cohort_shapes_remain_unchanged() -> None:
    assert rs.PART2_SWEEP_COHORTS["fixed_qos"] == (
        "BASELINE-NO-AUTH",
        "TOKEN-QOS2-JWT",
        "TOKEN-QOS2-BISCUIT",
    )
    assert rs.PART2_SWEEP_COHORTS["fixed_clients_qos"] == (
        "TOKEN-DENY-READ-JWT",
        "TOKEN-ATTENUATED-DENY-BISCUIT",
    )
    assert rs.PART2_SWEEP_COHORTS["reauth"] == (
        "TOKEN-MQTT5-REAUTH-JWT",
        "TOKEN-MQTT5-REAUTH-BISCUIT",
    )
    assert rs.PART2_SWEEP_COHORTS["issuer"] == (
        "TOKEN-ISSUER-BASELINE-JWT",
        "TOKEN-ISSUER-BASELINE-BISCUIT",
    )
    assert rs.PART2_SWEEP_COHORT_QOS["fixed_qos"] == (1,)
    assert rs.PART2_SWEEP_COHORT_QOS["fixed_clients_qos"] == (1,)
    assert rs.PART2_SWEEP_COHORT_QOS["reauth"] == (1,)
    assert rs.PART2_SWEEP_COHORT_QOS["issuer"] == (0, 1, 2)


def test_churn_registry_semantics_are_not_weakened() -> None:
    churn = _scenario_registry()["DYNAMIC-SECURITY-CHURN"]
    assert churn["runtime_control_expect_denial"] is True
    assert churn["runtime_control_after_messages"] == 10
    assert "qos" not in churn
    assert "client_count" not in churn
    assert "subscriber_count" not in churn


def test_inventory_rejects_churn_in_matrix_cohort() -> None:
    scenarios = _scenario_registry()
    original = dict(rs.PART2_SWEEP_COHORTS)
    try:
        rs.PART2_SWEEP_COHORTS["matrix"] = (
            *original["matrix"],
            "DYNAMIC-SECURITY-CHURN",
        )
        with pytest.raises(ValueError, match="duplicated|dedicated churn cohort"):
            rs._validate_part2_sweep_inventory(scenarios)
    finally:
        rs.PART2_SWEEP_COHORTS.clear()
        rs.PART2_SWEEP_COHORTS.update(original)
