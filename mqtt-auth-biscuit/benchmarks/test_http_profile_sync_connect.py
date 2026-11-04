"""HTTP profile scenarios must separate CONNECT and PUBLISH phases.

The broker authorizes PUBLISHes on its single event-loop thread. Without a
connect barrier, staggered container starts let early publishers queue later
CONNACKs behind HTTP authorization work until the fixed 10 s connect budget is
exhausted. The four SIMPLE/COMPLEX matrix cells therefore use the same
two-phase ``sync_connect`` barrier as the latency cells.

MED and parity variants are intentionally unchanged: the HOLD evidence covers
only the four matrix cells, and broadening the barrier would change unrelated
scenario semantics.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from benchmarks import run_scenarios as rs

HTTP_PROFILE_SYNC_SCENARIOS = (
    "HTTP-PROFILE-SIMPLE-JWT",
    "HTTP-PROFILE-SIMPLE-BISCUIT",
    "HTTP-PROFILE-COMPLEX-JWT",
    "HTTP-PROFILE-COMPLEX-BISCUIT",
)

HTTP_PROFILE_UNCHANGED_SCENARIOS = (
    "HTTP-PROFILE-MED-JWT",
    "HTTP-PROFILE-MED-BISCUIT",
    "HTTP-PROFILE-SIMPLE-PARITY-JWT",
    "HTTP-PROFILE-SIMPLE-PARITY-BISCUIT",
    "HTTP-PROFILE-MED-PARITY-JWT",
    "HTTP-PROFILE-MED-PARITY-BISCUIT",
    "HTTP-PROFILE-COMPLEX-PARITY-JWT",
    "HTTP-PROFILE-COMPLEX-PARITY-BISCUIT",
)

EXISTING_SYNC_CONNECT_SCENARIOS = frozenset(
    {
        "HTTP-LATENCY-200MS-JWT",
        "HTTP-LATENCY-1000MS-JWT",
        "HTTP-LATENCY-200MS-BISCUIT",
        "HTTP-LATENCY-200MS-PARITY-JWT",
        "HTTP-LATENCY-200MS-PARITY-BISCUIT",
        "HTTP-FAILURE-INJECTION-200MS-1PCT-JWT",
        "HTTP-FAILURE-INJECTION-200MS-5PCT-JWT",
        "TOKEN-THUNDERING-HERD-JWT",
        "TOKEN-THUNDERING-HERD-BISCUIT",
    }
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


@pytest.mark.parametrize(
    ("scenario_id", "profile"),
    (
        ("HTTP-PROFILE-SIMPLE-JWT", "simple"),
        ("HTTP-PROFILE-SIMPLE-BISCUIT", "simple"),
        ("HTTP-PROFILE-COMPLEX-JWT", "complex"),
        ("HTTP-PROFILE-COMPLEX-BISCUIT", "complex"),
    ),
)
def test_http_profile_matrix_cells_use_two_phase_connect(
    scenario_id: str,
    profile: str,
) -> None:
    scenario = _scenario_registry()[scenario_id]

    assert scenario["sync_connect"] is True
    assert scenario.get("restart_mosquitto") is not True
    assert scenario["complexity_axis"] == "http_profile"
    assert scenario["complexity_level"] == profile
    assert scenario["mosquitto_conf"] == "./mosquitto_http.conf"
    assert scenario.get("http_expected_delay_ms") is None
    assert scenario.get("http_timeout_budget_delay_ms") is None

    authz_config = scenario["authz_config"]
    assert authz_config is not None
    assert authz_config["authz_profile"] == profile
    assert authz_config["delay_ms"] == 0
    assert authz_config["fail_mode"] == "none"

    assert rs._publish_timeout_seconds(scenario, 50) == 10


def test_only_the_four_http_profile_matrix_cells_enable_the_barrier() -> None:
    scenarios = _scenario_registry()
    enabled = {
        scenario_id
        for scenario_id, scenario in scenarios.items()
        if scenario_id.startswith("HTTP-PROFILE") and scenario.get("sync_connect") is True
    }

    assert enabled == set(HTTP_PROFILE_SYNC_SCENARIOS)
    for scenario_id in HTTP_PROFILE_UNCHANGED_SCENARIOS:
        assert scenarios[scenario_id].get("sync_connect") is not True


def test_sync_connect_cohort_includes_only_qualified_scenarios() -> None:
    scenarios = _scenario_registry()
    enabled = {
        scenario_id
        for scenario_id, scenario in scenarios.items()
        if scenario.get("sync_connect") is True
    }

    assert enabled == (
        EXISTING_SYNC_CONNECT_SCENARIOS
        | set(HTTP_PROFILE_SYNC_SCENARIOS)
        | {"HYBRID-FALLBACK-AUTHZ-DOWN-JWT"}
    )


def test_http_latency_barrier_semantics_remain_unchanged() -> None:
    scenarios = _scenario_registry()
    for scenario_id in (
        "HTTP-LATENCY-200MS-JWT",
        "HTTP-LATENCY-1000MS-JWT",
        "HTTP-LATENCY-200MS-BISCUIT",
        "HTTP-LATENCY-200MS-PARITY-JWT",
        "HTTP-LATENCY-200MS-PARITY-BISCUIT",
    ):
        assert scenarios[scenario_id]["sync_connect"] is True
        assert scenarios[scenario_id].get("restart_mosquitto") is not True


def test_matrix_inventory_and_part2_slot_total_remain_unchanged() -> None:
    matrix = rs.PART2_SWEEP_COHORTS["matrix"]

    assert len(matrix) == 22
    assert set(HTTP_PROFILE_SYNC_SCENARIOS) <= set(matrix)
    assert rs.part2_expected_slot_total() == 1512
    assert rs.part2_expected_slot_total(repetitions=3) == 1512


@pytest.mark.parametrize(
    ("scenario_id", "profile"),
    (
        ("HTTP-PROFILE-SIMPLE-JWT", "simple"),
        ("HTTP-PROFILE-SIMPLE-BISCUIT", "simple"),
        ("HTTP-PROFILE-COMPLEX-JWT", "complex"),
        ("HTTP-PROFILE-COMPLEX-BISCUIT", "complex"),
    ),
)
def test_http_profile_authorization_targets_remain_unchanged(
    scenario_id: str,
    profile: str,
) -> None:
    scenario = _scenario_registry()[scenario_id]

    assert rs._qos0_quiescence_targets(
        scenario,
        message_count=10,
        client_count=50,
        qos=0,
        qos_distribution=None,
    ) == {
        "requests": 500,
        f"profile:{profile}": 500,
        "policy_allows": 500,
    }
