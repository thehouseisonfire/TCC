"""Model B isolates fallback authorization after established MQTT sessions."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from benchmarks import run_scenarios as rs
from benchmarks.test_scenario_semantics import _measured_result, _scenario_registry

BASE = "HYBRID-FALLBACK-AUTHZ-DOWN-JWT"


def test_model_b_base_and_tls_preserve_fallback_semantics_and_inventory() -> None:
    scenarios = _scenario_registry()
    expanded = rs._expand_tls_matrix(scenarios)
    base = scenarios[BASE]
    assert base["sync_connect"] is True
    assert expanded[f"{BASE}-TLS"] == {**base, "tls": True}
    assert {key for key in expanded if key.startswith("HYBRID-FALLBACK-AUTHZ-DOWN-")} == {
        BASE,
        f"{BASE}-TLS",
    }
    assert base == {
        "mosquitto_conf": "./mosquitto_hybrid.conf",
        "username": "jwt",
        "password": "jwt-fixture",
        "topic": "sensors/{client_id}/temp",
        "authz_config": rs._tuned_profile_authz_config("simple", delay_ms=0, fail_mode="always"),
        "netem": {"clear": True},
        "message_size": 0,
        "hybrid_fallback_required": True,
        "sync_connect": True,
        "jwt_identity_binding": "off",
        "biscuit_identity_binding": "off",
        "semantic_class": "capability",
        "credential_mode": "per_client",
        "password_map_profile": "jwt",
        "token_issuer_no_default_roles": False,
        "token_issuer_no_default_grants": False,
    }
    config = (Path(rs.__file__).parents[1] / "docker/mosquitto_hybrid.conf").read_text()
    assert "plugin_opt_policy_mode hybrid\n" in config
    assert rs.BASE_PUBLISH_TIMEOUT_S == 10
    assert rs._publish_timeout_seconds(base, 50) == 10
    assert (
        rs._expected_publish_authorization_count(base, message_count=100, client_count=50) == 5000
    )
    assert rs._qos0_quiescence_targets(
        base, message_count=100, client_count=50, qos=0, qos_distribution=None
    ) == {"requests": 5000, "injected_failures": 5000}
    assert len(expanded) == 444
    assert len(rs.PART2_SWEEP_COHORTS["matrix"]) == 22
    assert rs.part2_expected_slot_total() == 1512


def _complete_result() -> dict[str, Any]:
    barrier = {
        "barrier": "external",
        "participants": 50,
        "ready_count": 50,
        "max_ready_skew_ms": 1.0,
        "errors": [],
    }
    return {
        **_measured_result(50, 5000),
        "errors": [],
        "inputs": {
            "credential_attestations": {"clients": {"profile": "jwt", "validated_credentials": 50}}
        },
        "sync_connect": {**barrier, "enabled": True, "publish_barrier": dict(barrier)},
        "authz_stats": {
            "requests": 5000,
            "injected_failures": 5000,
            "policy_allows": 0,
            "policy_denies": 0,
            "configured_fail_mode": "always",
        },
    }


@pytest.mark.parametrize("scenario_id", (BASE, f"{BASE}-TLS"))
@pytest.mark.parametrize(
    ("failure", "expected_error"),
    (
        ("missing_connection", "connect metric count"),
        ("incomplete_connect_barrier", "synchronized connection barrier"),
        ("incomplete_publish_barrier", "synchronized publish-release barrier"),
        ("readiness_timeout", "synchronized publish-release barrier"),
        ("connect_failure", "loadgen errors"),
    ),
)
def test_model_b_rejects_incomplete_phase_even_if_survivors_publish(
    scenario_id: str, failure: str, expected_error: str
) -> None:
    scenario = rs._expand_tls_matrix(_scenario_registry())[scenario_id]
    scenario = {**scenario, "id": scenario_id}
    result = _complete_result()
    rs._validate_result_contract(scenario, result, message_count=100, client_count=50)
    assert result["fallback_attestation"] == {
        "validated": True,
        "source": "token",
        "external_failures": 5000,
        "successful_fallbacks": 5000,
    }
    broken = deepcopy(result)
    if failure == "missing_connection":
        broken["connect"] = rs._summary_from_values([1.0] * 49)
        broken["raw_metrics"]["connect"] = [1.0] * 49
    elif failure == "incomplete_connect_barrier":
        broken["sync_connect"]["ready_count"] = 49
    elif failure == "incomplete_publish_barrier":
        broken["sync_connect"]["publish_barrier"]["ready_count"] = 49
    elif failure == "readiness_timeout":
        broken["sync_connect"]["publish_barrier"]["errors"] = [
            "sync_publish_barrier_failed:readiness_timeout"
        ]
    else:
        broken["errors"] = ["connect_failed:connect_timeout"]
    with pytest.raises(RuntimeError, match=expected_error):
        rs._validate_result_contract(scenario, broken, message_count=100, client_count=50)
