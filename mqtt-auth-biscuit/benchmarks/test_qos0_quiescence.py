"""QoS0 post-workload authorization quiescence barrier.

At QoS 0, loadgen completion only means publishes were flushed to TCP; the
single-threaded broker may still be draining queued PUBLISHes through blocking
HTTP authorization. The runner must therefore wait for the expected downstream
terminal counter target before snapshotting cumulative authorizer counters.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

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


def _profile_stats_script(values: list[int], profile: str = "simple") -> list[dict[str, Any]]:
    return [
        {
            "requests": value,
            "policy_allows": value,
            "policy_denies": 0,
            "injected_failures": 0,
            "rules_examined": 2 * value,
            "profile_requests": {profile: value},
        }
        for value in values
    ]


class _ScriptedReader:
    """Replay a fixed counter sequence, then hold at the terminal value."""

    def __init__(self, values: list[int], profile: str = "simple") -> None:
        self._stats = _profile_stats_script(values, profile)
        self.reads = 0

    def __call__(self) -> dict[str, Any]:
        index = min(self.reads, len(self._stats) - 1)
        self.reads += 1
        return dict(self._stats[index])


class _FakeClock:
    def __init__(self) -> None:
        self.now_s = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.now_s

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now_s += seconds


def _targets(
    scenario_id: str,
    *,
    message_count: int = 10,
    client_count: int = 10,
    qos: int = 0,
    qos_distribution: str | None = None,
) -> dict[str, int]:
    scenario = _scenario_registry()[scenario_id]
    return rs._qos0_quiescence_targets(
        scenario,
        message_count=message_count,
        client_count=client_count,
        qos=qos,
        qos_distribution=qos_distribution,
    )


def test_qos0_barrier_waits_for_expected_target_before_snapshot() -> None:
    targets = _targets("HTTP-PROFILE-SIMPLE-BISCUIT")
    assert targets["profile:simple"] == 100
    reader = _ScriptedReader([32, 53, 66, 86, 100, 100])
    clock = _FakeClock()
    outcome = rs._wait_for_qos0_authorization_quiescence(
        "HTTP-PROFILE-SIMPLE-BISCUIT",
        targets,
        timeout_seconds=60,
        read_stats=reader,
        now=clock.now,
        sleep=clock.sleep,
    )
    assert outcome["observed"]["profile:simple"] == 100
    assert outcome["observed"]["requests"] == 100
    assert outcome["observed"]["policy_allows"] == 100
    assert outcome["started_observed"] == {
        "requests": 32,
        "profile:simple": 32,
        "policy_allows": 32,
    }
    assert outcome["targets"] == targets
    assert reader.reads == 6


def test_partial_sequence_does_not_snapshot_early() -> None:
    targets = _targets("HTTP-PROFILE-SIMPLE-BISCUIT")
    reader = _ScriptedReader([32, 53, 66, 86, 100, 100])
    clock = _FakeClock()
    outcome = rs._wait_for_qos0_authorization_quiescence(
        "HTTP-PROFILE-SIMPLE-BISCUIT",
        targets,
        timeout_seconds=60,
        read_stats=reader,
        now=clock.now,
        sleep=clock.sleep,
    )
    assert reader.reads > 4
    assert outcome["observed"] == {"requests": 100, "profile:simple": 100, "policy_allows": 100}


def test_temporary_stability_below_target_does_not_count_as_quiescence() -> None:
    targets = _targets("HTTP-PROFILE-SIMPLE-BISCUIT")
    reader = _ScriptedReader([66, 66, 66, 100, 100])
    clock = _FakeClock()
    outcome = rs._wait_for_qos0_authorization_quiescence(
        "HTTP-PROFILE-SIMPLE-BISCUIT",
        targets,
        timeout_seconds=60,
        read_stats=reader,
        now=clock.now,
        sleep=clock.sleep,
    )
    assert reader.reads == 5
    assert outcome["observed"]["profile:simple"] == 100


def test_target_reached_succeeds_immediately() -> None:
    targets = _targets("HTTP-PROFILE-SIMPLE-JWT")
    reader = _ScriptedReader([100, 100])
    clock = _FakeClock()
    outcome = rs._wait_for_qos0_authorization_quiescence(
        "HTTP-PROFILE-SIMPLE-JWT",
        targets,
        timeout_seconds=60,
        read_stats=reader,
        now=clock.now,
        sleep=clock.sleep,
    )
    assert reader.reads == 2
    assert clock.sleeps == []
    assert outcome["observed"]["profile:simple"] == 100


def test_timeout_below_target_fails_with_clear_diagnostic() -> None:
    targets = _targets("HTTP-PROFILE-SIMPLE-BISCUIT")
    reader = _ScriptedReader([66])
    clock = _FakeClock()
    with pytest.raises(RuntimeError) as excinfo:
        rs._wait_for_qos0_authorization_quiescence(
            "HTTP-PROFILE-SIMPLE-BISCUIT",
            targets,
            timeout_seconds=10,
            read_stats=reader,
            poll_interval_s=1.0,
            now=clock.now,
            sleep=clock.sleep,
        )
    message = str(excinfo.value)
    assert "HTTP-PROFILE-SIMPLE-BISCUIT" in message
    assert "expected" in message
    assert "observed" in message
    assert "started=" in message
    assert "'profile:simple': 66" in message
    assert "elapsed_s" in message
    assert "timeout_s=10" in message
    assert "66" in message


@pytest.mark.parametrize("qos", (1, 2))
@pytest.mark.parametrize(
    "scenario_id",
    (
        "HTTP-PROFILE-SIMPLE-JWT",
        "HTTP-PROFILE-SIMPLE-BISCUIT",
        "HTTP-PROFILE-COMPLEX-JWT",
        "HTTP-PROFILE-COMPLEX-BISCUIT",
        "HTTP-LATENCY-200MS-JWT",
        "HTTP-LATENCY-1000MS-JWT",
        "HYBRID-FALLBACK-AUTHZ-DOWN-JWT",
    ),
)
def test_q1_q2_do_not_use_qos0_barrier(scenario_id: str, qos: int) -> None:
    assert _targets(scenario_id, qos=qos) == {}


def test_mixed_qos_distribution_does_not_use_qos0_barrier() -> None:
    assert _targets("HTTP-PROFILE-SIMPLE-JWT", qos_distribution="0:0.6,1:0.3,2:0.1") == {}


@pytest.mark.parametrize(
    ("jwt_id", "biscuit_id"),
    (
        ("HTTP-PROFILE-SIMPLE-JWT", "HTTP-PROFILE-SIMPLE-BISCUIT"),
        ("HTTP-PROFILE-COMPLEX-JWT", "HTTP-PROFILE-COMPLEX-BISCUIT"),
    ),
)
def test_jwt_and_biscuit_use_identical_barrier_semantics(jwt_id: str, biscuit_id: str) -> None:
    assert _targets(jwt_id) == _targets(biscuit_id)


@pytest.mark.parametrize(
    ("scenario_id", "profile"),
    (
        ("HTTP-PROFILE-SIMPLE-JWT", "simple"),
        ("HTTP-PROFILE-SIMPLE-BISCUIT", "simple"),
        ("HTTP-PROFILE-COMPLEX-JWT", "complex"),
        ("HTTP-PROFILE-COMPLEX-BISCUIT", "complex"),
    ),
)
def test_http_profiles_compute_correct_expected_target(scenario_id: str, profile: str) -> None:
    assert _targets(scenario_id) == {
        "requests": 100,
        f"profile:{profile}": 100,
        "policy_allows": 100,
    }


@pytest.mark.parametrize(
    "scenario_id",
    ("HTTP-LATENCY-200MS-JWT", "HTTP-LATENCY-1000MS-JWT"),
)
def test_http_latency_scenarios_use_correct_expected_target(scenario_id: str) -> None:
    assert _targets(scenario_id) == {
        "requests": 100,
        "profile:simple": 100,
        "policy_allows": 100,
    }


def _timeout(
    scenario_id: str, *, clients: int, messages: int, expected_count: int | None = None
) -> int:
    scenario = _scenario_registry()[scenario_id]
    return rs._qos0_quiescence_timeout_seconds(
        scenario,
        clients=clients,
        expected_count=messages * clients if expected_count is None else expected_count,
    )


@pytest.mark.parametrize(
    ("scenario_id", "clients", "messages", "expected_timeout"),
    (
        ("HTTP-PROFILE-SIMPLE-BISCUIT", 10, 10, 65),
        ("HTTP-PROFILE-SIMPLE-BISCUIT", 10, 100, 515),
        ("HTTP-PROFILE-SIMPLE-BISCUIT", 50, 10, 265),
        ("HTTP-PROFILE-SIMPLE-BISCUIT", 50, 100, 2515),
        ("HTTP-PROFILE-SIMPLE-BISCUIT", 200, 10, 1015),
        ("HTTP-PROFILE-SIMPLE-BISCUIT", 200, 100, 10015),
        ("HTTP-PROFILE-COMPLEX-JWT", 200, 100, 10015),
        ("HTTP-LATENCY-200MS-JWT", 10, 10, 85),
        ("HTTP-LATENCY-200MS-JWT", 200, 100, 14015),
        ("HTTP-LATENCY-1000MS-JWT", 10, 10, 165),
        ("HTTP-LATENCY-1000MS-JWT", 200, 100, 30015),
        ("HYBRID-FALLBACK-AUTHZ-DOWN-JWT", 10, 10, 65),
        ("HYBRID-FALLBACK-AUTHZ-DOWN-JWT", 200, 100, 10015),
    ),
)
def test_qos0_timeout_scales_with_expected_downstream_work(
    scenario_id: str, clients: int, messages: int, expected_timeout: int
) -> None:
    assert _timeout(scenario_id, clients=clients, messages=messages) == expected_timeout


def test_qos0_timeout_grows_with_expected_work_not_clients_alone() -> None:
    scenarios = _scenario_registry()
    profile = scenarios["HTTP-PROFILE-SIMPLE-BISCUIT"]
    small = rs._qos0_quiescence_timeout_seconds(profile, clients=10, expected_count=100)
    large = rs._qos0_quiescence_timeout_seconds(profile, clients=200, expected_count=20000)
    assert large > small
    assert large > 15
    assert small >= rs._publish_timeout_seconds(profile, 10)
    assert large >= rs._publish_timeout_seconds(profile, 200)


def test_qos0_timeout_configured_delay_contributes() -> None:
    scenarios = _scenario_registry()
    profile_timeout = rs._qos0_quiescence_timeout_seconds(
        scenarios["HTTP-PROFILE-SIMPLE-JWT"], clients=10, expected_count=100
    )
    latency_timeout = rs._qos0_quiescence_timeout_seconds(
        scenarios["HTTP-LATENCY-1000MS-JWT"], clients=10, expected_count=100
    )
    assert latency_timeout > profile_timeout
    assert latency_timeout == 165


def test_qos0_timeout_covers_full_blocking_http_drain() -> None:
    scenarios = _scenario_registry()
    latency_1000 = scenarios["HTTP-LATENCY-1000MS-JWT"]
    timeout_s = rs._qos0_quiescence_timeout_seconds(latency_1000, clients=10, expected_count=100)
    assert timeout_s == 165
    assert timeout_s >= rs._publish_timeout_seconds(latency_1000, 10)
    latency_200 = scenarios["HTTP-LATENCY-200MS-JWT"]
    assert rs._qos0_quiescence_timeout_seconds(latency_200, clients=10, expected_count=100) == 85
    profile = scenarios["HTTP-PROFILE-SIMPLE-BISCUIT"]
    assert rs._qos0_quiescence_timeout_seconds(
        profile, clients=10, expected_count=100
    ) >= rs._publish_timeout_seconds(profile, 10)


def test_hybrid_fallback_target_semantics_remain_correct() -> None:
    assert _targets("HYBRID-FALLBACK-AUTHZ-DOWN-JWT") == {
        "requests": 100,
        "injected_failures": 100,
    }
    assert _targets("HYBRID-FALLBACK-AUTHZ-DOWN-JWT", qos=1) == {}


def test_non_http_q0_scenarios_have_no_downstream_barrier() -> None:
    assert _targets("TOKEN-BASELINE-JWT") == {}
    assert _targets("TOKEN-BASELINE-BISCUIT") == {}


def _measured_q0_result(connect_count: int, publish_count: int) -> dict[str, Any]:
    connect = [1.0] * connect_count
    publish = [1.0] * publish_count
    return {
        "connect": rs._summary_from_values(connect),
        "publish": rs._summary_from_values(publish),
        "publish_qos_0": rs._summary_from_values(publish),
        "publish_qos_1": rs._summary_from_values([]),
        "publish_qos_2": rs._summary_from_values([]),
        "raw_metrics": {
            "connect": connect,
            "publish": publish,
            "publish_qos_0": publish,
            "publish_qos_1": [],
            "publish_qos_2": [],
        },
        "publish_throughput_mps": float(publish_count),
    }


def _converged_http_profile_result(
    publish_count: int,
    profile: str = "simple",
    *,
    downstream_count: int | None = None,
) -> dict[str, Any]:
    downstream = publish_count if downstream_count is None else downstream_count
    return {
        **_measured_q0_result(10, publish_count),
        "errors": [],
        "qos_distribution_actual": {
            "qos_0_count": publish_count,
            "qos_1_count": 0,
            "qos_2_count": 0,
        },
        "authz_stats": {
            "requests": downstream,
            "policy_allows": downstream,
            "policy_denies": 0,
            "injected_failures": 0,
            "rules_examined": 2 * downstream,
            "profile_requests": {profile: downstream},
        },
    }


def test_existing_result_contracts_remain_unchanged() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "HTTP-PROFILE-SIMPLE-BISCUIT",
        "complexity_axis": "http_profile",
        "complexity_level": "simple",
    }
    result = _converged_http_profile_result(100)
    rs._validate_result_contract(
        scenario, result, message_count=10, client_count=10, effective_qos=0
    )


def test_no_expected_count_is_weakened() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "HTTP-PROFILE-SIMPLE-BISCUIT",
        "complexity_axis": "http_profile",
        "complexity_level": "simple",
    }
    partial = _converged_http_profile_result(100, downstream_count=66)
    with pytest.raises(RuntimeError, match=r"expected=100"):
        rs._validate_result_contract(
            scenario, partial, message_count=10, client_count=10, effective_qos=0
        )


def test_part2_total_remains_1512() -> None:
    assert rs.part2_expected_slot_total() == 1512
    assert rs.part2_expected_slot_total(repetitions=3) == 1512


def test_unexpected_result_errors_predicate() -> None:
    assert rs._unexpected_result_errors({"id": "X"}, {"errors": []}) == []
    assert rs._unexpected_result_errors({"id": "X"}, {"errors": ["boom", "bam"]}) == [
        "boom",
        "bam",
    ]
    scenario: rs.ScenarioConfig = {"id": "X", "allowed_error_prefixes": ["publish_failed:"]}
    assert (
        rs._unexpected_result_errors(scenario, {"errors": ["publish_failed:1", "publish_failed:2"]})
        == []
    )
    assert rs._unexpected_result_errors(scenario, {"errors": ["publish_failed:1", "other"]}) == [
        "other"
    ]


def test_barrier_entry_check_matches_contract_error_predicate() -> None:
    scenario: rs.ScenarioConfig = {
        "id": "HTTP-PROFILE-SIMPLE-BISCUIT",
        "complexity_axis": "http_profile",
        "complexity_level": "simple",
    }
    result = _converged_http_profile_result(100)
    result["errors"] = ["loadgen_container_x_failed"]
    assert rs._unexpected_result_errors(scenario, result) == ["loadgen_container_x_failed"]
    with pytest.raises(RuntimeError, match="loadgen errors"):
        rs._validate_result_contract(
            scenario, result, message_count=10, client_count=10, effective_qos=0
        )
