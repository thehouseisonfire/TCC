"""Executable infrastructure and observability preflight for TESTING.md Phase 2."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from benchmarks.run_scenarios import (
    ScenarioConfig,
    _build_available_scenarios,
    _effective_scenario_client_count,
    _effective_scenario_message_count,
    _expand_tls_matrix,
    _infer_acl_read_enforcement,
    _infer_policy_source,
    _read_tokens,
    _render_mosquitto_runtime_conf,
    _resolve_compose_path,
    _scenario_workload_axes,
    _scenario_workload_shape,
    _validate_broker_path_contract,
    _validate_resource_interval,
    _validate_result_contract,
)

BASE_SCENARIOS = (
    "BASELINE-NO-AUTH",
    "TOKEN-BASELINE-JWT",
    "TOKEN-BASELINE-BISCUIT",
    "STATIC-ACL-FANOUT-JWT",
    "DYNAMIC-SECURITY-CHURN",
    "HTTP-PROFILE-SIMPLE-JWT",
    "SQLITE-RBAC-CHURN-JWT",
    "HYBRID-FALLBACK-AUTHZ-DOWN-JWT",
    "TOKEN-DENY-READ-JWT",
    "TOKEN-QOS2-JWT",
    "TOKEN-MQTT5-REAUTH-JWT",
    "NETWORK-MTU-200-JWT",
    "NETWORK-MTU-1500-JWT",
    "HTTP-FAILURE-INJECTION-200MS-5PCT-JWT",
)

TLS_SCENARIOS = tuple(
    f"{scenario}-TLS"
    for scenario in (
        "BASELINE-NO-AUTH",
        "TOKEN-BASELINE-JWT",
        "TOKEN-BASELINE-BISCUIT",
        "STATIC-ACL-FANOUT-JWT",
        "DYNAMIC-SECURITY-CHURN",
        "HTTP-PROFILE-SIMPLE-JWT",
        "SQLITE-RBAC-CHURN-JWT",
        "HYBRID-FALLBACK-AUTHZ-DOWN-JWT",
    )
)


def _packet_metrics(result: dict[str, object], scenario: str) -> dict[str, object]:
    packet = result.get("packet_analysis_result")
    if not isinstance(packet, dict) or not packet.get("enabled"):
        raise RuntimeError(f"{scenario}: missing packet-analysis result")
    if packet.get("error"):
        raise RuntimeError(f"{scenario}: packet analysis failed: {packet['error']}")
    metrics = packet.get("metrics")
    if not isinstance(metrics, dict):
        raise RuntimeError(f"{scenario}: packet-analysis metrics missing")
    return metrics


def _required_int_metric(metrics: dict[str, object], name: str, scenario: str) -> int:
    value = metrics.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise RuntimeError(f"{scenario}: packet metric {name} is missing or invalid")
    return value


def _run(output: Path, scenarios: tuple[str, ...], *, tls: bool) -> None:
    command = [
        sys.executable,
        "-m",
        "benchmarks.run_scenarios",
        "--scenarios-arg",
        ",".join(scenarios),
        "--clients",
        "2",
        "--messages",
        "10",
        "--client-topology",
        "container-per-client",
        "--out",
        str(output),
        "--no-iperf3",
    ]
    if tls:
        command.extend(["--tls", "--tls-insecure"])
    subprocess.run(command, cwd=Path(__file__).parents[1], check=True)


def _scenario_registry() -> dict[str, ScenarioConfig]:
    repo_root = Path(__file__).parents[1]
    tokens = _read_tokens(str(repo_root / "benchmarks/tokens.json"))
    return cast(
        dict[str, ScenarioConfig],
        _expand_tls_matrix(
            _build_available_scenarios(
                tokens,
                token_issuer_no_default_roles=False,
                token_issuer_no_default_grants=False,
            )
        ),
    )


def _current_broker_fixture_hash(
    broker: dict[str, object], expected: ScenarioConfig, scenario: str
) -> str:
    effective_path = broker.get("effective_path")
    if not isinstance(effective_path, str):
        raise RuntimeError(f"{scenario}: effective broker configuration path missing")
    effective_file = _resolve_compose_path(effective_path)
    if ".generated" in effective_path:
        requested_path = broker.get("requested_path")
        if not isinstance(requested_path, str):
            raise RuntimeError(f"{scenario}: generated broker fixture source is missing")
        requested_file = _resolve_compose_path(requested_path)
        if not requested_file.is_file():
            raise RuntimeError(f"{scenario}: requested broker fixture is missing")
        current_bytes = _render_mosquitto_runtime_conf(
            requested_file.read_text(encoding="utf-8"),
            jwt_identity_binding=expected.get("jwt_identity_binding") or "off",
            biscuit_identity_binding=expected.get("biscuit_identity_binding") or "off",
            biscuit_client_id_fact=str(expected.get("biscuit_client_id_fact") or "client_id"),
        ).encode()
    elif effective_file.is_file():
        current_bytes = effective_file.read_bytes()
    else:
        raise RuntimeError(f"{scenario}: effective broker fixture is missing")
    return hashlib.sha256(current_bytes).hexdigest()


def _verify(output: Path, scenarios: tuple[str, ...]) -> list[dict[str, object]]:
    registry = _scenario_registry()
    evidence = []
    for scenario in scenarios:
        path = output / f"{scenario}.json"
        if not path.is_file():
            raise RuntimeError(f"missing preflight result: {path}")
        result = json.loads(path.read_text())
        if result.get("result_schema_version") != 2:
            raise RuntimeError(f"{scenario}: unsupported or missing result schema version")
        if result.get("scenario") != scenario:
            raise RuntimeError(f"{scenario}: result scenario identity mismatch")
        expected = cast(ScenarioConfig, dict(registry[scenario]))
        expected["id"] = scenario
        expected_clients = _effective_scenario_client_count(expected, 2)
        expected_messages = _effective_scenario_message_count(
            expected, 10, effective_clients=expected_clients
        )
        expected_qos = int(expected.get("qos", 1))
        expected_distribution = expected.get("qos_distribution")
        expected_tls = bool(expected.get("tls"))
        expected_authz_profile = expected.get("authz_profile")
        if expected_authz_profile is None and isinstance(expected.get("authz_config"), dict):
            expected_authz_profile = cast(dict[str, Any], expected["authz_config"]).get(
                "authz_profile"
            )
        tls = result.get("tls")
        if (
            not isinstance(tls, dict)
            or tls.get("enabled") is not expected_tls
            or tls.get("purpose") != "transport_encryption"
            or tls.get("certificate_validation_tested") is not False
            or expected_tls
            and tls.get("insecure") is not True
        ):
            raise RuntimeError(f"{scenario}: TLS semantics mismatch: {tls}")
        config = result.get("scenario_config")
        if not isinstance(config, dict):
            raise RuntimeError(f"{scenario}: scenario configuration provenance missing")
        expected_config = {
            "clients": expected_clients,
            "messages": expected_messages,
            "qos": expected_qos,
            "qos_distribution": expected_distribution,
            "workload_shape": _scenario_workload_shape(expected),
            "workload_axes": _scenario_workload_axes(expected),
            "credential_mode": expected.get("credential_mode"),
            "password_map_profile": expected.get("password_map_profile"),
            "traffic_pattern": expected.get("traffic_pattern"),
            "workload_kind": expected.get("workload_kind"),
            "authorization_probe_count": expected.get("authorization_probe_count"),
            "fanout_topic": expected.get("fanout_topic"),
            "subscriber_count": expected.get("subscriber_count"),
            "authz_profile": expected_authz_profile,
            "fanout_churn_kind": expected.get("fanout_churn_kind"),
            "runtime_control_after_messages": expected.get("runtime_control_after_messages"),
            "runtime_control_expect_denial": expected.get("runtime_control_expect_denial", False),
            "policy_source": expected.get("policy_source") or _infer_policy_source(expected),
            "acl_read_enforcement": _infer_acl_read_enforcement(expected),
        }
        for key, expected_value in expected_config.items():
            if config.get(key) != expected_value:
                raise RuntimeError(
                    f"{scenario}: scenario_config.{key}={config.get(key)!r}, "
                    f"expected {expected_value!r}"
                )
        topology = config.get("client_topology")
        if (
            not isinstance(topology, dict)
            or topology.get("mode") != "container-per-client"
            or topology.get("effective_mode") != "container-per-client"
        ):
            raise RuntimeError(f"{scenario}: wrong client topology")
        broker = result.get("broker_config_attestation")
        if not isinstance(broker, dict) or broker.get("validated") is not True:
            raise RuntimeError(f"{scenario}: broker configuration attestation missing")
        if broker.get("expected_sha256") != broker.get("container_sha256"):
            raise RuntimeError(f"{scenario}: mounted broker configuration hash mismatch")
        effective_path = broker.get("effective_path")
        if not isinstance(effective_path, str):
            raise RuntimeError(f"{scenario}: effective broker configuration path missing")
        current_hash = _current_broker_fixture_hash(broker, expected, scenario)
        if current_hash != broker.get("expected_sha256"):
            raise RuntimeError(f"{scenario}: result was produced from a stale broker fixture")
        runs = result.get("runs")
        if not isinstance(runs, list) or len(runs) != int(expected.get("repeat", 1)):
            raise RuntimeError(f"{scenario}: missing measured runs")
        checks = ["identity", "configuration", "topology", "tls", "broker_config"]
        for run_index, run in enumerate(runs):
            if not isinstance(run, dict):
                raise RuntimeError(f"{scenario}: invalid run payload")
            loadgen = run.get("loadgen")
            resources = run.get("resources")
            if not isinstance(loadgen, dict) or not isinstance(resources, dict):
                raise RuntimeError(f"{scenario}: loadgen/resource evidence missing")
            loadgen_topology = loadgen.get("topology")
            if (
                not isinstance(loadgen_topology, dict)
                or loadgen_topology.get("mode") != "container-per-client"
            ):
                raise RuntimeError(f"{scenario}: effective loadgen topology mismatch")
            _validate_broker_path_contract(
                cast(Any, expected), loadgen, broker, client_count=expected_clients
            )
            _validate_result_contract(
                cast(Any, expected),
                loadgen,
                message_count=expected_messages,
                client_count=expected_clients,
                effective_qos=expected_qos,
                effective_qos_distribution=cast(str | None, expected_distribution),
            )
            _validate_resource_interval(resources, scenario_id=scenario, run_index=run_index)
            checks.extend(["broker_path", "result_contract", "resource_interval"])
        if scenario.startswith("NETWORK-MTU-"):
            _packet_metrics(result, scenario)
            checks.append("packet_analysis")
        evidence.append(
            {
                "scenario": scenario,
                "result": str(path),
                "validated": True,
                "checks": sorted(set(checks)),
                "effective_workload": {
                    "clients": expected_clients,
                    "messages": expected_messages,
                    "qos": expected_qos,
                },
                "policy_mode": broker.get("policy_mode"),
            }
        )
    return evidence


def _verify_mtu_pair(output: Path) -> dict[str, object]:
    payload_sizes = {}
    for mtu in (200, 1500):
        path = output / f"NETWORK-MTU-{mtu}-JWT.json"
        result = json.loads(path.read_text())
        metrics = _packet_metrics(result, f"NETWORK-MTU-{mtu}-JWT")
        payload_sizes[mtu] = _required_int_metric(
            metrics, "max_tcp_payload_bytes", f"NETWORK-MTU-{mtu}-JWT"
        )
    if payload_sizes[200] <= 0 or payload_sizes[200] >= payload_sizes[1500]:
        raise RuntimeError(
            f"MTU pair does not demonstrate tighter TCP segmentation: max payloads={payload_sizes}"
        )
    return {
        "requirement": "mtu_pair_segmentation",
        "validated": True,
        "max_tcp_payload_mtu_200": payload_sizes[200],
        "max_tcp_payload_mtu_1500": payload_sizes[1500],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("benchmarks/results/phase2-preflight"))
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    base_output = args.output / "base"
    tls_output = args.output / "tls"
    if not args.verify_only:
        _run(base_output, BASE_SCENARIOS, tls=False)
        _run(tls_output, TLS_SCENARIOS, tls=True)
    evidence = _verify(base_output, BASE_SCENARIOS) + _verify(tls_output, TLS_SCENARIOS)
    evidence.append(_verify_mtu_pair(base_output))
    manifest = {"validated": True, "requirements": evidence}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "evidence.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
