"""Executable infrastructure and observability preflight for TESTING.md Phase 2."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

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


def _verify(output: Path, scenarios: tuple[str, ...]) -> list[dict[str, object]]:
    evidence = []
    for scenario in scenarios:
        path = output / f"{scenario}.json"
        if not path.is_file():
            raise RuntimeError(f"missing preflight result: {path}")
        result = json.loads(path.read_text())
        runs = result.get("runs")
        if not isinstance(runs, list) or not runs:
            raise RuntimeError(f"{scenario}: missing measured runs")
        if not all(isinstance(run.get("resources"), dict) for run in runs):
            raise RuntimeError(f"{scenario}: missing resource evidence")
        if scenario.startswith("NETWORK-MTU-"):
            _packet_metrics(result, scenario)
        evidence.append({"scenario": scenario, "result": str(path), "validated": True})
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
