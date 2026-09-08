import hashlib
import json
import math
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

import httpx
import typer
from pydantic import BaseModel, ConfigDict

from benchmarks import dynsec_commands, policy_churn
from benchmarks.iperf3_baseline import (
    check_network_validity,
    run_baseline_with_retry,
)
from benchmarks.logging_utils import get_logger, setup_logging
from benchmarks.packet_analysis import (
    analyze_pcap,
    check_pcap_parser_available,
    format_packet_summary,
)
from benchmarks.perf_profiler import (
    PerfConfig,
    check_perf_installation,
    format_perf_summary,
    get_default_perf_scenarios,
    profile_mosquitto_container,
)
from benchmarks.rust_helpers import resolve_rust_helper as _resolve_rust_helper


def _read_tokens(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        tokens = json.load(f)
    # Backward-compatible aliases for older fixtures.
    if isinstance(tokens, dict):
        if "jwt_admin" not in tokens and "jwt" in tokens:
            tokens["jwt_admin"] = tokens["jwt"]
        if "biscuit_admin" not in tokens and "biscuit" in tokens:
            tokens["biscuit_admin"] = tokens["biscuit"]
    return tokens


logger = get_logger(__name__)
app = typer.Typer(add_completion=False)
REPO_ROOT = Path(__file__).resolve().parents[1]
RAW_BISCUIT_MARKER = "b64:"
IdentityBindingMode = Literal["off", "strict"]
SemanticClass = Literal["capability", "mixed", "parity_identity_bound"]
CredentialMode = Literal["none", "shared", "per_client", "issuer"]
ClientTopology = Literal["host", "container-single", "container-per-client"]
DEFAULT_CLIENT_TOPOLOGY: ClientTopology = "container-single"
# Disabling a connected dynamic-security client deliberately severs its socket. The
# MQTT client surfaces that broker action as either a peer close or a TCP reset,
# depending on timing and the host networking stack.
EXPECTED_DISABLE_RECEIVE_ERROR_PREFIXES = (
    "receive_failed:Mqtt state: Connection closed by peer",
    "receive_failed:Mqtt state: Mqtt serialization/deserialization error: "
    "IO: Connection reset by peer",
)
LOADGEN_CONTAINER_REPO_ROOT = "/workspace"
SYNC_BARRIER_SERVICE = "sync-barrier"
SYNC_BARRIER_CONTAINER_URL = "http://sync-barrier:8083"
SYNC_BARRIER_HOST_URL = "http://localhost:8083"
SYNC_BARRIER_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class PerClientRuntimeControl:
    username: str
    password: str
    after_messages: int
    expect_denial: bool


@dataclass
class DynamicSecurityScenarioState:
    generated_path: str | None
    broker_started: bool = False


ScenarioTokenKind = Literal["jwt", "biscuit"]


class NetemConfig(TypedDict, total=False):
    clear: bool
    mtu: int
    delay_ms: int
    loss_pct: float
    rate_kbit: int


class AuthzConfig(TypedDict, total=False):
    delay_ms: int
    fail_mode: str
    fail_rate: float
    authz_profile: str
    rules: list[dict[str, Any]]
    client_roles: dict[str, list[str]]
    jwt_identity_binding: IdentityBindingMode


AUTHZ_BASELINE_STATE: dict[str, object] = {
    "delay_ms": 0,
    "fail_mode": "none",
    "fail_rate": 0.0,
    "authz_profile": "custom",
    "rules_count": 0,
    "client_roles_count": 0,
    "jwt_identity_binding": "off",
}

AUTHZ_STATE_KEYS: tuple[str, ...] = (
    "delay_ms",
    "fail_mode",
    "fail_rate",
    "authz_profile",
    "rules_count",
    "client_roles_count",
    "jwt_identity_binding",
)

AUTHZ_PROFILE_RULE_COUNT: dict[str, int] = {
    "simple": 2,
    "med": 6,
    "complex": 10,
    "custom": 0,
}

SCENARIO_SEMANTIC_DEFAULTS: tuple[IdentityBindingMode, IdentityBindingMode, SemanticClass] = (
    "off",
    "off",
    "capability",
)

SCENARIO_SEMANTIC_RULES: dict[SemanticClass, tuple[IdentityBindingMode, IdentityBindingMode]] = {
    "capability": ("off", "off"),
    "mixed": ("strict", "off"),
    "parity_identity_bound": ("strict", "strict"),
}
MOSQUITTO_BASE_CONFIGS = frozenset(
    {
        Path("mosquitto_base.conf"),
        Path("tls/mosquitto_base.conf"),
    }
)

MIXED_SCENARIO_IDS = frozenset(
    {
        "CONTROL-ENFORCEMENT-KICK-JWT",
        "CONTROL-ENFORCEMENT-KICK-BISCUIT",
        "CONTROL-CHURN-CREATE-ROLE-JWT",
        "CONTROL-CHURN-CREATE-ROLE-BISCUIT",
        "CONTROL-CHURN-GROUP-CLIENT-JWT",
        "CONTROL-CHURN-GROUP-CLIENT-BISCUIT",
        "CONTROL-CHURN-ACL-MODIFY-JWT",
        "CONTROL-CHURN-ACL-MODIFY-BISCUIT",
        "CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-JWT",
        "CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-BISCUIT",
        "CONTROL-CHURN-NOOP-GROUP-CLIENT-JWT",
        "CONTROL-CHURN-NOOP-GROUP-CLIENT-BISCUIT",
        "SQLITE-RBAC-DEEP-CONTROL-JWT",
        "SQLITE-RBAC-DEEP-CONTROL-BISCUIT",
    }
)

HTTP_PARITY_VARIANT_SOURCES: dict[str, tuple[str, str]] = {
    "HTTP-LATENCY-200MS-PARITY": ("HTTP-LATENCY-200MS-JWT", "HTTP-LATENCY-200MS-BISCUIT"),
    "HTTP-PROFILE-SIMPLE-PARITY": ("HTTP-PROFILE-SIMPLE-JWT", "HTTP-PROFILE-SIMPLE-BISCUIT"),
    "HTTP-PROFILE-MED-PARITY": ("HTTP-PROFILE-MED-JWT", "HTTP-PROFILE-MED-BISCUIT"),
    "HTTP-PROFILE-COMPLEX-PARITY": ("HTTP-PROFILE-COMPLEX-JWT", "HTTP-PROFILE-COMPLEX-BISCUIT"),
}
STRICT_FANOUT_PARITY_POLICY_SOURCES = frozenset({"http", "hybrid"})

# Part 2 is intentionally split by effective workload axes.  Keep this inventory
# executable: RUN.md obtains the comma-separated groups from this mapping instead
# of maintaining a second, easily-stale list.
PART2_SWEEP_COHORTS: dict[str, tuple[str, ...]] = {
    "matrix": (
        "TOKEN-BASELINE-JWT",
        "TOKEN-BASELINE-BISCUIT",
        "STATIC-ACL-PUBLISH-JWT",
        "STATIC-ACL-PUBLISH-BISCUIT",
        "DYNAMIC-SECURITY-BASELINE",
        "DYNAMIC-SECURITY-CHURN",
        "HTTP-PROFILE-SIMPLE-JWT",
        "HTTP-PROFILE-SIMPLE-BISCUIT",
        "HTTP-PROFILE-COMPLEX-JWT",
        "HTTP-PROFILE-COMPLEX-BISCUIT",
        "HTTP-LATENCY-200MS-JWT",
        "HTTP-LATENCY-1000MS-JWT",
        "HYBRID-FALLBACK-AUTHZ-DOWN-JWT",
        "TOKEN-COMPLEXITY-CHAIN-5-BISCUIT",
        "TOKEN-COMPLEXITY-CHAIN-25-BISCUIT",
        "TOKEN-COMPLEXITY-DATALOG-MED-BISCUIT",
        "TOKEN-COMPLEXITY-DATALOG-HIGH-BISCUIT",
        "TOKEN-ATTENUATION-COMBINED-BISCUIT",
        "TOKEN-ATTENUATION-SUBSCRIBE-DENY-BISCUIT",
        "NETWORK-MTU-200-JWT",
        "NETWORK-MTU-1500-JWT",
        "TOKEN-THUNDERING-HERD-JWT",
        "TOKEN-THUNDERING-HERD-BISCUIT",
    ),
    "fixed_qos": ("BASELINE-NO-AUTH", "TOKEN-QOS2-JWT", "TOKEN-QOS2-BISCUIT"),
    "fixed_clients_qos": ("TOKEN-DENY-READ-JWT", "TOKEN-ATTENUATED-DENY-BISCUIT"),
    "reauth": ("TOKEN-MQTT5-REAUTH-JWT", "TOKEN-MQTT5-REAUTH-BISCUIT"),
    "issuer": ("TOKEN-ISSUER-BASELINE-JWT", "TOKEN-ISSUER-BASELINE-BISCUIT"),
}


def _validate_part2_sweep_inventory(scenarios: dict[str, ScenarioConfig]) -> None:
    seen: set[str] = set()
    for cohort, scenario_ids in PART2_SWEEP_COHORTS.items():
        for scenario_id in scenario_ids:
            if scenario_id in seen:
                raise ValueError(f"Part 2 scenario is duplicated: {scenario_id}")
            seen.add(scenario_id)
            scenario = scenarios.get(scenario_id)
            if scenario is None:
                raise ValueError(f"Part 2 {cohort} scenario is not registered: {scenario_id}")
            fixed_qos = "qos" in scenario or scenario.get("mqtt5_auth") is not None
            fixed_clients = "client_count" in scenario or "subscriber_count" in scenario
            if cohort in {"matrix", "issuer"} and (fixed_qos or fixed_clients):
                raise ValueError(f"Part 2 {cohort} scenario has a fixed sweep axis: {scenario_id}")
            if cohort == "fixed_qos" and (not fixed_qos or fixed_clients):
                raise ValueError(f"Part 2 fixed_qos scenario has the wrong shape: {scenario_id}")
            if cohort == "fixed_clients_qos" and (not fixed_qos or not fixed_clients):
                raise ValueError(
                    f"Part 2 fixed_clients_qos scenario has the wrong shape: {scenario_id}"
                )
            if cohort == "reauth" and scenario.get("mqtt5_auth") is None:
                raise ValueError(f"Part 2 reauth scenario is not MQTT5 AUTH: {scenario_id}")
            if cohort == "issuer" and scenario.get("credential_mode") != "issuer":
                raise ValueError(f"Part 2 issuer scenario is not issuer-backed: {scenario_id}")


def _coerce_fail_rate(value: object, *, context: str) -> float:
    try:
        return float(cast(float | int | str, value))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"Authz state invalid for {context}: fail_rate is not numeric ({value!r})"
        ) from exc


class BiscuitAttenuateConfig(TypedDict, total=False):
    denies: list[str]
    checks: list[str]
    ttl_seconds: int
    topic: str
    op: str


class DeliveryContract(TypedDict, total=False):
    """Required semantic contract for fan-out workloads.

    Exactly one of ``steady`` or ``phases`` is populated by registry validation.
    """

    steady: Literal["all", "none"]
    phases: list[Literal["all", "none"]]


class BiscuitDelegateHandoffConfig(TypedDict, total=False):
    topic: str
    token: str
    qos: int
    retain: bool


class BiscuitDelegateConfig(TypedDict, total=False):
    denies: list[str]
    checks: list[str]
    ttl_seconds: int
    topic: str
    op: str
    handoff: BiscuitDelegateHandoffConfig


class TokenRefreshConfig(TypedDict):
    kind: Literal["jwt", "biscuit"]
    ttl_seconds: int


class Mqtt5AuthConfig(TypedDict, total=False):
    kind: Literal["jwt", "biscuit"]
    token1: str
    token2: str
    token1_ttl_seconds: int
    token2_ttl_seconds: int
    token1_topic: str
    token2_topic: str


class ScenarioConfig(TypedDict, total=False):
    id: str
    mosquitto_conf: str
    username: str
    password: str
    topic: str
    authz_config: AuthzConfig | None
    netem: NetemConfig | None
    message_size: int
    qos: int
    qos_distribution: str
    fanout_publisher_username: str
    fanout_publisher_password: str
    traffic_pattern: str
    fanout_topic: str
    biscuit_attenuate: BiscuitAttenuateConfig
    attenuation_probe_subscribe_denied: bool
    authorization_probe_subscribe_denied: bool
    biscuit_public_key_hex: str | None
    biscuit_public_key_file: str | None
    biscuit_delegate: BiscuitDelegateConfig
    biscuit_delegate_public_key_hex: str | None
    biscuit_delegate_public_key_file: str | None
    complexity_axis: (
        Literal[
            "chain_length",
            "datalog",
            "http_profile",
            "authorizer_template",
            "publish_authz",
            "publish_authz_reconnect",
        ]
        | None
    )
    complexity_level: Literal["simple", "med", "complex", "baseline", "low", "high"] | None
    mqtt5_auth: Mqtt5AuthConfig | None
    workload_kind: Literal["mqtt5_reauth_transition"]
    authorization_probe_count: int
    restart_mosquitto: bool
    sync_connect: bool
    repeat: int
    sleep_between: int
    token_refresh: TokenRefreshConfig
    credential_freshness_required: bool
    proactive_refresh: bool
    proactive_refresh_margin_seconds: int
    proactive_refresh_timeout_seconds: int
    proactive_refresh_assert_continuity: bool
    reauth_storm: bool
    message_count: int
    dynamic_security_config: str
    dynamic_security_generated_profile: str
    dynamic_security_churn: list[str]
    fanout_churn_kind: str
    fanout_churn_after_messages: int
    fanout_churn_interval_messages: int
    fanout_churn_max_events: int
    fanout_churn_settle_ms: int
    fanout_churn_dynamic_security_source: str
    fanout_churn_control_topic: str
    fanout_churn_control_payload: dict[str, Any]
    fanout_expect_control_notification: bool
    fanout_churn_sqlite_db: str
    fanout_churn_sqlite_topic: str
    fanout_churn_sqlite_subscribers: int
    sqlite_seed_fanout: bool
    sqlite_seed_profile: str
    sqlite_seed_db: str
    sqlite_seed_topic: str
    sqlite_seed_subscribers: int
    token_issuer_no_default_roles: bool
    token_issuer_no_default_grants: bool
    biscuit_client_id_fact: str
    tls: bool
    credential_mode: CredentialMode
    password_map_profile: str
    fanout_publisher_password_map_profile: str
    # CONTROL scenario support
    control_topic: str
    control_payload: dict[str, Any]
    control_mode: bool
    control_repeat: int
    control_response_topic: str
    # Issue 36: Interleaved control message support
    control_after_messages: int
    runtime_control_username: str
    runtime_control_password: str
    runtime_control_after_messages: int
    runtime_control_expect_denial: bool
    http_expected_delay_ms: int
    hybrid_fallback_required: bool
    # Issue 19: ACL_READ fan-out subscriber count
    subscriber_count: int
    client_count: int
    # Issue 37: ACL_READ fan-out source/profile metadata
    policy_source: str
    authz_profile: str
    authorizer_profile: str
    acl_read_enforcement: Literal["expiry_only", "strict"]
    jwt_identity_binding: IdentityBindingMode
    biscuit_identity_binding: IdentityBindingMode
    semantic_class: SemanticClass
    # Result contracts.  A scenario is successful only when these expectations hold.
    delivery_contract: DeliveryContract
    allowed_error_prefixes: list[str]
    http_failure_rate: float


def _compose_bin():
    return os.environ.get("DOCKER_COMPOSE_BIN", "docker compose")


def _compose(
    args: list[str],
    extra_env: dict | None = None,
    compose_files: list[str] | None = None,
):
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    files = compose_files or ["docker/docker-compose.yml"]
    file_args: list[str] = []
    for path in files:
        file_args.extend(["-f", path])
    cmd = _compose_bin().split(" ") + file_args + args
    subprocess.check_call(cmd, cwd=REPO_ROOT, env=env)


def _compose_diagnostics(
    *,
    extra_env: dict[str, str],
    compose_files: list[str],
) -> str:
    env = os.environ.copy()
    env.update(extra_env)
    diagnostics: list[str] = []
    for label, args in (
        ("compose ps", ["ps", "-a"]),
        ("mosquitto logs", ["logs", "--no-color", "--tail", "100", "mosquitto"]),
    ):
        cmd = _compose_cmd(args, compose_files=compose_files)
        result = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
        diagnostics.append(f"{label}:\n{output or '(no output)'}")
    return "\n".join(diagnostics)


def _compose_checked(
    args: list[str],
    *,
    extra_env: dict[str, str],
    compose_files: list[str],
    phase: str,
) -> None:
    try:
        _compose(args, extra_env=extra_env, compose_files=compose_files)
    except subprocess.CalledProcessError as exc:
        diagnostics = _compose_diagnostics(
            extra_env=extra_env,
            compose_files=compose_files,
        )
        raise RuntimeError(f"{phase} failed: {exc}\n{diagnostics}") from exc


def _wait_for_tcpdump_ready(
    *,
    extra_env: dict[str, str],
    compose_files: list[str],
    timeout_seconds: float = 15.0,
) -> None:
    """Wait until tcpdump has opened its capture interface and output file."""
    env = {**os.environ, **extra_env}
    deadline = time.monotonic() + timeout_seconds
    last_output = ""
    while time.monotonic() < deadline:
        completed = subprocess.run(
            _compose_cmd(["logs", "--no-color", "tcpdump"], compose_files=compose_files),
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        last_output = "\n".join(
            part.strip() for part in (completed.stdout, completed.stderr) if part.strip()
        )
        if "tcpdump: listening on" in last_output:
            return
        time.sleep(0.1)
    raise RuntimeError(f"tcpdump did not become ready within {timeout_seconds}s: {last_output}")


def _read_effective_mtu(
    *,
    interface: str,
    extra_env: dict[str, str],
    compose_files: list[str],
    compose_project_name: str | None,
) -> int:
    cmd = _compose_cmd(
        ["exec", "-T", "netem", "cat", f"/sys/class/net/{interface}/mtu"],
        compose_files=compose_files,
        compose_project_name=compose_project_name,
    )
    completed = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env={**os.environ, **extra_env},
        capture_output=True,
        text=True,
        check=True,
    )
    try:
        return int(completed.stdout.strip())
    except ValueError as exc:
        raise RuntimeError(f"invalid effective MTU output: {completed.stdout!r}") from exc


def _compose_cmd(
    args: list[str],
    *,
    compose_files: list[str] | None = None,
    compose_project_name: str | None = None,
) -> list[str]:
    files = compose_files or ["docker/docker-compose.yml"]
    file_args: list[str] = []
    for path in files:
        file_args.extend(["-f", path])
    cmd = _compose_bin().split(" ") + file_args
    if compose_project_name:
        cmd.extend(["-p", compose_project_name])
    cmd.extend(args)
    return cmd


BENCHMARK_DIAGNOSTICS_PORT = 18_083


def _broker_diagnostic_snapshot(
    *,
    compose_files: list[str] | None,
    compose_project_name: str | None,
    extra_env: dict[str, str],
) -> dict[str, Any]:
    completed = subprocess.run(
        _compose_cmd(
            [
                "exec",
                "-T",
                "mosquitto",
                "nc",
                "-w",
                "2",
                "127.0.0.1",
                str(BENCHMARK_DIAGNOSTICS_PORT),
            ],
            compose_files=compose_files,
            compose_project_name=compose_project_name,
        ),
        cwd=REPO_ROOT,
        env={**os.environ, **extra_env},
        input="snapshot\n",
        capture_output=True,
        text=True,
        check=True,
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid broker diagnostic snapshot: {completed.stdout!r}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"invalid broker diagnostic snapshot payload: {payload!r}")
    return cast(dict[str, Any], payload)


def _counter_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {key: value - int(before.get(key, 0)) for key, value in after.items()}


def _authz_counter_delta(
    before: dict[str, int | str], after: dict[str, int | str]
) -> dict[str, int | str]:
    delta: dict[str, int | str] = {"policy_mode": str(after.get("policy_mode", ""))}
    for key in (
        "checks",
        "allows",
        "denies",
        "expired",
        "anonymous_checks",
        "anonymous_allows",
        "anonymous_denies",
    ):
        delta[key] = int(after.get(key, 0)) - int(before.get(key, 0))
    return delta


def _broker_config_attestation(
    *,
    requested_path: str,
    effective_path: str,
    compose_files: list[str],
    compose_project_name: str | None,
    extra_env: dict[str, str],
) -> dict[str, Any]:
    """Attest the exact Mosquitto configuration mounted in the running container."""
    host_path = _resolve_compose_path(effective_path)
    content = host_path.read_bytes()
    expected_sha256 = hashlib.sha256(content).hexdigest()
    completed = subprocess.run(
        _compose_cmd(
            ["exec", "-T", "mosquitto", "sha256sum", "/mosquitto/config/mosquitto.conf"],
            compose_files=compose_files,
            compose_project_name=compose_project_name,
        ),
        cwd=REPO_ROOT,
        env={**os.environ, **extra_env},
        capture_output=True,
        text=True,
        check=True,
    )
    observed_sha256 = completed.stdout.split(maxsplit=1)[0].strip()
    if observed_sha256 != expected_sha256:
        raise RuntimeError(
            "running Mosquitto configuration hash does not match the requested fixture: "
            f"expected={expected_sha256} observed={observed_sha256}"
        )
    text = content.decode("utf-8")
    directives: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        directives.setdefault(key, []).append(value.strip())
    policy_values = directives.get("plugin_opt_policy_mode", [])
    return {
        "validated": True,
        "requested_path": requested_path,
        "effective_path": effective_path,
        "expected_sha256": expected_sha256,
        "container_sha256": observed_sha256,
        "listeners": directives.get("listener", []),
        "plugin_enabled": bool(directives.get("plugin")),
        "policy_mode": policy_values[-1] if policy_values else "none",
        "acl_read_full_authz": (directives.get("plugin_opt_acl_read_full_authz", ["false"])[-1]),
        "allow_anonymous_no_token": (
            directives.get("plugin_opt_allow_anonymous_no_token", ["false"])[-1] == "true"
        ),
        "benchmark_diagnostics": (
            directives.get("plugin_opt_benchmark_diagnostics", ["false"])[-1] == "true"
        ),
        "benchmark_diagnostics_transport": "loopback_tcp_snapshot",
        "benchmark_diagnostics_port": BENCHMARK_DIAGNOSTICS_PORT,
    }


def _compose_service_container_id(
    service: str,
    *,
    compose_files: list[str] | None = None,
    compose_project_name: str | None = None,
) -> str:
    files = compose_files or ["docker/docker-compose.yml"]
    file_args: list[str] = []
    for path in files:
        file_args.extend(["-f", path])

    cmd = _compose_bin().split(" ") + file_args
    if compose_project_name:
        cmd.extend(["-p", compose_project_name])
    cmd.extend(["ps", "--status", "running", "-q", service])
    try:
        result = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to resolve running container for compose service {service!r} "
            f"in project {compose_project_name or '<default>'!r}"
        ) from exc

    container_ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(container_ids) == 0:
        raise RuntimeError(
            f"No running container found for compose service {service!r} "
            f"in project {compose_project_name or '<default>'!r}"
        )
    if len(container_ids) > 1:
        raise RuntimeError(
            f"Multiple running containers found for compose service {service!r} "
            f"in project {compose_project_name or '<default>'!r}: {container_ids}"
        )
    return container_ids[0][:12]


def _http_client(ca_file: str | None, insecure: bool) -> httpx.Client:
    verify: bool | str = True
    if insecure:
        verify = False
    elif ca_file:
        verify = ca_file
    transport = httpx.HTTPTransport(http1=False, http2=True, verify=verify)
    return httpx.Client(timeout=5.0, transport=transport)


def _mark_biscuit_cli_token(tokens: dict[str, Any], token: str | None) -> str | None:
    if token is None:
        return None
    biscuit_values = {
        value
        for key, value in tokens.items()
        if key.startswith("biscuit") and key != "biscuit_root_key_hex" and isinstance(value, str)
    }
    if token in biscuit_values:
        return f"{RAW_BISCUIT_MARKER}{token}"
    return token


def _mark_mqtt5_auth_token(token: str) -> str:
    # JWT stays UTF-8 text on MQTT AUTH. Biscuit uses raw bytes and is carried
    # through the CLI as Base64URL with an explicit marker.
    if token.startswith("eyJ") and token.count(".") == 2:
        return token
    return f"{RAW_BISCUIT_MARKER}{token}"


def _coerce_output_dir_arg(path: object, default: str) -> str:
    if isinstance(path, (str, os.PathLike)):
        return os.fspath(path)
    return default


def _coerce_bool_arg(value: object, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _normalize_tcpdump_output_dir(path: str | os.PathLike[str]) -> str:
    return str(_resolve_repo_path(os.fspath(path)).resolve())


def _issue_token(
    token_issuer_base: str,
    endpoint: str,
    payload: dict[str, Any],
    *,
    ca_file: str | None,
    insecure: bool,
) -> str:
    with _http_client(ca_file, insecure) as client:
        response = client.post(f"{token_issuer_base}{endpoint}", json=payload)
        response.raise_for_status()
    token = response.json().get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"token issuer returned invalid token payload for {endpoint}")
    return token


def _issue_mqtt5_auth_tokens(
    scenario_id: str,
    token_kind: ScenarioTokenKind,
    token_issuer_base: str,
    *,
    token1_ttl_seconds: int,
    token2_ttl_seconds: int,
    ca_file: str | None,
    insecure: bool,
) -> tuple[str, str, dict[str, Any]]:
    client_id = f"mqtt5-auth-{scenario_id.lower()}-{uuid.uuid4().hex[:12]}"
    token1_topic = f"sensors/{client_id}/before"
    token2_topic = f"sensors/{client_id}/after"

    if token_kind == "jwt":

        def jwt_payload(ttl_seconds: int, topic: str) -> dict[str, Any]:
            return {
                "client_id": client_id,
                "ttl_seconds": ttl_seconds,
                "grants": [
                    {"op": "publish", "res": topic},
                    {"op": "subscribe", "res": topic},
                ],
                "no_default_roles": True,
                "no_default_grants": True,
            }

        token1 = _issue_token(
            token_issuer_base,
            "/jwt",
            jwt_payload(token1_ttl_seconds, token1_topic),
            ca_file=ca_file,
            insecure=insecure,
        )
        token2 = _issue_token(
            token_issuer_base,
            "/jwt",
            jwt_payload(token2_ttl_seconds, token2_topic),
            ca_file=ca_file,
            insecure=insecure,
        )
        return (
            token1,
            token2,
            {
                "source": "issuer",
                "token_kind": token_kind,
                "client_id": client_id,
                "token1_ttl_seconds": token1_ttl_seconds,
                "token2_ttl_seconds": token2_ttl_seconds,
                "token1_topic": token1_topic,
                "token2_topic": token2_topic,
            },
        )

    def biscuit_payload(ttl_seconds: int, topic: str) -> dict[str, Any]:
        return {
            "client_id": client_id,
            "topic": topic,
            "ttl_seconds": ttl_seconds,
        }

    token1 = _issue_token(
        token_issuer_base,
        "/biscuit",
        biscuit_payload(token1_ttl_seconds, token1_topic),
        ca_file=ca_file,
        insecure=insecure,
    )
    token2 = _issue_token(
        token_issuer_base,
        "/biscuit",
        biscuit_payload(token2_ttl_seconds, token2_topic),
        ca_file=ca_file,
        insecure=insecure,
    )
    return (
        token1,
        token2,
        {
            "source": "issuer",
            "token_kind": token_kind,
            "client_id": client_id,
            "token1_ttl_seconds": token1_ttl_seconds,
            "token2_ttl_seconds": token2_ttl_seconds,
            "token1_topic": token1_topic,
            "token2_topic": token2_topic,
        },
    )


def _resolve_mqtt5_auth_tokens(
    scenario_id: str,
    scenario: ScenarioConfig,
    token_issuer_base: str,
    *,
    ca_file: str | None,
    insecure: bool,
) -> tuple[str, str, dict[str, Any]]:
    mqtt5_cfg = scenario.get("mqtt5_auth")
    if mqtt5_cfg is None:
        raise RuntimeError(f"{scenario_id}: mqtt5 auth configuration missing")

    token1 = mqtt5_cfg.get("token1")
    token2 = mqtt5_cfg.get("token2")
    if token1 and token2:
        token1_topic = str(mqtt5_cfg.get("token1_topic") or "mqtt5/auth/before")
        token2_topic = str(mqtt5_cfg.get("token2_topic") or "mqtt5/auth/after")
        return (
            token1,
            token2,
            {
                "source": "static",
                "token_kind": mqtt5_cfg.get("kind"),
                "client_id": "client_auth",
                "token1_ttl_seconds": int(mqtt5_cfg.get("token1_ttl_seconds", 0)),
                "token2_ttl_seconds": int(mqtt5_cfg.get("token2_ttl_seconds", 0)),
                "token1_topic": token1_topic,
                "token2_topic": token2_topic,
            },
        )

    token_kind = cast(ScenarioTokenKind | None, mqtt5_cfg.get("kind")) or _scenario_token_kind(
        scenario_id, scenario
    )
    if token_kind is None:
        raise RuntimeError(f"{scenario_id}: mqtt5 auth token kind is not configured")

    return _issue_mqtt5_auth_tokens(
        scenario_id,
        token_kind,
        token_issuer_base,
        token1_ttl_seconds=int(mqtt5_cfg.get("token1_ttl_seconds", 180)),
        token2_ttl_seconds=int(mqtt5_cfg.get("token2_ttl_seconds", 300)),
        ca_file=ca_file,
        insecure=insecure,
    )


def _container_repo_path(path: str | None) -> str | None:
    if path is None:
        return None
    resolved = _resolve_repo_path(path)
    try:
        relative = resolved.relative_to(REPO_ROOT)
    except ValueError:
        return path
    return f"{LOADGEN_CONTAINER_REPO_ROOT}/{relative.as_posix()}"


def _sanitize_container_name(value: str) -> str:
    sanitized = "".join(ch.lower() if ch.isalnum() else "_" for ch in value)
    return "_".join(part for part in sanitized.split("_") if part)[:120] or "loadgen"


def _effective_compose_project_name(
    compose_project_name: str | None,
    compose_files: list[str] | None,
) -> str:
    if compose_project_name:
        return compose_project_name
    env_project = os.environ.get("COMPOSE_PROJECT_NAME")
    if env_project:
        return env_project
    first_file = Path((compose_files or ["docker/docker-compose.yml"])[0])
    if not first_file.is_absolute():
        first_file = REPO_ROOT / first_file
    return first_file.parent.name or REPO_ROOT.name


def _loadgen_container_name(
    *,
    compose_project_name: str | None,
    compose_files: list[str] | None,
    scenario_id: str,
    run_index: int,
    client_index: int | None = None,
) -> str:
    project = _effective_compose_project_name(compose_project_name, compose_files)
    name = f"loadgen_{project}_{scenario_id}_{run_index + 1}"
    if client_index is not None:
        name = f"{name}_client_{client_index + 1}"
    return _sanitize_container_name(name)


def _authz_config(
    authz_url: str,
    delay_ms: int | None = None,
    fail_mode: str | None = None,
    fail_rate: float | None = None,
    authz_profile: str | None = None,
    rules: list[dict[str, Any]] | None = None,
    client_roles: dict[str, list[str]] | None = None,
    jwt_identity_binding: str | None = None,
    ca_file: str | None = None,
    insecure: bool = False,
):
    body: dict[str, object] = {}
    if delay_ms is not None:
        body["delay_ms"] = delay_ms
    if fail_mode is not None:
        body["fail_mode"] = fail_mode
    if fail_rate is not None:
        body["fail_rate"] = fail_rate
    if authz_profile is not None:
        body["authz_profile"] = authz_profile
    if rules is not None:
        body["rules"] = rules
    if client_roles is not None:
        body["client_roles"] = client_roles
    if jwt_identity_binding is not None:
        body["jwt_identity_binding"] = jwt_identity_binding

    with _http_client(ca_file, insecure) as client:
        resp = client.post(
            authz_url.rstrip("/") + "/config",
            json=body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()


def _authz_reset(authz_url: str, ca_file: str | None = None, insecure: bool = False):
    with _http_client(ca_file, insecure) as client:
        resp = client.post(
            authz_url.rstrip("/") + "/config/reset",
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json()


def _authz_stats(
    authz_url: str,
    *,
    reset: bool = False,
    ca_file: str | None = None,
    insecure: bool = False,
) -> dict[str, Any]:
    with _http_client(ca_file, insecure) as client:
        url = authz_url.rstrip("/") + ("/stats/reset" if reset else "/stats")
        resp = client.post(url) if reset else client.get(url)
        resp.raise_for_status()
        payload = resp.json()
    stats: dict[str, Any] = {
        key: int(payload.get(key) or 0)
        for key in (
            "requests",
            "injected_failures",
            "policy_allows",
            "policy_denies",
            "rules_examined",
        )
    }
    profile_requests = payload.get("profile_requests")
    stats["profile_requests"] = (
        {key: int(profile_requests.get(key) or 0) for key in ("simple", "med", "complex", "custom")}
        if isinstance(profile_requests, dict)
        else {}
    )
    stats["configured_delay_ms"] = int(payload.get("configured_delay_ms") or 0)
    stats["configured_fail_mode"] = str(payload.get("configured_fail_mode") or "none")
    stats["configured_fail_rate"] = float(payload.get("configured_fail_rate") or 0.0)
    stats["configured_profile"] = str(payload.get("configured_profile") or "custom")
    return stats


def _validated_authz_state_baseline(
    scenario_id: str,
    step: str,
    observed: dict[str, Any],
) -> dict[str, object]:
    missing = [key for key in AUTHZ_STATE_KEYS if key not in observed]
    if missing:
        raise RuntimeError(
            f"Authz state missing keys after {step} in scenario {scenario_id}: {missing}"
        )

    baseline: dict[str, object] = {}
    for key in AUTHZ_STATE_KEYS:
        value = observed[key]
        if key == "fail_rate":
            try:
                baseline[key] = float(value)
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"Authz state invalid after {step} in scenario {scenario_id}: "
                    f"fail_rate is not numeric ({value!r})"
                ) from exc
            continue
        baseline[key] = value
    return baseline


def _expected_authz_state(
    cfg: AuthzConfig | None,
    baseline_state: dict[str, Any],
) -> dict[str, Any]:
    expected = dict(baseline_state)
    expected["fail_rate"] = _coerce_fail_rate(
        expected.get("fail_rate"),
        context="expected baseline",
    )
    if cfg is None:
        return expected
    if "delay_ms" in cfg:
        expected["delay_ms"] = cfg["delay_ms"]
    if "fail_mode" in cfg:
        expected["fail_mode"] = cfg["fail_mode"]
    if "fail_rate" in cfg:
        expected["fail_rate"] = cfg["fail_rate"]
    if "authz_profile" in cfg:
        expected["authz_profile"] = cfg["authz_profile"]
    if "jwt_identity_binding" in cfg:
        expected["jwt_identity_binding"] = cfg["jwt_identity_binding"]
    profile = cast(str, expected["authz_profile"])
    expected["rules_count"] = AUTHZ_PROFILE_RULE_COUNT.get(profile, 0) + len(cfg.get("rules", []))
    expected["client_roles_count"] = len(cfg.get("client_roles", {}))
    return expected


def _assert_authz_state(
    scenario_id: str,
    step: str,
    observed: dict[str, Any],
    expected: dict[str, object],
):
    mismatches: dict[str, dict[str, object]] = {}
    for key in AUTHZ_STATE_KEYS:
        actual = observed.get(key)
        want = expected[key]
        if key == "fail_rate":
            try:
                actual_fail_rate = _coerce_fail_rate(
                    actual,
                    context=f"{step} in scenario {scenario_id}",
                )
                want_fail_rate = _coerce_fail_rate(
                    want,
                    context=f"expected value for {step} in scenario {scenario_id}",
                )
            except RuntimeError:
                mismatches[key] = {"expected": want, "observed": actual}
                continue
            if actual_fail_rate != want_fail_rate:
                mismatches[key] = {"expected": want, "observed": actual}
        elif actual != want:
            mismatches[key] = {"expected": want, "observed": actual}
    if mismatches:
        raise RuntimeError(
            f"Authz state mismatch after {step} in scenario {scenario_id}: "
            f"{json.dumps(mismatches, sort_keys=True)}"
        )


# Prometheus query templates
CURRENT_DOCKER_COMPOSE_CPU_QUERY = (
    "sum(rate(container_cpu_usage_seconds_total{"
    'container_label_com_docker_compose_service="mosquitto"'
    "}[30s]))"
)
CURRENT_DOCKER_COMPOSE_MEM_QUERY = (
    "max(container_memory_working_set_bytes{"
    'container_label_com_docker_compose_service="mosquitto"'
    "})"
)


def _prom_query(base_url: str, query: str, ca_file: str | None, insecure: bool):
    verify: bool | str = True
    if insecure:
        verify = False
    elif ca_file:
        verify = ca_file
    with httpx.Client(verify=verify, timeout=5.0) as client:
        resp = client.get(
            base_url.rstrip("/") + "/api/v1/query",
            params={"query": query},
        )
        resp.raise_for_status()
        return resp.json()


def _prom_range_query(
    base_url: str,
    query: str,
    start: float,
    end: float,
    ca_file: str | None,
    insecure: bool,
) -> dict[str, Any]:
    verify: bool | str = True
    if insecure:
        verify = False
    elif ca_file:
        verify = ca_file
    with httpx.Client(verify=verify, timeout=10.0) as client:
        resp = client.get(
            base_url.rstrip("/") + "/api/v1/query_range",
            # Prometheus accepts sub-second query_range steps as numeric seconds;
            # duration strings only support integer units in the v1 API parser.
            params={"query": query, "start": start, "end": end, "step": "0.25"},
        )
        resp.raise_for_status()
        payload = resp.json()
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus range query failed: {payload}")
    return cast(dict[str, Any], payload)


def _range_values(payload: dict[str, Any], metric: str) -> list[tuple[float, float]]:
    data = payload.get("data")
    results = data.get("result") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != 1:
        raise RuntimeError(f"{metric}: expected exactly one Prometheus range series")
    values = results[0].get("values") if isinstance(results[0], dict) else None
    if not isinstance(values, list):
        raise RuntimeError(f"{metric}: Prometheus range samples missing")
    parsed: list[tuple[float, float]] = []
    for sample in values:
        if not isinstance(sample, list) or len(sample) != 2:
            raise RuntimeError(f"{metric}: invalid Prometheus range sample")
        parsed.append((float(sample[0]), float(sample[1])))
    return parsed


def _range_values_with_scrape_timestamps(
    values_payload: dict[str, Any],
    timestamps_payload: dict[str, Any],
    metric: str,
) -> list[tuple[float, float, float]]:
    """Return unique (scrape timestamp, value, evaluation timestamp) samples."""
    values = _range_values(values_payload, metric)
    timestamps = _range_values(timestamps_payload, f"{metric} scrape timestamps")
    timestamps_by_evaluation = dict(timestamps)
    if len(timestamps_by_evaluation) != len(timestamps) or {
        evaluation for evaluation, _value in values
    } != set(timestamps_by_evaluation):
        raise RuntimeError(f"{metric}: Prometheus value/timestamp evaluations do not align")

    unique: list[tuple[float, float, float]] = []
    values_by_scrape: dict[float, float] = {}
    for evaluation_timestamp, value in values:
        scrape_timestamp = timestamps_by_evaluation[evaluation_timestamp]
        previous = values_by_scrape.get(scrape_timestamp)
        if previous is not None:
            if previous != value:
                raise RuntimeError(
                    f"{metric}: values changed without a new Prometheus source sample"
                )
            continue
        values_by_scrape[scrape_timestamp] = value
        unique.append((scrape_timestamp, value, evaluation_timestamp))
    return unique


def _instant_vector_value(payload: dict[str, Any], metric: str) -> float:
    data = payload.get("data")
    results = data.get("result") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != 1:
        raise RuntimeError(f"{metric}: expected exactly one Prometheus instant series")
    value = results[0].get("value") if isinstance(results[0], dict) else None
    if not isinstance(value, list) or len(value) != 2:
        raise RuntimeError(f"{metric}: Prometheus instant value missing")
    return float(value[1])


def _wait_for_prometheus_samples_after(
    base_url: str,
    selectors: dict[str, str],
    timestamp: float,
    ca_file: str | None,
    insecure: bool,
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, float]:
    """Wait until every selector has a source sample at or after ``timestamp``."""
    deadline = time.monotonic() + timeout_seconds
    observed: dict[str, float] = {}
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            observed = {
                metric: _instant_vector_value(
                    _prom_query(base_url, f"max(timestamp({selector}))", ca_file, insecure),
                    f"{metric} scrape timestamp",
                )
                for metric, selector in selectors.items()
            }
            if all(sampled_at >= timestamp for sampled_at in observed.values()):
                return observed
            last_error = None
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.25)
    detail = f"last source timestamps={observed}"
    if last_error is not None:
        detail = f"last error={last_error!r}"
    raise RuntimeError(
        f"timed out waiting for Prometheus source samples at or after {timestamp}: {detail}"
    )


def _aligned_prometheus_query_end(query_start: float, minimum_end: float) -> float:
    """Return the first 250 ms range evaluation at or after ``minimum_end``."""
    step_seconds = 0.25
    steps = max(0, math.ceil((minimum_end - query_start) / step_seconds))
    return query_start + steps * step_seconds


def _python_subprocess_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    repo_pythonpath = str(REPO_ROOT)
    current_pythonpath = env.get("PYTHONPATH")
    if current_pythonpath:
        paths = current_pythonpath.split(os.pathsep)
        if repo_pythonpath not in paths:
            env["PYTHONPATH"] = os.pathsep.join([repo_pythonpath, current_pythonpath])
    else:
        env["PYTHONPATH"] = repo_pythonpath
    if extra_env:
        env.update(extra_env)
    return env


def _health_check(name: str, base_url: str, ca_file: str | None, insecure: bool) -> None:
    with _http_client(ca_file, insecure) as client:
        resp = client.get(base_url.rstrip("/") + "/health")
        resp.raise_for_status()
        payload = resp.json()
    if not payload.get("ok"):
        raise RuntimeError(f"{name} health check failed: {payload}")


def _wait_for_service_health(
    name: str,
    base_url: str,
    ca_file: str | None,
    insecure: bool,
    *,
    timeout_seconds: float = 60.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _health_check(name, base_url, ca_file, insecure)
            return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(1.0)
    raise RuntimeError(
        f"timed out waiting for {name} health endpoint at {base_url.rstrip('/')}/health: "
        f"{last_error!r}"
    )


def _wait_for_prometheus_api(
    base_url: str,
    ca_file: str | None,
    insecure: bool,
    *,
    timeout_seconds: float = 60.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            result = _prom_query(base_url, "up", ca_file, insecure)
            if result.get("status") == "success":
                return
            last_error = RuntimeError(
                f"unexpected Prometheus status {result.get('status')!r} for query API readiness"
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(1.0)
    raise RuntimeError(
        f"timed out waiting for Prometheus query API at {base_url.rstrip('/')}/api/v1/query: "
        f"{last_error!r}"
    )


def _resource_snapshot(
    base_url: str,
    ca_file: str | None,
    insecure: bool,
    cpu_query_type: str = "instant",
    *,
    compose_files: list[str] | None = None,
    compose_project_name: str | None = None,
):
    """
    Capture resource snapshot from Prometheus.

    Args:
        base_url: Prometheus base URL
        ca_file: TLS CA file path
        insecure: Skip TLS verification
        cpu_query_type: "instant" for immediate values, "rate" for rate over time
    """
    # Get mosquitto container ID for the active compose project.
    container_id = _compose_service_container_id(
        "mosquitto",
        compose_files=compose_files,
        compose_project_name=compose_project_name,
    )

    # Use container ID-based queries instead of Docker Compose labels
    if cpu_query_type == "rate":
        cpu_q = f'sum(rate(container_cpu_usage_seconds_total{{id=~".*{container_id}.*"}}[30s]))'
    else:  # instant (default)
        cpu_q = f'container_cpu_usage_seconds_total{{id=~".*{container_id}.*"}}'

    mem_q = f'max(container_memory_working_set_bytes{{id=~".*{container_id}.*"}})'

    snap = {
        "prometheus": {
            "cpu": _prom_query(base_url, cpu_q, ca_file, insecure),
            "memory": _prom_query(base_url, mem_q, ca_file, insecure),
        }
    }
    return snap


def _validate_resource_snapshot(
    snapshot: dict[str, Any],
    *,
    scenario_id: str,
    run_index: int,
) -> None:
    issues: list[str] = []
    prom = snapshot.get("prometheus")
    if not isinstance(prom, dict):
        raise RuntimeError(
            f"Resource snapshot validation failed for scenario {scenario_id} run {run_index + 1}: "
            "missing prometheus payload"
        )

    for metric in ("cpu", "memory"):
        metric_payload = prom.get(metric)
        if not isinstance(metric_payload, dict):
            issues.append(f"{metric}: missing metric payload")
            continue

        if metric_payload.get("status") != "success":
            issues.append(f"{metric}: status={metric_payload.get('status')!r}")
            continue

        data = metric_payload.get("data")
        if not isinstance(data, dict):
            issues.append(f"{metric}: missing data payload")
            continue

        result = data.get("result")
        if not isinstance(result, list):
            issues.append(f"{metric}: result is not a list")
        elif not result:
            issues.append(f"{metric}: result vector is empty")

    if issues:
        raise RuntimeError(
            f"Resource snapshot validation failed for scenario {scenario_id} run {run_index + 1}: "
            + "; ".join(issues)
        )


def _resource_interval(
    base_url: str,
    ca_file: str | None,
    insecure: bool,
    *,
    workload_started_at: float,
    workload_finished_at: float,
    compose_files: list[str] | None = None,
    compose_project_name: str | None = None,
) -> dict[str, Any]:
    container_id = _compose_service_container_id(
        "mosquitto",
        compose_files=compose_files,
        compose_project_name=compose_project_name,
    )
    cpu_selector = f'container_cpu_usage_seconds_total{{id=~".*{container_id}.*"}}'
    memory_selector = f'container_memory_working_set_bytes{{id=~".*{container_id}.*"}}'
    observed_scrapes = _wait_for_prometheus_samples_after(
        base_url,
        {"cpu": cpu_selector, "memory": memory_selector},
        workload_finished_at,
        ca_file,
        insecure,
    )
    query_start = workload_started_at - 2.0
    query_end = _aligned_prometheus_query_end(
        query_start,
        max(time.time(), *observed_scrapes.values()),
    )
    cpu_payload = _prom_range_query(
        base_url,
        f"sum({cpu_selector})",
        query_start,
        query_end,
        ca_file,
        insecure,
    )
    cpu_timestamps_payload = _prom_range_query(
        base_url,
        f"max(timestamp({cpu_selector}))",
        query_start,
        query_end,
        ca_file,
        insecure,
    )
    memory_payload = _prom_range_query(
        base_url,
        f"max({memory_selector})",
        query_start,
        query_end,
        ca_file,
        insecure,
    )
    memory_timestamps_payload = _prom_range_query(
        base_url,
        f"max(timestamp({memory_selector}))",
        query_start,
        query_end,
        ca_file,
        insecure,
    )
    cpu_samples = _range_values_with_scrape_timestamps(cpu_payload, cpu_timestamps_payload, "cpu")
    memory_samples = _range_values_with_scrape_timestamps(
        memory_payload, memory_timestamps_payload, "memory"
    )
    cpu_before = [sample for sample in cpu_samples if sample[0] <= workload_started_at]
    cpu_after = [sample for sample in cpu_samples if sample[0] >= workload_finished_at]
    memory_covered = [
        sample
        for sample in memory_samples
        if (cpu_before[-1][0] if cpu_before else workload_started_at)
        <= sample[0]
        <= (cpu_after[0][0] if cpu_after else workload_finished_at)
    ]
    if not cpu_before or not cpu_after or not memory_covered:
        return {
            "available": False,
            "reason": "workload_interval_not_bracketed_by_prometheus_samples",
            "workload_interval": {
                "started_at": workload_started_at,
                "finished_at": workload_finished_at,
            },
            "sample_counts": {"cpu": len(cpu_samples), "memory": len(memory_samples)},
        }
    start_sample = cpu_before[-1]
    end_sample = cpu_after[0]
    cpu_delta = end_sample[1] - start_sample[1]
    memory_values = [sample[1] for sample in memory_covered]
    return {
        "available": True,
        "collection": "prometheus_range",
        "workload_interval": {
            "started_at": workload_started_at,
            "finished_at": workload_finished_at,
        },
        "sampled_interval": {"started_at": start_sample[0], "finished_at": end_sample[0]},
        "coverage": {
            "before_start_seconds": workload_started_at - start_sample[0],
            "after_finish_seconds": end_sample[0] - workload_finished_at,
        },
        "cpu_usage_seconds": cpu_delta,
        "memory_working_set_bytes": {
            "min": min(memory_values),
            "max": max(memory_values),
            "mean": sum(memory_values) / len(memory_values),
            "samples": len(memory_values),
        },
        "raw_samples": {
            "cpu": [
                {
                    "scraped_at": scrape_timestamp,
                    "evaluated_at": evaluation_timestamp,
                    "value": value,
                }
                for scrape_timestamp, value, evaluation_timestamp in cpu_samples
            ],
            "memory": [
                {
                    "scraped_at": scrape_timestamp,
                    "evaluated_at": evaluation_timestamp,
                    "value": value,
                }
                for scrape_timestamp, value, evaluation_timestamp in memory_samples
            ],
        },
    }


def _validate_resource_interval(
    resource: dict[str, Any], *, scenario_id: str, run_index: int
) -> None:
    if resource.get("available") is not True:
        raise RuntimeError(
            f"Resource interval validation failed for {scenario_id} run {run_index + 1}: "
            f"{resource.get('reason') or 'interval evidence unavailable'}"
        )
    cpu = resource.get("cpu_usage_seconds")
    memory = resource.get("memory_working_set_bytes")
    workload_interval = resource.get("workload_interval")
    sampled_interval = resource.get("sampled_interval")
    interval_bounds: tuple[float, float, float, float] | None = None
    if isinstance(workload_interval, dict) and isinstance(sampled_interval, dict):
        try:
            interval_bounds = (
                float(sampled_interval["started_at"]),
                float(workload_interval["started_at"]),
                float(workload_interval["finished_at"]),
                float(sampled_interval["finished_at"]),
            )
        except KeyError, TypeError, ValueError:
            interval_bounds = None
    if (
        isinstance(cpu, bool)
        or not isinstance(cpu, int | float)
        or not math.isfinite(float(cpu))
        or float(cpu) < 0
        or interval_bounds is None
        or not all(math.isfinite(bound) for bound in interval_bounds)
        or interval_bounds != tuple(sorted(interval_bounds))
        or not isinstance(memory, dict)
        or int(memory.get("samples") or 0) <= 0
        or float(memory.get("min") or 0) <= 0
        or float(memory.get("min") or 0) > float(memory.get("mean") or 0)
        or float(memory.get("mean") or 0) > float(memory.get("max") or 0)
    ):
        raise RuntimeError(
            f"Resource interval validation failed for {scenario_id} run {run_index + 1}: {resource}"
        )


def _wait_for_non_empty_resource_snapshot(
    base_url: str,
    ca_file: str | None,
    insecure: bool,
    *,
    compose_files: list[str] | None = None,
    compose_project_name: str | None = None,
    timeout_seconds: float = 45.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            snap = _resource_snapshot(
                base_url,
                ca_file,
                insecure,
                compose_files=compose_files,
                compose_project_name=compose_project_name,
            )
            _validate_resource_snapshot(
                snap,
                scenario_id="STARTUP-READINESS",
                run_index=0,
            )
            return snap
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            time.sleep(2.0)
    raise RuntimeError(
        f"timed out waiting for non-empty Prometheus vectors for mosquitto: {last_error!r}"
    )


def _run_loadgen(
    tokens: dict,
    host: str,
    port: int,
    username: str,
    password: str,
    fanout_publisher_username: str | None,
    fanout_publisher_password: str | None,
    clients: int,
    messages: int,
    topic: str,
    mode: str | None,
    fanout_topic: str | None,
    qos: int,
    qos_distribution: str | None,
    message_size: int,
    sync_connect: bool,
    token_issuer_url: str | None,
    token_issuer_kind: str | None,
    token_issuer_ttl: int | None,
    token_issuer_no_default_roles: bool,
    token_issuer_no_default_grants: bool,
    token_refresh_codes: str | None,
    proactive_refresh: bool,
    proactive_refresh_margin_seconds: int | None,
    proactive_refresh_timeout_seconds: int | None,
    proactive_refresh_assert_continuity: bool,
    reauth_storm: bool,
    jwt_identity_binding: IdentityBindingMode,
    biscuit_identity_binding: IdentityBindingMode,
    biscuit_client_id_fact: str,
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
    biscuit_attenuate: bool,
    biscuit_attenuate_denies: list[str] | None,
    biscuit_attenuate_checks: list[str] | None,
    biscuit_attenuate_topic: str | None,
    biscuit_attenuate_op: str | None,
    biscuit_attenuate_ttl: int | None,
    biscuit_public_key_hex: str | None,
    biscuit_public_key_file: str | None,
    biscuit_delegate: bool,
    biscuit_delegate_denies: list[str] | None,
    biscuit_delegate_checks: list[str] | None,
    biscuit_delegate_topic: str | None,
    biscuit_delegate_op: str | None,
    biscuit_delegate_ttl: int | None,
    biscuit_delegate_public_key_hex: str | None,
    biscuit_delegate_public_key_file: str | None,
    biscuit_delegate_handoff: bool,
    biscuit_delegate_handoff_topic: str | None,
    biscuit_delegate_handoff_token: str | None,
    biscuit_delegate_handoff_qos: int | None,
    biscuit_delegate_handoff_retain: bool | None,
    biscuit_delegate_handoff_ready_timeout_seconds: int | None,
    attenuation_probe_subscribe_denied: bool = False,
    http_failure_rate: float | None = None,
    password_map_path: str | None = None,
    password_map_profile: str | None = None,
    fanout_publisher_password_map_profile: str | None = None,
    # CONTROL message parameters
    control_topic: str | None = None,
    control_payload: dict[str, Any] | None = None,
    control_mode: bool = False,
    control_after_messages: int = 0,
    control_repeat: int = 1,
    control_response_topic: str | None = None,
    runtime_control_username: str | None = None,
    runtime_control_password: str | None = None,
    runtime_control_after_messages: int = 0,
    runtime_control_expect_denial: bool = False,
    fanout_churn_kind: str | None = None,
    fanout_churn_after_messages: int = 0,
    fanout_churn_interval_messages: int = 0,
    fanout_churn_max_events: int = 1,
    fanout_churn_settle_ms: int = 0,
    fanout_churn_phase_delivery: list[Literal["all", "none"]] | None = None,
    fanout_churn_dynamic_security_source: str | None = None,
    fanout_churn_control_topic: str | None = None,
    fanout_churn_control_payload: dict[str, Any] | None = None,
    fanout_expect_control_notification: bool = False,
    fanout_churn_sqlite_db: str | None = None,
    fanout_churn_sqlite_topic: str | None = None,
    fanout_churn_sqlite_subscribers: int | None = None,
    client_topology: ClientTopology = "host",
    compose_files: list[str] | None = None,
    compose_project_name: str | None = None,
    compose_env: dict[str, str] | None = None,
    loadgen_service: str = "loadgen",
    loadgen_cpus: str = "1.0",
    loadgen_memory: str = "512m",
    loadgen_cpuset: str | None = None,
    scenario_id: str = "scenario",
    run_index: int = 0,
):
    helper_cmd = _resolve_rust_helper("mqtt-loadgen")
    cmd = [
        *helper_cmd,
        "--host",
        host,
        "--port",
        str(port),
        "--username",
        username,
        "--password",
        _mark_biscuit_cli_token(tokens, password) or "",
        "--clients",
        str(clients),
        "--messages",
        str(messages),
        "--topic",
        topic,
        "--qos",
        str(qos),
        "--message-size",
        str(message_size),
        "--json",
    ]
    if qos_distribution:
        cmd.extend(["--qos-distribution", qos_distribution])
    if http_failure_rate is not None:
        cmd.append("--continue-after-publish-failure")
    if sync_connect:
        cmd.append("--sync-connect")
    if mode:
        cmd.extend(["--mode", mode])
    if fanout_topic:
        cmd.extend(["--fanout-topic", fanout_topic])
    if fanout_publisher_username:
        cmd.extend(["--fanout-publisher-username", fanout_publisher_username])
    if fanout_publisher_password:
        cmd.extend(
            [
                "--fanout-publisher-password",
                _mark_biscuit_cli_token(tokens, fanout_publisher_password) or "",
            ]
        )
    if token_issuer_url:
        cmd.extend(["--token-issuer-url", token_issuer_url])
    if token_issuer_kind:
        cmd.extend(["--token-issuer-kind", token_issuer_kind])
    if token_issuer_ttl is not None:
        cmd.extend(["--token-issuer-ttl", str(token_issuer_ttl)])
    if token_issuer_no_default_roles:
        cmd.append("--token-issuer-no-default-roles")
    if token_issuer_no_default_grants:
        cmd.append("--token-issuer-no-default-grants")
    if password_map_path:
        cmd.extend(["--password-map", password_map_path])
    if password_map_profile:
        cmd.extend(["--password-map-profile", password_map_profile])
    if fanout_publisher_password_map_profile:
        cmd.extend(
            [
                "--fanout-publisher-password-map-profile",
                fanout_publisher_password_map_profile,
            ]
        )
    if token_refresh_codes:
        cmd.extend(["--token-refresh-codes", token_refresh_codes])
    if proactive_refresh:
        cmd.append("--proactive-refresh")
    if proactive_refresh_margin_seconds is not None:
        cmd.extend(["--proactive-refresh-margin-seconds", str(proactive_refresh_margin_seconds)])
    if proactive_refresh_timeout_seconds is not None:
        cmd.extend(["--proactive-refresh-timeout-seconds", str(proactive_refresh_timeout_seconds)])
    if proactive_refresh_assert_continuity:
        cmd.append("--proactive-refresh-assert-continuity")
    if reauth_storm:
        cmd.append("--reauth-storm")
    cmd.extend(["--jwt-identity-binding", jwt_identity_binding])
    cmd.extend(["--biscuit-identity-binding", biscuit_identity_binding])
    cmd.extend(["--biscuit-client-id-fact", biscuit_client_id_fact])
    if tls_enabled:
        cmd.append("--tls")
    if tls_ca_file:
        cmd.extend(["--tls-ca-file", tls_ca_file])
    if tls_insecure:
        cmd.append("--tls-insecure")
    if biscuit_attenuate:
        cmd.append("--biscuit-attenuate")
    for deny in biscuit_attenuate_denies or []:
        cmd.extend(["--biscuit-attenuate-deny", deny])
    for check in biscuit_attenuate_checks or []:
        cmd.extend(["--biscuit-attenuate-check", check])
    if biscuit_attenuate_topic:
        cmd.extend(["--biscuit-attenuate-topic", biscuit_attenuate_topic])
    if biscuit_attenuate_op:
        cmd.extend(["--biscuit-attenuate-op", biscuit_attenuate_op])
    if biscuit_attenuate_ttl is not None:
        cmd.extend(["--biscuit-attenuate-ttl", str(biscuit_attenuate_ttl)])
    if attenuation_probe_subscribe_denied:
        cmd.append("--attenuation-probe-subscribe-denied")
    if biscuit_public_key_hex:
        cmd.extend(["--biscuit-public-key-hex", biscuit_public_key_hex])
    if biscuit_public_key_file:
        cmd.extend(["--biscuit-public-key-file", biscuit_public_key_file])
    if biscuit_delegate:
        cmd.append("--biscuit-delegate")
    for deny in biscuit_delegate_denies or []:
        cmd.extend(["--biscuit-delegate-deny", deny])
    for check in biscuit_delegate_checks or []:
        cmd.extend(["--biscuit-delegate-check", check])
    if biscuit_delegate_topic:
        cmd.extend(["--biscuit-delegate-topic", biscuit_delegate_topic])
    if biscuit_delegate_op:
        cmd.extend(["--biscuit-delegate-op", biscuit_delegate_op])
    if biscuit_delegate_ttl is not None:
        cmd.extend(["--biscuit-delegate-ttl", str(biscuit_delegate_ttl)])
    if biscuit_delegate_public_key_hex:
        cmd.extend(["--biscuit-delegate-public-key-hex", biscuit_delegate_public_key_hex])
    if biscuit_delegate_public_key_file:
        cmd.extend(["--biscuit-delegate-public-key-file", biscuit_delegate_public_key_file])
    if biscuit_delegate_handoff:
        cmd.append("--biscuit-delegate-handoff")
    if biscuit_delegate_handoff_topic:
        cmd.extend(["--biscuit-delegate-handoff-topic", biscuit_delegate_handoff_topic])
    if biscuit_delegate_handoff_token:
        cmd.extend(
            [
                "--biscuit-delegate-handoff-token",
                _mark_biscuit_cli_token(tokens, biscuit_delegate_handoff_token) or "",
            ]
        )
    if biscuit_delegate_handoff_qos is not None:
        cmd.extend(["--biscuit-delegate-handoff-qos", str(biscuit_delegate_handoff_qos)])
    if biscuit_delegate_handoff_retain is False:
        cmd.append("--biscuit-delegate-handoff-no-retain")
    if (
        biscuit_delegate_handoff_ready_timeout_seconds is not None
        and biscuit_delegate_handoff_ready_timeout_seconds != 120
    ):
        cmd.extend(
            [
                "--biscuit-delegate-handoff-ready-timeout-seconds",
                str(biscuit_delegate_handoff_ready_timeout_seconds),
            ]
        )
    # CONTROL message CLI options
    if control_topic:
        cmd.extend(["--control-topic", control_topic])
    if control_payload:
        cmd.extend(["--control-payload", json.dumps(control_payload)])
    if control_mode:
        cmd.append("--control-mode")
    if control_after_messages > 0:
        cmd.extend(["--control-after-messages", str(control_after_messages)])
    if runtime_control_username:
        cmd.extend(["--runtime-control-username", runtime_control_username])
    if runtime_control_password:
        cmd.extend(
            [
                "--runtime-control-password",
                _mark_biscuit_cli_token(tokens, runtime_control_password) or "",
            ]
        )
    if runtime_control_after_messages > 0:
        cmd.extend(["--runtime-control-after-messages", str(runtime_control_after_messages)])
    if runtime_control_expect_denial:
        cmd.append("--runtime-control-expect-denial")
    if control_repeat != 1:
        cmd.extend(["--control-repeat", str(control_repeat)])
    if control_response_topic:
        cmd.extend(["--control-response-topic", control_response_topic])
    if fanout_churn_kind:
        cmd.extend(["--fanout-churn-kind", fanout_churn_kind])
    if fanout_churn_after_messages > 0:
        cmd.extend(["--fanout-churn-after-messages", str(fanout_churn_after_messages)])
    if fanout_churn_interval_messages > 0:
        cmd.extend(["--fanout-churn-interval-messages", str(fanout_churn_interval_messages)])
    if fanout_churn_max_events > 0:
        cmd.extend(["--fanout-churn-max-events", str(fanout_churn_max_events)])
    if fanout_churn_settle_ms > 0:
        cmd.extend(["--fanout-churn-settle-ms", str(fanout_churn_settle_ms)])
    if fanout_churn_phase_delivery:
        cmd.extend(["--fanout-churn-phase-delivery", ",".join(fanout_churn_phase_delivery)])
    if fanout_churn_dynamic_security_source:
        cmd.extend(
            [
                "--fanout-churn-dynamic-security-source",
                fanout_churn_dynamic_security_source,
            ]
        )
    if fanout_churn_control_topic:
        cmd.extend(["--fanout-churn-control-topic", fanout_churn_control_topic])
    if fanout_churn_control_payload:
        cmd.extend(["--fanout-churn-control-payload", json.dumps(fanout_churn_control_payload)])
    if fanout_expect_control_notification:
        cmd.append("--fanout-expect-control-notification")
    if fanout_churn_sqlite_db:
        cmd.extend(["--fanout-churn-sqlite-db", fanout_churn_sqlite_db])
    if fanout_churn_sqlite_topic:
        cmd.extend(["--fanout-churn-sqlite-topic", fanout_churn_sqlite_topic])
    if fanout_churn_sqlite_subscribers is not None:
        cmd.extend(["--fanout-churn-sqlite-subscribers", str(fanout_churn_sqlite_subscribers)])

    if client_topology == "host":
        out = subprocess.check_output(
            cmd,
            cwd=REPO_ROOT,
            text=True,
        )
        return json.loads(out)
    if reauth_storm and client_topology == "container-per-client":
        raise RuntimeError("reauth storm is only supported with host or container-single topology")

    loadgen_args = cmd[len(helper_cmd) :]
    env = {
        **(compose_env or {}),
        "LOADGEN_CPUS": loadgen_cpus,
        "LOADGEN_MEMORY": loadgen_memory,
    }
    if loadgen_cpuset:
        env["LOADGEN_CPUSET"] = loadgen_cpuset

    if client_topology == "container-single":
        return _run_loadgen_compose_container(
            loadgen_args,
            service=loadgen_service,
            container_name=_loadgen_container_name(
                compose_project_name=compose_project_name,
                compose_files=compose_files,
                scenario_id=scenario_id,
                run_index=run_index,
            ),
            compose_files=compose_files,
            compose_project_name=compose_project_name,
            extra_env=env,
        )

    if biscuit_delegate_handoff:
        if sync_connect:
            raise RuntimeError(
                "container-per-client Biscuit delegation handoff is not supported with "
                "sync_connect; use the dedicated connection-burst scenarios for sync_connect"
            )
        if mode == "fanout":
            raise RuntimeError(
                "container-per-client Biscuit delegation handoff is not supported for "
                "fanout split-role scenarios"
            )
        return _run_loadgen_container_per_client_delegation_handoff(
            loadgen_args,
            clients=clients,
            service=loadgen_service,
            scenario_id=scenario_id,
            run_index=run_index,
            compose_files=compose_files,
            compose_project_name=compose_project_name,
            extra_env=env,
            handoff_topic=biscuit_delegate_handoff_topic or "delegation/handoff",
            handoff_qos=(
                biscuit_delegate_handoff_qos if biscuit_delegate_handoff_qos is not None else 1
            ),
            handoff_retain=biscuit_delegate_handoff_retain is not False,
        )

    if mode == "fanout":
        if sync_connect:
            raise RuntimeError(
                "container-per-client fanout split-role topology is not supported for "
                "sync_connect scenarios; use a standard publish/connect-burst scenario"
            )
        return _run_loadgen_container_per_client_fanout(
            loadgen_args,
            clients=clients,
            messages=messages,
            service=loadgen_service,
            scenario_id=scenario_id,
            run_index=run_index,
            compose_files=compose_files,
            compose_project_name=compose_project_name,
            extra_env=env,
        )

    return _run_loadgen_container_per_client(
        loadgen_args,
        clients=clients,
        service=loadgen_service,
        scenario_id=scenario_id,
        run_index=run_index,
        compose_files=compose_files,
        compose_project_name=compose_project_name,
        extra_env=env,
        sync_connect=sync_connect,
        runtime_control=(
            PerClientRuntimeControl(
                username=runtime_control_username,
                password=_cli_option_value(loadgen_args, "--runtime-control-password") or "",
                after_messages=runtime_control_after_messages,
                expect_denial=runtime_control_expect_denial,
            )
            if runtime_control_username
            else None
        ),
    )


def _run_loadgen_compose_container(
    loadgen_args: list[str],
    *,
    service: str,
    container_name: str,
    compose_files: list[str] | None,
    compose_project_name: str | None,
    extra_env: dict[str, str],
) -> dict[str, Any]:
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    cmd = _compose_run_loadgen_cmd(
        loadgen_args,
        service=service,
        container_name=container_name,
        compose_files=compose_files,
        compose_project_name=compose_project_name,
        build=True,
    )
    env = os.environ.copy()
    env.update(extra_env)
    completed = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return _loads_json_from_compose_stdout(completed.stdout)


def _loads_json_from_compose_stdout(stdout: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    for index, char in enumerate(stdout):
        if char != "{":
            continue
        try:
            payload, _end = decoder.raw_decode(stdout[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise RuntimeError(f"loadgen container did not emit JSON payload: {stdout!r}")


def _compose_run_loadgen_cmd(
    loadgen_args: list[str],
    *,
    service: str,
    container_name: str,
    compose_files: list[str] | None,
    compose_project_name: str | None,
    build: bool,
) -> list[str]:
    args = ["run", "--rm", "--no-deps"]
    if build:
        args.append("--build")
    args.extend(["--name", container_name, service, *loadgen_args])
    return _compose_cmd(
        args,
        compose_files=compose_files,
        compose_project_name=compose_project_name,
    )


def _replace_cli_option(args: list[str], option: str, value: str) -> list[str]:
    updated = list(args)
    try:
        index = updated.index(option)
    except ValueError:
        updated.extend([option, value])
        return updated
    if index + 1 >= len(updated):
        updated.append(value)
    else:
        updated[index + 1] = value
    return updated


def _remove_cli_option(args: list[str], option: str) -> list[str]:
    updated = list(args)
    while option in updated:
        index = updated.index(option)
        del updated[index]
        if index < len(updated):
            del updated[index]
    return updated


def _remove_cli_flag(args: list[str], option: str) -> list[str]:
    return [arg for arg in args if arg != option]


def _append_cli_option(args: list[str], option: str, value: str) -> list[str]:
    updated = list(args)
    updated.extend([option, value])
    return updated


def _cli_option_value(args: list[str], option: str) -> str | None:
    try:
        index = args.index(option)
    except ValueError:
        return None
    if index + 1 >= len(args):
        return None
    return args[index + 1]


def _int_cli_option_value(args: list[str], option: str, default: int) -> int:
    raw = _cli_option_value(args, option)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"invalid integer value for {option}: {raw!r}") from exc


def _append_sync_barrier_args(
    args: list[str],
    *,
    run_id: str,
    participant_id: str,
    participants: int,
) -> list[str]:
    updated = list(args)
    updated.extend(
        [
            "--sync-connect-barrier-url",
            SYNC_BARRIER_CONTAINER_URL,
            "--sync-connect-run-id",
            run_id,
            "--sync-connect-participant-id",
            participant_id,
            "--sync-connect-participants",
            str(participants),
            "--sync-connect-barrier-timeout-seconds",
            str(SYNC_BARRIER_TIMEOUT_SECONDS),
        ]
    )
    return updated


def _append_runtime_control_barrier_args(
    args: list[str],
    *,
    run_id: str,
    participant_id: str,
    participants: int,
    local_after_messages: int,
) -> list[str]:
    updated = list(args)
    updated.extend(
        [
            "--runtime-control-barrier-url",
            SYNC_BARRIER_CONTAINER_URL,
            "--runtime-control-run-id",
            run_id,
            "--runtime-control-participant-id",
            participant_id,
            "--runtime-control-participants",
            str(participants),
            "--runtime-control-local-after-messages",
            str(local_after_messages),
            "--runtime-control-barrier-timeout-seconds",
            str(SYNC_BARRIER_TIMEOUT_SECONDS),
        ]
    )
    return updated


def _runtime_control_quotas(*, clients: int, after_messages: int) -> list[int]:
    if clients <= 0:
        raise RuntimeError("runtime control requires at least one publisher")
    if after_messages <= 0:
        raise RuntimeError("runtime control after-messages must be greater than zero")
    base, remainder = divmod(after_messages, clients)
    return [base + (1 if index < remainder else 0) for index in range(clients)]


def _sync_barrier_run_id(scenario_id: str, run_index: int) -> str:
    scenario = _sanitize_container_name(scenario_id)
    return f"{scenario}-{run_index + 1}-{time.time_ns()}-{uuid.uuid4().hex[:8]}"


def _ensure_sync_barrier_service(
    *,
    compose_files: list[str] | None,
    compose_project_name: str | None,
) -> None:
    cmd = _compose_cmd(
        ["up", "-d", "--build", SYNC_BARRIER_SERVICE],
        compose_files=compose_files,
        compose_project_name=compose_project_name,
    )
    subprocess.run(cmd, cwd=REPO_ROOT, env=os.environ.copy(), check=True)
    _wait_for_service_health(
        SYNC_BARRIER_SERVICE,
        SYNC_BARRIER_HOST_URL,
        None,
        False,
        timeout_seconds=60.0,
    )


def _sync_barrier_status(run_id: str) -> dict[str, Any] | None:
    try:
        with _http_client(None, False) as client:
            resp = client.get(f"{SYNC_BARRIER_HOST_URL}/runs/{run_id}/status")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return cast(dict[str, Any], resp.json())
    except httpx.HTTPStatusError:
        raise
    except Exception:
        return None


def _wait_for_sync_barrier_ready(
    run_id: str,
    *,
    participants: int,
    processes: list[tuple[str, subprocess.Popen[str]]],
    timeout_seconds: float = float(SYNC_BARRIER_TIMEOUT_SECONDS),
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_status: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        exited = []
        for container_name, process in processes:
            if process.poll() is None:
                continue
            stdout, stderr = process.communicate()
            exited.append(
                {
                    "container": container_name,
                    "returncode": process.returncode,
                    "stdout": stdout[-4000:],
                    "stderr": stderr[-4000:],
                }
            )
        if exited:
            raise RuntimeError(f"sync barrier participant exited before release: {exited}")
        status = _sync_barrier_status(run_id)
        if status is not None:
            last_status = status
            if int(status.get("ready_count") or 0) >= participants:
                return status
        time.sleep(0.1)
    raise RuntimeError(
        f"timed out waiting for sync barrier readiness for run {run_id}: {last_status}"
    )


def _release_sync_barrier(run_id: str, *, participants: int) -> dict[str, Any]:
    with _http_client(None, False) as client:
        resp = client.post(
            f"{SYNC_BARRIER_HOST_URL}/runs/{run_id}/release",
            params={"participants": str(participants)},
        )
        resp.raise_for_status()
        return cast(dict[str, Any], resp.json())


def _fanout_ready_host_dir(scenario_id: str, run_index: int) -> Path:
    return (
        REPO_ROOT
        / "benchmarks"
        / "results"
        / ".fanout-ready"
        / f"{_sanitize_container_name(scenario_id)}_{run_index + 1}"
    )


def _delegation_handoff_ready_host_dir(scenario_id: str, run_index: int) -> Path:
    return (
        REPO_ROOT
        / "benchmarks"
        / "results"
        / ".delegation-handoff-ready"
        / f"{_sanitize_container_name(scenario_id)}_{run_index + 1}"
    )


def _delegation_handoff_run_id(scenario_id: str, run_index: int) -> str:
    scenario = _sanitize_container_name(scenario_id)
    return f"{scenario}-{run_index + 1}-{time.time_ns()}-{uuid.uuid4().hex[:8]}"


def _redact_run_id(run_id: str) -> str:
    return f"{run_id[:12]}..." if len(run_id) > 12 else run_id


def _wait_for_fanout_ready_files(
    ready_dir: Path,
    *,
    clients: int,
    timeout_seconds: float = 120.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    expected = [ready_dir / f"client_{index}.ready" for index in range(1, clients + 1)]
    while time.monotonic() < deadline:
        if all(path.exists() for path in expected):
            return
        time.sleep(0.1)
    missing = [path.name for path in expected if not path.exists()]
    raise RuntimeError(
        f"timed out waiting for fanout subscriber readiness in {ready_dir}: {missing}"
    )


def _wait_for_delegation_handoff_ready_files(
    ready_dir: Path,
    *,
    clients: int,
    processes: list[tuple[str, subprocess.Popen[str]]] | None = None,
    timeout_seconds: float = 120.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    expected = [ready_dir / f"client_{index}.ready" for index in range(1, clients + 1)]
    processes = processes or []
    while time.monotonic() < deadline:
        if all(path.exists() for path in expected):
            return
        exited = [
            (container_name, process.returncode)
            for container_name, process in processes
            if process.poll() is not None
        ]
        if exited:
            raise RuntimeError(f"delegation handoff delegatee exited before readiness: {exited}")
        time.sleep(0.1)
    missing = [path.name for path in expected if not path.exists()]
    raise RuntimeError(
        f"timed out waiting for delegation handoff delegatee readiness in {ready_dir}: {missing}"
    )


def _summary_from_values(values: list[float]) -> dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "min_ms": None,
            "p50_ms": None,
            "p95_ms": None,
            "p99_ms": None,
            "max_ms": None,
            "mean_ms": None,
            "median_ms": None,
        }
    ordered = sorted(values)

    def percentile(p: float) -> float:
        if len(ordered) == 1:
            return float(ordered[0])
        rank = p * (len(ordered) - 1)
        lower = int(rank)
        upper = min(lower + 1, len(ordered) - 1)
        weight = rank - lower
        return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)

    return {
        "count": len(values),
        "min_ms": float(ordered[0]),
        "p50_ms": percentile(0.50),
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "max_ms": float(ordered[-1]),
        "mean_ms": float(sum(values) / len(values)),
        "median_ms": percentile(0.50),
    }


_SUMMARY_VALUE_FIELDS = (
    "min_ms",
    "p50_ms",
    "p95_ms",
    "p99_ms",
    "max_ms",
    "mean_ms",
    "median_ms",
)


def _validate_metric_summary(
    scenario_id: str,
    result: dict[str, Any],
    metric: str,
    *,
    expected_count: int | None = None,
) -> int:
    summary = result.get(metric)
    if not isinstance(summary, dict):
        raise RuntimeError(f"{scenario_id}: {metric} metric summary is missing")
    count = summary.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise RuntimeError(f"{scenario_id}: {metric} metric count is invalid")
    if expected_count is not None and count != expected_count:
        raise RuntimeError(
            f"{scenario_id}: {metric} metric count {count} does not match {expected_count}"
        )
    raw_metrics = result.get("raw_metrics")
    raw = raw_metrics.get(metric) if isinstance(raw_metrics, dict) else None
    if not isinstance(raw, list):
        raise RuntimeError(f"{scenario_id}: raw {metric} metric samples are missing")
    if len(raw) != count:
        raise RuntimeError(f"{scenario_id}: raw {metric} metric count does not match summary")
    if count == 0:
        if any(summary.get(field) is not None for field in _SUMMARY_VALUE_FIELDS):
            raise RuntimeError(f"{scenario_id}: empty {metric} metric summary is inconsistent")
        return count
    values: dict[str, float] = {}
    for field in _SUMMARY_VALUE_FIELDS:
        value = summary.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            raise RuntimeError(f"{scenario_id}: {metric}.{field} is missing or invalid")
        values[field] = float(value)
    if not (
        values["min_ms"]
        <= values["p50_ms"]
        <= values["p95_ms"]
        <= values["p99_ms"]
        <= values["max_ms"]
        and math.isclose(values["p50_ms"], values["median_ms"], abs_tol=1e-9)
        and values["min_ms"] <= values["mean_ms"] <= values["max_ms"]
    ):
        raise RuntimeError(f"{scenario_id}: {metric} metric summary is inconsistent")
    numeric_raw = [float(value) for value in raw]
    if any(not math.isfinite(value) or value < 0 for value in numeric_raw):
        raise RuntimeError(f"{scenario_id}: raw {metric} metric samples are invalid")
    recomputed = _summary_from_values(numeric_raw)
    for field in _SUMMARY_VALUE_FIELDS:
        if not math.isclose(
            float(summary[field]), float(recomputed[field]), rel_tol=1e-9, abs_tol=1e-9
        ):
            raise RuntimeError(f"{scenario_id}: {metric} metric summary does not match raw samples")
    return count


def _validate_throughput(
    scenario_id: str,
    result: dict[str, Any],
    metric: str,
    *,
    require_positive: bool,
) -> None:
    value = result.get(metric)
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(float(value))
        or float(value) < 0
        or require_positive
        and float(value) <= 0
    ):
        raise RuntimeError(f"{scenario_id}: {metric} is missing or invalid")


def _raw_metric_values(payload: dict[str, Any], metric: str) -> list[float]:
    raw_metrics = payload.get("raw_metrics")
    if isinstance(raw_metrics, dict):
        values = raw_metrics.get(metric)
        if isinstance(values, list):
            return [float(value) for value in values]
    if metric == "publish":
        values = payload.get("raw_publish_ms")
        if isinstance(values, list):
            return [float(value) for value in values]
    return []


def _merge_latency_summary(results: list[dict[str, Any]], metric: str) -> dict[str, Any]:
    values = [value for result in results for value in _raw_metric_values(result, metric)]
    return _summary_from_values(values)


def _sum_numeric_field(results: list[dict[str, Any]], field: str) -> int:
    return sum(int(result.get(field) or 0) for result in results)


def _policy_denial_count(result: dict[str, Any]) -> int:
    raw_metrics = result.get("raw_metrics")
    if isinstance(raw_metrics, dict) and "policy_denial_count" in raw_metrics:
        return int(raw_metrics.get("policy_denial_count") or 0)
    return int(result.get("policy_denial_count") or 0)


def _sum_count_object(results: list[dict[str, Any]], field: str) -> dict[str, int]:
    totals: dict[str, int] = {}
    for result in results:
        payload = result.get(field)
        if not isinstance(payload, dict):
            continue
        for key, value in payload.items():
            totals[key] = totals.get(key, 0) + int(value or 0)
    return totals


def _merge_per_client_loadgen_results(
    results: list[dict[str, Any]], wall_duration_s: float
) -> dict[str, Any]:
    if not results:
        return {"errors": ["container_per_client_no_results"]}
    merged = dict(results[0])
    publish_values = [
        value for result in results for value in _raw_metric_values(result, "publish")
    ]
    errors: list[str] = []
    for result in results:
        errors.extend(str(err) for err in result.get("errors", []))
    for metric in (
        "connect",
        "token_refresh",
        "token_refresh_len",
        "proactive_refresh",
        "proactive_refresh_len",
        "delegation",
        "delegation_len",
        "delegation_handoff_publish",
        "attenuation",
        "attenuation_len",
        "publish_qos_0",
        "publish_qos_1",
        "publish_qos_2",
        "receive",
        "control",
        "control_response",
        "control_injection_delay",
        "sync_connect_barrier_wait",
    ):
        merged[metric] = _merge_latency_summary(results, metric)
    merged["publish"] = _summary_from_values(publish_values)
    merged["raw_publish_ms"] = publish_values
    merged["raw_metrics"] = {
        metric: [value for result in results for value in _raw_metric_values(result, metric)]
        for metric in (
            "connect",
            "token_refresh",
            "token_refresh_len",
            "proactive_refresh",
            "proactive_refresh_len",
            "delegation",
            "delegation_len",
            "delegation_handoff_publish",
            "attenuation",
            "attenuation_len",
            "publish",
            "publish_qos_0",
            "publish_qos_1",
            "publish_qos_2",
            "receive",
            "control",
            "control_response",
            "control_injection_delay",
            "sync_connect_barrier_wait",
        )
    }
    merged["errors"] = errors
    issuance_records: list[Any] = []
    for result in results:
        records = result.get("credential_issuance")
        if isinstance(records, list):
            issuance_records.extend(records)
    merged["credential_issuance"] = issuance_records
    merged["qos_distribution_actual"] = _sum_count_object(results, "qos_distribution_actual")
    attempted_by_qos = {f"qos_{qos}": 0 for qos in range(3)}
    failed_by_qos = {f"qos_{qos}": 0 for qos in range(3)}
    attempted = succeeded = failed = 0
    for result in results:
        outcomes = result.get("publish_outcomes")
        if not isinstance(outcomes, dict):
            continue
        attempted += int(outcomes.get("attempted") or 0)
        succeeded += int(outcomes.get("succeeded") or 0)
        failed += int(outcomes.get("failed") or 0)
        for target, field in (
            (attempted_by_qos, "attempted_by_qos"),
            (failed_by_qos, "failed_by_qos"),
        ):
            source = outcomes.get(field)
            if isinstance(source, dict):
                for key in target:
                    target[key] += int(source.get(key) or 0)
    merged["publish_outcomes"] = {
        "attempted": attempted,
        "succeeded": succeeded,
        "failed": failed,
        "attempted_by_qos": attempted_by_qos,
        "failed_by_qos": failed_by_qos,
    }
    merged["received_messages"] = _sum_count_object(results, "received_messages")
    control_response_counts = _sum_count_object(results, "control_responses")
    merged["control_responses"] = {
        "enabled": any(
            result.get("control_responses", {}).get("enabled") is True
            for result in results
            if isinstance(result.get("control_responses"), dict)
        ),
        "successes": control_response_counts.get("successes", 0),
        "failures": control_response_counts.get("failures", 0),
    }
    for field in (
        "proactive_refresh_attempts",
        "proactive_refresh_successes",
        "proactive_refresh_failures",
        "expiry_denial_count",
    ):
        merged[field] = _sum_numeric_field(results, field)
    merged["policy_denial_count"] = sum(_policy_denial_count(result) for result in results)
    merged["session_continuity_ok"] = all(
        bool(result.get("session_continuity_ok", True)) for result in results
    )
    inputs = merged.get("inputs")
    if isinstance(inputs, dict):
        merged["inputs"] = {
            **inputs,
            "clients": len(results),
            "credential_attestations": _merge_credential_attestations(results, errors),
        }
    duration_s = max(wall_duration_s, 1e-9)
    publish_count = int(merged["publish"].get("count") or 0)
    receive_count = int(merged["receive"].get("count") or 0)
    merged["publish_throughput_mps"] = float(publish_count / duration_s)
    merged["receive_throughput_mps"] = float(receive_count / duration_s)
    mode = inputs.get("mode") if isinstance(inputs, dict) else None
    merged["throughput_mps"] = (
        merged["receive_throughput_mps"] if mode == "fanout" else merged["publish_throughput_mps"]
    )
    merged["topology"] = {
        "mode": "container-per-client",
        "container_count": len(results),
        "aggregation": "merged_from_single_client_containers",
        "wall_duration_s": wall_duration_s,
    }
    return merged


def _merge_credential_attestations(
    results: list[dict[str, Any]], errors: list[str]
) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for result in results:
        inputs = result.get("inputs")
        attestations = inputs.get("credential_attestations") if isinstance(inputs, dict) else None
        if attestations is None:
            continue
        if not isinstance(attestations, dict):
            errors.append("credential_attestations_invalid")
            continue
        for role, candidate in attestations.items():
            if role not in {"clients", "fanout_publisher"} or not isinstance(candidate, dict):
                errors.append(f"credential_attestation_invalid:{role}")
                continue
            profile = candidate.get("profile")
            validated = candidate.get("validated_credentials")
            if (
                not isinstance(profile, str)
                or not profile
                or not isinstance(validated, int)
                or validated <= 0
            ):
                errors.append(f"credential_attestation_invalid:{role}")
                continue
            existing = merged.get(role)
            if existing is None:
                merged[role] = dict(candidate)
                continue
            if existing.get("profile") != profile or existing.get("semantic") != candidate.get(
                "semantic"
            ):
                errors.append(f"credential_attestation_mismatch:{role}")
                continue
            existing["validated_credentials"] = (
                int(existing.get("validated_credentials") or 0) + validated
            )
    return merged


def _validate_reauth_storm_result(
    scenario_id: str,
    result: dict[str, Any],
    *,
    client_count: int,
) -> None:
    storm = result.get("reauth_storm")
    if not isinstance(storm, dict) or storm.get("enabled") is not True:
        raise RuntimeError(f"{scenario_id}: reauth storm metadata missing")
    attempts = int(storm.get("attempts") or result.get("proactive_refresh_attempts") or 0)
    successes = int(storm.get("successes") or result.get("proactive_refresh_successes") or 0)
    failures = int(storm.get("failures") or result.get("proactive_refresh_failures") or 0)
    if attempts < client_count:
        raise RuntimeError(
            f"{scenario_id}: reauth storm missed refresh attempts ({attempts}/{client_count})"
        )
    if successes != attempts:
        raise RuntimeError(
            f"{scenario_id}: reauth storm successes ({successes}) "
            f"did not match attempts ({attempts})"
        )
    if failures != 0:
        raise RuntimeError(f"{scenario_id}: reauth storm saw {failures} refresh failures")
    if result.get("expiry_denial_count", 0) != 0:
        raise RuntimeError(f"{scenario_id}: reauth storm saw expiry denials")
    if not result.get("session_continuity_ok") or storm.get("session_continuity_ok") is False:
        raise RuntimeError(f"{scenario_id}: reauth storm did not preserve session continuity")


def _validate_mqtt5_auth_result(scenario_id: str, result: dict[str, Any]) -> None:
    if result.get("connect_ok") is not True:
        raise RuntimeError(f"{scenario_id}: MQTT5 AUTH connection did not succeed")
    if result.get("reauth_ok") is not True:
        detail = result.get("reauth_error") or "unknown error"
        raise RuntimeError(f"{scenario_id}: MQTT5 reauthentication failed: {detail}")
    for metric in ("connect_ms", "reauth_ms"):
        value = result.get(metric)
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            raise RuntimeError(f"{scenario_id}: MQTT5 AUTH {metric} is missing or invalid")
    token1_sha = result.get("token1_sha256")
    token2_sha = result.get("token2_sha256")
    attestation = result.get("credential_attestation")
    attestation_data = cast(dict[str, Any], attestation) if isinstance(attestation, dict) else {}
    issuer_metadata_invalid = not attestation_data or (
        attestation_data.get("source") == "issuer"
        and (
            attestation_data.get("token_kind") not in {"jwt", "biscuit"}
            or not attestation_data.get("client_id")
            or int(attestation_data.get("token1_ttl_seconds") or 0) <= 0
            or int(attestation_data.get("token2_ttl_seconds") or 0) <= 0
        )
    )
    if (
        not isinstance(token1_sha, str)
        or len(token1_sha) != 64
        or not isinstance(token2_sha, str)
        or len(token2_sha) != 64
        or token1_sha == token2_sha
        or result.get("pre_reauth_publish_ok") is not True
        or result.get("post_reauth_publish_ok") is not True
        or result.get("post_reauth_old_topic_denied") is not True
        or issuer_metadata_invalid
        or attestation_data.get("source") not in {"issuer", "static"}
        or attestation_data.get("token1_topic") == attestation_data.get("token2_topic")
    ):
        raise RuntimeError(f"{scenario_id}: MQTT5 credential replacement evidence is invalid")


def _validate_thundering_herd_result(
    scenario_id: str, result: dict[str, Any], *, client_count: int
) -> None:
    sync = result.get("sync_connect")
    restart = result.get("broker_restart")
    connect = result.get("connect")
    if (
        not isinstance(sync, dict)
        or sync.get("enabled") is not True
        or int(sync.get("participants") or 0) != client_count
        or int(sync.get("ready_count") or 0) != client_count
        or not isinstance(sync.get("max_ready_skew_ms"), int | float)
        or sync.get("errors")
    ):
        raise RuntimeError(f"{scenario_id}: synchronized connection barrier contract failed")
    if (
        not isinstance(restart, dict)
        or restart.get("completed") is not True
        or not isinstance(restart.get("completed_at_unix_ms"), int)
    ):
        raise RuntimeError(f"{scenario_id}: broker restart provenance missing")
    if not isinstance(connect, dict) or int(connect.get("count") or 0) != client_count:
        raise RuntimeError(f"{scenario_id}: connected clients did not match herd size")


def _validate_external_policy_activity(
    scenario_id: str,
    stats: object,
) -> None:
    """Require evidence that an HTTP/hybrid workload reached the external PDP."""
    if not isinstance(stats, dict):
        raise RuntimeError(f"{scenario_id}: external policy statistics missing")
    requests = int(stats.get("requests") or 0)
    if requests <= 0:
        raise RuntimeError(
            f"{scenario_id}: external policy backend handled no authorization requests"
        )


def _validate_broker_path_contract(
    scenario: ScenarioConfig,
    result: dict[str, Any],
    attestation: dict[str, Any],
    *,
    client_count: int,
) -> None:
    if not attestation.get("validated"):
        raise RuntimeError(f"{scenario['id']}: broker configuration attestation missing")
    if not attestation.get("plugin_enabled"):
        return
    if (
        attestation.get("benchmark_diagnostics") is not True
        or attestation.get("benchmark_diagnostics_transport") != "loopback_tcp_snapshot"
        or int(attestation.get("benchmark_diagnostics_port") or 0) != BENCHMARK_DIAGNOSTICS_PORT
    ):
        raise RuntimeError(f"{scenario['id']}: broker diagnostics attestation missing")
    auth = result.get("broker_auth_delta")
    authz = result.get("broker_authz_delta")
    if not isinstance(auth, dict) or not isinstance(authz, dict):
        raise RuntimeError(
            f"{scenario['id']}: broker authentication/authorization counters missing"
        )
    expected_mode = str(attestation.get("policy_mode") or "")
    observed_mode = str(authz.get("policy_mode") or "")
    normalized_modes = {
        "token": "TokenOnly",
        "static_acl": "StaticAcl",
        "dynamic_security": "DynamicSecurity",
        "http": "Http",
        "sqlite": "Sqlite",
        "hybrid": "Hybrid",
    }
    expected_connections = client_count
    if (scenario.get("biscuit_delegate") or {}).get("handoff"):
        # Each worker first authenticates a handoff-receiver session, and the
        # delegator authenticates one master session used to publish the tokens.
        expected_connections += client_count + 1
    if scenario.get("traffic_pattern") == "fanout":
        expected_connections += 1
    if scenario.get("runtime_control_username"):
        expected_connections += 1
    if observed_mode != normalized_modes.get(expected_mode):
        raise RuntimeError(
            f"{scenario['id']}: broker authorization path contract failed: {authz}, "
            f"attested_policy_mode={expected_mode!r}"
        )
    if scenario.get("mqtt5_auth") is not None:
        token_kind = _scenario_token_kind(scenario["id"], scenario)
        if (
            int(auth.get("attempts") or 0) != 2
            or int(auth.get("successes") or 0) != 2
            or int(auth.get("failures") or 0) != 0
            or token_kind not in {"jwt", "biscuit"}
            or int(auth.get(f"{token_kind}_validations") or 0) != 2
            or int(authz.get("checks") or 0) < 3
        ):
            raise RuntimeError(
                f"{scenario['id']}: MQTT5 enhanced-auth broker path contract failed: "
                f"auth={auth}, authz={authz}"
            )
        return
    anonymous_dynamic_security = (
        expected_mode == "dynamic_security"
        and attestation.get("allow_anonymous_no_token") is True
        and not scenario.get("username")
        and not scenario.get("password")
    )
    if anonymous_dynamic_security:
        attempts = int(auth.get("attempts") or 0)
        deferrals = int(auth.get("anonymous_deferrals") or 0)
        authenticated_controllers = 1 if scenario.get("runtime_control_username") else 0
        expected_deferrals = expected_connections - authenticated_controllers
        anonymous_checks = int(authz.get("anonymous_checks") or 0)
        anonymous_allows = int(authz.get("anonymous_allows") or 0)
        if (
            attempts != expected_connections
            or deferrals != expected_deferrals
            or int(auth.get("successes") or 0) != authenticated_controllers
            or int(auth.get("failures") or 0) != 0
            or anonymous_checks <= 0
            or anonymous_allows != anonymous_checks
            or int(authz.get("anonymous_denies") or 0) != 0
            or int(authz.get("checks") or 0) != 0
        ):
            raise RuntimeError(
                f"{scenario['id']}: anonymous Dynamic Security path contract failed: "
                f"auth={auth}, authz={authz}"
            )
        return
    attempts = int(auth.get("attempts") or 0)
    successes = int(auth.get("successes") or 0)
    failures = int(auth.get("failures") or 0)
    lifecycle_reconnects = bool(scenario.get("token_refresh") or scenario.get("proactive_refresh"))
    wrong_connection_count = (
        attempts < expected_connections
        if lifecycle_reconnects
        else attempts != expected_connections
    )
    if wrong_connection_count or successes != attempts or failures != 0:
        raise RuntimeError(f"{scenario['id']}: broker authentication path contract failed: {auth}")
    token_kind = _scenario_token_kind(scenario["id"], scenario)
    if token_kind is None and scenario.get("password_map_profile") == "jwt":
        token_kind = "jwt"
    if token_kind is not None and int(auth.get(f"{token_kind}_validations") or 0) <= 0:
        raise RuntimeError(f"{scenario['id']}: {token_kind} validation counter is zero")
    if int(authz.get("checks") or 0) <= 0:
        raise RuntimeError(
            f"{scenario['id']}: broker authorization path contract failed: {authz}, "
            f"attested_policy_mode={expected_mode!r}"
        )


def _expected_qos_distribution_counts(
    raw: str, *, messages_per_publisher: int, publisher_count: int
) -> dict[int, int]:
    entries: list[tuple[int, float]] = []
    for part in raw.split(","):
        qos_raw, weight_raw = part.split(":", 1)
        entries.append((int(qos_raw.strip()), float(weight_raw.strip())))
    total_weight = sum(weight for _, weight in entries)
    normalized = [(qos, weight / total_weight) for qos, weight in entries]
    slots = 1000
    exact = [weight * slots for _, weight in normalized]
    counts = [math.floor(value) for value in exact]
    order = sorted(range(len(entries)), key=lambda i: (-(exact[i] - counts[i]), i))
    for index in order[: slots - sum(counts)]:
        counts[index] += 1
    current = [0] * len(entries)
    schedule: list[int] = []
    for _ in range(slots):
        for index, count in enumerate(counts):
            current[index] += count
        selected = max(range(len(entries)), key=lambda i: (current[i], -i))
        schedule.append(entries[selected][0])
        current[selected] -= slots
    per_publisher = {0: 0, 1: 0, 2: 0}
    for ordinal in range(messages_per_publisher):
        per_publisher[schedule[ordinal % slots]] += 1
    return {qos: count * publisher_count for qos, count in per_publisher.items()}


def _validate_credential_attestations(
    scenario: ScenarioConfig, result: dict[str, Any], *, client_count: int
) -> None:
    if scenario.get("credential_mode") != "per_client":
        return
    scenario_id = scenario["id"]
    inputs = result.get("inputs")
    attestations = inputs.get("credential_attestations") if isinstance(inputs, dict) else None
    if not isinstance(attestations, dict):
        raise RuntimeError(f"{scenario_id}: credential attestations missing")

    expected_roles = {
        "clients": (scenario.get("password_map_profile"), client_count),
    }
    if scenario.get("traffic_pattern") == "fanout":
        expected_roles["fanout_publisher"] = (
            scenario.get("fanout_publisher_password_map_profile"),
            1,
        )
    if set(attestations) != set(expected_roles):
        raise RuntimeError(
            f"{scenario_id}: credential attestation roles do not match "
            f"expected={sorted(expected_roles)} actual={sorted(attestations)}"
        )
    for role, (expected_profile, expected_count) in expected_roles.items():
        attestation = attestations.get(role)
        if (
            not isinstance(attestation, dict)
            or attestation.get("profile") != expected_profile
            or int(attestation.get("validated_credentials") or 0) != expected_count
        ):
            raise RuntimeError(
                f"{scenario_id}: {role} credential attestation does not match "
                f"profile={expected_profile!r} count={expected_count}"
            )


def _validate_issuer_credential_issuance(
    scenario: ScenarioConfig, result: dict[str, Any], *, client_count: int
) -> None:
    scenario_id = scenario["id"]
    records = result.get("credential_issuance")
    if not isinstance(records, list) or len(records) != client_count:
        actual = len(records) if isinstance(records, list) else 0
        raise RuntimeError(
            f"{scenario_id}: issuer returned {actual}/{client_count} credential attestations"
        )
    refresh = scenario.get("token_refresh")
    refresh_config = cast(dict[str, Any], refresh) if isinstance(refresh, dict) else {}
    expected_kind = refresh_config.get("kind")
    expected_ttl = int(refresh_config.get("ttl_seconds") or 0)
    clients: set[str] = set()
    fingerprints: set[str] = set()
    require_issuer_options = scenario_id.startswith("TOKEN-ISSUER-BASELINE-")
    for record in records:
        if not isinstance(record, dict):
            raise RuntimeError(f"{scenario_id}: invalid credential issuance record")
        client_id = record.get("client_id")
        fingerprint = record.get("token_sha256")
        issued_at = int(record.get("issued_at") or 0)
        exp = int(record.get("exp") or 0)
        if (
            not isinstance(client_id, str)
            or not client_id
            or client_id in clients
            or record.get("token_kind") != expected_kind
            or int(record.get("successful_requests") or 0) != 1
            or int(record.get("requested_ttl_seconds") or 0) != expected_ttl
            or exp - issued_at != expected_ttl
            or not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or fingerprint in fingerprints
            or require_issuer_options
            and (
                record.get("no_default_roles")
                is not bool(scenario.get("token_issuer_no_default_roles"))
                or record.get("no_default_grants")
                is not bool(scenario.get("token_issuer_no_default_grants"))
                or int(record.get("explicit_grants") or 0)
                != (2 if scenario.get("token_issuer_no_default_grants") else 0)
            )
        ):
            raise RuntimeError(f"{scenario_id}: invalid credential issuance attestation")
        clients.add(client_id)
        fingerprints.add(fingerprint)
    if scenario.get("complexity_axis") == "publish_authz_reconnect":
        delta = result.get("broker_auth_delta")
        if not isinstance(delta, dict):
            raise RuntimeError(f"{scenario_id}: broker authentication counters missing")
        kind_field = f"{expected_kind}_validations"
        if (
            int(delta.get("attempts") or 0) != client_count
            or int(delta.get("successes") or 0) != client_count
            or int(delta.get("failures") or 0) != 0
            or int(delta.get(kind_field) or 0) != client_count
            or int(delta.get("cache_hits") or 0) + int(delta.get("cache_misses") or 0) <= 0
        ):
            raise RuntimeError(
                f"{scenario_id}: broker authentication/cache contract failed: {delta}"
            )


def _validate_credential_freshness(
    scenario: ScenarioConfig, runs: list[dict[str, Any]], *, client_count: int
) -> dict[str, Any]:
    scenario_id = scenario["id"]
    expected_repeats = int(scenario.get("repeat", 1))
    by_client: dict[str, list[dict[str, Any]]] = {}
    for run in runs:
        loadgen = run.get("loadgen") if isinstance(run, dict) else None
        records = loadgen.get("credential_issuance") if isinstance(loadgen, dict) else None
        if not isinstance(records, list):
            raise RuntimeError(f"{scenario_id}: credential freshness evidence missing")
        for record in records:
            if isinstance(record, dict) and isinstance(record.get("client_id"), str):
                by_client.setdefault(record["client_id"], []).append(record)
    if len(by_client) != client_count:
        raise RuntimeError(f"{scenario_id}: credential freshness client set mismatch")
    for client_id, records in by_client.items():
        fingerprints = [str(record.get("token_sha256") or "") for record in records]
        issued = [int(record.get("issued_at") or 0) for record in records]
        if (
            len(records) != expected_repeats
            or len(set(fingerprints)) != expected_repeats
            or issued != sorted(issued)
        ):
            raise RuntimeError(f"{scenario_id}: reused or out-of-order credential for {client_id}")
    return {
        "validated": True,
        "clients": client_count,
        "repetitions": expected_repeats,
        "successful_issuer_requests": client_count * expected_repeats,
        "unique_per_client_per_repetition": True,
    }


def _validate_result_contract(
    scenario: ScenarioConfig,
    result: dict[str, Any],
    *,
    message_count: int,
    client_count: int,
    effective_qos: int | None = None,
    effective_qos_distribution: str | None = None,
) -> None:
    scenario_id = scenario["id"]
    errors = [str(error) for error in result.get("errors", [])]
    allowed_prefixes = tuple(scenario.get("allowed_error_prefixes", []))
    unexpected_errors = [error for error in errors if not error.startswith(allowed_prefixes)]
    if unexpected_errors:
        raise RuntimeError(f"{scenario_id}: loadgen errors: {', '.join(unexpected_errors[:5])}")

    _validate_credential_attestations(scenario, result, client_count=client_count)
    if scenario.get("credential_freshness_required"):
        _validate_issuer_credential_issuance(scenario, result, client_count=client_count)

    if scenario.get("mqtt5_auth") is not None:
        _validate_mqtt5_auth_result(scenario_id, result)
        return

    expected_connect_count = client_count + (
        1 if scenario.get("traffic_pattern") == "fanout" else 0
    )
    _validate_metric_summary(
        scenario_id,
        result,
        "connect",
        expected_count=expected_connect_count,
    )

    if scenario.get("sync_connect"):
        _validate_thundering_herd_result(scenario_id, result, client_count=client_count)

    publish = result.get("publish")
    publish_count = int(publish.get("count") or 0) if isinstance(publish, dict) else 0
    expected_publish_count = (
        message_count
        if scenario.get("traffic_pattern") == "fanout"
        else message_count * client_count
    )
    http_failure_rate = scenario.get("http_failure_rate")
    outcomes_object = result.get("publish_outcomes")
    outcomes = cast(dict[str, Any], outcomes_object) if isinstance(outcomes_object, dict) else {}
    attempted_count = int(outcomes.get("attempted") or publish_count)
    failed_count = int(outcomes.get("failed") or 0)
    succeeded_count = int(outcomes.get("succeeded") or publish_count)
    _validate_metric_summary(
        scenario_id,
        result,
        "publish",
        expected_count=publish_count,
    )
    _validate_throughput(
        scenario_id,
        result,
        "publish_throughput_mps",
        require_positive=publish_count > 0,
    )
    if attempted_count != succeeded_count + failed_count or succeeded_count != publish_count:
        raise RuntimeError(f"{scenario_id}: inconsistent publish outcome accounting: {outcomes}")
    if isinstance(outcomes_object, dict):
        attempted_by_qos_object = outcomes.get("attempted_by_qos")
        failed_by_qos_object = outcomes.get("failed_by_qos")
        succeeded_by_qos_object = result.get("qos_distribution_actual")
        if not all(
            isinstance(value, dict)
            for value in (
                attempted_by_qos_object,
                failed_by_qos_object,
                succeeded_by_qos_object,
            )
        ):
            raise RuntimeError(
                f"{scenario_id}: publish outcome QoS accounting is missing: {outcomes}"
            )
        attempted_by_qos_map = cast(dict[str, Any], attempted_by_qos_object)
        failed_by_qos_map = cast(dict[str, Any], failed_by_qos_object)
        succeeded_by_qos_map = cast(dict[str, Any], succeeded_by_qos_object)
        attempted_qos_counts = [
            int(attempted_by_qos_map.get(f"qos_{qos}") or 0) for qos in range(3)
        ]
        failed_qos_counts = [int(failed_by_qos_map.get(f"qos_{qos}") or 0) for qos in range(3)]
        succeeded_qos_counts = [
            int(succeeded_by_qos_map.get(f"qos_{qos}_count") or 0) for qos in range(3)
        ]
        if (
            sum(attempted_qos_counts) != attempted_count
            or sum(failed_qos_counts) != failed_count
            or sum(succeeded_qos_counts) != succeeded_count
            or any(
                attempted != succeeded + failed
                for attempted, succeeded, failed in zip(
                    attempted_qos_counts,
                    succeeded_qos_counts,
                    failed_qos_counts,
                    strict=True,
                )
            )
        ):
            raise RuntimeError(
                f"{scenario_id}: inconsistent publish outcome QoS accounting: "
                f"outcomes={outcomes}, succeeded_by_qos={succeeded_by_qos_map}"
            )
    if (
        publish_count != expected_publish_count
        and not scenario.get("control_mode")
        and not scenario.get("runtime_control_expect_denial")
        and http_failure_rate is None
    ):
        raise RuntimeError(
            f"{scenario_id}: published {publish_count}/{expected_publish_count} messages"
        )

    if http_failure_rate is not None:
        stats = result.get("authz_stats")
        if not isinstance(stats, dict):
            raise RuntimeError(f"{scenario_id}: authz failure statistics missing")
        requests = int(stats.get("requests") or 0)
        failures = int(stats.get("injected_failures") or 0)
        allows = int(stats.get("policy_allows") or 0)
        denies = int(stats.get("policy_denies") or 0)
        expected_failures = math.floor(expected_publish_count * float(http_failure_rate) + 1e-12)
        publish_errors = [error for error in errors if error.startswith("publish_failed:")]
        if (
            requests != expected_publish_count
            or failures <= 0
            or failures != expected_failures
            or allows != expected_publish_count - expected_failures
            or denies != 0
            or stats.get("configured_fail_mode") != "rate"
            or not math.isclose(
                float(stats.get("configured_fail_rate") or 0.0),
                float(http_failure_rate),
                rel_tol=0.0,
                abs_tol=1e-12,
            )
            or attempted_count != expected_publish_count
            or failed_count != expected_failures
            or publish_count != expected_publish_count - expected_failures
            or len(publish_errors) != expected_failures
        ):
            raise RuntimeError(
                f"{scenario_id}: HTTP failure workload contract failed: requests={requests}, "
                f"attempted={attempted_count}, succeeded={publish_count}, failed={failed_count}, "
                f"backend_failures={failures}, errors={len(publish_errors)}, "
                f"policy_allows={allows}, policy_denies={denies}, "
                f"fail_mode={stats.get('configured_fail_mode')}, "
                f"fail_rate={stats.get('configured_fail_rate')}, "
                f"expected_attempts={expected_publish_count}, expected_failures={expected_failures}"
            )

    if scenario.get("complexity_axis") == "http_profile":
        stats_object = result.get("authz_stats")
        stats = cast(dict[str, Any], stats_object) if isinstance(stats_object, dict) else {}
        profile = scenario.get("complexity_level")
        profile_requests = stats.get("profile_requests")
        requests = int(stats.get("requests") or 0)
        allows = int(stats.get("policy_allows") or 0)
        denies = int(stats.get("policy_denies") or 0)
        failures = int(stats.get("injected_failures") or 0)
        rules_examined = int(stats.get("rules_examined") or 0)
        active_profile_requests = (
            int(profile_requests.get(str(profile)) or 0)
            if isinstance(profile_requests, dict)
            else 0
        )
        if (
            requests != expected_publish_count
            or allows != expected_publish_count
            or active_profile_requests != expected_publish_count
            or denies != 0
            or failures != 0
            or rules_examined < expected_publish_count
        ):
            raise RuntimeError(
                f"{scenario_id}: HTTP profile contract failed: requests={requests}, "
                f"allows={allows}, profile_requests={active_profile_requests}, "
                f"denies={denies}, failures={failures}, rules_examined={rules_examined}, "
                f"expected={expected_publish_count}"
            )
        stats["rules_examined_per_request"] = rules_examined / requests

    expected_delay = scenario.get("http_expected_delay_ms")
    if expected_delay is not None:
        stats_object = result.get("authz_stats")
        stats = cast(dict[str, Any], stats_object) if isinstance(stats_object, dict) else {}
        profile_requests = stats.get("profile_requests")
        active_profile_requests = (
            int(profile_requests.get("simple") or 0) if isinstance(profile_requests, dict) else 0
        )
        if (
            int(stats.get("requests") or 0) != expected_publish_count
            or int(stats.get("policy_allows") or 0) != expected_publish_count
            or active_profile_requests != expected_publish_count
            or int(stats.get("policy_denies") or 0) != 0
            or int(stats.get("injected_failures") or 0) != 0
            or int(stats.get("configured_delay_ms") or 0) != int(expected_delay)
            or stats.get("configured_profile") != "simple"
            or stats.get("configured_fail_mode") != "none"
        ):
            raise RuntimeError(f"{scenario_id}: HTTP latency contract failed: {stats}")

    if scenario.get("hybrid_fallback_required"):
        stats_object = result.get("authz_stats")
        stats = cast(dict[str, Any], stats_object) if isinstance(stats_object, dict) else {}
        if (
            int(stats.get("requests") or 0) != expected_publish_count
            or int(stats.get("injected_failures") or 0) != expected_publish_count
            or int(stats.get("policy_allows") or 0) != 0
            or int(stats.get("policy_denies") or 0) != 0
            or stats.get("configured_fail_mode") != "always"
            or publish_count != expected_publish_count
        ):
            raise RuntimeError(f"{scenario_id}: hybrid fallback contract failed: {stats}")
        result["fallback_attestation"] = {
            "validated": True,
            "source": "token",
            "external_failures": expected_publish_count,
            "successful_fallbacks": expected_publish_count,
        }

    selected_qos = scenario.get("qos") if effective_qos is None else effective_qos
    if effective_qos is not None and selected_qos not in {0, 1, 2}:
        raise RuntimeError(f"{scenario_id}: invalid effective QoS {selected_qos!r}")
    selected_distribution = (
        scenario.get("qos_distribution")
        if effective_qos_distribution is None
        else effective_qos_distribution
    )
    if effective_qos is not None and selected_distribution is None:
        actual_object = result.get("qos_distribution_actual")
        if not isinstance(actual_object, dict):
            raise RuntimeError(f"{scenario_id}: effective QoS metrics missing")
        for qos_value in (0, 1, 2):
            expected_qos_count = attempted_count if qos_value == selected_qos else 0
            summary = result.get(f"publish_qos_{qos_value}")
            summary_count = int(summary.get("count") or 0) if isinstance(summary, dict) else 0
            _validate_metric_summary(
                scenario_id,
                result,
                f"publish_qos_{qos_value}",
                expected_count=summary_count,
            )
            actual_count = int(actual_object.get(f"qos_{qos_value}_count") or 0)
            failed_by_qos = outcomes.get("failed_by_qos")
            failed_qos_count = (
                int(failed_by_qos.get(f"qos_{qos_value}") or 0)
                if isinstance(failed_by_qos, dict)
                else 0
            )
            if (
                summary_count != actual_count
                or summary_count + failed_qos_count != expected_qos_count
            ):
                raise RuntimeError(
                    f"{scenario_id}: effective QoS {selected_qos} mismatch for bucket "
                    f"{qos_value}: summary={summary_count}, actual={actual_count}, "
                    f"failed={failed_qos_count}, "
                    f"expected={expected_qos_count}"
                )
    if distribution := selected_distribution:
        publisher_count = 1 if scenario.get("traffic_pattern") == "fanout" else client_count
        expected_qos = _expected_qos_distribution_counts(
            distribution,
            messages_per_publisher=message_count,
            publisher_count=publisher_count,
        )
        actual_object = result.get("qos_distribution_actual")
        if not isinstance(actual_object, dict):
            raise RuntimeError(f"{scenario_id}: QoS distribution metrics missing")
        for qos_value, expected_qos_count in expected_qos.items():
            summary = result.get(f"publish_qos_{qos_value}")
            summary_count = int(summary.get("count") or 0) if isinstance(summary, dict) else 0
            _validate_metric_summary(
                scenario_id,
                result,
                f"publish_qos_{qos_value}",
                expected_count=summary_count,
            )
            actual_count = int(actual_object.get(f"qos_{qos_value}_count") or 0)
            if summary_count != expected_qos_count or actual_count != expected_qos_count:
                raise RuntimeError(
                    f"{scenario_id}: QoS {qos_value} count was "
                    f"summary={summary_count}, actual={actual_count}, expected={expected_qos_count}"
                )

    if scenario.get("attenuation_probe_subscribe_denied") or scenario.get(
        "authorization_probe_subscribe_denied"
    ):
        probes = result.get("authorization_probes")
        successes = int(probes.get("successes") or 0) if isinstance(probes, dict) else 0
        failures = int(probes.get("failures") or 0) if isinstance(probes, dict) else 0
        if successes != client_count or failures != 0:
            raise RuntimeError(
                f"{scenario_id}: attenuation denial probes passed "
                f"{successes}/{client_count} with {failures} failures"
            )

    transform_field = None
    if scenario.get("biscuit_attenuate"):
        transform_field = "attenuation"
    elif scenario.get("biscuit_delegate"):
        transform_field = "delegation"
    if transform_field is not None:
        transform = result.get(transform_field)
        lengths = result.get(f"{transform_field}_len")
        transform_count = int(transform.get("count") or 0) if isinstance(transform, dict) else 0
        length_count = int(lengths.get("count") or 0) if isinstance(lengths, dict) else 0
        if transform_count != client_count or length_count != client_count:
            raise RuntimeError(
                f"{scenario_id}: {transform_field} was applied to "
                f"{transform_count}/{client_count} clients with {length_count} length samples"
            )
        _validate_metric_summary(scenario_id, result, transform_field, expected_count=client_count)
        _validate_metric_summary(
            scenario_id,
            result,
            f"{transform_field}_len",
            expected_count=client_count,
        )
    handoff = (scenario.get("biscuit_delegate") or {}).get("handoff")
    if handoff:
        handoff_publish = result.get("delegation_handoff_publish")
        handoff_count = (
            int(handoff_publish.get("count") or 0) if isinstance(handoff_publish, dict) else 0
        )
        topology = result.get("topology")
        topology_handoff = (
            topology.get("delegation_handoff") if isinstance(topology, dict) else None
        )
        if handoff_count != client_count:
            raise RuntimeError(
                f"{scenario_id}: delegated credentials handed off "
                f"{handoff_count}/{client_count} times"
            )
        _validate_metric_summary(
            scenario_id,
            result,
            "delegation_handoff_publish",
            expected_count=client_count,
        )
        if isinstance(topology_handoff, dict) and (
            int(topology_handoff.get("delegators") or 0) != 1
            or int(topology_handoff.get("delegatees") or 0) != client_count
            or int(topology_handoff.get("qos") or -1) != int(handoff.get("qos", 1))
        ):
            raise RuntimeError(f"{scenario_id}: delegation handoff topology mismatch")

    if scenario.get("complexity_axis") == "datalog":
        inputs = result.get("inputs")
        attestations = inputs.get("credential_attestations") if isinstance(inputs, dict) else None
        attestation = attestations.get("clients") if isinstance(attestations, dict) else None
        semantic = attestation.get("semantic") if isinstance(attestation, dict) else None
        expected_profile = scenario.get("password_map_profile")
        if (
            not isinstance(attestation, dict)
            or attestation.get("profile") != expected_profile
            or int(attestation.get("validated_credentials") or 0) != client_count
            or not isinstance(semantic, dict)
            or semantic.get("token_kind") != "biscuit"
            or semantic.get("complexity_axis") != "datalog"
            or semantic.get("complexity_level") != scenario.get("complexity_level")
            or int(semantic.get("biscuit_blocks") or 0) <= 0
            or int(semantic.get("rules") or 0) <= 0
        ):
            raise RuntimeError(
                f"{scenario_id}: credential attestation does not match "
                f"profile={expected_profile!r} level={scenario.get('complexity_level')!r}"
            )

    if scenario.get("complexity_axis") == "chain_length":
        inputs = result.get("inputs")
        attestations = inputs.get("credential_attestations") if isinstance(inputs, dict) else None
        attestation = attestations.get("clients") if isinstance(attestations, dict) else None
        semantic = attestation.get("semantic") if isinstance(attestation, dict) else None
        expected_depth = 5 if scenario.get("complexity_level") == "med" else 25
        if (
            not isinstance(semantic, dict)
            or semantic.get("token_kind") != "biscuit"
            or semantic.get("complexity_axis") != "chain_length"
            or int(semantic.get("chain_depth") or 0) != expected_depth
            or int(semantic.get("biscuit_blocks") or 0) != expected_depth
        ):
            raise RuntimeError(
                f"{scenario_id}: credential attestation does not prove chain depth {expected_depth}"
            )

    expected_control_count: int | None = None
    if scenario.get("control_mode"):
        expected_control_count = client_count * int(scenario.get("control_repeat", 1))
    elif scenario.get("runtime_control_username"):
        expected_control_count = 1
    elif scenario.get("control_after_messages"):
        interval = int(scenario["control_after_messages"])
        expected_control_count = client_count * (message_count // interval)
    elif scenario.get("fanout_churn_kind"):
        expected_control_count = int(scenario.get("fanout_churn_max_events", 1))
    if expected_control_count is not None:
        _validate_metric_summary(
            scenario_id,
            result,
            "control",
            expected_count=expected_control_count,
        )

    if scenario.get("control_response_topic"):
        response = result.get("control_responses")
        successes = int(response.get("successes") or 0) if isinstance(response, dict) else 0
        failures = int(response.get("failures") or 0) if isinstance(response, dict) else 0
        if scenario.get("control_mode"):
            expected_responses = client_count * int(scenario.get("control_repeat", 1))
        elif scenario.get("runtime_control_username"):
            expected_responses = 1
        else:
            interval = int(scenario.get("control_after_messages", 0))
            expected_responses = client_count * (message_count // interval) if interval else 0
        if successes != expected_responses or failures != 0:
            raise RuntimeError(
                f"{scenario_id}: validated {successes}/{expected_responses} control responses "
                f"with {failures} failures"
            )
        _validate_metric_summary(
            scenario_id,
            result,
            "control_response",
            expected_count=expected_responses,
        )

    if scenario.get("runtime_control_expect_denial"):
        configured_threshold = int(scenario.get("runtime_control_after_messages") or 0)
        runtime_control = result.get("runtime_control")
        raw_metrics = result.get("raw_metrics")
        raw_applied_after = (
            raw_metrics.get("runtime_control_applied_after_successful_publishes")
            if isinstance(raw_metrics, dict)
            else None
        )
        controller_connect_ms = (
            raw_metrics.get("runtime_control_connect_ms") if isinstance(raw_metrics, dict) else None
        )
        topology = result.get("topology")
        topology_mode = topology.get("mode") if isinstance(topology, dict) else None
        supported_topology = topology_mode in {
            "host",
            "container-single",
            "container-per-client",
        }
        runtime_control_metadata_invalid = runtime_control is not None and (
            not isinstance(runtime_control, dict)
            or runtime_control.get("enabled") is not True
            or runtime_control.get("applied_after_successful_publishes") != configured_threshold
        )
        if topology_mode == "container-per-client":
            runtime_control_metadata_invalid = runtime_control_metadata_invalid or (
                not isinstance(runtime_control, dict)
                or int(runtime_control.get("participants") or 0) != client_count
                or int(runtime_control.get("ready_count") or 0) != client_count
            )
        if (
            not supported_topology
            or runtime_control_metadata_invalid
            or isinstance(raw_applied_after, bool)
            or not isinstance(raw_applied_after, int)
            or raw_applied_after != configured_threshold
            or publish_count != configured_threshold
            or _policy_denial_count(result) != client_count
            or attempted_count != configured_threshold + client_count
            or succeeded_count != configured_threshold
            or failed_count != client_count
            or isinstance(controller_connect_ms, bool)
            or not isinstance(controller_connect_ms, int | float)
            or not math.isfinite(float(controller_connect_ms))
            or float(controller_connect_ms) < 0
        ):
            raise RuntimeError(
                f"{scenario_id}: Dynamic Security churn phase contract failed: "
                f"published={publish_count}, denials={_policy_denial_count(result)}, "
                f"topology={topology_mode!r}, runtime_control={runtime_control}, "
                f"raw_applied_after={raw_applied_after!r}"
            )

    if scenario.get("fanout_expect_control_notification"):
        effect = result.get("control_effect")
        notifications = int(effect.get("notifications") or 0) if isinstance(effect, dict) else 0
        if notifications != client_count:
            raise RuntimeError(
                f"{scenario_id}: received {notifications}/{client_count} control notifications"
            )

    if scenario.get("traffic_pattern") != "fanout":
        return

    receive = result.get("receive")
    receive_count = int(receive.get("count") or 0) if isinstance(receive, dict) else 0
    _validate_metric_summary(
        scenario_id,
        result,
        "receive",
        expected_count=receive_count,
    )
    _validate_throughput(
        scenario_id,
        result,
        "receive_throughput_mps",
        require_positive=receive_count > 0,
    )
    _validate_throughput(
        scenario_id,
        result,
        "throughput_mps",
        require_positive=receive_count > 0,
    )
    contract = scenario.get("delivery_contract")
    if not isinstance(contract, dict):
        raise RuntimeError(f"{scenario_id}: fan-out delivery contract missing")
    steady_expectation = contract.get("steady")
    phase_expectations = contract.get("phases")
    if (steady_expectation is None) == (phase_expectations is None):
        raise RuntimeError(f"{scenario_id}: fan-out delivery contract must select steady or phases")
    expected_count = message_count * client_count
    if steady_expectation == "all" and receive_count != expected_count:
        raise RuntimeError(f"{scenario_id}: received {receive_count}/{expected_count} deliveries")
    if steady_expectation == "none" and receive_count != 0:
        raise RuntimeError(f"{scenario_id}: expected no deliveries, got {receive_count}")

    if phase_expectations is None:
        return

    churn = result.get("fanout_churn")
    if not isinstance(churn, dict) or churn.get("enabled") is not True:
        raise RuntimeError(f"{scenario_id}: fanout churn metadata missing")
    if churn.get("triggered") is not True or int(churn.get("applied_events") or 0) <= 0:
        raise RuntimeError(f"{scenario_id}: fanout churn did not trigger")
    phases = churn.get("phases")
    applied_events = int(churn.get("applied_events") or 0)
    expected_events = int(scenario.get("fanout_churn_max_events", 1))
    required_phase_count = applied_events + 1
    control = result.get("control")
    control_count = int(control.get("count") or 0) if isinstance(control, dict) else 0
    if (
        applied_events != expected_events
        or int(churn.get("control_count") or 0) != expected_events
        or control_count != expected_events
        or not isinstance(phases, list)
        or len(phases) != required_phase_count
        or len(phases) != len(phase_expectations)
    ):
        raise RuntimeError(f"{scenario_id}: fanout churn phase metadata is incomplete")
    for index, (phase, expectation) in enumerate(zip(phases, phase_expectations, strict=False)):
        if not isinstance(phase, dict):
            raise RuntimeError(f"{scenario_id}: invalid fanout churn phase {index}")
        expected = int(phase.get("expected_deliveries") or 0)
        received = int(phase.get("received_deliveries") or 0)
        duration_ms = phase.get("duration_ms")
        if (
            isinstance(duration_ms, bool)
            or not isinstance(duration_ms, int | float)
            or not math.isfinite(float(duration_ms))
            or float(duration_ms) < 0
        ):
            raise RuntimeError(f"{scenario_id}: churn phase {index} duration is invalid")
        if expectation == "all" and received != expected:
            raise RuntimeError(
                f"{scenario_id}: churn phase {index} received {received}/{expected} deliveries"
            )
        if expectation == "none" and received != 0:
            raise RuntimeError(
                f"{scenario_id}: churn phase {index} expected no deliveries, got {received}"
            )


def _merge_fanout_role_loadgen_results(
    *,
    publisher: dict[str, Any],
    subscribers: list[dict[str, Any]],
    wall_duration_s: float,
    scenario_id: str,
    run_index: int,
    messages: int,
) -> dict[str, Any]:
    merged = _merge_per_client_loadgen_results([publisher, *subscribers], wall_duration_s)
    expected_clock = {"source": "clock_monotonic_raw", "payload_version": "v3"}
    clock_attestations = [
        result.get("inputs", {}).get("fanout_latency_clock") for result in [publisher, *subscribers]
    ]
    if any(attestation != expected_clock for attestation in clock_attestations):
        cast(list[str], merged.setdefault("errors", [])).append(
            "fanout_latency_clock_attestation_mismatch"
        )
    subscriber_count = len(subscribers)
    merged_inputs = merged.get("inputs")
    merged_attestations = (
        merged_inputs.get("credential_attestations") if isinstance(merged_inputs, dict) else None
    )
    source_attestations = [
        result.get("inputs", {}).get("credential_attestations")
        for result in [publisher, *subscribers]
    ]
    if any(bool(attestations) for attestations in source_attestations):
        expected_credential_counts = {"clients": subscriber_count, "fanout_publisher": 1}
        for role, expected_count in expected_credential_counts.items():
            attestation = (
                merged_attestations.get(role) if isinstance(merged_attestations, dict) else None
            )
            if not isinstance(attestation, dict):
                cast(list[str], merged.setdefault("errors", [])).append(
                    f"credential_attestation_missing:{role}"
                )
            elif int(attestation.get("validated_credentials") or 0) != expected_count:
                cast(list[str], merged.setdefault("errors", [])).append(
                    f"credential_attestation_count_mismatch:{role}"
                )
    received_count = int(merged.get("receive", {}).get("count") or 0)
    expected = messages * subscriber_count
    merged["received_messages"] = {"count": received_count, "expected": expected}
    duration_s = max(wall_duration_s, 1e-9)
    publish_count = int(merged.get("publish", {}).get("count") or 0)
    merged["publish_throughput_mps"] = float(publish_count / duration_s)
    merged["receive_throughput_mps"] = float(received_count / duration_s)
    merged["throughput_mps"] = merged["receive_throughput_mps"]

    publisher_churn = publisher.get("fanout_churn")
    if isinstance(publisher_churn, dict):
        churn = dict(publisher_churn)
        enabled = bool(churn.get("enabled"))
        if enabled:
            publisher_phases = churn.get("phases")
            after = int(churn.get("after_messages") or 0)
            interval = int(churn.get("interval_messages") or 0)
            applied = int(churn.get("applied_events") or 0)
            phase_publishes = [0]
            phase = 0
            for sequence_id in range(messages):
                is_boundary = sequence_id == after or (
                    interval > 0 and sequence_id > after and (sequence_id - after) % interval == 0
                )
                if is_boundary and phase < applied:
                    phase += 1
                    phase_publishes.append(0)
                phase_publishes[phase] += 1
            received_by_phase = [0] * len(phase_publishes)
            for result in subscribers:
                subscriber_churn = result.get("fanout_churn")
                phases = (
                    subscriber_churn.get("phases", []) if isinstance(subscriber_churn, dict) else []
                )
                if not isinstance(phases, list):
                    continue
                for index, entry in enumerate(phases):
                    if index < len(received_by_phase) and isinstance(entry, dict):
                        received_by_phase[index] += int(entry.get("received_deliveries") or 0)
            churn["phases"] = [
                {
                    "phase": index,
                    "expected_deliveries": publishes * subscriber_count,
                    "received_deliveries": received_by_phase[index],
                    "duration_ms": (
                        publisher_phases[index].get("duration_ms")
                        if isinstance(publisher_phases, list)
                        and index < len(publisher_phases)
                        and isinstance(publisher_phases[index], dict)
                        else None
                    ),
                }
                for index, publishes in enumerate(phase_publishes)
            ]
        merged["fanout_churn"] = churn

    inputs = merged.get("inputs")
    if isinstance(inputs, dict):
        merged["inputs"] = {
            **inputs,
            "clients": subscriber_count,
            "fanout_role": "merged",
        }
    merged["topology"] = {
        "mode": "container-per-client",
        "container_count": subscriber_count + 1,
        "aggregation": "merged_from_fanout_role_containers",
        "wall_duration_s": wall_duration_s,
        "scenario_id": scenario_id,
        "run_index": run_index,
        "fanout_roles": {
            "publishers": 1,
            "subscribers": subscriber_count,
        },
    }
    return merged


def _merge_delegation_handoff_loadgen_results(
    *,
    delegator: dict[str, Any],
    delegatees: list[dict[str, Any]],
    wall_duration_s: float,
    benchmark_duration_s: float,
    scenario_id: str,
    run_index: int,
    run_id: str,
    handoff_topic: str,
    handoff_qos: int,
    handoff_retain: bool,
) -> dict[str, Any]:
    merged = _merge_per_client_loadgen_results(
        [delegator, *delegatees],
        benchmark_duration_s,
    )
    delegatee_count = len(delegatees)
    inputs = merged.get("inputs")
    if isinstance(inputs, dict):
        merged["inputs"] = {
            **inputs,
            "clients": delegatee_count,
            "biscuit_delegate_handoff_role": "merged",
            "biscuit_delegate_handoff_nonce": _redact_run_id(run_id),
        }
    duration_s = max(benchmark_duration_s, 1e-9)
    publish_count = int(merged.get("publish", {}).get("count") or 0)
    merged["publish_throughput_mps"] = float(publish_count / duration_s)
    merged["throughput_mps"] = merged["publish_throughput_mps"]
    merged["topology"] = {
        "mode": "container-per-client",
        "container_count": delegatee_count + 1,
        "aggregation": "merged_from_delegation_handoff_role_containers",
        "wall_duration_s": wall_duration_s,
        "benchmark_duration_s": benchmark_duration_s,
        "scenario_id": scenario_id,
        "run_index": run_index,
        "delegation_handoff": {
            "delegators": 1,
            "delegatees": delegatee_count,
            "topic": handoff_topic,
            "qos": handoff_qos,
            "retain": handoff_retain,
            "run_id": _redact_run_id(run_id),
        },
    }
    return merged


def _cleanup_per_client_loadgen_processes(
    processes: list[tuple[str, subprocess.Popen[str]]],
    completed: set[str],
) -> None:
    for container_name, process in processes:
        if container_name in completed:
            continue
        if process.poll() is None:
            process.terminate()
    for container_name, process in processes:
        if container_name in completed:
            continue
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)
    for container_name, _process in processes:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


def _run_loadgen_container_per_client(
    loadgen_args: list[str],
    *,
    clients: int,
    service: str,
    scenario_id: str,
    run_index: int,
    compose_files: list[str] | None,
    compose_project_name: str | None,
    extra_env: dict[str, str],
    sync_connect: bool,
    runtime_control: PerClientRuntimeControl | None = None,
) -> dict[str, Any]:
    build_cmd = _compose_cmd(
        ["build", service],
        compose_files=compose_files,
        compose_project_name=compose_project_name,
    )
    env = os.environ.copy()
    env.update(extra_env)
    subprocess.run(build_cmd, cwd=REPO_ROOT, env=env, check=True)
    barrier_run_id = _sync_barrier_run_id(scenario_id, run_index) if sync_connect else None
    runtime_control_run_id = (
        _sync_barrier_run_id(f"{scenario_id}-runtime-control", run_index)
        if runtime_control is not None
        else None
    )
    if barrier_run_id is not None or runtime_control_run_id is not None:
        _ensure_sync_barrier_service(
            compose_files=compose_files,
            compose_project_name=compose_project_name,
        )
    publisher_args = list(loadgen_args)
    if runtime_control is not None:
        for option in (
            "--runtime-control-username",
            "--runtime-control-password",
            "--runtime-control-after-messages",
            "--control-topic",
            "--control-payload",
            "--control-payload-file",
            "--control-response-topic",
        ):
            publisher_args = _remove_cli_option(publisher_args, option)
        publisher_args = _remove_cli_flag(
            publisher_args,
            "--runtime-control-expect-denial",
        )
    messages = _int_cli_option_value(loadgen_args, "--messages", 0)
    if runtime_control is not None:
        publish_capacity = clients * messages
        if runtime_control.after_messages > publish_capacity:
            raise RuntimeError(
                "runtime control after-messages "
                f"({runtime_control.after_messages}) exceeds configured publish capacity "
                f"({publish_capacity})"
            )
        if runtime_control.expect_denial and runtime_control.after_messages >= publish_capacity:
            raise RuntimeError(
                "runtime control expected-denial mode requires after-messages "
                f"({runtime_control.after_messages}) to be below configured publish capacity "
                f"({publish_capacity})"
            )
        if not _cli_option_value(loadgen_args, "--control-topic"):
            raise RuntimeError("runtime control requires --control-topic")
    quotas = (
        _runtime_control_quotas(
            clients=clients,
            after_messages=runtime_control.after_messages,
        )
        if runtime_control is not None
        else []
    )

    started_at = time.monotonic()
    processes: list[tuple[str, subprocess.Popen[str]]] = []
    for index in range(clients):
        args = _replace_cli_option(publisher_args, "--clients", "1")
        args = _replace_cli_option(args, "--client-index-start", str(index + 1))
        if barrier_run_id is not None:
            args = _append_sync_barrier_args(
                args,
                run_id=barrier_run_id,
                participant_id=f"client_{index + 1}",
                participants=clients,
            )
        if runtime_control_run_id is not None:
            args = _append_runtime_control_barrier_args(
                args,
                run_id=runtime_control_run_id,
                participant_id=f"client_{index + 1}",
                participants=clients,
                local_after_messages=quotas[index],
            )
            if (
                runtime_control is not None
                and runtime_control.expect_denial
                and quotas[index] < messages
            ):
                args.append("--runtime-control-expect-denial")
        container_name = _loadgen_container_name(
            compose_project_name=compose_project_name,
            compose_files=compose_files,
            scenario_id=scenario_id,
            run_index=run_index,
            client_index=index,
        )
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        cmd = _compose_run_loadgen_cmd(
            args,
            service=service,
            container_name=container_name,
            compose_files=compose_files,
            compose_project_name=compose_project_name,
            build=False,
        )
        processes.append(
            (
                container_name,
                subprocess.Popen(
                    cmd,
                    cwd=REPO_ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ),
            )
        )

    results: list[dict[str, Any]] = []
    completed: set[str] = set()
    barrier_status: dict[str, Any] | None = None
    runtime_control_status: dict[str, Any] | None = None
    controller_result: dict[str, Any] | None = None
    try:
        if barrier_run_id is not None:
            _wait_for_sync_barrier_ready(
                barrier_run_id,
                participants=clients,
                processes=processes,
            )
            barrier_status = _release_sync_barrier(barrier_run_id, participants=clients)
        if runtime_control_run_id is not None and runtime_control is not None:
            _wait_for_sync_barrier_ready(
                runtime_control_run_id,
                participants=clients,
                processes=processes,
            )
            controller_args = list(loadgen_args)
            for option in (
                "--runtime-control-username",
                "--runtime-control-password",
                "--runtime-control-after-messages",
                "--password-map",
                "--password-map-profile",
                "--fanout-publisher-password-map-profile",
            ):
                controller_args = _remove_cli_option(controller_args, option)
            controller_args = _remove_cli_flag(
                controller_args,
                "--runtime-control-expect-denial",
            )
            controller_args = _remove_cli_flag(controller_args, "--sync-connect")
            controller_args = _replace_cli_option(controller_args, "--clients", "1")
            controller_args = _replace_cli_option(
                controller_args,
                "--client-index-start",
                str(clients + 1),
            )
            controller_args = _replace_cli_option(
                controller_args,
                "--client-id",
                "runtime-dynsec-controller",
            )
            controller_args = _replace_cli_option(
                controller_args,
                "--username",
                runtime_control.username,
            )
            controller_args = _replace_cli_option(
                controller_args,
                "--password",
                runtime_control.password,
            )
            if "--control-mode" not in controller_args:
                controller_args.append("--control-mode")
            controller_name = _loadgen_container_name(
                compose_project_name=compose_project_name,
                compose_files=compose_files,
                scenario_id=f"{scenario_id}-runtime-controller",
                run_index=run_index,
            )
            subprocess.run(
                ["docker", "rm", "-f", controller_name],
                cwd=REPO_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            controller_cmd = _compose_run_loadgen_cmd(
                controller_args,
                service=service,
                container_name=controller_name,
                compose_files=compose_files,
                compose_project_name=compose_project_name,
                build=False,
            )
            controller_completed = subprocess.run(
                controller_cmd,
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            if controller_completed.returncode != 0:
                raise RuntimeError(
                    f"runtime control container {controller_name} failed with exit code "
                    f"{controller_completed.returncode}: {controller_completed.stderr}"
                )
            controller_result = _loads_json_from_compose_stdout(controller_completed.stdout)
            if controller_result.get("errors"):
                raise RuntimeError(
                    f"runtime control container {controller_name} reported errors: "
                    f"{controller_result['errors']}"
                )
            if not _raw_metric_values(controller_result, "control"):
                raise RuntimeError(
                    f"runtime control container {controller_name} did not publish a control command"
                )
            runtime_control_status = _release_sync_barrier(
                runtime_control_run_id,
                participants=clients,
            )
        for container_name, process in processes:
            stdout, stderr = process.communicate()
            completed.add(container_name)
            if process.returncode != 0:
                raise RuntimeError(
                    f"loadgen container {container_name} failed with exit code "
                    f"{process.returncode}: {stderr}"
                )
            result = _loads_json_from_compose_stdout(stdout)
            result["container_name"] = container_name
            results.append(result)
    except Exception:
        _cleanup_per_client_loadgen_processes(processes, completed)
        raise
    wall_duration_s = time.monotonic() - started_at
    merged = _merge_per_client_loadgen_results(results, wall_duration_s)
    merged["topology"]["scenario_id"] = scenario_id
    merged["topology"]["run_index"] = run_index
    if controller_result is not None and runtime_control is not None:
        controller_connect = _raw_metric_values(controller_result, "connect")
        controller_control = _raw_metric_values(controller_result, "control")
        controller_response = _raw_metric_values(controller_result, "control_response")
        raw_metrics = cast(dict[str, Any], merged["raw_metrics"])
        raw_metrics["runtime_control_connect_ms"] = (
            controller_connect[0] if controller_connect else None
        )
        raw_metrics["runtime_control_applied_after_successful_publishes"] = sum(quotas)
        raw_metrics["control"] = [
            *cast(list[float], raw_metrics.get("control", [])),
            *controller_control,
        ]
        raw_metrics["control_response"] = [
            *cast(list[float], raw_metrics.get("control_response", [])),
            *controller_response,
        ]
        merged["control"] = _summary_from_values(cast(list[float], raw_metrics["control"]))
        merged["control_response"] = _summary_from_values(
            cast(list[float], raw_metrics["control_response"])
        )
        controller_responses = controller_result.get("control_responses")
        merged["control_responses"] = (
            dict(controller_responses) if isinstance(controller_responses, dict) else {}
        )
        merged["runtime_control"] = {
            "enabled": True,
            "barrier": "external",
            "run_id": runtime_control_run_id,
            "participants": clients,
            "ready_count": int((runtime_control_status or {}).get("ready_count") or 0),
            "released_at_unix_ms": (runtime_control_status or {}).get("released_at_unix_ms"),
            "after_messages": runtime_control.after_messages,
            "applied_after_successful_publishes": sum(quotas),
            "local_quotas": quotas,
            "controller_connect_ms": raw_metrics["runtime_control_connect_ms"],
        }
        if runtime_control.expect_denial and int(merged.get("policy_denial_count") or 0) == 0:
            merged["errors"].append("runtime_control_expected_policy_denial_not_observed")
    if barrier_run_id is not None:
        merged["sync_connect"] = {
            "enabled": True,
            "barrier": "external",
            "run_id": barrier_run_id,
            "participants": clients,
            "ready_count": int((barrier_status or {}).get("ready_count") or 0),
            "released_at_unix_ms": (barrier_status or {}).get("released_at_unix_ms"),
            "max_ready_skew_ms": (barrier_status or {}).get("max_ready_skew_ms"),
            "client_wait": merged.get("sync_connect_barrier_wait", {}),
            "errors": [err for err in merged.get("errors", []) if str(err).startswith("sync_")],
        }
    return merged


def _run_loadgen_container_per_client_delegation_handoff(
    loadgen_args: list[str],
    *,
    clients: int,
    service: str,
    scenario_id: str,
    run_index: int,
    compose_files: list[str] | None,
    compose_project_name: str | None,
    extra_env: dict[str, str],
    handoff_topic: str,
    handoff_qos: int,
    handoff_retain: bool,
) -> dict[str, Any]:
    build_cmd = _compose_cmd(
        ["build", service],
        compose_files=compose_files,
        compose_project_name=compose_project_name,
    )
    env = os.environ.copy()
    env.update(extra_env)
    subprocess.run(build_cmd, cwd=REPO_ROOT, env=env, check=True)

    ready_host_dir = _delegation_handoff_ready_host_dir(scenario_id, run_index)
    if ready_host_dir.exists():
        shutil.rmtree(ready_host_dir)
    ready_host_dir.mkdir(parents=True)
    ready_container_dir = _container_repo_path(str(ready_host_dir))
    if ready_container_dir is None:
        raise RuntimeError(
            f"delegation handoff ready directory is not under repo root: {ready_host_dir}"
        )
    run_id = _delegation_handoff_run_id(scenario_id, run_index)
    ready_timeout_seconds = _int_cli_option_value(
        loadgen_args,
        "--biscuit-delegate-handoff-ready-timeout-seconds",
        120,
    )

    started_at = time.monotonic()
    processes: list[tuple[str, subprocess.Popen[str]]] = []
    for index in range(clients):
        args = _replace_cli_option(loadgen_args, "--clients", "1")
        args = _replace_cli_option(args, "--client-index-start", str(index + 1))
        args = _replace_cli_option(args, "--biscuit-delegate-handoff-role", "delegatee")
        args = _replace_cli_option(args, "--biscuit-delegate-handoff-nonce", run_id)
        args = _replace_cli_option(
            args,
            "--biscuit-delegate-handoff-ready-dir",
            ready_container_dir,
        )
        args = _replace_cli_option(
            args,
            "--biscuit-delegate-handoff-ready-timeout-seconds",
            str(ready_timeout_seconds),
        )
        container_name = _loadgen_container_name(
            compose_project_name=compose_project_name,
            compose_files=compose_files,
            scenario_id=f"{scenario_id}_delegation_delegatee",
            run_index=run_index,
            client_index=index,
        )
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        cmd = _compose_run_loadgen_cmd(
            args,
            service=service,
            container_name=container_name,
            compose_files=compose_files,
            compose_project_name=compose_project_name,
            build=False,
        )
        processes.append(
            (
                container_name,
                subprocess.Popen(
                    cmd,
                    cwd=REPO_ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ),
            )
        )

    completed: set[str] = set()
    try:
        _wait_for_delegation_handoff_ready_files(
            ready_host_dir,
            clients=clients,
            processes=processes,
            timeout_seconds=ready_timeout_seconds,
        )
        benchmark_started_at = time.monotonic()
        delegator_args = _replace_cli_option(loadgen_args, "--clients", str(clients))
        delegator_args = _replace_cli_option(delegator_args, "--client-index-start", "1")
        delegator_args = _replace_cli_option(
            delegator_args,
            "--biscuit-delegate-handoff-role",
            "delegator",
        )
        delegator_args = _replace_cli_option(
            delegator_args,
            "--biscuit-delegate-handoff-nonce",
            run_id,
        )
        delegator_args = _replace_cli_option(
            delegator_args,
            "--biscuit-delegate-handoff-ready-dir",
            ready_container_dir,
        )
        delegator_args = _replace_cli_option(
            delegator_args,
            "--biscuit-delegate-handoff-ready-timeout-seconds",
            str(ready_timeout_seconds),
        )
        delegator_name = _loadgen_container_name(
            compose_project_name=compose_project_name,
            compose_files=compose_files,
            scenario_id=f"{scenario_id}_delegation_delegator",
            run_index=run_index,
        )
        subprocess.run(
            ["docker", "rm", "-f", delegator_name],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        delegator_cmd = _compose_run_loadgen_cmd(
            delegator_args,
            service=service,
            container_name=delegator_name,
            compose_files=compose_files,
            compose_project_name=compose_project_name,
            build=False,
        )
        delegator_completed = subprocess.run(
            delegator_cmd,
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        delegator_result = _loads_json_from_compose_stdout(delegator_completed.stdout)
        delegator_result["container_name"] = delegator_name
        delegator_result["delegation_handoff_role"] = "delegator"

        delegatee_results: list[dict[str, Any]] = []
        for container_name, process in processes:
            stdout, stderr = process.communicate()
            completed.add(container_name)
            if process.returncode != 0:
                raise RuntimeError(
                    f"loadgen container {container_name} failed with exit code "
                    f"{process.returncode}: {stderr}"
                )
            result = _loads_json_from_compose_stdout(stdout)
            result["container_name"] = container_name
            result["delegation_handoff_role"] = "delegatee"
            delegatee_results.append(result)
    except Exception:
        _cleanup_per_client_loadgen_processes(processes, completed)
        raise

    finished_at = time.monotonic()
    wall_duration_s = finished_at - started_at
    benchmark_duration_s = finished_at - benchmark_started_at
    return _merge_delegation_handoff_loadgen_results(
        delegator=delegator_result,
        delegatees=delegatee_results,
        wall_duration_s=wall_duration_s,
        benchmark_duration_s=benchmark_duration_s,
        scenario_id=scenario_id,
        run_index=run_index,
        run_id=run_id,
        handoff_topic=handoff_topic,
        handoff_qos=handoff_qos,
        handoff_retain=handoff_retain,
    )


def _run_loadgen_container_per_client_fanout(
    loadgen_args: list[str],
    *,
    clients: int,
    messages: int,
    service: str,
    scenario_id: str,
    run_index: int,
    compose_files: list[str] | None,
    compose_project_name: str | None,
    extra_env: dict[str, str],
) -> dict[str, Any]:
    build_cmd = _compose_cmd(
        ["build", service],
        compose_files=compose_files,
        compose_project_name=compose_project_name,
    )
    env = os.environ.copy()
    env.update(extra_env)
    subprocess.run(build_cmd, cwd=REPO_ROOT, env=env, check=True)

    ready_host_dir = _fanout_ready_host_dir(scenario_id, run_index)
    if ready_host_dir.exists():
        shutil.rmtree(ready_host_dir)
    ready_host_dir.mkdir(parents=True)
    ready_container_dir = _container_repo_path(str(ready_host_dir))
    if ready_container_dir is None:
        raise RuntimeError(f"fanout ready directory is not under repo root: {ready_host_dir}")

    started_at = time.monotonic()
    processes: list[tuple[str, subprocess.Popen[str]]] = []
    for index in range(clients):
        args = _replace_cli_option(loadgen_args, "--clients", "1")
        args = _replace_cli_option(args, "--client-index-start", str(index + 1))
        args = _replace_cli_option(args, "--fanout-role", "subscriber")
        args = _append_cli_option(args, "--fanout-ready-dir", ready_container_dir)
        container_name = _loadgen_container_name(
            compose_project_name=compose_project_name,
            compose_files=compose_files,
            scenario_id=f"{scenario_id}_fanout_subscriber",
            run_index=run_index,
            client_index=index,
        )
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        cmd = _compose_run_loadgen_cmd(
            args,
            service=service,
            container_name=container_name,
            compose_files=compose_files,
            compose_project_name=compose_project_name,
            build=False,
        )
        processes.append(
            (
                container_name,
                subprocess.Popen(
                    cmd,
                    cwd=REPO_ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                ),
            )
        )

    completed: set[str] = set()
    try:
        _wait_for_fanout_ready_files(ready_host_dir, clients=clients)
        publisher_args = _replace_cli_option(loadgen_args, "--clients", str(clients))
        publisher_args = _replace_cli_option(publisher_args, "--client-index-start", "1")
        publisher_args = _replace_cli_option(publisher_args, "--fanout-role", "publisher")
        publisher_args = _append_cli_option(
            publisher_args,
            "--fanout-ready-dir",
            ready_container_dir,
        )
        publisher_name = _loadgen_container_name(
            compose_project_name=compose_project_name,
            compose_files=compose_files,
            scenario_id=f"{scenario_id}_fanout_publisher",
            run_index=run_index,
        )
        subprocess.run(
            ["docker", "rm", "-f", publisher_name],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        publisher_cmd = _compose_run_loadgen_cmd(
            publisher_args,
            service=service,
            container_name=publisher_name,
            compose_files=compose_files,
            compose_project_name=compose_project_name,
            build=False,
        )
        publisher_completed = subprocess.run(
            publisher_cmd,
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        publisher_result = _loads_json_from_compose_stdout(publisher_completed.stdout)
        publisher_result["container_name"] = publisher_name
        publisher_result["fanout_role"] = "publisher"

        subscriber_results: list[dict[str, Any]] = []
        for container_name, process in processes:
            stdout, stderr = process.communicate()
            completed.add(container_name)
            if process.returncode != 0:
                raise RuntimeError(
                    f"loadgen container {container_name} failed with exit code "
                    f"{process.returncode}: {stderr}"
                )
            result = _loads_json_from_compose_stdout(stdout)
            result["container_name"] = container_name
            result["fanout_role"] = "subscriber"
            subscriber_results.append(result)
    except Exception:
        (ready_host_dir / "publisher.done").write_text(
            json.dumps({"done": True, "forced_by_runner": True}),
            encoding="utf-8",
        )
        _cleanup_per_client_loadgen_processes(processes, completed)
        raise

    wall_duration_s = time.monotonic() - started_at
    return _merge_fanout_role_loadgen_results(
        publisher=publisher_result,
        subscribers=subscriber_results,
        wall_duration_s=wall_duration_s,
        scenario_id=scenario_id,
        run_index=run_index,
        messages=messages,
    )


def _apply_dynamic_security_config(source_path: str):
    policy_churn.apply_dynsec_snapshot(source_path)


def _generate_dynamic_security_config(profile: str) -> str:
    return policy_churn.generate_dynsec_snapshot(profile)


def _capture_dynamic_security_baseline() -> bytes | None:
    path = _resolve_repo_path("docker/dynamic-security.json")
    try:
        with path.open("rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def _restore_dynamic_security_baseline(snapshot: bytes | None) -> None:
    path = _resolve_repo_path("docker/dynamic-security.json")
    if snapshot is None:
        path.unlink(missing_ok=True)
        return
    with path.open("wb") as f:
        f.write(snapshot)


def _scenario_uses_dynamic_security(scenario: ScenarioConfig) -> bool:
    return (
        "mosquitto_dynsec.conf" in str(scenario.get("mosquitto_conf") or "")
        or bool(scenario.get("dynamic_security_config"))
        or bool(scenario.get("dynamic_security_generated_profile"))
        or bool(scenario.get("runtime_control_username"))
    )


@contextmanager
def _dynamic_security_scenario_config(
    scenario: ScenarioConfig,
    *,
    extra_env: dict[str, str] | None = None,
    compose_files: list[str] | None = None,
    host: str = "localhost",
    port: int = 1883,
) -> Iterator[DynamicSecurityScenarioState]:
    baseline = _capture_dynamic_security_baseline()
    generated_path: str | None = None
    state = DynamicSecurityScenarioState(generated_path=None)
    try:
        if scenario.get("dynamic_security_generated_profile"):
            generated_path = _generate_dynamic_security_config(
                cast(str, scenario["dynamic_security_generated_profile"])
            )
            state.generated_path = generated_path
            _apply_dynamic_security_config(generated_path)
        elif scenario.get("dynamic_security_config"):
            _apply_dynamic_security_config(cast(str, scenario["dynamic_security_config"]))
        yield state
    finally:
        policy_churn.cleanup_dynsec_snapshot(generated_path)
        _restore_dynamic_security_baseline(baseline)
        if (
            state.broker_started
            and _scenario_uses_dynamic_security(scenario)
            and extra_env is not None
            and compose_files is not None
        ):
            _restart_mosquitto(
                extra_env=extra_env,
                compose_files=compose_files,
                host=host,
                port=port,
            )


def _wait_for_mqtt_listener(host: str, port: int, *, timeout_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError(f"timed out waiting for Mosquitto listener at {host}:{port}: {last_error!r}")


def _seed_sqlite_scenario_policy(
    scenario: ScenarioConfig,
    *,
    default_clients: int,
    allow_replace: bool,
) -> None:
    db_path = str(scenario.get("sqlite_seed_db", "docker/sqlite/policy.db"))
    resolved_db_path = _resolve_repo_path(db_path)
    resolved_db_path.parent.mkdir(parents=True, exist_ok=True)
    resolved_db_path.parent.chmod(0o777)

    def seed() -> None:
        policy_churn.seed_sqlite_fanout_policy(
            db_path,
            topic=str(
                scenario.get(
                    "sqlite_seed_topic",
                    scenario.get("fanout_topic", "fanout/broadcast"),
                )
            ),
            subscriber_count=int(
                scenario.get(
                    "sqlite_seed_subscribers",
                    scenario.get("subscriber_count", default_clients),
                )
            ),
            profile=str(scenario.get("sqlite_seed_profile", "fanout_basic")),
        )

    try:
        seed()
    except sqlite3.OperationalError as exc:
        if not allow_replace or "readonly" not in str(exc).lower():
            raise
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{resolved_db_path}{suffix}")
            if candidate.exists():
                candidate.unlink()
        seed()

    resolved_db_path.chmod(0o666)


def _restart_mosquitto(
    *,
    extra_env: dict[str, str],
    compose_files: list[str],
    host: str,
    port: int,
) -> None:
    _compose(
        ["restart", "mosquitto"],
        extra_env=extra_env,
        compose_files=compose_files,
    )
    _wait_for_mqtt_listener(host, port)


def _reset_generated_dynamic_security_between_repeats(
    run_index: int,
    generated_path: str | None,
    *,
    extra_env: dict[str, str],
    compose_files: list[str],
    host: str,
    port: int,
) -> None:
    if run_index == 0 or generated_path is None:
        return
    _apply_dynamic_security_config(generated_path)
    _restart_mosquitto(
        extra_env=extra_env,
        compose_files=compose_files,
        host=host,
        port=port,
    )


def _resolve_repo_path(path: str | Path) -> Path:
    resolved_path = Path(path)
    if resolved_path.is_absolute():
        return resolved_path
    return REPO_ROOT / resolved_path


def _resolve_compose_path(path: str | Path) -> Path:
    resolved_path = Path(path)
    if resolved_path.is_absolute():
        return resolved_path
    relative = str(resolved_path)
    if relative.startswith("./"):
        relative = relative[2:]
    return REPO_ROOT / "docker" / relative


def _load_dynamic_security_snapshot(path: str) -> dict[str, Any]:
    resolved = _resolve_repo_path(path)
    try:
        with resolved.open(encoding="utf-8") as f:
            payload = json.load(f)
    except FileNotFoundError as exc:
        raise ValueError(f"dynamic security snapshot file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"dynamic security snapshot parse failed: {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"dynamic security snapshot must be a JSON object: {path}")
    return payload


def _effective_scenario_client_count(scenario: ScenarioConfig, default_clients: int) -> int:
    return int(scenario.get("client_count", scenario.get("subscriber_count", default_clients)))


WorkloadShape = Literal["matrix", "fixed-clients", "fixed-messages", "fixed"]


def _scenario_workload_shape(scenario: ScenarioConfig) -> WorkloadShape:
    """Describe which workload axes are supplied by the scenario definition.

    Fan-out ``subscriber_count`` fixes the client axis, but does not fix the
    independent message axis. Keeping the axes separate prevents partially
    specified scenarios from silently dropping matrix levels.
    """
    clients_fixed = "client_count" in scenario or "subscriber_count" in scenario
    messages_fixed = "message_count" in scenario
    if clients_fixed and messages_fixed:
        return "fixed"
    if clients_fixed:
        return "fixed-clients"
    if messages_fixed:
        return "fixed-messages"
    return "matrix"


def _scenario_workload_axes(scenario: ScenarioConfig) -> dict[str, Literal["scenario", "cli"]]:
    shape = _scenario_workload_shape(scenario)
    return {
        "clients": "scenario" if shape in {"fixed-clients", "fixed"} else "cli",
        "messages": "scenario" if shape in {"fixed-messages", "fixed"} else "cli",
    }


def _effective_scenario_message_count(
    scenario: ScenarioConfig,
    default_messages: int,
    *,
    effective_clients: int | None = None,
) -> int:
    configured = int(scenario.get("message_count", default_messages))
    minimum = int(scenario.get("control_after_messages", 0))
    fanout_churn_after = int(scenario.get("fanout_churn_after_messages", 0))
    if scenario.get("fanout_churn_kind") and fanout_churn_after > 0:
        interval = int(scenario.get("fanout_churn_interval_messages", 0))
        max_events = int(scenario.get("fanout_churn_max_events", 1))
        last_event = fanout_churn_after + interval * max(max_events - 1, 0)
        minimum = max(minimum, last_event + 1)
    runtime_control_after = int(scenario.get("runtime_control_after_messages", 0))
    if runtime_control_after > 0 and effective_clients is not None:
        post_control_publishes = 1 if scenario.get("runtime_control_expect_denial") else 0
        minimum = max(
            minimum,
            math.ceil(runtime_control_after / effective_clients) + post_control_publishes,
        )
    return max(configured, minimum)


def _apply_result_contracts(scenarios: dict[str, ScenarioConfig]) -> dict[str, ScenarioConfig]:
    """Populate and validate the invariant contracts shared by fan-out families."""
    for scenario_id, scenario in scenarios.items():
        if scenario.get("control_topic") == "$CONTROL/dynamic-security/v1":
            scenario["control_response_topic"] = "$CONTROL/dynamic-security/v1/response"
        if scenario.get("traffic_pattern") != "fanout":
            continue
        if scenario.get("fanout_churn_kind"):
            kind = scenario["fanout_churn_kind"]
            if kind in {"dynamic_security_swap", "dynamic_security_control", "sqlite_revoke_read"}:
                phases: list[Literal["all", "none"]] = ["all", "none"]
            elif kind in {"sqlite_toggle_read", "sqlite_toggle_private_deny"}:
                # The seeded policy is allowed; each toggle alternates its delivery state.
                phases = ["all", "none", "all", "none", "all"]
            else:
                raise ValueError(f"{scenario_id}: unknown fan-out churn kind {kind!r}")
            scenario["delivery_contract"] = {"phases": phases}
            cast(dict[str, Any], scenario).pop("fanout_churn_phase_delivery", None)
            continue
        expectation: Literal["all", "none"] = "none" if "-DENY-" in scenario_id else "all"
        scenario["delivery_contract"] = {"steady": expectation}
    return scenarios


def _set_scenario_semantics(
    scenario: ScenarioConfig,
    *,
    jwt_identity_binding: IdentityBindingMode,
    biscuit_identity_binding: IdentityBindingMode,
    semantic_class: SemanticClass,
) -> None:
    scenario["jwt_identity_binding"] = jwt_identity_binding
    scenario["biscuit_identity_binding"] = biscuit_identity_binding
    scenario["semantic_class"] = semantic_class


def _apply_scenario_semantic_defaults(scenarios: dict[str, ScenarioConfig]) -> None:
    default_jwt, default_biscuit, default_semantic_class = SCENARIO_SEMANTIC_DEFAULTS
    for scenario in scenarios.values():
        scenario.setdefault("jwt_identity_binding", default_jwt)
        scenario.setdefault("biscuit_identity_binding", default_biscuit)
        scenario.setdefault("semantic_class", default_semantic_class)


def _clone_authz_config(authz_config: AuthzConfig | None) -> AuthzConfig | None:
    if authz_config is None:
        return None
    cloned = cast(AuthzConfig, dict(authz_config))
    if "rules" in cloned:
        cloned["rules"] = [dict(rule) for rule in cloned["rules"]]
    if "client_roles" in cloned:
        cloned["client_roles"] = {
            client_id: list(roles) for client_id, roles in cloned["client_roles"].items()
        }
    return cloned


def _make_http_parity_variants(
    scenarios: dict[str, ScenarioConfig],
    tokens: dict[str, Any],
) -> dict[str, ScenarioConfig]:
    parity_variants: dict[str, ScenarioConfig] = {}
    jwt_strict_token = tokens.get("jwt_strict_sub_client_id")
    biscuit_strict_token = tokens.get("biscuit_strict_client_id")

    for parity_prefix, (jwt_source_id, biscuit_source_id) in HTTP_PARITY_VARIANT_SOURCES.items():
        if jwt_strict_token is not None:
            jwt_source = scenarios[jwt_source_id]
            jwt_variant = cast(ScenarioConfig, dict(jwt_source))
            jwt_variant["password"] = cast(str, jwt_strict_token)
            jwt_variant["client_count"] = 1
            jwt_variant["authz_config"] = _clone_authz_config(jwt_source.get("authz_config"))
            if jwt_variant["authz_config"] is not None:
                jwt_variant["authz_config"]["jwt_identity_binding"] = "strict"
            _set_scenario_semantics(
                jwt_variant,
                jwt_identity_binding="strict",
                biscuit_identity_binding="strict",
                semantic_class="parity_identity_bound",
            )
            parity_variants[f"{parity_prefix}-JWT"] = jwt_variant

        if biscuit_strict_token is not None:
            biscuit_source = scenarios[biscuit_source_id]
            biscuit_variant = cast(ScenarioConfig, dict(biscuit_source))
            biscuit_variant["password"] = cast(str, biscuit_strict_token)
            biscuit_variant["client_count"] = 1
            biscuit_variant["authz_config"] = _clone_authz_config(
                biscuit_source.get("authz_config")
            )
            _set_scenario_semantics(
                biscuit_variant,
                jwt_identity_binding="strict",
                biscuit_identity_binding="strict",
                semantic_class="parity_identity_bound",
            )
            parity_variants[f"{parity_prefix}-BISCUIT"] = biscuit_variant

    return parity_variants


def _multi_client_fanout_parity_variant_id(
    scenario_id: str,
    token_kind: ScenarioTokenKind,
) -> str:
    token_label = token_kind.upper() if token_kind == "jwt" else "BISCUIT"
    source_fragment = f"-{token_label}-"
    parity_fragment = f"-PARITY-{token_label}-"
    if source_fragment not in scenario_id:
        raise ValueError(f"cannot derive parity variant id for {scenario_id}")
    return scenario_id.replace(source_fragment, parity_fragment, 1)


def _make_multi_client_fanout_parity_variants(
    scenarios: dict[str, ScenarioConfig],
) -> dict[str, ScenarioConfig]:
    parity_variants: dict[str, ScenarioConfig] = {}

    for scenario_id, scenario in scenarios.items():
        if scenario.get("traffic_pattern") != "fanout":
            continue
        if scenario.get("acl_read_enforcement") != "strict":
            continue
        if scenario.get("policy_source") not in STRICT_FANOUT_PARITY_POLICY_SOURCES:
            continue
        if _effective_scenario_client_count(scenario, default_clients=1) <= 1:
            continue

        token_kind = _scenario_token_kind(scenario_id, scenario)
        if token_kind is None:
            continue

        variant = cast(ScenarioConfig, dict(scenario))
        variant["password"] = ""
        if "fanout_publisher_password" in variant:
            variant["fanout_publisher_password"] = ""
        variant["authz_config"] = _clone_authz_config(scenario.get("authz_config"))
        if token_kind == "jwt" and variant["authz_config"] is not None:
            variant["authz_config"]["jwt_identity_binding"] = "strict"
        _set_scenario_semantics(
            variant,
            jwt_identity_binding="strict",
            biscuit_identity_binding="strict",
            semantic_class="parity_identity_bound",
        )
        parity_variants[_multi_client_fanout_parity_variant_id(scenario_id, token_kind)] = variant

    return parity_variants


def _apply_scenario_classification(
    scenarios: dict[str, ScenarioConfig],
    tokens: dict[str, Any],
) -> dict[str, ScenarioConfig]:
    _apply_scenario_semantic_defaults(scenarios)

    for scenario_id in MIXED_SCENARIO_IDS:
        scenario = scenarios.get(scenario_id)
        if scenario is None:
            continue
        _set_scenario_semantics(
            scenario,
            jwt_identity_binding="strict",
            biscuit_identity_binding="off",
            semantic_class="mixed",
        )

    scenarios.update(_make_http_parity_variants(scenarios, tokens))
    scenarios.update(_make_multi_client_fanout_parity_variants(scenarios))
    _apply_credential_profiles(scenarios, tokens)
    return scenarios


PROFILE_TOKEN_KEYS = (
    "jwt_deny",
    "jwt_fanout_read_deny",
    "jwt_fanout_allow",
    "jwt_static_admin",
    "jwt_static_writer",
    "jwt_static_reader",
    "jwt_strict_sub_client_id",
    "jwt",
    "biscuit_deny",
    "biscuit_fanout_read_deny",
    "biscuit_fanout_allow",
    "biscuit_static_admin",
    "biscuit_static_writer",
    "biscuit_static_reader",
    "biscuit_strict_client_id",
    "biscuit_delegated",
    "biscuit_complex_low",
    "biscuit_complex_med",
    "biscuit_complex_high",
    "biscuit_25",
    "biscuit_5",
    "biscuit",
)

SHARED_CREDENTIAL_SCENARIOS = frozenset(
    {
        "TOKEN-AUTHORIZER-PROFILE-SIMPLE-BISCUIT",
        "TOKEN-AUTHORIZER-PROFILE-RBAC-BISCUIT",
        "TOKEN-AUTHORIZER-PROFILE-CONTEXTUAL-BISCUIT",
    }
)


def _profile_for_password(
    scenario_id: str,
    password: str | None,
    tokens: dict[str, Any],
) -> str:
    if "-PARITY-" in scenario_id and "FANOUT" in scenario_id:
        return "jwt_fanout_strict" if "-JWT-" in scenario_id else "biscuit_fanout_strict"
    if scenario_id.endswith("-PARITY-BISCUIT"):
        return "biscuit_strict_client_id"
    if scenario_id.endswith("-PARITY-JWT"):
        return "jwt_strict_sub_client_id"
    for key in PROFILE_TOKEN_KEYS:
        if password == tokens.get(key):
            return key
    if "-JWT" in scenario_id:
        return "jwt"
    if "-BISCUIT" in scenario_id:
        return "biscuit"
    raise ValueError(f"{scenario_id}: cannot map password fixture to a credential profile")


def _apply_credential_profiles(
    scenarios: dict[str, ScenarioConfig],
    tokens: dict[str, Any],
) -> None:
    for scenario_id, scenario in scenarios.items():
        if not scenario.get("username") and not scenario.get("mqtt5_auth"):
            scenario["credential_mode"] = "none"
            continue
        if scenario.get("mqtt5_auth") or scenario_id in SHARED_CREDENTIAL_SCENARIOS:
            scenario["credential_mode"] = "shared"
            continue
        if scenario.get("token_refresh"):
            scenario["credential_mode"] = "issuer"
            continue
        if (
            scenario.get("traffic_pattern") == "fanout"
            and scenario.get("acl_read_enforcement") == "strict"
            and scenario.get("semantic_class") == "capability"
        ):
            scenario["credential_mode"] = "shared"
            continue
        scenario["credential_mode"] = "per_client"
        scenario["password_map_profile"] = _profile_for_password(
            scenario_id,
            scenario.get("password"),
            tokens,
        )
        if scenario.get("traffic_pattern") == "fanout":
            scenario["fanout_publisher_password_map_profile"] = _profile_for_password(
                scenario_id,
                scenario.get("fanout_publisher_password") or scenario.get("password"),
                tokens,
            )


def _scenario_token_kind(
    scenario_id: str,
    scenario: ScenarioConfig,
) -> ScenarioTokenKind | None:
    username = scenario.get("username")
    if username == "jwt":
        return "jwt"
    if username == "biscuit":
        return "biscuit"
    if "-JWT" in scenario_id and "-BISCUIT" not in scenario_id:
        return "jwt"
    if "-BISCUIT" in scenario_id and "-JWT" not in scenario_id:
        return "biscuit"
    return None


def _scenario_active_identity_binding(
    scenario_id: str,
    scenario: ScenarioConfig,
) -> tuple[ScenarioTokenKind, IdentityBindingMode] | None:
    token_kind = _scenario_token_kind(scenario_id, scenario)
    if token_kind is None:
        return None
    if token_kind == "jwt":
        return token_kind, cast(
            IdentityBindingMode,
            scenario.get("jwt_identity_binding", SCENARIO_SEMANTIC_DEFAULTS[0]),
        )
    return token_kind, cast(
        IdentityBindingMode,
        scenario.get("biscuit_identity_binding", SCENARIO_SEMANTIC_DEFAULTS[1]),
    )


def _scenario_requires_per_client_strict_provisioning(
    scenario_id: str,
    scenario: ScenarioConfig,
    *,
    default_clients: int,
) -> tuple[ScenarioTokenKind, IdentityBindingMode] | None:
    effective_client_count = _effective_scenario_client_count(scenario, default_clients)
    if effective_client_count <= 1:
        return None
    active_binding = _scenario_active_identity_binding(scenario_id, scenario)
    if active_binding is None:
        return None
    _, identity_binding = active_binding
    if identity_binding != "strict":
        return None
    return active_binding


def _supports_per_client_strict_provisioning(
    scenario_id: str,
    scenario: ScenarioConfig,
    *,
    default_clients: int,
) -> bool:
    effective_client_count = _effective_scenario_client_count(scenario, default_clients)
    if effective_client_count <= 1:
        return True
    jwt_identity_binding = cast(
        IdentityBindingMode,
        scenario.get("jwt_identity_binding", SCENARIO_SEMANTIC_DEFAULTS[0]),
    )
    biscuit_identity_binding = cast(
        IdentityBindingMode,
        scenario.get("biscuit_identity_binding", SCENARIO_SEMANTIC_DEFAULTS[1]),
    )
    if jwt_identity_binding != "strict" and biscuit_identity_binding != "strict":
        return True
    required_binding = _scenario_requires_per_client_strict_provisioning(
        scenario_id,
        scenario,
        default_clients=default_clients,
    )
    if required_binding is None:
        return _scenario_token_kind(scenario_id, scenario) is not None
    token_kind, _ = required_binding
    return token_kind in {"jwt", "biscuit"}


def _validate_scenario_semantics(
    scenario_id: str,
    scenario: ScenarioConfig,
    *,
    default_clients: int,
) -> None:
    jwt_identity_binding = cast(
        IdentityBindingMode,
        scenario.get("jwt_identity_binding", SCENARIO_SEMANTIC_DEFAULTS[0]),
    )
    biscuit_identity_binding = cast(
        IdentityBindingMode,
        scenario.get("biscuit_identity_binding", SCENARIO_SEMANTIC_DEFAULTS[1]),
    )
    semantic_class = cast(
        SemanticClass,
        scenario.get("semantic_class", SCENARIO_SEMANTIC_DEFAULTS[2]),
    )

    expected_bindings = SCENARIO_SEMANTIC_RULES[semantic_class]
    actual_bindings = (jwt_identity_binding, biscuit_identity_binding)
    if actual_bindings != expected_bindings:
        raise ValueError(
            f"{scenario_id}: semantic_class={semantic_class} requires "
            f"jwt_identity_binding={expected_bindings[0]} and "
            f"biscuit_identity_binding={expected_bindings[1]}, but scenario declares "
            f"jwt_identity_binding={jwt_identity_binding} and "
            f"biscuit_identity_binding={biscuit_identity_binding}"
        )

    effective_client_count = _effective_scenario_client_count(scenario, default_clients)
    strict_multi_client_declared = effective_client_count > 1 and (
        jwt_identity_binding == "strict" or biscuit_identity_binding == "strict"
    )
    if strict_multi_client_declared and not _supports_per_client_strict_provisioning(
        scenario_id,
        scenario,
        default_clients=default_clients,
    ):
        token_kind = _scenario_token_kind(scenario_id, scenario)
        token_label = f"{token_kind}_identity_binding" if token_kind is not None else "token kind"
        raise ValueError(
            f"{scenario_id}: semantic_class={semantic_class} uses "
            f"{token_label}=strict with effective_client_count={effective_client_count}, "
            "but the harness cannot determine how to "
            "provision one strict-bound token per client identity for this scenario."
        )


def _scenario_semantics_metadata(
    scenario_id: str,
    scenario: ScenarioConfig,
    *,
    default_clients: int,
) -> dict[str, str]:
    _validate_scenario_semantics(scenario_id, scenario, default_clients=default_clients)
    return {
        "jwt_identity_binding": cast(
            IdentityBindingMode,
            scenario.get("jwt_identity_binding", SCENARIO_SEMANTIC_DEFAULTS[0]),
        ),
        "biscuit_identity_binding": cast(
            IdentityBindingMode,
            scenario.get("biscuit_identity_binding", SCENARIO_SEMANTIC_DEFAULTS[1]),
        ),
        "semantic_class": cast(
            SemanticClass,
            scenario.get("semantic_class", SCENARIO_SEMANTIC_DEFAULTS[2]),
        ),
    }


def _validate_scenario_credentials(scenario_id: str, scenario: ScenarioConfig) -> None:
    mode = scenario.get("credential_mode")
    if mode not in {"none", "shared", "per_client", "issuer"}:
        raise ValueError(f"{scenario_id}: missing or invalid credential_mode")
    if mode == "per_client":
        profile = scenario.get("password_map_profile")
        if not profile:
            raise ValueError(f"{scenario_id}: per_client mode requires password_map_profile")
        if scenario.get("traffic_pattern") == "fanout" and not scenario.get(
            "fanout_publisher_password_map_profile"
        ):
            raise ValueError(
                f"{scenario_id}: per_client fanout requires fanout_publisher_password_map_profile"
            )
    if mode == "issuer" and not scenario.get("token_refresh"):
        raise ValueError(f"{scenario_id}: issuer mode requires token_refresh configuration")
    if mode == "shared":
        allowed = (
            scenario.get("mqtt5_auth") is not None
            or scenario_id in SHARED_CREDENTIAL_SCENARIOS
            or (
                scenario.get("traffic_pattern") == "fanout"
                and scenario.get("acl_read_enforcement") == "strict"
                and scenario.get("semantic_class") == "capability"
            )
        )
        if not allowed:
            raise ValueError(f"{scenario_id}: shared credential mode is not allowlisted")


def _render_mosquitto_runtime_conf(
    base_conf_text: str,
    *,
    jwt_identity_binding: IdentityBindingMode,
    biscuit_identity_binding: IdentityBindingMode,
    biscuit_client_id_fact: str,
) -> str:
    lines = base_conf_text.splitlines()
    filtered_lines = [
        line
        for line in lines
        if not line.strip().startswith("plugin_opt_jwt_identity_binding ")
        and not line.strip().startswith("plugin_opt_biscuit_identity_binding ")
        and not line.strip().startswith("plugin_opt_biscuit_client_id_fact ")
        and not line.strip().startswith("plugin_opt_benchmark_diagnostics ")
    ]
    insertion_indices = [
        idx
        for idx, line in enumerate(filtered_lines)
        if line.strip().startswith("plugin_opt_jwt_key_file ")
        or line.strip().startswith("plugin_opt_biscuit_root_key_file ")
    ]
    if not insertion_indices:
        raise ValueError("Mosquitto config missing JWT/Biscuit key-file plugin options")

    insert_at = insertion_indices[-1] + 1
    filtered_lines[insert_at:insert_at] = [
        f"plugin_opt_jwt_identity_binding {jwt_identity_binding}",
        f"plugin_opt_biscuit_identity_binding {biscuit_identity_binding}",
        f"plugin_opt_biscuit_client_id_fact {biscuit_client_id_fact}",
        "plugin_opt_benchmark_diagnostics true",
    ]
    return "\n".join(filtered_lines) + "\n"


def _materialize_mosquitto_runtime_conf(
    mosquitto_conf: str,
    *,
    jwt_identity_binding: IdentityBindingMode,
    biscuit_identity_binding: IdentityBindingMode,
    biscuit_client_id_fact: str,
) -> str:
    base_conf_path = _resolve_compose_path(mosquitto_conf)
    rendered_conf = _render_mosquitto_runtime_conf(
        base_conf_path.read_text(encoding="utf-8"),
        jwt_identity_binding=jwt_identity_binding,
        biscuit_identity_binding=biscuit_identity_binding,
        biscuit_client_id_fact=biscuit_client_id_fact,
    )

    base_conf_relative = _compose_relative_path(mosquitto_conf)
    generated_relative_dir = base_conf_relative.parent / ".generated"
    generated_name = (
        f"{base_conf_relative.stem}.jwt-{jwt_identity_binding}."
        f"biscuit-{biscuit_identity_binding}."
        f"fact-{biscuit_client_id_fact}{base_conf_relative.suffix}"
    )
    generated_relative_path = generated_relative_dir / generated_name
    generated_conf_path = _resolve_compose_path(generated_relative_path)
    generated_conf_path.parent.mkdir(parents=True, exist_ok=True)
    generated_conf_path.write_text(rendered_conf, encoding="utf-8")
    return f"./{generated_relative_path.as_posix()}"


def _compose_relative_path(path: str) -> Path:
    return Path(path[2:] if path.startswith("./") else path)


def _effective_mosquitto_runtime_conf(
    mosquitto_conf: str,
    *,
    jwt_identity_binding: IdentityBindingMode,
    biscuit_identity_binding: IdentityBindingMode,
    biscuit_client_id_fact: str,
) -> str:
    effective_conf_relative = _compose_relative_path(mosquitto_conf)
    if effective_conf_relative in MOSQUITTO_BASE_CONFIGS:
        return mosquitto_conf
    return _materialize_mosquitto_runtime_conf(
        mosquitto_conf,
        jwt_identity_binding=jwt_identity_binding,
        biscuit_identity_binding=biscuit_identity_binding,
        biscuit_client_id_fact=biscuit_client_id_fact,
    )


def _missing_requested_scenario_fixture_keys(
    scenario_id: str,
    tokens: dict[str, Any],
) -> list[str]:
    base_scenario_id = scenario_id.removesuffix("-TLS")
    missing_keys: list[str] = []

    if (
        base_scenario_id in AUTHORIZER_TEMPLATE_SCENARIO_IDS
        and tokens.get("biscuit_authorizer_template") is None
    ):
        missing_keys.append("biscuit_authorizer_template")

    if base_scenario_id.endswith("-JWT"):
        parity_prefix = base_scenario_id.removesuffix("-JWT")
        if (
            parity_prefix in HTTP_PARITY_VARIANT_SOURCES
            and tokens.get("jwt_strict_sub_client_id") is None
        ):
            missing_keys.append("jwt_strict_sub_client_id")

    if base_scenario_id.endswith("-BISCUIT"):
        parity_prefix = base_scenario_id.removesuffix("-BISCUIT")
        if (
            parity_prefix in HTTP_PARITY_VARIANT_SOURCES
            and tokens.get("biscuit_strict_client_id") is None
        ):
            missing_keys.append("biscuit_strict_client_id")

    return missing_keys


def _require_requested_scenario_fixtures(
    scenario_id: str,
    tokens: dict[str, Any],
) -> None:
    missing_keys = _missing_requested_scenario_fixture_keys(scenario_id, tokens)
    if not missing_keys:
        return

    quoted_keys = ", ".join(f"{key!r}" for key in missing_keys)
    key_label = "key" if len(missing_keys) == 1 else "keys"
    raise SystemExit(
        f"Scenario {scenario_id!r} requires token fixture {key_label} {quoted_keys}. "
        "Regenerate tokens with: cargo run -p gen-tokens --bin gen-tokens"
    )


def _find_dynamic_security_client(
    snapshot: dict[str, Any],
    *,
    scenario_id: str,
    snapshot_path: str,
    username: str,
) -> dict[str, Any]:
    clients = snapshot.get("clients")
    if not isinstance(clients, list):
        raise ValueError(
            f"{scenario_id}: dynamic security snapshot missing clients list: {snapshot_path}"
        )

    for client in clients:
        if isinstance(client, dict) and client.get("username") == username:
            return client

    raise ValueError(
        f"{scenario_id}: dynamic security snapshot '{snapshot_path}' has no client for "
        f"username '{username}'"
    )


def _validate_dynamic_security_snapshot_supports_principal(
    *,
    scenario_id: str,
    snapshot_path: str,
    username: str,
    principal_label: str,
    required_clientid: str | None = None,
    disallow_pinned_clientid: bool = False,
    effective_client_count: int | None = None,
) -> None:
    snapshot = _load_dynamic_security_snapshot(snapshot_path)
    matching_client = _find_dynamic_security_client(
        snapshot,
        scenario_id=scenario_id,
        snapshot_path=snapshot_path,
        username=username,
    )
    pinned_client_id = matching_client.get("clientid")
    if (
        required_clientid
        and isinstance(pinned_client_id, str)
        and pinned_client_id
        and pinned_client_id != required_clientid
    ):
        raise ValueError(
            f"{scenario_id}: dynamic security snapshot '{snapshot_path}' pins "
            f"{principal_label} '{username}' to clientid '{pinned_client_id}' but "
            f"benchmark expects '{required_clientid}'"
        )
    if disallow_pinned_clientid and isinstance(pinned_client_id, str) and pinned_client_id:
        raise ValueError(
            f"{scenario_id}: dynamic security snapshot '{snapshot_path}' pins {principal_label} "
            f"'{username}' to clientid '{pinned_client_id}' but scenario declares "
            f"effective_client_count={effective_client_count}. Remove clientid pinning or "
            "expand identities to match the benchmark worker count."
        )


def _validate_dynamic_security_alignment(
    scenario_id: str,
    scenario: ScenarioConfig,
    *,
    default_clients: int,
) -> None:
    dynamic_security_config = cast(str | None, scenario.get("dynamic_security_config"))
    generated_snapshot_path: str | None = None
    if not dynamic_security_config and scenario.get("dynamic_security_generated_profile"):
        generated_snapshot_path = _generate_dynamic_security_config(
            cast(str, scenario["dynamic_security_generated_profile"])
        )
        dynamic_security_config = generated_snapshot_path
    has_churn_validation_input = bool(
        scenario.get("fanout_churn_dynamic_security_source")
        or scenario.get("dynamic_security_churn")
    )
    if not dynamic_security_config and not has_churn_validation_input:
        return

    effective_client_count = _effective_scenario_client_count(scenario, default_clients)
    is_fanout = scenario.get("traffic_pattern") == "fanout"
    subscriber_username = scenario.get("username")
    publisher_username = scenario.get("fanout_publisher_username")

    try:
        if dynamic_security_config and subscriber_username:
            _validate_dynamic_security_snapshot_supports_principal(
                scenario_id=scenario_id,
                snapshot_path=dynamic_security_config,
                username=subscriber_username,
                principal_label="username",
                disallow_pinned_clientid=effective_client_count > 1,
                effective_client_count=effective_client_count,
            )
        if dynamic_security_config and publisher_username:
            _validate_dynamic_security_snapshot_supports_principal(
                scenario_id=scenario_id,
                snapshot_path=dynamic_security_config,
                username=publisher_username,
                principal_label="fanout_publisher_username",
                required_clientid="fanout_publisher",
            )

        if scenario.get("fanout_churn_kind") == "dynamic_security_swap":
            churn_snapshot = scenario.get("fanout_churn_dynamic_security_source")
            if not churn_snapshot:
                raise ValueError(
                    f"{scenario_id}: fanout_churn_kind=dynamic_security_swap requires "
                    "fanout_churn_dynamic_security_source"
                )
            if subscriber_username:
                _validate_dynamic_security_snapshot_supports_principal(
                    scenario_id=scenario_id,
                    snapshot_path=churn_snapshot,
                    username=subscriber_username,
                    principal_label="username",
                    disallow_pinned_clientid=is_fanout and effective_client_count > 1,
                    effective_client_count=effective_client_count,
                )
            if publisher_username:
                _validate_dynamic_security_snapshot_supports_principal(
                    scenario_id=scenario_id,
                    snapshot_path=churn_snapshot,
                    username=publisher_username,
                    principal_label="fanout_publisher_username",
                    required_clientid="fanout_publisher",
                )
        elif scenario.get("dynamic_security_churn"):
            for churn_snapshot in cast(list[str], scenario["dynamic_security_churn"]):
                if subscriber_username:
                    _validate_dynamic_security_snapshot_supports_principal(
                        scenario_id=scenario_id,
                        snapshot_path=churn_snapshot,
                        username=subscriber_username,
                        principal_label="username",
                        disallow_pinned_clientid=effective_client_count > 1,
                        effective_client_count=effective_client_count,
                    )
                if publisher_username:
                    _validate_dynamic_security_snapshot_supports_principal(
                        scenario_id=scenario_id,
                        snapshot_path=churn_snapshot,
                        username=publisher_username,
                        principal_label="fanout_publisher_username",
                        required_clientid="fanout_publisher",
                    )
    finally:
        policy_churn.cleanup_dynsec_snapshot(generated_snapshot_path)


def _validate_dynamic_security_fanout_alignment(scenario_id: str, scenario: ScenarioConfig) -> None:
    _validate_dynamic_security_alignment(scenario_id, scenario, default_clients=0)


def _expand_tls_matrix(
    scenarios: dict[str, ScenarioConfig],
) -> dict[str, ScenarioConfig]:
    expanded: dict[str, ScenarioConfig] = {}
    for scenario_id, scenario in scenarios.items():
        expanded[scenario_id] = scenario
        if scenario_id.endswith("-TLS"):
            continue
        tls_scenario = scenario.copy()
        tls_scenario["tls"] = True
        expanded[f"{scenario_id}-TLS"] = tls_scenario
    return expanded


def _write_result(out_dir: str, name: str, payload: dict):
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    path = out_path / f"{name}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return str(path)


def _generate_control_churn_payload(scenario_id: str, client_id: str) -> dict[str, Any] | None:
    """Generate Dynamic Security command payload for CONTROL-CHURN scenarios.

    Maps scenario ID patterns to appropriate churn sequences:
    - CREATE-ROLE -> role churn (createRole + deleteRole)
    - GROUP-CLIENT -> group client churn (createGroup + addGroupClient +
                     removeGroupClient + deleteGroup)
    - ACL-MODIFY -> ACL churn (createRole + addRoleACL + removeRoleACL + deleteRole)

    Args:
        scenario_id: The scenario identifier (e.g., "CONTROL-CHURN-CREATE-ROLE-JWT")
        client_id: Client ID for generating unique resource names

    Returns:
        Command payload dict or None if not a CONTROL-CHURN scenario
    """
    if "CONTROL-CHURN" not in scenario_id:
        return None

    # Extract churn type from scenario ID
    if "NOOP-GROUP-CLIENT" in scenario_id:
        sequence_type = "noop_group_client"
    elif "LARGE-STATE-GROUP-CLIENT" in scenario_id:
        return dynsec_commands.generate_command_payload(
            dynsec_commands.generate_churn_sequence(
                sequence_type="group_client",
                base_id="large_state_control",
                client_id="bulk_user_1",
            )
        )
    elif "CREATE-ROLE" in scenario_id:
        sequence_type = "role"
    elif "GROUP-CLIENT" in scenario_id:
        sequence_type = "group_client"
    elif "ACL-MODIFY" in scenario_id:
        sequence_type = "acl"
    elif "REPEAT-SAME-ENTITY" in scenario_id:
        return dynsec_commands.generate_command_payload(
            dynsec_commands.generate_churn_sequence(
                sequence_type="role",
                base_id="shared_control_entity",
                client_id="shared_control_entity",
            )
        )
    elif "REPEAT-DISTINCT-ENTITY" in scenario_id or "CONCURRENT-CONTROLLERS" in scenario_id:
        return dynsec_commands.generate_command_payload(
            dynsec_commands.generate_churn_sequence(
                sequence_type="role",
                base_id="{client_id}",
                client_id="{client_id}",
            )
        )
    else:
        logger.warning(f"Unknown CONTROL-CHURN type in scenario: {scenario_id}")
        return None

    commands = dynsec_commands.generate_churn_sequence(
        sequence_type=sequence_type,
        base_id=client_id,
        client_id=client_id,
    )
    return dynsec_commands.generate_command_payload(commands)


def _require_control_churn_payload(scenario_id: str, client_id: str) -> dict[str, Any]:
    payload = _generate_control_churn_payload(scenario_id, client_id)
    if payload is None:
        raise ValueError(f"scenario {scenario_id} does not define a control churn payload")
    return payload


def _control_churn_scenario(
    *,
    scenario_id: str,
    token: str,
    client_count: int,
    control_repeat: int,
    dynamic_security_config: str | None = None,
    dynamic_security_generated_profile: str | None = "control_admin_base",
) -> ScenarioConfig:
    scenario: ScenarioConfig = {
        "mosquitto_conf": "./mosquitto_dynsec.conf",
        "username": "admin",
        "password": token,
        "topic": "sensors/{client_id}/temp",
        "control_topic": "$CONTROL/dynamic-security/v1",
        "control_mode": True,
        "control_repeat": control_repeat,
        "authz_config": None,
        "netem": {"clear": True},
        "message_size": 256,
        "qos": 1,
        "repeat": 2,
        "sleep_between": 3,
        "client_count": client_count,
    }
    scenario["control_payload"] = _require_control_churn_payload(scenario_id, "admin")
    if dynamic_security_config:
        scenario["dynamic_security_config"] = dynamic_security_config
    if dynamic_security_generated_profile:
        scenario["dynamic_security_generated_profile"] = dynamic_security_generated_profile
    return scenario


def _run_mqtt5_auth(
    host: str,
    port: int,
    token1: str,
    token2: str,
    token1_topic: str,
    token2_topic: str,
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
    *,
    client_id: str,
    client_topology: ClientTopology = "host",
    service: str = "loadgen",
    scenario_id: str = "mqtt5-auth",
    run_index: int = 0,
    compose_files: list[str] | None = None,
    compose_project_name: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    helper_args = [
        "--host",
        host,
        "--port",
        str(port),
        "--client-id",
        client_id,
        "--auth-method",
        "token",
        "--token1",
        _mark_mqtt5_auth_token(token1),
        "--token2",
        _mark_mqtt5_auth_token(token2),
        "--token1-topic",
        token1_topic,
        "--token2-topic",
        token2_topic,
    ]
    if tls_enabled:
        helper_args.append("--tls")
    if tls_ca_file:
        helper_args.extend(["--tls-ca-file", tls_ca_file])
    if tls_insecure:
        helper_args.append("--tls-insecure")
    if client_topology == "host":
        cmd = [*_resolve_rust_helper("mqtt-auth-client"), *helper_args]
    else:
        container_name = _loadgen_container_name(
            scenario_id=scenario_id,
            run_index=run_index,
            client_index=0,
            compose_project_name=compose_project_name,
            compose_files=compose_files,
        )
        cmd = _compose_cmd(
            [
                "run",
                "--rm",
                "--no-deps",
                "--build",
                "--quiet-build",
                "--name",
                container_name,
                "--entrypoint",
                "/usr/local/bin/mqtt-auth-client",
                service,
                *helper_args,
            ],
            compose_files=compose_files,
            compose_project_name=compose_project_name,
        )
    env = os.environ.copy()
    env.update(extra_env or {})
    out = subprocess.check_output(cmd, cwd=REPO_ROOT, env=env, text=True)
    result = json.loads(out)
    result["topology"] = {
        "mode": client_topology,
        "container_count": 0 if client_topology == "host" else 1,
        "aggregation": "single_mqtt5_auth_client",
    }
    return result


class ScenarioModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str | None = None
    mosquitto_conf: str | None = None
    username: str | None = None
    password: str | None = None
    topic: str | None = None
    jwt_identity_binding: IdentityBindingMode | None = None
    biscuit_identity_binding: IdentityBindingMode | None = None
    semantic_class: SemanticClass | None = None


class ScenarioEndpointConfig(TypedDict):
    authz_base: str
    prom_base: str
    token_issuer_base: str
    loadgen_token_issuer_base: str
    host_mqtt_host: str
    loadgen_mqtt_host: str
    mqtt_port: int
    loadgen_tls_ca: str | None


def _scenario_endpoint_config(
    *,
    client_topology_mode: ClientTopology,
    scenario_tls: bool,
    tls_ca: str | None,
) -> ScenarioEndpointConfig:
    token_issuer_base = "https://localhost:8444" if scenario_tls else "http://localhost:8082"
    loadgen_token_issuer_base = token_issuer_base
    host_mqtt_host = "localhost"
    loadgen_mqtt_host = host_mqtt_host
    loadgen_tls_ca = tls_ca
    if client_topology_mode != "host":
        loadgen_mqtt_host = "mosquitto"
        loadgen_token_issuer_base = (
            "https://token-issuer:8444" if scenario_tls else "http://token-issuer:8082"
        )
        loadgen_tls_ca = _container_repo_path(tls_ca)
    return {
        "authz_base": "https://localhost:8443" if scenario_tls else "http://localhost:8081",
        "prom_base": "https://localhost:9443" if scenario_tls else "http://localhost:9090",
        "token_issuer_base": token_issuer_base,
        "loadgen_token_issuer_base": loadgen_token_issuer_base,
        "host_mqtt_host": host_mqtt_host,
        "loadgen_mqtt_host": loadgen_mqtt_host,
        "mqtt_port": 8883 if scenario_tls else 1883,
        "loadgen_tls_ca": loadgen_tls_ca,
    }


def _http_profile_authz_config(tier: Literal["simple", "med", "complex"]) -> AuthzConfig:
    return {
        "delay_ms": 0,
        "fail_mode": "none",
        "authz_profile": tier,
        # Deterministic local role source for role-aware rule paths.
        "client_roles": {
            "client_1": ["admin", "writer"],
            "client_2": ["reader"],
            "client_3": ["observer"],
        },
    }


def _tuned_profile_authz_config(
    tier: Literal["simple", "med", "complex"],
    *,
    delay_ms: int,
    fail_mode: str,
    fail_rate: float | None = None,
) -> AuthzConfig:
    cfg = _http_profile_authz_config(tier)
    cfg["delay_ms"] = delay_ms
    cfg["fail_mode"] = fail_mode
    if fail_rate is not None:
        cfg["fail_rate"] = fail_rate
    return cfg


def _http_hybrid_fanout_authz_config_profile_matrix(
    tier: Literal["simple", "med", "complex"],
    *,
    topic: str,
    deny_read: bool,
) -> AuthzConfig:
    rules: list[dict[str, Any]] = [
        {
            "id": "acl_read_profile_allow_fanout_publish_profile_matrix",
            "effect": "allow",
            "ops": ["publish"],
            "topics": [topic],
            "client_ids": ["fanout_publisher"],
        },
        {
            "id": "acl_read_profile_allow_fanout_subscribe_profile_matrix",
            "effect": "allow",
            "ops": ["subscribe"],
            "topics": [topic],
        },
    ]
    if deny_read:
        rules.append(
            {
                "id": "acl_read_profile_deny_fanout_read_profile_matrix",
                "effect": "deny",
                "ops": ["read"],
                "topics": [topic],
            }
        )
    else:
        rules.append(
            {
                "id": "acl_read_profile_allow_fanout_read_profile_matrix",
                "effect": "allow",
                "ops": ["read"],
                "topics": [topic],
            }
        )
    return {
        "delay_ms": 0,
        "fail_mode": "none",
        "authz_profile": tier,
        "rules": rules,
        # Deterministic local role source for role-aware paths in med/complex profiles.
        "client_roles": {
            "client_1": ["admin", "writer"],
            "client_2": ["reader"],
            "client_3": ["observer"],
            "fanout_publisher": ["writer", "admin"],
        },
    }


AUTHORIZER_TEMPLATE_SCENARIO_IDS = frozenset(
    {
        "TOKEN-AUTHORIZER-PROFILE-SIMPLE-BISCUIT",
        "TOKEN-AUTHORIZER-PROFILE-RBAC-BISCUIT",
        "TOKEN-AUTHORIZER-PROFILE-CONTEXTUAL-BISCUIT",
    }
)


def _biscuit_authorizer_template_scenarios(tokens: dict[str, Any]) -> dict[str, ScenarioConfig]:
    template_token = tokens.get("biscuit_authorizer_template")
    if template_token is None:
        return {}

    return {
        "TOKEN-AUTHORIZER-PROFILE-SIMPLE-BISCUIT": {
            "mosquitto_conf": "./mosquitto_biscuit_authz_simple.conf",
            "username": "biscuit",
            "password": template_token,
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "authorizer_template",
            "complexity_level": "simple",
            "authorizer_profile": "simple",
        },
        "TOKEN-AUTHORIZER-PROFILE-RBAC-BISCUIT": {
            "mosquitto_conf": "./mosquitto_biscuit_authz_rbac.conf",
            "username": "biscuit",
            "password": template_token,
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "authorizer_template",
            "complexity_level": "med",
            "authorizer_profile": "rbac",
        },
        "TOKEN-AUTHORIZER-PROFILE-CONTEXTUAL-BISCUIT": {
            "mosquitto_conf": "./mosquitto_biscuit_authz_contextual.conf",
            "username": "biscuit",
            "password": template_token,
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "authorizer_template",
            "complexity_level": "complex",
            "authorizer_profile": "contextual",
        },
    }


def _static_acl_scenarios(tokens: dict[str, Any]) -> dict[str, ScenarioConfig]:
    """Static ACL scenarios with role-only tokens to isolate ACL-file enforcement."""
    return {
        "STATIC-ACL-PUBLISH-JWT": {
            "mosquitto_conf": "./mosquitto_static.conf",
            "username": "jwt",
            "password": tokens["jwt_static_writer"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
        },
        "STATIC-ACL-PUBLISH-BISCUIT": {
            "mosquitto_conf": "./mosquitto_static.conf",
            "username": "biscuit",
            "password": tokens["biscuit_static_writer"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
        },
        "STATIC-ACL-FANOUT-JWT": {
            "mosquitto_conf": "./mosquitto_static.conf",
            "username": "jwt",
            "password": tokens["jwt_static_reader"],
            "fanout_publisher_username": "jwt",
            "fanout_publisher_password": tokens["jwt_static_writer"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
        },
        "STATIC-ACL-FANOUT-BISCUIT": {
            "mosquitto_conf": "./mosquitto_static.conf",
            "username": "biscuit",
            "password": tokens["biscuit_static_reader"],
            "fanout_publisher_username": "biscuit",
            "fanout_publisher_password": tokens["biscuit_static_writer"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
        },
    }


def _acl_read_fanout_churn_scenarios(tokens: dict[str, Any]) -> dict[str, ScenarioConfig]:
    scenarios: dict[str, ScenarioConfig] = {}
    subscriber_slices = [10, 50, 100]
    base_topic = "fanout/broadcast"

    for subscribers in subscriber_slices:
        scenarios[f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-JWT-{subscribers}"] = {
            "mosquitto_conf": "./mosquitto_dynsec_acl_read.conf",
            "username": "dynsec_client_1",
            "password": tokens["jwt"],
            "fanout_publisher_username": "dynsec_publisher",
            "fanout_publisher_password": tokens["jwt"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": subscribers,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_config": "docker/dynamic-security-fanout-read-allow-unpinned.json",
            "fanout_churn_kind": "dynamic_security_swap",
            "fanout_churn_after_messages": 5,
            "fanout_churn_settle_ms": 1200,
            "fanout_churn_dynamic_security_source": (
                "docker/dynamic-security-fanout-read-deny-unpinned.json"
            ),
        }
        scenarios[f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CHURN-BISCUIT-{subscribers}"] = {
            "mosquitto_conf": "./mosquitto_dynsec_acl_read.conf",
            "username": "dynsec_client_1",
            "password": tokens["biscuit"],
            "fanout_publisher_username": "dynsec_publisher",
            "fanout_publisher_password": tokens["biscuit"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": subscribers,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_config": "docker/dynamic-security-fanout-read-allow-unpinned.json",
            "fanout_churn_kind": "dynamic_security_swap",
            "fanout_churn_after_messages": 5,
            "fanout_churn_settle_ms": 1200,
            "fanout_churn_dynamic_security_source": (
                "docker/dynamic-security-fanout-read-deny-unpinned.json"
            ),
        }
        scenarios[f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-JWT-{subscribers}"] = {
            "mosquitto_conf": "./mosquitto_dynsec_acl_read.conf",
            "username": "dynsec_client_1",
            "password": tokens["jwt"],
            "fanout_publisher_username": "dynsec_publisher",
            "fanout_publisher_password": tokens["jwt"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": subscribers,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_generated_profile": "fanout_control_allow",
            "fanout_churn_kind": "dynamic_security_control",
            "fanout_churn_after_messages": 5,
            "fanout_churn_settle_ms": 1200,
            "fanout_churn_control_topic": "$CONTROL/dynamic-security/v1",
            "fanout_churn_control_payload": {
                "commands": [
                    {
                        "command": "removeRoleACL",
                        "rolename": "fanout_reader",
                        "acltype": "publishClientReceive",
                        "topic": base_topic,
                    }
                ]
            },
        }
        scenarios[f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-BISCUIT-{subscribers}"] = {
            "mosquitto_conf": "./mosquitto_dynsec_acl_read.conf",
            "username": "dynsec_client_1",
            "password": tokens["biscuit"],
            "fanout_publisher_username": "dynsec_publisher",
            "fanout_publisher_password": tokens["biscuit"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": subscribers,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_generated_profile": "fanout_control_allow",
            "fanout_churn_kind": "dynamic_security_control",
            "fanout_churn_after_messages": 5,
            "fanout_churn_settle_ms": 1200,
            "fanout_churn_control_topic": "$CONTROL/dynamic-security/v1",
            "fanout_churn_control_payload": {
                "commands": [
                    {
                        "command": "removeRoleACL",
                        "rolename": "fanout_reader",
                        "acltype": "publishClientReceive",
                        "topic": base_topic,
                    }
                ]
            },
        }
        scenarios[f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-JWT-{subscribers}"] = {
            "mosquitto_conf": "./mosquitto_dynsec_acl_read.conf",
            "username": "dynsec_client_1",
            "password": tokens["jwt"],
            "fanout_publisher_username": "dynsec_publisher",
            "fanout_publisher_password": tokens["jwt"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": subscribers,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_generated_profile": "fanout_control_allow",
            "fanout_churn_kind": "dynamic_security_control",
            "fanout_churn_after_messages": 5,
            "fanout_churn_settle_ms": 1200,
            "allowed_error_prefixes": list(EXPECTED_DISABLE_RECEIVE_ERROR_PREFIXES),
            "fanout_churn_control_topic": "$CONTROL/dynamic-security/v1",
            "fanout_churn_control_payload": {
                "commands": [{"command": "disableClient", "username": "dynsec_client_1"}]
            },
        }
        scenarios[f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-BISCUIT-{subscribers}"] = {
            "mosquitto_conf": "./mosquitto_dynsec_acl_read.conf",
            "username": "dynsec_client_1",
            "password": tokens["biscuit"],
            "fanout_publisher_username": "dynsec_publisher",
            "fanout_publisher_password": tokens["biscuit"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": subscribers,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_generated_profile": "fanout_control_allow",
            "fanout_churn_kind": "dynamic_security_control",
            "fanout_churn_after_messages": 5,
            "fanout_churn_settle_ms": 1200,
            "allowed_error_prefixes": list(EXPECTED_DISABLE_RECEIVE_ERROR_PREFIXES),
            "fanout_churn_control_topic": "$CONTROL/dynamic-security/v1",
            "fanout_churn_control_payload": {
                "commands": [{"command": "disableClient", "username": "dynsec_client_1"}]
            },
        }

        scenarios[f"SQLITE-ACL-READ-FANOUT-CHURN-JWT-{subscribers}"] = {
            "mosquitto_conf": "./mosquitto_sqlite_acl_read.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "fanout_publisher_username": "jwt",
            "fanout_publisher_password": tokens["jwt"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": subscribers,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "sqlite_seed_fanout": True,
            "sqlite_seed_db": "docker/sqlite/policy.db",
            "sqlite_seed_topic": base_topic,
            "sqlite_seed_subscribers": subscribers,
            "fanout_churn_kind": "sqlite_revoke_read",
            "fanout_churn_after_messages": 5,
            "fanout_churn_settle_ms": 1200,
            "fanout_churn_sqlite_db": "docker/sqlite/policy.db",
            "fanout_churn_sqlite_topic": base_topic,
            "fanout_churn_sqlite_subscribers": subscribers,
        }
        scenarios[f"SQLITE-ACL-READ-FANOUT-CHURN-BISCUIT-{subscribers}"] = {
            "mosquitto_conf": "./mosquitto_sqlite_acl_read.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "fanout_publisher_username": "biscuit",
            "fanout_publisher_password": tokens["biscuit"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": subscribers,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "sqlite_seed_fanout": True,
            "sqlite_seed_db": "docker/sqlite/policy.db",
            "sqlite_seed_topic": base_topic,
            "sqlite_seed_subscribers": subscribers,
            "fanout_churn_kind": "sqlite_revoke_read",
            "fanout_churn_after_messages": 5,
            "fanout_churn_settle_ms": 1200,
            "fanout_churn_sqlite_db": "docker/sqlite/policy.db",
            "fanout_churn_sqlite_topic": base_topic,
            "fanout_churn_sqlite_subscribers": subscribers,
        }

    return scenarios


def _acl_read_profile_matrix_scenarios(tokens: dict[str, Any]) -> dict[str, ScenarioConfig]:
    scenarios: dict[str, ScenarioConfig] = {}
    subscriber_slices = [10, 50, 100]
    base_topic = "fanout/broadcast"

    for token_label, token_key in (("JWT", "jwt"), ("BISCUIT", "biscuit")):
        allow_token = tokens.get(f"{token_key}_fanout_allow", tokens[token_key]) or ""
        deny_token = (
            tokens.get(
                f"{token_key}_fanout_read_deny",
                tokens.get(f"{token_key}_deny", allow_token),
            )
            or allow_token
        )
        username = "jwt" if token_key == "jwt" else "biscuit"

        for subscribers in subscriber_slices:
            scenarios[f"TOKEN-ACL-READ-FANOUT-STRICT-ALLOW-{token_label}-{subscribers}"] = {
                "mosquitto_conf": "./mosquitto_integration_acl_read_full.conf",
                "username": username,
                "password": allow_token,
                "fanout_publisher_username": username,
                "fanout_publisher_password": allow_token,
                "topic": base_topic,
                "traffic_pattern": "fanout",
                "subscriber_count": subscribers,
                "fanout_topic": base_topic,
                "authz_config": None,
                "netem": {"clear": True},
                "message_size": 256,
                "qos": 1,
                "policy_source": "token",
                "acl_read_enforcement": "strict",
            }

        scenarios[f"TOKEN-ACL-READ-FANOUT-STRICT-DENY-{token_label}-10"] = {
            "mosquitto_conf": "./mosquitto_integration_acl_read_full.conf",
            "username": username,
            "password": deny_token,
            "fanout_publisher_username": username,
            "fanout_publisher_password": allow_token,
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": 10,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "policy_source": "token",
            "acl_read_enforcement": "strict",
        }

    for source_label, source_key, mosquitto_conf in (
        ("HTTP", "http", "./mosquitto_http_acl_read.conf"),
        ("HYBRID", "hybrid", "./mosquitto_hybrid_acl_read.conf"),
    ):
        for tier in ("simple", "med", "complex"):
            for token_label, token_key in (("JWT", "jwt"), ("BISCUIT", "biscuit")):
                username = "jwt" if token_key == "jwt" else "biscuit"
                allow_token = tokens.get(f"{token_key}_fanout_allow", tokens[token_key]) or ""
                deny_token = (
                    tokens.get(
                        f"{token_key}_fanout_read_deny",
                        tokens.get(f"{token_key}_deny", allow_token),
                    )
                    or allow_token
                )

                scenarios[
                    f"{source_label}-ACL-READ-FANOUT-STRICT-{tier.upper()}-ALLOW-{token_label}-10"
                ] = {
                    "mosquitto_conf": mosquitto_conf,
                    "username": username,
                    "password": allow_token,
                    "fanout_publisher_username": username,
                    "fanout_publisher_password": allow_token,
                    "topic": base_topic,
                    "traffic_pattern": "fanout",
                    "subscriber_count": 10,
                    "fanout_topic": base_topic,
                    "authz_config": _http_hybrid_fanout_authz_config_profile_matrix(
                        cast(Literal["simple", "med", "complex"], tier),
                        topic=base_topic,
                        deny_read=False,
                    ),
                    "netem": {"clear": True},
                    "message_size": 256,
                    "qos": 1,
                    "policy_source": source_key,
                    "authz_profile": tier,
                    "acl_read_enforcement": "strict",
                }
                scenarios[
                    f"{source_label}-ACL-READ-FANOUT-STRICT-{tier.upper()}-DENY-{token_label}-10"
                ] = {
                    "mosquitto_conf": mosquitto_conf,
                    "username": username,
                    "password": deny_token,
                    "fanout_publisher_username": username,
                    "fanout_publisher_password": allow_token,
                    "topic": base_topic,
                    "traffic_pattern": "fanout",
                    "subscriber_count": 10,
                    "fanout_topic": base_topic,
                    "authz_config": _http_hybrid_fanout_authz_config_profile_matrix(
                        cast(Literal["simple", "med", "complex"], tier),
                        topic=base_topic,
                        deny_read=True,
                    ),
                    "netem": {"clear": True},
                    "message_size": 256,
                    "qos": 1,
                    "policy_source": source_key,
                    "authz_profile": tier,
                    "acl_read_enforcement": "strict",
                }

                if tier != "med":
                    continue

                for subscribers in (50, 100):
                    scenarios[
                        f"{source_label}-ACL-READ-FANOUT-STRICT-{tier.upper()}-ALLOW-{token_label}-{subscribers}"
                    ] = {
                        "mosquitto_conf": mosquitto_conf,
                        "username": username,
                        "password": allow_token,
                        "fanout_publisher_username": username,
                        "fanout_publisher_password": allow_token,
                        "topic": base_topic,
                        "traffic_pattern": "fanout",
                        "subscriber_count": subscribers,
                        "fanout_topic": base_topic,
                        "authz_config": _http_hybrid_fanout_authz_config_profile_matrix(
                            cast(Literal["simple", "med", "complex"], tier),
                            topic=base_topic,
                            deny_read=False,
                        ),
                        "netem": {"clear": True},
                        "message_size": 256,
                        "qos": 1,
                        "policy_source": source_key,
                        "authz_profile": tier,
                        "acl_read_enforcement": "strict",
                    }

    return scenarios


def _infer_policy_source(scenario: ScenarioConfig) -> str | None:
    conf = str(scenario.get("mosquitto_conf", ""))
    if "mosquitto_http" in conf:
        return "http"
    if "mosquitto_hybrid" in conf:
        return "hybrid"
    if "mosquitto_dynsec" in conf or "mosquitto_anon" in conf:
        return "dynamic_security"
    if "mosquitto_sqlite" in conf:
        return "sqlite"
    if "mosquitto_static" in conf:
        return "static_acl"
    if "mosquitto_base" in conf:
        return "none"
    if "mosquitto" in conf:
        return "token"
    return None


def _infer_acl_read_enforcement(
    scenario: ScenarioConfig,
) -> Literal["expiry_only", "strict"]:
    if "acl_read_enforcement" in scenario:
        return cast(Literal["expiry_only", "strict"], scenario["acl_read_enforcement"])
    conf = str(scenario.get("mosquitto_conf", ""))
    strict_conf_suffixes = (
        "mosquitto_integration_acl_read_full.conf",
        "mosquitto_dynsec_acl_read.conf",
        "mosquitto_sqlite_acl_read.conf",
        "mosquitto_http_acl_read.conf",
        "mosquitto_hybrid_acl_read.conf",
    )
    return "strict" if conf.endswith(strict_conf_suffixes) else "expiry_only"


def _sqlite_rbac_churn_toggle_scenarios(tokens: dict[str, Any]) -> dict[str, ScenarioConfig]:
    base_topic = "fanout/broadcast"
    return {
        "SQLITE-RBAC-CHURN-JWT": {
            "mosquitto_conf": "./mosquitto_sqlite_acl_read.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "fanout_publisher_username": "jwt",
            "fanout_publisher_password": tokens["jwt"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": 50,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "sqlite_seed_fanout": True,
            "sqlite_seed_profile": "fanout_basic",
            "sqlite_seed_db": "docker/sqlite/policy.db",
            "sqlite_seed_topic": base_topic,
            "sqlite_seed_subscribers": 50,
            "fanout_churn_kind": "sqlite_toggle_read",
            "fanout_churn_after_messages": 4,
            "fanout_churn_interval_messages": 4,
            "fanout_churn_max_events": 4,
            "fanout_churn_settle_ms": 800,
            "fanout_churn_sqlite_db": "docker/sqlite/policy.db",
            "fanout_churn_sqlite_topic": base_topic,
            "fanout_churn_sqlite_subscribers": 50,
        },
        "SQLITE-RBAC-CHURN-BISCUIT": {
            "mosquitto_conf": "./mosquitto_sqlite_acl_read.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "fanout_publisher_username": "biscuit",
            "fanout_publisher_password": tokens["biscuit"],
            "topic": base_topic,
            "traffic_pattern": "fanout",
            "subscriber_count": 50,
            "fanout_topic": base_topic,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "sqlite_seed_fanout": True,
            "sqlite_seed_profile": "fanout_basic",
            "sqlite_seed_db": "docker/sqlite/policy.db",
            "sqlite_seed_topic": base_topic,
            "sqlite_seed_subscribers": 50,
            "fanout_churn_kind": "sqlite_toggle_read",
            "fanout_churn_after_messages": 4,
            "fanout_churn_interval_messages": 4,
            "fanout_churn_max_events": 4,
            "fanout_churn_settle_ms": 800,
            "fanout_churn_sqlite_db": "docker/sqlite/policy.db",
            "fanout_churn_sqlite_topic": base_topic,
            "fanout_churn_sqlite_subscribers": 50,
        },
    }


def _sqlite_rbac_deep_toggle_scenarios(tokens: dict[str, Any]) -> dict[str, ScenarioConfig]:
    return {
        "SQLITE-RBAC-DEEP-CONFLICT-JWT": {
            "mosquitto_conf": "./mosquitto_sqlite_acl_read.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "fanout_publisher_username": "jwt",
            "fanout_publisher_password": tokens["jwt"],
            "topic": "sensors/private/broadcast",
            "traffic_pattern": "fanout",
            "subscriber_count": 50,
            "fanout_topic": "sensors/private/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "sqlite_seed_fanout": True,
            "sqlite_seed_profile": "rbac_deep",
            "sqlite_seed_db": "docker/sqlite/policy.db",
            "sqlite_seed_topic": "sensors/private/broadcast",
            "sqlite_seed_subscribers": 50,
            "fanout_churn_kind": "sqlite_toggle_private_deny",
            "fanout_churn_after_messages": 4,
            "fanout_churn_interval_messages": 4,
            "fanout_churn_max_events": 4,
            "fanout_churn_settle_ms": 800,
            "fanout_churn_sqlite_db": "docker/sqlite/policy.db",
            "fanout_churn_sqlite_topic": "sensors/private/broadcast",
            "fanout_churn_sqlite_subscribers": 50,
        },
        "SQLITE-RBAC-DEEP-CONFLICT-BISCUIT": {
            "mosquitto_conf": "./mosquitto_sqlite_acl_read.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "fanout_publisher_username": "biscuit",
            "fanout_publisher_password": tokens["biscuit"],
            "topic": "sensors/private/broadcast",
            "traffic_pattern": "fanout",
            "subscriber_count": 50,
            "fanout_topic": "sensors/private/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "sqlite_seed_fanout": True,
            "sqlite_seed_profile": "rbac_deep",
            "sqlite_seed_db": "docker/sqlite/policy.db",
            "sqlite_seed_topic": "sensors/private/broadcast",
            "sqlite_seed_subscribers": 50,
            "fanout_churn_kind": "sqlite_toggle_private_deny",
            "fanout_churn_after_messages": 4,
            "fanout_churn_interval_messages": 4,
            "fanout_churn_max_events": 4,
            "fanout_churn_settle_ms": 800,
            "fanout_churn_sqlite_db": "docker/sqlite/policy.db",
            "fanout_churn_sqlite_topic": "sensors/private/broadcast",
            "fanout_churn_sqlite_subscribers": 50,
        },
        "SQLITE-RBAC-DEEP-CONTROL-JWT": {
            "mosquitto_conf": "./mosquitto_sqlite_acl_read.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "system/notifications/acl-change",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 128,
            "qos": 1,
            "subscriber_count": 1,
            "sqlite_seed_fanout": True,
            "sqlite_seed_profile": "rbac_deep_control_allow",
            "sqlite_seed_db": "docker/sqlite/policy.db",
            "sqlite_seed_topic": "sensors/private/broadcast",
            "sqlite_seed_subscribers": 1,
            "control_mode": True,
            "control_repeat": 5,
            "control_topic": "$CONTROL/dynamic-security/v1",
            "control_payload": {"commands": [{"command": "listClients"}]},
            "client_count": 1,
        },
        "SQLITE-RBAC-DEEP-CONTROL-BISCUIT": {
            "mosquitto_conf": "./mosquitto_sqlite_acl_read.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "system/notifications/acl-change",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 128,
            "qos": 1,
            "subscriber_count": 1,
            "sqlite_seed_fanout": True,
            "sqlite_seed_profile": "rbac_deep_control_allow",
            "sqlite_seed_db": "docker/sqlite/policy.db",
            "sqlite_seed_topic": "sensors/private/broadcast",
            "sqlite_seed_subscribers": 1,
            "control_mode": True,
            "control_repeat": 5,
            "control_topic": "$CONTROL/dynamic-security/v1",
            "control_payload": {"commands": [{"command": "listClients"}]},
            "client_count": 1,
        },
    }


def _build_available_scenarios(
    tokens: dict[str, Any],
    *,
    token_issuer_no_default_roles: bool,
    token_issuer_no_default_grants: bool,
) -> dict[str, ScenarioConfig]:
    authorizer_template_scenarios = _biscuit_authorizer_template_scenarios(tokens)
    available_scenarios: dict[str, ScenarioConfig] = {
        "BASELINE-NO-AUTH": {
            "mosquitto_conf": "./mosquitto_base.conf",
            "username": "",
            "password": "",
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "qos": 0,
        },
        "BASELINE-NO-AUTH-QOS0": {
            "mosquitto_conf": "./mosquitto_base.conf",
            "username": "",
            "password": "",
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "qos": 0,
        },
        "TOKEN-BASELINE-JWT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
        },
        "TOKEN-ISSUER-BASELINE-JWT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "token_refresh": {"kind": "jwt", "ttl_seconds": 300},
            "credential_freshness_required": True,
        },
        "TOKEN-QOS2-JWT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "qos": 2,
        },
        "TOKEN-DENY-READ-JWT": {
            "mosquitto_conf": "./mosquitto_integration_acl_read_full.conf",
            "username": "jwt",
            "password": tokens["jwt_fanout_read_deny"],
            "fanout_publisher_username": "jwt",
            "fanout_publisher_password": tokens["jwt_fanout_allow"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "qos": 1,
            "subscriber_count": 10,
            "acl_read_enforcement": "strict",
        },
        "TOKEN-BASELINE-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
        },
        "TOKEN-ISSUER-BASELINE-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "token_refresh": {"kind": "biscuit", "ttl_seconds": 300},
            "credential_freshness_required": True,
        },
        "TOKEN-PUBLISH-STRESS-JWT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "publish_authz",
            "complexity_level": "baseline",
        },
        "TOKEN-PUBLISH-STRESS-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "publish_authz",
            "complexity_level": "baseline",
        },
        "TOKEN-QOS2-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "qos": 2,
        },
        "TOKEN-QOS-MIXED-JWT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "qos": 1,
            "qos_distribution": "0:0.6,1:0.3,2:0.1",
        },
        "TOKEN-QOS-MIXED-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "qos": 1,
            "qos_distribution": "0:0.6,1:0.3,2:0.1",
        },
        "TOKEN-ATTENUATED-DENY-BISCUIT": {
            "mosquitto_conf": "./mosquitto_integration_acl_read_full.conf",
            "username": "biscuit",
            "password": tokens["biscuit_fanout_read_deny"],
            "fanout_publisher_username": "biscuit",
            "fanout_publisher_password": tokens["biscuit_fanout_allow"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "qos": 1,
            "subscriber_count": 10,
            "acl_read_enforcement": "strict",
        },
        "TOKEN-ATTENUATION-COMBINED-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "biscuit_attenuate": {
                "denies": ["subscribe:sensors/{client_id}/temp"],
                "checks": ['resource("sensors/{client_id}/temp")'],
                "ttl_seconds": 300,
            },
            "attenuation_probe_subscribe_denied": True,
        },
        "TOKEN-ATTENUATION-TTL-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "biscuit_attenuate": {"ttl_seconds": 120},
        },
        "TOKEN-ATTENUATION-SUBSCRIBE-DENY-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "biscuit_attenuate": {
                "denies": ["subscribe:sensors/{client_id}/temp"],
                "checks": ['resource("sensors/{client_id}/temp")'],
            },
            "attenuation_probe_subscribe_denied": True,
        },
        "TOKEN-ATTENUATION-PUBLISH-ONLY-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "biscuit_attenuate": {"op": "publish"},
            "attenuation_probe_subscribe_denied": True,
        },
        "TOKEN-COMPLEXITY-CHAIN-1-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "chain_length",
        },
        "TOKEN-COMPLEXITY-CHAIN-5-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_5"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "chain_length",
            "complexity_level": "med",
        },
        "TOKEN-COMPLEXITY-CHAIN-25-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_25"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "chain_length",
            "complexity_level": "high",
        },
        "TOKEN-COMPLEXITY-DATALOG-LOW-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_low"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "datalog",
            "complexity_level": "low",
        },
        "TOKEN-DATALOG-STRESS-LOW-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_low"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "datalog",
            "complexity_level": "low",
        },
        "TOKEN-COMPLEXITY-DATALOG-MED-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_med"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "datalog",
            "complexity_level": "med",
        },
        "TOKEN-DATALOG-STRESS-MED-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_med"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "datalog",
            "complexity_level": "med",
        },
        "TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-MED-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_med"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "qos": 1,
            "complexity_axis": "datalog",
            "complexity_level": "med",
            "biscuit_attenuate": {
                "ttl_seconds": 300,
                "topic": "sensors/{client_id}/temp",
                "op": "publish",
            },
            "attenuation_probe_subscribe_denied": True,
        },
        "TOKEN-COMPOSABILITY-DELEGATED-DATALOG-MED-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_med"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "qos": 1,
            "complexity_axis": "datalog",
            "complexity_level": "med",
            "biscuit_delegate": {
                "ttl_seconds": 300,
                "topic": "sensors/{client_id}/temp",
                "op": "publish",
                "handoff": {
                    "topic": "delegation/handoff",
                    "token": tokens["biscuit_delegation_handoff"],
                    "qos": 1,
                    "retain": True,
                },
            },
            "attenuation_probe_subscribe_denied": True,
        },
        "TOKEN-COMPLEXITY-DATALOG-HIGH-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_high"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "datalog",
            "complexity_level": "high",
        },
        "TOKEN-DATALOG-STRESS-HIGH-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_high"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "datalog",
            "complexity_level": "high",
        },
        "TOKEN-COMPOSABILITY-ATTENUATED-DATALOG-HIGH-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_high"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "qos": 1,
            "complexity_axis": "datalog",
            "complexity_level": "high",
            "biscuit_attenuate": {
                "ttl_seconds": 300,
                "topic": "sensors/{client_id}/temp",
                "op": "publish",
            },
            "attenuation_probe_subscribe_denied": True,
        },
        "TOKEN-COMPOSABILITY-DELEGATED-DATALOG-HIGH-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_complex_high"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "qos": 1,
            "complexity_axis": "datalog",
            "complexity_level": "high",
            "biscuit_delegate": {
                "ttl_seconds": 300,
                "topic": "sensors/{client_id}/temp",
                "op": "publish",
                "handoff": {
                    "topic": "delegation/handoff",
                    "token": tokens["biscuit_delegation_handoff"],
                    "qos": 1,
                    "retain": True,
                },
            },
            "attenuation_probe_subscribe_denied": True,
        },
        **authorizer_template_scenarios,
        **_static_acl_scenarios(tokens),
        **_acl_read_fanout_churn_scenarios(tokens),
        **_acl_read_profile_matrix_scenarios(tokens),
        **_sqlite_rbac_churn_toggle_scenarios(tokens),
        **_sqlite_rbac_deep_toggle_scenarios(tokens),
        "HTTP-LATENCY-200MS-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _tuned_profile_authz_config(
                "simple",
                delay_ms=200,
                fail_mode="none",
            ),
            "netem": {"clear": True},
            "message_size": 0,
            "http_expected_delay_ms": 200,
        },
        "HTTP-PROFILE-SIMPLE-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("simple"),
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "http_profile",
            "complexity_level": "simple",
        },
        "HTTP-AUTHZ-COMPLEXITY-SIMPLE-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("simple"),
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "http_profile",
            "complexity_level": "simple",
        },
        "HTTP-PROFILE-MED-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("med"),
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "http_profile",
            "complexity_level": "med",
        },
        "HTTP-AUTHZ-COMPLEXITY-MED-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("med"),
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "http_profile",
            "complexity_level": "med",
        },
        "HTTP-PROFILE-COMPLEX-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("complex"),
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "http_profile",
            "complexity_level": "complex",
        },
        "HTTP-AUTHZ-COMPLEXITY-COMPLEX-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("complex"),
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "http_profile",
            "complexity_level": "complex",
        },
        "HTTP-LATENCY-1000MS-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _tuned_profile_authz_config(
                "simple",
                delay_ms=1000,
                fail_mode="none",
            ),
            "netem": {"clear": True},
            "message_size": 0,
            "http_expected_delay_ms": 1000,
        },
        "HYBRID-FALLBACK-AUTHZ-DOWN-JWT": {
            "mosquitto_conf": "./mosquitto_hybrid.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _tuned_profile_authz_config(
                "simple",
                delay_ms=0,
                fail_mode="always",
            ),
            "netem": {"clear": True},
            "message_size": 0,
            "hybrid_fallback_required": True,
        },
        "NETWORK-MTU-200-JWT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"mtu": 200},
            "message_size": 0,
        },
        "HTTP-LATENCY-200MS-BISCUIT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _tuned_profile_authz_config(
                "simple",
                delay_ms=200,
                fail_mode="none",
            ),
            "netem": {"clear": True},
            "message_size": 0,
        },
        "HTTP-PROFILE-SIMPLE-BISCUIT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("simple"),
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "http_profile",
            "complexity_level": "simple",
        },
        "HTTP-AUTHZ-COMPLEXITY-SIMPLE-BISCUIT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("simple"),
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "http_profile",
            "complexity_level": "simple",
        },
        "HTTP-PROFILE-MED-BISCUIT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("med"),
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "http_profile",
            "complexity_level": "med",
        },
        "HTTP-AUTHZ-COMPLEXITY-MED-BISCUIT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("med"),
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "http_profile",
            "complexity_level": "med",
        },
        "HTTP-PROFILE-COMPLEX-BISCUIT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("complex"),
            "netem": {"clear": True},
            "message_size": 0,
            "complexity_axis": "http_profile",
            "complexity_level": "complex",
        },
        "HTTP-AUTHZ-COMPLEXITY-COMPLEX-BISCUIT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _http_profile_authz_config("complex"),
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "complexity_axis": "http_profile",
            "complexity_level": "complex",
        },
        "HTTP-FAILURE-INJECTION-200MS-1PCT-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _tuned_profile_authz_config(
                "simple",
                delay_ms=200,
                fail_mode="rate",
                fail_rate=0.01,
            ),
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 100,
            "http_failure_rate": 0.01,
            "allowed_error_prefixes": ["publish_failed:"],
        },
        "HTTP-FAILURE-INJECTION-200MS-5PCT-JWT": {
            "mosquitto_conf": "./mosquitto_http.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": _tuned_profile_authz_config(
                "simple",
                delay_ms=200,
                fail_mode="rate",
                fail_rate=0.05,
            ),
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 100,
            "http_failure_rate": 0.05,
            "allowed_error_prefixes": ["publish_failed:"],
        },
        "TOKEN-MQTT5-REAUTH-JWT": {
            "mosquitto_conf": "./mosquitto.conf",
            "authz_config": None,
            "netem": {"clear": True},
            "client_count": 1,
            "message_count": 2,
            "qos": 1,
            "workload_kind": "mqtt5_reauth_transition",
            "authorization_probe_count": 1,
            "mqtt5_auth": {
                "kind": "jwt",
                "token1_ttl_seconds": 180,
                "token2_ttl_seconds": 300,
            },
        },
        "TOKEN-MQTT5-REAUTH-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "authz_config": None,
            "netem": {"clear": True},
            "client_count": 1,
            "message_count": 2,
            "qos": 1,
            "workload_kind": "mqtt5_reauth_transition",
            "authorization_probe_count": 1,
            "mqtt5_auth": {
                "kind": "biscuit",
                "token1_ttl_seconds": 180,
                "token2_ttl_seconds": 300,
            },
        },
        "TOKEN-THUNDERING-HERD-JWT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "restart_mosquitto": True,
            "sync_connect": True,
        },
        "TOKEN-THUNDERING-HERD-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "restart_mosquitto": True,
            "sync_connect": True,
        },
        "TOKEN-DELEGATION-TEMP-ONLY-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "biscuit_delegate": {
                "topic": "sensors/{client_id}/temp",
                "op": "publish",
                "ttl_seconds": 300,
            },
        },
        "TOKEN-DELEGATION-HANDOFF-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "biscuit_delegate": {
                "topic": "sensors/{client_id}/temp",
                "op": "publish",
                "ttl_seconds": 300,
                "handoff": {
                    "topic": "delegation/handoff",
                    "token": tokens["biscuit_delegation_handoff"],
                    "qos": 1,
                    "retain": True,
                },
            },
        },
        "TOKEN-DELEGATION-SIMULATED-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_delegated"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
        },
        "TOKEN-LIFECYCLE-SHORT-RECONNECT-JWT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "jwt",
            "password": tokens["jwt_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "repeat": 3,
            "sleep_between": 2,
            "token_refresh": {"kind": "jwt", "ttl_seconds": 5},
        },
        "TOKEN-LIFECYCLE-SHORT-RECONNECT-BISCUIT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "biscuit",
            "password": tokens["biscuit_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "repeat": 3,
            "sleep_between": 2,
            "token_refresh": {"kind": "biscuit", "ttl_seconds": 5},
        },
        "TOKEN-LIFECYCLE-RECONNECT-PUBLISH-JWT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "jwt",
            "password": tokens["jwt_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "message_count": 25,
            "client_count": 25,
            "repeat": 6,
            "sleep_between": 1,
            "token_refresh": {"kind": "jwt", "ttl_seconds": 30},
        },
        "TOKEN-LIFECYCLE-RECONNECT-PUBLISH-BISCUIT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "biscuit",
            "password": tokens["biscuit_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "message_count": 25,
            "client_count": 25,
            "repeat": 6,
            "sleep_between": 1,
            "token_refresh": {"kind": "biscuit", "ttl_seconds": 30},
        },
        "TOKEN-PUBLISH-STRESS-RECONNECT-JWT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "jwt",
            "password": tokens["jwt_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "qos": 1,
            "repeat": 6,
            "sleep_between": 1,
            "token_refresh": {"kind": "jwt", "ttl_seconds": 30},
            "credential_freshness_required": True,
            "complexity_axis": "publish_authz_reconnect",
            "complexity_level": "baseline",
        },
        "TOKEN-PUBLISH-STRESS-RECONNECT-BISCUIT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "biscuit",
            "password": tokens["biscuit_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "client_count": 25,
            "message_count": 1000,
            "qos": 1,
            "repeat": 6,
            "sleep_between": 1,
            "token_refresh": {"kind": "biscuit", "ttl_seconds": 30},
            "credential_freshness_required": True,
            "complexity_axis": "publish_authz_reconnect",
            "complexity_level": "baseline",
        },
        "TOKEN-LIFECYCLE-PROACTIVE-REAUTH-JWT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "jwt",
            "password": tokens["jwt_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "repeat": 2,
            "client_count": 1,
            "token_refresh": {"kind": "jwt", "ttl_seconds": 75},
            "proactive_refresh": True,
            "proactive_refresh_margin_seconds": 60,
            "proactive_refresh_timeout_seconds": 10,
            "proactive_refresh_assert_continuity": True,
        },
        "TOKEN-LIFECYCLE-PROACTIVE-REAUTH-BISCUIT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "biscuit",
            "password": tokens["biscuit_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "repeat": 2,
            "client_count": 1,
            "token_refresh": {"kind": "biscuit", "ttl_seconds": 75},
            "proactive_refresh": True,
            "proactive_refresh_margin_seconds": 60,
            "proactive_refresh_timeout_seconds": 10,
            "proactive_refresh_assert_continuity": True,
        },
        "TOKEN-LIFECYCLE-REAUTH-STORM-JWT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "jwt",
            "password": tokens["jwt_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "message_count": 1,
            "client_count": 25,
            "token_refresh": {"kind": "jwt", "ttl_seconds": 75},
            "proactive_refresh": True,
            "proactive_refresh_margin_seconds": 60,
            "proactive_refresh_timeout_seconds": 10,
            "proactive_refresh_assert_continuity": True,
            "reauth_storm": True,
        },
        "TOKEN-LIFECYCLE-REAUTH-STORM-BISCUIT": {
            "mosquitto_conf": "./mosquitto_shortcache.conf",
            "username": "biscuit",
            "password": tokens["biscuit_short"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "message_count": 1,
            "client_count": 25,
            "token_refresh": {"kind": "biscuit", "ttl_seconds": 75},
            "proactive_refresh": True,
            "proactive_refresh_margin_seconds": 60,
            "proactive_refresh_timeout_seconds": 10,
            "proactive_refresh_assert_continuity": True,
            "reauth_storm": True,
        },
        "DYNAMIC-SECURITY-BASELINE": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "dynsec_client_1",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "dynamic_security_generated_profile": "publish_multi_client_base",
            "authorization_probe_subscribe_denied": True,
        },
        "DYNAMIC-SECURITY-CHURN": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "dynsec_client_1",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "dynamic_security_generated_profile": "publish_multi_client_base",
            "control_topic": "$CONTROL/dynamic-security/v1",
            "control_payload": dynsec_commands.generate_command_payload(
                [
                    dynsec_commands.generate_remove_role_acl_command(
                        "sensor_writer",
                        "publishClientSend",
                        "sensors/+/#",
                    )
                ]
            ),
            "runtime_control_username": "admin",
            "runtime_control_password": tokens["jwt_admin"],
            "runtime_control_after_messages": 10,
            "runtime_control_expect_denial": True,
        },
        "DYNAMIC-SECURITY-READ-FANOUT": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "dynsec_client_1",
            "password": tokens["jwt"],
            "fanout_publisher_username": "dynsec_publisher",
            "fanout_publisher_password": tokens["jwt"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "dynamic_security_config": "docker/dynamic-security.json",
            "subscriber_count": 1,
        },
        # Issue 19: ACL_READ fan-out authorization cost measurement scenarios
        # These scenarios measure per-subscriber authorization scaling with varying counts
        "TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-JWT-10": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "fanout_publisher_username": "jwt",
            "fanout_publisher_password": tokens["jwt"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "subscriber_count": 10,
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
        },
        "TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-JWT-50": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "fanout_publisher_username": "jwt",
            "fanout_publisher_password": tokens["jwt"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "subscriber_count": 50,
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
        },
        "TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-JWT-100": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "fanout_publisher_username": "jwt",
            "fanout_publisher_password": tokens["jwt"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "subscriber_count": 100,
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
        },
        "TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-BISCUIT-10": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "fanout_publisher_username": "biscuit",
            "fanout_publisher_password": tokens["biscuit"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "subscriber_count": 10,
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
        },
        "TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-BISCUIT-50": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "fanout_publisher_username": "biscuit",
            "fanout_publisher_password": tokens["biscuit"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "subscriber_count": 50,
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
        },
        "TOKEN-ACL-READ-FANOUT-EXPIRY-ONLY-BISCUIT-100": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "fanout_publisher_username": "biscuit",
            "fanout_publisher_password": tokens["biscuit"],
            "topic": "fanout/broadcast",
            "traffic_pattern": "fanout",
            "subscriber_count": 100,
            "fanout_topic": "fanout/broadcast",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
        },
        # Issue 35: CONTROL-CHURN scenarios with actual Dynamic Security command payloads
        # These scenarios exercise actual policy modifications via Dynamic Security commands
        "CONTROL-CHURN-CREATE-ROLE-JWT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-CREATE-ROLE-JWT",
            token=tokens["jwt_admin"],
            client_count=1,
            control_repeat=3,
        ),
        "CONTROL-CHURN-CREATE-ROLE-BISCUIT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-CREATE-ROLE-BISCUIT",
            token=tokens["biscuit_admin"],
            client_count=1,
            control_repeat=3,
        ),
        "CONTROL-CHURN-GROUP-CLIENT-JWT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-GROUP-CLIENT-JWT",
            token=tokens["jwt_admin"],
            client_count=1,
            control_repeat=2,
        ),
        "CONTROL-CHURN-GROUP-CLIENT-BISCUIT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-GROUP-CLIENT-BISCUIT",
            token=tokens["biscuit_admin"],
            client_count=1,
            control_repeat=2,
        ),
        "CONTROL-CHURN-ACL-MODIFY-JWT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-ACL-MODIFY-JWT",
            token=tokens["jwt_admin"],
            client_count=1,
            control_repeat=2,
        ),
        "CONTROL-CHURN-ACL-MODIFY-BISCUIT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-ACL-MODIFY-BISCUIT",
            token=tokens["biscuit_admin"],
            client_count=1,
            control_repeat=2,
        ),
        "CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-JWT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-JWT",
            token=tokens["jwt_admin"],
            client_count=1,
            control_repeat=1,
            dynamic_security_config=None,
            dynamic_security_generated_profile="large_state_control",
        ),
        "CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-BISCUIT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-LARGE-STATE-GROUP-CLIENT-BISCUIT",
            token=tokens["biscuit_admin"],
            client_count=1,
            control_repeat=1,
            dynamic_security_config=None,
            dynamic_security_generated_profile="large_state_control",
        ),
        "CONTROL-CHURN-NOOP-GROUP-CLIENT-JWT": {
            **_control_churn_scenario(
                scenario_id="CONTROL-CHURN-NOOP-GROUP-CLIENT-JWT",
                token=tokens["jwt_admin"],
                client_count=1,
                control_repeat=1,
                dynamic_security_config=None,
                dynamic_security_generated_profile="fanout_control_noop_group",
            ),
            "control_payload": _require_control_churn_payload(
                "CONTROL-CHURN-NOOP-GROUP-CLIENT-JWT", "dynsec_client_1"
            ),
        },
        "CONTROL-CHURN-NOOP-GROUP-CLIENT-BISCUIT": {
            **_control_churn_scenario(
                scenario_id="CONTROL-CHURN-NOOP-GROUP-CLIENT-BISCUIT",
                token=tokens["biscuit_admin"],
                client_count=1,
                control_repeat=1,
                dynamic_security_config=None,
                dynamic_security_generated_profile="fanout_control_noop_group",
            ),
            "control_payload": _require_control_churn_payload(
                "CONTROL-CHURN-NOOP-GROUP-CLIENT-BISCUIT", "dynsec_client_1"
            ),
        },
        "CONTROL-CHURN-REPEAT-SAME-ENTITY-JWT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-REPEAT-SAME-ENTITY-JWT",
            token=tokens["jwt_admin"],
            client_count=10,
            control_repeat=3,
        ),
        "CONTROL-CHURN-REPEAT-SAME-ENTITY-BISCUIT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-REPEAT-SAME-ENTITY-BISCUIT",
            token=tokens["biscuit_admin"],
            client_count=10,
            control_repeat=3,
        ),
        "CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-JWT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-JWT",
            token=tokens["jwt_admin"],
            client_count=10,
            control_repeat=3,
        ),
        "CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-BISCUIT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-REPEAT-DISTINCT-ENTITY-BISCUIT",
            token=tokens["biscuit_admin"],
            client_count=10,
            control_repeat=3,
        ),
        "CONTROL-CHURN-CONCURRENT-CONTROLLERS-JWT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-CONCURRENT-CONTROLLERS-JWT",
            token=tokens["jwt_admin"],
            client_count=50,
            control_repeat=1,
        ),
        "CONTROL-CHURN-CONCURRENT-CONTROLLERS-BISCUIT": _control_churn_scenario(
            scenario_id="CONTROL-CHURN-CONCURRENT-CONTROLLERS-BISCUIT",
            token=tokens["biscuit_admin"],
            client_count=50,
            control_repeat=1,
        ),
        # Issue 36: Interleaved control message scenarios
        # These scenarios publish control messages interleaved with data messages
        # to measure control plane latency under active data plane load.
        "CONTROL-INTERLEAVED-DATA-JWT": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "control_topic": "$CONTROL/dynamic-security/v1",
            "control_payload": {"commands": [{"command": "getClient", "username": "jwt"}]},
            "control_mode": False,
            "control_repeat": 1,
            "control_after_messages": 10,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_generated_profile": "control_interleaved_base",
        },
        "CONTROL-INTERLEAVED-DATA-BISCUIT": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "control_topic": "$CONTROL/dynamic-security/v1",
            "control_payload": {"commands": [{"command": "getClient", "username": "biscuit"}]},
            "control_mode": False,
            "control_repeat": 1,
            "control_after_messages": 10,
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_generated_profile": "control_interleaved_base",
        },
        # Issue 29: Anonymous flow scenario using Dynamic Security anonymousGroup
        # Demonstrates how Dynamic Security can enforce policies for unauthenticated clients
        "DYNAMIC-SECURITY-ANONYMOUS-BASELINE": {
            "mosquitto_conf": "./mosquitto_anon.conf",
            "username": "",
            "password": "",
            "topic": "public/announce",
            "traffic_pattern": "fanout",
            "fanout_topic": "public/announce",
            "fanout_publisher_username": "",
            "fanout_publisher_password": "",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_config": "docker/dynamic-security-anon.json",
        },
    }

    # Add dynamic MTU scenarios
    for mtu in [500, 1500, 9000]:
        available_scenarios[f"NETWORK-MTU-{mtu}-BISCUIT-CHAIN-25"] = {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_25"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"mtu": mtu},
            "message_size": 0,
        }
        available_scenarios[f"NETWORK-MTU-{mtu}-JWT"] = {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"mtu": mtu},
            "message_size": 0,
        }

    # Real runtime enforcement workloads replace the former transport-only
    # control scenarios and restart-between-repeat pseudo-churn case.
    for token_label in ("JWT", "BISCUIT"):
        kick_source = f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-DISABLE-{token_label}-10"
        notify_source = f"DYNAMIC-SECURITY-ACL-READ-FANOUT-CONTROL-REVOKE-{token_label}-10"
        available_scenarios[f"CONTROL-ENFORCEMENT-KICK-{token_label}"] = {
            **available_scenarios[kick_source],
            "complexity_axis": None,
        }
        available_scenarios[f"CONTROL-ENFORCEMENT-ACL-READ-NOTIFY-{token_label}"] = {
            **available_scenarios[notify_source],
            "fanout_expect_control_notification": True,
            "complexity_axis": None,
        }

    available_scenarios = _apply_scenario_classification(available_scenarios, tokens)
    available_scenarios = _apply_result_contracts(available_scenarios)

    for scenario in available_scenarios.values():
        scenario.setdefault("token_issuer_no_default_roles", token_issuer_no_default_roles)
        scenario.setdefault("token_issuer_no_default_grants", token_issuer_no_default_grants)

    _validate_part2_sweep_inventory(available_scenarios)
    return available_scenarios


@app.command()
def main(
    tokens_path: str = "benchmarks/tokens.json",
    out: str = "benchmarks/results",
    clients: int = 50,
    messages: int = 20,
    qos: int = 1,
    qos_distribution: str | None = None,
    scenarios_arg: str | None = None,
    workload_shape: str = typer.Option(
        "all",
        "--workload-shape",
        help=(
            "Select all scenarios or one workload binding: matrix, fixed-clients, "
            "fixed-messages, or fixed."
        ),
    ),
    token_issuer_no_default_roles: bool = False,
    token_issuer_no_default_grants: bool = False,
    token_refresh_codes: str | None = typer.Option(None, envvar="TOKEN_REFRESH_CODES"),
    tls: bool = False,
    tls_insecure: bool = False,
    tls_ca_file: str | None = None,
    summary_json: str = "summary.json",
    summary_csv: str = "summary.csv",
    no_summary_csv: bool = False,
    log_level: str = typer.Option("INFO", "--log-level"),
    # iperf3 baseline configuration
    iperf3_enabled: bool = typer.Option(True, "--iperf3/--no-iperf3"),
    iperf3_host: str = typer.Option("localhost", "--iperf3-host"),
    iperf3_port: int = typer.Option(5201, "--iperf3-port"),
    iperf3_duration: int = typer.Option(5, "--iperf3-duration"),
    iperf3_streams: int = typer.Option(4, "--iperf3-streams"),
    iperf3_min_mbps: float = typer.Option(100.0, "--iperf3-min-mbps"),
    # perf profiling configuration
    perf_enabled: bool = typer.Option(False, "--perf/--no-perf"),
    perf_duration: int = typer.Option(10, "--perf-duration"),
    perf_sample_rate: int = typer.Option(1000, "--perf-sample-rate"),
    perf_events: str = typer.Option("cycles,instructions,cache-misses", "--perf-events"),
    perf_callgraph: bool = typer.Option(True, "--perf-callgraph/--no-perf-callgraph"),
    perf_scenarios: str | None = typer.Option(
        None,
        "--perf-scenarios",
        help="Comma-separated list of scenarios to profile (default: key scenarios)",
    ),
    perf_output_dir: str = typer.Option("benchmarks/results/perf", "--perf-output-dir"),
    # tcpdump packet capture configuration
    tcpdump_enabled: bool = typer.Option(True, "--tcpdump/--no-tcpdump"),
    tcpdump_filter: str = typer.Option("port 1883 or port 8883", "--tcpdump-filter"),
    tcpdump_duration: int = typer.Option(300, "--tcpdump-duration"),
    tcpdump_output_dir: str = typer.Option("benchmarks/results/pcap", "--tcpdump-output-dir"),
    tcpdump_analyze: bool = typer.Option(True, "--tcpdump-analyze/--no-tcpdump-analyze"),
    client_topology: str = typer.Option(
        DEFAULT_CLIENT_TOPOLOGY,
        "--client-topology",
        help="Client execution topology: host, container-single, or container-per-client.",
    ),
    loadgen_service: str = typer.Option("loadgen", "--client-loadgen-service"),
    loadgen_cpus: str = typer.Option("1.0", "--client-cpus"),
    loadgen_memory: str = typer.Option("512m", "--client-memory"),
    loadgen_cpuset: str | None = typer.Option(None, "--client-cpuset"),
    reauth_storm_clients: int | None = typer.Option(
        None,
        "--reauth-storm-clients",
        help="Override client count for TOKEN-LIFECYCLE-REAUTH-STORM scenarios.",
    ),
    biscuit_delegate_handoff_ready_timeout_seconds: int = typer.Option(
        120,
        "--biscuit-delegate-handoff-ready-timeout-seconds",
        help="Readiness and token receive timeout for Biscuit delegation handoff roles.",
    ),
):
    if not isinstance(log_level, str):
        log_level = "INFO"
    if not isinstance(workload_shape, str):
        workload_shape = "all"
    valid_workload_shapes = {"all", "matrix", "fixed-clients", "fixed-messages", "fixed"}
    if workload_shape not in valid_workload_shapes:
        raise typer.BadParameter(
            "workload_shape must be one of: all, matrix, fixed-clients, fixed-messages, fixed"
        )
    setup_logging(log_level)
    iperf3_enabled = _coerce_bool_arg(iperf3_enabled, True)
    perf_enabled = _coerce_bool_arg(perf_enabled, False)
    perf_callgraph = _coerce_bool_arg(perf_callgraph, True)
    tcpdump_enabled = _coerce_bool_arg(tcpdump_enabled, True)
    tcpdump_analyze = _coerce_bool_arg(tcpdump_analyze, True)
    if not isinstance(client_topology, str):
        client_topology = DEFAULT_CLIENT_TOPOLOGY
    if not isinstance(loadgen_service, str):
        loadgen_service = "loadgen"
    if not isinstance(loadgen_cpus, str):
        loadgen_cpus = "1.0"
    if not isinstance(loadgen_memory, str):
        loadgen_memory = "512m"
    if not isinstance(loadgen_cpuset, str):
        loadgen_cpuset = None
    if not isinstance(reauth_storm_clients, int):
        reauth_storm_clients = None
    if reauth_storm_clients is not None and reauth_storm_clients <= 1:
        raise typer.BadParameter("reauth_storm_clients must be greater than one")
    if not isinstance(biscuit_delegate_handoff_ready_timeout_seconds, int):
        biscuit_delegate_handoff_ready_timeout_seconds = 120
    tcpdump_output_dir = _coerce_output_dir_arg(
        tcpdump_output_dir,
        "benchmarks/results/pcap",
    )
    if not isinstance(token_refresh_codes, str):
        token_refresh_codes = None
    if not isinstance(iperf3_host, str):
        iperf3_host = "localhost"
    if not isinstance(iperf3_port, int):
        iperf3_port = 5201
    if not isinstance(iperf3_duration, int):
        iperf3_duration = 5
    if not isinstance(iperf3_streams, int):
        iperf3_streams = 4
    if isinstance(iperf3_min_mbps, bool) or not isinstance(iperf3_min_mbps, int | float):
        iperf3_min_mbps = 100.0
    else:
        iperf3_min_mbps = float(iperf3_min_mbps)
    if not isinstance(perf_duration, int):
        perf_duration = 10
    if not isinstance(perf_sample_rate, int):
        perf_sample_rate = 1000
    if not isinstance(perf_events, str):
        perf_events = "cycles,instructions,cache-misses"
    perf_output_dir = _coerce_output_dir_arg(
        perf_output_dir,
        "benchmarks/results/perf",
    )
    if not isinstance(perf_scenarios, str):
        perf_scenarios = None
    if not isinstance(tcpdump_filter, str):
        tcpdump_filter = "port 1883 or port 8883"
    if not isinstance(tcpdump_duration, int):
        tcpdump_duration = 300
    if client_topology not in {"host", "container-single", "container-per-client"}:
        raise typer.BadParameter(
            "client_topology must be one of: host, container-single, container-per-client"
        )
    client_topology_mode = cast(ClientTopology, client_topology)

    # Check perf installation if profiling enabled
    perf_status: dict[str, Any] = {"enabled": perf_enabled}
    if perf_enabled:
        perf_check = check_perf_installation()
        perf_status["installed"] = perf_check["installed"]
        perf_status["version"] = perf_check.get("version")
        if not perf_check["installed"]:
            logger.warning(
                "perf profiling requested but not installed: %s", perf_check.get("error")
            )
            logger.warning(
                "Install with: sudo apt-get install linux-tools-common linux-tools-generic"
            )
        else:
            logger.info(
                "perf profiling enabled (version: %s)", perf_check.get("version", "unknown")
            )
            logger.info("Events: %s, Duration: %ds", perf_events, perf_duration)

    # Check pcap parser availability if packet capture enabled
    tcpdump_status: dict[str, Any] = {"enabled": tcpdump_enabled}
    if tcpdump_enabled:
        parser_check = check_pcap_parser_available()
        tcpdump_status["installed"] = parser_check["installed"]
        tcpdump_status["parser"] = parser_check.get("parser")
        tcpdump_status["version"] = parser_check.get("version")
        if not parser_check["installed"]:
            logger.warning(
                "Packet capture requested but no parser available: %s", parser_check.get("error")
            )
            logger.warning("Packet analysis will be skipped. Install dpkt (preferred) or tcpdump.")
        else:
            logger.info(
                "Packet capture enabled using %s parser (version: %s)",
                parser_check.get("parser", "unknown"),
                parser_check.get("version", "unknown"),
            )
            logger.info("Filter: %s, Duration: %ds", tcpdump_filter, tcpdump_duration)

    tokens: dict[str, Any] = _read_tokens(str(_resolve_repo_path(tokens_path)))

    scenarios: list[ScenarioConfig] = []
    tls_enabled = tls
    tls_ca = tls_ca_file or ("docker/tls/ca.pem" if tls_enabled else None)
    normalized_tcpdump_output_dir = _normalize_tcpdump_output_dir(tcpdump_output_dir)
    if tls_enabled and tls_ca and not _resolve_repo_path(tls_ca).exists():
        raise SystemExit(
            f"TLS enabled but CA file not found at {tls_ca}. Run docker/tls/generate_certs.sh"
        )
    if scenarios_arg:
        scenario_ids = [s.strip() for s in scenarios_arg.split(",")]
        available_scenarios = _build_available_scenarios(
            tokens,
            token_issuer_no_default_roles=token_issuer_no_default_roles,
            token_issuer_no_default_grants=token_issuer_no_default_grants,
        )
        available_scenarios = _expand_tls_matrix(available_scenarios)

        # Select requested scenarios
        for scenario_id in scenario_ids:
            _require_requested_scenario_fixtures(scenario_id, tokens)
            if scenario_id in available_scenarios:
                scenario = available_scenarios[scenario_id].copy()
                if workload_shape != "all" and _scenario_workload_shape(scenario) != workload_shape:
                    continue
                scenario["id"] = scenario_id
                scenarios.append(
                    cast(
                        ScenarioConfig,
                        ScenarioModel.model_validate(scenario).model_dump(),
                    )
                )
            else:
                raise typer.BadParameter(f"Unknown scenario: {scenario_id}")
    else:
        logger.info(
            "No scenarios specified. Use --scenarios-arg to specify which scenarios to run."
        )
        logger.info("Available scenarios:")
        available_scenarios = _build_available_scenarios(
            tokens,
            token_issuer_no_default_roles=token_issuer_no_default_roles,
            token_issuer_no_default_grants=token_issuer_no_default_grants,
        )
        for scenario_id in sorted(_expand_tls_matrix(available_scenarios)):
            logger.info("%s", scenario_id)
        logger.info("Append -TLS to any scenario id for TLS variants.")
        return

    for s in scenarios:
        _validate_scenario_credentials(s["id"], s)
        scenario_semantics = _scenario_semantics_metadata(
            s["id"],
            s,
            default_clients=clients,
        )
        scenario_tls = bool(s.get("tls")) or tls_enabled
        scenario_tls_ca_config = (
            tls_ca if tls_ca else ("docker/tls/ca.pem" if scenario_tls else None)
        )
        scenario_tls_ca = (
            str(_resolve_repo_path(scenario_tls_ca_config)) if scenario_tls_ca_config else None
        )
        if scenario_tls and scenario_tls_ca and not Path(scenario_tls_ca).exists():
            raise SystemExit(
                f"{s['id']} enables TLS but CA file was not found at {scenario_tls_ca_config}. "
                "Run docker/tls/generate_certs.sh"
            )
        mosq_conf = s["mosquitto_conf"]
        if scenario_tls:
            mosq_conf = mosq_conf.replace("./", "./tls/")
        runtime_mosq_conf = _effective_mosquitto_runtime_conf(
            mosq_conf,
            jwt_identity_binding=cast(
                IdentityBindingMode,
                scenario_semantics["jwt_identity_binding"],
            ),
            biscuit_identity_binding=cast(
                IdentityBindingMode,
                scenario_semantics["biscuit_identity_binding"],
            ),
            biscuit_client_id_fact=cast(
                str,
                s.get("biscuit_client_id_fact", "client_id"),
            ),
        )
        extra_env = {"MOSQUITTO_CONF": runtime_mosq_conf}
        endpoints = _scenario_endpoint_config(
            client_topology_mode=client_topology_mode,
            scenario_tls=scenario_tls,
            tls_ca=scenario_tls_ca,
        )
        authz_base = endpoints["authz_base"]
        prom_base = endpoints["prom_base"]
        token_issuer_base = endpoints["token_issuer_base"]
        loadgen_token_issuer_base = endpoints["loadgen_token_issuer_base"]
        host_mqtt_host = endpoints["host_mqtt_host"]
        loadgen_mqtt_host = endpoints["loadgen_mqtt_host"]
        mqtt_port = endpoints["mqtt_port"]
        loadgen_tls_ca = endpoints["loadgen_tls_ca"]
        extra_env["MOSQUITTO_HEALTH_PORT"] = str(mqtt_port)
        compose_files = ["docker/docker-compose.yml"]
        if scenario_tls:
            compose_files.append("docker/docker-compose.tls.yml")

        netem = s.get("netem")
        if netem:
            if netem.get("clear"):
                extra_env.update(
                    {
                        "NETEM_CLEAR": "1",
                        "NETEM_MTU": "",
                        "NETEM_DELAY_MS": "",
                        "NETEM_LOSS_PCT": "",
                        "NETEM_RATE_KBIT": "",
                    }
                )
            if "mtu" in netem:
                extra_env.update(
                    {
                        "NETEM_CLEAR": "1",
                        "NETEM_MTU": str(netem["mtu"]),
                        "LOADGEN_MTU": str(netem["mtu"]),
                    }
                )
            if "delay_ms" in netem:
                extra_env.update({"NETEM_CLEAR": "1", "NETEM_DELAY_MS": str(netem["delay_ms"])})
            if "loss_pct" in netem:
                extra_env.update({"NETEM_CLEAR": "1", "NETEM_LOSS_PCT": str(netem["loss_pct"])})

        token_issuer_no_default_grants = s.get(
            "token_issuer_no_default_grants", token_issuer_no_default_grants
        )
        token_issuer_no_default_roles = s.get(
            "token_issuer_no_default_roles", token_issuer_no_default_roles
        )
        extra_env.update(
            {
                "TOKEN_ISSUER_ALLOW_DEFAULT_KEYS": os.environ.get(
                    "TOKEN_ISSUER_ALLOW_DEFAULT_KEYS", "1"
                ),
                "JWT_NO_DEFAULT_ROLES": "1" if token_issuer_no_default_roles else "0",
                "JWT_NO_DEFAULT_GRANTS": "1" if token_issuer_no_default_grants else "0",
            }
        )

        with _dynamic_security_scenario_config(
            s,
            extra_env=extra_env,
            compose_files=compose_files,
            host=host_mqtt_host,
            port=mqtt_port,
        ) as dynamic_security_state:
            if s.get("sqlite_seed_fanout"):
                _seed_sqlite_scenario_policy(
                    s,
                    default_clients=clients,
                    allow_replace=True,
                )

            core_services = [
                "up",
                "--build",
                "-d",
                "mosquitto",
                "authz",
                "metrics-collector",
                "cadvisor",
                "token-issuer",
                "iperf3",
            ]
            namespace_services = ["netem"]

            # Auto-enable tcpdump for MTU scenarios to capture fragmentation data
            netem = s.get("netem")
            capture_this_scenario = (
                tcpdump_enabled
                and tcpdump_status.get("installed", False)
                and netem is not None
                and "mtu" in netem
            )
            if netem is not None and "mtu" in netem:
                if not tcpdump_enabled or not tcpdump_analyze:
                    raise RuntimeError(
                        f"{s['id']}: MTU scenarios require tcpdump capture and analysis"
                    )
                if not tcpdump_status.get("installed", False):
                    raise RuntimeError(f"{s['id']}: packet parser unavailable for MTU contract")

            if capture_this_scenario:
                namespace_services.append("tcpdump")
                pcap_filename = f"{s['id']}.pcap"
                extra_env.update(
                    {
                        "TCPDUMP_FILTER": tcpdump_filter,
                        "TCPDUMP_DURATION": str(tcpdump_duration),
                        "TCPDUMP_OUTPUT": f"/pcap/{pcap_filename}",
                        "TCPDUMP_OUTPUT_DIR": normalized_tcpdump_output_dir,
                        "TCPDUMP_KEEP_ALIVE": "0",
                    }
                )
                Path(normalized_tcpdump_output_dir).mkdir(parents=True, exist_ok=True)

            compose_project_name = extra_env.get("COMPOSE_PROJECT_NAME") or os.environ.get(
                "COMPOSE_PROJECT_NAME"
            )
            _compose_checked(
                ["rm", "-s", "-f", "netem", "tcpdump"],
                extra_env=extra_env,
                compose_files=compose_files,
                phase="namespace-service cleanup",
            )
            _compose_checked(
                core_services,
                extra_env=extra_env,
                compose_files=compose_files,
                phase="core service startup",
            )
            dynamic_security_state.broker_started = True
            try:
                _wait_for_mqtt_listener(host_mqtt_host, mqtt_port)
            except RuntimeError as exc:
                diagnostics = _compose_diagnostics(
                    extra_env=extra_env,
                    compose_files=compose_files,
                )
                raise RuntimeError(f"mosquitto startup failed: {exc}\n{diagnostics}") from exc
            broker_config_attestation = _broker_config_attestation(
                requested_path=mosq_conf,
                effective_path=runtime_mosq_conf,
                compose_files=compose_files,
                compose_project_name=compose_project_name,
                extra_env=extra_env,
            )
            _compose_checked(
                ["up", "--build", "--no-deps", "-d", *namespace_services],
                extra_env=extra_env,
                compose_files=compose_files,
                phase="namespace-service startup",
            )
            if capture_this_scenario:
                _wait_for_tcpdump_ready(extra_env=extra_env, compose_files=compose_files)
            effective_mtu: int | None = None
            if netem is not None and "mtu" in netem:
                requested_mtu = int(netem["mtu"])
                effective_mtu = _read_effective_mtu(
                    interface=os.environ.get("NETEM_IFACE", "eth0"),
                    extra_env=extra_env,
                    compose_files=compose_files,
                    compose_project_name=compose_project_name,
                )
                if effective_mtu != requested_mtu:
                    raise RuntimeError(
                        f"{s['id']}: effective MTU {effective_mtu} != requested {requested_mtu}"
                    )
            _wait_for_service_health("authz", authz_base, scenario_tls_ca, tls_insecure)
            _wait_for_service_health(
                "token-issuer",
                token_issuer_base,
                scenario_tls_ca,
                tls_insecure,
            )
            _wait_for_prometheus_api(prom_base, scenario_tls_ca, tls_insecure)
            _wait_for_non_empty_resource_snapshot(
                prom_base,
                scenario_tls_ca,
                tls_insecure,
                compose_files=compose_files,
                compose_project_name=compose_project_name,
            )

            # Run iperf3 baseline measurement before test batch
            iperf3_baseline_result: dict[str, Any] = {}
            network_validity: dict[str, Any] = {}
            if iperf3_enabled:
                time.sleep(2)  # Give iperf3 server time to start
                iperf3_baseline_result = run_baseline_with_retry(
                    host=iperf3_host,
                    port=iperf3_port,
                    duration=iperf3_duration,
                    parallel_streams=iperf3_streams,
                    retries=2,
                )
                network_validity = check_network_validity(
                    iperf3_baseline_result,
                    expected_min_mbps=iperf3_min_mbps,
                )
                if network_validity.get("warnings"):
                    for warning in network_validity["warnings"]:
                        logger.warning("Network baseline: %s", warning)
                else:
                    throughput_mbps = iperf3_baseline_result.get("throughput", {}).get(
                        "megabits_per_second", 0
                    )
                    logger.info("Network baseline: %.2f Mbps capacity confirmed", throughput_mbps)

            cfg = s.get("authz_config")
            uses_http_authz = (
                "mosquitto_http.conf" in s["mosquitto_conf"]
                or "mosquitto_hybrid.conf" in s["mosquitto_conf"]
                or cfg is not None
            )
            reset_baseline: dict[str, object] | None = None
            if uses_http_authz:
                reset_res = _authz_reset(
                    authz_base,
                    ca_file=scenario_tls_ca,
                    insecure=tls_insecure,
                )
                reset_baseline = _validated_authz_state_baseline(
                    s["id"],
                    "authz reset",
                    reset_res,
                )
                _assert_authz_state(
                    s["id"],
                    "authz reset",
                    reset_res,
                    reset_baseline,
                )

            if cfg is not None:
                if reset_baseline is None:
                    raise RuntimeError(
                        "Authz reset baseline unavailable before config apply in scenario "
                        f"{s['id']}"
                    )
                apply_res = _authz_config(
                    authz_base,
                    delay_ms=cfg.get("delay_ms"),
                    fail_mode=cfg.get("fail_mode"),
                    fail_rate=cfg.get("fail_rate"),
                    authz_profile=cfg.get("authz_profile"),
                    rules=cfg.get("rules"),
                    client_roles=cfg.get("client_roles"),
                    jwt_identity_binding=cfg.get("jwt_identity_binding"),
                    ca_file=scenario_tls_ca,
                    insecure=tls_insecure,
                )
                _assert_authz_state(
                    s["id"],
                    "authz config apply",
                    apply_res,
                    _expected_authz_state(cfg, reset_baseline),
                )

            repeats = int(s.get("repeat", 1))
            token_len = len(s.get("password", "")) if s.get("password") else 0
            token_issuer_no_default_grants = s.get(
                "token_issuer_no_default_grants", token_issuer_no_default_grants
            )
            token_issuer_no_default_roles = s.get(
                "token_issuer_no_default_roles", token_issuer_no_default_roles
            )
            token_schema = tokens.get("jwt_grants_schema")
            token_schema_version = token_schema.get("version") if token_schema else None
            token_denies_schema = tokens.get("jwt_denies_schema")
            token_denies_schema_version = (
                token_denies_schema.get("version") if token_denies_schema else None
            )
            grants_default_enabled = None
            if s.get("username") == "jwt" and token_schema is not None:
                grants_default_enabled = not token_issuer_no_default_grants

            biscuit_only = bool(s.get("biscuit_attenuate") or s.get("biscuit_delegate"))
            complexity_axis = s.get("complexity_axis")
            complexity_level = s.get("complexity_level")
            policy_source = s.get("policy_source") or _infer_policy_source(s)
            authz_profile = s.get("authz_profile")
            if authz_profile is None and isinstance(s.get("authz_config"), dict):
                authz_profile = cast(dict[str, Any], s["authz_config"]).get("authz_profile")
            authorizer_profile = s.get("authorizer_profile")
            acl_read_enforcement = _infer_acl_read_enforcement(s)
            if s.get("reauth_storm") and client_topology_mode == "container-per-client":
                raise RuntimeError(
                    f"{s['id']}: reauth storm is only supported with host or "
                    "container-single topology"
                )
            effective_client_count = (
                int(reauth_storm_clients)
                if s.get("reauth_storm") and reauth_storm_clients is not None
                else _effective_scenario_client_count(s, clients)
            )
            if (
                isinstance(s.get("netem"), dict)
                and "mtu" in cast(dict[str, Any], s["netem"])
                and effective_client_count > 1
                and client_topology_mode != "container-per-client"
            ):
                raise RuntimeError(
                    f"{s['id']}: multi-client MTU capture requires container-per-client "
                    "topology for client-correlated packet evidence"
                )
            configured_messages = int(s.get("message_count", messages))
            scenario_messages = _effective_scenario_message_count(
                s,
                messages,
                effective_clients=effective_client_count,
            )
            scenario_qos = int(s.get("qos", qos))
            scenario_qos_distribution = s.get("qos_distribution", qos_distribution)
            scenario_workload_shape = _scenario_workload_shape(s)
            if scenario_messages > configured_messages:
                logger.info(
                    "%s requires at least %d messages per client for thresholded behavior; "
                    "raising the configured count from %d",
                    s["id"],
                    scenario_messages,
                    configured_messages,
                )
            out_payload: dict[str, Any] = {
                "result_schema_version": 2,
                "scenario": s["id"],
                "token_len": token_len,
                "token_schema": token_schema,
                "token_metadata": {
                    "jwt_grants_schema_version": token_schema_version,
                    "jwt_default_grants_enabled": grants_default_enabled,
                    "jwt_denies_schema_version": token_denies_schema_version,
                },
                "tls": {
                    "enabled": scenario_tls,
                    "ca_file": scenario_tls_ca,
                    "insecure": tls_insecure,
                    "purpose": "transport_encryption",
                    "certificate_validation_tested": False,
                },
                "parity": {
                    "token_issuer_no_default_roles": token_issuer_no_default_roles,
                    "token_issuer_no_default_grants": token_issuer_no_default_grants,
                    "token_refresh_codes": token_refresh_codes,
                },
                "capability_flags": {
                    "biscuit_only": biscuit_only,
                },
                "complexity": {
                    "axis": complexity_axis,
                    "level": complexity_level,
                },
                "attenuation": s.get("biscuit_attenuate"),
                "delegation": s.get("biscuit_delegate"),
                "scenario_config": {
                    **scenario_semantics,
                    "clients": effective_client_count,
                    "requested_clients": clients,
                    "client_count": s.get("client_count"),
                    "messages": scenario_messages,
                    "requested_messages": messages,
                    "workload_shape": scenario_workload_shape,
                    "workload_axes": _scenario_workload_axes(s),
                    "qos": scenario_qos,
                    "requested_qos": qos,
                    "qos_distribution": scenario_qos_distribution,
                    "requested_qos_distribution": qos_distribution,
                    "token_issuer_no_default_roles": token_issuer_no_default_roles,
                    "token_issuer_no_default_grants": token_issuer_no_default_grants,
                    "proactive_refresh": s.get("proactive_refresh", False),
                    "proactive_refresh_margin_seconds": s.get("proactive_refresh_margin_seconds"),
                    "proactive_refresh_timeout_seconds": s.get("proactive_refresh_timeout_seconds"),
                    "proactive_refresh_assert_continuity": s.get(
                        "proactive_refresh_assert_continuity", False
                    ),
                    "reauth_storm": s.get("reauth_storm", False),
                    "credential_mode": s.get("credential_mode"),
                    "password_map_profile": s.get("password_map_profile"),
                    "fanout_publisher_password_map_profile": s.get(
                        "fanout_publisher_password_map_profile"
                    ),
                    "traffic_pattern": s.get("traffic_pattern"),
                    "workload_kind": s.get("workload_kind"),
                    "authorization_probe_count": s.get("authorization_probe_count"),
                    "fanout_topic": s.get("fanout_topic"),
                    "subscriber_count": s.get("subscriber_count"),
                    "policy_source": policy_source,
                    "authz_profile": authz_profile,
                    "authorizer_profile": authorizer_profile,
                    "acl_read_enforcement": acl_read_enforcement,
                    "fanout_churn_kind": s.get("fanout_churn_kind"),
                    "fanout_churn_after_messages": s.get("fanout_churn_after_messages"),
                    "fanout_churn_interval_messages": s.get("fanout_churn_interval_messages"),
                    "fanout_churn_max_events": s.get("fanout_churn_max_events"),
                    "fanout_churn_settle_ms": s.get("fanout_churn_settle_ms"),
                    "fanout_churn_control_topic": s.get("fanout_churn_control_topic"),
                    "fanout_churn_control_payload": s.get("fanout_churn_control_payload"),
                    "runtime_control_after_messages": s.get("runtime_control_after_messages"),
                    "runtime_control_expect_denial": s.get("runtime_control_expect_denial", False),
                    "sqlite_seed_fanout": s.get("sqlite_seed_fanout"),
                    "sqlite_seed_profile": s.get("sqlite_seed_profile"),
                    "sqlite_seed_db": s.get("sqlite_seed_db"),
                    "sqlite_seed_topic": s.get("sqlite_seed_topic"),
                    "sqlite_seed_subscribers": s.get("sqlite_seed_subscribers"),
                    "fanout_churn_sqlite_db": s.get("fanout_churn_sqlite_db"),
                    "fanout_churn_sqlite_topic": s.get("fanout_churn_sqlite_topic"),
                    "fanout_churn_sqlite_subscribers": s.get("fanout_churn_sqlite_subscribers"),
                    "client_topology": {
                        "mode": client_topology_mode,
                        "effective_mode": client_topology_mode,
                        "loadgen_service": loadgen_service,
                        "cpus": loadgen_cpus,
                        "memory": loadgen_memory,
                        "cpuset": loadgen_cpuset,
                        "internal_mqtt_host": (
                            loadgen_mqtt_host if client_topology_mode != "host" else None
                        ),
                        "internal_token_issuer_url": (
                            loadgen_token_issuer_base if client_topology_mode != "host" else None
                        ),
                    },
                    "cache_context": {
                        "acl_read_enforcement_expected": acl_read_enforcement,
                        "cache_ttl_seconds": 3600,
                        "note": (
                            "strict ACL_READ scenarios should enforce policy changes on fan-out "
                            "delivery; cache must not mask runtime authorization changes"
                        ),
                    },
                },
                "broker_config_attestation": broker_config_attestation,
                "fanout_metrics": {
                    "subscriber_count": (
                        effective_client_count if s.get("traffic_pattern") == "fanout" else None
                    ),
                    "message_count": (
                        scenario_messages if s.get("traffic_pattern") == "fanout" else None
                    ),
                },
                "network_baseline": {
                    "enabled": iperf3_enabled,
                    "config": {
                        "host": iperf3_host,
                        "port": iperf3_port,
                        "duration": iperf3_duration,
                        "streams": iperf3_streams,
                        "min_mbps": iperf3_min_mbps,
                    },
                    "result": iperf3_baseline_result,
                    "validity": network_validity,
                },
                "perf_profiling": {
                    "enabled": perf_enabled and perf_status.get("installed", False),
                    "config": {
                        "duration": perf_duration,
                        "sample_rate": perf_sample_rate,
                        "events": perf_events,
                        "callgraph": perf_callgraph,
                        "output_dir": perf_output_dir,
                    },
                    "status": perf_status,
                },
                "packet_analysis": {
                    "enabled": tcpdump_enabled and tcpdump_status.get("installed", False),
                    "config": {
                        "filter": tcpdump_filter,
                        "duration": tcpdump_duration,
                        "output_dir": tcpdump_output_dir,
                        "analyze": tcpdump_analyze,
                    },
                    "status": tcpdump_status,
                },
                "runs": [],
            }

            broker_restart: dict[str, Any] | None = None
            if s.get("restart_mosquitto"):
                _restart_mosquitto(
                    extra_env=extra_env,
                    compose_files=compose_files,
                    host=host_mqtt_host,
                    port=mqtt_port,
                )
                broker_restart = {
                    "completed": True,
                    "completed_at_unix_ms": int(time.time() * 1000),
                    "scenario_id": s["id"],
                }

            _validate_dynamic_security_alignment(s["id"], s, default_clients=clients)
            for idx in range(repeats):
                try:
                    if uses_http_authz:
                        _authz_stats(
                            authz_base,
                            reset=True,
                            ca_file=scenario_tls_ca,
                            insecure=tls_insecure,
                        )
                    _reset_generated_dynamic_security_between_repeats(
                        idx,
                        dynamic_security_state.generated_path,
                        extra_env=extra_env,
                        compose_files=compose_files,
                        host=host_mqtt_host,
                        port=mqtt_port,
                    )
                    if s.get("dynamic_security_churn"):
                        churn_list = cast(list[str], s["dynamic_security_churn"])
                        _apply_dynamic_security_config(churn_list[idx % len(churn_list)])
                        _restart_mosquitto(
                            extra_env=extra_env,
                            compose_files=compose_files,
                            host=host_mqtt_host,
                            port=mqtt_port,
                        )
                    if idx > 0 and s.get("sqlite_seed_fanout"):
                        _seed_sqlite_scenario_policy(
                            s,
                            default_clients=clients,
                            allow_replace=False,
                        )
                    mqtt5_cfg = s.get("mqtt5_auth")
                    scenario_clients = effective_client_count
                    attest_broker_auth = bool(broker_config_attestation["plugin_enabled"])
                    broker_diagnostics_before = (
                        _broker_diagnostic_snapshot(
                            compose_files=compose_files,
                            compose_project_name=compose_project_name,
                            extra_env=extra_env,
                        )
                        if attest_broker_auth
                        else {}
                    )
                    workload_started_at = time.time()
                    if mqtt5_cfg is not None:
                        token1, token2, credential_metadata = _resolve_mqtt5_auth_tokens(
                            s["id"],
                            s,
                            token_issuer_base,
                            ca_file=scenario_tls_ca,
                            insecure=tls_insecure,
                        )
                        res = _run_mqtt5_auth(
                            host_mqtt_host if client_topology_mode == "host" else loadgen_mqtt_host,
                            mqtt_port,
                            token1,
                            token2,
                            str(credential_metadata["token1_topic"]),
                            str(credential_metadata["token2_topic"]),
                            scenario_tls,
                            (scenario_tls_ca if client_topology_mode == "host" else loadgen_tls_ca),
                            tls_insecure,
                            client_id=str(credential_metadata["client_id"]),
                            client_topology=client_topology_mode,
                            service=loadgen_service,
                            scenario_id=s["id"],
                            run_index=idx,
                            compose_files=compose_files,
                            compose_project_name=compose_project_name,
                            extra_env=extra_env,
                        )
                        res["credential_attestation"] = credential_metadata
                    else:
                        token_refresh = s.get("token_refresh")
                        proactive_refresh = bool(s.get("proactive_refresh", False))
                        credential_mode = cast(
                            CredentialMode,
                            s.get("credential_mode", "shared"),
                        )
                        strict_startup_provisioning = (
                            None
                            if credential_mode == "per_client"
                            else _scenario_requires_per_client_strict_provisioning(
                                s["id"],
                                s,
                                default_clients=clients,
                            )
                        )
                        startup_token_kind = (
                            strict_startup_provisioning[0]
                            if strict_startup_provisioning is not None
                            else None
                        )
                        res = _run_loadgen(
                            tokens=tokens,
                            host=loadgen_mqtt_host,
                            port=mqtt_port,
                            username=s.get("username", ""),
                            password=("" if credential_mode == "issuer" else s.get("password", "")),
                            fanout_publisher_username=s.get("fanout_publisher_username"),
                            fanout_publisher_password=s.get("fanout_publisher_password"),
                            clients=scenario_clients,
                            messages=scenario_messages,
                            topic=s.get("topic", "sensors/{client_id}/temp"),
                            mode=s.get("traffic_pattern"),
                            fanout_topic=s.get("fanout_topic"),
                            qos=scenario_qos,
                            qos_distribution=scenario_qos_distribution,
                            message_size=int(s.get("message_size", 0)),
                            http_failure_rate=s.get("http_failure_rate"),
                            sync_connect=bool(s.get("sync_connect", False)),
                            token_issuer_url=(
                                loadgen_token_issuer_base
                                if credential_mode == "issuer"
                                or token_refresh
                                or proactive_refresh
                                or strict_startup_provisioning is not None
                                else None
                            ),
                            token_issuer_kind=(
                                token_refresh.get("kind") if token_refresh else startup_token_kind
                            ),
                            token_issuer_ttl=(
                                token_refresh.get("ttl_seconds") if token_refresh else None
                            ),
                            token_issuer_no_default_roles=token_issuer_no_default_roles,
                            token_issuer_no_default_grants=token_issuer_no_default_grants,
                            token_refresh_codes=token_refresh_codes,
                            proactive_refresh=proactive_refresh,
                            proactive_refresh_margin_seconds=s.get(
                                "proactive_refresh_margin_seconds"
                            ),
                            proactive_refresh_timeout_seconds=s.get(
                                "proactive_refresh_timeout_seconds"
                            ),
                            proactive_refresh_assert_continuity=bool(
                                s.get("proactive_refresh_assert_continuity", False)
                            ),
                            reauth_storm=bool(s.get("reauth_storm", False)),
                            jwt_identity_binding=cast(
                                IdentityBindingMode,
                                scenario_semantics["jwt_identity_binding"],
                            ),
                            biscuit_identity_binding=cast(
                                IdentityBindingMode,
                                scenario_semantics["biscuit_identity_binding"],
                            ),
                            biscuit_client_id_fact=cast(
                                str,
                                s.get("biscuit_client_id_fact", "client_id"),
                            ),
                            tls_enabled=scenario_tls,
                            tls_ca_file=loadgen_tls_ca,
                            tls_insecure=tls_insecure,
                            biscuit_attenuate=bool(s.get("biscuit_attenuate")),
                            biscuit_attenuate_denies=(
                                s.get("biscuit_attenuate", {}).get("denies")
                                if s.get("biscuit_attenuate")
                                else None
                            ),
                            biscuit_attenuate_checks=(
                                s.get("biscuit_attenuate", {}).get("checks")
                                if s.get("biscuit_attenuate")
                                else None
                            ),
                            biscuit_attenuate_topic=(
                                s.get("biscuit_attenuate", {}).get("topic")
                                if s.get("biscuit_attenuate")
                                else None
                            ),
                            biscuit_attenuate_op=(
                                s.get("biscuit_attenuate", {}).get("op")
                                if s.get("biscuit_attenuate")
                                else None
                            ),
                            biscuit_attenuate_ttl=(
                                s.get("biscuit_attenuate", {}).get("ttl_seconds")
                                if s.get("biscuit_attenuate")
                                else None
                            ),
                            attenuation_probe_subscribe_denied=bool(
                                s.get("attenuation_probe_subscribe_denied", False)
                                or s.get("authorization_probe_subscribe_denied", False)
                            ),
                            biscuit_public_key_hex=s.get("biscuit_public_key_hex"),
                            biscuit_public_key_file=(
                                _container_repo_path(
                                    s.get("biscuit_public_key_file", "docker/biscuit_public.key")
                                )
                                if client_topology_mode != "host"
                                else s.get("biscuit_public_key_file", "docker/biscuit_public.key")
                            ),
                            biscuit_delegate=bool(s.get("biscuit_delegate")),
                            biscuit_delegate_denies=(
                                s.get("biscuit_delegate", {}).get("denies")
                                if s.get("biscuit_delegate")
                                else None
                            ),
                            biscuit_delegate_checks=(
                                s.get("biscuit_delegate", {}).get("checks")
                                if s.get("biscuit_delegate")
                                else None
                            ),
                            biscuit_delegate_topic=(
                                s.get("biscuit_delegate", {}).get("topic")
                                if s.get("biscuit_delegate")
                                else None
                            ),
                            biscuit_delegate_op=(
                                s.get("biscuit_delegate", {}).get("op")
                                if s.get("biscuit_delegate")
                                else None
                            ),
                            biscuit_delegate_ttl=(
                                s.get("biscuit_delegate", {}).get("ttl_seconds")
                                if s.get("biscuit_delegate")
                                else None
                            ),
                            biscuit_delegate_public_key_hex=s.get(
                                "biscuit_delegate_public_key_hex"
                            ),
                            biscuit_delegate_public_key_file=(
                                _container_repo_path(
                                    s.get(
                                        "biscuit_delegate_public_key_file",
                                        "docker/biscuit_public.key",
                                    )
                                )
                                if client_topology_mode != "host"
                                else s.get(
                                    "biscuit_delegate_public_key_file",
                                    "docker/biscuit_public.key",
                                )
                            ),
                            biscuit_delegate_handoff=bool(
                                s.get("biscuit_delegate", {}).get("handoff")
                                if s.get("biscuit_delegate")
                                else False
                            ),
                            biscuit_delegate_handoff_topic=(
                                s.get("biscuit_delegate", {}).get("handoff", {}).get("topic")
                                if s.get("biscuit_delegate")
                                else None
                            ),
                            biscuit_delegate_handoff_token=(
                                s.get("biscuit_delegate", {}).get("handoff", {}).get("token")
                                if s.get("biscuit_delegate")
                                else None
                            ),
                            biscuit_delegate_handoff_qos=(
                                s.get("biscuit_delegate", {}).get("handoff", {}).get("qos")
                                if s.get("biscuit_delegate")
                                else None
                            ),
                            biscuit_delegate_handoff_retain=(
                                s.get("biscuit_delegate", {}).get("handoff", {}).get("retain")
                                if s.get("biscuit_delegate")
                                else None
                            ),
                            biscuit_delegate_handoff_ready_timeout_seconds=(
                                biscuit_delegate_handoff_ready_timeout_seconds
                            ),
                            control_topic=s.get("control_topic"),
                            control_payload=s.get("control_payload")
                            or _generate_control_churn_payload(s["id"], "admin"),
                            control_mode=bool(s.get("control_mode", False)),
                            control_repeat=s.get("control_repeat", 1),
                            control_response_topic=s.get("control_response_topic"),
                            control_after_messages=s.get("control_after_messages", 0),
                            runtime_control_username=s.get("runtime_control_username"),
                            runtime_control_password=s.get("runtime_control_password"),
                            runtime_control_after_messages=s.get(
                                "runtime_control_after_messages", 0
                            ),
                            runtime_control_expect_denial=bool(
                                s.get("runtime_control_expect_denial", False)
                            ),
                            fanout_churn_kind=s.get("fanout_churn_kind"),
                            fanout_churn_after_messages=s.get("fanout_churn_after_messages", 0),
                            fanout_churn_interval_messages=s.get(
                                "fanout_churn_interval_messages", 0
                            ),
                            fanout_churn_max_events=s.get("fanout_churn_max_events", 1),
                            fanout_churn_settle_ms=s.get("fanout_churn_settle_ms", 0),
                            fanout_churn_phase_delivery=(
                                cast(DeliveryContract, s.get("delivery_contract", {})).get("phases")
                            ),
                            fanout_churn_dynamic_security_source=(
                                _container_repo_path(s.get("fanout_churn_dynamic_security_source"))
                                if client_topology_mode != "host"
                                else s.get("fanout_churn_dynamic_security_source")
                            ),
                            fanout_churn_control_topic=s.get("fanout_churn_control_topic"),
                            fanout_churn_control_payload=s.get("fanout_churn_control_payload"),
                            fanout_expect_control_notification=bool(
                                s.get("fanout_expect_control_notification", False)
                            ),
                            fanout_churn_sqlite_db=(
                                _container_repo_path(s.get("fanout_churn_sqlite_db"))
                                if client_topology_mode != "host"
                                else s.get("fanout_churn_sqlite_db")
                            ),
                            fanout_churn_sqlite_topic=s.get("fanout_churn_sqlite_topic"),
                            fanout_churn_sqlite_subscribers=s.get(
                                "fanout_churn_sqlite_subscribers"
                            ),
                            client_topology=client_topology_mode,
                            compose_files=compose_files,
                            compose_project_name=compose_project_name,
                            compose_env=extra_env,
                            loadgen_service=loadgen_service,
                            loadgen_cpus=loadgen_cpus,
                            loadgen_memory=loadgen_memory,
                            loadgen_cpuset=loadgen_cpuset,
                            scenario_id=s["id"],
                            run_index=idx,
                            password_map_path=(
                                "benchmarks/password-map.json"
                                if credential_mode == "per_client"
                                else None
                            ),
                            password_map_profile=s.get("password_map_profile"),
                            fanout_publisher_password_map_profile=s.get(
                                "fanout_publisher_password_map_profile"
                            ),
                        )
                    res.setdefault(
                        "topology",
                        {
                            "mode": client_topology_mode,
                            "container_count": 0 if client_topology_mode == "host" else 1,
                            "aggregation": "single_loadgen_process",
                        },
                    )
                    res["workload_interval"] = {
                        "started_at": workload_started_at,
                        "finished_at": time.time(),
                    }
                    if attest_broker_auth:
                        broker_diagnostics_after = _broker_diagnostic_snapshot(
                            compose_files=compose_files,
                            compose_project_name=compose_project_name,
                            extra_env=extra_env,
                        )
                        broker_auth_before = cast(
                            dict[str, int], broker_diagnostics_before.get("authentication", {})
                        )
                        broker_auth_after = cast(
                            dict[str, int], broker_diagnostics_after.get("authentication", {})
                        )
                        res["broker_auth_delta"] = _counter_delta(
                            broker_auth_before, broker_auth_after
                        )
                        broker_authz_before = cast(
                            dict[str, int | str],
                            broker_diagnostics_before.get("authorization", {}),
                        )
                        broker_authz_after = cast(
                            dict[str, int | str],
                            broker_diagnostics_after.get("authorization", {}),
                        )
                        res["broker_authz_delta"] = _authz_counter_delta(
                            broker_authz_before, broker_authz_after
                        )
                    if uses_http_authz:
                        res["authz_stats"] = _authz_stats(
                            authz_base,
                            ca_file=scenario_tls_ca,
                            insecure=tls_insecure,
                        )
                        _validate_external_policy_activity(s["id"], res["authz_stats"])
                    if broker_restart is not None:
                        res["broker_restart"] = dict(broker_restart)
                    _validate_broker_path_contract(
                        s,
                        res,
                        broker_config_attestation,
                        client_count=effective_client_count,
                    )
                    _validate_result_contract(
                        s,
                        res,
                        message_count=scenario_messages,
                        client_count=effective_client_count,
                        effective_qos=scenario_qos,
                        effective_qos_distribution=scenario_qos_distribution,
                    )
                    if s.get("proactive_refresh_assert_continuity"):
                        if not res.get("session_continuity_ok"):
                            raise RuntimeError(
                                f"{s['id']}: proactive refresh did not preserve session continuity"
                            )
                        if res.get("expiry_denial_count", 0) != 0:
                            raise RuntimeError(f"{s['id']}: proactive refresh saw expiry denials")
                        if res.get("proactive_refresh_attempts", 0) <= 0:
                            raise RuntimeError(f"{s['id']}: proactive refresh did not execute")
                    if s.get("reauth_storm"):
                        _validate_reauth_storm_result(
                            s["id"],
                            res,
                            client_count=scenario_clients,
                        )
                finally:
                    pass
                interval = cast(dict[str, Any], res["workload_interval"])
                snap = _resource_interval(
                    prom_base,
                    scenario_tls_ca,
                    tls_insecure,
                    workload_started_at=float(interval["started_at"]),
                    workload_finished_at=float(interval["finished_at"]),
                    compose_files=compose_files,
                    compose_project_name=compose_project_name,
                )
                _validate_resource_interval(snap, scenario_id=s["id"], run_index=idx)

                # Run perf profiling if enabled and scenario matches filter
                perf_result: dict[str, Any] = {"enabled": False}
                if perf_enabled and perf_status.get("installed", False):
                    # Check if this scenario should be profiled
                    profile_this_scenario = True
                    if perf_scenarios:
                        allowed = [p.strip() for p in perf_scenarios.split(",")]
                        profile_this_scenario = s["id"] in allowed
                    else:
                        # Default: profile key scenarios for CPU analysis
                        default_perf_scenarios = get_default_perf_scenarios()
                        profile_this_scenario = s["id"] in default_perf_scenarios

                    if profile_this_scenario:
                        logger.info("Running perf profiling for scenario %s", s["id"])
                        events = perf_events.split(",")
                        perf_config = PerfConfig(
                            events=events,
                            sample_rate=perf_sample_rate,
                            duration=perf_duration,
                            output_dir=perf_output_dir,
                            record_callgraph=perf_callgraph,
                        )
                        try:
                            perf_result = profile_mosquitto_container(
                                container_name="docker-mosquitto-1",
                                config=perf_config,
                            )
                            if perf_result.get("success"):
                                logger.info("Perf profiling complete for %s", s["id"])
                                logger.debug(format_perf_summary(perf_result))
                            else:
                                logger.warning(
                                    "Perf profiling failed for %s: %s",
                                    s["id"],
                                    perf_result.get("error", "unknown error"),
                                )
                        except Exception as e:
                            logger.error("Error during perf profiling: %s", e)
                            perf_result = {"enabled": True, "error": str(e)}
                    else:
                        perf_result = {
                            "enabled": True,
                            "skipped": True,
                            "reason": "not in profile list",
                        }

                if "policy_denial_count" not in res:
                    raw = res.get("raw_metrics")
                    if isinstance(raw, dict) and "policy_denial_count" in raw:
                        res["policy_denial_count"] = int(raw.get("policy_denial_count") or 0)
                out_payload["runs"].append({"loadgen": res, "resources": snap, "perf": perf_result})
                if s.get("sleep_between"):
                    time.sleep(float(s["sleep_between"]))
            if s.get("credential_freshness_required") and repeats > 1:
                out_payload["credential_freshness"] = _validate_credential_freshness(
                    s,
                    cast(list[dict[str, Any]], out_payload["runs"]),
                    client_count=effective_client_count,
                )
        # Issue 15: Run packet analysis if tcpdump was enabled for this scenario
        packet_analysis_result: dict[str, Any] = {"enabled": False}
        if capture_this_scenario and tcpdump_analyze:
            _compose_checked(
                ["stop", "tcpdump"],
                extra_env=extra_env,
                compose_files=compose_files,
                phase="packet capture flush",
            )
            # The bind mount is resolved relative to the benchmark repository,
            # so inspect the same canonical host path even when the runner was
            # launched from the outer workspace.
            pcap_file = Path(normalized_tcpdump_output_dir) / f"{s['id']}.pcap"
            if pcap_file.exists():
                logger.info("Running packet analysis for scenario %s", s["id"])
                try:
                    # Get MTU and token length for correlation
                    netem_config = s.get("netem") or {}
                    mtu = netem_config.get("mtu", 1500) if netem_config else 1500
                    token_length = len(s.get("password", "")) if s.get("password") else 0

                    workload_intervals = [
                        run.get("loadgen", {}).get("workload_interval")
                        for run in out_payload["runs"]
                        if isinstance(run, dict) and isinstance(run.get("loadgen"), dict)
                    ]
                    validated_intervals = [
                        (float(interval["started_at"]), float(interval["finished_at"]))
                        for interval in workload_intervals
                        if isinstance(interval, dict)
                        and interval.get("started_at") is not None
                        and interval.get("finished_at") is not None
                    ]
                    if len(validated_intervals) != len(out_payload["runs"]):
                        raise RuntimeError(f"{s['id']}: measured workload intervals are missing")
                    packet_analysis_result = analyze_pcap(
                        str(pcap_file),
                        mtu,
                        token_length,
                        workload_intervals=validated_intervals,
                    )
                    packet_analysis_result["enabled"] = True
                    packet_analysis_result["pcap_file"] = str(pcap_file)
                    packet_analysis_result["effective_mtu"] = effective_mtu
                    metrics = packet_analysis_result.get("metrics")
                    if (
                        not isinstance(metrics, dict)
                        or int(metrics.get("mqtt_tcp_packets") or 0) <= 0
                    ):
                        raise RuntimeError(f"{s['id']}: capture contains no MQTT TCP traffic")
                    max_ip_packet = int(metrics.get("max_ip_packet_bytes") or 0)
                    asserted_mtu = int(effective_mtu or 0)
                    if max_ip_packet <= 0 or asserted_mtu <= 0 or max_ip_packet > asserted_mtu:
                        raise RuntimeError(
                            f"{s['id']}: observed IP packet size {max_ip_packet} exceeds "
                            f"effective MTU {effective_mtu}"
                        )
                    if metrics.get("capture_start") is None or metrics.get("capture_end") is None:
                        raise RuntimeError(f"{s['id']}: capture interval is missing")
                    coverage = packet_analysis_result.get("workload_interval_coverage")
                    if (
                        not isinstance(coverage, list)
                        or len(coverage) != len(validated_intervals)
                        or any(
                            not isinstance(interval, dict)
                            or int(interval.get("mqtt_packets") or 0) <= 0
                            or int(interval.get("mqtt_payload_packets") or 0) <= 0
                            or int(interval.get("mqtt_client_ips") or 0) < effective_client_count
                            for interval in coverage
                        )
                    ):
                        raise RuntimeError(
                            f"{s['id']}: packet capture lacks MQTT workload traffic "
                            "for one or more measured intervals"
                        )

                    # Log summary
                    summary = format_packet_summary(packet_analysis_result)
                    logger.info("Packet analysis summary:\n%s", summary)
                except Exception as e:
                    logger.error("Error during packet analysis: %s", e)
                    packet_analysis_result = {
                        "enabled": True,
                        "error": str(e),
                        "pcap_file": str(pcap_file),
                    }
                    raise RuntimeError(f"{s['id']}: packet analysis failed: {e}") from e
            else:
                logger.warning("Pcap file not found: %s", pcap_file)
                packet_analysis_result = {
                    "enabled": True,
                    "error": f"Pcap file not found: {pcap_file}",
                }
                raise RuntimeError(f"{s['id']}: required pcap file is missing")

        # Add packet analysis result to output payload
        out_payload["packet_analysis_result"] = packet_analysis_result

        path = _write_result(out, s["id"], out_payload)
        logger.info("Wrote %s", path)

    summary_json_path = Path(summary_json)
    if not summary_json_path.is_absolute():
        summary_json_path = Path(out) / summary_json_path
    summary_json_path = summary_json_path.resolve()
    summary_csv_path = Path(summary_csv)
    if not summary_csv_path.is_absolute():
        summary_csv_path = Path(out) / summary_csv_path
    summary_csv_path = summary_csv_path.resolve()

    agg_cmd = [
        sys.executable,
        "benchmarks/aggregate_results.py",
        "--input",
        out,
        "--out-json",
        str(summary_json_path),
    ]
    if no_summary_csv:
        agg_cmd.append("--no-csv")
    else:
        agg_cmd.extend(["--out-csv", str(summary_csv_path)])
    try:
        subprocess.check_call(
            agg_cmd,
            cwd=REPO_ROOT,
            env=_python_subprocess_env(),
        )
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "Aggregation failed (%s); scenario results preserved",
            exc,
        )


if __name__ == "__main__":
    app()
