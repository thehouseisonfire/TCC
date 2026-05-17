import json
import os
import shutil
import subprocess
import sys
import time
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
ClientTopology = Literal["host", "container-single", "container-per-client"]
DEFAULT_CLIENT_TOPOLOGY: ClientTopology = "container-single"
LOADGEN_CONTAINER_REPO_ROOT = "/workspace"


def _resolve_rust_helper(binary: str) -> list[str]:
    env_name = f"MQTT_AUTH_BISCUIT_{binary.upper().replace('-', '_')}"
    if override := os.environ.get(env_name):
        return [override]
    for profile in ("release", "debug"):
        candidate = REPO_ROOT / "target" / profile / binary
        if candidate.exists():
            return [str(candidate)]
    cargo = shutil.which("cargo")
    if cargo is None:
        raise SystemExit(f"Missing required command: cargo (needed to run {binary})")
    return [cargo, "run", "--locked", "-p", "gen-tokens", "--bin", binary, "--"]


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
        "CONTROL-OVERHEAD-KICK-REAUTH-JWT",
        "CONTROL-OVERHEAD-KICK-REAUTH-BISCUIT",
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
    token1: str
    token2: str


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
    biscuit_public_key_hex: str | None
    biscuit_public_key_file: str | None
    biscuit_delegate: BiscuitDelegateConfig
    biscuit_delegate_public_key_hex: str | None
    biscuit_delegate_public_key_file: str | None
    complexity_axis: (
        Literal["chain_length", "datalog", "http_profile", "authorizer_template"] | None
    )
    complexity_level: Literal["simple", "med", "complex"] | None
    mqtt5_auth: Mqtt5AuthConfig | None
    restart_mosquitto: bool
    sync_connect: bool
    repeat: int
    sleep_between: int
    token_refresh: TokenRefreshConfig
    proactive_refresh: bool
    proactive_refresh_margin_seconds: int
    proactive_refresh_timeout_seconds: int
    proactive_refresh_assert_continuity: bool
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
    # CONTROL scenario support
    control_topic: str
    control_payload: dict[str, Any]
    control_mode: bool
    control_repeat: int
    # Issue 36: Interleaved control message support
    control_after_messages: int
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
    transport = httpx.HTTPTransport(http1=False, http2=True)
    return httpx.Client(verify=verify, timeout=5.0, transport=transport)


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
    baseline_state: dict[str, object],
) -> dict[str, object]:
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
        expected["fail_rate"] = float(cfg["fail_rate"])
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
    verify: bool | str = True
    if insecure:
        verify = False
    elif ca_file:
        verify = ca_file
    transport = httpx.HTTPTransport(http1=False, http2=True)
    with httpx.Client(verify=verify, timeout=5.0, transport=transport) as client:
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
        "timed out waiting for non-empty Prometheus vectors for mosquitto: " f"{last_error!r}"
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
    # CONTROL message parameters
    control_topic: str | None = None,
    control_payload: dict[str, Any] | None = None,
    control_mode: bool = False,
    control_after_messages: int = 0,
    control_repeat: int = 1,
    fanout_churn_kind: str | None = None,
    fanout_churn_after_messages: int = 0,
    fanout_churn_interval_messages: int = 0,
    fanout_churn_max_events: int = 1,
    fanout_churn_settle_ms: int = 0,
    fanout_churn_dynamic_security_source: str | None = None,
    fanout_churn_control_topic: str | None = None,
    fanout_churn_control_payload: dict[str, Any] | None = None,
    fanout_churn_sqlite_db: str | None = None,
    fanout_churn_sqlite_topic: str | None = None,
    fanout_churn_sqlite_subscribers: int | None = None,
    client_topology: ClientTopology = "host",
    compose_files: list[str] | None = None,
    compose_project_name: str | None = None,
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
    # CONTROL message CLI options
    if control_topic:
        cmd.extend(["--control-topic", control_topic])
    if control_payload:
        cmd.extend(["--control-payload", json.dumps(control_payload)])
    if control_mode:
        cmd.append("--control-mode")
    if control_after_messages > 0:
        cmd.extend(["--control-after-messages", str(control_after_messages)])
    if control_repeat != 1:
        cmd.extend(["--control-repeat", str(control_repeat)])
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

    loadgen_args = cmd[len(helper_cmd) :]
    env = {
        "LOADGEN_CPUS": loadgen_cpus,
        "LOADGEN_MEMORY": loadgen_memory,
    }
    if loadgen_cpuset:
        env["LOADGEN_CPUSET"] = loadgen_cpuset

    if client_topology == "container-per-client" and mode == "fanout":
        raise RuntimeError(
            "container-per-client topology is not supported for fanout scenarios yet; "
            "use --client-topology container-single for ACL_READ fan-out runs"
        )
    if client_topology == "container-per-client" and sync_connect:
        raise RuntimeError(
            "container-per-client topology is not supported for sync_connect scenarios yet; "
            "use --client-topology container-single until a cross-container start barrier exists"
        )

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

    return _run_loadgen_container_per_client(
        loadgen_args,
        clients=clients,
        service=loadgen_service,
        scenario_id=scenario_id,
        run_index=run_index,
        compose_files=compose_files,
        compose_project_name=compose_project_name,
        extra_env=env,
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
        "attenuation",
        "attenuation_len",
        "publish_qos_0",
        "publish_qos_1",
        "publish_qos_2",
        "receive",
        "control",
        "control_injection_delay",
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
            "attenuation",
            "attenuation_len",
            "publish",
            "publish_qos_0",
            "publish_qos_1",
            "publish_qos_2",
            "receive",
            "control",
            "control_injection_delay",
        )
    }
    merged["errors"] = errors
    merged["qos_distribution_actual"] = _sum_count_object(results, "qos_distribution_actual")
    merged["received_messages"] = _sum_count_object(results, "received_messages")
    for field in (
        "proactive_refresh_attempts",
        "proactive_refresh_successes",
        "proactive_refresh_failures",
        "expiry_denial_count",
    ):
        merged[field] = _sum_numeric_field(results, field)
    merged["session_continuity_ok"] = all(
        bool(result.get("session_continuity_ok", True)) for result in results
    )
    inputs = merged.get("inputs")
    if isinstance(inputs, dict):
        merged["inputs"] = {**inputs, "clients": len(results)}
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
) -> dict[str, Any]:
    build_cmd = _compose_cmd(
        ["build", service],
        compose_files=compose_files,
        compose_project_name=compose_project_name,
    )
    env = os.environ.copy()
    env.update(extra_env)
    subprocess.run(build_cmd, cwd=REPO_ROOT, env=env, check=True)

    started_at = time.monotonic()
    processes: list[tuple[str, subprocess.Popen[str]]] = []
    for index in range(clients):
        args = _replace_cli_option(loadgen_args, "--clients", "1")
        args = _replace_cli_option(args, "--client-index-start", str(index + 1))
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
    try:
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
    return merged


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
    if snapshot is None:
        return
    path = _resolve_repo_path("docker/dynamic-security.json")
    with path.open("wb") as f:
        f.write(snapshot)


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
    return scenarios


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
    dynamic_security_config = scenario.get("dynamic_security_config")
    generated_snapshot_path: str | None = None
    if not dynamic_security_config and scenario.get("dynamic_security_generated_profile"):
        generated_snapshot_path = _generate_dynamic_security_config(
            cast(str, scenario["dynamic_security_generated_profile"])
        )
        dynamic_security_config = generated_snapshot_path
    if not dynamic_security_config:
        return

    effective_client_count = _effective_scenario_client_count(scenario, default_clients)
    is_fanout = scenario.get("traffic_pattern") == "fanout"
    subscriber_username = scenario.get("username")
    publisher_username = scenario.get("fanout_publisher_username")

    try:
        if subscriber_username:
            _validate_dynamic_security_snapshot_supports_principal(
                scenario_id=scenario_id,
                snapshot_path=dynamic_security_config,
                username=subscriber_username,
                principal_label="username",
                disallow_pinned_clientid=is_fanout and effective_client_count > 1,
                effective_client_count=effective_client_count,
            )
        if publisher_username:
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
    tls_enabled: bool,
    tls_ca_file: str | None,
    tls_insecure: bool,
):
    cmd = [
        *_resolve_rust_helper("mqtt-auth-client"),
        "--host",
        host,
        "--port",
        str(port),
        "--auth-method",
        "token",
        "--token1",
        _mark_mqtt5_auth_token(token1),
        "--token2",
        _mark_mqtt5_auth_token(token2),
    ]
    if tls_enabled:
        cmd.append("--tls")
    if tls_ca_file:
        cmd.extend(["--tls-ca-file", tls_ca_file])
    if tls_insecure:
        cmd.append("--tls-insecure")
    out = subprocess.check_output(
        cmd,
        cwd=REPO_ROOT,
        text=True,
    )
    return json.loads(out)


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
        allow_token = tokens.get(f"{token_key}_fanout_allow", tokens[token_key])
        deny_token = tokens.get(
            f"{token_key}_fanout_read_deny",
            tokens.get(f"{token_key}_deny", allow_token),
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
                allow_token = tokens.get(f"{token_key}_fanout_allow", tokens[token_key])
                deny_token = tokens.get(
                    f"{token_key}_fanout_read_deny",
                    tokens.get(f"{token_key}_deny", allow_token),
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
            "mosquitto_conf": "./mosquitto.conf",
            "username": "jwt",
            "password": tokens["jwt_deny"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
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
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit_deny"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
        },
        "TOKEN-ATTENUATION-CLIENT-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "biscuit_attenuate": {
                "denies": ["publish:sensors/{client_id}/temp"],
                "ttl_seconds": 300,
                "topic": "sensors/{client_id}/temp",
                "op": "publish",
            },
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
        "TOKEN-ATTENUATION-DENY-BISCUIT": {
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
        },
        "TOKEN-ATTENUATION-OP-ONLY-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "username": "biscuit",
            "password": tokens["biscuit"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "biscuit_attenuate": {"op": "publish"},
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
        "HTTP-LATENCY-200MS-FAILURE-1PCT-JWT": {
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
        },
        "HTTP-LATENCY-200MS-FAILURE-5PCT-JWT": {
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
        },
        "TOKEN-MQTT5-REAUTH-JWT": {
            "mosquitto_conf": "./mosquitto.conf",
            "authz_config": None,
            "netem": {"clear": True},
            "mqtt5_auth": {"token1": tokens["jwt_short"], "token2": tokens["jwt"]},
        },
        "TOKEN-MQTT5-REAUTH-BISCUIT": {
            "mosquitto_conf": "./mosquitto.conf",
            "authz_config": None,
            "netem": {"clear": True},
            "mqtt5_auth": {
                "token1": tokens["biscuit_short"],
                "token2": tokens["biscuit"],
            },
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
        "DYNAMIC-SECURITY-BASELINE": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "dynsec_client_1",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "dynamic_security_config": "docker/dynamic-security.json",
        },
        "DYNAMIC-SECURITY-CHURN": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "dynsec_client_1",
            "password": tokens["jwt"],
            "topic": "sensors/{client_id}/temp",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 0,
            "repeat": 2,
            "sleep_between": 2,
            "dynamic_security_churn": [
                "docker/dynamic-security.json",
                "docker/dynamic-security-churn.json",
            ],
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
        "DYNAMIC-SECURITY-READ-FANOUT-CHURN": {
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
            "repeat": 2,
            "sleep_between": 2,
            "dynamic_security_churn": [
                "docker/dynamic-security.json",
                "docker/dynamic-security-fanout-churn.json",
            ],
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
        # Issue 20: Control-Triggered Enforcement Scenarios
        # These scenarios exercise the $CONTROL callback semantics and measure
        # control-plane overhead vs data-plane operations.
        # Issue 35: Renamed to CONTROL-OVERHEAD to distinguish from CONTROL-CHURN
        "CONTROL-OVERHEAD-KICK-REAUTH-JWT": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "admin",
            "password": tokens["jwt_admin"],
            "topic": "$CONTROL/dynamic-security/v1",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_generated_profile": "control_admin_base",
            "repeat": 2,
            "sleep_between": 3,
            "client_count": 1,
        },
        "CONTROL-OVERHEAD-KICK-REAUTH-BISCUIT": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "admin",
            "password": tokens["biscuit_admin"],
            "topic": "$CONTROL/dynamic-security/v1",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "dynamic_security_generated_profile": "control_admin_base",
            "repeat": 2,
            "sleep_between": 3,
            "client_count": 1,
        },
        "CONTROL-OVERHEAD-ACL-READ-NOTIFY-JWT": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "admin",
            "password": tokens["jwt_admin"],
            "topic": "$CONTROL/dynamic-security/v1",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "fanout_publisher_username": "admin",
            "fanout_publisher_password": tokens["jwt_admin"],
            "traffic_pattern": "fanout",
            "fanout_topic": "system/notifications/acl-change",
            "dynamic_security_generated_profile": "control_admin_base",
            "repeat": 2,
            "sleep_between": 3,
            "client_count": 1,
        },
        "CONTROL-OVERHEAD-ACL-READ-NOTIFY-BISCUIT": {
            "mosquitto_conf": "./mosquitto_dynsec.conf",
            "username": "admin",
            "password": tokens["biscuit_admin"],
            "topic": "$CONTROL/dynamic-security/v1",
            "authz_config": None,
            "netem": {"clear": True},
            "message_size": 256,
            "qos": 1,
            "fanout_publisher_username": "admin",
            "fanout_publisher_password": tokens["biscuit_admin"],
            "traffic_pattern": "fanout",
            "fanout_topic": "system/notifications/acl-change",
            "dynamic_security_generated_profile": "control_admin_base",
            "repeat": 2,
            "sleep_between": 3,
            "client_count": 1,
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

    available_scenarios = _apply_scenario_classification(available_scenarios, tokens)

    for scenario in available_scenarios.values():
        scenario.setdefault("token_issuer_no_default_roles", token_issuer_no_default_roles)
        scenario.setdefault("token_issuer_no_default_grants", token_issuer_no_default_grants)

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
):
    setup_logging(log_level)
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
                scenario["id"] = scenario_id
                scenarios.append(
                    cast(
                        ScenarioConfig,
                        ScenarioModel.model_validate(scenario).model_dump(),
                    )
                )
            else:
                logger.warning("Unknown scenario '%s', skipping", scenario_id)
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
        scenario_semantics = _scenario_semantics_metadata(
            s["id"],
            s,
            default_clients=clients,
        )
        scenario_tls = bool(s.get("tls")) or tls_enabled
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
            tls_ca=tls_ca,
        )
        authz_base = endpoints["authz_base"]
        prom_base = endpoints["prom_base"]
        token_issuer_base = endpoints["token_issuer_base"]
        loadgen_token_issuer_base = endpoints["loadgen_token_issuer_base"]
        host_mqtt_host = endpoints["host_mqtt_host"]
        loadgen_mqtt_host = endpoints["loadgen_mqtt_host"]
        mqtt_port = endpoints["mqtt_port"]
        loadgen_tls_ca = endpoints["loadgen_tls_ca"]
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
                extra_env.update({"NETEM_CLEAR": "1", "NETEM_MTU": str(netem["mtu"])})
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

        # Add iperf3 service to compose deployment
        services_to_deploy = [
            "up",
            "--build",
            "-d",
            "mosquitto",
            "authz",
            "netem",
            "metrics-collector",
            "cadvisor",
            "token-issuer",
            "iperf3",
        ]

        # Auto-enable tcpdump for MTU scenarios to capture fragmentation data
        netem = s.get("netem")
        capture_this_scenario = (
            tcpdump_enabled
            and tcpdump_status.get("installed", False)
            and netem is not None
            and "mtu" in netem
        )

        if capture_this_scenario:
            services_to_deploy.append("tcpdump")
            pcap_filename = f"{s['id']}.pcap"
            extra_env.update(
                {
                    "TCPDUMP_FILTER": tcpdump_filter,
                    "TCPDUMP_DURATION": str(tcpdump_duration),
                    "TCPDUMP_OUTPUT": f"/pcap/{pcap_filename}",
                    "TCPDUMP_OUTPUT_DIR": tcpdump_output_dir,
                    "TCPDUMP_KEEP_ALIVE": "0",
                }
            )
            Path(tcpdump_output_dir).mkdir(parents=True, exist_ok=True)

        compose_project_name = extra_env.get("COMPOSE_PROJECT_NAME") or os.environ.get(
            "COMPOSE_PROJECT_NAME"
        )
        _compose(
            services_to_deploy,
            extra_env=extra_env,
            compose_files=compose_files,
        )
        time.sleep(1)
        _wait_for_service_health("authz", authz_base, tls_ca, tls_insecure)
        _wait_for_service_health("token-issuer", token_issuer_base, tls_ca, tls_insecure)
        _wait_for_prometheus_api(prom_base, tls_ca, tls_insecure)
        _wait_for_non_empty_resource_snapshot(
            prom_base,
            tls_ca,
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
                ca_file=tls_ca,
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
                    f"Authz reset baseline unavailable before config apply in scenario {s['id']}"
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
                ca_file=tls_ca,
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
        effective_client_count = _effective_scenario_client_count(s, clients)
        out_payload: dict[str, Any] = {
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
                "ca_file": tls_ca,
                "insecure": tls_insecure,
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
                "client_count": s.get("client_count"),
                "messages": messages,
                "qos": qos,
                "qos_distribution": qos_distribution,
                "token_issuer_no_default_roles": token_issuer_no_default_roles,
                "token_issuer_no_default_grants": token_issuer_no_default_grants,
                "proactive_refresh": s.get("proactive_refresh", False),
                "proactive_refresh_margin_seconds": s.get("proactive_refresh_margin_seconds"),
                "proactive_refresh_timeout_seconds": s.get("proactive_refresh_timeout_seconds"),
                "proactive_refresh_assert_continuity": s.get(
                    "proactive_refresh_assert_continuity", False
                ),
                "traffic_pattern": s.get("traffic_pattern"),
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
            "fanout_metrics": {
                "subscriber_count": (
                    effective_client_count if s.get("traffic_pattern") == "fanout" else None
                ),
                "message_count": messages if s.get("traffic_pattern") == "fanout" else None,
                "acl_read_cost_per_subscriber_ms": None,  # Calculated from receive latencies
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

        if s.get("restart_mosquitto"):
            _compose(["restart", "mosquitto"], extra_env=extra_env)
            time.sleep(1)

        _validate_dynamic_security_alignment(s["id"], s, default_clients=clients)
        dynsec_baseline = _capture_dynamic_security_baseline()
        try:
            for idx in range(repeats):
                generated_dynsec_path: str | None = None
                try:
                    if s.get("dynamic_security_generated_profile"):
                        generated_dynsec_path = _generate_dynamic_security_config(
                            cast(str, s["dynamic_security_generated_profile"])
                        )
                        _apply_dynamic_security_config(generated_dynsec_path)
                    elif s.get("dynamic_security_config"):
                        _apply_dynamic_security_config(s["dynamic_security_config"])
                    elif s.get("dynamic_security_churn"):
                        churn_list = s["dynamic_security_churn"]
                        _apply_dynamic_security_config(churn_list[idx % len(churn_list)])
                    if s.get("sqlite_seed_fanout"):
                        policy_churn.seed_sqlite_fanout_policy(
                            s.get("sqlite_seed_db", "docker/sqlite/policy.db"),
                            topic=s.get(
                                "sqlite_seed_topic", s.get("fanout_topic", "fanout/broadcast")
                            ),
                            subscriber_count=int(
                                s.get("sqlite_seed_subscribers", s.get("subscriber_count", clients))
                            ),
                            profile=str(s.get("sqlite_seed_profile", "fanout_basic")),
                        )
                    mqtt5_cfg = s.get("mqtt5_auth")
                    if mqtt5_cfg is not None:
                        res = _run_mqtt5_auth(
                            host_mqtt_host,
                            mqtt_port,
                            mqtt5_cfg["token1"],
                            mqtt5_cfg["token2"],
                            scenario_tls,
                            tls_ca,
                            tls_insecure,
                        )
                    else:
                        token_refresh = s.get("token_refresh")
                        proactive_refresh = bool(s.get("proactive_refresh", False))
                        scenario_qos = int(s.get("qos", qos))
                        scenario_qos_distribution = s.get("qos_distribution", qos_distribution)
                        scenario_clients = _effective_scenario_client_count(s, clients)
                        strict_startup_provisioning = (
                            _scenario_requires_per_client_strict_provisioning(
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
                            password=s.get("password", ""),
                            fanout_publisher_username=s.get("fanout_publisher_username"),
                            fanout_publisher_password=s.get("fanout_publisher_password"),
                            clients=scenario_clients,
                            messages=messages,
                            topic=s.get("topic", "sensors/{client_id}/temp"),
                            mode=s.get("traffic_pattern"),
                            fanout_topic=s.get("fanout_topic"),
                            qos=scenario_qos,
                            qos_distribution=scenario_qos_distribution,
                            message_size=int(s.get("message_size", 0)),
                            sync_connect=bool(s.get("sync_connect", False)),
                            token_issuer_url=(
                                loadgen_token_issuer_base
                                if token_refresh
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
                            control_topic=s.get("control_topic"),
                            control_payload=s.get("control_payload")
                            or _generate_control_churn_payload(s["id"], "admin"),
                            control_mode=bool(s.get("control_mode", False)),
                            control_repeat=s.get("control_repeat", 1),
                            control_after_messages=s.get("control_after_messages", 0),
                            fanout_churn_kind=s.get("fanout_churn_kind"),
                            fanout_churn_after_messages=s.get("fanout_churn_after_messages", 0),
                            fanout_churn_interval_messages=s.get(
                                "fanout_churn_interval_messages", 0
                            ),
                            fanout_churn_max_events=s.get("fanout_churn_max_events", 1),
                            fanout_churn_settle_ms=s.get("fanout_churn_settle_ms", 0),
                            fanout_churn_dynamic_security_source=(
                                _container_repo_path(s.get("fanout_churn_dynamic_security_source"))
                                if client_topology_mode != "host"
                                else s.get("fanout_churn_dynamic_security_source")
                            ),
                            fanout_churn_control_topic=s.get("fanout_churn_control_topic"),
                            fanout_churn_control_payload=s.get("fanout_churn_control_payload"),
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
                            loadgen_service=loadgen_service,
                            loadgen_cpus=loadgen_cpus,
                            loadgen_memory=loadgen_memory,
                            loadgen_cpuset=loadgen_cpuset,
                            scenario_id=s["id"],
                            run_index=idx,
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
                finally:
                    policy_churn.cleanup_dynsec_snapshot(generated_dynsec_path)
                # Small delay to ensure container metrics are available after loadgen
                time.sleep(2)
                snap = _resource_snapshot(
                    prom_base,
                    tls_ca,
                    tls_insecure,
                    compose_files=compose_files,
                    compose_project_name=compose_project_name,
                )
                _validate_resource_snapshot(snap, scenario_id=s["id"], run_index=idx)

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

                out_payload["runs"].append({"loadgen": res, "resources": snap, "perf": perf_result})
                if s.get("sleep_between"):
                    time.sleep(float(s["sleep_between"]))
        finally:
            _restore_dynamic_security_baseline(dynsec_baseline)

        # Issue 15: Run packet analysis if tcpdump was enabled for this scenario
        packet_analysis_result: dict[str, Any] = {"enabled": False}
        if capture_this_scenario and tcpdump_analyze:
            pcap_file = Path(tcpdump_output_dir) / f"{s['id']}.pcap"
            if pcap_file.exists():
                logger.info("Running packet analysis for scenario %s", s["id"])
                try:
                    # Get MTU and token length for correlation
                    netem_config = s.get("netem") or {}
                    mtu = netem_config.get("mtu", 1500) if netem_config else 1500
                    token_length = len(s.get("password", "")) if s.get("password") else 0

                    packet_analysis_result = analyze_pcap(str(pcap_file), mtu, token_length)
                    packet_analysis_result["enabled"] = True
                    packet_analysis_result["pcap_file"] = str(pcap_file)

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
            else:
                logger.warning("Pcap file not found: %s", pcap_file)
                packet_analysis_result = {
                    "enabled": True,
                    "error": f"Pcap file not found: {pcap_file}",
                }

        # Add packet analysis result to output payload
        out_payload["packet_analysis_result"] = packet_analysis_result

        # Issue 19: Calculate ACL_READ cost per subscriber for fanout scenarios
        subscriber_count = _effective_scenario_client_count(s, clients)
        if s.get("traffic_pattern") == "fanout" and out_payload["runs"] and subscriber_count:
            total_receive_ms = 0.0
            total_receive_count = 0
            for run in out_payload["runs"]:
                loadgen_res = run.get("loadgen", {})
                receive_stats = loadgen_res.get("receive", {})
                if receive_stats and receive_stats.get("count", 0) > 0:
                    # Use mean receive latency as proxy for per-message delivery cost
                    mean_receive = receive_stats.get("mean_ms", 0)
                    count = receive_stats.get("count", 0)
                    total_receive_ms += mean_receive * count
                    total_receive_count += count
            if total_receive_count > 0 and subscriber_count > 0:
                # Average receive latency per message per subscriber
                avg_receive_per_msg = total_receive_ms / total_receive_count
                # Estimate ACL_READ cost as portion of receive latency
                # This is a proxy metric - actual ACL_READ cost is part of auth overhead
                out_payload["fanout_metrics"]["acl_read_cost_per_subscriber_ms"] = round(
                    avg_receive_per_msg / subscriber_count, 3
                )

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
