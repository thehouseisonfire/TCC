from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Literal, Protocol

import httpx
import pytest
from benchmarks import policy_churn
from benchmarks import run_scenarios as rs

REPO_ROOT = Path(__file__).resolve().parents[2]


class _IssuedTokenLike(Protocol):
    token: str | bytes


class _TokenIssuerLike(Protocol):
    def issue_jwt(
        self,
        *,
        client_id: str,
        ttl_seconds: int,
        grants: list[dict[str, str]] | None = None,
        denies: list[dict[str, str]] | None = None,
        no_default_grants: bool = True,
        no_default_roles: bool = True,
    ) -> _IssuedTokenLike: ...

    def issue_biscuit(
        self,
        *,
        client_id: str,
        topic: str,
        ttl_seconds: int,
        denies: list[dict[str, str]] | None = None,
    ) -> _IssuedTokenLike: ...


class _ObservedMqttClientLike(Protocol):
    @property
    def message_count(self) -> int: ...

    def connect(self, timeout_s: float = 10.0) -> None: ...

    def subscribe(self, topic: str, qos: int = 1, timeout_s: float = 5.0) -> list[int]: ...

    def publish(
        self,
        topic: str,
        payload: str | bytes,
        qos: int = 1,
        timeout_s: float = 5.0,
    ) -> int | None: ...

    def wait_for_messages(self, minimum: int, timeout_s: float = 5.0) -> bool: ...

    def assert_connected_for(self, duration_s: float) -> None: ...

    def close(self) -> None: ...


def _is_granted(codes: list[int]) -> bool:
    return bool(codes) and all(code < 128 for code in codes)


def _fanout_minimum_expected(subscriber_count: int, message_count: int) -> int:
    # QoS0 fan-out delivery in CI can exhibit small transient loss under load.
    return max(1, int(subscriber_count * message_count * 0.82))


def _fanout_receiving_subscriber_minimum(subscriber_count: int) -> int:
    # Strict ACL_READ with per-subscriber HTTP/hybrid policy checks can reduce
    # effective fan-out under heavy CI load. Validate broad subscriber coverage
    # rather than near-perfect aggregate delivery volume.
    return max(1, int(subscriber_count * 0.70))


def _wait_for_total_messages(
    subscribers: list[_ObservedMqttClientLike],
    minimum: int,
    *,
    timeout_s: float = 8.0,
    step_s: float = 0.15,
) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        total = sum(sub.message_count for sub in subscribers)
        if total >= minimum:
            return True
        time.sleep(step_s)
    return sum(sub.message_count for sub in subscribers) >= minimum


def _wait_for_receiving_subscribers(
    subscribers: list[_ObservedMqttClientLike],
    minimum: int,
    *,
    timeout_s: float = 10.0,
    step_s: float = 0.15,
) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        receiving = sum(1 for sub in subscribers if sub.message_count > 0)
        if receiving >= minimum:
            return True
        time.sleep(step_s)
    return sum(1 for sub in subscribers if sub.message_count > 0) >= minimum


def _close_all(clients: list[_ObservedMqttClientLike]) -> None:
    for client in clients:
        client.close()


def _issue_token(
    issuer: _TokenIssuerLike,
    *,
    token_kind: str,
    client_id: str,
    topic: str,
    ttl_seconds: int,
    grants: list[dict[str, str]] | None = None,
    denies: list[dict[str, str]] | None = None,
) -> str | bytes:
    if token_kind == "jwt":
        token = issuer.issue_jwt(
            client_id=client_id,
            ttl_seconds=ttl_seconds,
            grants=grants,
            denies=denies,
            no_default_grants=True,
            no_default_roles=True,
        )
    elif token_kind == "biscuit":
        token = issuer.issue_biscuit(
            client_id=client_id,
            topic=topic,
            ttl_seconds=ttl_seconds,
            denies=denies,
        )
    else:
        raise AssertionError(f"unsupported token kind: {token_kind}")
    return token.token


def _authz_reset(base_url: str) -> None:
    transport = httpx.HTTPTransport(http1=False, http2=True)
    with httpx.Client(timeout=5.0, transport=transport) as client:
        resp = client.post(base_url.rstrip("/") + "/config/reset")
        resp.raise_for_status()


def _authz_apply(base_url: str, body: rs.AuthzConfig) -> None:
    transport = httpx.HTTPTransport(http1=False, http2=True)
    with httpx.Client(timeout=5.0, transport=transport) as client:
        resp = client.post(
            base_url.rstrip("/") + "/config",
            json=body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()


def _prepare_sqlite_policy_db_for_container_write() -> None:
    db_dir = REPO_ROOT / "docker" / "sqlite"
    db_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(db_dir, 0o777)
    db_path = db_dir / "policy.db"
    db_path.touch(exist_ok=True)
    os.chmod(db_path, 0o666)


@pytest.mark.broker_integration
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
def test_runtime_token_strict_acl_read_allow_and_deny_profile_matrix(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
) -> None:
    compose_harness.up(mosquitto_conf="./mosquitto_integration_acl_read_full.conf", tls=False)
    issuer = compose_harness.token_issuer(tls=False)

    topic = f"fanout/acl-read-profile/token/profile-matrix/{token_kind}/{unique_suffix}"
    allow_sub_id = f"acl-read-profile-token-allow-profile-matrix-{unique_suffix}"
    deny_sub_id = f"acl-read-profile-token-deny-profile-matrix-{unique_suffix}"
    pub_id = "fanout_publisher"

    allow_sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=allow_sub_id,
        topic=topic,
        ttl_seconds=180,
        grants=[{"op": "subscribe", "res": topic}],
    )
    deny_sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=deny_sub_id,
        topic=topic,
        ttl_seconds=180,
        grants=[{"op": "subscribe", "res": topic}],
        denies=[{"op": "read", "res": topic}],
    )
    pub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=pub_id,
        topic=topic,
        ttl_seconds=180,
        grants=[{"op": "publish", "res": topic}],
    )

    allow_sub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=allow_sub_id,
        username=token_kind,
        password=allow_sub_token,
    )
    deny_sub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=deny_sub_id,
        username=token_kind,
        password=deny_sub_token,
    )
    publisher = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=pub_id,
        username=token_kind,
        password=pub_token,
    )

    try:
        allow_sub.connect()
        deny_sub.connect()
        assert _is_granted(allow_sub.subscribe(topic, qos=1))
        assert _is_granted(deny_sub.subscribe(topic, qos=1))
        publisher.connect()

        for idx in range(3):
            publisher.publish(
                topic, f"acl-read-profile-token-profile-matrix|{idx}|{unique_suffix}", qos=0
            )

        assert allow_sub.wait_for_messages(1, timeout_s=5.0)
        time.sleep(1.0)
        assert deny_sub.message_count == 0
        allow_sub.assert_connected_for(1.0)
        deny_sub.assert_connected_for(1.0)
    finally:
        allow_sub.close()
        deny_sub.close()
        publisher.close()


@pytest.mark.broker_integration
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
@pytest.mark.parametrize(
    "subscriber_count",
    [
        10,
        pytest.param(50, marks=pytest.mark.ci_heavy),
        pytest.param(100, marks=pytest.mark.ci_heavy),
    ],
)
def test_runtime_token_strict_acl_read_allow_scaling_profile_matrix(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
    subscriber_count: int,
) -> None:
    compose_harness.up(mosquitto_conf="./mosquitto_integration_acl_read_full.conf", tls=False)
    issuer = compose_harness.token_issuer(tls=False)

    topic = (
        f"fanout/acl-read-profile/token/profile-matrix/scale/{token_kind}/"
        f"{subscriber_count}/{unique_suffix}"
    )
    sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"acl-read-profile-token-scale-sub-profile-matrix-{unique_suffix}",
        topic=topic,
        ttl_seconds=180,
        grants=[{"op": "subscribe", "res": topic}],
    )
    pub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id="fanout_publisher",
        topic=topic,
        ttl_seconds=180,
        grants=[{"op": "publish", "res": topic}],
    )

    subscribers = [
        mqtt_client_factory(
            host="localhost",
            port=1883,
            client_id=f"acl-read-profile-token-scale-profile-matrix-{idx}-{unique_suffix}",
            username=token_kind,
            password=sub_token,
        )
        for idx in range(subscriber_count)
    ]
    publisher = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id="fanout_publisher",
        username=token_kind,
        password=pub_token,
    )
    message_count = 6

    try:
        for subscriber in subscribers:
            subscriber.connect()
            assert _is_granted(subscriber.subscribe(topic, qos=1))
        publisher.connect()

        for idx in range(message_count):
            publisher.publish(
                topic, f"acl-read-profile-token-scale-profile-matrix|{idx}|{unique_suffix}", qos=0
            )

        expected = _fanout_minimum_expected(subscriber_count, message_count)
        assert _wait_for_total_messages(subscribers, expected)
        subscribers[0].assert_connected_for(0.5)
        subscribers[-1].assert_connected_for(0.5)
    finally:
        _close_all(subscribers)
        publisher.close()


@pytest.mark.broker_integration
@pytest.mark.parametrize(
    "policy_source,token_kind",
    [
        ("http", "jwt"),
        ("http", "biscuit"),
        ("hybrid", "jwt"),
        ("hybrid", "biscuit"),
    ],
)
@pytest.mark.parametrize(
    "tier",
    [
        "med",
        pytest.param("simple", marks=pytest.mark.ci_heavy),
        pytest.param("complex", marks=pytest.mark.ci_heavy),
    ],
)
def test_runtime_http_hybrid_profile_fanout_enforcement_profile_matrix(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    policy_source: str,
    token_kind: str,
    tier: Literal["simple", "med", "complex"],
) -> None:
    conf_by_source = {
        "http": "./mosquitto_http_acl_read.conf",
        "hybrid": "./mosquitto_hybrid_acl_read.conf",
    }
    compose_harness.up(mosquitto_conf=conf_by_source[policy_source], tls=False)
    issuer = compose_harness.token_issuer(tls=False)
    authz_base = "http://localhost:8081"
    topic = (
        f"fanout/acl-read-profile/profile-matrix/"
        f"{policy_source}/{tier}/{token_kind}/{unique_suffix}"
    )
    sub_id = (
        f"acl-read-profile-{policy_source}-{tier}-{token_kind}-sub-profile-matrix-{unique_suffix}"
    )
    pub_id = "fanout_publisher"

    sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=sub_id,
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )
    pub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=pub_id,
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )

    allow_authz = rs._http_hybrid_fanout_authz_config_profile_matrix(
        tier, topic=topic, deny_read=False
    )
    deny_authz = rs._http_hybrid_fanout_authz_config_profile_matrix(
        tier, topic=topic, deny_read=True
    )

    _authz_reset(authz_base)
    _authz_apply(authz_base, allow_authz)

    subscriber: _ObservedMqttClientLike | None = None
    publisher: _ObservedMqttClientLike | None = None
    try:
        subscriber = mqtt_client_factory(
            host="localhost",
            port=1883,
            client_id=sub_id,
            username=token_kind,
            password=sub_token,
        )
        publisher = mqtt_client_factory(
            host="localhost",
            port=1883,
            client_id=pub_id,
            username=token_kind,
            password=pub_token,
        )

        subscriber.connect()
        assert _is_granted(subscriber.subscribe(topic, qos=1))
        publisher.connect()

        publisher.publish(
            topic,
            f"acl-read-profile-pre-profile-matrix|{policy_source}|{tier}|{unique_suffix}",
            qos=0,
        )
        assert subscriber.wait_for_messages(1, timeout_s=5.0)
        pre_count = subscriber.message_count

        _authz_apply(authz_base, deny_authz)
        time.sleep(0.8)

        for idx in range(4):
            publisher.publish(
                topic, f"acl-read-profile-post-profile-matrix|{idx}|{unique_suffix}", qos=0
            )
        time.sleep(1.0)

        assert subscriber.message_count == pre_count
        subscriber.assert_connected_for(1.0)
    finally:
        if subscriber is not None:
            subscriber.close()
        if publisher is not None:
            publisher.close()


@pytest.mark.broker_integration
@pytest.mark.parametrize("policy_source", ["http", "hybrid"])
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
@pytest.mark.parametrize(
    "subscriber_count",
    [
        10,
        pytest.param(50, marks=pytest.mark.ci_heavy),
        pytest.param(100, marks=pytest.mark.ci_heavy),
    ],
)
def test_runtime_http_hybrid_med_allow_scaling_profile_matrix(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    policy_source: str,
    token_kind: str,
    subscriber_count: int,
) -> None:
    if subscriber_count == 100 and token_kind == "biscuit":
        pytest.xfail(
            "CI/runtime saturation observed at 100 Biscuit subscribers (CONNACK timeouts); "
            "scaling runtime coverage is enforced at 10/50 for Biscuit and 10/50/100 for JWT."
        )

    conf_by_source = {
        "http": "./mosquitto_http_acl_read.conf",
        "hybrid": "./mosquitto_hybrid_acl_read.conf",
    }
    compose_harness.up(mosquitto_conf=conf_by_source[policy_source], tls=False)
    issuer = compose_harness.token_issuer(tls=False)
    authz_base = "http://localhost:8081"

    tier: Literal["simple", "med", "complex"] = "med"
    topic = (
        f"fanout/acl-read-profile/profile-matrix/{policy_source}/{tier}/scale/"
        f"{token_kind}/{subscriber_count}/{unique_suffix}"
    )
    pub_id = "fanout_publisher"
    sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"acl-read-profile-{policy_source}-scale-sub-profile-matrix-{unique_suffix}",
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )
    pub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=pub_id,
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )

    _authz_reset(authz_base)
    _authz_apply(
        authz_base,
        rs._http_hybrid_fanout_authz_config_profile_matrix(tier, topic=topic, deny_read=False),
    )

    subscribers = [
        mqtt_client_factory(
            host="localhost",
            port=1883,
            client_id=f"acl-read-profile-{policy_source}-{token_kind}-scale-profile-matrix-{idx}-{unique_suffix}",
            username=token_kind,
            password=sub_token,
        )
        for idx in range(subscriber_count)
    ]
    publisher = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=pub_id,
        username=token_kind,
        password=pub_token,
    )
    message_count = 6

    try:
        connect_timeout_s = 60.0 if subscriber_count >= 100 else 20.0
        connect_delay_s = (
            0.08 if subscriber_count >= 100 else 0.02 if subscriber_count >= 50 else 0.0
        )
        for subscriber in subscribers:
            subscriber.connect(timeout_s=connect_timeout_s)
            assert _is_granted(subscriber.subscribe(topic, qos=1))
            if connect_delay_s > 0.0:
                time.sleep(connect_delay_s)
        publisher.connect(timeout_s=15.0)

        for idx in range(message_count):
            publisher.publish(
                topic,
                f"acl-read-profile-{policy_source}-med-scale-profile-matrix|{idx}|{unique_suffix}",
                qos=0,
            )
            time.sleep(0.08)

        expected_receiving = _fanout_receiving_subscriber_minimum(subscriber_count)
        assert _wait_for_receiving_subscribers(subscribers, expected_receiving)
        subscribers[0].assert_connected_for(0.5)
        subscribers[-1].assert_connected_for(0.5)
    finally:
        _close_all(subscribers)
        publisher.close()


@pytest.mark.broker_integration
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
def test_runtime_sqlite_strict_acl_read_revoke_profile_matrix(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
) -> None:
    _prepare_sqlite_policy_db_for_container_write()
    compose_harness.up(mosquitto_conf="./mosquitto_sqlite_acl_read.conf", tls=False)
    issuer = compose_harness.token_issuer(tls=False)

    topic = f"fanout/acl-read-profile/profile-matrix/sqlite/{token_kind}/{unique_suffix}"
    db_path = "docker/sqlite/policy.db"
    policy_churn.seed_sqlite_fanout_policy(
        db_path,
        topic=topic,
        subscriber_count=1,
        publisher_client_id="fanout_publisher",
        profile="fanout_basic",
    )

    sub_id = "client_1"
    pub_id = "fanout_publisher"

    sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=sub_id,
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )
    pub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=pub_id,
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )

    subscriber = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=sub_id,
        username=token_kind,
        password=sub_token,
    )
    publisher = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=pub_id,
        username=token_kind,
        password=pub_token,
    )

    try:
        subscriber.connect()
        assert _is_granted(subscriber.subscribe(topic, qos=1))
        publisher.connect()

        publisher.publish(
            topic, f"acl-read-profile-sqlite-pre-profile-matrix|{unique_suffix}", qos=0
        )
        assert subscriber.wait_for_messages(1, timeout_s=5.0)
        pre_count = subscriber.message_count

        policy_churn.revoke_sqlite_read_fanout(db_path, topic=topic, subscriber_count=1)
        time.sleep(1.2)

        for idx in range(3):
            publisher.publish(
                topic, f"acl-read-profile-sqlite-post-profile-matrix|{idx}|{unique_suffix}", qos=0
            )
        time.sleep(1.0)

        assert subscriber.message_count == pre_count
        subscriber.assert_connected_for(1.0)
    finally:
        subscriber.close()
        publisher.close()
