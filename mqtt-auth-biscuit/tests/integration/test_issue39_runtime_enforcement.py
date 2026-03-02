from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Protocol

import pytest
from benchmarks import policy_churn

REPO_ROOT = Path(__file__).resolve().parents[2]
TLS_CA_FILE = Path(__file__).resolve().parents[2] / "docker" / "tls" / "ca.pem"
EXPIRED_TOKEN_TTL_S = 3
EXPIRY_TRIGGER_DELAY_S = 4.2


class _IssuedTokenLike(Protocol):
    token: str


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

    def wait_for_topic_messages(self, topic: str, minimum: int, timeout_s: float = 5.0) -> bool: ...

    def wait_disconnected(self, timeout_s: float = 5.0) -> bool: ...

    def message_count_for_topic(self, topic: str) -> int: ...

    def assert_connected_for(self, duration_s: float) -> None: ...

    def close(self) -> None: ...


def _resolve_conf(base_conf: str, *, tls: bool) -> str:
    if not tls:
        return base_conf
    return base_conf.replace("./", "./tls/")


def _is_granted(codes: list[int]) -> bool:
    return bool(codes) and all(code < 128 for code in codes)


def _is_denied(codes: list[int]) -> bool:
    return any(code >= 128 for code in codes)


def _issue_token(
    issuer: _TokenIssuerLike,
    *,
    token_kind: str,
    client_id: str,
    topic: str,
    ttl_seconds: int,
    grants: list[dict[str, str]] | None = None,
    denies: list[dict[str, str]] | None = None,
) -> str:
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


def _upsert_acl(
    role: dict[str, Any],
    *,
    acltype: str,
    topic: str,
    allow: bool,
    priority: int = 0,
) -> None:
    acls = role.setdefault("acls", [])
    for acl in acls:
        if acl.get("acltype") == acltype and acl.get("topic") == topic:
            acl["allow"] = allow
            acl["priority"] = priority
            return
    acls.append({"acltype": acltype, "topic": topic, "priority": priority, "allow": allow})


def _build_dynsec_control_notify_snapshot(
    *,
    source_path: str,
    output_path: Path,
    notification_topic: str,
    allow_data_read: bool,
) -> Path:
    src = REPO_ROOT / source_path
    cfg = json.loads(src.read_text(encoding="utf-8"))
    roles = {role["rolename"]: role for role in cfg.get("roles", [])}
    fanout_reader = roles["fanout_reader"]
    fanout_writer = roles["fanout_writer"]

    _upsert_acl(
        fanout_reader,
        acltype="subscribeLiteral",
        topic="fanout/broadcast",
        allow=True,
    )
    if allow_data_read:
        _upsert_acl(
            fanout_reader,
            acltype="publishClientReceive",
            topic="fanout/broadcast",
            allow=True,
        )
    else:
        fanout_reader["acls"] = [
            acl
            for acl in fanout_reader.get("acls", [])
            if not (
                acl.get("acltype") == "publishClientReceive"
                and acl.get("topic") == "fanout/broadcast"
            )
        ]
    _upsert_acl(
        fanout_reader,
        acltype="subscribeLiteral",
        topic=notification_topic,
        allow=True,
    )
    _upsert_acl(
        fanout_reader,
        acltype="publishClientReceive",
        topic=notification_topic,
        allow=True,
    )
    _upsert_acl(
        fanout_writer,
        acltype="publishClientSend",
        topic="fanout/broadcast",
        allow=True,
    )
    _upsert_acl(
        fanout_writer,
        acltype="publishClientSend",
        topic=notification_topic,
        allow=True,
    )
    _upsert_acl(
        fanout_writer,
        acltype="publishClientSend",
        topic="$CONTROL/dynamic-security/v1",
        allow=True,
    )

    output_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return output_path


def _total_messages(clients: list[_ObservedMqttClientLike]) -> int:
    return sum(client.message_count for client in clients)


@pytest.mark.broker_integration
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
@pytest.mark.parametrize("acl_read_full_authz", [False, True])
def test_issue39_acl_read_expiry_disconnect_and_reconnect(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
    acl_read_full_authz: bool,
) -> None:
    base_conf = (
        "./mosquitto_integration_acl_read_full.conf" if acl_read_full_authz else "./mosquitto.conf"
    )
    compose_harness.up(mosquitto_conf=base_conf, tls=False)
    issuer = compose_harness.token_issuer(tls=False)

    topic = f"fanout/issue39/expiry/{token_kind}/{acl_read_full_authz}/{unique_suffix}"
    sub_client_id = f"issue39-sub-{unique_suffix}"
    pub_client_id = f"issue39-pub-{unique_suffix}"

    subscribe_grants = [{"op": "subscribe", "res": topic}]
    publish_grants = [{"op": "publish", "res": topic}]

    expired_sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=sub_client_id,
        topic=topic,
        ttl_seconds=EXPIRED_TOKEN_TTL_S,
        grants=subscribe_grants,
    )
    fresh_sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=sub_client_id,
        topic=topic,
        ttl_seconds=180,
        grants=subscribe_grants,
    )
    pub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=pub_client_id,
        topic=topic,
        ttl_seconds=180,
        grants=publish_grants,
    )

    sub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=sub_client_id,
        username=token_kind,
        password=expired_sub_token,
    )
    pub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=pub_client_id,
        username=token_kind,
        password=pub_token,
    )

    try:
        sub.connect()
        assert _is_granted(sub.subscribe(topic, qos=1))
        pub.connect()

        # Ensure cached session is expired before we trigger ACL_READ.
        time.sleep(EXPIRY_TRIGGER_DELAY_S)
        pub.publish(topic, "trigger-expiry", qos=0)
        assert sub.wait_disconnected(timeout_s=8.0), "expired ACL_READ should disconnect client"

        logs = compose_harness.logs("mosquitto")
        expected_log = f"ACL expiry disconnect applied: client={sub_client_id} with_will=false"
        assert expected_log in logs
    finally:
        sub.close()
        pub.close()

    pub_reconnect = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=f"{pub_client_id}-reconnect",
        username=token_kind,
        password=pub_token,
    )
    reconnect_sub: _ObservedMqttClientLike | None = None
    try:
        granted = False
        for attempt in range(1, 4):
            reconnect_sub = mqtt_client_factory(
                host="localhost",
                port=1883,
                client_id=sub_client_id,
                username=token_kind,
                password=fresh_sub_token,
            )
            reconnect_sub.connect()
            if _is_granted(reconnect_sub.subscribe(topic, qos=1)):
                granted = True
                break
            reconnect_sub.close()
            reconnect_sub = None
            time.sleep(0.6 * attempt)

        assert granted, "same-client-id reconnect should eventually resubscribe with fresh token"
        pub_reconnect.connect()
        pub_reconnect.publish(topic, "after-reconnect", qos=0)
        assert reconnect_sub is not None
        assert reconnect_sub.wait_for_messages(1, timeout_s=5.0)
    finally:
        if reconnect_sub is not None:
            reconnect_sub.close()
        pub_reconnect.close()


@pytest.mark.broker_integration
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
def test_issue39_expiry_disconnect_does_not_emit_lwt(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
) -> None:
    compose_harness.up(mosquitto_conf="./mosquitto_integration_acl_read_full.conf", tls=False)
    issuer = compose_harness.token_issuer(tls=False)

    data_topic = f"fanout/issue39/lwt/data/{unique_suffix}"
    will_topic = f"fanout/issue39/lwt/will/{unique_suffix}"
    sub_client_id = f"issue39-lwt-sub-{unique_suffix}"
    pub_client_id = f"issue39-lwt-pub-{unique_suffix}"
    observer_client_id = f"issue39-lwt-observer-{unique_suffix}"
    will_payload = f"unexpected-will-{unique_suffix}"

    expired_sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=sub_client_id,
        topic=data_topic,
        ttl_seconds=EXPIRED_TOKEN_TTL_S,
        grants=[{"op": "subscribe", "res": data_topic}],
    )
    pub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=pub_client_id,
        topic=data_topic,
        ttl_seconds=180,
        grants=[{"op": "publish", "res": data_topic}],
    )
    observer_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=observer_client_id,
        topic=will_topic,
        ttl_seconds=180,
        grants=[{"op": "subscribe", "res": will_topic}],
    )

    observer = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=observer_client_id,
        username=token_kind,
        password=observer_token,
    )
    sub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=sub_client_id,
        username=token_kind,
        password=expired_sub_token,
        will_topic=will_topic,
        will_payload=will_payload,
        will_qos=1,
    )
    pub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=pub_client_id,
        username=token_kind,
        password=pub_token,
    )

    try:
        observer.connect()
        assert _is_granted(observer.subscribe(will_topic, qos=1))
        sub.connect()
        assert _is_granted(sub.subscribe(data_topic, qos=1))
        pub.connect()

        time.sleep(EXPIRY_TRIGGER_DELAY_S)
        pub.publish(data_topic, "trigger-expiry-with-lwt", qos=0)
        assert sub.wait_disconnected(timeout_s=8.0), "expired ACL_READ should disconnect client"
        assert not observer.wait_for_topic_messages(will_topic, 1, timeout_s=2.5)

        logs = compose_harness.logs("mosquitto")
        expected_log = f"ACL expiry disconnect applied: client={sub_client_id} with_will=false"
        assert expected_log in logs
    finally:
        observer.close()
        sub.close()
        pub.close()


@pytest.mark.broker_integration
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
def test_issue39_control_acl_read_notify_workflow(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
    tmp_path,
) -> None:
    topic = "fanout/broadcast"
    subscriber_client_id = f"issue39-control-sub-{unique_suffix}"
    notification_topic = f"system_notification/{subscriber_client_id}"
    allow_snapshot = _build_dynsec_control_notify_snapshot(
        source_path="docker/dynamic-security-fanout-read-allow-unpinned.json",
        output_path=tmp_path / "dynsec-allow.json",
        notification_topic=notification_topic,
        allow_data_read=True,
    )

    policy_churn.apply_dynsec_snapshot(str(allow_snapshot))
    compose_harness.up(mosquitto_conf="./mosquitto_dynsec_acl_read.conf", tls=False)
    issuer = compose_harness.token_issuer(tls=False)

    subscriber_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=subscriber_client_id,
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )
    publisher_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id="fanout_publisher",
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )

    subscriber = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=subscriber_client_id,
        username="dynsec_client_1",
        password=subscriber_token,
    )
    publisher = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id="fanout_publisher",
        username="dynsec_publisher",
        password=publisher_token,
    )

    try:
        subscriber.connect()
        assert _is_granted(subscriber.subscribe(topic, qos=1))
        assert _is_granted(subscriber.subscribe(notification_topic, qos=1))
        publisher.connect()

        publisher.publish(topic, f"pre|{unique_suffix}", qos=0)
        assert subscriber.wait_for_topic_messages(topic, 1, timeout_s=5.0)
        pre_data_count = subscriber.message_count_for_topic(topic)

        control_payload = json.dumps(
            {
                "commands": [
                    {
                        "command": "removeRoleACL",
                        "rolename": "fanout_reader",
                        "acltype": "publishClientReceive",
                        "topic": topic,
                    }
                ]
            }
        )
        publisher.publish("$CONTROL/dynamic-security/v1", control_payload, qos=1)
        assert subscriber.wait_for_topic_messages(notification_topic, 1, timeout_s=5.0)
        time.sleep(1.2)

        for idx in range(5):
            publisher.publish(topic, f"post|{idx}|{unique_suffix}", qos=0)
        time.sleep(1.2)

        assert subscriber.message_count_for_topic(topic) == pre_data_count
        subscriber.assert_connected_for(1.0)
        logs = compose_harness.logs("mosquitto")
        assert f"Control notify published: client={subscriber_client_id}" in logs
    finally:
        subscriber.close()
        publisher.close()


@pytest.mark.broker_integration
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
def test_issue39_negative_controls_no_false_disconnects(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
) -> None:
    compose_harness.up(mosquitto_conf="./mosquitto_integration_acl_read_full.conf", tls=False)
    issuer = compose_harness.token_issuer(tls=False)

    topic_subscribe = f"sensors/issue39/sub/{unique_suffix}"
    topic_write = f"sensors/issue39/write/{unique_suffix}"
    topic_read = f"sensors/issue39/read/{unique_suffix}"
    topic_allow = f"sensors/issue39/allow/{unique_suffix}"

    deny_sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"deny-sub-{unique_suffix}",
        topic=topic_subscribe,
        ttl_seconds=180,
        grants=[],
        denies=[{"op": "subscribe", "res": topic_subscribe}],
    )
    deny_write_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"deny-write-{unique_suffix}",
        topic=topic_write,
        ttl_seconds=180,
        grants=[],
        denies=[{"op": "publish", "res": topic_write}],
    )
    deny_read_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"deny-read-{unique_suffix}",
        topic=topic_read,
        ttl_seconds=180,
        grants=[{"op": "subscribe", "res": topic_read}],
        denies=[{"op": "read", "res": topic_read}],
    )
    allow_read_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"allow-read-{unique_suffix}",
        topic=topic_read,
        ttl_seconds=180,
        grants=[{"op": "publish", "res": topic_read}],
    )
    allow_sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"allow-sub-{unique_suffix}",
        topic=topic_allow,
        ttl_seconds=180,
        grants=[{"op": "subscribe", "res": topic_allow}],
    )
    allow_pub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"allow-pub-{unique_suffix}",
        topic=topic_allow,
        ttl_seconds=180,
        grants=[{"op": "publish", "res": topic_allow}],
    )
    write_observer_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"allow-write-observer-{unique_suffix}",
        topic=topic_write,
        ttl_seconds=180,
        grants=[{"op": "subscribe", "res": topic_write}],
    )

    deny_sub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=f"deny-sub-{unique_suffix}",
        username=token_kind,
        password=deny_sub_token,
    )
    deny_pub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=f"deny-write-{unique_suffix}",
        username=token_kind,
        password=deny_write_token,
    )
    deny_read = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=f"deny-read-{unique_suffix}",
        username=token_kind,
        password=deny_read_token,
    )
    allow_read_pub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=f"allow-read-pub-{unique_suffix}",
        username=token_kind,
        password=allow_read_token,
    )
    allow_sub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=f"allow-sub-{unique_suffix}",
        username=token_kind,
        password=allow_sub_token,
    )
    allow_pub = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=f"allow-pub-{unique_suffix}",
        username=token_kind,
        password=allow_pub_token,
    )
    write_observer = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id=f"allow-write-observer-{unique_suffix}",
        username=token_kind,
        password=write_observer_token,
    )

    clients = [deny_sub, deny_pub, deny_read, allow_read_pub, allow_sub, allow_pub, write_observer]
    try:
        for client in clients:
            client.connect()

        # ACL_SUBSCRIBE deny: expect SUBACK denial, but no disconnect.
        assert _is_denied(deny_sub.subscribe(topic_subscribe, qos=1))
        deny_sub.assert_connected_for(1.0)

        # ACL_WRITE deny: denied publisher should not fan-out messages, but stay connected.
        assert _is_granted(write_observer.subscribe(topic_write, qos=1))
        deny_pub.publish(topic_write, "denied-write", qos=0)
        time.sleep(0.8)
        assert write_observer.message_count == 0
        deny_pub.assert_connected_for(1.0)

        # ACL_READ deny: subscribe allowed, delivery denied, client remains connected.
        assert _is_granted(deny_read.subscribe(topic_read, qos=1))
        allow_read_pub.publish(topic_read, "denied-read", qos=0)
        time.sleep(0.8)
        assert deny_read.message_count == 0
        deny_read.assert_connected_for(1.0)

        # Allow path stays connected and receives delivery.
        assert _is_granted(allow_sub.subscribe(topic_allow, qos=1))
        allow_pub.publish(topic_allow, "allow-path", qos=0)
        assert allow_sub.wait_for_messages(1, timeout_s=4.0)
        allow_sub.assert_connected_for(1.0)

        logs = compose_harness.logs("mosquitto")
        for client_id in (
            f"deny-sub-{unique_suffix}",
            f"deny-write-{unique_suffix}",
            f"deny-read-{unique_suffix}",
            f"allow-sub-{unique_suffix}",
        ):
            assert f"ACL expiry disconnect applied: client={client_id}" not in logs
    finally:
        for client in clients:
            client.close()


@pytest.mark.broker_integration
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
@pytest.mark.parametrize(
    "tls",
    [False, pytest.param(True, marks=pytest.mark.ci_heavy)],
)
def test_issue31_control_disable_client_kick_and_reconnect_denied(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
    tls: bool,
    tmp_path,
) -> None:
    topic = "fanout/broadcast"
    snapshot = _build_dynsec_control_notify_snapshot(
        source_path="docker/dynamic-security.json",
        output_path=tmp_path / "dynsec-issue31-control.json",
        notification_topic=f"fanout/notifications/issue31/{unique_suffix}",
        allow_data_read=True,
    )
    policy_churn.apply_dynsec_snapshot(str(snapshot))

    compose_harness.up(mosquitto_conf=_resolve_conf("./mosquitto_dynsec.conf", tls=tls), tls=tls)
    issuer = compose_harness.token_issuer(tls=tls)
    port = 8883 if tls else 1883
    tls_client_kwargs = (
        {"tls": True, "tls_ca_file": str(TLS_CA_FILE), "tls_insecure": True} if tls else {}
    )

    sub_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id="client_1",
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )
    control_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id="fanout_publisher",
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )

    sub = mqtt_client_factory(
        host="localhost",
        port=port,
        client_id="client_1",
        username="dynsec_client_1",
        password=sub_token,
        **tls_client_kwargs,
    )
    controller = mqtt_client_factory(
        host="localhost",
        port=port,
        client_id="fanout_publisher",
        username="dynsec_publisher",
        password=control_token,
        **tls_client_kwargs,
    )

    try:
        sub.connect()
        assert _is_granted(sub.subscribe(topic, qos=1))
        controller.connect()

        controller.publish(topic, f"pre|{unique_suffix}", qos=0)
        assert sub.wait_for_topic_messages(topic, 1, timeout_s=5.0)

        control_payload = json.dumps(
            {"commands": [{"command": "disableClient", "username": "dynsec_client_1"}]}
        )
        controller.publish("$CONTROL/dynamic-security/v1", control_payload, qos=1)
        assert sub.wait_disconnected(timeout_s=8.0), "control disableClient should kick target"

        logs = compose_harness.logs("mosquitto")
        expected_log = "Control enforcement kick applied: client=client_1 with_will=false"
        assert expected_log in logs
    finally:
        sub.close()
        controller.close()

    refreshed_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id="client_1",
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )
    reconnect = mqtt_client_factory(
        host="localhost",
        port=port,
        client_id="client_1",
        username="dynsec_client_1",
        password=refreshed_token,
        **tls_client_kwargs,
    )
    try:
        reconnect.connect()
        assert _is_denied(reconnect.subscribe(topic, qos=1))
        reconnect.assert_connected_for(1.0)
    finally:
        reconnect.close()


@pytest.mark.broker_integration
@pytest.mark.ci_heavy
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
@pytest.mark.parametrize("tls", [False, True])
def test_issue31_control_disable_client_skips_offline_stale_session_kick(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
    tls: bool,
    tmp_path,
) -> None:
    topic = "fanout/broadcast"
    stale_client_id = f"issue31-stale-{unique_suffix}"
    snapshot = _build_dynsec_control_notify_snapshot(
        source_path="docker/dynamic-security.json",
        output_path=tmp_path / "dynsec-issue31-stale.json",
        notification_topic=f"fanout/notifications/issue31/stale/{unique_suffix}",
        allow_data_read=True,
    )
    policy_churn.apply_dynsec_snapshot(str(snapshot))

    compose_harness.up(mosquitto_conf=_resolve_conf("./mosquitto_dynsec.conf", tls=tls), tls=tls)
    issuer = compose_harness.token_issuer(tls=tls)
    port = 8883 if tls else 1883
    tls_client_kwargs = (
        {"tls": True, "tls_ca_file": str(TLS_CA_FILE), "tls_insecure": True} if tls else {}
    )

    stale_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=stale_client_id,
        topic=topic,
        ttl_seconds=2,
        grants=[],
    )
    control_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id="fanout_publisher",
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )

    stale_client = mqtt_client_factory(
        host="localhost",
        port=port,
        client_id=stale_client_id,
        username="dynsec_client_1",
        password=stale_token,
        **tls_client_kwargs,
    )
    controller = mqtt_client_factory(
        host="localhost",
        port=port,
        client_id="fanout_publisher",
        username="dynsec_publisher",
        password=control_token,
        **tls_client_kwargs,
    )

    try:
        stale_client.connect()
        stale_client.assert_connected_for(0.5)
        stale_client.close()
        # Allow the cached auth session to expire so stale index cleanup can prune it.
        time.sleep(13.0)

        controller.connect()
        control_payload = json.dumps(
            {"commands": [{"command": "disableClient", "username": "dynsec_client_1"}]}
        )
        controller.publish("$CONTROL/dynamic-security/v1", control_payload, qos=1)
        controller.assert_connected_for(0.8)

        logs = compose_harness.logs("mosquitto")
        assert (
            f"Control enforcement kick applied: client={stale_client_id} with_will=false"
            not in logs
        )
        assert (
            f"Control enforcement kick failed: client={stale_client_id} with_will=false" not in logs
        )
    finally:
        stale_client.close()
        controller.close()


@pytest.mark.broker_integration
@pytest.mark.parametrize("token_kind", ["jwt", "biscuit"])
@pytest.mark.parametrize(
    "tls",
    [False, pytest.param(True, marks=pytest.mark.ci_heavy)],
)
def test_issue39_enhanced_auth_entrypoint_over_tcp_and_tls(
    compose_harness,
    unique_suffix: str,
    token_kind: str,
    tls: bool,
) -> None:
    base_conf = "./mosquitto_integration_acl_read_full.conf"
    compose_harness.up(mosquitto_conf=_resolve_conf(base_conf, tls=tls), tls=tls)
    issuer = compose_harness.token_issuer(tls=tls)

    topic = f"sensors/issue39/enhanced/{unique_suffix}"
    client_id = f"issue39-enhanced-{token_kind}-{unique_suffix}"
    grants = [{"op": "publish", "res": topic}, {"op": "subscribe", "res": topic}]

    token1 = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=client_id,
        topic=topic,
        ttl_seconds=180,
        grants=grants,
    )
    token2 = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=client_id,
        topic=topic,
        ttl_seconds=300,
        grants=grants,
    )

    cmd = [
        "python3",
        "benchmarks/mqtt_auth_client.py",
        "--host",
        "localhost",
        "--port",
        "8883" if tls else "1883",
        "--client-id",
        client_id,
        "--auth-method",
        "token",
        "--token1",
        token1,
        "--token2",
        token2,
        "--sleep",
        "0.2",
    ]
    if tls:
        cmd.extend(["--tls", "--tls-insecure"])

    completed = subprocess.run(
        cmd,
        cwd=Path(__file__).resolve().parents[2],
        env={**os.environ, "PYTHONPATH": "."},
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(completed.stdout)
    assert payload["connect_ok"] is True
    assert payload["connect_reason"] == 0
    assert payload["reauth_pkt_type"] == 15


@pytest.mark.broker_integration
@pytest.mark.ci_heavy
def test_issue39_basic_auth_over_tls_stays_functional(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
) -> None:
    compose_harness.up(
        mosquitto_conf=_resolve_conf("./mosquitto.conf", tls=True),
        tls=True,
    )
    issuer = compose_harness.token_issuer(tls=True)

    topic = f"sensors/issue39/tls/basic/{unique_suffix}"
    sub_client_id = f"tls-sub-{unique_suffix}"
    pub_client_id = f"tls-pub-{unique_suffix}"

    sub_token = issuer.issue_jwt(
        client_id=sub_client_id,
        ttl_seconds=180,
        grants=[{"op": "subscribe", "res": topic}],
        no_default_grants=True,
        no_default_roles=True,
    ).token
    pub_token = issuer.issue_jwt(
        client_id=pub_client_id,
        ttl_seconds=180,
        grants=[{"op": "publish", "res": topic}],
        no_default_grants=True,
        no_default_roles=True,
    ).token

    sub = mqtt_client_factory(
        host="localhost",
        port=8883,
        client_id=sub_client_id,
        username="jwt",
        password=sub_token,
        tls=True,
        tls_ca_file=str(TLS_CA_FILE),
        tls_insecure=True,
    )
    pub = mqtt_client_factory(
        host="localhost",
        port=8883,
        client_id=pub_client_id,
        username="jwt",
        password=pub_token,
        tls=True,
        tls_ca_file=str(TLS_CA_FILE),
        tls_insecure=True,
    )

    try:
        sub.connect()
        pub.connect()
        assert _is_granted(sub.subscribe(topic, qos=1))
        pub.publish(topic, "tls-basic-ok", qos=0)
        assert sub.wait_for_messages(1, timeout_s=5.0)
    finally:
        sub.close()
        pub.close()


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
def test_issue39_fanout_churn_runtime_enforcement(
    compose_harness,
    mqtt_client_factory,
    unique_suffix: str,
    token_kind: str,
    subscriber_count: int,
) -> None:
    policy_churn.apply_dynsec_snapshot("docker/dynamic-security-fanout-read-allow-unpinned.json")
    compose_harness.up(mosquitto_conf="./mosquitto_dynsec_acl_read.conf", tls=False)
    issuer = compose_harness.token_issuer(tls=False)

    topic = "fanout/broadcast"
    pre_messages = 8
    post_messages = 8

    subscriber_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id=f"dynsec-client-{unique_suffix}",
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )
    publisher_token = _issue_token(
        issuer,
        token_kind=token_kind,
        client_id="fanout_publisher",
        topic=topic,
        ttl_seconds=180,
        grants=[],
    )

    subscribers = [
        mqtt_client_factory(
            host="localhost",
            port=1883,
            client_id=f"issue39-fanout-sub-{idx}-{unique_suffix}",
            username="dynsec_client_1",
            password=subscriber_token,
        )
        for idx in range(subscriber_count)
    ]
    publisher = mqtt_client_factory(
        host="localhost",
        port=1883,
        client_id="fanout_publisher",
        username="dynsec_publisher",
        password=publisher_token,
    )

    try:
        for sub in subscribers:
            sub.connect()
            assert _is_granted(sub.subscribe(topic, qos=1))
        publisher.connect()

        for idx in range(pre_messages):
            publisher.publish(topic, f"pre|{idx}|{unique_suffix}", qos=0)
        expected_pre = int(subscriber_count * pre_messages * 0.82)
        deadline = time.monotonic() + 8.0
        pre_received = _total_messages(subscribers)
        while pre_received < expected_pre and time.monotonic() < deadline:
            time.sleep(0.15)
            pre_received = _total_messages(subscribers)
        assert pre_received >= expected_pre

        policy_churn.apply_dynsec_snapshot("docker/dynamic-security-fanout-read-deny-unpinned.json")
        time.sleep(2.2)

        for idx in range(post_messages):
            publisher.publish(topic, f"post|{idx}|{unique_suffix}", qos=0)
        time.sleep(1.8)
        total_received = _total_messages(subscribers)
        post_received = total_received - pre_received

        # After churn, strict ACL_READ should block almost all post-churn fanout delivery.
        assert post_received <= max(5, int(subscriber_count * 0.08))
        for sub in subscribers:
            sub.assert_connected_for(0.8)
    finally:
        for sub in subscribers:
            sub.close()
        publisher.close()
