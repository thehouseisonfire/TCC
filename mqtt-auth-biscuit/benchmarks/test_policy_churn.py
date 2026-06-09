import sqlite3

from benchmarks import policy_churn


def _count_role_acl(conn: sqlite3.Connection, access: int) -> int:
    row = conn.execute("SELECT COUNT(*) FROM role_acls WHERE access = ?", (access,)).fetchone()
    assert row is not None
    return int(row[0])


def _count_role_deny_acl(conn: sqlite3.Connection, access: int) -> int:
    row = conn.execute("SELECT COUNT(*) FROM role_deny_acls WHERE access = ?", (access,)).fetchone()
    assert row is not None
    return int(row[0])


def _count_user_roles(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM user_roles").fetchone()
    assert row is not None
    return int(row[0])


def test_seed_then_revoke_sqlite_fanout_policy(tmp_path) -> None:
    db_path = tmp_path / "policy.db"

    seeded = policy_churn.seed_sqlite_fanout_policy(
        str(db_path),
        topic="fanout/broadcast",
        subscriber_count=3,
    )

    assert seeded["rows_seeded"] == 11
    assert seeded["profile"] == "fanout_basic"

    with sqlite3.connect(db_path) as conn:
        assert _count_user_roles(conn) == 4
        assert _count_role_acl(conn, policy_churn.ACL_READ) == 1
        assert _count_role_acl(conn, policy_churn.ACL_SUBSCRIBE) == 1
        assert _count_role_acl(conn, policy_churn.ACL_WRITE) == 1

    revoked = policy_churn.revoke_sqlite_read_fanout(
        str(db_path),
        topic="fanout/broadcast",
        subscriber_count=3,
    )
    assert revoked["read_rows_revoked"] == 3

    with sqlite3.connect(db_path) as conn:
        assert _count_role_acl(conn, policy_churn.ACL_READ) == 0
        assert _count_role_acl(conn, policy_churn.ACL_SUBSCRIBE) == 1
        assert _count_role_acl(conn, policy_churn.ACL_WRITE) == 1


def test_toggle_sqlite_read_fanout_switches_between_revoke_and_grant(tmp_path) -> None:
    db_path = tmp_path / "policy.db"
    policy_churn.seed_sqlite_fanout_policy(
        str(db_path),
        topic="fanout/broadcast",
        subscriber_count=2,
    )

    first = policy_churn.toggle_sqlite_read_fanout(
        str(db_path),
        topic="fanout/broadcast",
        subscriber_count=2,
    )
    assert first["action"] == "revoke"

    with sqlite3.connect(db_path) as conn:
        assert _count_role_acl(conn, policy_churn.ACL_READ) == 0

    second = policy_churn.toggle_sqlite_read_fanout(
        str(db_path),
        topic="fanout/broadcast",
        subscriber_count=2,
    )
    assert second["action"] == "grant"

    with sqlite3.connect(db_path) as conn:
        assert _count_role_acl(conn, policy_churn.ACL_READ) == 1


def test_seed_sqlite_deep_policy_sets_conflict_and_control_roles(tmp_path) -> None:
    db_path = tmp_path / "policy-deep.db"
    seeded = policy_churn.seed_sqlite_fanout_policy(
        str(db_path),
        topic="sensors/private/broadcast",
        subscriber_count=4,
        profile="rbac_deep",
    )
    assert seeded["profile"] == "rbac_deep"
    assert seeded["rows_seeded"] == 36

    with sqlite3.connect(db_path) as conn:
        odd = conn.execute(
            "SELECT priority FROM user_roles WHERE client_id = ? AND role_name = ?",
            ("client_1", policy_churn.DEEP_DATA_ALLOW_ROLE),
        ).fetchone()
        assert odd is not None
        assert int(odd[0]) == 100
        even = conn.execute(
            "SELECT priority FROM user_roles WHERE client_id = ? AND role_name = ?",
            ("client_2", policy_churn.DEEP_DATA_ALLOW_ROLE),
        ).fetchone()
        assert even is not None
        assert int(even[0]) == 40
        assert _count_role_deny_acl(conn, policy_churn.ACL_READ) >= 1
        assert _count_role_deny_acl(conn, policy_churn.ACL_CONTROL) >= 1


def test_toggle_sqlite_private_deny_fanout_switches_deny_rows(tmp_path) -> None:
    db_path = tmp_path / "policy-private-deny.db"
    policy_churn.seed_sqlite_fanout_policy(
        str(db_path),
        topic="sensors/private/broadcast",
        subscriber_count=2,
        profile="rbac_deep",
    )

    first = policy_churn.toggle_sqlite_private_deny_fanout(
        str(db_path),
        topic="sensors/private/broadcast",
        subscriber_count=2,
    )
    assert first["action"] == "revoke_deny"
    with sqlite3.connect(db_path) as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM role_deny_acls WHERE role_name = ? AND topic_filter = ?",
                (policy_churn.DEEP_PRIVATE_DENY_ROLE, "sensors/private/broadcast"),
            ).fetchone()[0]
            == 0
        )

    second = policy_churn.toggle_sqlite_private_deny_fanout(
        str(db_path),
        topic="sensors/private/broadcast",
        subscriber_count=2,
    )
    assert second["action"] == "grant_deny"
    with sqlite3.connect(db_path) as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM role_deny_acls WHERE role_name = ? AND topic_filter = ?",
                (policy_churn.DEEP_PRIVATE_DENY_ROLE, "sensors/private/broadcast"),
            ).fetchone()[0]
            == 2
        )


def test_seed_sqlite_deep_control_allow_profile_assigns_client_control_role(tmp_path) -> None:
    db_path = tmp_path / "policy-control-allow.db"
    seeded = policy_churn.seed_sqlite_fanout_policy(
        str(db_path),
        topic="sensors/private/broadcast",
        subscriber_count=1,
        profile="rbac_deep_control_allow",
    )
    assert seeded["profile"] == "rbac_deep_control_allow"

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT role_name FROM user_roles WHERE client_id = ? AND role_name = ?",
            ("client_1", policy_churn.DEEP_CONTROL_ADMIN_ROLE),
        ).fetchone()
        assert row is not None


def test_build_dynsec_snapshot_fanout_control_allow_grants_control_publish_acl() -> None:
    payload = policy_churn.build_dynsec_snapshot("fanout_control_allow")
    roles = payload["roles"]
    assert isinstance(roles, list)

    fanout_writer = next(role for role in roles if role.get("rolename") == "fanout_writer")
    acls = fanout_writer["acls"]
    assert isinstance(acls, list)
    assert {
        "acltype": "publishClientSend",
        "topic": "$CONTROL/dynamic-security/v1",
        "priority": 0,
        "allow": True,
    } in acls


def test_build_dynsec_snapshot_control_admin_base_contains_admin_control_identity() -> None:
    payload = policy_churn.build_dynsec_snapshot("control_admin_base")
    clients = payload["clients"]
    roles = payload["roles"]
    assert isinstance(clients, list)
    assert isinstance(roles, list)

    admin_client = next(client for client in clients if client.get("username") == "admin")
    assert admin_client["roles"] == [{"rolename": policy_churn.CONTROL_ADMIN_ROLE, "priority": 0}]

    admin_role = next(
        role for role in roles if role.get("rolename") == policy_churn.CONTROL_ADMIN_ROLE
    )
    acls = admin_role["acls"]
    assert isinstance(acls, list)
    assert {
        "acltype": "publishClientSend",
        "topic": "$CONTROL/dynamic-security/v1",
        "priority": 0,
        "allow": True,
    } in acls
    assert {
        "acltype": "publishClientSend",
        "topic": "system/notifications/#",
        "priority": 0,
        "allow": True,
    } in acls
    assert {
        "acltype": "publishClientSend",
        "topic": "sensors/+/#",
        "priority": 0,
        "allow": True,
    } in acls
    assert {
        "acltype": "publishClientReceive",
        "topic": "system/notifications/#",
        "priority": 0,
        "allow": True,
    } in acls
    assert {
        "acltype": "subscribePattern",
        "topic": "system/notifications/#",
        "priority": 0,
        "allow": True,
    } in acls


def test_apply_dynsec_snapshot_same_source_and_dest_is_a_noop(tmp_path) -> None:
    snapshot = tmp_path / "dynamic-security.json"
    snapshot.write_text('{"clients":[]}\n', encoding="utf-8")

    result = policy_churn.apply_dynsec_snapshot(str(snapshot), str(snapshot))

    assert result == {"source": str(snapshot), "dest": str(snapshot)}
    assert snapshot.read_text(encoding="utf-8") == '{"clients":[]}\n'


def test_build_dynsec_snapshot_control_interleaved_base_contains_jwt_and_biscuit_publishers() -> (
    None
):
    payload = policy_churn.build_dynsec_snapshot("control_interleaved_base")
    clients = payload["clients"]
    roles = payload["roles"]
    assert isinstance(clients, list)
    assert isinstance(roles, list)

    for username in ("jwt", "biscuit"):
        client = next(client for client in clients if client.get("username") == username)
        expected_role = f"{policy_churn.CONTROL_DATA_PUBLISHER_ROLE}_{username}"
        assert client["roles"] == [{"rolename": expected_role, "priority": 0}]

        role = next(role for role in roles if role.get("rolename") == expected_role)
        acls = role["acls"]
        assert isinstance(acls, list)
        assert {
            "acltype": "publishClientSend",
            "topic": "sensors/+/#",
            "priority": 0,
            "allow": True,
        } in acls
        assert {
            "acltype": "publishClientSend",
            "topic": "$CONTROL/dynamic-security/v1",
            "priority": 0,
            "allow": True,
        } in acls


def test_build_dynsec_snapshot_noop_group_seeds_existing_reader_membership() -> None:
    payload = policy_churn.build_dynsec_snapshot("fanout_control_noop_group")
    groups = payload["groups"]
    clients = payload["clients"]
    assert isinstance(groups, list)
    assert isinstance(clients, list)

    group = next(group for group in groups if group.get("groupname") == "fanout_existing_readers")
    assert group["roles"] == [{"rolename": policy_churn.FANOUT_READER_ROLE, "priority": 0}]
    assert group["clients"] == [{"username": "dynsec_client_1", "priority": 0}]
    admin_client = next(client for client in clients if client.get("username") == "admin")
    assert admin_client["roles"] == [{"rolename": policy_churn.CONTROL_ADMIN_ROLE, "priority": 0}]


def test_build_dynsec_snapshot_large_state_adds_deterministic_bulk_entities() -> None:
    payload = policy_churn.build_dynsec_snapshot("large_state_control")

    roles = payload["roles"]
    groups = payload["groups"]
    clients = payload["clients"]
    assert isinstance(roles, list)
    assert isinstance(groups, list)
    assert isinstance(clients, list)

    bulk_role_names = {
        role["rolename"] for role in roles if role["rolename"].startswith("dynamic_bulk_reader_")
    }
    bulk_group_names = {
        group["groupname"]
        for group in groups
        if group["groupname"].startswith("dynamic_bulk_group_")
    }
    bulk_usernames = {
        client["username"] for client in clients if client["username"].startswith("bulk_user_")
    }

    assert len(bulk_role_names) == 20
    assert len(bulk_group_names) == 20
    assert len(bulk_usernames) == 100
    assert "dynamic_bulk_reader_1" in bulk_role_names
    assert "dynamic_bulk_group_20" in bulk_group_names
    assert "bulk_user_100" in bulk_usernames
    admin_client = next(client for client in clients if client.get("username") == "admin")
    assert admin_client["roles"] == [{"rolename": policy_churn.CONTROL_ADMIN_ROLE, "priority": 0}]
