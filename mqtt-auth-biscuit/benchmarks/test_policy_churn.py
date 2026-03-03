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
