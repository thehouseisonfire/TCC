import sqlite3

from benchmarks import policy_churn


def _count(conn: sqlite3.Connection, access: int) -> int:
    row = conn.execute("SELECT COUNT(*) FROM acl WHERE access = ?", (access,)).fetchone()
    assert row is not None
    return int(row[0])


def test_seed_then_revoke_sqlite_fanout_policy(tmp_path) -> None:
    db_path = tmp_path / "policy.db"

    seeded = policy_churn.seed_sqlite_fanout_policy(
        str(db_path),
        topic="fanout/broadcast",
        subscriber_count=3,
    )

    assert seeded["rows_seeded"] == 7

    with sqlite3.connect(db_path) as conn:
        assert _count(conn, policy_churn.ACL_READ) == 3
        assert _count(conn, policy_churn.ACL_SUBSCRIBE) == 3
        assert _count(conn, policy_churn.ACL_WRITE) == 1

    revoked = policy_churn.revoke_sqlite_read_fanout(
        str(db_path),
        topic="fanout/broadcast",
        subscriber_count=3,
    )
    assert revoked["read_rows_revoked"] == 3

    with sqlite3.connect(db_path) as conn:
        assert _count(conn, policy_churn.ACL_READ) == 0
        assert _count(conn, policy_churn.ACL_SUBSCRIBE) == 3
        assert _count(conn, policy_churn.ACL_WRITE) == 1
