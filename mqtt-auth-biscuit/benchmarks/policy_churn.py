import os
import shutil
import sqlite3
from collections.abc import Iterable
from typing import TypedDict

ACL_READ = 0x01
ACL_WRITE = 0x02
ACL_SUBSCRIBE = 0x04
ACL_CONTROL = 0x08
FANOUT_READER_ROLE = "fanout_reader"
FANOUT_PUBLISHER_ROLE = "fanout_publisher"
DEEP_DATA_ALLOW_ROLE = "deep_data_allow"
DEEP_PRIVATE_DENY_ROLE = "deep_private_deny"
DEEP_PUBLISHER_ROLE = "deep_publisher"
DEEP_CONTROL_ADMIN_ROLE = "deep_control_admin"
DEEP_CONTROL_OBSERVER_ROLE = "deep_control_observer"


class SqliteFanoutSeedResult(TypedDict):
    subscriber_count: int
    rows_seeded: int
    topic: str
    profile: str


class SqliteFanoutRevokeResult(TypedDict):
    subscriber_count: int
    read_rows_revoked: int
    topic: str


class SqliteFanoutGrantResult(TypedDict):
    subscriber_count: int
    read_rows_granted: int
    topic: str


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(__file__))


def _resolve_repo_path(path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.join(_repo_root(), path)


def apply_dynsec_snapshot(
    source_path: str,
    dest_path: str = "docker/dynamic-security.json",
    *,
    copy_tls: bool = False,
) -> dict[str, str]:
    src = _resolve_repo_path(source_path)
    dest = _resolve_repo_path(dest_path)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    # Keep inode stable for bind-mounted single-file volumes used by Docker.
    shutil.copyfile(src, dest)

    out = {"source": src, "dest": dest}
    if copy_tls:
        tls_dest = _resolve_repo_path("docker/tls/dynamic-security.json")
        os.makedirs(os.path.dirname(tls_dest), exist_ok=True)
        shutil.copyfile(src, tls_dest)
        out["tls_dest"] = tls_dest
    return out


def _ensure_policy_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(
        "PRAGMA foreign_keys = ON;"
        "CREATE TABLE IF NOT EXISTS users("
        "client_id TEXT PRIMARY KEY"
        ");"
        "CREATE TABLE IF NOT EXISTS roles("
        "role_name TEXT PRIMARY KEY"
        ");"
        "CREATE TABLE IF NOT EXISTS user_roles("
        "client_id TEXT NOT NULL,"
        "role_name TEXT NOT NULL,"
        "priority INTEGER NOT NULL DEFAULT 100,"
        "PRIMARY KEY(client_id, role_name),"
        "FOREIGN KEY(client_id) REFERENCES users(client_id) ON DELETE CASCADE,"
        "FOREIGN KEY(role_name) REFERENCES roles(role_name) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS role_acls("
        "role_name TEXT NOT NULL,"
        "topic_filter TEXT NOT NULL,"
        "access INTEGER NOT NULL,"
        "PRIMARY KEY(role_name, topic_filter, access),"
        "FOREIGN KEY(role_name) REFERENCES roles(role_name) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS role_deny_acls("
        "role_name TEXT NOT NULL,"
        "topic_filter TEXT NOT NULL,"
        "access INTEGER NOT NULL,"
        "PRIMARY KEY(role_name, topic_filter, access),"
        "FOREIGN KEY(role_name) REFERENCES roles(role_name) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS acl("
        "client_id TEXT NOT NULL,"
        "topic TEXT NOT NULL,"
        "access INTEGER NOT NULL,"
        "PRIMARY KEY(client_id, topic, access)"
        ");"
    )
    try:
        conn.execute("ALTER TABLE user_roles ADD COLUMN priority INTEGER NOT NULL DEFAULT 100")
    except sqlite3.OperationalError as exc:
        if "duplicate column name" not in str(exc).lower():
            raise


def _subscriber_ids(subscriber_count: int) -> Iterable[str]:
    for idx in range(1, subscriber_count + 1):
        yield f"client_{idx}"


def seed_sqlite_fanout_policy(
    db_path: str,
    *,
    topic: str,
    subscriber_count: int,
    publisher_client_id: str = "fanout_publisher",
    profile: str = "fanout_basic",
) -> SqliteFanoutSeedResult:
    if profile == "rbac_deep":
        return seed_sqlite_deep_policy(
            db_path,
            topic=topic,
            subscriber_count=subscriber_count,
            publisher_client_id=publisher_client_id,
            profile_name="rbac_deep",
        )
    if profile == "rbac_deep_control_allow":
        return seed_sqlite_deep_policy(
            db_path,
            topic=topic,
            subscriber_count=subscriber_count,
            publisher_client_id=publisher_client_id,
            control_client_id="client_1",
            control_role="admin",
            profile_name="rbac_deep_control_allow",
        )
    if profile != "fanout_basic":
        raise ValueError(f"unknown sqlite seed profile: {profile}")

    resolved_db_path = _resolve_repo_path(db_path)
    os.makedirs(os.path.dirname(resolved_db_path), exist_ok=True)

    with sqlite3.connect(resolved_db_path) as conn:
        _ensure_policy_tables(conn)
        conn.execute("DELETE FROM user_roles")
        conn.execute("DELETE FROM role_acls")
        conn.execute("DELETE FROM role_deny_acls")
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM roles")
        conn.execute("DELETE FROM acl")

        subscriber_ids = list(_subscriber_ids(subscriber_count))

        conn.executemany(
            "INSERT OR REPLACE INTO roles(role_name) VALUES(?)",
            [(FANOUT_READER_ROLE,), (FANOUT_PUBLISHER_ROLE,)],
        )

        conn.executemany(
            "INSERT OR REPLACE INTO users(client_id) VALUES(?)",
            [(client_id,) for client_id in subscriber_ids] + [(publisher_client_id,)],
        )

        conn.executemany(
            "INSERT OR REPLACE INTO user_roles(client_id, role_name, priority) VALUES(?, ?, ?)",
            [(client_id, FANOUT_READER_ROLE, 100) for client_id in subscriber_ids]
            + [(publisher_client_id, FANOUT_PUBLISHER_ROLE, 100)],
        )

        conn.executemany(
            "INSERT OR REPLACE INTO role_acls(role_name, topic_filter, access) VALUES(?, ?, ?)",
            [
                (FANOUT_READER_ROLE, topic, ACL_SUBSCRIBE),
                (FANOUT_READER_ROLE, topic, ACL_READ),
                (FANOUT_PUBLISHER_ROLE, topic, ACL_WRITE),
            ],
        )
        conn.commit()

    return {
        "subscriber_count": subscriber_count,
        "rows_seeded": (2 * subscriber_count) + 5,
        "topic": topic,
        "profile": profile,
    }


def seed_sqlite_deep_policy(
    db_path: str,
    *,
    topic: str,
    subscriber_count: int,
    publisher_client_id: str = "fanout_publisher",
    control_client_id: str | None = None,
    control_role: str = "admin",
    profile_name: str = "rbac_deep",
) -> SqliteFanoutSeedResult:
    resolved_db_path = _resolve_repo_path(db_path)
    os.makedirs(os.path.dirname(resolved_db_path), exist_ok=True)

    with sqlite3.connect(resolved_db_path) as conn:
        _ensure_policy_tables(conn)
        conn.execute("DELETE FROM user_roles")
        conn.execute("DELETE FROM role_acls")
        conn.execute("DELETE FROM role_deny_acls")
        conn.execute("DELETE FROM users")
        conn.execute("DELETE FROM roles")
        conn.execute("DELETE FROM acl")

        subscriber_ids = list(_subscriber_ids(subscriber_count))
        roles = [
            DEEP_DATA_ALLOW_ROLE,
            DEEP_PRIVATE_DENY_ROLE,
            DEEP_PUBLISHER_ROLE,
            DEEP_CONTROL_ADMIN_ROLE,
            DEEP_CONTROL_OBSERVER_ROLE,
        ]
        conn.executemany(
            "INSERT OR REPLACE INTO roles(role_name) VALUES(?)",
            [(role_name,) for role_name in roles],
        )
        users = subscriber_ids + [publisher_client_id, "ops_admin", "ops_observer"]
        conn.executemany(
            "INSERT OR REPLACE INTO users(client_id) VALUES(?)",
            [(client_id,) for client_id in users],
        )

        user_roles_rows: list[tuple[str, str, int]] = []
        for idx, client_id in enumerate(subscriber_ids, start=1):
            if idx % 2 == 1:
                user_roles_rows.append((client_id, DEEP_DATA_ALLOW_ROLE, 100))
                user_roles_rows.append((client_id, DEEP_PRIVATE_DENY_ROLE, 100))
            else:
                user_roles_rows.append((client_id, DEEP_DATA_ALLOW_ROLE, 40))
                user_roles_rows.append((client_id, DEEP_PRIVATE_DENY_ROLE, 120))
        user_roles_rows.extend(
            [
                (publisher_client_id, DEEP_PUBLISHER_ROLE, 30),
                ("ops_admin", DEEP_CONTROL_ADMIN_ROLE, 10),
                ("ops_observer", DEEP_CONTROL_OBSERVER_ROLE, 10),
            ]
        )
        if control_client_id:
            role = (
                DEEP_CONTROL_ADMIN_ROLE if control_role == "admin" else DEEP_CONTROL_OBSERVER_ROLE
            )
            user_roles_rows.append((control_client_id, role, 15))
        conn.executemany(
            "INSERT OR REPLACE INTO user_roles(client_id, role_name, priority) VALUES(?, ?, ?)",
            user_roles_rows,
        )

        conn.executemany(
            "INSERT OR REPLACE INTO role_acls(role_name, topic_filter, access) VALUES(?, ?, ?)",
            [
                (DEEP_DATA_ALLOW_ROLE, topic, ACL_SUBSCRIBE),
                (DEEP_DATA_ALLOW_ROLE, topic, ACL_READ),
                (DEEP_PUBLISHER_ROLE, topic, ACL_WRITE),
                (DEEP_CONTROL_ADMIN_ROLE, "$CONTROL/#", ACL_CONTROL),
                (DEEP_CONTROL_ADMIN_ROLE, "system/notifications/#", ACL_SUBSCRIBE),
                (DEEP_CONTROL_ADMIN_ROLE, "system/notifications/#", ACL_READ),
                (DEEP_CONTROL_ADMIN_ROLE, "system/notifications/#", ACL_WRITE),
                (DEEP_CONTROL_OBSERVER_ROLE, "system/notifications/#", ACL_SUBSCRIBE),
                (DEEP_CONTROL_OBSERVER_ROLE, "system/notifications/#", ACL_READ),
            ],
        )
        conn.executemany(
            (
                "INSERT OR REPLACE INTO role_deny_acls(role_name, topic_filter, access) "
                "VALUES(?, ?, ?)"
            ),
            [
                (DEEP_PRIVATE_DENY_ROLE, topic, ACL_SUBSCRIBE),
                (DEEP_PRIVATE_DENY_ROLE, topic, ACL_READ),
                (DEEP_CONTROL_OBSERVER_ROLE, "$CONTROL/#", ACL_CONTROL),
                (DEEP_CONTROL_OBSERVER_ROLE, "system/notifications/#", ACL_WRITE),
            ],
        )
        conn.commit()

    return {
        "subscriber_count": subscriber_count,
        "rows_seeded": (3 * subscriber_count) + 24,
        "topic": topic,
        "profile": profile_name,
    }


def revoke_sqlite_read_fanout(
    db_path: str,
    *,
    topic: str,
    subscriber_count: int,
) -> SqliteFanoutRevokeResult:
    resolved_db_path = _resolve_repo_path(db_path)

    with sqlite3.connect(resolved_db_path) as conn:
        _ensure_policy_tables(conn)
        cur = conn.execute(
            "DELETE FROM role_acls WHERE role_name = ? AND topic_filter = ? AND access = ?",
            (FANOUT_READER_ROLE, topic, ACL_READ),
        )
        conn.commit()
        read_rows_revoked = subscriber_count if cur.rowcount > 0 else 0

    return {
        "subscriber_count": subscriber_count,
        "read_rows_revoked": read_rows_revoked,
        "topic": topic,
    }


def grant_sqlite_read_fanout(
    db_path: str,
    *,
    topic: str,
    subscriber_count: int,
) -> SqliteFanoutGrantResult:
    resolved_db_path = _resolve_repo_path(db_path)

    with sqlite3.connect(resolved_db_path) as conn:
        _ensure_policy_tables(conn)
        conn.execute(
            "INSERT OR REPLACE INTO role_acls(role_name, topic_filter, access) VALUES(?, ?, ?)",
            (FANOUT_READER_ROLE, topic, ACL_READ),
        )
        conn.commit()

    return {
        "subscriber_count": subscriber_count,
        "read_rows_granted": subscriber_count,
        "topic": topic,
    }


def toggle_sqlite_read_fanout(
    db_path: str,
    *,
    topic: str,
    subscriber_count: int,
) -> dict[str, int | str]:
    resolved_db_path = _resolve_repo_path(db_path)

    with sqlite3.connect(resolved_db_path) as conn:
        _ensure_policy_tables(conn)
        row = conn.execute(
            (
                "SELECT 1 FROM role_acls WHERE role_name = ? AND topic_filter = ? "
                "AND access = ? LIMIT 1"
            ),
            (FANOUT_READER_ROLE, topic, ACL_READ),
        ).fetchone()

    if row is None:
        granted = grant_sqlite_read_fanout(
            db_path,
            topic=topic,
            subscriber_count=subscriber_count,
        )
        return {
            "action": "grant",
            "subscriber_count": granted["subscriber_count"],
            "read_rows_granted": granted["read_rows_granted"],
            "topic": granted["topic"],
        }

    revoked = revoke_sqlite_read_fanout(
        db_path,
        topic=topic,
        subscriber_count=subscriber_count,
    )
    return {
        "action": "revoke",
        "subscriber_count": revoked["subscriber_count"],
        "read_rows_revoked": revoked["read_rows_revoked"],
        "topic": revoked["topic"],
    }


def toggle_sqlite_private_deny_fanout(
    db_path: str,
    *,
    topic: str,
    subscriber_count: int,
) -> dict[str, int | str]:
    resolved_db_path = _resolve_repo_path(db_path)

    with sqlite3.connect(resolved_db_path) as conn:
        _ensure_policy_tables(conn)
        row = conn.execute(
            (
                "SELECT 1 FROM role_deny_acls WHERE role_name = ? AND topic_filter = ? "
                "AND access = ? LIMIT 1"
            ),
            (DEEP_PRIVATE_DENY_ROLE, topic, ACL_READ),
        ).fetchone()

        if row is None:
            conn.executemany(
                (
                    "INSERT OR REPLACE INTO role_deny_acls(role_name, topic_filter, access) "
                    "VALUES(?, ?, ?)"
                ),
                [
                    (DEEP_PRIVATE_DENY_ROLE, topic, ACL_SUBSCRIBE),
                    (DEEP_PRIVATE_DENY_ROLE, topic, ACL_READ),
                ],
            )
            conn.commit()
            return {
                "action": "grant_deny",
                "subscriber_count": subscriber_count,
                "deny_rows_changed": subscriber_count,
                "topic": topic,
            }

        conn.executemany(
            "DELETE FROM role_deny_acls WHERE role_name = ? AND topic_filter = ? AND access = ?",
            [
                (DEEP_PRIVATE_DENY_ROLE, topic, ACL_SUBSCRIBE),
                (DEEP_PRIVATE_DENY_ROLE, topic, ACL_READ),
            ],
        )
        conn.commit()
        return {
            "action": "revoke_deny",
            "subscriber_count": subscriber_count,
            "deny_rows_changed": subscriber_count,
            "topic": topic,
        }
