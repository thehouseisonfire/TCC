import contextlib
import json
import shutil
import sqlite3
import tempfile
from collections.abc import Iterable
from os import fdopen
from pathlib import Path
from typing import Any, TypedDict

ACL_READ = 0x01
ACL_WRITE = 0x02
ACL_SUBSCRIBE = 0x04
ACL_CONTROL = 0x08
FANOUT_READER_ROLE = "fanout_reader"
FANOUT_PUBLISHER_ROLE = "fanout_publisher"
CONTROL_ADMIN_ROLE = "benchmark_control_admin"
CONTROL_DATA_PUBLISHER_ROLE = "benchmark_control_data_publisher"
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


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_repo_path(path: str | Path) -> Path:
    resolved_path = Path(path)
    if resolved_path.is_absolute():
        return resolved_path
    return _repo_root() / resolved_path


def apply_dynsec_snapshot(
    source_path: str,
    dest_path: str = "docker/dynamic-security.json",
    *,
    copy_tls: bool = False,
) -> dict[str, str]:
    src = _resolve_repo_path(source_path)
    dest = _resolve_repo_path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Keep inode stable for bind-mounted single-file volumes used by Docker.
    if src.resolve() != dest.resolve():
        shutil.copyfile(src, dest)

    out = {"source": str(src), "dest": str(dest)}
    if copy_tls:
        tls_dest = _resolve_repo_path("docker/tls/dynamic-security.json")
        tls_dest.parent.mkdir(parents=True, exist_ok=True)
        if src.resolve() != tls_dest.resolve():
            shutil.copyfile(src, tls_dest)
        out["tls_dest"] = str(tls_dest)
    return out


def read_dynsec_snapshot(source_path: str | Path) -> dict[str, Any]:
    src = _resolve_repo_path(source_path)
    return json.loads(src.read_text(encoding="utf-8"))


def write_dynsec_snapshot(
    payload: dict[str, Any],
    *,
    prefix: str = "dynamic-security-generated-",
    suffix: str = ".json",
) -> str:
    fd, temp_path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    with fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    Path(temp_path).chmod(0o600)
    return temp_path


def cleanup_dynsec_snapshot(path: str | None) -> None:
    if not path:
        return
    candidate = Path(path)
    with contextlib.suppress(FileNotFoundError):
        candidate.unlink()


def _upsert_acl(
    role: dict[str, Any], *, acltype: str, topic: str, allow: bool, priority: int = 0
) -> None:
    acls = role.setdefault("acls", [])
    assert isinstance(acls, list)
    for acl in acls:
        if acl.get("acltype") == acltype and acl.get("topic") == topic:
            acl["allow"] = allow
            acl["priority"] = priority
            return
    acls.append({"acltype": acltype, "topic": topic, "priority": priority, "allow": allow})


def _upsert_group(
    payload: dict[str, Any],
    *,
    groupname: str,
    roles: list[dict[str, Any]] | None = None,
    clients: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    groups = payload.setdefault("groups", [])
    assert isinstance(groups, list)
    for group in groups:
        if group.get("groupname") == groupname:
            if roles is not None:
                group["roles"] = roles
            group.setdefault("clients", [])
            if clients:
                existing = {
                    entry.get("username"): entry
                    for entry in group.get("clients", [])
                    if isinstance(entry, dict)
                }
                for client in clients:
                    existing[client["username"]] = client
                group["clients"] = list(existing.values())
            return group
    group = {"groupname": groupname, "roles": roles or [], "clients": clients or []}
    groups.append(group)
    return group


def _upsert_role(payload: dict[str, Any], rolename: str) -> dict[str, Any]:
    roles = payload.setdefault("roles", [])
    assert isinstance(roles, list)
    for role in roles:
        if role.get("rolename") == rolename:
            role.setdefault("acls", [])
            return role
    role = {"rolename": rolename, "acls": []}
    roles.append(role)
    return role


def _upsert_client(
    payload: dict[str, Any], *, username: str, clientid: str | None = None
) -> dict[str, Any]:
    clients = payload.setdefault("clients", [])
    assert isinstance(clients, list)
    for existing_client in clients:
        if existing_client.get("username") == username:
            if clientid is not None:
                existing_client["clientid"] = clientid
            existing_client.setdefault("roles", [])
            existing_client.setdefault("disabled", False)
            return existing_client
    client_entry: dict[str, Any] = {"username": username, "roles": [], "disabled": False}
    if clientid is not None:
        client_entry["clientid"] = clientid
    clients.append(client_entry)
    return client_entry


def _clear_client_id_pin(payload: dict[str, Any], *, username: str) -> None:
    client = _upsert_client(payload, username=username)
    client.pop("clientid", None)


def _upsert_client_role(
    payload: dict[str, Any],
    *,
    username: str,
    rolename: str,
    priority: int = 0,
) -> None:
    client = _upsert_client(payload, username=username)
    roles = client.setdefault("roles", [])
    assert isinstance(roles, list)
    for role in roles:
        if role.get("rolename") == rolename:
            role["priority"] = priority
            return
    roles.append({"rolename": rolename, "priority": priority})


def _add_control_admin_identity(payload: dict[str, Any]) -> None:
    role = _upsert_role(payload, CONTROL_ADMIN_ROLE)
    _upsert_acl(
        role,
        acltype="publishClientSend",
        topic="$CONTROL/dynamic-security/v1",
        allow=True,
    )
    _upsert_acl(
        role,
        acltype="subscribeLiteral",
        topic="$CONTROL/dynamic-security/v1/response",
        allow=True,
    )
    _upsert_acl(
        role,
        acltype="publishClientReceive",
        topic="$CONTROL/dynamic-security/v1/response",
        allow=True,
    )
    _upsert_acl(
        role,
        acltype="publishClientSend",
        topic="system/notifications/#",
        allow=True,
    )
    _upsert_acl(
        role,
        acltype="publishClientSend",
        topic="sensors/+/#",
        allow=True,
    )
    _upsert_acl(
        role,
        acltype="publishClientReceive",
        topic="system/notifications/#",
        allow=True,
    )
    _upsert_acl(
        role,
        acltype="subscribePattern",
        topic="system/notifications/#",
        allow=True,
    )
    _upsert_client_role(payload, username="admin", rolename=CONTROL_ADMIN_ROLE)


def _add_control_data_identity(payload: dict[str, Any], username: str) -> None:
    role = _upsert_role(payload, f"{CONTROL_DATA_PUBLISHER_ROLE}_{username}")
    _upsert_acl(
        role,
        acltype="publishClientSend",
        topic="sensors/+/#",
        allow=True,
    )
    _upsert_acl(
        role,
        acltype="subscribeLiteral",
        topic="$CONTROL/dynamic-security/v1/response",
        allow=True,
    )
    _upsert_acl(
        role,
        acltype="publishClientReceive",
        topic="$CONTROL/dynamic-security/v1/response",
        allow=True,
    )
    _upsert_acl(
        role,
        acltype="publishClientSend",
        topic="$CONTROL/dynamic-security/v1",
        allow=True,
    )
    _upsert_client_role(payload, username=username, rolename=role["rolename"])


def build_dynsec_snapshot(profile: str) -> dict[str, Any]:
    if profile in {"fanout_control_allow"}:
        payload = read_dynsec_snapshot("docker/dynamic-security-fanout-read-allow-unpinned.json")
    elif profile == "publish_multi_client_base" or profile in {
        "control_admin_base",
        "control_interleaved_base",
        "fanout_control_noop_group",
        "large_state_control",
    }:
        payload = read_dynsec_snapshot("docker/dynamic-security.json")
    else:
        raise ValueError(f"unknown dynsec snapshot profile: {profile}")

    if profile == "fanout_control_allow":
        publisher_role = _upsert_role(payload, "fanout_writer")
        _upsert_acl(
            publisher_role,
            acltype="publishClientSend",
            topic="$CONTROL/dynamic-security/v1",
            allow=True,
        )
        notification_role = _upsert_role(payload, "control_notification_reader")
        _upsert_acl(
            notification_role,
            acltype="subscribePattern",
            topic="system_notification/#",
            allow=True,
        )
        _upsert_acl(
            notification_role,
            acltype="publishClientReceive",
            topic="system_notification/#",
            allow=True,
        )
        _upsert_client_role(
            payload,
            username="dynsec_client_1",
            rolename="control_notification_reader",
        )
        _upsert_acl(
            publisher_role,
            acltype="subscribeLiteral",
            topic="$CONTROL/dynamic-security/v1/response",
            allow=True,
        )
        _upsert_acl(
            publisher_role,
            acltype="publishClientReceive",
            topic="$CONTROL/dynamic-security/v1/response",
            allow=True,
        )
    else:
        _add_control_admin_identity(payload)

    if profile == "publish_multi_client_base":
        _clear_client_id_pin(payload, username="dynsec_client_1")

    if profile == "control_interleaved_base":
        _add_control_data_identity(payload, "jwt")
        _add_control_data_identity(payload, "biscuit")

    if profile == "fanout_control_noop_group":
        _upsert_group(
            payload,
            groupname="fanout_existing_readers",
            roles=[{"rolename": FANOUT_READER_ROLE, "priority": 0}],
            clients=[{"username": "dynsec_client_1", "priority": 0}],
        )
    elif profile == "large_state_control":
        for idx in range(1, 21):
            role = _upsert_role(payload, f"dynamic_bulk_reader_{idx}")
            _upsert_acl(
                role,
                acltype="publishClientReceive",
                topic=f"bulk/{idx}/#",
                allow=True,
            )
            _upsert_acl(
                role,
                acltype="subscribeLiteral",
                topic=f"bulk/{idx}/notifications",
                allow=True,
            )
        for idx in range(1, 21):
            members: list[dict[str, Any]] = []
            for member in range(1, 6):
                username = f"bulk_user_{((idx - 1) * 5) + member}"
                client = _upsert_client(
                    payload, username=username, clientid=f"bulk-client-{((idx - 1) * 5) + member}"
                )
                client["roles"] = []
                members.append({"username": username, "priority": 0})
            _upsert_group(
                payload,
                groupname=f"dynamic_bulk_group_{idx}",
                roles=[{"rolename": f"dynamic_bulk_reader_{idx}", "priority": 0}],
                clients=members,
            )

    return payload


def generate_dynsec_snapshot(profile: str) -> str:
    return write_dynsec_snapshot(build_dynsec_snapshot(profile))


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
    resolved_db_path.parent.mkdir(parents=True, exist_ok=True)

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
    resolved_db_path.parent.mkdir(parents=True, exist_ok=True)

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
        for client_id in subscriber_ids:
            user_roles_rows.append((client_id, DEEP_DATA_ALLOW_ROLE, 100))
            user_roles_rows.append((client_id, DEEP_PRIVATE_DENY_ROLE, 100))
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
                (DEEP_CONTROL_OBSERVER_ROLE, "$CONTROL/#", ACL_CONTROL),
                (DEEP_CONTROL_OBSERVER_ROLE, "system/notifications/#", ACL_WRITE),
            ],
        )
        conn.commit()

    return {
        "subscriber_count": subscriber_count,
        "rows_seeded": (3 * subscriber_count) + 22,
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
