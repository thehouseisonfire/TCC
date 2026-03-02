import os
import shutil
import sqlite3
from collections.abc import Iterable
from typing import TypedDict

ACL_READ = 0x01
ACL_WRITE = 0x02
ACL_SUBSCRIBE = 0x04


class SqliteFanoutSeedResult(TypedDict):
    subscriber_count: int
    rows_seeded: int
    topic: str


class SqliteFanoutRevokeResult(TypedDict):
    subscriber_count: int
    read_rows_revoked: int
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


def _ensure_acl_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS acl("
        "client_id TEXT NOT NULL,"
        "topic TEXT NOT NULL,"
        "access INTEGER NOT NULL,"
        "PRIMARY KEY(client_id, topic, access)"
        ")"
    )


def _subscriber_ids(subscriber_count: int) -> Iterable[str]:
    for idx in range(1, subscriber_count + 1):
        yield f"client_{idx}"


def seed_sqlite_fanout_policy(
    db_path: str,
    *,
    topic: str,
    subscriber_count: int,
    publisher_client_id: str = "fanout_publisher",
) -> SqliteFanoutSeedResult:
    resolved_db_path = _resolve_repo_path(db_path)
    os.makedirs(os.path.dirname(resolved_db_path), exist_ok=True)

    with sqlite3.connect(resolved_db_path) as conn:
        _ensure_acl_table(conn)
        conn.execute("DELETE FROM acl")

        rows = []
        for client_id in _subscriber_ids(subscriber_count):
            rows.append((client_id, topic, ACL_SUBSCRIBE))
            rows.append((client_id, topic, ACL_READ))

        rows.append((publisher_client_id, topic, ACL_WRITE))

        conn.executemany(
            "INSERT OR REPLACE INTO acl(client_id, topic, access) VALUES(?, ?, ?)",
            rows,
        )
        conn.commit()

    return {
        "subscriber_count": subscriber_count,
        "rows_seeded": len(rows),
        "topic": topic,
    }


def revoke_sqlite_read_fanout(
    db_path: str,
    *,
    topic: str,
    subscriber_count: int,
) -> SqliteFanoutRevokeResult:
    resolved_db_path = _resolve_repo_path(db_path)

    with sqlite3.connect(resolved_db_path) as conn:
        _ensure_acl_table(conn)
        subscriber_ids = list(_subscriber_ids(subscriber_count))
        conn.executemany(
            "DELETE FROM acl WHERE client_id = ? AND topic = ? AND access = ?",
            [(client_id, topic, ACL_READ) for client_id in subscriber_ids],
        )
        conn.commit()

    return {
        "subscriber_count": subscriber_count,
        "read_rows_revoked": subscriber_count,
        "topic": topic,
    }
