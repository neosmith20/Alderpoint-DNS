"""Stable V2 node identity.

The node id is a cryptographically-random UUID persisted in control.db.
It is never derived from hostname and is separate from the operator-facing
display name. Backup/restore intentionally retains the id; a simultaneously
active clone must run ``regenerate_node_identity`` before replication is
authorized as a distinct appliance.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.v2 import control_db

NODE_IDENTITY_SCHEMA_VERSION = 4

_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS node_identity (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        node_id TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        regenerated_at TEXT
    )
    """,
]


@dataclass(frozen=True)
class NodeIdentity:
    node_id: str
    display_name: str
    created_at: str
    regenerated_at: str | None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def ensure_schema(path: str | Path) -> None:
    control_db.initialize(path)
    with control_db.connect(path) as conn:
        present = _table_exists(conn, "node_identity")
    if not present:
        control_db.apply_migration_in_transaction(path, _MIGRATION, NODE_IDENTITY_SCHEMA_VERSION)


def get_or_create(conn: sqlite3.Connection, *, display_name: str = "") -> NodeIdentity:
    row = conn.execute(
        "SELECT node_id, display_name, created_at, regenerated_at FROM node_identity WHERE id=1"
    ).fetchone()
    if row is None:
        now = _now()
        node_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO node_identity(id, node_id, display_name, created_at) VALUES (1, ?, ?, ?)",
            (node_id, display_name, now),
        )
        return NodeIdentity(node_id=node_id, display_name=display_name, created_at=now, regenerated_at=None)
    return NodeIdentity(row[0], row[1], row[2], row[3])


def set_display_name(conn: sqlite3.Connection, display_name: str) -> NodeIdentity:
    if len(display_name) > 128:
        raise ValueError("display_name must be 128 characters or fewer")
    identity = get_or_create(conn)
    conn.execute("UPDATE node_identity SET display_name=? WHERE id=1", (display_name,))
    return NodeIdentity(identity.node_id, display_name, identity.created_at, identity.regenerated_at)


def regenerate_node_identity(conn: sqlite3.Connection, *, display_name: str | None = None) -> NodeIdentity:
    """Explicit clone/restore escape hatch. Peer trust is cleared by the
    replication layer before calling this in the packaged CLI/API path.
    """
    existing = get_or_create(conn)
    new_display_name = existing.display_name if display_name is None else display_name
    now = _now()
    node_id = str(uuid.uuid4())
    conn.execute(
        "UPDATE node_identity SET node_id=?, display_name=?, regenerated_at=? WHERE id=1",
        (node_id, new_display_name, now),
    )
    return NodeIdentity(node_id, new_display_name, existing.created_at, now)
