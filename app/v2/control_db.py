"""V2 control database foundation: bounded transactional/relational state only.

Scope (V2 Workstream 1): schema-versioned SQLite (WAL) database prototype for
the tables classified CONTROL in ``docs/v2/storage-audit.md`` — admins,
sessions, audit log, clients/identifiers, groups/tags, policy tables, job
history (backup/restore/update/import/deploy), replication metadata, and a
migration-state bookkeeping table.

This module never creates or opens the live path
(``/var/lib/alderpointdns/control.db``) implicitly — callers pass a path in,
and Workstream 1's own usage only ever points it at disposable dev/test
paths. Nothing here is wired into the running v1.1.1 webapp.

Hard rule enforced by tests: raw DNS query history (the ANALYTICS-RAW class
in docs/v2/storage-audit.md, i.e. the equivalent of v1's ``query_events``)
must never be a table in this schema.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Callable, Iterator

CONTROL_SCHEMA_VERSION = 1

# Names that must never appear as a table in control.db. This is a guard
# against accidentally reintroducing v1's architecture mistake (raw query
# history sharing the control database) while iterating on this schema.
_FORBIDDEN_TABLE_NAME_FRAGMENTS = ("query_event", "raw_quer", "query_log")

_SCHEMA_STATEMENTS: tuple[str, ...] = (
    # --- migration bookkeeping -------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
    # --- admin accounts / auth --------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        admin_id INTEGER REFERENCES admins(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        csrf TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY,
        ip TEXT NOT NULL,
        attempted_at TEXT NOT NULL,
        success INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS admin_audit_log (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL,
        admin_id INTEGER,
        username TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL,
        success INTEGER NOT NULL,
        ip TEXT,
        detail TEXT NOT NULL DEFAULT ''
    )
    """,
    # --- clients / access / policy placeholders --------------------------------
    """
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS client_identifiers (
        id INTEGER PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK(kind IN ('ipv4','ipv4_cidr','ipv6','ipv6_cidr','clientid')),
        value TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(kind, value)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS client_groups (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS client_group_members (
        group_id INTEGER NOT NULL REFERENCES client_groups(id) ON DELETE CASCADE,
        client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        PRIMARY KEY(group_id, client_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL CHECK(scope IN ('global','network','group','client')),
        target_id INTEGER,
        policy_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    # --- job / operation history -------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS update_jobs (
        id INTEGER PRIMARY KEY,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        detail_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS backup_jobs (
        id INTEGER PRIMARY KEY,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        path TEXT,
        detail_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS restore_jobs (
        id INTEGER PRIMARY KEY,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        backup_path TEXT,
        detail_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
    # --- replication metadata ---------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS replication_replicas (
        id INTEGER PRIMARY KEY,
        node_id TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        last_seen_at TEXT
    )
    """,
    # --- migration bookkeeping (V1 -> V2) ---------------------------------------
    """
    CREATE TABLE IF NOT EXISTS migration_state (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        source_version TEXT,
        stage TEXT NOT NULL DEFAULT 'not_started',
        started_at TEXT,
        point_of_no_return_at TEXT,
        completed_at TEXT,
        detail_json TEXT NOT NULL DEFAULT '{}'
    )
    """,
)


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    return {r[0] for r in rows}


class ForbiddenSchemaError(RuntimeError):
    """Raised when a migration would leave (or already finds) a forbidden
    raw-history table in control.db. Distinct from generic RuntimeError so
    callers/tests can distinguish "invariant violation" from other failures.
    """


def _assert_no_forbidden_tables(conn: sqlite3.Connection) -> None:
    """Inspect the actual ``sqlite_master`` schema (source of truth — never
    the migration SQL text) for any table whose name matches a forbidden
    raw-history fragment. Called both before and after a migration body runs
    inside the same open transaction; see ``_run_guarded_transaction``.
    """
    for name in _table_names(conn):
        lowered = name.lower()
        for fragment in _FORBIDDEN_TABLE_NAME_FRAGMENTS:
            if fragment in lowered:
                raise ForbiddenSchemaError(
                    f"control.db schema guard: table {name!r} looks like raw "
                    "query-history storage, which must never live in "
                    "control.db (see docs/v2/storage-audit.md)"
                )


@contextmanager
def connect(path: str | Path) -> Iterator[sqlite3.Connection]:
    """Open (creating if needed) a control.db at ``path`` with WAL + busy_timeout."""
    conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
    finally:
        conn.close()


def _run_guarded_transaction(
    conn: sqlite3.Connection,
    cur: sqlite3.Cursor,
    body: "Callable[[sqlite3.Cursor], None]",
) -> None:
    """Run ``body`` inside BEGIN/COMMIT with the forbidden-table invariant
    checked both BEFORE any statement executes and AFTER, all inside the
    same still-uncommitted transaction. Any invariant violation — pre-
    existing or introduced by ``body`` — rolls back the entire transaction
    before the exception propagates, so COMMIT is never reached with a
    forbidden table present and no earlier mutation from this call survives.

    This is the single choke point both ``initialize`` and
    ``apply_migration_in_transaction`` go through — the guard cannot be
    bypassed by calling one entry point instead of the other, and it cannot
    be bypassed by migration statement ordering (CREATE, ALTER/RENAME, or
    any other DDL/DML) because the check re-reads ``sqlite_master`` from
    scratch after ``body`` runs, rather than pattern-matching the SQL text.
    """
    cur.execute("BEGIN")
    try:
        # Pre-check: refuse to build on top of an already-invalid schema
        # rather than silently letting a migration "fix" it as a side
        # effect. If control.db somehow already has a forbidden table, no
        # further migration should be allowed to proceed until that's
        # resolved out-of-band.
        _assert_no_forbidden_tables(conn)
        body(cur)
        # Post-check: whatever body() just did — CREATE TABLE, ALTER TABLE
        # ... RENAME TO, or anything else — must not have left a forbidden
        # table in the schema. This reads the actual post-execution
        # sqlite_master state, still inside the open transaction, so it
        # sees every effect of body() including renames.
        _assert_no_forbidden_tables(conn)
        cur.execute("COMMIT")
    except BaseException:
        cur.execute("ROLLBACK")
        raise


def initialize(path: str | Path) -> None:
    """Create the schema at ``path`` if not already present, then verify it."""

    def _body(cur: sqlite3.Cursor) -> None:
        for stmt in _SCHEMA_STATEMENTS:
            cur.execute(stmt)
        row = cur.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        if row[0] is None:
            cur.execute(
                "INSERT INTO schema_migrations(version, applied_at) "
                "VALUES (?, datetime('now'))",
                (CONTROL_SCHEMA_VERSION,),
            )

    with connect(path) as conn:
        with closing(conn.cursor()) as cur:
            _run_guarded_transaction(conn, cur, _body)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"control.db integrity_check failed: {integrity}")


def schema_version(path: str | Path) -> int | None:
    with connect(path) as conn:
        row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return row[0] if row else None


def apply_migration_in_transaction(
    path: str | Path, statements: list[str], new_version: int
) -> None:
    """Apply ``statements`` as one migration transaction.

    Behaves as: BEGIN -> validate current schema invariants -> execute
    ``statements`` -> validate resulting schema invariants -> bump schema
    version -> COMMIT. A failure at any point (a SQL error, or either
    invariant check) rolls back the entire transaction — no partial mutation,
    no forbidden table, no advanced schema version survives a failed call.
    """

    def _body(cur: sqlite3.Cursor) -> None:
        for stmt in statements:
            cur.execute(stmt)
        cur.execute(
            "INSERT INTO schema_migrations(version, applied_at) "
            "VALUES (?, datetime('now'))",
            (new_version,),
        )

    with connect(path) as conn:
        with closing(conn.cursor()) as cur:
            _run_guarded_transaction(conn, cur, _body)
