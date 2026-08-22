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

import re
import time

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


# Derived, not hand-duplicated, from _SCHEMA_STATEMENTS above -- stays
# in sync automatically if a future table is added there.
_CORE_TABLE_NAMES: frozenset[str] = frozenset(
    re.findall(r"CREATE TABLE(?: IF NOT EXISTS)? (\w+)", "\n".join(_SCHEMA_STATEMENTS))
)


def _schema_already_current(conn: sqlite3.Connection) -> bool:
    """Cheap, read-only (no write lock ever taken) check: is every core
    table this module's own ``_SCHEMA_STATEMENTS`` creates already
    present, is ``schema_migrations`` already at
    ``CONTROL_SCHEMA_VERSION``, and does no forbidden table exist? Used
    by ``initialize()`` to skip its own write transaction + full
    integrity_check entirely once there is genuinely nothing to do --
    see that function's own docstring for the real boot-time write-lock
    contention this exists to avoid. Still runs the real forbidden-table
    guard on every call, same as the full path -- a schema that is
    otherwise "current" but has since had a forbidden table added out of
    band (see TestMigrationForbiddenSchemaGuard) must still be rejected;
    this is a safety check, not a schema-creation step, so the fast path
    must not skip it."""
    names = _table_names(conn)
    if "schema_migrations" not in names:
        return False
    if not _CORE_TABLE_NAMES.issubset(names):
        return False
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    if row is None or row[0] != CONTROL_SCHEMA_VERSION:
        return False
    _assert_no_forbidden_tables(conn)
    return True


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


class ControlDbMissingError(RuntimeError):
    """Raised by ``connect(..., create_if_missing=False)`` when ``path``
    does not already exist. See that parameter's own docstring for why
    this distinction is real and load-bearing, not defensive
    boilerplate."""


@contextmanager
def connect(path: str | Path, *, create_if_missing: bool = True) -> Iterator[sqlite3.Connection]:
    """Open a control.db at ``path`` with WAL + busy_timeout, creating it
    if needed by default (``create_if_missing=True``, the historical
    behavior every existing caller already relies on -- bootstrap/
    ``init-state``, migration, replication cert issuance, and every
    ``ensure_schema()`` all genuinely need "create on first use").

    Real defect found and fixed live during this workstream's failure-
    domain/chaos pass (docs/v2/control-db-silent-recreation-fix.md):
    ``sqlite3.connect()`` (what this function wraps) transparently
    creates an empty file at ``path`` if none exists -- confirmed live,
    a real installed appliance's ``control.db`` moved aside (simulating
    it becoming unavailable -- a failed mount, accidental deletion,
    disk issue) was silently, invisibly replaced by a brand-new, empty,
    freshly-schema'd database the moment any web request touched it.
    Every API caller -- including the admin -- then saw "setup
    required" exactly as if this were a genuinely fresh, never-
    configured appliance, with **no signal whatsoever** that their real
    configuration (networks, policies, clients, DNSCrypt identity,
    everything) was sitting right there, merely temporarily
    unreachable. An admin who then completed setup again would create a
    second, disconnected identity while their real state remained
    invisible.

    ``create_if_missing=False`` closes this: ``app/v2/webapp.py``'s
    ``_db()`` (the one call site representing "ongoing request-serving
    against an already-initialized appliance", as opposed to the
    explicit, deliberate, root-only bootstrap/migration/replication
    call sites that legitimately need creation) now passes it, and gets
    a clear ``ControlDbMissingError`` instead of a silent, indistinguishable
    fresh-install illusion.
    """
    path = Path(path)
    if not create_if_missing and not path.exists():
        raise ControlDbMissingError(
            f"control.db not found at {path} -- refusing to silently create a new, empty "
            "database in its place (a real, previously-initialized appliance's control.db "
            "should never simply not exist; this looks like the file became unavailable, "
            "not a fresh install)"
        )
    conn = sqlite3.connect(str(path), timeout=10.0, isolation_level=None)
    try:
        # Real root cause found live during a real KVM clean-install/
        # reboot acceptance (see this module's own initialize() and
        # packaging/v2/alderpointdns-v2-state-init.service for the full
        # story): busy_timeout was PRAGMA'd *after* journal_mode, so the
        # journal_mode pragma itself -- re-asserted on every single
        # connect() call, even when the database is already in WAL mode
        # -- ran with SQLite's default busy handler (fail immediately,
        # no retry at all) rather than the 5s one this module clearly
        # intends every connection to have. Confirmed live and
        # reproduced in isolation: two real concurrent connections each
        # opening a real write transaction against the same file hit an
        # immediate (sub-millisecond, not "waited 5s then gave up")
        # "database is locked" on the *second* connection's own
        # journal_mode pragma -- busy_timeout, set one line later, never
        # got a chance to apply to it. Setting busy_timeout first makes
        # every subsequent statement on this connection, including this
        # same journal_mode re-assertion, honor the real 5s retry
        # window. Reproduced fixed in
        # tests/v2/test_control_db_concurrency.py.
        #
        # 10000ms (doubled from the original 5000ms), not an arbitrary
        # or "enormous" bump: with the pragma-ordering and
        # BEGIN IMMEDIATE fixes above, the two mechanisms that produced
        # an *immediate* lock failure regardless of timeout value are
        # gone -- what's left is genuine queueing depth under real
        # concurrent writers, which is exactly what busy_timeout exists
        # to bound. packaging/v2/alderpointdns-v2-state-init.service is
        # the real, primary fix for the boot-time case (schema is
        # established deterministically, serially, before any worker
        # starts, so workers essentially never race a truly-fresh
        # schema in production); this bound stays modest and finite
        # specifically for the remaining legitimate case -- multiple
        # independent ensure_schema() callers genuinely queuing behind
        # each other under real, if unusual, concurrent load (a worker
        # manually restarted while others are mid-write, or several
        # workers restarting together after a crash) -- rather than
        # papering over a design problem with an unbounded wait.
        conn.execute("PRAGMA busy_timeout = 10000")
        # Real residual defect found live via this module's own
        # concurrency regression suite even after the busy_timeout
        # reordering above: re-asserting journal_mode=WAL on a
        # connection that is opening for the very first time (its own
        # pager has not yet read the database header) can still return
        # "database is locked" immediately under real concurrent
        # contention, in a way that empirically does not always honor
        # busy_timeout for this specific pragma the way ordinary
        # reads/writes do on an already-open connection. A small,
        # explicitly bounded retry (3 attempts, brief fixed backoff --
        # not busy_timeout's own job, which already covers the normal
        # case; this covers the specific pragma that sometimes bypasses
        # it) closes this real, reproduced-live residual gap without
        # an unbounded/"enormous" wait. Reproduced fixed in
        # tests/v2/test_control_db_concurrency.py.
        for attempt in range(3):
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                break
            except sqlite3.OperationalError:
                if attempt == 2:
                    raise
                time.sleep(0.05 * (attempt + 1))
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

    Real root cause found live during a real KVM clean-install/reboot
    acceptance (the precise mechanism behind app/v2/control_db.py's own
    ``connect()`` pragma-ordering fix above, and the reason that fix
    alone was not sufficient): this used a plain ``BEGIN`` (deferred),
    and the pre-check read (``_assert_no_forbidden_tables``, a real
    ``SELECT`` against ``sqlite_master``) runs *before* ``body()``'s
    first write. A deferred transaction that reads before it writes has
    to upgrade its own lock from none/shared to reserved at the moment
    of that first write -- and reproduced directly, in isolation,
    against a real concurrently-held write lock from a real second OS
    process: that specific read-then-write lock *upgrade* can return
    "database is locked" immediately, without ever invoking the
    busy_timeout retry that a write-first transaction reliably gets.
    ``BEGIN IMMEDIATE`` acquires the reserved lock upfront, before any
    read runs, so this same real concurrent-holder scenario correctly
    waits out busy_timeout and succeeds instead. Reproduced fixed in
    tests/v2/test_control_db_concurrency.py.
    """
    cur.execute("BEGIN IMMEDIATE")
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
    """Create the schema at ``path`` if not already present, then verify it.

    Real defect found live during a real KVM clean-install/reboot
    acceptance: every ``ensure_schema()`` across every V2 module
    (policy_store, node_identity, observed_clients, notification_store,
    replication_v2 -- which itself cascades into three more) calls this
    function unconditionally as its first line, and this function used
    to unconditionally open a write transaction (BEGIN/COMMIT, even for
    a plain ``CREATE TABLE IF NOT EXISTS`` no-op) plus a full
    ``PRAGMA integrity_check`` (a real whole-database scan) on *every*
    single call, from *every* process, on *every* boot -- with no
    short-circuit even when the schema was already fully correct.
    Several V2 worker services all independently call their own
    ensure_schema() chain at their own startup, all racing to start at
    once at boot; SQLite allows only one writer at a time, so this
    turned an already-idempotent, nothing-to-do operation into real,
    repeated write-lock contention every single boot -- confirmed live:
    one worker's own ``ensure_schema()`` genuinely exceeded the
    already-generous 5s busy_timeout waiting for another, unrelated
    worker's own redundant, needless write transaction to finish.
    A cheap, non-blocking, read-only fast path (checking real table
    existence AND the schema version, not just the version counter
    alone, since a mid-migration crash could in principle leave the
    version bumped before every statement in a later _SCHEMA_STATEMENTS
    addition ran) skips the write transaction and integrity_check
    entirely once the schema is already known-correct, without weakening
    anything: the guarded transaction and integrity_check still run in
    full, exactly as before, the first time (or after any real change).
    """
    with connect(path) as conn:
        if _schema_already_current(conn):
            return

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

    Real defect found live during a real KVM clean-install/reboot
    acceptance: every ``ensure_schema()`` caller checks table presence
    in its own separate, unprotected read *before* deciding whether to
    call this function at all (by design -- that check has to happen
    outside this function's own transaction, since it's what decides
    whether to call it in the first place). Under real concurrency
    (several V2 workers each independently calling their own
    ensure_schema() chain at boot), two callers can both see "not
    present yet" in that race window and both call this function for
    the exact same migration; now that ``_run_guarded_transaction``
    uses ``BEGIN IMMEDIATE`` (see its own docstring) they no longer
    corrupt each other's writes, but they still serialize into two
    real, sequential attempts to apply the identical migration -- the
    second one's own unconditional INSERT then collided with the
    first's already-committed ``schema_migrations`` row
    (``UNIQUE constraint failed: schema_migrations.version``),
    reproduced live via tests/v2/test_control_db_concurrency.py.
    ``INSERT OR IGNORE`` makes the second, redundant application of an
    already-applied migration a real no-op instead of a real error --
    this is safe specifically because each module owns one hardcoded,
    distinct version integer (see e.g. observed_clients.py's own
    OBSERVED_SCHEMA_VERSION); the only way two INSERT attempts ever
    target the same version row is this exact same-migration race, not
    a genuine cross-module version collision (which would be a static,
    trivially-caught bug regardless of this fix).
    """

    def _body(cur: sqlite3.Cursor) -> None:
        for stmt in statements:
            cur.execute(stmt)
        cur.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) "
            "VALUES (?, datetime('now'))",
            (new_version,),
        )

    with connect(path) as conn:
        with closing(conn.cursor()) as cur:
            _run_guarded_transaction(conn, cur, _body)


def add_columns_if_missing(
    path: str | Path, table: str, column_defs: dict[str, str]
) -> None:
    """Atomically add whichever of ``column_defs`` (``{column_name: "TYPE
    ... DEFAULT ..."}``) are not already present on ``table`` -- the
    "runs unconditionally on every ensure_schema() call, reaches an
    already-migrated install too" incremental-column pattern several V2
    modules use for a table whose shape has grown release over release
    (e.g. app/v2/policy_store.py's own dns_transport_settings/
    policy_layers columns).

    Real defect found live during a real KVM clean-install/reboot
    acceptance: every existing caller of this pattern did its own
    ``PRAGMA table_info`` read, then conditionally ``ALTER TABLE ...
    ADD COLUMN``, as separate, individually-autocommitted statements
    (no transaction wrapping the read-then-write sequence at all) --
    under real concurrency, two callers could both read "column not
    present yet" in the race window and both attempt to add the exact
    same column, the second failing with a real
    ``sqlite3.OperationalError: duplicate column name``. This wraps the
    whole check-then-alter sequence in one ``BEGIN IMMEDIATE``
    transaction (same fix/rationale as ``_run_guarded_transaction``'s
    own docstring), so two concurrent callers correctly serialize
    instead of racing -- the second one, once it gets its turn,
    re-reads ``PRAGMA table_info`` fresh inside its own transaction and
    correctly finds the column already added by the first, adding
    nothing. Reproduced fixed in tests/v2/test_control_db_concurrency.py.
    """
    with connect(path) as conn:
        with closing(conn.cursor()) as cur:
            cur.execute("BEGIN IMMEDIATE")
            try:
                cols = {row[1] for row in cur.execute(f"PRAGMA table_info({table})").fetchall()}
                for name, decl in column_defs.items():
                    if name not in cols:
                        cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
