"""V2 control.db-backed policy storage (Workstream 3 continuation, §1).

Wires the in-memory policy model (``app/v2/policy_model.py``,
``app/v2/policy_compiler.py``, ``app/v2/network_match.py``,
``app/v2/schedule_policy.py``) to real, structured, relational control.db
tables — not one opaque JSON blob per scope. Every answer-affecting/
non-answer-affecting field from ``PolicyLayer`` is its own typed column in
``policy_layers``; networks, groups, schedules, upstream profiles, domain
routing rules, and service definitions each get their own table with real
foreign keys and uniqueness constraints.

This module only ever operates on a caller-supplied control.db path — same
rule as the rest of ``app/v2/``: never the live
``/var/lib/alderpointdns/control.db``, only disposable dev/test paths.

Migration is layered on top of ``app/v2/control_db.py``'s existing
guarded-transaction migration mechanism (``apply_migration_in_transaction``)
at schema version 2, so the forbidden-raw-history-table invariant Dex's
review locked in continues to be checked on every DDL change this module
makes, not just the original Workstream 1 schema.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.v2 import control_db
from app.v2.network_match import InvalidNetworkError, NetworkScope, compile_network_table
from app.v2.policy_model import ALL_FIELDS, GroupPolicy, PolicyLayer, order_groups
from app.v2.schedule_policy import Schedule, ScheduleWindow, make_window

POLICY_STORE_SCHEMA_VERSION = 2

_MIGRATION_V2: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS policy_layers (
        id INTEGER PRIMARY KEY,
        scope TEXT NOT NULL CHECK(scope IN ('global','network','group','client','schedule')),
        scope_ref TEXT NOT NULL,
        filtering_profile_id TEXT,
        safesearch_mode TEXT,
        parental_policy_id TEXT,
        security_policy_id TEXT,
        service_blocking_ruleset_id TEXT,
        blocking_response_mode TEXT,
        upstream_profile_id TEXT,
        fallback_strategy TEXT,
        ecs_mode TEXT,
        domain_routing_ruleset_id TEXT,
        query_log_enabled INTEGER,
        statistics_enabled INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(scope, scope_ref)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS policy_networks (
        id INTEGER PRIMARY KEY,
        network_id TEXT NOT NULL UNIQUE,
        cidr TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS policy_groups (
        id INTEGER PRIMARY KEY,
        group_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL UNIQUE,
        priority INTEGER NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS policy_client_group_membership (
        client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
        policy_group_row_id INTEGER NOT NULL REFERENCES policy_groups(id) ON DELETE CASCADE,
        PRIMARY KEY(client_id, policy_group_row_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS policy_schedules (
        id INTEGER PRIMARY KEY,
        schedule_id TEXT NOT NULL UNIQUE,
        timezone TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS policy_schedule_windows (
        id INTEGER PRIMARY KEY,
        schedule_row_id INTEGER NOT NULL REFERENCES policy_schedules(id) ON DELETE CASCADE,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        weekdays TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS upstream_profiles (
        id INTEGER PRIMARY KEY,
        upstream_profile_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        transport TEXT NOT NULL CHECK(transport IN ('plain','dot','doh')),
        strategy TEXT NOT NULL DEFAULT 'ordered'
            CHECK(strategy IN ('ordered','failover','load_balanced','parallel_first_success')),
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS upstream_endpoints (
        id INTEGER PRIMARY KEY,
        upstream_profile_row_id INTEGER NOT NULL REFERENCES upstream_profiles(id) ON DELETE CASCADE,
        address TEXT NOT NULL,
        tls_hostname TEXT,
        priority INTEGER NOT NULL DEFAULT 0,
        weight INTEGER NOT NULL DEFAULT 1,
        secret_ref TEXT,
        doh_path TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS domain_routing_rules (
        id INTEGER PRIMARY KEY,
        ruleset_id TEXT NOT NULL,
        match_kind TEXT NOT NULL CHECK(match_kind IN ('exact','suffix')),
        domain TEXT NOT NULL,
        upstream_profile_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(ruleset_id, match_kind, domain)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS service_definitions (
        id INTEGER PRIMARY KEY,
        service_id TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS service_domains (
        id INTEGER PRIMARY KEY,
        service_row_id INTEGER NOT NULL REFERENCES service_definitions(id) ON DELETE CASCADE,
        match_kind TEXT NOT NULL CHECK(match_kind IN ('exact','suffix')),
        domain TEXT NOT NULL,
        UNIQUE(service_row_id, match_kind, domain)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS service_blocking_rulesets (
        id INTEGER PRIMARY KEY,
        ruleset_id TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS service_blocking_ruleset_members (
        ruleset_row_id INTEGER NOT NULL REFERENCES service_blocking_rulesets(id) ON DELETE CASCADE,
        service_row_id INTEGER NOT NULL REFERENCES service_definitions(id) ON DELETE CASCADE,
        PRIMARY KEY(ruleset_row_id, service_row_id)
    )
    """,
]


class PolicyStoreError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table_exists(conn, name: str) -> bool:
    return (
        conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
        ).fetchone()
        is not None
    )


def ensure_schema(path: str | Path) -> None:
    """Idempotent: safe to call every process startup. Gates on actual
    table existence (via ``sqlite_master``), not solely on the shared
    ``schema_migrations`` version counter -- other modules
    (``app/v2/notification_store.py``) apply their own migrations against
    the same control.db using that same counter, so "current version >= N"
    does not by itself prove *this* module's tables exist if a caller only
    ever invoked the other module's ``ensure_schema``. Checking real table
    existence makes this correct regardless of call order.
    """
    control_db.initialize(path)
    with control_db.connect(path) as conn:
        already_present = _table_exists(conn, "policy_layers")
    if not already_present:
        control_db.apply_migration_in_transaction(path, _MIGRATION_V2, POLICY_STORE_SCHEMA_VERSION)


# --------------------------------------------------------------------------
# Policy layers (global/network/group/client/schedule)
# --------------------------------------------------------------------------


def save_policy_layer(conn: sqlite3.Connection, scope: str, scope_ref: str, layer: PolicyLayer) -> None:
    if scope not in ("global", "network", "group", "client", "schedule"):
        raise PolicyStoreError(f"invalid scope: {scope!r}")
    values = {f: getattr(layer, f) for f in ALL_FIELDS}
    # sqlite3 has no native bool type; store 0/1/NULL explicitly so NULL
    # (unset/inherit) is never confused with False.
    for bool_field in ("query_log_enabled", "statistics_enabled"):
        if values[bool_field] is not None:
            values[bool_field] = int(values[bool_field])
    now = _now()
    cols = ", ".join(ALL_FIELDS)
    placeholders = ", ".join("?" for _ in ALL_FIELDS)
    conn.execute(
        f"""
        INSERT INTO policy_layers (scope, scope_ref, {cols}, created_at, updated_at)
        VALUES (?, ?, {placeholders}, ?, ?)
        ON CONFLICT(scope, scope_ref) DO UPDATE SET
            {", ".join(f"{f} = excluded.{f}" for f in ALL_FIELDS)},
            updated_at = excluded.updated_at
        """,
        (scope, scope_ref, *[values[f] for f in ALL_FIELDS], now, now),
    )


def load_policy_layer(conn: sqlite3.Connection, scope: str, scope_ref: str) -> PolicyLayer:
    row = conn.execute(
        f"SELECT {', '.join(ALL_FIELDS)} FROM policy_layers WHERE scope = ? AND scope_ref = ?",
        (scope, scope_ref),
    ).fetchone()
    if row is None:
        return PolicyLayer()
    kwargs = dict(zip(ALL_FIELDS, row))
    for bool_field in ("query_log_enabled", "statistics_enabled"):
        if kwargs[bool_field] is not None:
            kwargs[bool_field] = bool(kwargs[bool_field])
    return PolicyLayer(**kwargs)


# --------------------------------------------------------------------------
# Networks
# --------------------------------------------------------------------------


def create_network(conn: sqlite3.Connection, network_id: str, cidr: str) -> None:
    # Validate through the real NetworkScope constructor first so an
    # invalid CIDR never reaches the database at all.
    NetworkScope.create(network_id, cidr, policy_ref="unused")
    try:
        conn.execute(
            "INSERT INTO policy_networks (network_id, cidr, created_at) VALUES (?, ?, ?)",
            (network_id, cidr, _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise PolicyStoreError(f"duplicate network_id or cidr: {exc}") from exc


def load_network_table(conn: sqlite3.Connection):
    rows = conn.execute("SELECT network_id, cidr FROM policy_networks").fetchall()
    scopes = [NetworkScope.create(nid, cidr, policy_ref=nid) for nid, cidr in rows]
    return compile_network_table(scopes)


# --------------------------------------------------------------------------
# Groups
# --------------------------------------------------------------------------


def create_group(conn: sqlite3.Connection, group_id: str, name: str, priority: int) -> None:
    try:
        conn.execute(
            "INSERT INTO policy_groups (group_id, name, priority, created_at) VALUES (?, ?, ?, ?)",
            (group_id, name, priority, _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise PolicyStoreError(f"duplicate group_id or name: {exc}") from exc


def add_client_to_group(conn: sqlite3.Connection, client_id: int, group_id: str) -> None:
    row = conn.execute("SELECT id FROM policy_groups WHERE group_id = ?", (group_id,)).fetchone()
    if row is None:
        raise PolicyStoreError(f"unknown group_id: {group_id!r}")
    conn.execute(
        "INSERT OR IGNORE INTO policy_client_group_membership (client_id, policy_group_row_id) "
        "VALUES (?, ?)",
        (client_id, row[0]),
    )


def load_groups_for_client(conn: sqlite3.Connection, client_id: int) -> list[GroupPolicy]:
    rows = conn.execute(
        """
        SELECT g.group_id, g.name, g.priority
        FROM policy_groups g
        JOIN policy_client_group_membership m ON m.policy_group_row_id = g.id
        WHERE m.client_id = ?
        """,
        (client_id,),
    ).fetchall()
    groups = []
    for group_id, name, priority in rows:
        layer = load_policy_layer(conn, "group", group_id)
        groups.append(GroupPolicy(group_id=group_id, name=name, priority=priority, layer=layer))
    return list(order_groups(groups))


# --------------------------------------------------------------------------
# Schedules
# --------------------------------------------------------------------------


def create_schedule(
    conn: sqlite3.Connection, schedule_id: str, tz_name: str, windows: list[ScheduleWindow]
) -> None:
    try:
        cur = conn.execute(
            "INSERT INTO policy_schedules (schedule_id, timezone, created_at) VALUES (?, ?, ?)",
            (schedule_id, tz_name, _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise PolicyStoreError(f"duplicate schedule_id: {exc}") from exc
    row_id = cur.lastrowid
    for w in windows:
        conn.execute(
            "INSERT INTO policy_schedule_windows (schedule_row_id, start_time, end_time, weekdays) "
            "VALUES (?, ?, ?, ?)",
            (
                row_id,
                w.start.strftime("%H:%M"),
                w.end.strftime("%H:%M"),
                ",".join(str(d) for d in sorted(w.weekdays)),
            ),
        )


def load_schedule(conn: sqlite3.Connection, schedule_id: str) -> Optional[Schedule]:
    row = conn.execute(
        "SELECT id, timezone FROM policy_schedules WHERE schedule_id = ?", (schedule_id,)
    ).fetchone()
    if row is None:
        return None
    row_id, tz_name = row
    window_rows = conn.execute(
        "SELECT start_time, end_time, weekdays FROM policy_schedule_windows WHERE schedule_row_id = ?",
        (row_id,),
    ).fetchall()
    _WD = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    windows = []
    for start, end, weekdays_csv in window_rows:
        wd_names = [_WD[int(i)] for i in weekdays_csv.split(",")]
        windows.append(make_window(start, end, wd_names))
    return Schedule(schedule_id=schedule_id, timezone=tz_name, windows=tuple(windows))


# --------------------------------------------------------------------------
# Upstream profiles
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class UpstreamEndpointRecord:
    address: str
    tls_hostname: Optional[str]
    priority: int
    weight: int
    secret_ref: Optional[str]
    doh_path: Optional[str] = None


@dataclass(frozen=True)
class UpstreamProfileRecord:
    upstream_profile_id: str
    name: str
    transport: str
    strategy: str
    endpoints: tuple[UpstreamEndpointRecord, ...]


def create_upstream_profile(
    conn: sqlite3.Connection,
    upstream_profile_id: str,
    name: str,
    transport: str,
    endpoints: list[UpstreamEndpointRecord],
    strategy: str = "ordered",
) -> None:
    if transport not in ("plain", "dot", "doh"):
        raise PolicyStoreError(f"invalid transport: {transport!r}")
    if not endpoints:
        raise PolicyStoreError("upstream profile requires at least one endpoint")
    for ep in endpoints:
        if ep.secret_ref is not None and not ep.secret_ref:
            raise PolicyStoreError("secret_ref must not be an empty string")
        if transport == "doh":
            # DoH backend certificate validation requires a real TLS
            # hostname (SNI + subjectName cert check) -- an encrypted-
            # transport profile with no way to validate the peer
            # certificate is not meaningfully "encrypted upstream intent"
            # and must be rejected at profile-creation time, not silently
            # accepted and downgraded later at config-generation time.
            if not ep.tls_hostname:
                raise PolicyStoreError(
                    f"DoH endpoint {ep.address!r} requires tls_hostname for certificate "
                    "validation -- refusing to create a DoH profile with no way to verify "
                    "the peer certificate"
                )
            path = ep.doh_path or "/dns-query"
            if not path.startswith("/") or "\n" in path or "\r" in path or " " in path:
                raise PolicyStoreError(f"invalid doh_path: {path!r}")
    try:
        cur = conn.execute(
            "INSERT INTO upstream_profiles (upstream_profile_id, name, transport, strategy, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (upstream_profile_id, name, transport, strategy, _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise PolicyStoreError(f"duplicate upstream_profile_id: {exc}") from exc
    row_id = cur.lastrowid
    for ep in endpoints:
        doh_path = ep.doh_path if transport == "doh" else None
        if doh_path is None and transport == "doh":
            doh_path = "/dns-query"
        conn.execute(
            "INSERT INTO upstream_endpoints "
            "(upstream_profile_row_id, address, tls_hostname, priority, weight, secret_ref, doh_path) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (row_id, ep.address, ep.tls_hostname, ep.priority, ep.weight, ep.secret_ref, doh_path),
        )


def load_upstream_profile(
    conn: sqlite3.Connection, upstream_profile_id: str
) -> Optional[UpstreamProfileRecord]:
    row = conn.execute(
        "SELECT id, name, transport, strategy FROM upstream_profiles WHERE upstream_profile_id = ?",
        (upstream_profile_id,),
    ).fetchone()
    if row is None:
        return None
    row_id, name, transport, strategy = row
    ep_rows = conn.execute(
        "SELECT address, tls_hostname, priority, weight, secret_ref, doh_path FROM upstream_endpoints "
        "WHERE upstream_profile_row_id = ? ORDER BY priority ASC, address ASC",
        (row_id,),
    ).fetchall()
    endpoints = tuple(UpstreamEndpointRecord(*r) for r in ep_rows)
    return UpstreamProfileRecord(upstream_profile_id, name, transport, strategy, endpoints)


# --------------------------------------------------------------------------
# Domain-specific upstream routing
# --------------------------------------------------------------------------


def add_domain_routing_rule(
    conn: sqlite3.Connection,
    ruleset_id: str,
    match_kind: str,
    domain: str,
    upstream_profile_id: str,
) -> None:
    if match_kind not in ("exact", "suffix"):
        raise PolicyStoreError(f"invalid match_kind: {match_kind!r}")
    domain = domain.strip(".").lower()
    if not domain:
        raise PolicyStoreError("domain must not be empty")
    try:
        conn.execute(
            "INSERT INTO domain_routing_rules (ruleset_id, match_kind, domain, upstream_profile_id, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (ruleset_id, match_kind, domain, upstream_profile_id, _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise PolicyStoreError(f"duplicate routing rule: {exc}") from exc


def resolve_domain_route(
    conn: sqlite3.Connection, ruleset_id: str, qname: str
) -> Optional[str]:
    """Most-specific-match precedence: exact match wins outright; among
    suffix matches, the longest (most-specific) label match wins. No
    per-query DB call is implied by this function's existence — callers
    compile a ruleset into an in-memory structure at policy-compile time in
    the real runtime; this is the control.db-backed source of truth that
    feeds that compile step.
    """
    qname = qname.strip(".").lower()
    rows = conn.execute(
        "SELECT match_kind, domain, upstream_profile_id FROM domain_routing_rules WHERE ruleset_id = ?",
        (ruleset_id,),
    ).fetchall()
    for match_kind, domain, profile_id in rows:
        if match_kind == "exact" and qname == domain:
            return profile_id
    best_len = -1
    best_profile = None
    for match_kind, domain, profile_id in rows:
        if match_kind == "suffix" and (qname == domain or qname.endswith("." + domain)):
            if len(domain) > best_len:
                best_len = len(domain)
                best_profile = profile_id
    return best_profile


# --------------------------------------------------------------------------
# Service definitions / blocking rulesets
# --------------------------------------------------------------------------


def create_service(
    conn: sqlite3.Connection,
    service_id: str,
    display_name: str,
    domains: list[tuple[str, str]],
    category: str = "",
) -> None:
    """``domains`` is a list of (match_kind, domain) tuples."""
    try:
        cur = conn.execute(
            "INSERT INTO service_definitions (service_id, display_name, category, created_at) "
            "VALUES (?, ?, ?, ?)",
            (service_id, display_name, category, _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise PolicyStoreError(f"duplicate service_id: {exc}") from exc
    row_id = cur.lastrowid
    for match_kind, domain in domains:
        if match_kind not in ("exact", "suffix"):
            raise PolicyStoreError(f"invalid match_kind: {match_kind!r}")
        conn.execute(
            "INSERT INTO service_domains (service_row_id, match_kind, domain) VALUES (?, ?, ?)",
            (row_id, match_kind, domain.strip(".").lower()),
        )


def create_service_ruleset(
    conn: sqlite3.Connection, ruleset_id: str, service_ids: list[str]
) -> None:
    try:
        cur = conn.execute(
            "INSERT INTO service_blocking_rulesets (ruleset_id, created_at) VALUES (?, ?)",
            (ruleset_id, _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise PolicyStoreError(f"duplicate ruleset_id: {exc}") from exc
    ruleset_row_id = cur.lastrowid
    for sid in service_ids:
        row = conn.execute(
            "SELECT id FROM service_definitions WHERE service_id = ?", (sid,)
        ).fetchone()
        if row is None:
            raise PolicyStoreError(f"unknown service_id: {sid!r}")
        conn.execute(
            "INSERT INTO service_blocking_ruleset_members (ruleset_row_id, service_row_id) VALUES (?, ?)",
            (ruleset_row_id, row[0]),
        )


def is_domain_service_blocked(conn: sqlite3.Connection, ruleset_id: str, qname: str) -> Optional[str]:
    """Returns the blocking service_id if ``qname`` matches any service in
    the ruleset, else None. Exact matches and suffix matches are both
    checked; the specific service_id returned is for diagnostics (§47
    "block reason").
    """
    qname = qname.strip(".").lower()
    rows = conn.execute(
        """
        SELECT sd.service_id, sdom.match_kind, sdom.domain
        FROM service_blocking_ruleset_members m
        JOIN service_definitions sd ON sd.id = m.service_row_id
        JOIN service_domains sdom ON sdom.service_row_id = sd.id
        JOIN service_blocking_rulesets r ON r.id = m.ruleset_row_id
        WHERE r.ruleset_id = ?
        """,
        (ruleset_id,),
    ).fetchall()
    for service_id, match_kind, domain in rows:
        if match_kind == "exact" and qname == domain:
            return service_id
        if match_kind == "suffix" and (qname == domain or qname.endswith("." + domain)):
            return service_id
    return None
