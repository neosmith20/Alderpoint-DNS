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
at schema version 2, so the forbidden-raw-history-table invariant continues
to be checked on every DDL change this module makes, not just the original
Workstream 1 schema.
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
        custom_ipv4 TEXT,
        custom_ipv6 TEXT,
        upstream_profile_id TEXT,
        fallback_strategy TEXT,
        fallback_upstream_profile_id TEXT,
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
    _ensure_policy_layers_beta_rescue_columns(path)
    _ensure_dns_transport_settings_table(path)
    _ensure_dnscrypt_settings_table(path)


def _ensure_policy_layers_beta_rescue_columns(path: str | Path) -> None:
    """Incremental migration (real defect closed, beta-rescue pass):
    custom_ip blocking response mode had no columns to store its address
    in at all. Runs unconditionally on every ensure_schema() call, like
    _ensure_dns_transport_settings_table below, so it reaches an already-
    migrated install upgrading from a prior RC, not only a fresh one.
    """
    with control_db.connect(path) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(policy_layers)").fetchall()}
        if "custom_ipv4" not in cols:
            conn.execute("ALTER TABLE policy_layers ADD COLUMN custom_ipv4 TEXT")
        if "custom_ipv6" not in cols:
            conn.execute("ALTER TABLE policy_layers ADD COLUMN custom_ipv6 TEXT")
        if "fallback_upstream_profile_id" not in cols:
            conn.execute("ALTER TABLE policy_layers ADD COLUMN fallback_upstream_profile_id TEXT")
        conn.commit()


def _ensure_dns_transport_settings_table(path: str | Path) -> None:
    """Runs unconditionally on every ``ensure_schema`` call (unlike
    ``_MIGRATION_V2`` above, which is gated on ``policy_layers`` not yet
    existing and so never runs again for a pre-existing install) --
    ``CREATE TABLE IF NOT EXISTS`` is naturally idempotent and this needs
    to reach existing installs too, not only fresh ones, matching the
    incremental-migration pattern app/v2/replication_v2.py's
    ``ensure_schema`` already established for the same reason.

    Real defect found this continuation (docs/v2/
    encrypted-transport-parity-gap.md): DoH/DoT/DoQ/DoH3/DNSCrypt were
    entirely absent from V2's real config generation. DoT is the first
    one implemented here -- it needs no new key material (reuses the
    appliance's existing management TLS cert, same as V1's real
    ``packaging/dnsdist.conf`` does) and no HTTP/QUIC protocol surface,
    making it the lowest-risk of the five to add safely. A single-row
    singleton table (matching the global policy layer's own
    ``scope_ref='singleton'`` convention) rather than folding into
    ``policy_layers``: a listening port is an appliance-wide concept,
    not a per-client/per-network answer-affecting policy dimension the
    rest of that table's columns are.
    """
    with control_db.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_transport_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                dot_enabled INTEGER NOT NULL DEFAULT 0,
                dot_port INTEGER NOT NULL DEFAULT 853,
                updated_at TEXT NOT NULL
            )
            """
        )
        # Incremental columns added after the table's first release
        # (DoH support) -- ALTER TABLE ADD COLUMN, not a CREATE TABLE
        # change, since CREATE TABLE IF NOT EXISTS is a no-op against a
        # table an earlier package version already created (same
        # incremental-migration need app/v2/replication_v2.py's
        # ensure_schema documents for the exact same reason).
        cols = {row[1] for row in conn.execute("PRAGMA table_info(dns_transport_settings)").fetchall()}
        if "doh_enabled" not in cols:
            conn.execute("ALTER TABLE dns_transport_settings ADD COLUMN doh_enabled INTEGER NOT NULL DEFAULT 0")
        if "doh_port" not in cols:
            conn.execute("ALTER TABLE dns_transport_settings ADD COLUMN doh_port INTEGER NOT NULL DEFAULT 443")
        if "doh_path" not in cols:
            conn.execute("ALTER TABLE dns_transport_settings ADD COLUMN doh_path TEXT NOT NULL DEFAULT '/dns-query'")
        if "doq_enabled" not in cols:
            conn.execute("ALTER TABLE dns_transport_settings ADD COLUMN doq_enabled INTEGER NOT NULL DEFAULT 0")
        if "doq_port" not in cols:
            conn.execute("ALTER TABLE dns_transport_settings ADD COLUMN doq_port INTEGER NOT NULL DEFAULT 853")
        # DoH3 (roadmap continuation: closes the last QUIC-dependent row
        # of the confirmed mandatory-parity gap alongside DoQ -- see
        # docs/v2/doh3-transport-implemented.md). Same incremental-
        # migration pattern as every prior protocol added to this table.
        if "doh3_enabled" not in cols:
            conn.execute("ALTER TABLE dns_transport_settings ADD COLUMN doh3_enabled INTEGER NOT NULL DEFAULT 0")
        if "doh3_port" not in cols:
            conn.execute("ALTER TABLE dns_transport_settings ADD COLUMN doh3_port INTEGER NOT NULL DEFAULT 443")
        conn.commit()


@dataclass
class DnsTransportSettings:
    dot_enabled: bool = False
    dot_port: int = 853
    doh_enabled: bool = False
    doh_port: int = 443
    doh_path: str = "/dns-query"
    doq_enabled: bool = False
    doq_port: int = 853
    doh3_enabled: bool = False
    doh3_port: int = 443


def load_dns_transport_settings(conn: sqlite3.Connection) -> DnsTransportSettings:
    row = conn.execute(
        "SELECT dot_enabled, dot_port, doh_enabled, doh_port, doh_path, doq_enabled, doq_port, "
        "doh3_enabled, doh3_port FROM dns_transport_settings WHERE id=1"
    ).fetchone()
    if row is None:
        return DnsTransportSettings()
    return DnsTransportSettings(
        dot_enabled=bool(row[0]), dot_port=row[1], doh_enabled=bool(row[2]), doh_port=row[3], doh_path=row[4],
        doq_enabled=bool(row[5]), doq_port=row[6], doh3_enabled=bool(row[7]), doh3_port=row[8],
    )


def save_dns_transport_settings(conn: sqlite3.Connection, settings: DnsTransportSettings) -> None:
    if not (1 <= settings.dot_port <= 65535):
        raise PolicyStoreError(f"invalid dot_port: {settings.dot_port!r}")
    if not (1 <= settings.doh_port <= 65535):
        raise PolicyStoreError(f"invalid doh_port: {settings.doh_port!r}")
    if not settings.doh_path.startswith("/"):
        raise PolicyStoreError(f"invalid doh_path: {settings.doh_path!r}")
    if not (1 <= settings.doq_port <= 65535):
        raise PolicyStoreError(f"invalid doq_port: {settings.doq_port!r}")
    if not (1 <= settings.doh3_port <= 65535):
        raise PolicyStoreError(f"invalid doh3_port: {settings.doh3_port!r}")
    conn.execute(
        """
        INSERT INTO dns_transport_settings
            (id, dot_enabled, dot_port, doh_enabled, doh_port, doh_path, doq_enabled, doq_port,
             doh3_enabled, doh3_port, updated_at)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            dot_enabled = excluded.dot_enabled,
            dot_port = excluded.dot_port,
            doh_enabled = excluded.doh_enabled,
            doh_port = excluded.doh_port,
            doh_path = excluded.doh_path,
            doq_enabled = excluded.doq_enabled,
            doq_port = excluded.doq_port,
            doh3_enabled = excluded.doh3_enabled,
            doh3_port = excluded.doh3_port,
            updated_at = excluded.updated_at
        """,
        (
            int(settings.dot_enabled), settings.dot_port,
            int(settings.doh_enabled), settings.doh_port, settings.doh_path,
            int(settings.doq_enabled), settings.doq_port,
            int(settings.doh3_enabled), settings.doh3_port,
            _now(),
        ),
    )


# --------------------------------------------------------------------------
# DNSCrypt (roadmap continuation: closes the last remaining row of the
# confirmed mandatory encrypted-transport parity gap -- see
# docs/v2/dnscrypt-transport-implemented.md)
# --------------------------------------------------------------------------

# A separate table from dns_transport_settings deliberately: DNSCrypt has
# no shared management-TLS-cert-reuse rationale the way DoT/DoH/DoQ/DoH3
# do (see DnscryptConfig's own docstring in dnsdist_policy_runtime.py) --
# its own provider-identity/resolver-certificate lifecycle needs distinct
# columns (secret references, cert bytes, serial, validity window) that
# don't fit the simple enabled/port shape the other four share.
#
# Frozen architecture (docs/v2/architecture-map.md "Notification secret
# architecture", the same invariant app/v2/secret_store.py's own module
# docstring documents and app/v2/replication_v2.py's
# REPLICATION_CA_KEY_SECRET_ID already follows for the CA signing key):
# control.db holds a secret REFERENCE only (provider_secret_id/
# resolver_secret_id) -- the real private key bytes live in the protected
# SecretStore, never here. provider_public_key_b64 and cert_b64 are NOT
# secrets (the public key is the fingerprint every client is meant to
# pin against; the certificate is broadcast in plaintext to any client
# that asks for it) -- stored directly as ordinary columns.
def _ensure_dnscrypt_settings_table(path: str | Path) -> None:
    with control_db.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dnscrypt_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                port INTEGER NOT NULL DEFAULT 5443,
                provider_name TEXT NOT NULL DEFAULT '2.dnscrypt-cert.alderpointdns-v2.local',
                provider_secret_id TEXT,
                provider_public_key_b64 TEXT,
                resolver_secret_id TEXT,
                cert_b64 TEXT,
                cert_serial INTEGER NOT NULL DEFAULT 0,
                cert_valid_from INTEGER,
                cert_valid_until INTEGER,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


@dataclass
class DnscryptSettings:
    enabled: bool = False
    port: int = 5443
    provider_name: str = "2.dnscrypt-cert.alderpointdns-v2.local"
    provider_secret_id: Optional[str] = None
    provider_public_key_b64: Optional[str] = None
    resolver_secret_id: Optional[str] = None
    cert_b64: Optional[str] = None
    cert_serial: int = 0
    cert_valid_from: Optional[int] = None
    cert_valid_until: Optional[int] = None

    @property
    def identity_provisioned(self) -> bool:
        """True once a provider identity AND a signed resolver
        certificate both exist -- the real precondition for emitting a
        live addDNSCryptBind, mirroring the cert_provisioned gate
        webapp.py already applies to DoT/DoH/DoQ/DoH3 (never emit a
        listener pointing at material that doesn't exist yet)."""
        return bool(self.provider_secret_id and self.resolver_secret_id and self.cert_b64)


def load_dnscrypt_settings(conn: sqlite3.Connection) -> DnscryptSettings:
    row = conn.execute(
        "SELECT enabled, port, provider_name, provider_secret_id, provider_public_key_b64, "
        "resolver_secret_id, cert_b64, cert_serial, cert_valid_from, cert_valid_until "
        "FROM dnscrypt_settings WHERE id=1"
    ).fetchone()
    if row is None:
        return DnscryptSettings()
    return DnscryptSettings(
        enabled=bool(row[0]), port=row[1], provider_name=row[2],
        provider_secret_id=row[3], provider_public_key_b64=row[4],
        resolver_secret_id=row[5], cert_b64=row[6], cert_serial=row[7],
        cert_valid_from=row[8], cert_valid_until=row[9],
    )


def save_dnscrypt_settings(conn: sqlite3.Connection, settings: DnscryptSettings) -> None:
    if not (1 <= settings.port <= 65535):
        raise PolicyStoreError(f"invalid dnscrypt port: {settings.port!r}")
    if not settings.provider_name.strip():
        raise PolicyStoreError("dnscrypt provider_name must not be empty")
    if settings.cert_serial < 0:
        raise PolicyStoreError(f"invalid cert_serial: {settings.cert_serial!r}")
    conn.execute(
        """
        INSERT INTO dnscrypt_settings
            (id, enabled, port, provider_name, provider_secret_id, provider_public_key_b64,
             resolver_secret_id, cert_b64, cert_serial, cert_valid_from, cert_valid_until, updated_at)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            enabled = excluded.enabled,
            port = excluded.port,
            provider_name = excluded.provider_name,
            provider_secret_id = excluded.provider_secret_id,
            provider_public_key_b64 = excluded.provider_public_key_b64,
            resolver_secret_id = excluded.resolver_secret_id,
            cert_b64 = excluded.cert_b64,
            cert_serial = excluded.cert_serial,
            cert_valid_from = excluded.cert_valid_from,
            cert_valid_until = excluded.cert_valid_until,
            updated_at = excluded.updated_at
        """,
        (
            int(settings.enabled), settings.port, settings.provider_name,
            settings.provider_secret_id, settings.provider_public_key_b64,
            settings.resolver_secret_id, settings.cert_b64, settings.cert_serial,
            settings.cert_valid_from, settings.cert_valid_until,
            _now(),
        ),
    )


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
    # Real defect closed (beta-rescue pass): "ordered" and "load_balanced"
    # previously compiled equivalently because nothing downstream ever
    # read `strategy` at all (see app/v2/runtime_compile.py's real fix).
    # "failover" is accepted as a synonym of "ordered" (both compile to
    # dnsdist's real order-respecting firstAvailable policy) rather than
    # forcing a rename of already-stored real profiles. "parallel_first_
    # success" is rejected here: genuine simultaneous multi-server fan-
    # out with first-response-wins is not a real dnsdist server-selection
    # policy and is not implemented -- per "wire every advertised control
    # into the real runtime or remove/disable controls that are genuinely
    # unsupported," it must not be selectable, not silently no-op.
    if strategy not in ("ordered", "failover", "load_balanced"):
        raise PolicyStoreError(
            f"unsupported upstream strategy: {strategy!r} (supported: ordered, failover, load_balanced)"
        )
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
    from app.v2.dns_name_validate import InvalidDnsNameError, validate_dns_name

    if match_kind not in ("exact", "suffix"):
        raise PolicyStoreError(f"invalid match_kind: {match_kind!r}")
    try:
        domain = validate_dns_name(domain)
    except InvalidDnsNameError as exc:
        raise PolicyStoreError(f"invalid domain: {exc}") from exc
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


def list_domain_routing_rules(
    conn: sqlite3.Connection, ruleset_id: str
) -> list[tuple[str, str, str]]:
    """All rules in one domain-routing ruleset, as (match_kind, domain,
    upstream_profile_id) -- the control.db-backed source the real runtime
    compiler (``app/v2/runtime_compile.py``) reads to materialize a
    policy's ``domain_routing_ruleset_id`` into real per-binding
    ``domain_routes``. Deterministically ordered (domain, match_kind) so
    repeated compiles of identical control.db state are byte-identical,
    matching every other list-shaped compiler input in this module.
    """
    rows = conn.execute(
        "SELECT match_kind, domain, upstream_profile_id FROM domain_routing_rules "
        "WHERE ruleset_id = ? ORDER BY domain ASC, match_kind ASC",
        (ruleset_id,),
    ).fetchall()
    return [(match_kind, domain, profile_id) for match_kind, domain, profile_id in rows]


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
    from app.v2.dns_name_validate import InvalidDnsNameError, validate_dns_name

    row_id = cur.lastrowid
    for match_kind, domain in domains:
        if match_kind not in ("exact", "suffix"):
            raise PolicyStoreError(f"invalid match_kind: {match_kind!r}")
        try:
            validated_domain = validate_dns_name(domain)
        except InvalidDnsNameError as exc:
            raise PolicyStoreError(f"invalid service domain: {exc}") from exc
        conn.execute(
            "INSERT INTO service_domains (service_row_id, match_kind, domain) VALUES (?, ?, ?)",
            (row_id, match_kind, validated_domain),
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


def service_ruleset_exists(conn: sqlite3.Connection, ruleset_id: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM service_blocking_rulesets WHERE ruleset_id = ?", (ruleset_id,)).fetchone())


def list_service_ruleset_member_service_ids(conn: sqlite3.Connection, ruleset_id: str) -> list[str]:
    """Member service_ids of ``ruleset_id`` in insertion order, or an empty
    list if the ruleset does not exist. Used to accumulate imports into a
    shared ruleset (append, never silently replace)."""
    return [
        row[0]
        for row in conn.execute(
            """
            SELECT sd.service_id FROM service_blocking_ruleset_members m
            JOIN service_definitions sd ON sd.id = m.service_row_id
            JOIN service_blocking_rulesets r ON r.id = m.ruleset_row_id
            WHERE r.ruleset_id = ?
            ORDER BY sd.id
            """,
            (ruleset_id,),
        ).fetchall()
    ]


def replace_service_ruleset(conn: sqlite3.Connection, ruleset_id: str, service_ids: list[str]) -> None:
    """Idempotent create-or-replace: deletes ``ruleset_id`` if it already
    exists (members only -- member services' own service_definitions rows
    are left alone) and recreates it with exactly ``service_ids``."""
    conn.execute(
        "DELETE FROM service_blocking_ruleset_members WHERE ruleset_row_id IN "
        "(SELECT id FROM service_blocking_rulesets WHERE ruleset_id = ?)",
        (ruleset_id,),
    )
    conn.execute("DELETE FROM service_blocking_rulesets WHERE ruleset_id = ?", (ruleset_id,))
    create_service_ruleset(conn, ruleset_id, service_ids)


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


# --------------------------------------------------------------------------
# Local DNS records (shared with app/v2/webapp.py's own lazily-created
# copy of this exact table -- CREATE TABLE IF NOT EXISTS with identical
# DDL, so it is safe for either module to create it first; see
# app/v2/runtime_compile.py for the reader that feeds it into the real
# compiled runtime, and app/v2/migration_convert.py for the migration
# writer).
# --------------------------------------------------------------------------


def ensure_local_dns_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS local_dns_records (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            record_type TEXT NOT NULL CHECK(record_type IN ('A','AAAA','CNAME','PTR')),
            value TEXT NOT NULL,
            ttl INTEGER NOT NULL DEFAULT 300,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(name, record_type, value)
        )
        """
    )


def load_local_dns_records(conn: sqlite3.Connection) -> list[tuple[str, str, str, int]]:
    """Returns (name, record_type, value, ttl) for every enabled record."""
    ensure_local_dns_schema(conn)
    return conn.execute(
        "SELECT name, record_type, value, ttl FROM local_dns_records WHERE enabled = 1"
    ).fetchall()


def upsert_local_dns_record(
    conn: sqlite3.Connection, name: str, record_type: str, value: str, ttl: int = 300,
    *, enabled: bool = True,
) -> None:
    ensure_local_dns_schema(conn)
    now = _now()
    conn.execute(
        """
        INSERT INTO local_dns_records (name, record_type, value, ttl, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name, record_type, value) DO UPDATE SET
            ttl = excluded.ttl, enabled = excluded.enabled, updated_at = excluded.updated_at
        """,
        (name, record_type, value, ttl, int(enabled), now, now),
    )


# --- import/migration jobs (staged preview -> apply, see
# app/v2/import_migration.py) ------------------------------------------------

def ensure_import_job_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS import_jobs (
            id INTEGER PRIMARY KEY,
            source_type TEXT NOT NULL,
            source_name TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'previewed',
            plan_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            applied_at TEXT
        )
        """
    )


def create_import_job(conn: sqlite3.Connection, source_type: str, source_name: str, plan_json: str) -> int:
    ensure_import_job_schema(conn)
    now = _now()
    cur = conn.execute(
        "INSERT INTO import_jobs (source_type, source_name, status, plan_json, created_at) VALUES (?, ?, 'previewed', ?, ?)",
        (source_type, source_name, plan_json, now),
    )
    return int(cur.lastrowid)


def get_import_job(conn: sqlite3.Connection, job_id: int) -> dict | None:
    ensure_import_job_schema(conn)
    row = conn.execute(
        "SELECT id, source_type, source_name, status, plan_json, result_json, created_at, applied_at "
        "FROM import_jobs WHERE id = ?",
        (job_id,),
    ).fetchone()
    if row is None:
        return None
    cols = ["id", "source_type", "source_name", "status", "plan_json", "result_json", "created_at", "applied_at"]
    return dict(zip(cols, row))


def list_import_jobs(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    ensure_import_job_schema(conn)
    rows = conn.execute(
        "SELECT id, source_type, source_name, status, plan_json, result_json, created_at, applied_at "
        "FROM import_jobs ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    cols = ["id", "source_type", "source_name", "status", "plan_json", "result_json", "created_at", "applied_at"]
    return [dict(zip(cols, row)) for row in rows]


def mark_import_job(conn: sqlite3.Connection, job_id: int, status: str, result_json: str, applied: bool = False) -> None:
    ensure_import_job_schema(conn)
    now = _now()
    if applied:
        conn.execute(
            "UPDATE import_jobs SET status = ?, result_json = ?, applied_at = ? WHERE id = ?",
            (status, result_json, now, job_id),
        )
    else:
        conn.execute(
            "UPDATE import_jobs SET status = ?, result_json = ? WHERE id = ?",
            (status, result_json, job_id),
        )


# --- software updates settings (beta-rescue priority 4) ---------------------

def ensure_update_settings_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS update_settings (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            private_feed_dir TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )


def load_update_settings(conn: sqlite3.Connection) -> dict:
    ensure_update_settings_schema(conn)
    row = conn.execute("SELECT private_feed_dir FROM update_settings WHERE id = 1").fetchone()
    return {"private_feed_dir": row[0] if row else None}


def save_update_settings(conn: sqlite3.Connection, private_feed_dir: str | None) -> None:
    ensure_update_settings_schema(conn)
    now = _now()
    conn.execute(
        """
        INSERT INTO update_settings (id, private_feed_dir, updated_at) VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET private_feed_dir = excluded.private_feed_dir, updated_at = excluded.updated_at
        """,
        (private_feed_dir, now),
    )


# --- subscribed blocklist feeds (beta-rescue priority 3B) --------------------
#
# Distinct from the one-time, import-derived block domains
# app/v2/import_migration.py already writes (those are a snapshot taken
# once, at import time). A subscription is a URL that gets re-fetched on
# a schedule; each subscription's own domains live in their own service
# (so a broken/removed subscription only ever touches its own domains),
# accumulated into a shared ruleset the same way import jobs already do.

def ensure_blocklist_subscription_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS blocklist_subscriptions (
            id INTEGER PRIMARY KEY,
            subscription_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_refresh_at TEXT,
            last_status TEXT NOT NULL DEFAULT 'never_refreshed',
            last_error TEXT NOT NULL DEFAULT '',
            rule_count INTEGER NOT NULL DEFAULT 0
        )
        """
    )


def create_blocklist_subscription(conn: sqlite3.Connection, subscription_id: str, name: str, url: str, category: str = "") -> None:
    ensure_blocklist_subscription_schema(conn)
    try:
        conn.execute(
            "INSERT INTO blocklist_subscriptions (subscription_id, name, url, category, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)",
            (subscription_id, name, url, category, _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise PolicyStoreError(f"duplicate subscription_id: {exc}") from exc


def list_blocklist_subscriptions(conn: sqlite3.Connection) -> list[dict]:
    ensure_blocklist_subscription_schema(conn)
    cols = ["id", "subscription_id", "name", "url", "category", "enabled", "created_at", "last_refresh_at", "last_status", "last_error", "rule_count"]
    rows = conn.execute(f"SELECT {', '.join(cols)} FROM blocklist_subscriptions ORDER BY subscription_id").fetchall()
    out = [dict(zip(cols, row)) for row in rows]
    for row in out:
        row["enabled"] = bool(row["enabled"])
    return out


def get_blocklist_subscription(conn: sqlite3.Connection, subscription_id: str) -> dict | None:
    ensure_blocklist_subscription_schema(conn)
    cols = ["id", "subscription_id", "name", "url", "category", "enabled", "created_at", "last_refresh_at", "last_status", "last_error", "rule_count"]
    row = conn.execute(f"SELECT {', '.join(cols)} FROM blocklist_subscriptions WHERE subscription_id = ?", (subscription_id,)).fetchone()
    if row is None:
        return None
    result = dict(zip(cols, row))
    result["enabled"] = bool(result["enabled"])
    return result


def set_blocklist_subscription_enabled(conn: sqlite3.Connection, subscription_id: str, enabled: bool) -> None:
    ensure_blocklist_subscription_schema(conn)
    conn.execute("UPDATE blocklist_subscriptions SET enabled = ? WHERE subscription_id = ?", (int(enabled), subscription_id))


def delete_blocklist_subscription(conn: sqlite3.Connection, subscription_id: str) -> None:
    ensure_blocklist_subscription_schema(conn)
    conn.execute("DELETE FROM blocklist_subscriptions WHERE subscription_id = ?", (subscription_id,))


def record_blocklist_refresh_result(
    conn: sqlite3.Connection, subscription_id: str, status: str, error: str = "", rule_count: int | None = None,
) -> None:
    ensure_blocklist_subscription_schema(conn)
    if rule_count is None:
        conn.execute(
            "UPDATE blocklist_subscriptions SET last_refresh_at = ?, last_status = ?, last_error = ? WHERE subscription_id = ?",
            (_now(), status, error, subscription_id),
        )
    else:
        conn.execute(
            "UPDATE blocklist_subscriptions SET last_refresh_at = ?, last_status = ?, last_error = ?, rule_count = ? WHERE subscription_id = ?",
            (_now(), status, error, rule_count, subscription_id),
        )
