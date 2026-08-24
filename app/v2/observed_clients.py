"""Bounded observational client discovery for V2.

This is an aggregate observation store, not raw query history. One row per
source address is retained with caps/expiry; DNS callers enqueue tiny events
and a worker coalesces them asynchronously.
"""

from __future__ import annotations

import ipaddress
import queue
import re
import socket
import sqlite3
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.v2 import control_db

OBSERVED_SCHEMA_VERSION = 5
DEFAULT_MAX_ENTRIES = 4096
DEFAULT_EXPIRY_DAYS = 30
MAX_HOSTNAME_LEN = 253

_MIGRATION: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS observed_clients (
        source_ip TEXT PRIMARY KEY,
        address_family TEXT NOT NULL CHECK(address_family IN ('ipv4','ipv6')),
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        query_count INTEGER NOT NULL DEFAULT 0,
        hostname_candidate TEXT NOT NULL DEFAULT '',
        hostname_source TEXT NOT NULL DEFAULT '',
        managed_client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
        dismissed INTEGER NOT NULL DEFAULT 0,
        confidence TEXT NOT NULL DEFAULT 'dns-observed'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS observed_client_stats (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        dropped INTEGER NOT NULL DEFAULT 0,
        evicted INTEGER NOT NULL DEFAULT 0,
        coalesced INTEGER NOT NULL DEFAULT 0,
        last_error TEXT NOT NULL DEFAULT '',
        last_error_at REAL,
        last_success_at REAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS observed_client_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
]


@dataclass(frozen=True)
class Observation:
    source_ip: str
    hostname_candidate: str = ""
    hostname_source: str = ""
    ts: float = 0.0


class ObservationQueue:
    def __init__(self, capacity: int = 2048):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._q: queue.Queue[Observation] = queue.Queue(maxsize=capacity)
        self.dropped = 0
        self.coalesced = 0
        self._recent: dict[str, float] = {}
        self._lock = threading.Lock()

    def submit(self, source_ip: str, *, hostname_candidate: str = "", hostname_source: str = "") -> bool:
        obs = Observation(source_ip, hostname_candidate, hostname_source, time.time())
        with self._lock:
            last = self._recent.get(source_ip)
            if last is not None and obs.ts - last < 0.25:
                self.coalesced += 1
                return True
            self._recent[source_ip] = obs.ts
            if len(self._recent) > self.capacity * 2:
                cutoff = obs.ts - 60
                self._recent = {k: v for k, v in self._recent.items() if v >= cutoff}
        try:
            self._q.put_nowait(obs)
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def drain(self, max_items: int = 512) -> list[Observation]:
        items: list[Observation] = []
        for _ in range(max_items):
            try:
                items.append(self._q.get_nowait())
            except queue.Empty:
                break
        return items

    def __len__(self) -> int:
        return self._q.qsize()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def ensure_schema(path: str | Path) -> None:
    control_db.initialize(path)
    with control_db.connect(path) as conn:
        present = _table_exists(conn, "observed_clients")
    if not present:
        control_db.apply_migration_in_transaction(path, _MIGRATION, OBSERVED_SCHEMA_VERSION)
    # Additive columns for an already-migrated install (e.g. the preview
    # database created before last_error grew a timestamp) -- see
    # control_db.add_columns_if_missing()'s own docstring for why this is
    # its own atomic check-then-alter step rather than folded into
    # _MIGRATION, which only ever runs for a brand-new table.
    control_db.add_columns_if_missing(
        path,
        "observed_client_stats",
        {
            "last_error_at": "REAL",
            "last_success_at": "REAL",
        },
    )
    with control_db.connect(path) as conn:
        conn.execute("INSERT OR IGNORE INTO observed_client_stats(id) VALUES (1)")
        # Backfill: a pre-existing install may carry a last_error written
        # before last_error_at existed. stats() treats an untimestamped
        # error as unable to prove it's historical, so it would otherwise
        # report forever-current with no way to ever recover -- stamping
        # it "as of now" the first time this runs after upgrade means it
        # behaves like any other current error from here on (in
        # particular: a subsequent successful drain recovers it normally).
        conn.execute(
            "UPDATE observed_client_stats SET last_error_at=? "
            "WHERE id=1 AND last_error != '' AND last_error_at IS NULL",
            (time.time(),),
        )
        conn.execute(
            "INSERT OR IGNORE INTO observed_client_settings(key, value) VALUES ('max_entries', ?)",
            (str(DEFAULT_MAX_ENTRIES),),
        )
        conn.execute(
            "INSERT OR IGNORE INTO observed_client_settings(key, value) VALUES ('expiry_days', ?)",
            (str(DEFAULT_EXPIRY_DAYS),),
        )
        # Clean up any already-persisted rows from the now-fixed producer
        # bug (see _is_plausible_client_address's docstring) on every
        # schema-ensure call -- cheap (bounded by max_entries, a normal
        # DELETE loop over at most a few thousand rows) and idempotent,
        # so this runs on every worker start without needing a one-off
        # migration script.
        purge_implausible(conn)


def _now_iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts if ts else time.time(), tz=timezone.utc).isoformat()


def sanitize_hostname(value: str) -> str:
    value = value.strip().strip(".")
    value = "".join(ch for ch in value if ch.isprintable() and ch not in "\r\n\t<>\"'`;&|$")
    value = value[:MAX_HOSTNAME_LEN]
    if not value:
        return ""
    labels = []
    for label in value.split("."):
        label = re.sub(r"[^A-Za-z0-9-]", "-", label).strip("-")[:63]
        if label:
            labels.append(label.lower())
    return ".".join(labels)[:MAX_HOSTNAME_LEN]


# Real defect fixed here (owner-reported live: the owner's own PC showed
# as "192.168.32.0" -- a network address, not a host address -- and an
# unexplained "10.89.0.0" also appeared as a client). Root cause traced
# end to end: the only producer of observed_clients rows was
# dns-observer's TeeAction+ECS ingress (see
# scripts/v2/alderpointdns_v2_ctl.py's _parse_ecs_source_ip), which is
# architecturally incapable of exact precision -- it decodes whatever
# EDNS Client Subnet dnsdist embedded, and dnsdist's ECS source-prefix is
# a single global setting shared with real upstream-forwarded ECS
# (app/v2/ecs_policy.py, deliberately never full-length for privacy), so
# every observation from that path was truncated to whatever prefix
# length happened to be configured (192.168.32.0 = a /24-truncated real
# client address). When ECS was entirely absent, it fell back to the raw
# UDP peer address of TeeAction's own re-originated packet -- which is
# dnsdist's OWN local socket address, not the client's (10.89.0.0, this
# preview's Podman bridge network). Both symptoms are the same
# mechanism. The real fix (this pass) stops trusting that path for
# identity at all and instead derives observations from
# analytics-protobuf-receiver's already-real, already-verified,
# never-ECS-truncated dnsdist protobuf "from" field (see
# app/v2/dnsdist_protobuf.py's _client_ip -- the exact same field Query
# Log's client column already uses correctly). This filter is the
# second, independent layer: even a correctly-sourced observation must
# still look like a plausible single host, never a network/broadcast
# address, loopback, link-local, multicast, or unspecified address --
# defense in depth against any future producer bug, not a rewrite of the
# same broken assumption. IPv4 addresses whose last octet is 0 are
# rejected as well: within any conventionally-sized subnet (the
# overwhelming common case for an operator's own LAN) that is always the
# network's own address, never a real assignable host, so trusting it
# would materialize exactly the class of bug this fix exists to close.
_LOCAL_GATEWAY_ADDRESS_CACHE: "list[str | None]" = []  # single-element memo; None means "checked, none found"


def _local_gateway_address() -> Optional[str]:
    """Best-effort: this host/container's own default-route gateway
    address, e.g. a Podman bridge network's gateway (confirmed live:
    172.16.43.100's own owner-preview container sees exactly this
    address, 10.89.0.1, for host-originated traffic reaching it through
    Podman's port-forwarding NAT -- indistinguishable from a real client
    by address shape alone, unlike the network-address heuristic above).
    Reads Linux's /proc/net/route (present in every real deployment
    target -- Debian under BIND/dnsdist) directly rather than depending
    on an external tool; any failure (non-Linux, no default route,
    permission) is swallowed and simply disables this specific check,
    never raises into a caller that's just trying to record a DNS
    observation.
    """
    if _LOCAL_GATEWAY_ADDRESS_CACHE:
        return _LOCAL_GATEWAY_ADDRESS_CACHE[0]
    address = None
    try:
        with open("/proc/net/route", encoding="ascii") as fh:
            next(fh)  # header line
            for line in fh:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == "00000000":  # destination 0.0.0.0 == default route
                    address = socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
                    break
    except (OSError, StopIteration, ValueError):
        address = None
    _LOCAL_GATEWAY_ADDRESS_CACHE.append(address)
    return address


def _is_plausible_client_address(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        return False
    if ip.version == 4 and int(ip) & 0xFF == 0:
        return False
    if str(ip) == _local_gateway_address():
        return False
    return True


def purge_implausible(conn: sqlite3.Connection) -> int:
    """Removes any already-persisted observed_clients row that fails
    ``_is_plausible_client_address`` -- cleans up rows a past run of the
    now-fixed producer bug above already wrote, so they stop resurfacing
    on their own. Never touches a row already promoted to a managed
    client (``managed_client_id`` set): a real operator-created client
    record is never silently deleted out from under them, even if its
    underlying address later fails this heuristic (e.g. a legitimately
    reconfigured network).
    """
    removed = 0
    for (source_ip,) in conn.execute(
        "SELECT source_ip FROM observed_clients WHERE managed_client_id IS NULL"
    ).fetchall():
        try:
            ip = ipaddress.ip_address(source_ip)
        except ValueError:
            continue
        if not _is_plausible_client_address(ip):
            conn.execute("DELETE FROM observed_clients WHERE source_ip=?", (source_ip,))
            removed += 1
    return removed


def managed_client_for_ip(conn: sqlite3.Connection, source_ip: str) -> Optional[int]:
    ip = ipaddress.ip_address(source_ip)
    for client_id, kind, value in conn.execute("SELECT client_id, kind, value FROM client_identifiers").fetchall():
        try:
            if kind in ("ipv4", "ipv6") and ip == ipaddress.ip_address(value):
                return client_id
            if kind in ("ipv4_cidr", "ipv6_cidr") and ip in ipaddress.ip_network(value, strict=False):
                return client_id
        except ValueError:
            continue
    return None


def settings(conn: sqlite3.Connection) -> dict[str, int]:
    rows = dict(conn.execute("SELECT key, value FROM observed_client_settings").fetchall())
    return {
        "max_entries": max(1, min(100000, int(rows.get("max_entries", DEFAULT_MAX_ENTRIES)))),
        "expiry_days": max(1, min(3650, int(rows.get("expiry_days", DEFAULT_EXPIRY_DAYS)))),
    }


def update_settings(conn: sqlite3.Connection, *, max_entries: int | None = None, expiry_days: int | None = None) -> None:
    if max_entries is not None:
        if max_entries < 1 or max_entries > 100000:
            raise ValueError("max_entries must be between 1 and 100000")
        conn.execute(
            "INSERT INTO observed_client_settings(key, value) VALUES ('max_entries', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(max_entries),),
        )
    if expiry_days is not None:
        if expiry_days < 1 or expiry_days > 3650:
            raise ValueError("expiry_days must be between 1 and 3650")
        conn.execute(
            "INSERT INTO observed_client_settings(key, value) VALUES ('expiry_days', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(expiry_days),),
        )


def apply_observations(conn: sqlite3.Connection, observations: list[Observation]) -> int:
    if not observations:
        return 0
    applied = 0
    for obs in observations[:1024]:
        ip = ipaddress.ip_address(obs.source_ip)
        if not _is_plausible_client_address(ip):
            continue
        family = "ipv6" if ip.version == 6 else "ipv4"
        ts = _now_iso(obs.ts)
        hostname = sanitize_hostname(obs.hostname_candidate)
        managed_id = managed_client_for_ip(conn, str(ip))
        conn.execute(
            """
            INSERT INTO observed_clients(
                source_ip, address_family, first_seen, last_seen, query_count,
                hostname_candidate, hostname_source, managed_client_id
            ) VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            ON CONFLICT(source_ip) DO UPDATE SET
                last_seen=excluded.last_seen,
                query_count=query_count + 1,
                hostname_candidate=CASE WHEN excluded.hostname_candidate != '' THEN excluded.hostname_candidate ELSE hostname_candidate END,
                hostname_source=CASE WHEN excluded.hostname_candidate != '' THEN excluded.hostname_source ELSE hostname_source END,
                managed_client_id=COALESCE(excluded.managed_client_id, managed_client_id),
                dismissed=0
            """,
            (str(ip), family, ts, ts, hostname, obs.hostname_source if hostname else "", managed_id),
        )
        applied += 1
    enforce_retention(conn)
    return applied


def enforce_retention(conn: sqlite3.Connection) -> None:
    cfg = settings(conn)
    cutoff = _now_iso(time.time() - cfg["expiry_days"] * 86400)
    cur = conn.execute("DELETE FROM observed_clients WHERE managed_client_id IS NULL AND last_seen < ?", (cutoff,))
    evicted = cur.rowcount if cur.rowcount else 0
    count = conn.execute("SELECT count(*) FROM observed_clients").fetchone()[0]
    over = max(0, count - cfg["max_entries"])
    if over:
        rows = conn.execute(
            "SELECT source_ip FROM observed_clients WHERE managed_client_id IS NULL ORDER BY last_seen ASC LIMIT ?",
            (over,),
        ).fetchall()
        for (source_ip,) in rows:
            conn.execute("DELETE FROM observed_clients WHERE source_ip=?", (source_ip,))
        evicted += len(rows)
    if evicted:
        conn.execute("UPDATE observed_client_stats SET evicted=evicted+? WHERE id=1", (evicted,))


def list_observed(conn: sqlite3.Connection, *, limit: int = 100, offset: int = 0, search: str = "") -> dict:
    limit = max(1, min(500, limit))
    offset = max(0, offset)
    where = ""
    params: list[object] = []
    if search:
        where = "WHERE source_ip LIKE ? OR hostname_candidate LIKE ?"
        params.extend([f"%{search[:128]}%", f"%{search[:128]}%"])
    total = conn.execute(f"SELECT count(*) FROM observed_clients {where}", params).fetchone()[0]
    rows = conn.execute(
        f"""
        SELECT source_ip, address_family, first_seen, last_seen, query_count,
               hostname_candidate, hostname_source, managed_client_id, dismissed, confidence
        FROM observed_clients {where}
        ORDER BY last_seen DESC LIMIT ? OFFSET ?
        """,
        (*params, limit, offset),
    ).fetchall()
    return {
        "total": total,
        "observed_clients": [_row_dict(r) for r in rows],
    }


def get_observed(conn: sqlite3.Connection, source_ip: str) -> dict:
    source_ip = str(ipaddress.ip_address(source_ip))
    row = conn.execute(
        """
        SELECT source_ip, address_family, first_seen, last_seen, query_count,
               hostname_candidate, hostname_source, managed_client_id, dismissed, confidence
        FROM observed_clients WHERE source_ip=?
        """,
        (source_ip,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown observed client: {source_ip}")
    return _row_dict(row)


def _row_dict(row) -> dict:
    return {
        "source_ip": row[0],
        "address_family": row[1],
        "first_seen": row[2],
        "last_seen": row[3],
        "query_count": row[4],
        "hostname_candidate": row[5],
        "hostname_source": row[6],
        "managed_client_id": row[7],
        "dismissed": bool(row[8]),
        "confidence": row[9],
    }


def forget(conn: sqlite3.Connection, source_ip: str) -> None:
    source_ip = str(ipaddress.ip_address(source_ip))
    conn.execute("DELETE FROM observed_clients WHERE source_ip=?", (source_ip,))


def record_drain_error(conn: sqlite3.Connection, message: str, *, ts: float | None = None) -> None:
    """Records a discovery-inbox drain failure (e.g. a per-file SQLite
    write that raised). Distinct from ``record_drain_success`` below --
    ``stats()`` compares the two timestamps to tell a currently-failing
    worker from one that failed once and has since recovered, instead of
    the failure text sitting in health forever (real defect: a transient
    "database is locked" from Aug 23 was still reported as the live
    ``client_discovery`` error on Aug 24 after the worker had gone on to
    process thousands of observations cleanly)."""
    conn.execute(
        "UPDATE observed_client_stats SET last_error=?, last_error_at=? WHERE id=1",
        (message[:512], ts if ts is not None else time.time()),
    )


def record_drain_success(conn: sqlite3.Connection, *, ts: float | None = None) -> None:
    """Marks that the discovery-inbox drain made real progress (a file
    committed cleanly), so ``stats()`` can tell an error timestamped
    before this one is recovered rather than still active."""
    conn.execute(
        "UPDATE observed_client_stats SET last_success_at=? WHERE id=1",
        (ts if ts is not None else time.time(),),
    )


def stats(conn: sqlite3.Connection, *, queue_obj: ObservationQueue | None = None) -> dict:
    row = conn.execute(
        "SELECT dropped, evicted, coalesced, last_error, last_error_at, last_success_at "
        "FROM observed_client_stats WHERE id=1"
    ).fetchone()
    count = conn.execute("SELECT count(*) FROM observed_clients").fetchone()[0]
    last_error_text, last_error_at, last_success_at = row[3], row[4], row[5]
    # An error is "current" only while no success has been recorded since
    # it happened -- a success at or after the error's own timestamp means
    # the worker recovered on its own (e.g. the file that hit "database is
    # locked" was retried, or a later file committed fine), so the error
    # is historical, not live. See record_drain_error()'s docstring for
    # the real staleness bug this replaces.
    is_current = bool(last_error_text) and last_error_at is not None and (
        last_success_at is None or last_success_at < last_error_at
    )
    current_error = last_error_text if is_current else None
    if last_error_text and not is_current:
        last_historical_error = last_error_text
        last_historical_error_at = last_error_at
        recovered_at = last_success_at
    else:
        last_historical_error = None
        last_historical_error_at = None
        recovered_at = None
    return {
        "status": "error" if current_error else "ok",
        "observed_count": count,
        "dropped": row[0] + (queue_obj.dropped if queue_obj else 0),
        "evicted": row[1],
        "coalesced": row[2] + (queue_obj.coalesced if queue_obj else 0),
        # Back-compat shape: empty string, never null, and only ever
        # populated while the error is actually still current -- old
        # dashboards/tests reading this field as "the live error" now get
        # a truthful answer instead of a permanently-stuck one.
        "last_error": current_error or "",
        "last_error_at": last_error_at,
        "last_success_at": last_success_at,
        "last_historical_error": last_historical_error,
        "last_historical_error_at": last_historical_error_at,
        "recovered_at": recovered_at,
        "settings": settings(conn),
        "queue_depth": len(queue_obj) if queue_obj else 0,
    }


def promote(
    conn: sqlite3.Connection,
    source_ip: str,
    *,
    display_name: str,
    groups: list[str] | None = None,
    policy_override: dict | None = None,
) -> int:
    source_ip = str(ipaddress.ip_address(source_ip))
    observed = get_observed(conn, source_ip)
    if observed["managed_client_id"] is not None:
        return int(observed["managed_client_id"])
    kind = "ipv6" if ipaddress.ip_address(source_ip).version == 6 else "ipv4"
    now = _now_iso()
    try:
        cur = conn.execute(
            "INSERT INTO clients(name, description, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
            (display_name[:128], "Promoted from observed DNS client discovery", now, now),
        )
        client_id = cur.lastrowid
        conn.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES (?, ?, ?, ?)",
            (client_id, kind, source_ip, now),
        )
    except sqlite3.IntegrityError:
        existing = managed_client_for_ip(conn, source_ip)
        if existing is None:
            raise
        client_id = existing
    for group_id in groups or []:
        from app.v2 import policy_store

        policy_store.add_client_to_group(conn, client_id, group_id)
    if policy_override:
        from app.v2 import policy_store
        from app.v2.policy_model import PolicyLayer

        policy_store.save_policy_layer(conn, "client", str(client_id), PolicyLayer(**policy_override))
    conn.execute("UPDATE observed_clients SET managed_client_id=? WHERE source_ip=?", (client_id, source_ip))
    return int(client_id)
