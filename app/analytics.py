#!/usr/bin/env python3
"""Alderpoint DNS analytics collection, storage, and query helpers."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import queue
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from app import local_dns
except ModuleNotFoundError:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app import local_dns

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.alderpointdns_compiler import DB_PATH, connect, enabled_sources, init_db, normalize_domain, parse_rules, source_paths


ANALYTICS_HOST = "127.0.0.1"
ANALYTICS_PORT = 5301
BUCKET_SECONDS = 60
DEFAULT_INTERVAL = 15
DEFAULT_DETAILED_RETENTION_DAYS = 7
DEFAULT_AGGREGATE_RETENTION_DAYS = 90
DEFAULT_DB_LIMIT_BYTES = 256 * 1024 * 1024
DEFAULT_RECENT_LIMIT = 100
QUEUE_SIZE = 10000
MAX_FRAME_BYTES = 1024 * 1024

# Writer-loop resilience: a locked database (a web request or another writer
# holding the write lock past busy_timeout) is treated as transient and
# retried with backoff; only after LOCK_RETRY_ATTEMPTS in a row does the
# cycle give up. WRITER_MAX_CONSECUTIVE_FAILURES bounds how many *whole
# cycles* (not lock retries) can fail in a row before the writer thread
# gives up entirely and terminates the process -- a single flaky cycle must
# never take the collector down, but a writer that can never make forward
# progress must not spin forever pretending to be healthy either.
LOCK_RETRY_ATTEMPTS = 5
LOCK_RETRY_BASE_DELAY = 0.2
WRITER_MAX_CONSECUTIVE_FAILURES = 10
HEARTBEAT_FILE = Path("/var/lib/alderpointdns/analytics-writer-heartbeat.json")
# Generous vs. the ~1s writer_loop cadence and the lock-retry ceiling above
# (5 attempts x up to ~3.2s backoff) so a heartbeat is only ever considered
# stale once the writer has demonstrably stopped making progress.
WRITER_STALE_SECONDS = 60
# Well above dnsdist's configured 5s TCP / 2s UDP upstream timeouts (with
# margin for retries), so real slow queries are never dropped, but a
# corrupted/misparsed protobuf timestamp cannot silently inflate aggregates.
MAX_PLAUSIBLE_LATENCY_MS = 30_000
SECRET_FILE = Path("/etc/alderpointdns/analytics.secret")
DNSDIST_SERVER_API_URL = "http://127.0.0.1:8083/api/v1/servers/localhost"
UPSTREAM_SERVER_RE = re.compile(r"^upstream-(?P<id>\d+)-")

QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}
RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}
PROTO_NAMES = {
    1: "UDP",
    2: "TCP",
    3: "DoT",
    4: "DoH",
    7: "DoQ",
}


@dataclass
class QueryEvent:
    ts: int
    client: str
    domain: str
    qtype: str
    protocol: str
    rcode: str
    latency_ms: float | None
    blocked: bool
    blocked_domain: str | None = None
    block_source: str | None = None
    block_category: str | None = None


def utc_now() -> int:
    return int(time.time())


def _log(priority: int, message: str) -> None:
    """Emits a line prefixed with its syslog priority (systemd's default
    SyslogLevelPrefix=yes strips and honors "<N>" on stdout/stderr), so
    System Status classifies collector diagnostics by real severity instead
    of everything landing as Info."""
    print(f"<{priority}>analytics: {message}", file=sys.stderr, flush=True)


def _is_lock_error(exc: BaseException) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and ("locked" in str(exc).lower() or "busy" in str(exc).lower())


def _retry_on_lock(func, *, attempts: int = LOCK_RETRY_ATTEMPTS, base_delay: float = LOCK_RETRY_BASE_DELAY):
    """Runs `func()`, retrying with exponential backoff only for a locked/busy
    database. Returns (result, retries_used). Any other exception, or a lock
    that outlasts every retry, propagates to the caller."""
    last_exc: BaseException | None = None
    for attempt in range(attempts):
        try:
            return func(), attempt
        except sqlite3.OperationalError as exc:
            if not _is_lock_error(exc):
                raise
            last_exc = exc
            if attempt < attempts - 1:
                time.sleep(base_delay * (2 ** attempt))
    raise last_exc


def _write_heartbeat(status: str, detail: str = "") -> None:
    """Persists writer-thread health to a plain file rather than the
    database itself -- the whole point of this heartbeat is to stay
    readable even while the database is locked or the writer is failing to
    reach it, so webapp/notify_check can tell "active but dead" apart from
    "genuinely healthy" without depending on the thing that might be broken."""
    payload = {"ts": utc_now(), "status": status, "detail": detail}
    try:
        tmp = HEARTBEAT_FILE.with_suffix(".tmp")
        HEARTBEAT_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(payload))
        tmp.replace(HEARTBEAT_FILE)
    except OSError:
        pass


def writer_health() -> dict[str, Any]:
    """Reads the writer heartbeat file. `status` is one of "ok", "degraded"
    (a lock was retried but the cycle still completed or was skipped),
    "dead" (the writer thread terminated), or "unknown" (no heartbeat yet,
    e.g. right after install/upgrade before the service has completed its
    first cycle). `stale` is true once a previously-live heartbeat has not
    been touched for WRITER_STALE_SECONDS, which is how an "active" systemd
    unit whose writer thread silently died gets caught."""
    try:
        payload = json.loads(HEARTBEAT_FILE.read_text())
    except (OSError, ValueError):
        return {"status": "unknown", "stale": False, "ts": None, "detail": ""}
    age = utc_now() - int(payload.get("ts", 0))
    return {
        "status": payload.get("status", "unknown"),
        "stale": age > WRITER_STALE_SECONDS,
        "ts": payload.get("ts"),
        "detail": payload.get("detail", ""),
    }


def iso_from_ts(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).replace(microsecond=0).isoformat()


def bucket_start(ts: int, size: int = BUCKET_SECONDS) -> int:
    return ts - (ts % size)


def init_analytics_db() -> None:
    """Called on essentially every analytics read/write (dashboard_data(),
    settings(), update_settings(), ...), so this is by far the most
    frequently-opened write transaction against the shared database --
    unlike the writer thread's own batched event/cleanup writes
    (_write_events()/_run_cleanup()), it used to rely solely on the
    connection's PRAGMA busy_timeout with no Python-level retry at all. A
    real appliance reproduction (multiple systemd units restarting together
    after a restore/upgrade, each re-running init_db()/init_analytics_db()
    within milliseconds of each other, on the same schedule a real restore
    or update actually triggers) showed that gap: this write occasionally
    lost the SQLITE_BUSY race and surfaced a raw sqlite3.OperationalError
    instead of retrying, exactly the asymmetry _retry_on_lock() already
    closes for the writer thread. The script is entirely idempotent (CREATE
    TABLE IF NOT EXISTS / INSERT OR IGNORE), so retrying it from scratch on
    a lock is always safe."""
    init_db()

    def _do() -> None:
        with connect() as conn:
            conn.executescript(
                """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS analytics_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analytics_aggregate_buckets (
                bucket_start INTEGER PRIMARY KEY,
                total_queries INTEGER NOT NULL DEFAULT 0,
                allowed_queries INTEGER NOT NULL DEFAULT 0,
                blocked_queries INTEGER NOT NULL DEFAULT 0,
                responses INTEGER NOT NULL DEFAULT 0,
                noerror INTEGER NOT NULL DEFAULT 0,
                nxdomain INTEGER NOT NULL DEFAULT 0,
                servfail INTEGER NOT NULL DEFAULT 0,
                refused INTEGER NOT NULL DEFAULT 0,
                udp_queries INTEGER NOT NULL DEFAULT 0,
                tcp_queries INTEGER NOT NULL DEFAULT 0,
                doh_queries INTEGER NOT NULL DEFAULT 0,
                dot_queries INTEGER NOT NULL DEFAULT 0,
                doq_queries INTEGER NOT NULL DEFAULT 0,
                doh3_queries INTEGER NOT NULL DEFAULT 0,
                dropped_requests INTEGER NOT NULL DEFAULT 0,
                rate_limited_requests INTEGER NOT NULL DEFAULT 0,
                cache_hits INTEGER NOT NULL DEFAULT 0,
                cache_misses INTEGER NOT NULL DEFAULT 0,
                latency_sum_ms REAL NOT NULL DEFAULT 0,
                latency_count INTEGER NOT NULL DEFAULT 0,
                backend_healthy INTEGER NOT NULL DEFAULT 1,
                telemetry_dropped INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analytics_counter_state (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS query_events (
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                client TEXT NOT NULL,
                domain TEXT NOT NULL,
                qtype TEXT NOT NULL,
                protocol TEXT NOT NULL,
                rcode TEXT NOT NULL,
                latency_ms REAL,
                blocked INTEGER NOT NULL DEFAULT 0,
                blocked_domain TEXT,
                block_source TEXT,
                block_category TEXT
            );
            CREATE TABLE IF NOT EXISTS analytics_events (
                id INTEGER PRIMARY KEY,
                ts INTEGER NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS upstream_resolver_aggregate_buckets (
                bucket_start INTEGER NOT NULL,
                resolver_id INTEGER,
                resolver_name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                health_state TEXT NOT NULL DEFAULT 'unknown',
                queries_attempted INTEGER NOT NULL DEFAULT 0,
                successful_responses INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                timeouts INTEGER NOT NULL DEFAULT 0,
                latency_sum_ms REAL NOT NULL DEFAULT 0,
                latency_count INTEGER NOT NULL DEFAULT 0,
                recent_latency_ms REAL,
                last_success_at TEXT,
                last_failure_at TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(bucket_start, resolver_id, resolver_name)
            );
            CREATE TABLE IF NOT EXISTS upstream_resolver_counter_state (
                server_name TEXT PRIMARY KEY,
                resolver_id INTEGER,
                counters_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_query_events_ts ON query_events(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_query_events_domain ON query_events(domain);
            CREATE INDEX IF NOT EXISTS idx_query_events_client ON query_events(client);
            CREATE INDEX IF NOT EXISTS idx_query_events_blocked ON query_events(blocked, ts DESC);
            CREATE INDEX IF NOT EXISTS idx_upstream_resolver_buckets_resolver ON upstream_resolver_aggregate_buckets(resolver_id, bucket_start DESC);
                """
            )
            defaults = {
                "analytics_enabled": "1",
                "detailed_query_logging_enabled": "1",
                "privacy_mode": "full",
                "detailed_retention_days": str(DEFAULT_DETAILED_RETENTION_DAYS),
                "aggregate_retention_days": str(DEFAULT_AGGREGATE_RETENTION_DAYS),
                "db_size_limit_bytes": str(DEFAULT_DB_LIMIT_BYTES),
                "client_anonymization": "truncate",
                "collection_interval": str(DEFAULT_INTERVAL),
                "recent_query_limit": str(DEFAULT_RECENT_LIMIT),
            }
            conn.executemany(
                "INSERT OR IGNORE INTO analytics_settings(key, value) VALUES (?, ?)",
                defaults.items(),
            )

    _retry_on_lock(_do)


def settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    close = False
    if conn is None:
        init_analytics_db()
        conn = connect()
        close = True
    try:
        return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM analytics_settings")}
    finally:
        if close:
            conn.close()


def update_settings(values: dict[str, str]) -> None:
    init_analytics_db()
    allowed = set(settings().keys())
    with connect() as conn:
        for key, value in values.items():
            if key in allowed:
                conn.execute("UPDATE analytics_settings SET value=? WHERE key=?", (str(value), key))


def normalize_client(value: str, mode: str, anonymization: str = "truncate") -> str:
    if mode == "full":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value.strip() or "unknown"
    secret = analytics_secret()
    try:
        ip = ipaddress.ip_address(value)
        if anonymization == "truncate":
            if ip.version == 4:
                return str(ipaddress.ip_network(f"{ip}/24", strict=False))
            return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except ValueError:
        pass
    digest = hashlib.sha256((secret + value).encode()).hexdigest()[:16]
    return f"anon-{digest}"


def normalize_query_domain(value: str) -> str:
    return normalize_domain(value) or value.strip().strip(".").lower() or "unknown"


def analytics_secret() -> str:
    try:
        return SECRET_FILE.read_text().strip()
    except Exception:
        secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
        try:
            SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
            SECRET_FILE.write_text(secret + "\n")
            os.chmod(SECRET_FILE, 0o640)
        except Exception:
            pass
        return secret


def read_varint(data: bytes, pos: int) -> tuple[int, int]:
    shift = 0
    value = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            break
    raise ValueError("invalid protobuf varint")


def protobuf_fields(data: bytes) -> list[tuple[int, int, Any]]:
    fields: list[tuple[int, int, Any]] = []
    pos = 0
    while pos < len(data):
        key, pos = read_varint(data, pos)
        field = key >> 3
        wire = key & 7
        if wire == 0:
            value, pos = read_varint(data, pos)
        elif wire == 1:
            value = data[pos : pos + 8]
            pos += 8
        elif wire == 2:
            length, pos = read_varint(data, pos)
            value = data[pos : pos + length]
            pos += length
        elif wire == 5:
            value = data[pos : pos + 4]
            pos += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        fields.append((field, wire, value))
    return fields


def field_map(data: bytes) -> dict[int, list[Any]]:
    out: dict[int, list[Any]] = {}
    for field, _, value in protobuf_fields(data):
        out.setdefault(field, []).append(value)
    return out


def first(mapping: dict[int, list[Any]], key: int, default: Any = None) -> Any:
    values = mapping.get(key)
    return values[0] if values else default


def decode_ip(raw: bytes | None) -> str:
    if not raw:
        return "unknown"
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return "unknown"


def decode_question(raw: bytes | None) -> tuple[str, str]:
    if not raw:
        return "unknown", "UNKNOWN"
    fields = field_map(raw)
    qname = first(fields, 1, b"unknown")
    if isinstance(qname, bytes):
        qname = qname.decode(errors="replace")
    qtype_value = first(fields, 2, 0)
    qtype = int(0 if qtype_value is None else qtype_value)
    return normalize_query_domain(str(qname)), QTYPE_NAMES.get(qtype, str(qtype or "UNKNOWN"))


def decode_response(raw: bytes | None) -> tuple[str, int | None, int | None]:
    if not raw:
        return "UNKNOWN", None, None
    fields = field_map(raw)
    rcode_value = first(fields, 1, 65536)
    rcode = int(65536 if rcode_value is None else rcode_value)
    query_sec = first(fields, 5)
    query_usec = first(fields, 6, 0)
    return RCODE_NAMES.get(rcode, str(rcode)), query_sec, query_usec


def decode_dnsdist_message(data: bytes) -> list[dict[str, Any]]:
    fields = field_map(data)
    candidates = fields.get(1, [])
    messages = []
    if candidates and all(isinstance(item, bytes) for item in candidates):
        for item in candidates:
            try:
                nested = field_map(item)
                if 12 in nested or 13 in nested:
                    messages.append(nested)
            except ValueError:
                pass
    if not messages:
        messages = [fields]
    decoded = []
    for msg in messages:
        domain, qtype = decode_question(first(msg, 12))
        rcode, query_sec, query_usec = decode_response(first(msg, 13))
        ts = int(first(msg, 9, utc_now()) or utc_now())
        usec = int(first(msg, 10, 0) or 0)
        latency_ms = None
        if query_sec is not None:
            # Latency comes entirely from timestamps embedded by dnsdist in the
            # protobuf payload (query time vs. this response's own time), never
            # from when the collector happens to receive/process the frame, so
            # analytics-queue or network delivery delay to the collector cannot
            # inflate DNS latency. Clamp negative deltas (clock skew) to zero and
            # discard implausible values (corrupted/misparsed timestamp fields)
            # above the highest configured dnsdist upstream timeout instead of
            # letting a single bad frame corrupt aggregate averages.
            raw_latency_ms = ((ts - int(query_sec)) * 1000.0) + ((usec - int(query_usec or 0)) / 1000.0)
            if raw_latency_ms <= MAX_PLAUSIBLE_LATENCY_MS:
                latency_ms = max(0.0, raw_latency_ms)
        protocol = PROTO_NAMES.get(int(first(msg, 5, 0) or 0), "UNKNOWN")
        http_version = int(first(msg, 24, 0) or 0)
        if protocol == "DoH" and http_version == 3:
            protocol = "DoH3"
        decoded.append(
            {
                "ts": ts,
                "client": decode_ip(first(msg, 6)),
                "domain": domain,
                "qtype": qtype,
                "protocol": protocol,
                "rcode": rcode,
                "latency_ms": latency_ms,
            }
        )
    return decoded


def iter_frames(buffer: bytearray) -> list[bytes]:
    frames: list[bytes] = []
    while True:
        if len(buffer) < 2:
            return frames
        length = struct.unpack("!H", buffer[:2])[0]
        header = 2
        if length == 0 and len(buffer) >= 4:
            length = struct.unpack("!I", buffer[:4])[0]
            header = 4
        if length <= 0 or length > MAX_FRAME_BYTES:
            del buffer[0]
            continue
        if len(buffer) < header + length:
            return frames
        frames.append(bytes(buffer[header : header + length]))
        del buffer[: header + length]


def load_policy_index() -> dict[str, tuple[str | None, str | None]]:
    init_db()
    policy: dict[str, tuple[str | None, str | None]] = {}
    with connect() as conn:
        allows = {row["domain"] for row in conn.execute("SELECT domain FROM custom_rules WHERE enabled=1 AND action='allow'")}
        for row in conn.execute("SELECT domain FROM custom_rules WHERE enabled=1 AND action='block'"):
            if row["domain"] not in allows:
                policy[row["domain"]] = ("Custom rule", "custom")
        for source in enabled_sources(conn):
            current, _ = source_paths(source)
            try:
                blocks, source_allows, _ = parse_rules(current.read_text(errors="replace"))
            except Exception:
                continue
            allows.update(source_allows)
            for domain in blocks:
                if domain not in allows and domain not in policy:
                    policy[domain] = (source["name"], source["category"])
    for allowed in allows:
        policy.pop(allowed, None)
    return policy


def policy_match(domain: str, policy: dict[str, tuple[str | None, str | None]]) -> tuple[str | None, str | None, str | None]:
    labels = domain.split(".")
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in policy:
            source, category = policy[candidate]
            return candidate, source, category
    return None, None, None


def event_from_message(message: dict[str, Any], policy: dict[str, tuple[str | None, str | None]], cfg: dict[str, str]) -> QueryEvent:
    domain = normalize_query_domain(str(message.get("domain") or "unknown"))
    matched, source, category = policy_match(domain, policy)
    rcode = str(message.get("rcode") or "UNKNOWN")
    blocked = matched is not None and rcode in {"NXDOMAIN", "NOERROR", "REFUSED"}
    privacy_mode = cfg.get("privacy_mode", "full")
    client = normalize_client(str(message.get("client") or "unknown"), privacy_mode, cfg.get("client_anonymization", "truncate"))
    return QueryEvent(
        ts=int(message.get("ts") or utc_now()),
        client=client,
        domain=domain if privacy_mode != "aggregate_only" else "",
        qtype=str(message.get("qtype") or "UNKNOWN"),
        protocol=str(message.get("protocol") or "UNKNOWN"),
        rcode=rcode,
        latency_ms=message.get("latency_ms"),
        blocked=blocked,
        blocked_domain=matched,
        block_source=source,
        block_category=category,
    )


def bucket_columns_for_event(event: QueryEvent) -> dict[str, Any]:
    protocol = event.protocol.lower()
    rcode = event.rcode.lower()
    return {
        "total_queries": 1,
        "allowed_queries": 0 if event.blocked else 1,
        "blocked_queries": 1 if event.blocked else 0,
        "responses": 1,
        "noerror": 1 if rcode == "noerror" else 0,
        "nxdomain": 1 if rcode == "nxdomain" else 0,
        "servfail": 1 if rcode == "servfail" else 0,
        "refused": 1 if rcode == "refused" else 0,
        "udp_queries": 1 if protocol == "udp" else 0,
        "tcp_queries": 1 if protocol == "tcp" else 0,
        "doh_queries": 1 if protocol == "doh" else 0,
        "dot_queries": 1 if protocol == "dot" else 0,
        "doq_queries": 1 if protocol == "doq" else 0,
        "doh3_queries": 1 if protocol == "doh3" else 0,
        "latency_sum_ms": float(event.latency_ms or 0),
        "latency_count": 1 if event.latency_ms is not None else 0,
    }


def upsert_bucket(conn: sqlite3.Connection, ts: int, values: dict[str, Any]) -> None:
    start = bucket_start(ts)
    all_values = {
        "total_queries": 0,
        "allowed_queries": 0,
        "blocked_queries": 0,
        "responses": 0,
        "noerror": 0,
        "nxdomain": 0,
        "servfail": 0,
        "refused": 0,
        "udp_queries": 0,
        "tcp_queries": 0,
        "doh_queries": 0,
        "dot_queries": 0,
        "doq_queries": 0,
        "doh3_queries": 0,
        "dropped_requests": 0,
        "rate_limited_requests": 0,
        "cache_hits": 0,
        "cache_misses": 0,
        "latency_sum_ms": 0.0,
        "latency_count": 0,
        "backend_healthy": 1,
        "telemetry_dropped": 0,
    }
    all_values.update(values)
    columns = ", ".join(all_values.keys())
    placeholders = ", ".join("?" for _ in all_values)
    updates = ", ".join(f"{key}={key}+excluded.{key}" for key in all_values if key != "backend_healthy")
    updates += ", backend_healthy=excluded.backend_healthy, updated_at=excluded.updated_at"
    conn.execute(
        f"""
        INSERT INTO analytics_aggregate_buckets(bucket_start, {columns}, updated_at)
        VALUES (?, {placeholders}, ?)
        ON CONFLICT(bucket_start) DO UPDATE SET {updates}
        """,
        (start, *all_values.values(), iso_from_ts(utc_now())),
    )


def insert_events(conn: sqlite3.Connection, events: list[QueryEvent], detailed_enabled: bool) -> None:
    if not events:
        return
    for event in events:
        upsert_bucket(conn, event.ts, bucket_columns_for_event(event))
    if detailed_enabled:
        conn.executemany(
            """
            INSERT INTO query_events(
                ts, client, domain, qtype, protocol, rcode, latency_ms, blocked,
                blocked_domain, block_source, block_category
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    event.ts,
                    event.client,
                    event.domain,
                    event.qtype,
                    event.protocol,
                    event.rcode,
                    event.latency_ms,
                    1 if event.blocked else 0,
                    event.blocked_domain,
                    event.block_source,
                    event.block_category,
                )
                for event in events
            ],
        )


def dnsdist_stats() -> dict[str, Any]:
    creds = Path("/etc/alderpointdns/dnsdist-web.creds").read_text().strip()
    api_key = Path("/etc/alderpointdns/dnsdist-api.key").read_text().strip()
    request = urllib.request.Request("http://127.0.0.1:8083/jsonstat?command=stats")
    request.add_header("Authorization", "Basic " + base64.b64encode(creds.encode()).decode())
    request.add_header("x-api-key", api_key)
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.loads(response.read().decode())


def dnsdist_server_state() -> dict[str, Any]:
    creds = Path("/etc/alderpointdns/dnsdist-web.creds").read_text().strip()
    api_key = Path("/etc/alderpointdns/dnsdist-api.key").read_text().strip()
    request = urllib.request.Request(DNSDIST_SERVER_API_URL)
    request.add_header("Authorization", "Basic " + base64.b64encode(creds.encode()).decode())
    request.add_header("x-api-key", api_key)
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.loads(response.read().decode())


COUNTER_MAP = {
    "responses": "responses",
    "cache-hits": "cache_hits",
    "cache-misses": "cache_misses",
    "packetcache-hits": "cache_hits",
    "packetcache-misses": "cache_misses",
    "acl-drops": "dropped_requests",
    "dyn-blocked": "rate_limited_requests",
    "over-capacity-drops": "dropped_requests",
    "rule-drop": "dropped_requests",
    "rule-refused": "refused",
}


def collect_dnsdist_aggregate(conn: sqlite3.Connection, stats: dict[str, Any] | None = None, ts: int | None = None) -> dict[str, Any]:
    stats = stats or dnsdist_stats()
    ts = ts or utc_now()
    previous = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM analytics_counter_state")}
    deltas: dict[str, Any] = {"backend_healthy": 1 if stats.get("no-policy", 0) == 0 else 0}
    for source, target in COUNTER_MAP.items():
        current = int(stats.get(source, 0) or 0)
        old = previous.get(source)
        if old is None or current < old:
            delta = 0
        else:
            delta = current - old
        deltas[target] = deltas.get(target, 0) + delta
        conn.execute(
            """
            INSERT INTO analytics_counter_state(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (source, current, iso_from_ts(ts)),
        )
    latency = stats.get("latency-avg100")
    if latency is not None:
        # dnsdist reports latency-avg100 in microseconds; buckets store milliseconds.
        # latency-avg100 is a live rolling average, not a monotonic counter, so a
        # dnsdist restart naturally resets it without needing delta logic here.
        latency_ms = float(latency) / 1000.0
        if 0 <= latency_ms <= MAX_PLAUSIBLE_LATENCY_MS:
            deltas["latency_sum_ms"] = latency_ms
            deltas["latency_count"] = 1
    upsert_bucket(conn, ts, deltas)
    return deltas


SERVER_COUNTER_FIELDS = (
    "queries",
    "responses",
    "sendErrors",
    "healthCheckFailures",
    "healthCheckFailuresTimeout",
    "tcpConnectTimeouts",
    "tcpReadTimeouts",
    "tcpWriteTimeouts",
    "tcpGaveUp",
)


def _resolver_id_from_server_name(name: str) -> int | None:
    match = UPSTREAM_SERVER_RE.match(name or "")
    if not match:
        return None
    try:
        return int(match.group("id"))
    except ValueError:
        return None


def _endpoint_for_resolver(row: sqlite3.Row | None, server: dict[str, Any]) -> str:
    if row is None:
        return str(server.get("address") or "unknown")
    address = str(row["address"])
    port = int(row["port"])
    if row["protocol"] == "doh":
        return f"https://{address}:{port}{row['doh_path'] or '/dns-query'}"
    if row["protocol"] == "dot":
        return f"tls://{address}:{port}"
    return f"{address}:{port}"


def _protocol_for_server(row: sqlite3.Row | None, server: dict[str, Any]) -> str:
    if row is not None:
        return {"plain": "UDP/TCP", "dot": "DoT", "doh": "DoH"}.get(str(row["protocol"]), str(row["protocol"]))
    protocol = str(server.get("protocol") or "")
    if "DoH" in protocol:
        return "DoH"
    if "DoT" in protocol or "TLS" in protocol:
        return "DoT"
    if "TCP" in protocol:
        return "TCP"
    if "UDP" in protocol or "Do53" in protocol:
        return "UDP"
    return protocol or "unknown"


def _server_counter_values(server: dict[str, Any]) -> dict[str, int]:
    return {field: int(server.get(field, 0) or 0) for field in SERVER_COUNTER_FIELDS}


def _server_deltas(current: dict[str, int], previous: dict[str, int] | None) -> dict[str, int]:
    if not previous:
        return {key: 0 for key in current}
    out: dict[str, int] = {}
    for key, value in current.items():
        old = int(previous.get(key, 0) or 0)
        out[key] = 0 if value < old else value - old
    return out


def collect_upstream_resolver_aggregate(conn: sqlite3.Connection, state: dict[str, Any] | None = None, ts: int | None = None) -> list[dict[str, Any]]:
    """Collect resolver-scoped dnsdist server counters.

    dnsdist identifies the upstream backend selected for BIND's forwarded
    lookup through per-server counters. It does not expose the original client
    query alongside that backend selection in this architecture, so Alderpoint DNS
    records resolver activity aggregates only and does not annotate individual
    query log rows with fabricated upstream identity.
    """

    state = state or dnsdist_server_state()
    ts = ts or utc_now()
    ts_iso = iso_from_ts(ts)
    try:
        resolver_rows = {
            row["id"]: row
            for row in conn.execute(
                "SELECT id, name, protocol, address, port, doh_path, enabled, last_status FROM upstream_resolvers"
            )
        }
    except sqlite3.OperationalError:
        resolver_rows = {}
    previous = {
        row["server_name"]: json.loads(row["counters_json"])
        for row in conn.execute("SELECT server_name, counters_json FROM upstream_resolver_counter_state")
    }
    collected: list[dict[str, Any]] = []
    for server in state.get("servers", []) or []:
        pools = set(server.get("pools") or [])
        name = str(server.get("name") or "")
        resolver_id = _resolver_id_from_server_name(name)
        if "alderpointdns_upstreams" not in pools or resolver_id is None:
            continue
        row = resolver_rows.get(resolver_id)
        current = _server_counter_values(server)
        deltas = _server_deltas(current, previous.get(name))
        queries = deltas["queries"]
        responses = min(deltas["responses"], queries) if queries > 0 else 0
        timeout_delta = sum(deltas[key] for key in ("healthCheckFailuresTimeout", "tcpConnectTimeouts", "tcpReadTimeouts", "tcpWriteTimeouts", "tcpGaveUp"))
        failure_delta = max(0, queries - responses) + deltas["sendErrors"] + deltas["healthCheckFailures"]
        try:
            recent_latency_ms = float(server["latency"]) if server.get("latency") is not None else None
        except (TypeError, ValueError):
            recent_latency_ms = None
        latency_count = responses if responses > 0 and recent_latency_ms is not None else (1 if recent_latency_ms is not None else 0)
        latency_sum = (recent_latency_ms or 0.0) * latency_count
        resolver_name = str(row["name"] if row is not None else name)
        protocol = _protocol_for_server(row, server)
        endpoint = _endpoint_for_resolver(row, server)
        enabled = int(row["enabled"]) if row is not None else 0
        health_state = str(server.get("state") or (row["last_status"] if row is not None else "unknown"))
        conn.execute(
            """
            INSERT INTO upstream_resolver_aggregate_buckets(
                bucket_start, resolver_id, resolver_name, protocol, endpoint,
                enabled, health_state, queries_attempted, successful_responses,
                failures, timeouts, latency_sum_ms, latency_count,
                recent_latency_ms, last_success_at, last_failure_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(bucket_start, resolver_id, resolver_name) DO UPDATE SET
                protocol=excluded.protocol,
                endpoint=excluded.endpoint,
                enabled=excluded.enabled,
                health_state=excluded.health_state,
                queries_attempted=queries_attempted+excluded.queries_attempted,
                successful_responses=successful_responses+excluded.successful_responses,
                failures=failures+excluded.failures,
                timeouts=timeouts+excluded.timeouts,
                latency_sum_ms=latency_sum_ms+excluded.latency_sum_ms,
                latency_count=latency_count+excluded.latency_count,
                recent_latency_ms=excluded.recent_latency_ms,
                last_success_at=coalesce(excluded.last_success_at, last_success_at),
                last_failure_at=coalesce(excluded.last_failure_at, last_failure_at),
                updated_at=excluded.updated_at
            """,
            (
                bucket_start(ts),
                resolver_id,
                resolver_name,
                protocol,
                endpoint,
                enabled,
                health_state,
                queries,
                responses,
                failure_delta,
                timeout_delta,
                latency_sum,
                latency_count,
                recent_latency_ms,
                ts_iso if responses > 0 else None,
                ts_iso if failure_delta > 0 or timeout_delta > 0 else None,
                ts_iso,
            ),
        )
        conn.execute(
            """
            INSERT INTO upstream_resolver_counter_state(server_name, resolver_id, counters_json, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(server_name) DO UPDATE SET
                resolver_id=excluded.resolver_id,
                counters_json=excluded.counters_json,
                updated_at=excluded.updated_at
            """,
            (name, resolver_id, json.dumps(current, sort_keys=True), ts_iso),
        )
        collected.append(
            {
                "resolver_id": resolver_id,
                "resolver_name": resolver_name,
                "queries_attempted": queries,
                "successful_responses": responses,
                "failures": failure_delta,
                "timeouts": timeout_delta,
                "recent_latency_ms": recent_latency_ms,
                "health_state": health_state,
            }
        )
    return collected


def cleanup(conn: sqlite3.Connection, cfg: dict[str, str]) -> None:
    now_ts = utc_now()
    detailed_days = max(0, int(cfg.get("detailed_retention_days", DEFAULT_DETAILED_RETENTION_DAYS)))
    aggregate_days = max(1, int(cfg.get("aggregate_retention_days", DEFAULT_AGGREGATE_RETENTION_DAYS)))
    conn.execute("DELETE FROM query_events WHERE ts < ?", (now_ts - detailed_days * 86400,))
    conn.execute("DELETE FROM analytics_aggregate_buckets WHERE bucket_start < ?", (now_ts - aggregate_days * 86400,))
    conn.execute("DELETE FROM upstream_resolver_aggregate_buckets WHERE bucket_start < ?", (now_ts - aggregate_days * 86400,))
    limit = int(cfg.get("db_size_limit_bytes", DEFAULT_DB_LIMIT_BYTES))
    size = db_size()
    if size > limit:
        conn.execute(
            """
            DELETE FROM query_events
            WHERE id IN (SELECT id FROM query_events ORDER BY ts ASC LIMIT max(1, (SELECT count(*) / 4 FROM query_events)))
            """
        )
        conn.execute(
            "INSERT INTO analytics_events(ts, level, message) VALUES (?, 'warning', ?)",
            (now_ts, f"database size {size} exceeded analytics limit {limit}; oldest query events were pruned"),
        )


def db_size() -> int:
    total = 0
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(DB_PATH) + suffix)
        try:
            total += path.stat().st_size
        except FileNotFoundError:
            pass
    return total


class Collector:
    def __init__(self) -> None:
        init_analytics_db()
        self.events: queue.Queue[QueryEvent] = queue.Queue(maxsize=QUEUE_SIZE)
        self.stop_event = threading.Event()
        self.policy = load_policy_index()
        self.policy_loaded = time.monotonic()
        self.dropped = 0
        self.writer_consecutive_failures = 0
        self.fatal_error = threading.Event()

    def current_settings(self) -> dict[str, str]:
        with connect() as conn:
            return settings(conn)

    def refresh_policy(self) -> None:
        if time.monotonic() - self.policy_loaded > 30:
            self.policy = load_policy_index()
            self.policy_loaded = time.monotonic()

    def enqueue_message(self, message: dict[str, Any]) -> None:
        cfg = self.current_settings()
        if cfg.get("analytics_enabled", "1") != "1":
            return
        self.refresh_policy()
        event = event_from_message(message, self.policy, cfg)
        try:
            self.events.put_nowait(event)
        except queue.Full:
            self.dropped += 1

    def serve_tcp(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((ANALYTICS_HOST, ANALYTICS_PORT))
        server.listen(16)
        server.settimeout(1)
        while not self.stop_event.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
        server.close()

    def handle_client(self, conn: socket.socket) -> None:
        buffer = bytearray()
        conn.settimeout(2)
        with conn:
            while not self.stop_event.is_set():
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                buffer.extend(chunk)
                try:
                    frames = iter_frames(buffer)
                    for frame in frames:
                        for message in decode_dnsdist_message(frame):
                            self.enqueue_message(message)
                except Exception:
                    self.dropped += 1
                    buffer.clear()

    def _write_events(self, batch: list[QueryEvent], cfg: dict[str, str]) -> None:
        def _do() -> None:
            with connect() as conn:
                detailed = cfg.get("detailed_query_logging_enabled", "1") == "1" and cfg.get("privacy_mode") != "aggregate_only"
                insert_events(conn, batch, detailed)
                if self.dropped:
                    upsert_bucket(conn, utc_now(), {"telemetry_dropped": self.dropped})
                    self.dropped = 0

        _, retries = _retry_on_lock(_do)
        if retries:
            _log(4, f"database lock recovered after {retries} retry(s) while writing query events")

    def _run_cleanup(self, cfg: dict[str, str]) -> None:
        def _do() -> None:
            with connect() as conn:
                cleanup(conn, cfg)

        try:
            _, retries = _retry_on_lock(_do)
        except sqlite3.OperationalError as exc:
            # Retention cleanup skips only this cycle -- it never counts
            # toward writer_loop's consecutive-failure/termination logic,
            # since losing a cleanup pass is harmless (the next cycle tries
            # again) while losing query events is not.
            _log(4, f"retention cleanup skipped this cycle after {LOCK_RETRY_ATTEMPTS} exhausted retries: {exc}")
            return
        if retries:
            _log(4, f"database lock recovered after {retries} retry(s) during retention cleanup")

    def _writer_cycle(self, batch: list[QueryEvent], cfg: dict[str, str]) -> None:
        """Runs one writer_loop iteration's work and updates
        writer_consecutive_failures/heartbeat/notifications accordingly.
        Returns normally on success (including a recoverable, retried
        success); sets self.fatal_error and stops the collector only once
        WRITER_MAX_CONSECUTIVE_FAILURES whole cycles have failed in a row."""
        try:
            self._write_events(batch, cfg)
            self._run_cleanup(cfg)
        except Exception as exc:  # noqa: BLE001
            self.writer_consecutive_failures += 1
            if self.writer_consecutive_failures >= WRITER_MAX_CONSECUTIVE_FAILURES:
                _log(3, f"analytics writer thread terminated after {self.writer_consecutive_failures} consecutive failed cycles: {exc}")
                _write_heartbeat("dead", str(exc))
                self._notify_writer("critical", f"Analytics writer thread terminated: {exc}", recovered=False)
                self.fatal_error.set()
                self.stop_event.set()
                return
            _log(4, f"analytics writer cycle failed ({self.writer_consecutive_failures}/{WRITER_MAX_CONSECUTIVE_FAILURES}), will retry next cycle: {exc}")
            _write_heartbeat("degraded", str(exc))
            return
        if self.writer_consecutive_failures:
            _log(6, "analytics writer recovered after transient failure")
            self._notify_writer("critical", "Analytics writer thread recovered", recovered=True)
        self.writer_consecutive_failures = 0
        _write_heartbeat("ok")

    def writer_loop(self) -> None:
        while not self.stop_event.is_set():
            batch: list[QueryEvent] = []
            deadline = time.monotonic() + 1
            while len(batch) < 500 and time.monotonic() < deadline:
                try:
                    batch.append(self.events.get(timeout=0.1))
                except queue.Empty:
                    pass
            cfg = self.current_settings()
            self._writer_cycle(batch, cfg)

    def _notify_writer(self, severity: str, summary: str, *, recovered: bool) -> None:
        try:
            from app import notifications

            notifications.dispatch("service_unavailable", severity, "Analytics collector (writer thread)", summary, recovered=recovered)
        except Exception:  # noqa: BLE001
            pass

    def poll_loop(self) -> None:
        while not self.stop_event.is_set():
            cfg = self.current_settings()
            interval = max(5, int(cfg.get("collection_interval", DEFAULT_INTERVAL)))
            if cfg.get("analytics_enabled", "1") == "1":
                try:
                    with connect() as conn:
                        collect_dnsdist_aggregate(conn)
                        collect_upstream_resolver_aggregate(conn)
                except Exception:
                    pass
            self.stop_event.wait(interval)

    def run(self) -> None:
        threads = [
            threading.Thread(target=self.serve_tcp, daemon=True),
            threading.Thread(target=self.writer_loop, daemon=True),
            threading.Thread(target=self.poll_loop, daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            while True:
                time.sleep(1)
                if self.fatal_error.is_set():
                    # Restart=on-failure in the systemd unit brings the
                    # collector back up; a plain `return` here would exit 0
                    # and leave it down instead.
                    sys.exit(1)
        except KeyboardInterrupt:
            self.stop_event.set()
            for thread in threads:
                thread.join(timeout=2)


def range_seconds(range_key: str) -> int:
    return {
        "1h": 3600,
        "24h": 86400,
        "7d": 7 * 86400,
        "30d": 30 * 86400,
    }.get(range_key, 86400)


def dashboard_data(range_key: str = "24h") -> dict[str, Any]:
    init_analytics_db()
    since = utc_now() - range_seconds(range_key)
    with connect() as conn:
        buckets = conn.execute(
            "SELECT * FROM analytics_aggregate_buckets WHERE bucket_start >= ? ORDER BY bucket_start",
            (since,),
        ).fetchall()
        totals = {
            "total_queries": sum(row["total_queries"] for row in buckets),
            "blocked_queries": sum(row["blocked_queries"] for row in buckets),
            "allowed_queries": sum(row["allowed_queries"] for row in buckets),
            "latency_sum_ms": sum(row["latency_sum_ms"] for row in buckets),
            "latency_count": sum(row["latency_count"] for row in buckets),
        }
        totals["blocked_percent"] = (totals["blocked_queries"] / totals["total_queries"] * 100) if totals["total_queries"] else 0
        totals["avg_latency_ms"] = (totals["latency_sum_ms"] / totals["latency_count"]) if totals["latency_count"] else 0
        active_clients = conn.execute("SELECT count(DISTINCT client) FROM query_events WHERE ts >= ?", (since,)).fetchone()[0]
        top_clients_raw = conn.execute("SELECT client AS raw_client, client AS label, count(*) AS value FROM query_events WHERE ts >= ? GROUP BY client ORDER BY value DESC LIMIT 10", (since,)).fetchall()
        top_domains = conn.execute("SELECT domain AS label, count(*) AS value FROM query_events WHERE ts >= ? GROUP BY domain ORDER BY value DESC LIMIT 10", (since,)).fetchall()
        top_blocked = conn.execute("SELECT coalesce(blocked_domain, domain) AS label, count(*) AS value FROM query_events WHERE ts >= ? AND blocked=1 GROUP BY label ORDER BY value DESC LIMIT 10", (since,)).fetchall()
        qtypes = conn.execute("SELECT qtype AS label, count(*) AS value FROM query_events WHERE ts >= ? GROUP BY qtype ORDER BY value DESC", (since,)).fetchall()
        rcodes = conn.execute("SELECT rcode AS label, count(*) AS value FROM query_events WHERE ts >= ? GROUP BY rcode ORDER BY value DESC", (since,)).fetchall()
        protocols = conn.execute("SELECT protocol AS label, count(*) AS value FROM query_events WHERE ts >= ? GROUP BY protocol ORDER BY value DESC", (since,)).fetchall()
        top_upstreams_raw = conn.execute(
            """
            SELECT
                resolver_id,
                resolver_name AS label,
                protocol,
                endpoint,
                enabled,
                health_state,
                sum(queries_attempted) AS value,
                sum(successful_responses) AS successful_responses,
                sum(failures) AS failures,
                sum(timeouts) AS timeouts,
                sum(latency_sum_ms) AS latency_sum_ms,
                sum(latency_count) AS latency_count,
                max(recent_latency_ms) AS recent_latency_ms,
                max(last_success_at) AS last_success_at,
                max(last_failure_at) AS last_failure_at
            FROM upstream_resolver_aggregate_buckets
            WHERE bucket_start >= ?
            GROUP BY resolver_id, resolver_name, protocol, endpoint, enabled, health_state
            ORDER BY value DESC, successful_responses DESC, label
            LIMIT 10
            """,
            (since,),
        ).fetchall()
        recent_raw = conn.execute("SELECT * FROM query_events ORDER BY ts DESC LIMIT 20").fetchall()
    top_clients = []
    for row in top_clients_raw:
        item = dict(row)
        item["label"] = local_dns.alias_for_client(item["raw_client"]) or item["raw_client"]
        top_clients.append(item)
    recent = []
    for row in recent_raw:
        item = dict(row)
        item["client_display"] = local_dns.alias_for_client(item["client"]) or item["client"]
        recent.append(item)
    return {
        "range": range_key,
        "buckets": [dict(row) for row in buckets],
        "totals": totals,
        "active_clients": active_clients,
        "top_clients": top_clients,
        "top_domains": top_domains,
        "top_blocked": top_blocked,
        "qtypes": qtypes,
        "rcodes": rcodes,
        "protocols": protocols,
        "top_upstreams": [
            {
                **dict(row),
                "avg_latency_ms": (row["latency_sum_ms"] / row["latency_count"]) if row["latency_count"] else None,
            }
            for row in top_upstreams_raw
        ],
        "recent": recent,
        "has_data": bool(buckets),
    }


def clients_data(range_key: str = "24h", limit: int = 200) -> dict[str, Any]:
    """Full ranked client list for the given range -- the drill-down target
    for the Dashboard's "Top Clients" panel. Unlike dashboard_data()'s
    top_clients (capped at 10 for the summary panel), this returns every
    client seen in the range up to `limit`, so administrators can find a
    client that isn't in the dashboard's top-10 slice."""
    init_analytics_db()
    since = utc_now() - range_seconds(range_key)
    with connect() as conn:
        rows_raw = conn.execute(
            """
            SELECT
                client AS raw_client,
                count(*) AS value,
                sum(CASE WHEN blocked THEN 1 ELSE 0 END) AS blocked,
                max(ts) AS last_seen
            FROM query_events
            WHERE ts >= ?
            GROUP BY client
            ORDER BY value DESC
            LIMIT ?
            """,
            (since, limit),
        ).fetchall()
    clients = []
    for row in rows_raw:
        item = dict(row)
        item["label"] = local_dns.alias_for_client(item["raw_client"]) or item["raw_client"]
        item["blocked_percent"] = (item["blocked"] / item["value"] * 100) if item["value"] else 0
        clients.append(item)
    total = sum(item["value"] for item in clients)
    return {"range": range_key, "clients": clients, "total": total}


def query_log(filters: dict[str, str], page: int = 1, limit: int = 50) -> dict[str, Any]:
    init_analytics_db()
    clauses = []
    params: list[Any] = []
    for key, column in (("client", "client"), ("domain", "domain"), ("qtype", "qtype"), ("protocol", "protocol"), ("rcode", "rcode")):
        value = filters.get(key, "").strip()
        if value:
            clauses.append(f"{column} LIKE ?")
            params.append(f"%{value}%")
    search = filters.get("search", "").strip()
    if search:
        clauses.append("(domain LIKE ? OR client LIKE ?)")
        params.extend((f"%{search}%", f"%{search}%"))
    blocked = filters.get("blocked", "").strip()
    if blocked in {"0", "1"}:
        clauses.append("blocked=?")
        params.append(int(blocked))
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    offset = max(0, page - 1) * limit
    with connect() as conn:
        total = conn.execute(f"SELECT count(*) FROM query_events {where}", params).fetchone()[0]
        rows_raw = conn.execute(
            f"SELECT * FROM query_events {where} ORDER BY ts DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
    rows = []
    for row in rows_raw:
        item = dict(row)
        item["client_display"] = local_dns.alias_for_client(item["client"]) or item["client"]
        rows.append(item)
    return {"rows": rows, "total": total, "page": page, "limit": limit, "filters": filters}


def clear_statistics() -> None:
    init_analytics_db()
    with connect() as conn:
        conn.execute("DELETE FROM query_events")
        conn.execute("DELETE FROM analytics_aggregate_buckets")
        conn.execute("DELETE FROM analytics_counter_state")
        conn.execute("DELETE FROM upstream_resolver_aggregate_buckets")
        conn.execute("DELETE FROM upstream_resolver_counter_state")
        conn.execute("INSERT INTO analytics_events(ts, level, message) VALUES (?, 'info', 'statistics cleared')", (utc_now(),))


def export_statistics() -> str:
    init_analytics_db()
    with connect() as conn:
        payload = {
            "settings": settings(conn),
            "buckets": [dict(row) for row in conn.execute("SELECT * FROM analytics_aggregate_buckets ORDER BY bucket_start")],
            "upstream_resolvers": [dict(row) for row in conn.execute("SELECT * FROM upstream_resolver_aggregate_buckets ORDER BY bucket_start DESC LIMIT 10000")],
            "queries": [dict(row) for row in conn.execute("SELECT * FROM query_events ORDER BY ts DESC LIMIT 10000")],
        }
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Alderpoint DNS analytics collector")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db").set_defaults(func=lambda _: init_analytics_db())
    sub.add_parser("collect-once").set_defaults(func=lambda _: collect_once())
    sub.add_parser("run").set_defaults(func=lambda _: Collector().run())
    sub.add_parser("clear").set_defaults(func=lambda _: clear_statistics())
    args = parser.parse_args(argv)
    args.func(args)
    return 0


def collect_once() -> None:
    init_analytics_db()
    with connect() as conn:
        collect_dnsdist_aggregate(conn)
        collect_upstream_resolver_aggregate(conn)
        cleanup(conn, settings(conn))


if __name__ == "__main__":
    raise SystemExit(main())
