#!/usr/bin/env python3
"""BindGuard analytics collection, storage, and query helpers."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import queue
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

from app.bindguard_compiler import DB_PATH, connect, enabled_sources, init_db, normalize_domain, parse_rules, source_paths


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
SECRET_FILE = Path("/etc/bindguard/analytics.secret")

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


def iso_from_ts(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).replace(microsecond=0).isoformat()


def bucket_start(ts: int, size: int = BUCKET_SECONDS) -> int:
    return ts - (ts % size)


def init_analytics_db() -> None:
    init_db()
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
            CREATE INDEX IF NOT EXISTS idx_query_events_ts ON query_events(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_query_events_domain ON query_events(domain);
            CREATE INDEX IF NOT EXISTS idx_query_events_client ON query_events(client);
            CREATE INDEX IF NOT EXISTS idx_query_events_blocked ON query_events(blocked, ts DESC);
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
            latency_ms = max(0.0, ((ts - int(query_sec)) * 1000.0) + ((usec - int(query_usec or 0)) / 1000.0))
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
    creds = Path("/etc/bindguard/dnsdist-web.creds").read_text().strip()
    api_key = Path("/etc/bindguard/dnsdist-api.key").read_text().strip()
    request = urllib.request.Request("http://127.0.0.1:8083/jsonstat?command=stats")
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
        deltas["latency_sum_ms"] = float(latency)
        deltas["latency_count"] = 1
    upsert_bucket(conn, ts, deltas)
    return deltas


def cleanup(conn: sqlite3.Connection, cfg: dict[str, str]) -> None:
    now_ts = utc_now()
    detailed_days = max(0, int(cfg.get("detailed_retention_days", DEFAULT_DETAILED_RETENTION_DAYS)))
    aggregate_days = max(1, int(cfg.get("aggregate_retention_days", DEFAULT_AGGREGATE_RETENTION_DAYS)))
    conn.execute("DELETE FROM query_events WHERE ts < ?", (now_ts - detailed_days * 86400,))
    conn.execute("DELETE FROM analytics_aggregate_buckets WHERE bucket_start < ?", (now_ts - aggregate_days * 86400,))
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
            with connect() as conn:
                detailed = cfg.get("detailed_query_logging_enabled", "1") == "1" and cfg.get("privacy_mode") != "aggregate_only"
                insert_events(conn, batch, detailed)
                if self.dropped:
                    upsert_bucket(conn, utc_now(), {"telemetry_dropped": self.dropped})
                    self.dropped = 0
                cleanup(conn, cfg)

    def poll_loop(self) -> None:
        while not self.stop_event.is_set():
            cfg = self.current_settings()
            interval = max(5, int(cfg.get("collection_interval", DEFAULT_INTERVAL)))
            if cfg.get("analytics_enabled", "1") == "1":
                try:
                    with connect() as conn:
                        collect_dnsdist_aggregate(conn)
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
        "recent": recent,
        "has_data": bool(buckets),
    }


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
        conn.execute("INSERT INTO analytics_events(ts, level, message) VALUES (?, 'info', 'statistics cleared')", (utc_now(),))


def export_statistics() -> str:
    init_analytics_db()
    with connect() as conn:
        payload = {
            "settings": settings(conn),
            "buckets": [dict(row) for row in conn.execute("SELECT * FROM analytics_aggregate_buckets ORDER BY bucket_start")],
            "queries": [dict(row) for row in conn.execute("SELECT * FROM query_events ORDER BY ts DESC LIMIT 10000")],
        }
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BindGuard analytics collector")
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
        cleanup(conn, settings(conn))


if __name__ == "__main__":
    raise SystemExit(main())
