"""Builds a disposable, realistic V1 SQLite fixture database (the same
schema shape as the live v1.1.1 appliance's tables relevant to migration)
for tests. Never touches the live database -- every fixture here is
created fresh in a tmp_path by the caller.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE admins (
    id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE clients (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE client_identifiers (
    id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id),
    kind TEXT NOT NULL CHECK(kind IN ('ipv4','ipv4_cidr','ipv6','ipv6_cidr','clientid')),
    value TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(kind, value)
);
CREATE TABLE access_rules (
    id INTEGER PRIMARY KEY, action TEXT NOT NULL CHECK(action IN ('allow','deny')),
    kind TEXT NOT NULL, value TEXT, client_id INTEGER REFERENCES clients(id),
    created_at TEXT NOT NULL
);
CREATE TABLE local_dns_records (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, fqdn TEXT NOT NULL,
    record_type TEXT NOT NULL CHECK(record_type IN ('A','AAAA','PTR','CNAME')),
    value TEXT NOT NULL, ttl INTEGER NOT NULL DEFAULT 300, comment TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE custom_rules (
    id INTEGER PRIMARY KEY, domain TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('allow','block')),
    enabled INTEGER NOT NULL DEFAULT 1, comment TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE notification_providers (
    id INTEGER PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, config_json TEXT NOT NULL DEFAULT '{}',
    secret TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE upstream_resolvers (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK(protocol IN ('plain','dot','doh')),
    address TEXT NOT NULL, port INTEGER NOT NULL, doh_path TEXT NOT NULL DEFAULT '',
    tls_hostname TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
    position INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE policy_profiles (
    key TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    is_custom INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE network_policies (
    id INTEGER PRIMARY KEY, cidr TEXT NOT NULL UNIQUE, profile_key TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE access_settings (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    default_policy TEXT NOT NULL DEFAULT 'allow', updated_at TEXT NOT NULL
);
CREATE TABLE dns_cache_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE encryption_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE analytics_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE query_events (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, domain TEXT NOT NULL
);
"""


def build_v1_fixture(
    db_path: Path,
    *,
    populate: bool = True,
    local_dns_records: int = 0,
    custom_rules: int = 0,
    clients: int = 0,
    notification_providers: int = 0,
    upstream_protocol: str | None = None,
    dot_enabled: bool | None = None,
    drop_optional_tables: tuple[str, ...] = (),
) -> Path:
    """Builds a realistic V1 fixture. ``populate=True`` seeds the original
    minimal baseline shape (kept exactly as-is so existing tests are
    unaffected); the keyword-only ``*_records``/``*_rules``/``clients``/
    ``notification_providers`` knobs additionally append N extra rows of
    that kind (for "heavy" variants), ``upstream_protocol`` overrides the
    single baseline upstream's transport (``'plain'``/``'dot'``/``'doh'``),
    ``dot_enabled`` overrides the ``encryption_settings`` flag independent
    of the upstream transport (so DoT-capable-but-disabled states are
    representable), and ``drop_optional_tables`` simulates realistic older
    schema shapes that lack tables migration treats as optional (e.g. a
    pre-notifications V1 install) by omitting them entirely rather than
    leaving them empty -- "missing table" and "empty table" are different
    real states and migration must tolerate both.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(_SCHEMA)
        if populate:
            conn.execute(
                "INSERT INTO admins VALUES (1, 'admin', "
                "'$argon2id$v=19$m=65536,t=4,p=2$abcdefghijklmnop$hashedvaluehere', "
                "'2026-01-01T00:00:00')"
            )
            conn.execute(
                "INSERT INTO clients VALUES (1, 'Kids Laptop', 'desc', 1, "
                "'2026-01-01T00:00:00', '2026-01-01T00:00:00')"
            )
            conn.execute(
                "INSERT INTO client_identifiers VALUES (1, 1, 'ipv4', '10.0.0.50', "
                "'2026-01-01T00:00:00')"
            )
            conn.execute(
                "INSERT INTO access_rules VALUES (1, 'allow', 'ipv4', '10.0.0.50', 1, "
                "'2026-01-01T00:00:00')"
            )
            conn.execute(
                "INSERT INTO local_dns_records VALUES (1, 'nas', 'nas.lan', 'A', "
                "'10.0.0.10', 300, '', 1, '2026-01-01T00:00:00', '2026-01-01T00:00:00')"
            )
            conn.execute(
                "INSERT INTO local_dns_records VALUES (2, 'printer', 'printer.lan', 'A', "
                "'10.0.0.20', 300, '', 1, '2026-01-01T00:00:00', '2026-01-01T00:00:00')"
            )
            conn.execute(
                "INSERT INTO custom_rules VALUES (1, 'ads.example', 'block', 1, '', "
                "'2026-01-01T00:00:00')"
            )
            conn.execute(
                "INSERT INTO custom_rules VALUES (2, 'good.example', 'allow', 1, '', "
                "'2026-01-01T00:00:00')"
            )
            conn.execute(
                "INSERT INTO notification_providers VALUES (1, 'webhook', 'Ops Webhook', 1, "
                "'{\"url\": \"https://hooks.example/notify\"}', 'super-secret-token-abc', "
                "'2026-01-01T00:00:00', '2026-01-01T00:00:00')"
            )
            conn.execute(
                "INSERT INTO upstream_resolvers VALUES (1, 'Cloudflare', 'dot', "
                "'1.1.1.1', 853, '', 'cloudflare-dns.com', 1, 0, "
                "'2026-01-01T00:00:00', '2026-01-01T00:00:00')"
            )
            conn.execute("INSERT INTO policy_profiles VALUES ('default', 'Default', '', 0)")
            conn.execute(
                "INSERT INTO network_policies VALUES (1, '10.0.0.0/24', 'default', '', 1)"
            )
            conn.execute(
                "INSERT INTO access_settings VALUES (1, 'allow', '2026-01-01T00:00:00')"
            )
            conn.execute("INSERT INTO dns_cache_settings VALUES ('max_cache_size_mb', '500')")
            conn.execute("INSERT INTO encryption_settings VALUES ('dot_enabled', 'true')")
            conn.execute("INSERT INTO analytics_settings VALUES ('retention_days', '30')")
            if upstream_protocol and upstream_protocol != "dot":
                port = {"plain": 53, "doh": 443}[upstream_protocol]
                doh_path = "/dns-query" if upstream_protocol == "doh" else ""
                conn.execute(
                    "UPDATE upstream_resolvers SET protocol=?, port=?, doh_path=? WHERE id=1",
                    (upstream_protocol, port, doh_path),
                )
            if dot_enabled is not None:
                conn.execute(
                    "UPDATE encryption_settings SET value=? WHERE key='dot_enabled'",
                    ("true" if dot_enabled else "false",),
                )
            for i in range(local_dns_records):
                n = 3 + i
                conn.execute(
                    "INSERT INTO local_dns_records VALUES (?, ?, ?, 'A', ?, 300, '', 1, "
                    "'2026-01-01T00:00:00', '2026-01-01T00:00:00')",
                    (n, f"host{n}", f"host{n}.lan", f"10.0.1.{n % 250}"),
                )
            for i in range(custom_rules):
                n = 3 + i
                action = "block" if i % 2 == 0 else "allow"
                conn.execute(
                    "INSERT INTO custom_rules VALUES (?, ?, ?, 1, '', '2026-01-01T00:00:00')",
                    (n, f"rule{n}.example", action),
                )
            for i in range(clients):
                n = 2 + i
                conn.execute(
                    "INSERT INTO clients VALUES (?, ?, '', 1, '2026-01-01T00:00:00', "
                    "'2026-01-01T00:00:00')",
                    (n, f"Client {n}"),
                )
                conn.execute(
                    "INSERT INTO client_identifiers VALUES (?, ?, 'ipv4', ?, "
                    "'2026-01-01T00:00:00')",
                    (100 + n, n, f"10.0.2.{n % 250}"),
                )
            for i in range(notification_providers):
                n = 2 + i
                conn.execute(
                    "INSERT INTO notification_providers VALUES (?, 'webhook', ?, 1, "
                    "'{}', ?, '2026-01-01T00:00:00', '2026-01-01T00:00:00')",
                    (n, f"Extra Webhook {n}", f"extra-secret-token-{n}"),
                )
            for i in range(50):
                conn.execute(
                    "INSERT INTO query_events (ts, domain) VALUES (?, ?)",
                    (1700000000.0 + i, f"host{i}.example"),
                )
        for table in drop_optional_tables:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.commit()
    finally:
        conn.close()
    return db_path
