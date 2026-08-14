#!/usr/bin/env python3
"""Alderpoint DNS blocklist downloader, parser, RPZ compiler, and deployer."""

from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import datetime as dt
import email
import fcntl
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

try:
    from app import backup, clients, custom_rules, dns_cache, encryption, filter_schedule, local_dns, network_config, replication, service_logs, software_updates, upstream_dns
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app import backup, clients, custom_rules, dns_cache, encryption, filter_schedule, local_dns, network_config, replication, service_logs, software_updates, upstream_dns


DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
DEFAULT_DB_PATH = DB_PATH
DOWNLOAD_DIR = Path("/var/lib/alderpointdns/downloads")
COMPILED_RPZ = Path("/var/lib/alderpointdns/compiled/bind/alderpointdns.rpz")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
DEPLOY_LOCK = Path("/var/lib/alderpointdns/staging/deploy.lock")
MIGRATION_LOCK = Path("/var/lib/alderpointdns/staging/schema-migration.lock")
CLI_ERROR_LOG = Path("/var/log/alderpointdns/compiler-errors.log")
MIGRATION_THREAD_LOCK = threading.Lock()
MAX_SOURCE_BYTES = 25 * 1024 * 1024
CONNECT_TIMEOUT = 10
TOTAL_TIMEOUT = 60
RPZ_ZONE = "alderpointdns.rpz"
DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.?$")

# Hostnames that identify the local machine itself, not a real domain to
# block. Some public hosts-format blocklists carry these (mirroring
# /etc/hosts convention) even though they have no meaning as a DNS block.
LOCALHOST_ALIASES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})

# AdGuard's own hosted DNS-filter registry (e.g. the "AdGuard DNS Popup
# Hosts filter" source) rewrites known ad/pop-up domains to this CNAME
# landing page via `$dnsrewrite=ad-block.dns.adguard.com` instead of a plain
# `||domain^` block. Alderpoint DNS's blocklist pipeline has no per-source
# CNAME/landing-page concept, so -- as an explicit, documented policy choice
# -- exact matches on this specific, known AdGuard target are normalized to
# an ordinary block instead of being reported unsupported. Any other
# hostname-target $dnsrewrite is left to the shared custom-rule parser's
# normal modifier handling, which reports it unsupported with a reason.
ADGUARD_DNSREWRITE_BLOCKPAGE_TARGETS = frozenset({"ad-block.dns.adguard.com"})

HEALTH_HEALTHY = "healthy"
HEALTH_HEALTHY_REDUNDANT = "healthy_redundant"
HEALTH_WARNING = "warning"
HEALTH_UNSUPPORTED_FORMAT = "unsupported_format"
HEALTH_ERROR = "error"
HEALTH_USING_CACHED = "using_cached"
HEALTH_PENDING = "pending"
HEALTH_DISABLED = "disabled"

HEALTH_LABELS = {
    HEALTH_HEALTHY: "Healthy",
    HEALTH_HEALTHY_REDUNDANT: "Healthy, redundant",
    HEALTH_WARNING: "Warning",
    HEALTH_UNSUPPORTED_FORMAT: "Unsupported format",
    HEALTH_ERROR: "Error",
    HEALTH_USING_CACHED: "Using cached copy",
    HEALTH_PENDING: "Pending",
    HEALTH_DISABLED: "Disabled",
}

HEALTH_TONES = {
    HEALTH_HEALTHY: "healthy",
    HEALTH_HEALTHY_REDUNDANT: "healthy",
    HEALTH_WARNING: "degraded",
    HEALTH_UNSUPPORTED_FORMAT: "degraded",
    HEALTH_ERROR: "down",
    HEALTH_USING_CACHED: "degraded",
    HEALTH_PENDING: "unavailable",
    HEALTH_DISABLED: "unavailable",
}


class AlderpointDNSConnection(sqlite3.Connection):
    """Closes on exit like a plain connection factory would, but only once
    the outermost `with` block exits -- callers that reuse an already-open
    connection as its own nested `with conn: ...` transaction boundary (a
    common pattern for grouping a subset of statements into one commit)
    would otherwise have the connection closed out from under them by the
    first nested block's __exit__, breaking every statement after it."""

    def __enter__(self):
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 0) + 1
        return super().__enter__()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        super().__exit__(exc_type, exc_value, traceback)
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 1) - 1
        if self._alderpointdns_depth <= 0:
            self.close()


@dataclass
class ParseStats:
    downloaded_entries: int = 0
    parsed_rules: int = 0
    accepted_domains: int = 0
    duplicate_domains: int = 0
    invalid_rules: int = 0
    unsupported_rules: int = 0
    unique_active_domains: int = 0
    exceptions: int = 0
    # Sample rejected (invalid/unsupported) lines for the UI's expandable
    # details panel: {"line": N, "kind": "invalid"|"unsupported", "reason": str, "excerpt": str}.
    # Capped so a badly-formed source can't bloat the sources row.
    rejected_samples: list[dict] = field(default_factory=list)


@dataclass
class SourceResult:
    source_id: int
    name: str
    url: str
    success: bool
    http_status: int | None = None
    downloaded_bytes: int = 0
    path: Path | None = None
    error: str | None = None


@dataclass(frozen=True)
class PublicSource:
    name: str
    url: str
    category: str


@dataclass(frozen=True)
class DefaultSource(PublicSource):
    upstream_project: str
    purpose: str


# Single source of truth for HaGeZi's "Multi Normal" list's URL, used by
# both DEFAULT_FRESH_INSTALL_SOURCES (the curated fresh-install seed) and
# PUBLIC_SOURCES (the broader, admin-invoked "add all suggested sources"
# catalog) below -- the raw.githubusercontent.com mirror this used to point
# at 404s; jsDelivr's @latest tag is HaGeZi's own documented primary
# Adblock link for this exact list. A shared constant, not two separately
# hand-maintained literals, is what actually prevents the two catalogs'
# entries for the same upstream list from silently drifting to different
# URLs again -- see test_hagezi_catalog_entries_share_the_same_url in
# tests/test_fresh_install_defaults.py.
HAGEZI_MULTI_NORMAL_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt"


DEFAULT_FRESH_INSTALL_SOURCES = (
    DefaultSource(
        "AdGuard DNS filter",
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "ads_trackers",
        "AdGuardTeam/AdGuardSDNSFilter",
        "EasyList/EasyPrivacy-derived DNS-compatible advertising and tracking coverage",
    ),
    DefaultSource(
        "StevenBlack Unified Hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "ads_trackers",
        "StevenBlack/hosts",
        "Unified adware and malware hosts coverage",
    ),
    DefaultSource(
        "HaGeZi Multi Normal",
        # The raw.githubusercontent.com mirror of this file currently
        # 404s. jsDelivr's @latest tag is HaGeZi's own documented primary
        # Adblock link for this exact list and mirrors the same content.
        # PUBLIC_SOURCES' own "HaGeZi Multi Normal" entry below must use
        # this same URL -- see
        # HAGEZI_MULTI_NORMAL_URL/test_hagezi_catalog_entries_share_the_same_url
        # in tests/test_fresh_install_defaults.py, which pins both against
        # drifting apart again.
        HAGEZI_MULTI_NORMAL_URL,
        "ads_trackers",
        "hagezi/dns-blocklists",
        "Balanced ads, tracking, telemetry, device, mobile tracker, phishing, and malware coverage",
    ),
)


PUBLIC_SOURCES = (
    PublicSource("AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "ads_trackers"),
    PublicSource("OISD Blocklist Big", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt", "ads_trackers"),
    PublicSource("1Hosts Lite", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt", "ads_trackers"),
    PublicSource("StevenBlack Unified Hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "ads_trackers"),
    PublicSource("HaGeZi Multi Normal", HAGEZI_MULTI_NORMAL_URL, "ads_trackers"),
    PublicSource("HaGeZi Multi Pro", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", "ads_trackers"),
    PublicSource("Peter Lowe Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt", "ads_trackers"),
    PublicSource("Dan Pollock Hosts", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt", "ads_trackers"),
    PublicSource("AWAvenue Ads Rule", "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt", "ads_trackers"),
    PublicSource("AdGuard Popup Hosts", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_59.txt", "ads_trackers"),
    PublicSource("OISD Blocklist Small", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt", "ads_trackers"),
    PublicSource("ShadowWhisperer Tracking", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking", "ads_trackers"),
    PublicSource("URLHaus Malicious URL Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt", "malware"),
    PublicSource("Dandelion Sprout Anti-Malware", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt", "malware"),
    PublicSource("Phishing Army", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt", "malware"),
    PublicSource("Stalkerware Indicators", "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts", "malware"),
    PublicSource("ShadowWhisperer Malware", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware", "malware"),
    PublicSource("HaGeZi Threat Intelligence Feeds", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt", "malware"),
    PublicSource("uBlock Badware Risks", "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt", "malware"),
)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def slug(text: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_.-]+", "-", text.strip().lower()).strip("-")
    return value or hashlib.sha256(text.encode()).hexdigest()[:16]


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, factory=AlderpointDNSConnection, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN "{column}" {definition}')


SCHEMA_VERSION = 3
PARSER_CACHE_VERSION = "2026-08-09-v1-parser-fastpath"
POLICY_CACHE_VERSION = "2026-08-09-v1-policy-manifest"
PROTECTION_REUSE_UNAVAILABLE = 2


def source_parse_cache_dir() -> Path:
    return DOWNLOAD_DIR / "parse-cache"


def protection_cache_paths() -> tuple[Path, Path]:
    cache_dir = COMPILED_RPZ.parent / "policy-cache"
    return cache_dir / "protection-current.rpz", cache_dir / "protection-current.manifest.json"


@contextlib.contextmanager
def migration_lock():
    """Interprocess lock (flock) so two processes -- e.g. the webapp's
    startup hook (running as the unprivileged alderpointdns user) and a
    concurrent root-context CLI invocation (package install/upgrade, or a
    sudo'd deploy) -- can never run schema migrations against the same
    database file at the same time.

    Opened read-only and never written to: flock() only needs an open file
    descriptor, not write access, so this works no matter which privilege
    level happens to create the lock file first (root creates it 0644 by
    default, which the unprivileged service user can still open O_RDONLY
    -- opening "w" here previously failed with PermissionError once root
    had created it first, crash-looping the web service on every startup)."""
    lock_path = MIGRATION_LOCK if DB_PATH == DEFAULT_DB_PATH else DB_PATH.parent / "schema-migration.lock"
    lock_exists = lock_path.exists()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if not lock_exists:
        try:
            lock_path.touch()
        except OSError:
            pass  # another process (of either privilege level) won the race to create it; we only need to read it
    with MIGRATION_THREAD_LOCK:
        with lock_path.open("rb") as lock_handle:
            fcntl.flock(lock_handle, fcntl.LOCK_EX)
            yield


def seed_fresh_install_defaults(conn: sqlite3.Connection) -> None:
    conn.executemany(
        """
        INSERT OR IGNORE INTO sources(name, url, enabled, category)
        VALUES (?, ?, 1, ?)
        """,
        [(source.name, source.url, source.category) for source in DEFAULT_FRESH_INSTALL_SOURCES],
    )


def has_established_database_state(conn: sqlite3.Connection) -> bool:
    """True when this DB already contains any Alderpoint-managed table.

    `PRAGMA user_version` alone cannot distinguish a genuinely new database
    from an older existing install that predates schema version stamping. A
    fresh SQLite file has no user tables before _apply_schema() runs; any
    existing user table means an install, restore, or prior failed setup has
    already established state and must not receive fresh-install defaults.
    """
    return bool(
        conn.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            LIMIT 1
            """
        ).fetchone()
    )


def _apply_schema(conn: sqlite3.Connection, *, seed_defaults: bool = False) -> None:
    """The full idempotent DDL/seed/migration script. Every statement here is
    safe to run against an already-up-to-date database (CREATE TABLE IF NOT
    EXISTS, INSERT OR IGNORE, or an ALTER-if-missing probe via
    _ensure_column), which is what makes init_db() safe to call repeatedly.
    Only called from init_db() while migration_lock() and SCHEMA_VERSION
    gating are held, so it never runs concurrently or unnecessarily.

    Includes the webapp's own auth tables (admins/sessions/login_attempts/
    admin_audit_log) alongside the compiler's schema: both live in the same
    database file, so they migrate under the same lock and version gate
    rather than webapp.py racing its own ad hoc DDL on every request."""
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            url TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            category TEXT NOT NULL DEFAULT 'ads_trackers',
            last_attempt TEXT,
            last_success TEXT,
            http_status INTEGER,
            downloaded_bytes INTEGER NOT NULL DEFAULT 0,
            parsed_rules INTEGER NOT NULL DEFAULT 0,
            accepted_domains INTEGER NOT NULL DEFAULT 0,
            duplicate_domains INTEGER NOT NULL DEFAULT 0,
            invalid_rules INTEGER NOT NULL DEFAULT 0,
            unsupported_rules INTEGER NOT NULL DEFAULT 0,
            final_active_domains INTEGER NOT NULL DEFAULT 0,
            last_error TEXT
        );
        CREATE TABLE IF NOT EXISTS custom_rules (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('allow', 'block')),
            enabled INTEGER NOT NULL DEFAULT 1,
            comment TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(domain, action)
        );
        CREATE TABLE IF NOT EXISTS deployments (
            id INTEGER PRIMARY KEY,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            active_domains INTEGER NOT NULL DEFAULT 0,
            blocked_test_domain TEXT,
            allowed_test_domain TEXT,
            message TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS categories (
            key TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS policy_profiles (
            key TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            is_custom INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS network_policies (
            id INTEGER PRIMARY KEY,
            cidr TEXT NOT NULL UNIQUE,
            profile_key TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            FOREIGN KEY(profile_key) REFERENCES policy_profiles(key)
        );
        CREATE TABLE IF NOT EXISTS profile_categories (
            profile_key TEXT NOT NULL,
            category_key TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY(profile_key, category_key),
            FOREIGN KEY(profile_key) REFERENCES policy_profiles(key),
            FOREIGN KEY(category_key) REFERENCES categories(key)
        );
        CREATE INDEX IF NOT EXISTS idx_custom_rules_domain ON custom_rules(domain);
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY,
            ip TEXT NOT NULL,
            attempted_at TEXT NOT NULL,
            success INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            admin_id INTEGER,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT,
            csrf TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS admin_audit_log (
            id INTEGER PRIMARY KEY,
            at TEXT NOT NULL,
            admin_id INTEGER,
            username TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            success INTEGER NOT NULL,
            ip TEXT,
            detail TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS source_parse_cache (
            source_id INTEGER PRIMARY KEY,
            content_sha256 TEXT NOT NULL,
            parser_version TEXT NOT NULL,
            blocks_path TEXT NOT NULL,
            allows_path TEXT NOT NULL,
            stats_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    conn.executemany(
        """
        INSERT OR IGNORE INTO categories(key, name, description)
        VALUES (?, ?, ?)
        """,
        (
            ("malware", "Malware", "Malware, phishing, scam, and threat-intelligence lists"),
            ("ads_trackers", "Ads and trackers", "Advertising, affiliate, analytics, and tracking lists"),
            ("adult_content", "Adult content", "Adult and explicit-content filtering lists"),
            ("iot_telemetry", "IoT telemetry", "Device telemetry and vendor tracking lists"),
            ("safesearch", "SafeSearch", "Search and video safety-enforcement policy"),
            ("custom", "Custom categories", "Operator-defined categories and local rules"),
        ),
    )
    conn.executemany(
        """
        INSERT OR IGNORE INTO policy_profiles(key, name, description, is_custom)
        VALUES (?, ?, ?, 0)
        """,
        (
            ("trusted", "Trusted", "Minimal policy for trusted administrator devices"),
            ("standard", "Standard", "Default balanced malware, ads, and tracker protection"),
            ("iot", "IoT", "Stricter telemetry-aware policy for appliance networks"),
            ("restricted", "Restricted", "Most restrictive built-in profile for sensitive networks"),
        ),
    )
    profile_defaults = {
        "trusted": ("malware",),
        "standard": ("malware", "ads_trackers"),
        "iot": ("malware", "ads_trackers", "iot_telemetry"),
        "restricted": ("malware", "ads_trackers", "adult_content", "iot_telemetry", "safesearch"),
    }
    conn.executemany(
        """
        INSERT OR IGNORE INTO profile_categories(profile_key, category_key, enabled)
        VALUES (?, ?, 1)
        """,
        [
            (profile, category)
            for profile, categories in profile_defaults.items()
            for category in categories
        ],
    )
    # Distinguishes automatic (timer-driven) deployments from manual ones.
    # Added as an idempotent ALTER-if-missing migration so existing
    # installations pick it up on upgrade without a schema rewrite; older
    # rows keep NULL, which reads as "manual".
    _ensure_column(conn, "deployments", "trigger", "TEXT")
    # Per-source download/parse breakdown and health-state fields, added
    # as idempotent ALTER-if-missing migrations. "duplicate_domains"
    # already existed (within-source only); its meaning is widened
    # below to "did not contribute a new unique active rule" (within- or
    # cross-source), matching what the UI displays.
    _ensure_column(conn, "sources", "downloaded_entries", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "sources", "unique_active_domains", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "sources", "using_cached_copy", "INTEGER NOT NULL DEFAULT 0")
    _ensure_column(conn, "sources", "last_compile_success", "TEXT")
    _ensure_column(conn, "sources", "last_warning", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "sources", "rejected_samples", "TEXT NOT NULL DEFAULT '[]'")
    if seed_defaults:
        seed_fresh_install_defaults(conn)
    local_dns.init_db(conn)
    filter_schedule.init_db(conn)
    custom_rules.init_db(conn)
    clients.init_db(conn)


def init_db(*, seed_defaults: bool = False) -> bool:
    """Idempotent, interprocess-lock-protected schema migration entrypoint.

    Cheap no-op once the database is already at SCHEMA_VERSION (a single
    connection open + one PRAGMA read), so it is safe to call from every CLI
    subcommand, package install/upgrade, and the webapp's startup hook alike
    -- but it must never be called from the ordinary per-request database
    path, since that would repeat the (comparatively expensive) migration
    work on every request instead of once per process lifetime."""
    with migration_lock():
        with connect() as conn:
            current_version = conn.execute("PRAGMA user_version").fetchone()[0]
            established_state = has_established_database_state(conn)
            if current_version >= SCHEMA_VERSION:
                return False
            genuinely_fresh = seed_defaults and current_version == 0 and not established_state
            if genuinely_fresh:
                _apply_schema(conn, seed_defaults=True)
            else:
                _apply_schema(conn)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            return genuinely_fresh if seed_defaults else True


def normalize_domain(raw: str) -> str | None:
    value = raw.strip().strip(".").lower()
    if not value or len(value) > 253:
        return None
    if "://" in value or "/" in value or ":" in value or "@" in value:
        return None
    if not value.isascii():
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not DOMAIN_RE.match(value + "."):
        return None
    if _looks_like_ip_literal(value):
        try:
            ipaddress.ip_address(value)
            return None
        except ValueError:
            pass
    return value


def _adguard_blockpage_normalize(text: str) -> str:
    """Strips `$dnsrewrite=<target>` when it is the line's *only* modifier
    and the target is a recognized AdGuard block-page CNAME (see
    ADGUARD_DNSREWRITE_BLOCKPAGE_TARGETS), turning the line back into a
    plain `||domain^`/`|domain^` block before the shared parser sees it.
    Any other modifier combination -- including this same target combined
    with another modifier -- is left untouched and handled (as unsupported,
    for a hostname dnsrewrite target) by custom_rules.parse_rule below."""
    if "$dnsrewrite=" not in text:
        return text
    head, sep, modifiers = text.partition("$")
    if not sep:
        return text
    modifiers = modifiers.strip()
    for target in ADGUARD_DNSREWRITE_BLOCKPAGE_TARGETS:
        if modifiers == f"dnsrewrite={target}":
            return head.strip()
    return text


def _is_hosts_line(first_token: str) -> bool:
    if not _could_be_ip_literal(first_token):
        return False
    try:
        ipaddress.ip_address(first_token)
        return True
    except ValueError:
        return False


def _could_be_ip_literal(value: str) -> bool:
    if not value:
        return False
    first = value[0]
    return first.isdigit() or first == ":" or ":" in value


def _looks_like_ip_literal(value: str) -> bool:
    if ":" in value:
        return True
    if "." not in value:
        return False
    return all(part.isdigit() for part in value.split(".") if part)


_FAST_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def _fast_common_source_rule(raw: str) -> list[tuple[str, str | None, str]] | None:
    """Fast path for the overwhelmingly common source-list rule shapes.

    Anything with modifiers, paths, regex/cosmetic syntax, wildcards, or other
    ambiguity falls back to custom_rules.parse_rule(), preserving its exact
    validation behavior for complex AdGuard/Pi-hole syntax.
    """
    is_allow = raw.startswith("@@")
    body = raw[2:] if is_allow else raw
    candidate: str | None = None
    if body.startswith("||") and body.endswith("^") and body.count("^") == 1:
        candidate = body[2:-1]
    elif body.startswith("|") and body.endswith("^") and body.count("^") == 1:
        candidate = body[1:-1]
    elif not is_allow and all(ch in _FAST_DOMAIN_CHARS for ch in body):
        candidate = body
    elif is_allow and all(ch in _FAST_DOMAIN_CHARS for ch in body):
        candidate = body
    if not candidate or not all(ch in _FAST_DOMAIN_CHARS for ch in candidate):
        return None
    domain = normalize_domain(candidate)
    if domain is None:
        return None
    return [("allow" if is_allow else "block", domain, "")]


def parse_source_line(raw: str) -> list[tuple[str, str | None, str]]:
    """Classifies one already-stripped, non-blank, non-full-line-comment
    source line into zero or more (kind, domain, reason) results, where
    kind is one of: skip, block, allow, invalid, unsupported. A hosts-format
    line with multiple hostnames yields one result per hostname.

    Hosts-format lines (`<address> <hostname...>`) are handled directly: for
    blocklist sources the address is always a sinkhole marker (0.0.0.0,
    127.0.0.1, ::, ::0, 0:0:0:0:0:0:0:0, ...), never an intentional rewrite
    target, so every address form blocks the domain -- unlike custom user
    rules (app/custom_rules.py), which treat a non-zero/non-`::` address as
    a deliberate local rewrite. Everything else (AdBlock/AdGuard syntax,
    including $dnsrewrite modifiers) is delegated to
    custom_rules.parse_rule, the same parser used for user-supplied custom
    filtering rules, so blocklist sources and custom rules share one
    AdBlock-syntax implementation instead of two incompatible ones.
    """
    first_token = raw.split(None, 1)[0] if raw else ""
    if _is_hosts_line(first_token):
        body, _, _inline = raw.partition("#")
        parts = body.split()
        if len(parts) < 2:
            return [("invalid", None, "hosts entry has no hostname")]
        results: list[tuple[str, str | None, str]] = []
        for host in parts[1:]:
            # Checked against the raw token first: normalize_domain rejects
            # single-label names outright (no dot), which would otherwise
            # misreport "localhost"/"ip6-localhost"/"ip6-loopback" as
            # invalid instead of the intentional, silent skip these
            # /etc/hosts-style aliases are supposed to get.
            if host.strip(".").lower() in LOCALHOST_ALIASES:
                results.append(("skip", None, ""))
                continue
            domain = normalize_domain(host)
            if domain is None:
                results.append(("invalid", None, f"'{host}' is not a valid hostname"))
                continue
            if domain in LOCALHOST_ALIASES:
                results.append(("skip", None, ""))
                continue
            results.append(("block", domain, ""))
        return results

    normalized = _adguard_blockpage_normalize(raw)
    common = _fast_common_source_rule(normalized)
    if common is not None:
        return common
    parsed = custom_rules.parse_rule(normalized, plain_domain_subdomains=True)
    results = []
    for rule in parsed:
        if rule.rule_type == "comment":
            continue
        if rule.validation_state == "invalid":
            results.append(("invalid", None, rule.unsupported_reason))
        elif rule.validation_state == "unsupported":
            results.append(("unsupported", None, rule.unsupported_reason))
        elif rule.rule_type in ("regex_block", "regex_allow"):
            # Blocklist sources contribute to plain domain sets only; a
            # POSIX-ERE regex rule has no `domain`, and RPZ regex matching
            # is a dnsdist-layer, custom-rule-only feature (app/custom_rules.py).
            results.append(("unsupported", None, "regex rules are not supported for blocklist sources"))
        elif rule.rule_type == "rewrite":
            # Only reachable for a non-hosts line carrying an IP-address
            # $dnsrewrite (e.g. "||host.example^$dnsrewrite=1.2.3.4");
            # blocklist sources have no rewrite/Local-DNS concept, so this
            # is reported rather than silently creating an address record.
            results.append(("unsupported", None, "modifier $dnsrewrite to an IP address is not supported for blocklist sources"))
        elif rule.domain in LOCALHOST_ALIASES:
            results.append(("skip", None, ""))
        else:
            results.append((rule.action, rule.domain, ""))
    return results


def parse_rule_lines(lines) -> tuple[set[str], set[str], ParseStats]:
    blocks: set[str] = set()
    allows: set[str] = set()
    stats = ParseStats()
    for line_number, line in enumerate(lines, 1):
        raw = line.strip()
        if not raw or raw.startswith("#") or raw.startswith("!") or raw.startswith("//"):
            continue
        if raw.startswith("[") and raw.endswith("]"):
            continue
        stats.downloaded_entries += 1
        for kind, domain, reason in parse_source_line(raw):
            if kind == "skip":
                continue
            if kind in ("invalid", "unsupported"):
                if kind == "invalid":
                    stats.invalid_rules += 1
                else:
                    stats.unsupported_rules += 1
                if len(stats.rejected_samples) < 20:
                    stats.rejected_samples.append(
                        {
                            "line": line_number,
                            "kind": kind,
                            "reason": reason or f"{kind} entry",
                            "excerpt": raw[:120],
                        }
                    )
                continue
            stats.parsed_rules += 1
            target = allows if kind == "allow" else blocks
            if domain in target:
                continue
            target.add(domain)
            stats.accepted_domains += 1
            if kind == "allow":
                stats.exceptions += 1
    # Within-source duplicates only (lines repeated inside this one source).
    # collect_rules() overwrites this with the fuller, cross-source-aware
    # figure once every enabled source's domains are known; a bare
    # parse_rules() call on a single source's content still gets a
    # meaningful number instead of always reading 0.
    stats.unique_active_domains = len(blocks)
    stats.duplicate_domains = stats.parsed_rules - stats.accepted_domains
    return blocks, allows, stats


def parse_rules(content: str) -> tuple[set[str], set[str], ParseStats]:
    return parse_rule_lines(content.splitlines())


def source_paths(source: sqlite3.Row) -> tuple[Path, Path]:
    name = f"{source['id']}-{slug(source['name'])}.txt"
    return DOWNLOAD_DIR / "current" / name, DOWNLOAD_DIR / "staging" / name


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stats_to_json(stats: ParseStats) -> str:
    return json.dumps(
        {
            "downloaded_entries": stats.downloaded_entries,
            "parsed_rules": stats.parsed_rules,
            "accepted_domains": stats.accepted_domains,
            "duplicate_domains": stats.duplicate_domains,
            "invalid_rules": stats.invalid_rules,
            "unsupported_rules": stats.unsupported_rules,
            "unique_active_domains": stats.unique_active_domains,
            "exceptions": stats.exceptions,
            "rejected_samples": stats.rejected_samples[:20],
        },
        sort_keys=True,
    )


def _stats_from_json(text: str) -> ParseStats:
    data = json.loads(text)
    return ParseStats(
        downloaded_entries=int(data.get("downloaded_entries", 0)),
        parsed_rules=int(data.get("parsed_rules", 0)),
        accepted_domains=int(data.get("accepted_domains", 0)),
        duplicate_domains=int(data.get("duplicate_domains", 0)),
        invalid_rules=int(data.get("invalid_rules", 0)),
        unsupported_rules=int(data.get("unsupported_rules", 0)),
        unique_active_domains=int(data.get("unique_active_domains", 0)),
        exceptions=int(data.get("exceptions", 0)),
        rejected_samples=list(data.get("rejected_samples", []))[:20],
    )


def _read_domain_artifact(path: Path) -> set[str]:
    if not path.exists():
        raise FileNotFoundError(path)
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def _write_domain_artifact(path: Path, domains: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{domain}\n" for domain in sorted(domains)))


def parse_source_file(conn: sqlite3.Connection, source: sqlite3.Row, path: Path) -> tuple[set[str], set[str], ParseStats]:
    content_hash = file_sha256(path)
    cache = conn.execute(
        """
        SELECT * FROM source_parse_cache
        WHERE source_id=? AND content_sha256=? AND parser_version=?
        """,
        (source["id"], content_hash, PARSER_CACHE_VERSION),
    ).fetchone()
    if cache:
        try:
            blocks = _read_domain_artifact(Path(cache["blocks_path"]))
            allows = _read_domain_artifact(Path(cache["allows_path"]))
            stats = _stats_from_json(cache["stats_json"])
            return blocks, allows, stats
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass

    with path.open("r", errors="replace") as handle:
        blocks, allows, stats = parse_rule_lines(handle)
    cache_dir = source_parse_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    prefix = cache_dir / f"{source['id']}-{content_hash}"
    blocks_path = prefix.with_suffix(".blocks")
    allows_path = prefix.with_suffix(".allows")
    _write_domain_artifact(blocks_path, blocks)
    _write_domain_artifact(allows_path, allows)
    conn.execute(
        """
        INSERT INTO source_parse_cache(
            source_id, content_sha256, parser_version, blocks_path, allows_path, stats_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_id) DO UPDATE SET
            content_sha256=excluded.content_sha256,
            parser_version=excluded.parser_version,
            blocks_path=excluded.blocks_path,
            allows_path=excluded.allows_path,
            stats_json=excluded.stats_json,
            updated_at=excluded.updated_at
        """,
        (source["id"], content_hash, PARSER_CACHE_VERSION, str(blocks_path), str(allows_path), _stats_to_json(stats), now()),
    )
    return blocks, allows, stats


def download_source(source: sqlite3.Row) -> SourceResult:
    current_path, staging_path = source_paths(source)
    current_path.parent.mkdir(parents=True, exist_ok=True)
    staging_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    result = SourceResult(source["id"], source["name"], source["url"], False)
    req = urllib.request.Request(source["url"], headers={"User-Agent": "Alderpoint DNS/1"})
    try:
        with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT) as response:
            result.http_status = getattr(response, "status", None)
            with staging_path.open("wb") as handle:
                while True:
                    if time.monotonic() - started > TOTAL_TIMEOUT:
                        raise TimeoutError("source download exceeded total timeout")
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    result.downloaded_bytes += len(chunk)
                    if result.downloaded_bytes > MAX_SOURCE_BYTES:
                        raise ValueError(f"source exceeds {MAX_SOURCE_BYTES} byte limit")
                    handle.write(chunk)
        os.replace(staging_path, current_path)
        result.success = True
        result.path = current_path
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        result.error = str(exc)
        if current_path.exists():
            result.path = current_path
    return result


def record_download_result(conn: sqlite3.Connection, result: SourceResult, using_cached_copy: bool) -> None:
    """Records the outcome of an actual network download attempt only.
    Never called for a no-download (cache-only) recompute pass, so it can
    never clobber a real attempt's http_status/downloaded_bytes/last_error
    with the placeholder values a cache-only pass would otherwise produce."""
    fields = {
        "last_attempt": now(),
        "http_status": result.http_status,
        "downloaded_bytes": result.downloaded_bytes,
        "last_error": result.error,
        "using_cached_copy": 1 if using_cached_copy else 0,
    }
    if result.success:
        fields["last_success"] = now()
    assignments = ", ".join(f"{key}=:{key}" for key in fields)
    fields["id"] = result.source_id
    conn.execute(f"UPDATE sources SET {assignments} WHERE id=:id", fields)


def record_parse_stats(conn: sqlite3.Connection, source_id: int, stats: ParseStats) -> None:
    warning_parts = []
    if stats.invalid_rules:
        warning_parts.append(f"{stats.invalid_rules} invalid")
    if stats.unsupported_rules:
        warning_parts.append(f"{stats.unsupported_rules} unsupported")
    last_warning = (", ".join(warning_parts) + " entries") if warning_parts else ""
    fields = {
        "downloaded_entries": stats.downloaded_entries,
        "parsed_rules": stats.parsed_rules,
        "accepted_domains": stats.accepted_domains,
        "duplicate_domains": stats.duplicate_domains,
        "invalid_rules": stats.invalid_rules,
        "unsupported_rules": stats.unsupported_rules,
        "unique_active_domains": stats.unique_active_domains,
        "rejected_samples": json.dumps(stats.rejected_samples[:20]),
        "last_warning": last_warning,
    }
    assignments = ", ".join(f"{key}=:{key}" for key in fields)
    fields["id"] = source_id
    conn.execute(f"UPDATE sources SET {assignments} WHERE id=:id", fields)


def enabled_sources(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM sources WHERE enabled=1 ORDER BY id"))


def collect_rules(conn: sqlite3.Connection, download: bool) -> tuple[set[str], set[str], dict[int, ParseStats], list[str]]:
    """Downloads and parses every enabled source, then writes the run's
    outcome in a single short transaction at the very end. Downloading and
    parsing N sources can take much longer than SQLite's busy_timeout, so no
    write transaction is opened on `conn` until all of that slow I/O has
    already finished -- record_download_result()/record_parse_stats() below
    are deferred rather than interleaved into the download loop, so a
    blocklist update never holds the database-wide writer lock across a
    sequence of network downloads."""
    all_blocks: set[str] = set()
    all_allows: set[str] = set()
    per_source: dict[int, ParseStats] = {}
    per_source_blocks: dict[int, set[str]] = {}
    errors: list[str] = []
    pending: list[tuple[sqlite3.Row, SourceResult]] = []
    download_results: list[tuple[SourceResult, bool]] = []

    for source in enabled_sources(conn):
        if download:
            result = download_source(source)
            using_cached = (not result.success) and bool(result.path and result.path.exists())
            download_results.append((result, using_cached))
        else:
            current_path, _ = source_paths(source)
            result = SourceResult(source["id"], source["name"], source["url"], current_path.exists(), path=current_path)
        pending.append((source, result))

    for source, result in pending:
        stats = ParseStats()
        if result.path and result.path.exists():
            blocks, allows, stats = parse_source_file(conn, source, result.path)
            all_blocks.update(blocks)
            all_allows.update(allows)
            per_source_blocks[source["id"]] = blocks
        else:
            per_source_blocks[source["id"]] = set()
        if result.error:
            errors.append(f"{result.name}: {result.error}")
        per_source[source["id"]] = stats

    # A source's "unique active rules contributed" is processed in stable
    # source-id order (pending preserves enabled_sources' ORDER BY id): a
    # domain counts toward a source's own unique contribution only if no
    # earlier-processed enabled source's block list already carried it. The
    # IPv4 and IPv6 editions of the same upstream list legitimately mirror
    # each other's domain set -- whichever was added to Alderpoint DNS
    # first (typically the IPv4 edition) "owns" the domains, and the
    # second, added-later edition is expected to show zero unique
    # contribution -- "healthy, redundant" rather than "0 rules".
    seen_domains: set[str] = set()
    for source, _result in pending:
        stats = per_source[source["id"]]
        blocks = per_source_blocks[source["id"]]
        new_domains = blocks - seen_domains
        stats.unique_active_domains = len(new_domains)
        seen_domains.update(blocks)
        # "Duplicates" as shown to the operator bundles both kinds of
        # non-contribution into one number: lines repeated within this same
        # source (parsed_rules - accepted_domains) plus this source's own
        # deduped block domains that an earlier-processed source already
        # contributed (len(blocks) - unique_active_domains). This keeps
        # parsed == duplicates + unique_active_domains true for the common
        # (no exceptions) case, matching the "347 parsed / 347 duplicates /
        # 0 unique rules contributed" healthy-redundant display.
        stats.duplicate_domains = (stats.parsed_rules - stats.accepted_domains) + (len(blocks) - stats.unique_active_domains)

    # Custom rules no longer merge into the external sets here; the deploy
    # path reads only custom_filter_rules through custom_rules.collect_active
    # and applies subdomain-aware allow subtraction on top of this result.
    active_blocks = all_blocks - all_allows

    # Everything above this point is pure computation and I/O against the
    # filesystem/network, not the database. This is the one short write
    # transaction for the whole run, committed immediately so it does not
    # remain open into whatever the caller does next (RPZ validation,
    # subprocess calls, service restarts, DNS test queries).
    for result, using_cached in download_results:
        record_download_result(conn, result, using_cached)
    for source, _result in pending:
        record_parse_stats(conn, source["id"], per_source[source["id"]])
    conn.execute(
        "UPDATE sources SET final_active_domains=? WHERE enabled=1",
        (len(active_blocks),),
    )
    conn.commit()
    return active_blocks, all_allows, per_source, errors


def source_health(source: sqlite3.Row) -> dict[str, str]:
    """Derives the display health state for one source row from its stored
    download/parse counters, instead of the old "Healthy unless last_error
    is set" rule that reported a real download success with an unsupported
    or entirely-redundant source as plain Healthy alongside 0 rules."""
    if not source["enabled"]:
        state = HEALTH_DISABLED
        return {"state": state, "label": HEALTH_LABELS[state], "tone": HEALTH_TONES[state]}
    if not source["last_success"]:
        state = HEALTH_ERROR if source["last_error"] else HEALTH_PENDING
        return {"state": state, "label": HEALTH_LABELS[state], "tone": HEALTH_TONES[state]}

    downloaded = source["downloaded_entries"] or 0
    parsed = source["parsed_rules"] or 0
    invalid = source["invalid_rules"] or 0
    unsupported = source["unsupported_rules"] or 0
    unique = source["unique_active_domains"] or 0
    using_cached = bool(source["using_cached_copy"])

    if source["last_error"]:
        # A failed download attempt that still has a previously-successful
        # cached copy on disk keeps contributing that copy's parsed rules
        # (collect_rules re-parses the cached file regardless of download
        # outcome) -- distinguish that from a hard failure with nothing to
        # fall back on.
        state = HEALTH_USING_CACHED if using_cached else HEALTH_ERROR
        return {"state": state, "label": HEALTH_LABELS[state], "tone": HEALTH_TONES[state]}
    if downloaded and parsed == 0:
        state = HEALTH_UNSUPPORTED_FORMAT
    elif invalid or unsupported:
        state = HEALTH_WARNING
    elif parsed and unique == 0:
        state = HEALTH_HEALTHY_REDUNDANT
    else:
        state = HEALTH_HEALTHY
    return {"state": state, "label": HEALTH_LABELS[state], "tone": HEALTH_TONES[state]}


def rpz_name(domain: str) -> str:
    return domain.rstrip(".")


def render_rpz(domains: set[str], custom: custom_rules.ActiveRuleSet | None = None) -> str:
    serial = str(int(time.time()))
    lines = [
        "$TTL 2h",
        f"@ IN SOA localhost. hostmaster.localhost. {serial} 1h 15m 30d 2h",
        "@ IN NS localhost.",
        "",
    ]
    occupied: set[str] = set()
    if custom is not None:
        custom_lines, occupied = custom_rules.rpz_records(custom)
        lines.extend(custom_lines)
    for domain in sorted(domains):
        name = rpz_name(domain)
        if name not in occupied:
            lines.append(f"{name} CNAME .")
        if f"*.{name}" not in occupied:
            lines.append(f"*.{name} CNAME .")
    return "\n".join(lines) + "\n"


def refresh_rpz_serial(rpz_text: str) -> str:
    serial = str(int(time.time()))
    return re.sub(
        r"(@\s+IN\s+SOA\s+localhost\.\s+hostmaster\.localhost\.\s+)\d+(\s+1h\s+15m\s+30d\s+2h)",
        rf"\g<1>{serial}\2",
        rpz_text,
        count=1,
    )


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)


def validate_rpz(path: Path) -> None:
    run(["named-checkzone", RPZ_ZONE, str(path)])


def validate_bind() -> None:
    run(["named-checkconf", "-p", "/etc/bind/named.conf"])


def reload_bind() -> None:
    run(["rndc", "reload", RPZ_ZONE])


def restore_rpz_backup_for_rollback(backup_path: Path) -> None:
    rpz_text = refresh_rpz_serial(backup_path.read_text())
    COMPILED_RPZ.parent.mkdir(parents=True, exist_ok=True)
    COMPILED_RPZ.write_text(rpz_text)
    reload_bind()


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())


def _canonical_rows(conn: sqlite3.Connection, table: str, columns: list[str], order_by: str) -> list[dict[str, object]]:
    if not _table_exists(conn, table):
        return []
    selected = ", ".join(f'"{column}"' for column in columns)
    return [
        {column: row[column] for column in columns}
        for row in conn.execute(f"SELECT {selected} FROM {table} ORDER BY {order_by}")
    ]


def protection_policy_manifest(conn: sqlite3.Connection) -> dict[str, object] | None:
    """Canonical inputs that materially affect the compiled protection policy.

    Returning None means reuse cannot be proven safe and callers must run the
    ordinary rebuild/deploy path.
    """
    sources = []
    for source in conn.execute("SELECT id, name, url, enabled, category FROM sources ORDER BY id"):
        item = dict(source)
        if source["enabled"]:
            current_path, _ = source_paths(source)
            if not current_path.exists():
                return None
            item["content_sha256"] = file_sha256(current_path)
        else:
            item["content_sha256"] = None
        sources.append(item)
    manifest = {
        "policy_cache_version": POLICY_CACHE_VERSION,
        "parser_cache_version": PARSER_CACHE_VERSION,
        "rpz_zone": RPZ_ZONE,
        "sources": sources,
        "custom_filter_rules": _canonical_rows(
            conn,
            "custom_filter_rules",
            [
                "id",
                "rule_text",
                "normalized",
                "rule_type",
                "action",
                "domain",
                "match_subdomains",
                "pattern",
                "rewrite_address",
                "address_family",
                "qtype_restriction",
                "priority",
                "enabled",
                "validation_state",
            ],
            "id",
        ),
        "custom_rules": _canonical_rows(conn, "custom_rules", ["id", "domain", "action", "enabled", "comment"], "id"),
        "local_dns_settings": _canonical_rows(conn, "local_dns_settings", ["key", "value"], "key"),
        "local_dns_records": _canonical_rows(
            conn,
            "local_dns_records",
            ["id", "name", "fqdn", "record_type", "value", "ttl", "enabled", "auto_ptr", "ptr_record_id", "comment"],
            "id",
        ),
        "dns_cache_settings": _canonical_rows(conn, "dns_cache_settings", ["key", "value"], "key"),
        "upstream_resolvers": _canonical_rows(
            conn,
            "upstream_resolvers",
            ["id", "name", "protocol", "address", "port", "doh_path", "tls_hostname", "bootstrap_ips", "enabled", "position"],
            "position, id",
        ),
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["manifest_sha256"] = hashlib.sha256(encoded).hexdigest()
    return manifest


def record_reusable_protection_policy(conn: sqlite3.Connection, rpz_text: str, active_domains: int) -> None:
    if active_domains <= 0:
        return
    manifest = protection_policy_manifest(conn)
    if manifest is None:
        return
    manifest["active_domains"] = active_domains
    rpz_cache, manifest_cache = protection_cache_paths()
    rpz_cache.parent.mkdir(parents=True, exist_ok=True)
    staged_rpz = rpz_cache.with_suffix(".rpz.tmp")
    staged_manifest = manifest_cache.with_suffix(".json.tmp")
    try:
        staged_rpz.write_text(rpz_text)
        staged_manifest.write_text(json.dumps(manifest, sort_keys=True, indent=2))
        os.replace(staged_rpz, rpz_cache)
        os.replace(staged_manifest, manifest_cache)
    except OSError:
        for path in (staged_rpz, staged_manifest):
            try:
                path.unlink()
            except OSError:
                pass


def reusable_protection_policy_available(conn: sqlite3.Connection) -> tuple[bool, str]:
    rpz_cache, manifest_cache = protection_cache_paths()
    if not rpz_cache.exists() or not manifest_cache.exists():
        return False, "cached policy artifact is missing"
    if conn.execute(
        """
        SELECT 1 FROM custom_filter_rules
        WHERE enabled=1 AND validation_state='valid' AND rule_type IN ('regex_allow', 'regex_block')
        LIMIT 1
        """
    ).fetchone():
        return False, "enabled regex rules require full dnsdist-layer deployment"
    try:
        cached = json.loads(manifest_cache.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"cached policy manifest is unreadable: {exc}"
    current = protection_policy_manifest(conn)
    if current is None:
        return False, "current policy inputs are incomplete"
    if cached.get("manifest_sha256") != current.get("manifest_sha256"):
        return False, "current policy inputs do not match cached manifest"
    return True, "cached compiled policy matches current inputs"


def protection_enable_reuse(_: argparse.Namespace | None = None) -> None:
    init_db()
    with deploy_lock():
        conn = connect()
        try:
            ok, reason = reusable_protection_policy_available(conn)
            if not ok:
                print(f"reused=0 reason={reason}")
                raise SystemExit(PROTECTION_REUSE_UNAVAILABLE)
            rpz_cache, _manifest_cache = protection_cache_paths()
            started = now()
            cursor = conn.execute(
                """
                INSERT INTO deployments(started_at, status, message, "trigger")
                VALUES (?, 'running', 'reusing cached compiled protection policy', 'protection-reuse')
                """,
                (started,),
            )
            deployment_id = cursor.lastrowid
            conn.commit()
            stage = Path(tempfile.mkdtemp(prefix="alderpointdns-rpz-reuse-", dir=str(STAGING_DIR)))
            staged_rpz = stage / "alderpointdns.rpz"
            backup_path = BACKUP_DIR / f"alderpointdns.rpz.last-good.{int(time.time())}"
            status = "failed"
            message = reason
            active_domains = 0
            blocked_test = None
            allowed_test = None
            failure: Exception | None = None
            try:
                cached_manifest = json.loads(_manifest_cache.read_text())
                shutil.copy2(rpz_cache, staged_rpz)
                rpz_text = refresh_rpz_serial(staged_rpz.read_text())
                staged_rpz.write_text(rpz_text)
                active_domains = int(cached_manifest.get("active_domains") or 0)
                validate_rpz(staged_rpz)
                validate_bind()
                if COMPILED_RPZ.exists():
                    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(COMPILED_RPZ, backup_path)
                COMPILED_RPZ.parent.mkdir(parents=True, exist_ok=True)
                os.replace(staged_rpz, COMPILED_RPZ)
                reload_bind()
                conn.execute("UPDATE sources SET last_compile_success=? WHERE enabled=1", (now(),))
                conn.commit()
                if not resolves("cloudflare.com"):
                    raise RuntimeError("post-deploy ordinary resolution failed")
                status = "deployed"
                message = "reused cached compiled protection policy"
                replication.on_deploy_success(conn)
            except Exception as exc:
                failure = exc
                message = str(exc)
                if backup_path.exists():
                    try:
                        restore_rpz_backup_for_rollback(backup_path)
                        status = "rolled_back"
                    except Exception as rollback_exc:
                        status = "rollback_failed"
                        message = f"{message}; RPZ rollback failed: {rollback_exc}"
                else:
                    status = "rolled_back"
            finally:
                conn.execute(
                    """
                    UPDATE deployments
                    SET finished_at=?, status=?, active_domains=?,
                        blocked_test_domain=?, allowed_test_domain=?, message=?
                    WHERE id=?
                    """,
                    (now(), status, active_domains, blocked_test, allowed_test, message, deployment_id),
                )
                conn.commit()
                shutil.rmtree(stage, ignore_errors=True)
            if failure:
                raise failure
            print(f"reused=1 deployment_id={deployment_id} active_domains={active_domains}")
        finally:
            conn.close()


def dig(domain: str) -> subprocess.CompletedProcess[str]:
    return run(["dig", "@127.0.0.1", "-p", "5353", domain, "A", "+time=3", "+tries=1"], check=False)


def is_blocked(domain: str) -> bool:
    result = dig(domain)
    return result.returncode == 0 and (
        "status: NXDOMAIN" in result.stdout
        or ("status: NOERROR" in result.stdout and "ANSWER: 0" in result.stdout and "\tA\t" not in result.stdout)
    )


def resolves(domain: str) -> bool:
    result = dig(domain)
    return result.returncode == 0 and "status: NOERROR" in result.stdout and "\tA\t" in result.stdout


def resolves_to(domain: str, rtype: str, address: str) -> bool:
    result = run(["dig", "@127.0.0.1", "-p", "5353", domain, rtype, "+time=3", "+tries=1"], check=False)
    return result.returncode == 0 and "status: NOERROR" in result.stdout and address in result.stdout


@dataclass
class DNSResult:
    """A structured view of one dig lookup, so post-deploy checks reason
    about DNS status/record-type/transport outcome explicitly instead of via
    fragile substring tests on raw dig text scattered through the compiler."""

    domain: str
    status: str | None = None
    answer_count: int = 0
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    timed_out: bool = False
    transport_ok: bool = True

    @property
    def resolved(self) -> bool:
        """True only when the name definitively answered with data (A, AAAA,
        or CNAME) -- positive proof that no blocking policy rewrote it away."""
        return bool(self.a_records or self.aaaa_records or self.cname_records)

    @property
    def is_nodata(self) -> bool:
        return self.status == "NOERROR" and self.answer_count == 0

    @property
    def is_nxdomain(self) -> bool:
        return self.status == "NXDOMAIN"

    @property
    def is_servfail(self) -> bool:
        return self.status == "SERVFAIL"

    @property
    def usable(self) -> bool:
        """A candidate worth drawing a conclusion from at all -- excludes
        transport failures, which say nothing about DNS/policy behavior."""
        return self.transport_ok and not self.timed_out


_DIG_ANSWER_LINE_RE = re.compile(r"^\S+\.\s+\d+\s+\S+\s+(A|AAAA|CNAME)\s+(\S+)\s*$")


def classify_dns(domain: str, rtype: str = "A") -> DNSResult:
    """Runs dig for `domain` and returns a structured DNSResult instead of
    raw text, so callers can distinguish a real block from ordinary DNS
    variance (NODATA, AAAA/CNAME-only, NXDOMAIN, SERVFAIL, timeout)."""
    result = run(["dig", "@127.0.0.1", "-p", "5353", domain, rtype, "+time=3", "+tries=1"], check=False)
    stdout = result.stdout or ""
    if result.returncode != 0:
        timed_out = "timed out" in stdout.lower() or "no servers could be reached" in stdout.lower()
        return DNSResult(domain=domain, timed_out=timed_out, transport_ok=not timed_out)
    status_match = re.search(r"status:\s*(\w+)", stdout)
    answer_match = re.search(r"ANSWER:\s*(\d+)", stdout)
    parsed = DNSResult(
        domain=domain,
        status=status_match.group(1) if status_match else None,
        answer_count=int(answer_match.group(1)) if answer_match else 0,
    )
    in_answer_section = False
    for line in stdout.splitlines():
        if line.startswith(";; ANSWER SECTION"):
            in_answer_section = True
            continue
        if in_answer_section and (not line.strip() or line.startswith(";;")):
            in_answer_section = False
            continue
        if not in_answer_section:
            continue
        match = _DIG_ANSWER_LINE_RE.match(line)
        if not match:
            continue
        record_type, value = match.groups()
        if record_type == "A":
            parsed.a_records.append(value)
        elif record_type == "AAAA":
            parsed.aaaa_records.append(value)
        elif record_type == "CNAME":
            parsed.cname_records.append(value)
    return parsed


@dataclass
class AllowValidationResult:
    ok: bool
    tested_domain: str | None
    message: str


def _custom_allow_represented(domain: str, rpz_text: str, custom_active: "custom_rules.ActiveRuleSet") -> bool:
    """Structural check: a custom allow rule must produce the rpz-passthru
    record its type promises in the compiled zone. Downloaded/list-inherited
    allow domains have no rpz-passthru representation of their own -- they
    are simply absent from active_blocks, which subtract_allowed already
    guarantees -- so this only applies to rows present in custom_active."""
    allow = custom_active.allows.get(domain)
    if not allow:
        return True
    name = rpz_name(domain)
    if (allow["exact"] or allow["subdomains"]) and f"{name} CNAME rpz-passthru." not in rpz_text:
        return False
    if allow["subdomains"] and f"*.{name} CNAME rpz-passthru." not in rpz_text:
        return False
    return True


def validate_allow_domains(
    allowed_domains: set[str],
    active_blocks: set[str],
    custom_active: "custom_rules.ActiveRuleSet",
    rpz_text: str,
    max_live_checks: int = 5,
) -> AllowValidationResult:
    """Verifies allow rules against the compiled policy itself rather than
    external domain availability. An allow rule promises Alderpoint will not
    apply its blocking policy to a name -- it is not a guarantee that name
    currently has a live IPv4 address, so a NODATA/AAAA-only/CNAME-only/
    NXDOMAIN/SERVFAIL/timeout response from a real-world allow-listed domain
    (e.g. a downloaded AdGuard `@@||...^` exception rule) must never fail a
    deployment on its own. The only fatal condition is a structural mismatch
    between the allow rule and the compiled policy."""
    for domain in sorted(allowed_domains):
        if domain in active_blocks:
            return AllowValidationResult(
                ok=False,
                tested_domain=domain,
                message=f"post-deploy allow-policy check failed: {domain} is allow-listed but still present in the active block set",
            )
        if not _custom_allow_represented(domain, rpz_text, custom_active):
            return AllowValidationResult(
                ok=False,
                tested_domain=domain,
                message=f"post-deploy allow-policy check failed: custom allow rule for {domain} is missing its rpz-passthru representation in the compiled policy",
            )
    tested: str | None = None
    for domain in sorted(allowed_domains)[:max_live_checks]:
        result = classify_dns(domain)
        if result.usable and result.resolved:
            tested = domain
            break
    if tested:
        return AllowValidationResult(ok=True, tested_domain=tested, message=f"allow-domain policy verified; {tested} resolves normally")
    return AllowValidationResult(
        ok=True,
        tested_domain=None,
        message="allow-domain policy verified structurally; no live allow-domain candidate could be confirmed resolving (non-fatal)",
    )


def wait_until(predicate, timeout: int = 50) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(1)
    return predicate()


VENDOR_DIR = Path("/opt/alderpointdns/vendor")
VENDOR_RUNTIME_DIR = Path("/opt/alderpointdns/vendor-runtime")
VENDOR_REQUIREMENTS_PATH = Path("/opt/alderpointdns/requirements.txt")
VENDOR_WHEEL_SHA256 = {
    "python_multipart-0.0.31-py3-none-any.whl": "8408153d68a9773291fc1da39a8b85a50044bddbabd2dd72e9229776b7b15e28",
}


def _normalize_dist_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _verify_vendor_wheel(wheel: Path, dist_name: str, pinned_version: str) -> set[str]:
    expected_hash = VENDOR_WHEEL_SHA256.get(wheel.name)
    if not expected_hash:
        raise RuntimeError(f"vendored wheel {wheel.name} has no pinned SHA-256")
    actual_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise RuntimeError(f"vendored wheel {wheel.name} SHA-256 mismatch: expected {expected_hash}, got {actual_hash}")

    with zipfile.ZipFile(wheel) as zf:
        metadata_name = f"{wheel.stem.split('-')[0]}-{pinned_version}.dist-info/METADATA"
        metadata_candidates = [name for name in zf.namelist() if name.endswith(".dist-info/METADATA")]
        if metadata_name not in zf.namelist() and len(metadata_candidates) == 1:
            metadata_name = metadata_candidates[0]
        metadata = email.message_from_bytes(zf.read(metadata_name))
        wheel_name = _normalize_dist_name(metadata.get("Name", ""))
        wheel_version = metadata.get("Version", "")
        if wheel_name != dist_name or wheel_version != pinned_version:
            raise RuntimeError(f"vendored wheel {wheel.name} metadata is {wheel_name}=={wheel_version}, expected {dist_name}=={pinned_version}")

        record_name = metadata_name.rsplit("/", 1)[0] + "/RECORD"
        record_rows = zf.read(record_name).decode().splitlines()
        for parts in csv.reader(record_rows):
            if len(parts) < 3:
                raise RuntimeError(f"vendored wheel {wheel.name} has malformed RECORD entry: {parts!r}")
            path, digest, size = parts[0], parts[1], parts[2]
            data = zf.read(path)
            if size and int(size) != len(data):
                raise RuntimeError(f"vendored wheel {wheel.name} RECORD size mismatch for {path}")
            if digest:
                algo, _, b64_digest = digest.partition("=")
                actual_digest = base64.urlsafe_b64encode(hashlib.new(algo, data).digest()).rstrip(b"=").decode()
                if actual_digest != b64_digest:
                    raise RuntimeError(f"vendored wheel {wheel.name} RECORD digest mismatch for {path}")

        top_level: set[str] = set()
        for name in zf.namelist():
            first = name.split("/", 1)[0]
            if first and not first.endswith(".dist-info"):
                top_level.add(first)
        return top_level


def _remove_existing_vendor_runtime_files(dist_name: str, import_roots: set[str]) -> None:
    if not VENDOR_RUNTIME_DIR.exists():
        return
    for root in import_roots:
        candidate = VENDOR_RUNTIME_DIR / root
        if candidate.is_dir():
            shutil.rmtree(candidate)
        elif candidate.exists():
            candidate.unlink()
    dist_prefix = dist_name.replace("-", "_")
    for candidate in VENDOR_RUNTIME_DIR.glob(f"{dist_prefix}-*.dist-info"):
        if candidate.is_dir():
            shutil.rmtree(candidate)
        elif candidate.exists():
            candidate.unlink()


def _normalize_vendor_runtime_permissions() -> None:
    if not VENDOR_RUNTIME_DIR.exists():
        return
    for path in [VENDOR_RUNTIME_DIR, *VENDOR_RUNTIME_DIR.rglob("*")]:
        if path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o644)


def sync_vendored_python_deps() -> str:
    """Installs any requirements.txt-pinned package for which a wheel is
    vendored under vendor/ into vendor-runtime/, via `pip install --target`
    (never into the system/dpkg-managed site-packages -- --target writes to
    an Alderpoint-owned directory only, so this can never conflict with or
    drift dpkg's own tracking of the Debian-packaged version of the same
    library). Alderpoint's systemd units put vendor-runtime first on
    PYTHONPATH, so a vendored package wins the import over the Debian
    package, without ever touching or uninstalling it.

    This exists because Debian's own package archive does not always carry
    the exact upstream version requirements.txt pins (as of this change,
    Debian trixie's python3-python-multipart tops out at 0.0.20, and even
    unstable/forky only has 0.0.26 -- nowhere in Debian ships 0.0.31). This
    is the supported mechanism for that gap: `--no-index --find-links`
    against the vendored wheel only, so it never needs network access at
    deploy time, and it's a no-op (returns "no vendored dependency updates
    needed") wherever nothing under vendor/ applies.

    Idempotent and cheap to call on every install/upgrade, matching
    dnsdist_conf_migrate()'s own convention."""
    if not VENDOR_DIR.is_dir():
        return "no vendored dependency updates needed (no vendor/ directory)"
    wheels = sorted(VENDOR_DIR.glob("*.whl"))
    if not wheels:
        return "no vendored dependency updates needed (vendor/ is empty)"
    requirements_path = VENDOR_REQUIREMENTS_PATH
    if not requirements_path.exists():
        requirements_path = Path(__file__).resolve().parent.parent / "requirements.txt"
    pins: dict[str, str] = {}
    for line in requirements_path.read_text().splitlines():
        line = line.strip()
        if "==" in line and not line.startswith("#"):
            name, _, version = line.partition("==")
            pins[name.strip().lower().replace("_", "-")] = version.strip()
    installed: list[str] = []
    for wheel in wheels:
        # Wheel filename: {name}-{version}-{python tag}-{abi tag}-{platform tag}.whl
        dist_name = _normalize_dist_name(wheel.name.split("-")[0])
        pinned_version = pins.get(dist_name)
        if not pinned_version:
            continue
        import_roots = _verify_vendor_wheel(wheel, dist_name, pinned_version)
        spec = f"{dist_name}=={pinned_version}"
        VENDOR_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        _remove_existing_vendor_runtime_files(dist_name, import_roots)
        run([
            "python3", "-B", "-m", "pip", "install",
            "--no-index", "--find-links", str(VENDOR_DIR),
            "--target", str(VENDOR_RUNTIME_DIR),
            "--upgrade",
            "--no-compile",
            spec,
        ])
        _normalize_vendor_runtime_permissions()
        installed.append(spec)
    if not installed:
        return "no vendored dependency updates needed (no vendored wheel matches a requirements.txt pin)"
    return "vendored dependency updates applied: " + ", ".join(installed)


def dnsdist_conf_migrate() -> str:
    """Run every currently-defined dnsdist.conf managed-block migration
    (base parameterization, then doh-altsvc) idempotently, without
    restarting dnsdist itself -- callers that need the new config live
    (the package postinst, scripts/upgrade.sh) already restart dnsdist as
    a normal part of their own flow immediately after this runs, so this
    only ever rewrites and validates the file, never both that and a
    live reload, to avoid restarting dnsdist twice in the same upgrade.

    Safe and cheap to call on every install/upgrade: each migration checks
    its own marker and does nothing once already applied.
    """
    template = Path("/opt/alderpointdns/packaging/dnsdist.conf")
    parts: list[str] = []
    if encryption.ensure_dnsdist_conf_parameterized(template):
        parts.append("base dnsdist.conf parameterization applied")
    altsvc_changed, altsvc_message = encryption.ensure_doh_altsvc_migration(template)
    if altsvc_changed:
        parts.append(altsvc_message)
    elif altsvc_message:
        parts.append(altsvc_message)
    if clients.ensure_doh_clientid_paths_migration():
        parts.append("DoH ClientID path routing added")
    if clients.ensure_dnsdist_access_include():
        parts.append("Clients & Access dofile include added")
    if clients.ensure_access_data_files():
        parts.append("Clients & Access data files written")
    if not parts:
        parts.append("no dnsdist.conf migrations were needed; already up to date")
    return "; ".join(parts)


@contextlib.contextmanager
def deploy_lock():
    """The single global appliance-wide mutex guarding every entry point that
    writes live BIND/dnsdist runtime configuration: the full deploy()
    pipeline, protection-enable-reuse, and each of the narrower single-stage
    CLI deploys that also touch that same runtime config outside a full
    deploy() run (cache-deploy, cache-flush, upstream-deploy, encryption-deploy).

    v1.0.1 RC acceptance found that real UI use -- an administrator toggling
    several upstream resolvers in quick succession, each one submitted as its
    own request before the previous had finished -- spawned multiple
    concurrent `alderpointdns_compiler.py deploy --no-download` processes.
    This lock is why that never actually corrupted or split-brained the
    runtime files or last-good backups: only one holder ever mutates BIND's
    RPZ/forwarders, dnsdist's upstream/cache/encryption config, or their
    last-good backups at a time, and every other invocation -- from the web
    app, cron timers, or a manual sudo'd CLI call -- blocks here until its
    turn rather than racing. It does NOT by itself fix the UX problems that
    incident also exposed (an admin's request blocking for as long as
    however many pipelines were already queued ahead of it, with no
    indication a deployment was already in progress) -- see
    webapp._DeployCoordinator for that half of the fix.

    Must not be acquired twice by the same call stack: deploy() and
    protection_enable_reuse() acquire it themselves and are never called
    from within another holder's critical section, and the narrower
    single-stage deploys below acquire it only at their own CLI entry point,
    never when invoked as a plain Python call from inside deploy()'s own
    already-locked body (deploy() calls upstream_dns.deploy_upstreams(conn)
    etc. directly, not through this lock, for exactly that reason) --
    flock() is per open-file-description, so a second acquire from the same
    process before the first is released would deadlock against itself.
    """
    DEPLOY_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with DEPLOY_LOCK.open("w") as lock_handle:
        fcntl.flock(lock_handle, fcntl.LOCK_EX)
        yield


def _locked(fn):
    """Runs a narrower, single-stage runtime deploy (dns_cache/upstream_dns/
    encryption's own deploy_*) under deploy_lock(), for standalone CLI/webapp
    invocations that -- unlike calls from inside deploy()'s own body -- have
    no other holder of the lock on their call stack."""
    with deploy_lock():
        return fn()


def _run_upstream_deploy_for_cli(args) -> None:
    """Prints the deployment id *and* its own truthful message -- not just
    the id `upstream-deploy` used to print alone -- so the webapp's
    upstream deploy coordinator can tell, from this subprocess's own
    stdout, whether this particular deploy actually restarted dnsdist or
    applied live over its console (see upstream_dns.deploy_upstreams()'s
    _console_reconcile() docstring). That distinction is what lets the
    coordinator's restart-rate pacing apply only when a restart really
    happened, instead of throttling every ordinary sequential upstream
    change to one every min_interval_seconds regardless of whether
    anything was ever actually restarted."""
    deployment_id = _locked(upstream_dns.deploy_upstreams)
    row = upstream_dns.last_deployment()
    message = row["message"] if row else ""
    print(f"{deployment_id} {message}")


def deploy(download: bool = True, trigger: str | None = None, fail_on_source_errors: bool = False) -> int:
    init_db()
    with deploy_lock():
        conn = connect()
        try:
            started = now()
            cursor = conn.execute(
                """
                INSERT INTO deployments(started_at, status, message, "trigger")
                VALUES (?, 'running', '', ?)
                """,
                (started, trigger),
            )
            deployment_id = cursor.lastrowid
            conn.commit()
            backup_path = BACKUP_DIR / f"alderpointdns.rpz.last-good.{int(time.time())}"
            stage = Path(tempfile.mkdtemp(prefix="alderpointdns-rpz-", dir=str(STAGING_DIR)))
            staged_rpz = stage / "alderpointdns.rpz"
            status = "failed"
            message = ""
            active_domains = 0
            blocked_test = None
            allowed_test = None
            failure: Exception | None = None
            dnsdist_layer: dict | None = None
            cache_options_snapshot: str | None = None
            cache_deployed_this_run = False
            try:
                active_blocks, allowed_domains, _, errors = collect_rules(conn, download)
                if fail_on_source_errors and errors:
                    raise RuntimeError("initial default blocklist download failed: " + "; ".join(errors))
                custom_active = custom_rules.collect_active(conn)
                active_blocks = custom_rules.subtract_allowed(active_blocks, custom_active)
                active_domains = len(active_blocks) + len(custom_active.blocks)
                rpz_text = render_rpz(active_blocks, custom_active)
                if os.environ.get("ALDERPOINTDNS_TEST_INVALID_RPZ") == "1":
                    rpz_text += "this is not a valid zone record\n"
                staged_rpz.write_text(rpz_text)
                validate_rpz(staged_rpz)
                # named.conf.local unconditionally `include`s this file, so on
                # the very first deploy ever run (nothing under
                # /var/lib/alderpointdns/compiled/ exists yet) named-checkconf
                # fails to parse the config before local_dns.deploy_zones()
                # below ever gets a chance to generate it. An empty file is a
                # safe, honest bootstrap default (equivalent to "no local
                # zones configured yet") and deploy_zones() below replaces it
                # with the real content in the same run regardless.
                if not local_dns.LOCAL_ZONES_CONF.exists():
                    local_dns.LOCAL_ZONES_CONF.parent.mkdir(parents=True, exist_ok=True)
                    local_dns.LOCAL_ZONES_CONF.write_text("")
                validate_bind()
                if COMPILED_RPZ.exists():
                    shutil.copy2(COMPILED_RPZ, backup_path)
                COMPILED_RPZ.parent.mkdir(parents=True, exist_ok=True)
                os.replace(staged_rpz, COMPILED_RPZ)
                reload_bind()
                # Compilation is one atomic RPZ file covering every enabled
                # source, so "last successful compilation" is the same
                # timestamp for all of them -- unlike last_success, which is
                # per-source and reflects that source's own last successful
                # download.
                conn.execute(
                    "UPDATE sources SET last_compile_success=? WHERE enabled=1",
                    (now(),),
                )
                # Short, explicit commit: this update must not stay open
                # across local_dns.deploy_zones()'s own subprocess/DNS
                # validation work below.
                conn.commit()
                local_dns.deploy_zones(conn)
                # Upstream forwarders must be (re)deployed before cache
                # options: dns_cache.deploy_cache_options()'s own post-deploy
                # health check resolves a live domain through BIND :5353,
                # which forwards through dnsdist's managed upstream listener
                # (:5355) -- i.e. it transitively depends on the upstream
                # forwarder chain already being current. Deploying upstream
                # second used to let a stale/dead upstream runtime config
                # (e.g. from an earlier failed edit, or resolvers that have
                # since gone down) fail the *cache* stage's health check
                # before upstream_dns.deploy_upstreams() ever ran -- which
                # aborted the whole pipeline right there, so a just-saved,
                # perfectly valid upstream_resolvers.enabled change was
                # never actually applied, never recorded in
                # upstream_deployments (success or failure), and the
                # operator saw a misleading "cache options" error while the
                # database and the live dnsdist config silently diverged.
                # Deploying upstream first means every full deploy always
                # attempts to reconcile the live upstream config with the
                # database first, so its own success/failure is always
                # attempted and recorded, and any later stage's health
                # check observes the freshly applied upstream state.
                upstream_dns.deploy_upstreams(conn)
                cache_options_snapshot = dns_cache.CACHE_OPTIONS_CONF.read_text() if dns_cache.CACHE_OPTIONS_CONF.exists() else None
                dns_cache.deploy_cache_options(conn)
                cache_deployed_this_run = True
                # Restarts dnsdist only when the custom-rule dnsdist-layer
                # files actually changed; rolls its own files back and
                # re-raises on failure.
                dnsdist_layer = custom_rules.deploy_dnsdist_layer(conn, custom_active)
                if os.environ.get("ALDERPOINTDNS_TEST_FORCE_POSTCHECK_FAIL") == "1":
                    raise RuntimeError("forced post-deploy failure for rollback test")
                if not resolves("cloudflare.com"):
                    raise RuntimeError("post-deploy ordinary resolution failed")
                custom_blocks = {name for name, block in custom_active.blocks.items() if block["subdomains"] or block["exact"]}
                if active_blocks:
                    blocked_test = "cloudflare-dns.com" if "cloudflare-dns.com" in active_blocks else sorted(active_blocks)[0]
                elif custom_blocks:
                    blocked_test = sorted(custom_blocks)[0]
                if blocked_test:
                    if not wait_until(lambda: is_blocked(blocked_test)):
                        raise RuntimeError(f"post-deploy blocked-domain test failed for {blocked_test}")
                allowed_domains = allowed_domains | set(custom_active.allows)
                if allowed_domains:
                    allow_result = validate_allow_domains(allowed_domains, active_blocks, custom_active, rpz_text)
                    if not allow_result.ok:
                        raise RuntimeError(allow_result.message)
                    allowed_test = allow_result.tested_domain
                    if allow_result.tested_domain is None:
                        errors.append(allow_result.message)
                if custom_active.rewrites:
                    rewrite_name = sorted(custom_active.rewrites)[0]
                    rewrite_entry = custom_active.rewrites[rewrite_name]
                    rewrite_type = "A" if rewrite_entry["A"] else "AAAA"
                    rewrite_addr = rewrite_entry[rewrite_type]
                    if not wait_until(lambda: resolves_to(rewrite_name, rewrite_type, rewrite_addr)):
                        raise RuntimeError(f"post-deploy rewrite test failed for {rewrite_name}")
                record_reusable_protection_policy(conn, rpz_text, active_domains)
                status = "deployed"
                message = "; ".join(errors)
                replication.on_deploy_success(conn)
            except Exception as exc:
                failure = exc
                message = str(exc)
                rollback_errors: list[str] = []
                if dnsdist_layer:
                    custom_rules.rollback_dnsdist_layer(dnsdist_layer)
                if backup_path.exists():
                    try:
                        restore_rpz_backup_for_rollback(backup_path)
                    except Exception as rollback_exc:
                        rollback_errors.append(f"RPZ rollback failed: {rollback_exc}")
                if cache_deployed_this_run:
                    try:
                        if cache_options_snapshot is not None:
                            dns_cache.CACHE_OPTIONS_CONF.write_text(cache_options_snapshot)
                        elif dns_cache.CACHE_OPTIONS_CONF.exists():
                            dns_cache.CACHE_OPTIONS_CONF.unlink()
                        run(["rndc", "reconfig"], check=False)
                    except Exception as rollback_exc:
                        rollback_errors.append(f"cache-options rollback failed: {rollback_exc}")
                if rollback_errors:
                    status = "rollback_failed"
                    message = f"{message}; " + "; ".join(rollback_errors)
                else:
                    status = "rolled_back"
            finally:
                conn.execute(
                    """
                    UPDATE deployments
                    SET finished_at=?, status=?, active_domains=?,
                        blocked_test_domain=?, allowed_test_domain=?, message=?
                    WHERE id=?
                    """,
                    (now(), status, active_domains, blocked_test, allowed_test, message, deployment_id),
                )
                conn.commit()
                shutil.rmtree(stage, ignore_errors=True)
            if failure:
                raise failure
        finally:
            conn.close()
    return deployment_id


# Bounded backoff between fresh-install-init's own retries of the initial
# deploy: two retries (three attempts total) at these delays. Found via a
# real appliance install where the curated default sources transiently
# failed to resolve (DHCP-provided resolvers not yet reachable at the
# exact moment postinst ran, immediately after apt itself had just
# successfully resolved and downloaded bind9/dnsdist) and a manual "Update
# All Now" moments later succeeded -- i.e. genuinely transient, not
# "network was never configured". This must stay short: postinst/dpkg
# configure blocks on this call, so it cannot retry indefinitely waiting
# for Internet access. Worst case this adds ~20s to a fresh install;
# nothing here can leave the package half-configured or corrupt existing
# state either way (see the function's docstring).
FRESH_INSTALL_DEPLOY_RETRY_DELAYS_SECONDS: tuple[int, ...] = (5, 15)

FRESH_INSTALL_RECOVERY_HINT = (
    "once network connectivity is available, open Security > Blocklists and "
    "click \"Update All Now\" to complete initial filtering setup"
)


def fresh_install_init(_: argparse.Namespace | None = None) -> None:
    """First-install bootstrap only.

    A database is considered genuinely fresh only when, before schema
    creation, it has PRAGMA user_version=0 and no user tables in
    sqlite_master. Existing installs that merely need migration may also have
    user_version=0, so the no-user-tables condition is the critical guard.
    Only that fresh case seeds ordinary source rows and runs the normal
    download/compile/deploy path -- exactly once, regardless of outcome:
    upgrades/reinstalls never re-seed or re-deploy these defaults.

    The initial deploy is retried a bounded number of times
    (FRESH_INSTALL_DEPLOY_RETRY_DELAYS_SECONDS) to absorb a short transient
    network/DNS-resolution hiccup right at postinst time without demanding
    the administrator notice and retry manually -- but never indefinitely:
    dpkg configure blocks on this call, and a genuinely offline appliance
    must not hang it. Persistent failure (offline, or a real, non-transient
    problem) is reported honestly and does not corrupt or half-configure
    anything: init_db already committed the three seeded source rows as
    ordinary editable sources (deploy()'s own rollback keeps the compiled
    policy/live services untouched on any failure), and the `deployments`
    table's own failed-status row (active_domains=0) is the single source
    of truth the dashboard's Protection indicator reads -- so it always
    truthfully reports "Disabled", never a false "Active", when this
    never/didn't-yet succeed. See FRESH_INSTALL_RECOVERY_HINT for the
    manual recovery path once connectivity exists.
    """
    seeded = init_db(seed_defaults=True)
    if not seeded:
        print("fresh_install=0")
        return
    print(f"fresh_install=1 seeded_defaults={len(DEFAULT_FRESH_INSTALL_SOURCES)}")
    attempts = len(FRESH_INSTALL_DEPLOY_RETRY_DELAYS_SECONDS) + 1
    deployment_id: int | None = None
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            deployment_id = deploy(download=True, trigger="fresh-install", fail_on_source_errors=True)
            last_exc = None
            break
        except Exception as exc:
            last_exc = exc
            if attempt <= len(FRESH_INSTALL_DEPLOY_RETRY_DELAYS_SECONDS):
                delay = FRESH_INSTALL_DEPLOY_RETRY_DELAYS_SECONDS[attempt - 1]
                print(f"initial_deploy=retrying attempt={attempt}/{attempts} error={exc} retry_in={delay}s")
                time.sleep(delay)
    if last_exc is not None:
        print(f"initial_deploy=failed attempts={attempts} error={last_exc}")
        print(f"initial_deploy=recovery {FRESH_INSTALL_RECOVERY_HINT}")
        return
    row = deployment_row(deployment_id)
    active_domains = row["active_domains"] if row else 0
    if not row or row["status"] != "deployed" or active_domains <= 0:
        print(f"initial_deploy=failed status={row['status'] if row else 'missing'} active_domains={active_domains}")
        print(f"initial_deploy=recovery {FRESH_INSTALL_RECOVERY_HINT}")
        return
    print(f"initial_deploy=deployed deployment_id={deployment_id} active_domains={active_domains}")


def add_source(args: argparse.Namespace) -> None:
    init_db()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO sources(name, url, enabled, category)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
              url=excluded.url,
              enabled=excluded.enabled,
              category=excluded.category
            """,
            (args.name, args.url, 1 if args.enabled else 0, args.category),
        )


def add_custom(args: argparse.Namespace) -> None:
    init_db()
    domain = normalize_domain(args.domain)
    if not domain:
        raise SystemExit(f"invalid domain: {args.domain}")
    # Legacy CLI semantics always covered subdomains, so write the
    # subdomain-anchored form through the new custom-rule model.
    text = ("@@||" if args.action == "allow" else "||") + domain + "^"
    results = custom_rules.add_rule(text, source_system="manual", comment=args.comment or "")
    for result in results:
        print(f"custom_rule_id={result['id']} status={result['status']}")


def list_status(_: argparse.Namespace) -> None:
    init_db()
    with connect() as conn:
        print("Sources:")
        for row in conn.execute("SELECT * FROM sources ORDER BY id"):
            fields = dict(row)
            fields["health"] = source_health(row)["label"]
            print(fields)
        print("Custom rules:")
        for row in conn.execute(
            "SELECT id, rule_text, rule_type, action, enabled, validation_state, comment FROM custom_filter_rules ORDER BY id"
        ):
            print(dict(row))
        print("Deployments:")
        for row in conn.execute("SELECT id, status, active_domains, finished_at, message FROM deployments ORDER BY id DESC LIMIT 5"):
            print(dict(row))
        print("Local DNS deployments:")
        for row in conn.execute("SELECT id, status, forward_zone, reverse_zones, serial, finished_at, message FROM local_dns_deployments ORDER BY id DESC LIMIT 5"):
            print(dict(row))
        print("Policy profiles:")
        for row in conn.execute(
            """
            SELECT p.key, p.name, group_concat(pc.category_key, ',') AS categories
            FROM policy_profiles p
            LEFT JOIN profile_categories pc ON pc.profile_key=p.key AND pc.enabled=1
            GROUP BY p.key, p.name
            ORDER BY p.key
            """
        ):
            print(dict(row))
        print("Network policies:")
        for row in conn.execute("SELECT cidr, profile_key, enabled, description FROM network_policies ORDER BY cidr"):
            print(dict(row))


def seed_lab(_: argparse.Namespace) -> None:
    init_db()
    with connect() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO sources(name, url, enabled, category)
            VALUES (?, ?, 1, 'ads_trackers')
            """,
            (
                "AdGuard DNS filter",
                "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
            ),
        )


def seed_public(args: argparse.Namespace) -> None:
    init_db()
    enabled = 1 if args.enabled else 0
    with connect() as conn:
        conn.executemany(
            """
            INSERT INTO sources(name, url, enabled, category)
            VALUES (:name, :url, :enabled, :category)
            ON CONFLICT(name) DO UPDATE SET
              url=excluded.url,
              enabled=excluded.enabled,
              category=excluded.category
            """,
            [
                {
                    "name": source.name,
                    "url": source.url,
                    "category": source.category,
                    "enabled": enabled,
                }
                for source in PUBLIC_SOURCES
            ],
        )
    print(f"seeded_public_sources={len(PUBLIC_SOURCES)} enabled={enabled}")


def update_one_source(conn: sqlite3.Connection, source: sqlite3.Row) -> tuple[SourceResult, ParseStats]:
    """Downloads and parses one source, then recomputes every enabled
    source's cross-source duplicate/unique-contribution stats (and the
    global final_active_domains total) from their currently cached
    downloads with no further network access -- so a single "Update now"
    keeps the whole dashboard's dedup numbers consistent, not just the one
    source that was refreshed. collect_rules(download=False) never touches
    http_status/downloaded_bytes/last_error, so this cannot clobber the
    real download outcome recorded immediately below."""
    result = download_source(source)
    using_cached = (not result.success) and bool(result.path and result.path.exists())
    record_download_result(conn, result, using_cached)
    _active_blocks, _allows, per_source, _errors = collect_rules(conn, download=False)
    stats = per_source.get(source["id"], ParseStats())
    return result, stats


def update_sources(_: argparse.Namespace) -> None:
    """Result contract for callers (timer, admin CLI, notification checker):
    0 -- every enabled source updated/validated cleanly; 2 -- at least one
    source failed, used a cached fallback, or produced warnings/unsupported
    content, but at least one other source is still fully healthy (partial
    success); 1 -- every enabled source is in a hard-failure state (or there
    were no usable results at all). Previously this always exited 0, so a
    source download failure (an `error=` line) was visible only to someone
    reading stdout by hand."""
    init_db()
    with connect() as conn:
        active_blocks, _, _per_source, errors = collect_rules(conn, download=True)
        print(f"active_domains={len(active_blocks)}")
        sources = enabled_sources(conn)
        hard_failures = 0
        degraded = 0
        for source in sources:
            state = source_health(source)["state"]
            if state == HEALTH_ERROR:
                hard_failures += 1
            elif state in (HEALTH_WARNING, HEALTH_UNSUPPORTED_FORMAT, HEALTH_USING_CACHED):
                degraded += 1
                print(f"warning={source['name']}: {HEALTH_LABELS[state]} ({source['last_warning'] or source['last_error'] or ''})")
        for error in errors:
            print(f"error={error}")
    if sources and hard_failures == len(sources):
        raise SystemExit(1)
    if hard_failures or degraded:
        raise SystemExit(2)


def update_source(args: argparse.Namespace) -> None:
    init_db()
    with connect() as conn:
        source = conn.execute("SELECT * FROM sources WHERE id=?", (args.source_id,)).fetchone()
        if not source:
            raise SystemExit(f"source not found: {args.source_id}")
        result, stats = update_one_source(conn, source)
        print(f"source_id={source['id']}")
        print(f"success={1 if result.success else 0}")
        print(f"accepted_domains={stats.accepted_domains}")
        print(f"unique_active_domains={stats.unique_active_domains}")
        if result.error:
            print(f"error={result.error}")


def backup_create(_: argparse.Namespace) -> None:
    processed = backup.process_pending_request("create")
    if processed is not None:
        print(processed)
        return
    # No pending web-originated request: this is a scheduled or manual
    # invocation, so fall back to the stored default component selection.
    cfg = backup.settings()
    try:
        components = json.loads(cfg.get("default_components", "{}"))
    except json.JSONDecodeError:
        components = {}
    path = backup.create_backup(backup.validate_components(components))
    pruned = backup.prune_backups()
    print(f"backup_path={path}")
    if pruned:
        print(f"pruned={len(pruned)}")


def backup_restore(_: argparse.Namespace) -> None:
    processed = backup.process_pending_request("restore")
    if processed is None:
        raise SystemExit("no pending restore request found")
    print(processed)


def backup_preview(_: argparse.Namespace) -> None:
    processed = backup.process_pending_request("preview")
    if processed is None:
        raise SystemExit("no pending preview request found")
    print(processed)


def backup_schedule_deploy(_: argparse.Namespace) -> None:
    print(backup.deploy_backup_schedule())


def network_apply(_: argparse.Namespace) -> None:
    processed = network_config.process_pending_request("apply")
    if processed is None:
        raise SystemExit("no pending network configuration request found")
    print(processed)


def network_confirm(_: argparse.Namespace) -> None:
    processed = network_config.process_pending_request("confirm")
    if processed is None:
        raise SystemExit("no pending network configuration confirmation found")
    print(processed)


def network_rollback_check(_: argparse.Namespace) -> None:
    # Invoked by the independent systemd-run watchdog timer, not by the web
    # process -- this must work even if alderpointdns.service is down.
    print(network_config.rollback_check())


def update_check(args: argparse.Namespace) -> None:
    # Safe to invoke directly via `sudo` from an HTTP request (the "Check
    # for Updates" button) as well as from the unattended timer's own
    # service unit: it never restarts anything, so it never needs the
    # independent-of-the-request-lifecycle treatment update-run does.
    result = software_updates.run_check(force=bool(args.force))
    print(json.dumps(result, default=str))


def update_run(_: argparse.Namespace) -> None:
    # Invoked only by `systemctl start --no-block alderpointdns-software-update.service`
    # (see packaging/*.service), never as a `sudo` child of the web
    # request: this call may restart alderpointdns.service partway
    # through, and this process must survive that. Reads its instructions
    # from the most recent 'pending' software_update_jobs row rather than
    # argv -- see app/software_updates.py's module docstring.
    result = software_updates.run_pending_job()
    if result is None:
        print("no pending update job")
        return
    print(json.dumps(result, default=str))


def update_postcheck(args: argparse.Namespace) -> None:
    noise = io.StringIO()
    with contextlib.redirect_stdout(noise), contextlib.redirect_stderr(noise):
        result = software_updates.post_upgrade_health_check_json(expected_deb_version=args.expected_deb_version)
    print(result)


def filter_schedule_deploy(_: argparse.Namespace) -> None:
    print(filter_schedule.deploy_filter_schedule())


def update_check_schedule_deploy(_: argparse.Namespace) -> None:
    print(software_updates.deploy_check_schedule())


def deployment_row(deployment_id: int) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute("SELECT * FROM deployments WHERE id=?", (deployment_id,)).fetchone()


def filter_update_run(_: argparse.Namespace) -> None:
    """Timer entry point for automatic filter updates.

    Records the attempt, then runs the ordinary full deployment pipeline
    (download enabled sources, recompile, validate, atomic activation,
    health check, automatic rollback, recorded deployment row). deploy() holds
    the exclusive deploy flock, so this can never overlap a manual deploy or a
    previous timer run, and a single list's failed download still leaves the
    remaining lists updated with the last valid policy active. Only the
    success path records last_success; the stored result summary holds counts
    and a sanitized error description only.
    """
    filter_schedule.record_attempt()
    try:
        deployment_id = deploy(download=True, trigger="scheduled")
    except Exception as exc:
        result = filter_schedule.record_result(status="failed", error=str(exc))
        print(json.dumps(result))
        raise SystemExit(1) from None
    row = deployment_row(deployment_id)
    result = filter_schedule.record_result(
        status=row["status"] if row else "deployed",
        active_domains=row["active_domains"] if row else 0,
        error=row["message"] if row else "",
        deployment_id=deployment_id,
    )
    filter_schedule.record_success()
    print(json.dumps(result))


def replication_primary_init(_: argparse.Namespace) -> None:
    # Ensures /etc/alderpointdns/certs (root:_dnsdist, not writable by the
    # unprivileged alderpointdns web process) has the CA + replication server
    # cert the primary's in-process listener needs before it can start.
    replication.ensure_server_cert()
    print(json.dumps({"ok": True}))


def replication_consume_enrollment(_: argparse.Namespace) -> None:
    # The reservation's token_hash arrives over stdin -- never argv, so it
    # never appears in `ps` -- identifying exactly which concurrently
    # in-flight enrollment reservation this particular sudo invocation must
    # finish. See replication.request_enrollment_consumption()'s docstring
    # for why a shared file (the old design) is not safe here.
    token_hash = sys.stdin.read().strip()
    if not token_hash:
        print(json.dumps({"error": "no enrollment reservation token provided on stdin"}))
        raise SystemExit(1)
    result = replication.process_pending_enrollment_consumption(token_hash)
    print(json.dumps(result))


def logs_command(args: argparse.Namespace) -> None:
    print(json.dumps(service_logs.fetch_unit_logs(args.unit)))


def local_dns_add_host(args: argparse.Namespace) -> None:
    local_dns.add_host(args.hostname, args.domain, args.address, args.ttl, args.comment or "", args.auto_ptr, args.override)
    print(f"local_dns_host={args.hostname}.{args.domain}")


def local_dns_add_alias(args: argparse.Namespace) -> None:
    local_dns.upsert_alias(args.cidr, args.name, args.description or "")
    print(f"client_alias={args.cidr}")


def _log_unexpected_failure(exc: Exception) -> None:
    """Writes the full traceback to a dedicated log file rather than letting
    it reach stdout/stderr, which webapp.py's subprocess runners capture
    verbatim and can otherwise surface directly on an admin-facing error
    page. main()'s caller only ever sees the concise str(exc).

    Tracebacks can embed exception arguments (paths, domain names, DB rows),
    so the file is created and kept at 0600 -- root-only, never relying on
    umask -- rather than inheriting /var/log/alderpointdns's normal 0755
    directory permissions. This CLI always runs as root (invoked directly
    or via the alderpointdns sudoers drop-in), so root ownership here always
    matches the process's real uid."""
    try:
        CLI_ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(CLI_ERROR_LOG, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        os.chmod(CLI_ERROR_LOG, 0o600)
        with os.fdopen(fd, "a") as handle:
            handle.write(f"---- {now()} ----\n")
            handle.write(traceback.format_exc())
            handle.write("\n")
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Alderpoint DNS blocklist compiler")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db").set_defaults(func=lambda args: init_db())
    sub.add_parser("fresh-install-init").set_defaults(func=fresh_install_init)
    seed = sub.add_parser("seed-lab")
    seed.set_defaults(func=seed_lab)
    seed_public_parser = sub.add_parser("seed-public")
    seed_public_parser.add_argument("--disabled", dest="enabled", action="store_false")
    seed_public_parser.set_defaults(enabled=True, func=seed_public)
    add = sub.add_parser("add-source")
    add.add_argument("name")
    add.add_argument("url")
    add.add_argument("--category", default="ads_trackers")
    add.add_argument("--disabled", dest="enabled", action="store_false")
    add.set_defaults(enabled=True, func=add_source)
    custom = sub.add_parser("add-custom")
    custom.add_argument("action", choices=["allow", "block"])
    custom.add_argument("domain")
    custom.add_argument("--comment", default="")
    custom.set_defaults(func=add_custom)
    dep = sub.add_parser("deploy")
    dep.add_argument("--no-download", action="store_true")
    dep.set_defaults(func=lambda args: print(deploy(download=not args.no_download)))
    protection_reuse_parser = sub.add_parser("protection-enable-reuse")
    protection_reuse_parser.set_defaults(func=protection_enable_reuse)
    local_dep = sub.add_parser("local-dns-deploy")
    local_dep.set_defaults(func=lambda args: print(local_dns.deploy_zones()))
    # cache-deploy, cache-flush, upstream-deploy, and encryption-deploy are
    # each a narrower, single-stage sibling of a step deploy() also runs
    # inside its own already-held deploy_lock() -- and each writes to the
    # same live BIND/dnsdist runtime files deploy() does (cache-options.conf,
    # named.conf.options, the dnsdist/BIND upstream-forwarder confs,
    # dnsdist.conf's encryption listeners). Standalone, they used to run
    # with no locking at all: a cache-only or upstream-only change from the
    # web app could race a concurrent full deploy() at the OS-process level
    # and clobber the same files it was also writing. Acquiring the same
    # deploy_lock() here closes that gap without touching the functions
    # themselves (which are also called, conn already open, from *inside*
    # deploy()'s own already-locked body -- acquiring it there too would
    # self-deadlock, which is exactly why it's only acquired at this CLI
    # boundary, never inside dns_cache/upstream_dns/encryption themselves).
    cache_dep = sub.add_parser("cache-deploy")
    cache_dep.set_defaults(func=lambda args: print(_locked(dns_cache.deploy_cache_options)))
    cache_flush = sub.add_parser("cache-flush")
    cache_flush.set_defaults(func=lambda args: print(_locked(dns_cache.process_pending_flush)))
    upstream_dep = sub.add_parser("upstream-deploy")
    upstream_dep.set_defaults(func=_run_upstream_deploy_for_cli)
    encryption_dep = sub.add_parser("encryption-deploy")
    encryption_dep.set_defaults(func=lambda args: print(_locked(encryption.deploy_encryption)))
    access_policy_dep = sub.add_parser("access-policy-deploy")
    access_policy_dep.set_defaults(func=lambda args: print(_locked(clients.deploy_access_layer)))
    dnsdist_conf_migrate_parser = sub.add_parser(
        "dnsdist-conf-migrate",
        help="idempotently apply dnsdist.conf managed-block migrations (e.g. doh-altsvc) without restarting dnsdist",
    )
    dnsdist_conf_migrate_parser.set_defaults(func=lambda args: print(dnsdist_conf_migrate()))
    vendor_sync_parser = sub.add_parser(
        "vendor-deps-sync",
        help="idempotently install any vendor/*.whl into vendor-runtime/ for packages requirements.txt pins ahead of what Debian packages",
    )
    vendor_sync_parser.set_defaults(func=lambda args: print(sync_vendored_python_deps()))
    backup_create_parser = sub.add_parser("backup-create")
    backup_create_parser.set_defaults(func=backup_create)
    backup_restore_parser = sub.add_parser("backup-restore")
    backup_restore_parser.set_defaults(func=backup_restore)
    backup_preview_parser = sub.add_parser("backup-preview")
    backup_preview_parser.set_defaults(func=backup_preview)
    backup_schedule_parser = sub.add_parser("backup-schedule-deploy")
    backup_schedule_parser.set_defaults(func=backup_schedule_deploy)
    network_apply_parser = sub.add_parser("network-apply")
    network_apply_parser.set_defaults(func=network_apply)
    network_confirm_parser = sub.add_parser("network-confirm")
    network_confirm_parser.set_defaults(func=network_confirm)
    update_check_parser = sub.add_parser("update-check")
    update_check_parser.add_argument("--force", action="store_true", help="check even if automatic checking is disabled")
    update_check_parser.set_defaults(func=update_check)
    update_run_parser = sub.add_parser("update-run")
    update_run_parser.set_defaults(func=update_run)
    update_postcheck_parser = sub.add_parser("update-postcheck")
    update_postcheck_parser.add_argument("--expected-deb-version")
    update_postcheck_parser.set_defaults(func=update_postcheck)
    update_check_schedule_parser = sub.add_parser("update-check-schedule-deploy")
    update_check_schedule_parser.set_defaults(func=update_check_schedule_deploy)
    network_rollback_check_parser = sub.add_parser("network-rollback-check")
    network_rollback_check_parser.set_defaults(func=network_rollback_check)
    filter_schedule_parser = sub.add_parser("filter-schedule-deploy")
    filter_schedule_parser.set_defaults(func=filter_schedule_deploy)
    filter_update_parser = sub.add_parser("filter-update-run")
    filter_update_parser.set_defaults(func=filter_update_run)
    repl_primary_init_parser = sub.add_parser("replication-primary-init")
    repl_primary_init_parser.set_defaults(func=replication_primary_init)
    repl_consume_parser = sub.add_parser("replication-consume-enrollment")
    repl_consume_parser.set_defaults(func=replication_consume_enrollment)
    local_host = sub.add_parser("local-dns-add-host")
    local_host.add_argument("hostname")
    local_host.add_argument("domain")
    local_host.add_argument("address")
    local_host.add_argument("--ttl", type=int, default=300)
    local_host.add_argument("--comment", default="")
    local_host.add_argument("--no-ptr", dest="auto_ptr", action="store_false")
    local_host.add_argument("--override", action="store_true")
    local_host.set_defaults(auto_ptr=True, func=local_dns_add_host)
    local_alias = sub.add_parser("local-dns-add-alias")
    local_alias.add_argument("cidr")
    local_alias.add_argument("name")
    local_alias.add_argument("--description", default="")
    local_alias.set_defaults(func=local_dns_add_alias)
    update = sub.add_parser("update-sources")
    update.set_defaults(func=update_sources)
    update_one = sub.add_parser("update-source")
    update_one.add_argument("source_id", type=int)
    update_one.set_defaults(func=update_source)
    status = sub.add_parser("status")
    status.set_defaults(func=list_status)
    logs_parser = sub.add_parser("logs")
    logs_parser.add_argument("unit", choices=service_logs.ALLOWED_UNITS)
    logs_parser.set_defaults(func=logs_command)
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except Exception as exc:
        _log_unexpected_failure(exc)
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
