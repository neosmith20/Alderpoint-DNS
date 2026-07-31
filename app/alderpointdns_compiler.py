#!/usr/bin/env python3
"""Alderpoint DNS blocklist downloader, parser, RPZ compiler, and deployer."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

try:
    from app import backup, custom_rules, dns_cache, encryption, filter_schedule, local_dns, replication, service_logs, upstream_dns
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app import backup, custom_rules, dns_cache, encryption, filter_schedule, local_dns, replication, service_logs, upstream_dns


DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
DOWNLOAD_DIR = Path("/var/lib/alderpointdns/downloads")
COMPILED_RPZ = Path("/var/lib/alderpointdns/compiled/bind/alderpointdns.rpz")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
DEPLOY_LOCK = Path("/var/lib/alderpointdns/staging/deploy.lock")
CLI_ERROR_LOG = Path("/var/log/alderpointdns/compiler-errors.log")
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


PUBLIC_SOURCES = (
    PublicSource("AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "ads_trackers"),
    PublicSource("OISD Blocklist Big", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt", "ads_trackers"),
    PublicSource("1Hosts Lite", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt", "ads_trackers"),
    PublicSource("StevenBlack Unified Hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "ads_trackers"),
    PublicSource("HaGeZi Multi Normal", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt", "ads_trackers"),
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


def init_db() -> None:
    with connect() as conn:
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
        local_dns.init_db(conn)
        filter_schedule.init_db(conn)
        custom_rules.init_db(conn)


def normalize_domain(raw: str) -> str | None:
    value = raw.strip().strip(".").lower()
    if not value or len(value) > 253:
        return None
    if "://" in value or "/" in value or ":" in value or "@" in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not DOMAIN_RE.match(value + "."):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
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
    try:
        ipaddress.ip_address(first_token)
        return True
    except ValueError:
        return False


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
    first_token = raw.split(None, 1)[0] if raw.split(None, 1) else ""
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


def parse_rules(content: str) -> tuple[set[str], set[str], ParseStats]:
    blocks: set[str] = set()
    allows: set[str] = set()
    stats = ParseStats()
    for line_number, line in enumerate(content.splitlines(), 1):
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


def source_paths(source: sqlite3.Row) -> tuple[Path, Path]:
    name = f"{source['id']}-{slug(source['name'])}.txt"
    return DOWNLOAD_DIR / "current" / name, DOWNLOAD_DIR / "staging" / name


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
    all_blocks: set[str] = set()
    all_allows: set[str] = set()
    per_source: dict[int, ParseStats] = {}
    per_source_blocks: dict[int, set[str]] = {}
    errors: list[str] = []
    pending: list[tuple[sqlite3.Row, SourceResult]] = []

    for source in enabled_sources(conn):
        if download:
            result = download_source(source)
            using_cached = (not result.success) and bool(result.path and result.path.exists())
            record_download_result(conn, result, using_cached)
        else:
            current_path, _ = source_paths(source)
            result = SourceResult(source["id"], source["name"], source["url"], current_path.exists(), path=current_path)
        pending.append((source, result))

    for source, result in pending:
        stats = ParseStats()
        if result.path and result.path.exists():
            content = result.path.read_text(errors="replace")
            blocks, allows, stats = parse_rules(content)
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
        record_parse_stats(conn, source["id"], stats)

    # Custom rules no longer merge into the external sets here; the deploy
    # path reads only custom_filter_rules through custom_rules.collect_active
    # and applies subdomain-aware allow subtraction on top of this result.
    active_blocks = all_blocks - all_allows
    conn.execute(
        "UPDATE sources SET final_active_domains=? WHERE enabled=1",
        (len(active_blocks),),
    )
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


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)


def validate_rpz(path: Path) -> None:
    run(["named-checkzone", RPZ_ZONE, str(path)])


def validate_bind() -> None:
    run(["named-checkconf", "-p", "/etc/bind/named.conf"])


def reload_bind() -> None:
    run(["rndc", "reload", RPZ_ZONE])


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


def deploy(download: bool = True, trigger: str | None = None) -> int:
    init_db()
    DEPLOY_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with DEPLOY_LOCK.open("w") as lock_handle:
        fcntl.flock(lock_handle, fcntl.LOCK_EX)
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
                local_dns.deploy_zones(conn)
                cache_options_snapshot = dns_cache.CACHE_OPTIONS_CONF.read_text() if dns_cache.CACHE_OPTIONS_CONF.exists() else None
                dns_cache.deploy_cache_options(conn)
                cache_deployed_this_run = True
                upstream_dns.deploy_upstreams(conn)
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
                    os.replace(backup_path, COMPILED_RPZ)
                    try:
                        reload_bind()
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


def filter_schedule_deploy(_: argparse.Namespace) -> None:
    print(filter_schedule.deploy_filter_schedule())


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
    result = replication.process_pending_enrollment_consumption()
    if result is None:
        print(json.dumps({"error": "no pending enrollment request found"}))
        raise SystemExit(1)
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
    local_dep = sub.add_parser("local-dns-deploy")
    local_dep.set_defaults(func=lambda args: print(local_dns.deploy_zones()))
    cache_dep = sub.add_parser("cache-deploy")
    cache_dep.set_defaults(func=lambda args: print(dns_cache.deploy_cache_options()))
    cache_flush = sub.add_parser("cache-flush")
    cache_flush.set_defaults(func=lambda args: print(dns_cache.process_pending_flush()))
    upstream_dep = sub.add_parser("upstream-deploy")
    upstream_dep.set_defaults(func=lambda args: print(upstream_dns.deploy_upstreams()))
    encryption_dep = sub.add_parser("encryption-deploy")
    encryption_dep.set_defaults(func=lambda args: print(encryption.deploy_encryption()))
    backup_create_parser = sub.add_parser("backup-create")
    backup_create_parser.set_defaults(func=backup_create)
    backup_restore_parser = sub.add_parser("backup-restore")
    backup_restore_parser.set_defaults(func=backup_restore)
    backup_preview_parser = sub.add_parser("backup-preview")
    backup_preview_parser.set_defaults(func=backup_preview)
    backup_schedule_parser = sub.add_parser("backup-schedule-deploy")
    backup_schedule_parser.set_defaults(func=backup_schedule_deploy)
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
