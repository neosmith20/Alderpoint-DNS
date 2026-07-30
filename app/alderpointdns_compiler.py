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
MAX_SOURCE_BYTES = 25 * 1024 * 1024
CONNECT_TIMEOUT = 10
TOTAL_TIMEOUT = 60
RPZ_ZONE = "alderpointdns.rpz"
DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.?$")


class AlderpointDNSConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> None:
        super().__exit__(exc_type, exc_value, traceback)
        self.close()


@dataclass
class ParseStats:
    parsed_rules: int = 0
    accepted_domains: int = 0
    duplicate_domains: int = 0
    invalid_rules: int = 0
    unsupported_rules: int = 0
    exceptions: int = 0
    errors: list[str] = field(default_factory=list)


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
    conn = sqlite3.connect(DB_PATH, factory=AlderpointDNSConnection)
    conn.row_factory = sqlite3.Row
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


def parse_line(line: str) -> tuple[str, str | None]:
    text = line.strip()
    if not text or text.startswith("#") or text.startswith("!") or text.startswith("//"):
        return "skip", None
    if text.startswith("[") and text.endswith("]"):
        return "skip", None

    if text.startswith("@@||"):
        if "$" in text:
            return "unsupported", None
        end = text.find("^", 4)
        candidate = text[4:end if end != -1 else None]
        return "allow", normalize_domain(candidate)

    if text.startswith("||"):
        if "$" in text:
            return "unsupported", None
        end = text.find("^", 2)
        candidate = text[2:end if end != -1 else None]
        return "block", normalize_domain(candidate)

    if text.startswith("@@") or "##" in text or "#@#" in text or "$" in text or "/" in text:
        return "unsupported", None

    parts = text.split()
    if len(parts) >= 2 and parts[0] in {"0.0.0.0", "127.0.0.1"}:
        return "block", normalize_domain(parts[1])

    if len(parts) == 1:
        return "block", normalize_domain(parts[0])

    return "invalid", None


def parse_rules(content: str) -> tuple[set[str], set[str], ParseStats]:
    blocks: set[str] = set()
    allows: set[str] = set()
    stats = ParseStats()
    for line_number, line in enumerate(content.splitlines(), 1):
        action, domain = parse_line(line)
        if action == "skip":
            continue
        if action == "unsupported":
            stats.unsupported_rules += 1
            continue
        if action == "invalid" or domain is None:
            stats.invalid_rules += 1
            if len(stats.errors) < 20:
                stats.errors.append(f"line {line_number}: invalid or unsupported domain")
            continue
        stats.parsed_rules += 1
        target = allows if action == "allow" else blocks
        if domain in target:
            stats.duplicate_domains += 1
            continue
        target.add(domain)
        stats.accepted_domains += 1
        if action == "allow":
            stats.exceptions += 1
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


def record_source_result(conn: sqlite3.Connection, result: SourceResult, stats: ParseStats | None = None) -> None:
    fields = {
        "last_attempt": now(),
        "http_status": result.http_status,
        "downloaded_bytes": result.downloaded_bytes,
        "last_error": result.error,
    }
    if result.success:
        fields["last_success"] = now()
    if stats:
        fields.update(
            {
                "parsed_rules": stats.parsed_rules,
                "accepted_domains": stats.accepted_domains,
                "duplicate_domains": stats.duplicate_domains,
                "invalid_rules": stats.invalid_rules,
                "unsupported_rules": stats.unsupported_rules,
            }
        )
    assignments = ", ".join(f"{key}=:{key}" for key in fields)
    fields["id"] = result.source_id
    conn.execute(f"UPDATE sources SET {assignments} WHERE id=:id", fields)


def enabled_sources(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM sources WHERE enabled=1 ORDER BY id"))


def collect_rules(conn: sqlite3.Connection, download: bool) -> tuple[set[str], set[str], dict[int, ParseStats], list[str]]:
    all_blocks: set[str] = set()
    all_allows: set[str] = set()
    per_source: dict[int, ParseStats] = {}
    errors: list[str] = []
    for source in enabled_sources(conn):
        result: SourceResult
        if download:
            result = download_source(source)
        else:
            current_path, _ = source_paths(source)
            result = SourceResult(source["id"], source["name"], source["url"], current_path.exists(), path=current_path)
            if not current_path.exists():
                result.error = "no successful downloaded copy exists"
        content = ""
        stats = ParseStats()
        if result.path and result.path.exists():
            content = result.path.read_text(errors="replace")
            blocks, allows, stats = parse_rules(content)
            all_blocks.update(blocks)
            all_allows.update(allows)
        if result.error:
            errors.append(f"{result.name}: {result.error}")
        record_source_result(conn, result, stats)
        per_source[source["id"]] = stats

    # Custom rules no longer merge into the external sets here; the deploy
    # path reads only custom_filter_rules through custom_rules.collect_active
    # and applies subdomain-aware allow subtraction on top of this result.
    active_blocks = all_blocks - all_allows
    conn.execute(
        "UPDATE sources SET final_active_domains=? WHERE enabled=1",
        (len(active_blocks),),
    )
    return active_blocks, all_allows, per_source, errors


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
                local_dns.deploy_zones(conn)
                dns_cache.deploy_cache_options(conn)
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
                    allowed_test = "cloudflare.com" if "cloudflare.com" in allowed_domains else sorted(allowed_domains)[0]
                    if not resolves(allowed_test):
                        raise RuntimeError(f"post-deploy allowed-domain test failed for {allowed_test}")
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
                if dnsdist_layer:
                    custom_rules.rollback_dnsdist_layer(dnsdist_layer)
                if backup_path.exists():
                    os.replace(backup_path, COMPILED_RPZ)
                    try:
                        reload_bind()
                        status = "rolled_back"
                    except Exception as rollback_exc:
                        status = "rollback_failed"
                        message = f"{message}; rollback failed: {rollback_exc}"
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
        for row in conn.execute("SELECT id, name, enabled, accepted_domains, invalid_rules, unsupported_rules, last_error FROM sources ORDER BY id"):
            print(dict(row))
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
    result = download_source(source)
    stats = ParseStats()
    if result.path and result.path.exists():
        blocks, _, stats = parse_rules(result.path.read_text(errors="replace"))
        conn.execute(
            "UPDATE sources SET final_active_domains=? WHERE id=?",
            (len(blocks), source["id"]),
        )
    record_source_result(conn, result, stats)
    return result, stats


def update_sources(_: argparse.Namespace) -> None:
    init_db()
    with connect() as conn:
        active_blocks, _, _, errors = collect_rules(conn, download=True)
        print(f"active_domains={len(active_blocks)}")
        for error in errors:
            print(f"error={error}")


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
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
