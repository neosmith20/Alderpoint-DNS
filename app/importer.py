#!/usr/bin/env python3
"""Alderpoint DNS Import and Migration: AdGuard Home migration, and spreadsheet/
text imports for Local DNS records, with staged preview, conflict
resolution, automatic backup, and rollback on failure.

Every function here only ever writes to SQLite (the same unprivileged
operation ordinary Local DNS / blocklist source edits already perform); the
privileged BIND/dnsdist deployment step is the existing, unmodified
`sudo alderpointdns_compiler.py deploy [--no-download]` path already used by
every other Local DNS and blocklist mutation. This module does not need any
new sudo entries.
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import ipaddress
import json
import re
import sqlite3
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

import yaml

from app import clients, custom_rules, local_dns, upstream_dns

DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
IMPORT_UPLOAD_DIR = Path("/var/lib/alderpointdns/imports")


class AlderpointDNSConnection(sqlite3.Connection):
    """Closes on exit like a plain connection factory would, but only once
    the outermost `with` block exits, so a nested `with conn: ...` reused as
    a transaction boundary doesn't close the connection out from under the
    rest of the function."""

    def __enter__(self):
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 0) + 1
        return super().__enter__()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        super().__exit__(exc_type, exc_value, traceback)
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 1) - 1
        if self._alderpointdns_depth <= 0:
            self.close()
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
# Text imports are additionally line-capped (the 10 MiB byte cap alone would
# still admit pathological inputs such as millions of one-character lines).
MAX_IMPORT_LINES = 200_000
MAX_LINE_CHARS = 2048
MAX_API_RESPONSE_BYTES = MAX_UPLOAD_BYTES

CANONICAL_FIELDS = [
    "hostname",
    "fqdn",
    "domain",
    "ipv4",
    "ipv6",
    "record_type",
    "target",
    "create_ptr",
    "ttl",
    "comment",
    "enabled",
    "client_alias",
    "client_id_or_cidr",
]
MIGRATION_SOURCE_TYPES = {"adguard_yaml", "adguard_api", "pihole", "alderpointdns_json"}


class ImportError_(ValueError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, factory=AlderpointDNSConnection, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        if close:
            db.execute("PRAGMA journal_mode=WAL")
        # execute(), not executescript(): executescript issues an implicit
        # COMMIT, which must never happen while a transactional apply is open.
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS import_jobs (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                finished_at TEXT,
                source_type TEXT NOT NULL,
                source_name TEXT NOT NULL DEFAULT '',
                headers_json TEXT NOT NULL DEFAULT '[]',
                raw_rows_json TEXT NOT NULL DEFAULT '[]',
                column_map_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'uploaded',
                total_rows INTEGER NOT NULL DEFAULT 0,
                valid_rows INTEGER NOT NULL DEFAULT 0,
                invalid_rows INTEGER NOT NULL DEFAULT 0,
                duplicate_rows INTEGER NOT NULL DEFAULT 0,
                conflict_rows INTEGER NOT NULL DEFAULT 0,
                applied_rows INTEGER NOT NULL DEFAULT 0,
                skipped_rows INTEGER NOT NULL DEFAULT 0,
                failed_rows INTEGER NOT NULL DEFAULT 0,
                inserted_record_ids_json TEXT NOT NULL DEFAULT '[]',
                report_json TEXT NOT NULL DEFAULT '{}',
                message TEXT NOT NULL DEFAULT ''
            )
            """
        )
        _ensure_column(db, "import_jobs", "source_path", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(db, "import_jobs", "rollback_json", "TEXT NOT NULL DEFAULT '{}'")
        _ensure_column(db, "import_jobs", "result_label", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(db, "import_jobs", "warning_rows", "INTEGER NOT NULL DEFAULT 0")
        if close:
            db.commit()
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Parsing: CSV / XLSX / hosts / zone
# ---------------------------------------------------------------------------

def _ensure_column(db: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def sanitize_filename(name: str) -> str:
    candidate = Path(name or "upload").name
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "-", candidate).strip(".-")
    return candidate[:160] or "upload"


def sanitize_url(url: str) -> str:
    """Strip userinfo, query strings, and fragments from a URL so credentials
    and access tokens never appear in job names or downloadable reports."""
    raw = str(url or "").strip()
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError:
        return raw.split("?", 1)[0].split("#", 1)[0]
    if not parts.scheme or not parts.hostname:
        return raw.split("?", 1)[0].split("#", 1)[0]
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    if parts.port:
        host = f"{host}:{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", ""))


_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
# Individual word-boundary tokens that make a key sensitive on their own
# (e.g. "admin_password", "AuthToken" -> tokens "admin"/"password",
# "auth"/"token"). Deliberately excludes bare "key", since this codebase has
# legitimate non-secret fields named "key"/"keys" (the migration preview's
# stable item-selection keys).
_SENSITIVE_KEY_TOKENS = {"password", "passwd", "token", "secret", "authorization", "auth", "credentials", "credential"}
# Compound forms only sensitive without a separator, checked against the key
# with all separators stripped (so "api_key" and "apikey" both match, but
# "api"/"key" alone do not).
_SENSITIVE_KEY_COMPOUNDS = {"apikey"}


def _is_sensitive_key(key: Any) -> bool:
    normalized = _CAMEL_BOUNDARY_RE.sub("_", str(key)).lower()
    if _NON_ALNUM_RE.sub("", normalized) in _SENSITIVE_KEY_COMPOUNDS:
        return True
    return any(token in _SENSITIVE_KEY_TOKENS for token in _NON_ALNUM_RE.split(normalized) if token)


def redact_sensitive(value: Any) -> Any:
    """Recursively sanitize a report payload: drop credential-named keys and
    strip userinfo/query strings from every embedded URL. Key matching is
    token-based (word-boundary and camelCase aware), not exact-string, so
    compound names like "admin_password" or "AuthToken" are caught too."""
    if isinstance(value, dict):
        return {
            key: redact_sensitive(item)
            for key, item in value.items()
            if not _is_sensitive_key(key)
        }
    if isinstance(value, (list, tuple)):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        return _URL_RE.sub(lambda match: sanitize_url(match.group(0)), value)
    return value


def check_text_limits(text: str) -> None:
    lines = text.count("\n") + 1
    if lines > MAX_IMPORT_LINES:
        raise ImportError_(
            f"import text has {lines} lines, exceeding the {MAX_IMPORT_LINES}-line limit; split the import into smaller files"
        )


def stage_uploaded_source(filename: str, data: bytes) -> Path:
    if not data:
        raise ImportError_("uploaded file is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ImportError_(f"uploaded file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit")
    IMPORT_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    target = IMPORT_UPLOAD_DIR / f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{sanitize_filename(filename)}"
    target.write_bytes(data)
    target.chmod(0o640)
    return target


def _init_filter_tables(conn: sqlite3.Connection) -> None:
    # execute(), not executescript(), so no implicit COMMIT can fire while a
    # caller holds an open transaction.
    conn.execute(
        """
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
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS custom_rules (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('allow', 'block')),
            enabled INTEGER NOT NULL DEFAULT 1,
            comment TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(domain, action)
        )
        """
    )


def parse_csv_text(text: str) -> tuple[list[str], list[dict[str, str]]]:
    reader = csv.DictReader(StringIO(text))
    rows = [dict(row) for row in reader]
    headers = list(reader.fieldnames or [])
    return headers, rows


def parse_xlsx_bytes(data: bytes) -> tuple[list[str], list[dict[str, str]]]:
    import openpyxl

    wb = openpyxl.load_workbook(BytesIO(data), read_only=True, data_only=True)
    sheet = wb.active
    rows_iter = sheet.iter_rows(values_only=True)
    try:
        headers = [str(cell).strip() if cell is not None else "" for cell in next(rows_iter)]
    except StopIteration:
        return [], []
    rows = []
    for values in rows_iter:
        if all(v is None for v in values):
            continue
        row = {headers[i]: ("" if values[i] is None else str(values[i])) for i in range(min(len(headers), len(values)))}
        rows.append(row)
    return headers, rows


def parse_hosts_text(text: str, default_domain: str) -> list[dict[str, str]]:
    domain = local_dns.normalize_domain(default_domain)
    rows: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        try:
            ip = ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        for host in parts[1:]:
            row = {field: "" for field in CANONICAL_FIELDS}
            row["fqdn"] = local_dns.normalize_fqdn(host, domain)
            row["record_type"] = "A" if isinstance(ip, ipaddress.IPv4Address) else "AAAA"
            row["target"] = str(ip)
            row["ttl"] = "300"
            row["enabled"] = "1"
            row["create_ptr"] = "0"
            rows.append(row)
    return rows


ZONE_LINE_RE = re.compile(
    r"^(?P<name>\S+)\s+(?:(?P<ttl>\d+)\s+)?(?:IN\s+)?(?P<type>A|AAAA|CNAME|PTR)\s+(?P<data>\S+)\s*$",
    re.IGNORECASE,
)


def parse_zone_text(text: str, default_domain: str) -> list[dict[str, str]]:
    """A practical subset of BIND zone-file syntax: `name [ttl] [IN] TYPE data`
    lines for A/AAAA/CNAME/PTR records. $ORIGIN/$TTL directives, SOA/NS/MX
    records, and multi-line parenthesized records are not supported."""
    domain = local_dns.normalize_domain(default_domain)
    origin = domain
    rows: list[dict[str, str]] = []
    for raw in text.splitlines():
        line = raw.split(";", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.upper().startswith("$ORIGIN"):
            origin = local_dns.normalize_domain(line.split(None, 1)[1].strip().rstrip("."))
            continue
        if line.startswith("$"):
            continue
        match = ZONE_LINE_RE.match(line.strip())
        if not match:
            continue
        name = match.group("name")
        rtype = match.group("type").upper()
        data = match.group("data").rstrip(".")
        fqdn = origin if name in ("@", "") else local_dns.normalize_fqdn(name, origin)
        row = {field: "" for field in CANONICAL_FIELDS}
        row["fqdn"] = fqdn
        row["record_type"] = rtype
        row["target"] = data
        row["ttl"] = match.group("ttl") or "300"
        row["enabled"] = "1"
        row["create_ptr"] = "0"
        rows.append(row)
    return rows


def parse_alderpointdns_csv(text: str) -> list[dict[str, str]]:
    _headers, rows = parse_csv_text(text)
    out = []
    for row in rows:
        item = {field: "" for field in CANONICAL_FIELDS}
        item["fqdn"] = row.get("fqdn", "")
        item["record_type"] = row.get("record_type", "")
        item["target"] = row.get("value", "")
        item["ttl"] = row.get("ttl", "300")
        item["enabled"] = row.get("enabled", "1")
        item["comment"] = row.get("comment", "")
        out.append(item)
    return out


# Pi-hole section headers accepted as `[name]` lines or `# name` comment
# markers (as commonly produced when several Pi-hole files are pasted into
# one text block). Bare domains inside a whitelist section become exact
# allow rules instead of the default exact block.
_PIHOLE_SECTIONS = {
    "adlist": "adlists",
    "adlists": "adlists",
    "adlists.list": "adlists",
    "whitelist": "whitelist",
    "whitelist.txt": "whitelist",
    "exact whitelist": "whitelist",
    "blacklist": "blacklist",
    "blacklist.txt": "blacklist",
    "exact blacklist": "blacklist",
    "regex": "regex_black",
    "regex.list": "regex_black",
    "regex blacklist": "regex_black",
    "blacklist regex": "regex_black",
    "regex whitelist": "regex_white",
    "whitelist regex": "regex_white",
    "custom.list": "hosts",
    "custom list": "hosts",
    "hosts": "hosts",
    "local dns": "hosts",
    "cname": "cname",
    "cnames": "cname",
    "custom cname": "cname",
    "group": "groups",
    "groups": "groups",
}

# Pi-hole's wildcard-blocking idiom: `pihole -wild domain.tld` stores the
# regex (\.|^)domain\.tld$ (also seen as (^|\.)domain\.tld$).
_PIHOLE_WILDCARD_RE = re.compile(r"^\((?:\\\.\|\^|\^\|\\\.)\)((?:[A-Za-z0-9_-]+\\\.)+[A-Za-z0-9_-]+)\$$")

_PIHOLE_DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _pihole_section_for(line: str) -> str | None:
    stripped = line.strip()
    match = re.match(r"^\[([^\]]+)\]$", stripped)
    if not match:
        match = re.match(r"^#+\s*(.+?)\s*#*\s*$", stripped)
    if not match:
        return None
    return _PIHOLE_SECTIONS.get(match.group(1).strip().lower())


def _pihole_regex_entry(pattern: str, allow: bool, original: str) -> dict[str, Any]:
    """Translate one Pi-hole regex list line. The wildcard-blocking idiom is
    recognized and offered as a subdomain rule of the normalized domain; the
    original regex text is preserved in the rule comment."""
    wildcard = _PIHOLE_WILDCARD_RE.match(pattern)
    if wildcard:
        domain = wildcard.group(1).replace("\\.", ".")
        return {
            "text": original,
            "rule": ("@@||" if allow else "||") + domain + "^",
            "plain_domain_subdomains": True,
            "origin": "regex whitelist" if allow else "regex.list",
            "comment": f"Pi-hole wildcard regex: {pattern}",
        }
    return {
        "text": original,
        "rule": ("@@/" if allow else "/") + pattern + "/",
        "plain_domain_subdomains": False,
        "origin": "regex whitelist" if allow else "regex.list",
        "comment": "",
    }


def parse_pihole_text(text: str, default_domain: str) -> dict[str, Any]:
    """Structured multi-section parser for practical Pi-hole exports:
    adlists.list URLs, exact whitelist/blacklist domains (with or without the
    `whitelist`/`blacklist` keyword), regex block and regex allow lists, the
    wildcard-blocking regex idiom, custom.list hosts-style Local DNS records,
    dnsmasq `cname=alias,target[,ttl]` lines, and group-assignment syntax
    (reported as explicit findings; Alderpoint DNS has no group equivalent).
    Anything unrecognized becomes an explicit unsupported finding, never a
    silent drop."""
    check_text_limits(text)
    blocklist_sources: list[dict[str, Any]] = []
    rule_entries: list[dict[str, Any]] = []
    rewrites_as_local_dns: list[dict[str, Any]] = []
    client_scoped: list[str] = []
    unsupported: list[str] = []
    section: str | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if len(line) > MAX_LINE_CHARS:
            unsupported.append(f"line {number} exceeds {MAX_LINE_CHARS} characters and was not imported")
            continue
        new_section = _pihole_section_for(line)
        if new_section:
            section = new_section
            continue
        if line.startswith("#"):
            rule_entries.append({"text": line, "rule": line, "plain_domain_subdomains": False, "origin": "comment", "comment": ""})
            continue
        lower = line.lower()
        if lower.startswith(("http://", "https://")):
            blocklist_sources.append({
                "name": sanitize_filename(line.rsplit("/", 1)[-1].split("?", 1)[0] or "Pi-hole list"),
                "url": line,
                "enabled": True,
                "category": "ads_trackers",
            })
            continue
        if lower.startswith("cname="):
            parts = [part.strip() for part in line[len("cname="):].split(",")]
            if len(parts) >= 2 and parts[0] and parts[1]:
                try:
                    fqdn = local_dns.normalize_fqdn(parts[0], default_domain)
                    target = local_dns.normalize_fqdn(parts[1], default_domain)
                except Exception as exc:
                    unsupported.append(f"line {number}: invalid cname entry ({exc}): {line}")
                    continue
                ttl = parts[2] if len(parts) >= 3 and parts[2] else "300"
                rewrites_as_local_dns.append({"fqdn": fqdn, "record_type": "CNAME", "value": target, "ttl": ttl, "origin": "05-pihole-custom-cname.conf"})
            else:
                unsupported.append(f"line {number}: invalid cname entry (need cname=alias,target): {line}")
            continue
        if lower.startswith(("whitelist ", "allow ")):
            domain = line.split(None, 1)[1].strip().strip(".")
            rule_entries.append({"text": line, "rule": "@@" + domain, "plain_domain_subdomains": False, "origin": "whitelist.txt", "comment": ""})
            continue
        if lower.startswith(("blacklist ", "block ", "deny ")):
            domain = line.split(None, 1)[1].strip().strip(".")
            rule_entries.append({"text": line, "rule": domain, "plain_domain_subdomains": False, "origin": "blacklist.txt", "comment": ""})
            continue
        if lower.startswith("regex whitelist "):
            rule_entries.append(_pihole_regex_entry(line[len("regex whitelist "):].strip(), True, line))
            continue
        if lower.startswith("regex "):
            rule_entries.append(_pihole_regex_entry(line[len("regex "):].strip(), False, line))
            continue
        if lower.startswith("group ") or section == "groups":
            client_scoped.append(f"line {number}: Pi-hole group assignments have no Alderpoint DNS equivalent and were not imported: {line}")
            continue
        if section == "regex_black":
            rule_entries.append(_pihole_regex_entry(line, False, line))
            continue
        if section == "regex_white":
            rule_entries.append(_pihole_regex_entry(line, True, line))
            continue
        parts = line.split()
        if len(parts) >= 2:
            try:
                ip = ipaddress.ip_address(parts[0])
            except ValueError:
                ip = None
            if ip is not None:
                for host in parts[1:]:
                    try:
                        fqdn = local_dns.normalize_fqdn(host, default_domain)
                    except Exception as exc:
                        unsupported.append(f"line {number}: invalid hostname in custom.list entry ({exc}): {line}")
                        continue
                    rewrites_as_local_dns.append({
                        "fqdn": fqdn,
                        "record_type": "A" if isinstance(ip, ipaddress.IPv4Address) else "AAAA",
                        "value": str(ip),
                        "ttl": 300,
                        "origin": "custom.list",
                    })
                continue
        comma_split = [part.strip() for part in re.split(r"[,\t]", line)]
        if len(comma_split) > 1 and _PIHOLE_DOMAIN_RE.match(comma_split[0]) and all(part.isdigit() for part in comma_split[1:] if part):
            client_scoped.append(
                f"line {number}: Pi-hole group-assignment columns have no Alderpoint DNS equivalent; the row was not imported: {line}"
            )
            continue
        if _PIHOLE_DOMAIN_RE.match(line):
            domain = line.strip(".")
            if section == "whitelist":
                rule_entries.append({"text": line, "rule": "@@" + domain, "plain_domain_subdomains": False, "origin": "whitelist.txt", "comment": ""})
            else:
                rule_entries.append({"text": line, "rule": domain, "plain_domain_subdomains": False, "origin": "blacklist.txt", "comment": ""})
            continue
        unsupported.append(f"line {number}: unrecognized Pi-hole line: {line}")
    return {
        "blocklist_sources": blocklist_sources,
        "allowlist_unsupported": [],
        "custom_rules": rule_entries,
        "custom_allow": [],
        "custom_block": [],
        "unsupported_rules": unsupported,
        "rewrites_as_local_dns": rewrites_as_local_dns,
        "clients_as_aliases": [],
        "client_scoped": client_scoped,
        "upstream_resolvers": [],
        "untranslatable": [],
    }


def export_alderpointdns_native(conn: sqlite3.Connection | None = None) -> str:
    close = conn is None
    db = conn or connect()
    try:
        local_dns.init_db(db)
        upstream_dns.init_db(db)
        _init_filter_tables(db)
        custom_rules.init_db(db)
        clients.init_db(db)
        native_clients = []
        for client_row in db.execute("SELECT id, name, description, enabled FROM clients ORDER BY id"):
            identifiers = [
                {"kind": row["kind"], "value": row["value"]}
                for row in db.execute("SELECT kind, value FROM client_identifiers WHERE client_id=? ORDER BY id", (client_row["id"],))
            ]
            native_clients.append({
                "name": client_row["name"],
                "description": client_row["description"],
                "enabled": bool(client_row["enabled"]),
                "identifiers": identifiers,
            })
        access_rules_rows = db.execute(
            """
            SELECT access_rules.action, access_rules.kind, access_rules.value, clients.name AS client_name
            FROM access_rules LEFT JOIN clients ON clients.id = access_rules.client_id
            ORDER BY access_rules.id
            """
        ).fetchall()
        default_policy_row = db.execute("SELECT default_policy FROM access_settings WHERE id=1").fetchone()
        payload = {
            "format": "alderpointdns-native",
            # v2 adds "clients" (full multi-identifier persistent client
            # model) and "access_policy" (default policy + allow/deny
            # rules) alongside the pre-existing v1 fields, which are kept
            # for backward compatibility -- an older Alderpoint DNS build
            # reading a v2 export still finds every v1 key it expects.
            "version": 2,
            "created_at": now(),
            "local_dns_records": [dict(row) for row in db.execute("SELECT fqdn, record_type, value, ttl, comment, enabled FROM local_dns_records ORDER BY fqdn, record_type, value")],
            "client_aliases": [dict(row) for row in db.execute("SELECT cidr, display_name, description FROM client_aliases ORDER BY cidr")],
            "clients": native_clients,
            "access_policy": {
                "default_policy": default_policy_row["default_policy"] if default_policy_row else "allow",
                "rules": [dict(row) for row in access_rules_rows],
            },
            "custom_rules": [dict(row) for row in db.execute("SELECT domain, action, enabled, comment FROM custom_rules ORDER BY domain, action")],
            "custom_filter_rules": [
                dict(row)
                for row in db.execute(
                    "SELECT rule_text, enabled, comment FROM custom_filter_rules WHERE source_system != 'legacy' ORDER BY id"
                )
            ],
            "blocklist_sources": [dict(row) for row in db.execute("SELECT name, url, enabled, category FROM sources ORDER BY name")],
            "upstream_resolvers": [
                {
                    key: row[key]
                    for key in ("name", "protocol", "address", "port", "doh_path", "tls_hostname", "bootstrap_ips", "enabled", "position")
                    if key in row.keys()
                }
                for row in db.execute("SELECT name, protocol, address, port, doh_path, tls_hostname, bootstrap_ips, enabled, position FROM upstream_resolvers ORDER BY position, id")
            ],
        }
        return json.dumps(payload, indent=2)
    finally:
        if close:
            db.close()


def parse_alderpointdns_native_json(text: str) -> dict[str, Any]:
    data = json.loads(text)
    if not isinstance(data, dict) or data.get("format") != "alderpointdns-native":
        raise ImportError_("not a Alderpoint DNS native JSON export")
    local_records = []
    for row in data.get("local_dns_records", []):
        if isinstance(row, dict):
            local_records.append({"fqdn": row.get("fqdn", ""), "record_type": row.get("record_type", ""), "value": row.get("value", ""), "ttl": row.get("ttl", 300)})
    rule_entries = []
    for row in data.get("custom_filter_rules", []):
        if isinstance(row, dict) and str(row.get("rule_text", "")).strip():
            rule_entries.append({
                "text": str(row["rule_text"]).strip(),
                "rule": str(row["rule_text"]).strip(),
                "plain_domain_subdomains": True,
                "origin": "custom_filter_rules",
                "comment": str(row.get("comment", "")),
            })
    clients_full = []
    for row in data.get("clients", []) or []:
        if not isinstance(row, dict) or not row.get("name"):
            continue
        identifiers = []
        for ident in row.get("identifiers", []) or []:
            if isinstance(ident, dict) and ident.get("kind") and ident.get("value"):
                identifiers.append({"kind": ident["kind"], "value": ident["value"]})
        clients_full.append({
            "name": row["name"],
            "description": row.get("description", ""),
            "identifiers": identifiers,
            "weak_clientids": [],
            "unrecognized": [],
            "enabled": bool(row.get("enabled", True)),
        })
    access_policy = data.get("access_policy") if isinstance(data.get("access_policy"), dict) else {}
    access_allowed = []
    access_denied = []
    for rule in access_policy.get("rules", []) or []:
        if not isinstance(rule, dict):
            continue
        entry = {"kind": rule.get("kind", ""), "value": rule.get("value") or "", "raw": rule.get("value") or "", "client_name": rule.get("client_name")}
        (access_allowed if rule.get("action") == "allow" else access_denied).append(entry)

    return {
        "blocklist_sources": [row for row in data.get("blocklist_sources", []) if isinstance(row, dict)],
        "allowlist_unsupported": [],
        "custom_rules": rule_entries,
        "custom_allow": sorted({row.get("domain", "") for row in data.get("custom_rules", []) if isinstance(row, dict) and row.get("action") == "allow"}),
        "custom_block": sorted({row.get("domain", "") for row in data.get("custom_rules", []) if isinstance(row, dict) and row.get("action") == "block"}),
        "unsupported_rules": [],
        "rewrites_as_local_dns": local_records,
        "clients_as_aliases": [
            {"display_name": row.get("display_name", ""), "cidr_or_ip": row.get("cidr", ""), "all_ids": []}
            for row in data.get("client_aliases", [])
            if isinstance(row, dict)
        ],
        "clients_full": clients_full,
        "access_default_policy": access_policy.get("default_policy") if access_policy.get("default_policy") in {"allow", "deny"} else None,
        "access_allowed": access_allowed,
        "access_denied": access_denied,
        "client_scoped": [],
        "upstream_resolvers": [row for row in data.get("upstream_resolvers", []) if isinstance(row, dict)],
        "untranslatable": [],
    }


def _rule_entries(translation: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalized custom-rule entries from a stored translation. Newer
    translations carry typed `custom_rules` entries; the legacy
    `custom_allow`/`custom_block` domain lists (Alderpoint DNS native JSON)
    keep their historical subdomain semantics."""
    entries: list[dict[str, Any]] = []
    for raw in translation.get("custom_rules", []):
        if not isinstance(raw, dict):
            continue
        rule = str(raw.get("rule") or raw.get("text") or "").strip()
        if not rule:
            continue
        entries.append({
            "text": str(raw.get("text") or rule).strip(),
            "rule": rule,
            "plain_domain_subdomains": bool(raw.get("plain_domain_subdomains", True)),
            "origin": str(raw.get("origin", "")),
            "comment": str(raw.get("comment", "")),
        })
    for action, prefix in (("custom_allow", "@@||"), ("custom_block", "||")):
        for domain in translation.get(action, []):
            name = str(domain).strip().strip(".")
            if not name:
                continue
            entries.append({
                "text": name,
                "rule": f"{prefix}{name}^",
                "plain_domain_subdomains": True,
                "origin": action,
                "comment": "",
            })
    return entries


MIGRATION_CATEGORIES: dict[str, str] = {
    "blocklists": "Blocklist subscriptions",
    "custom_blocks": "Custom block rules",
    "custom_allows": "Custom allow rules",
    "rewrites": "Rewrite rules",
    "regex_rules": "Regex rules",
    "local_dns": "Local DNS records",
    "upstreams": "Upstream resolvers",
    "client_scoped": "Client-scoped items",
    "clients_access": "Clients & Access",
    "comments": "Comments",
    "duplicates": "Duplicates within the import",
    "invalid": "Invalid entries",
    "unsupported": "Unsupported entries",
    "skipped": "Skipped entries",
}

_RULE_TYPE_CATEGORY = {
    "block": "custom_blocks",
    "allow": "custom_allows",
    "rewrite": "rewrites",
    "regex_block": "regex_rules",
    "regex_allow": "regex_rules",
}


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())


def _internal_domain(default_domain: str | None = None) -> str:
    """Resolve the internal domain without creating tables or rows, so
    preview stays a pure read."""
    if default_domain:
        return str(default_domain).strip().strip(".").lower()
    try:
        with connect() as conn:
            if _table_exists(conn, "local_dns_settings"):
                row = conn.execute("SELECT value FROM local_dns_settings WHERE key='internal_domain'").fetchone()
                if row:
                    return row["value"]
    except sqlite3.Error:
        pass
    return local_dns.DEFAULT_DOMAIN


def _describe_rule(rule: Any) -> str:
    if rule.rule_type == "comment":
        return "comment"
    if rule.rule_type in {"regex_block", "regex_allow"}:
        label = "regex allow" if rule.rule_type == "regex_allow" else "regex block"
    elif rule.rule_type == "rewrite":
        label = f"rewrite to {rule.rewrite_address}"
    else:
        label = rule.rule_type
    if rule.rule_type in {"block", "allow", "rewrite"}:
        label += " (domain + subdomains)" if rule.match_subdomains else " (exact host)"
    if rule.priority:
        label += ", $important"
    return label


def build_migration_plan(translation: dict[str, Any], default_domain: str | None = None) -> dict[str, Any]:
    """Deterministic, itemized classification of a stored translation.

    Every item gets a stable `category:index` key derived only from the
    translation payload frozen in the job row (never from live database
    state), so keys rendered in a preview remain valid when the selection is
    POSTed back to apply. Database-dependent annotations (already-exists,
    record conflicts) are added by summarize_migration() as display fields
    that never change an item's category or key."""
    domain = _internal_domain(default_domain)
    categories: dict[str, list[dict[str, Any]]] = {key: [] for key in MIGRATION_CATEGORIES}

    def add(
        category: str,
        *,
        source: str,
        detected: str,
        destination: str,
        normalized: str = "",
        outcome: str = "active",
        warning: str = "",
        conflict: str = "",
        selectable: bool = True,
        selected: bool = True,
        apply: tuple[str, int] | None = None,
        dupkeys: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any]:
        item = {
            "key": f"{category}:{len(categories[category])}",
            "category": category,
            "source": source,
            "detected": detected,
            "destination": destination,
            "normalized": normalized,
            "outcome": outcome,
            "warning": warning,
            "conflict": conflict,
            "selectable": selectable,
            "selected": bool(selected and selectable),
            "apply": apply,
            "_dupkeys": dupkeys or [],
        }
        categories[category].append(item)
        return item

    # Blocklist subscription sources.
    for index, raw_source in enumerate(translation.get("blocklist_sources", [])):
        source = raw_source if isinstance(raw_source, dict) else {}
        name = str(source.get("name", "")).strip()[:120]
        url = str(source.get("url", "")).strip()
        category = str(source.get("category", "ads_trackers")).strip() or "ads_trackers"
        enabled = bool(source.get("enabled", True))
        if not name or not url or not url.lower().startswith(("http://", "https://")):
            add(
                "skipped",
                source=f"{name or '(unnamed)'} {url or '(no URL)'}".strip(),
                detected="blocklist subscription",
                destination="Blocklists",
                warning="missing name or non-HTTP(S) URL",
                outcome="informational",
                selectable=False,
            )
            continue
        add(
            "blocklists",
            source=name,
            detected=f"blocklist subscription ({category})",
            destination="Blocklists",
            normalized=url,
            outcome="active" if enabled else "inactive",
            apply=("source", index),
        )

    # Custom filtering rules (typed entries plus legacy allow/block lists).
    entries = _rule_entries(translation)
    seen_rules: set[tuple[str, str]] = set()
    domain_actions: dict[str, set[str]] = {}
    parsed_entries: list[tuple[int, dict[str, Any], list[Any]]] = []
    for index, entry in enumerate(entries):
        rules = custom_rules.parse_rule(entry["rule"], plain_domain_subdomains=entry["plain_domain_subdomains"])
        parsed_entries.append((index, entry, rules))
        for rule in rules:
            if rule.validation_state == "valid" and rule.domain and rule.action in {"allow", "block"}:
                domain_actions.setdefault(rule.domain, set()).add(rule.action)
    conflicted_domains = {name for name, actions in domain_actions.items() if len(actions) > 1}
    for index, entry, rules in parsed_entries:
        if not rules:
            continue
        # Comments are included (not filtered out) so a comment that already
        # exists verbatim -- either earlier in this same import or from a
        # previous run against this database -- is recognized as a
        # duplicate too, the same as block/allow/rewrite/regex rules.
        valid_rules = [r for r in rules if r.validation_state == "valid"]
        invalid_rules = [r for r in rules if r.validation_state == "invalid"]
        unsupported_rules_ = [r for r in rules if r.validation_state == "unsupported"]
        dupkeys = [(r.normalized, r.action) for r in valid_rules]
        all_duplicate = bool(valid_rules) and all(key in seen_rules for key in dupkeys)
        seen_rules.update(dupkeys)
        conflict = ""
        hit = next((r.domain for r in valid_rules if r.domain in conflicted_domains), None)
        if hit:
            conflict = f"both allow and block rules in this import target {hit}"
        warning = "; ".join(r.unsupported_reason for r in invalid_rules + unsupported_rules_ if r.unsupported_reason)
        normalized = "; ".join(r.normalized for r in rules)
        first = rules[0]
        detected = _describe_rule(valid_rules[0] if valid_rules else first)
        if len(rules) > 1:
            detected = f"hosts entry ({len(rules)} hostnames): {detected}"
        if all(r.rule_type == "comment" for r in rules):
            add(
                "comments",
                source=entry["text"],
                detected="comment",
                destination="Custom Rules",
                normalized=normalized,
                outcome="comment only, no DNS effect",
                apply=("rule", index),
            )
        elif all_duplicate:
            add(
                "duplicates",
                source=entry["text"],
                detected=detected,
                destination="Custom Rules",
                normalized=normalized,
                conflict="duplicate within this import",
                outcome="inactive",
                selected=False,
                apply=("rule", index),
                dupkeys=dupkeys,
            )
        elif not valid_rules and invalid_rules and not unsupported_rules_:
            add(
                "invalid",
                source=entry["text"],
                detected="invalid rule",
                destination="Custom Rules",
                normalized=normalized,
                warning=warning,
                outcome="inactive",
                apply=("rule", index),
            )
        elif not valid_rules and unsupported_rules_:
            reason = "; ".join(r.unsupported_reason for r in unsupported_rules_)
            category = "client_scoped" if "$client" in reason else "unsupported"
            add(
                category,
                source=entry["text"],
                detected="unsupported rule",
                destination="Custom Rules",
                normalized=normalized,
                warning=reason,
                outcome="inactive",
                apply=("rule", index),
            )
        else:
            category = _RULE_TYPE_CATEGORY.get(valid_rules[0].rule_type, "unsupported")
            add(
                category,
                source=entry["text"],
                detected=detected,
                destination="Custom Rules",
                normalized=normalized,
                warning=warning,
                conflict=conflict,
                outcome="active",
                apply=("rule", index),
                dupkeys=dupkeys,
            )

    # Local DNS records (hosts entries, rewrites under the internal domain,
    # and CNAME records).
    seen_records: set[tuple[str, str, str]] = set()
    for index, rec in enumerate(translation.get("rewrites_as_local_dns", [])):
        record = rec if isinstance(rec, dict) else {}
        label = f"{record.get('fqdn', '')} {record.get('record_type', '')} {record.get('value', '')}".strip()
        try:
            fqdn = local_dns.normalize_fqdn(str(record.get("fqdn", "")), domain)
            rtype, fqdn, value, ttl = local_dns.validate_record(
                str(record.get("record_type", "")),
                fqdn,
                str(record.get("value", "")),
                record.get("ttl", 300) or 300,
            )
        except Exception as exc:
            add(
                "invalid",
                source=label,
                detected="local DNS record",
                destination="Local DNS",
                warning=str(exc),
                outcome="informational",
                selectable=False,
            )
            continue
        key = (fqdn, rtype, value)
        normalized = f"{fqdn} {rtype} {value} (TTL {ttl})"
        if key in seen_records:
            add(
                "duplicates",
                source=label,
                detected=f"{rtype} record",
                destination="Local DNS",
                normalized=normalized,
                conflict="duplicate within this import",
                outcome="inactive",
                selected=False,
                apply=("local_dns", index),
            )
            continue
        seen_records.add(key)
        enabled = bool(record.get("enabled", True))
        disabled_reason = str(record.get("disabled_reason", ""))
        item = add(
            "local_dns",
            source=label,
            detected=f"{rtype} record",
            destination="Local DNS",
            normalized=normalized,
            outcome="disabled at source" if not enabled else "new",
            warning=disabled_reason,
            apply=("local_dns", index),
        )
        item["_record"] = [fqdn, rtype, value]
        item["_enabled"] = enabled

    # Upstream resolvers.
    seen_resolvers: set[tuple[str, str, int, str]] = set()
    for index, resolver in enumerate(translation.get("upstream_resolvers", [])):
        raw = resolver if isinstance(resolver, dict) else {}
        label = str(raw.get("name") or raw.get("address") or raw)
        try:
            data = upstream_dns.validate_resolver({**raw, "enabled": raw.get("enabled", "1")}, require_enabled_set=True)
        except Exception as exc:
            add(
                "skipped",
                source=label,
                detected="upstream resolver",
                destination="Upstream DNS",
                warning=str(exc),
                outcome="informational",
                selectable=False,
            )
            continue
        key = (data["protocol"], data["address"], int(data["port"]), data["doh_path"] or "")
        normalized = f"{data['protocol']} {data['address']}:{data['port']}{data['doh_path'] or ''}"
        if key in seen_resolvers:
            add(
                "duplicates",
                source=label,
                detected="upstream resolver",
                destination="Upstream DNS",
                normalized=normalized,
                conflict="duplicate within this import",
                outcome="inactive",
                selected=False,
                apply=("upstream", index),
            )
            continue
        seen_resolvers.add(key)
        item = add(
            "upstreams",
            source=label,
            detected=f"{data['protocol']} upstream",
            destination="Upstream DNS",
            normalized=normalized,
            outcome="active" if str(data["enabled"]) == "1" else "inactive",
            apply=("upstream", index),
        )
        item["_upstream_key"] = list(key)

    # Legacy display-only client aliases. Only surfaced when this
    # translation has no richer clients_full data (native-JSON v1 imports,
    # or a hypothetical future source with no ClientID/multi-identifier
    # concept) -- AdGuard imports always populate clients_full, which is
    # the enforced, runtime-effective successor to this. Without this
    # guard, an AdGuard client would be imported twice: once as a rich
    # new-model client, and again via this legacy path's own
    # client_aliases row, which the new-model migration in
    # app.clients.init_db() would then auto-promote into a *second*,
    # duplicate clients-table row the next time anything touched the DB.
    for index, client in enumerate(translation.get("clients_as_aliases", []) if not translation.get("clients_full") else []):
        raw = client if isinstance(client, dict) else {}
        name = str(raw.get("display_name", "")).strip()
        cidr = str(raw.get("cidr_or_ip", "")).strip()
        try:
            network = str(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            network = ""
        if not name or not network:
            add(
                "skipped",
                source=f"{name or '(unnamed)'} {cidr or '(no address)'}",
                detected="client alias",
                destination="Client aliases",
                warning="client needs a display name and a valid IP or CIDR",
                outcome="informational",
                selectable=False,
            )
            continue
        item = add(
            "client_scoped",
            source=f"{name} ({cidr})",
            detected="client alias (display label only)",
            destination="Client aliases",
            normalized=f"{network} -> {name}",
            apply=("alias", index),
        )
        item["_alias_cidr"] = network

    # New-model persistent clients (name + every identifier, including
    # strong ClientIDs) -- this is the enforced, runtime-effective
    # successor to the display-only "client alias" item above. Weak
    # (sub-192-bit) ClientIDs found on the client are reported inline as
    # part of the item's warning, never activated.
    for index, client in enumerate(translation.get("clients_full", [])):
        name = str(client.get("name", "")).strip()
        identifiers = client.get("identifiers", [])
        weak = client.get("weak_clientids", [])
        unrecognized = client.get("unrecognized", [])
        if not name or not identifiers:
            continue
        summary = ", ".join(f"{i['kind']}={i['value']}" for i in identifiers)
        warning_bits = []
        if weak:
            warning_bits.append(
                f"{len(weak)} ClientID(s) below Alderpoint's 192-bit minimum were found and are NOT imported as active "
                "ClientIDs (generate a new strong ClientID for this client after import if encrypted-DNS identification is needed)"
            )
        if unrecognized:
            warning_bits.append(f"{len(unrecognized)} unrecognized identifier(s) were not imported: {', '.join(unrecognized)}")
        add(
            "clients_access",
            source=f"{name} ({summary})",
            detected="persistent client",
            destination="Clients & Access",
            normalized=summary,
            warning="; ".join(warning_bits),
            apply=("client", index),
        )
    for index, rule in enumerate(translation.get("access_allowed", [])):
        add(
            "clients_access",
            source=f"{rule.get('raw', rule.get('value', ''))}",
            detected=f"allowed client ({rule.get('kind', '')})",
            destination="Clients & Access (Allowed)",
            normalized=str(rule.get("value", "")),
            apply=("access_allow", index),
        )
    for index, rule in enumerate(translation.get("access_denied", [])):
        add(
            "clients_access",
            source=f"{rule.get('raw', rule.get('value', ''))}",
            detected=f"denied client ({rule.get('kind', '')})",
            destination="Clients & Access (Denied)",
            normalized=str(rule.get("value", "")),
            apply=("access_deny", index),
        )
    for finding in translation.get("client_scoped", []):
        add(
            "client_scoped",
            source=str(finding),
            detected="client-scoped setting",
            destination="Not imported",
            outcome="informational",
            warning="Alderpoint DNS has no per-client policy enforcement yet",
            selectable=False,
        )

    # Findings that carry no importable object.
    for entry in translation.get("allowlist_unsupported", []):
        raw = entry if isinstance(entry, dict) else {"name": str(entry)}
        add(
            "unsupported",
            source=f"{raw.get('name', '')} {raw.get('url', '')}".strip(),
            detected="allowlist subscription",
            destination="Not imported",
            warning=str(raw.get("note", "Alderpoint DNS has no allowlist-subscription object")),
            outcome="informational",
            selectable=False,
        )
    for finding in list(translation.get("unsupported_rules", [])) + list(translation.get("untranslatable", [])):
        add(
            "unsupported",
            source=str(finding),
            detected="unsupported source item",
            destination="Not imported",
            outcome="informational",
            selectable=False,
        )

    return {"domain": domain, "categories": categories}


def _plan_items(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for key in MIGRATION_CATEGORIES for item in plan["categories"][key]]


def summarize_migration(translation: dict[str, Any], default_domain: str | None = None) -> dict[str, Any]:
    """The plan plus database-aware annotations (existing objects, conflicts)
    and headline counts. Annotations only fill display fields — an item's
    category and key never depend on database state. Reads only; preview
    never creates or modifies destination objects."""
    plan = build_migration_plan(translation, default_domain)
    categories = plan["categories"]
    conflicts: list[dict[str, str]] = []
    finding_warnings: list[dict[str, str]] = []
    existing: list[dict[str, str]] = []
    with connect() as conn:
        have_sources = _table_exists(conn, "sources")
        have_rules = _table_exists(conn, "custom_filter_rules")
        have_records = _table_exists(conn, "local_dns_records")
        have_upstreams = _table_exists(conn, "upstream_resolvers")
        have_aliases = _table_exists(conn, "client_aliases")
        existing_source_names = (
            {row["name"] for row in conn.execute("SELECT name FROM sources")} if have_sources else set()
        )
        existing_source_urls = (
            {row["url"]: row["name"] for row in conn.execute("SELECT name, url FROM sources")} if have_sources else {}
        )
        existing_resolvers = (
            {
                (row["protocol"], row["address"], int(row["port"]), row["doh_path"] or "")
                for row in conn.execute("SELECT protocol, address, port, doh_path FROM upstream_resolvers")
            }
            if have_upstreams
            else set()
        )
        existing_aliases = (
            {row["cidr"] for row in conn.execute("SELECT cidr FROM client_aliases")} if have_aliases else set()
        )
        for item in _plan_items(plan):
            kind = item["apply"][0] if item["apply"] else ""
            if kind == "source" and item["source"] in existing_source_names:
                item["conflict"] = "a source with this name already exists; its URL, category, and enabled state will be updated"
                existing.append({"key": item["key"], "label": f"blocklist source {item['source']}"})
            elif kind == "source" and item.get("normalized") in existing_source_urls:
                existing_name = existing_source_urls[item["normalized"]]
                item["conflict"] = f"a source named {existing_name!r} already subscribes to this exact URL; skipped to avoid a duplicate subscription"
                existing.append({"key": item["key"], "label": f"blocklist source {item['source']} (duplicate of {existing_name})"})
            elif kind == "rule" and have_rules and item["_dupkeys"]:
                for normalized, action in item["_dupkeys"]:
                    if custom_rules.find_duplicate(conn, normalized, action):
                        item["conflict"] = (item["conflict"] + "; " if item["conflict"] else "") + "an identical rule already exists and will be skipped"
                        existing.append({"key": item["key"], "label": f"custom rule {normalized}"})
                        break
            elif kind == "local_dns" and have_records and item.get("_record"):
                fqdn, rtype, value = item["_record"]
                exact = conn.execute(
                    "SELECT 1 FROM local_dns_records WHERE fqdn=? AND record_type=? AND value=?",
                    (fqdn, rtype, value),
                ).fetchone()
                if exact:
                    item["conflict"] = "an identical Local DNS record already exists and will be skipped"
                    if item["outcome"] == "new":
                        item["outcome"] = "existing"
                    existing.append({"key": item["key"], "label": f"Local DNS {fqdn} {rtype} {value}"})
                else:
                    findings = local_dns.record_findings(conn, fqdn, rtype, value)
                    conflict_messages = [message for severity, message in findings if severity == "conflict"]
                    warning_messages = [message for severity, message in findings if severity == "warning"]
                    if conflict_messages:
                        item["conflict"] = (item["conflict"] + "; " if item["conflict"] else "") + "; ".join(conflict_messages)
                        if item["outcome"] == "new":
                            item["outcome"] = "conflicting"
                        conflicts.append({"key": item["key"], "label": f"{fqdn} {rtype}: {'; '.join(conflict_messages)}"})
                    if warning_messages:
                        item["warning"] = (item["warning"] + "; " if item["warning"] else "") + "; ".join(warning_messages)
                        if item["outcome"] == "new":
                            item["outcome"] = "warning"
                        finding_warnings.append({"key": item["key"], "label": f"{fqdn} {rtype}: {'; '.join(warning_messages)}"})
            elif kind == "upstream" and item.get("_upstream_key"):
                if tuple(item["_upstream_key"]) in existing_resolvers:
                    item["conflict"] = "an identical upstream resolver already exists and will be skipped"
                    existing.append({"key": item["key"], "label": f"upstream resolver {item['normalized']}"})
            elif kind == "alias" and item.get("_alias_cidr"):
                cidr = item["_alias_cidr"]
                if cidr in existing_aliases:
                    item["conflict"] = "an alias for this network already exists; its display name will be updated"
                    existing.append({"key": item["key"], "label": f"client alias {item['normalized']}"})
            if item["conflict"] and "allow and block" in item["conflict"]:
                conflicts.append({"key": item["key"], "label": f"{item['source']}: {item['conflict']}"})
    counts = {
        "total_items": 0,
        "selectable": 0,
        "selected_default": 0,
        "active": 0,
        "inactive": 0,
        "informational": 0,
        "duplicates": len(categories["duplicates"]),
        "invalid": len(categories["invalid"]),
        "unsupported": len(categories["unsupported"]),
        "conflicts": len(conflicts),
        "warnings": len(finding_warnings),
        "existing": len(existing),
    }
    for item in _plan_items(plan):
        counts["total_items"] += 1
        if item["selectable"]:
            counts["selectable"] += 1
        if item["selected"]:
            counts["selected_default"] += 1
        if item["outcome"] == "informational":
            counts["informational"] += 1
        elif item["outcome"] in ("inactive", "disabled at source"):
            counts["inactive"] += 1
        else:
            counts["active"] += 1
    ordered = [
        {"name": name, "label": MIGRATION_CATEGORIES[name], "items": categories[name]}
        for name in MIGRATION_CATEGORIES
        if categories[name]
    ]
    return {
        "domain": plan["domain"],
        "categories": ordered,
        "conflicts": conflicts,
        "warnings": finding_warnings,
        "existing": existing,
        "counts": counts,
    }


def _public_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """A storable copy of the summary without internal bookkeeping fields."""
    public = {key: value for key, value in summary.items() if key != "categories"}
    public["categories"] = [
        {
            "name": section["name"],
            "label": section["label"],
            "items": [
                {k: v for k, v in item.items() if not k.startswith("_") and k != "apply"}
                for item in section["items"]
            ],
        }
        for section in summary["categories"]
    ]
    return public


# ---------------------------------------------------------------------------
# Column mapping
# ---------------------------------------------------------------------------

_ALIASES: dict[str, list[str]] = {
    "hostname": ["hostname", "host", "name"],
    "fqdn": ["fqdn", "full name", "fullname", "domain name"],
    "domain": ["domain", "zone", "internal domain"],
    "ipv4": ["ipv4", "ip", "ip address", "ip4", "address"],
    "ipv6": ["ipv6", "ip6"],
    "record_type": ["record_type", "type", "record type", "rtype"],
    "target": ["target", "value", "data", "cname", "ptr target"],
    "create_ptr": ["create_ptr", "ptr", "auto_ptr", "reverse"],
    "ttl": ["ttl"],
    "comment": ["comment", "note", "notes", "description"],
    "enabled": ["enabled", "active"],
    "client_alias": ["client_alias", "alias", "display name", "client name"],
    "client_id_or_cidr": ["client_id_or_cidr", "client id", "cidr", "client"],
}


def auto_map_columns(headers: list[str]) -> dict[str, str]:
    normalized = {h.strip().lower(): h for h in headers}
    mapping: dict[str, str] = {}
    for canonical, aliases in _ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                mapping[canonical] = normalized[alias]
                break
    return mapping


def apply_column_map(raw_rows: list[dict[str, str]], column_map: dict[str, str]) -> list[dict[str, str]]:
    out = []
    for raw in raw_rows:
        # Rows already in canonical shape (hosts/zone/alderpointdns-csv parsers)
        # have no mapping to apply; pass through unchanged.
        if not column_map:
            out.append({field: raw.get(field, "") for field in CANONICAL_FIELDS})
            continue
        item = {}
        for canonical in CANONICAL_FIELDS:
            source_col = column_map.get(canonical, "")
            item[canonical] = str(raw.get(source_col, "")).strip() if source_col else ""
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def create_job(source_type: str, source_name: str, headers: list[str], raw_rows: list[dict[str, str]], source_path: str = "") -> int:
    with connect() as conn:
        init_db(conn)
        cursor = conn.execute(
            """
            INSERT INTO import_jobs(created_at, source_type, source_name, headers_json, raw_rows_json, source_path, status, total_rows)
            VALUES (?, ?, ?, ?, ?, ?, 'uploaded', ?)
            """,
            (now(), source_type, source_name, json.dumps(headers), json.dumps(raw_rows), source_path, len(raw_rows)),
        )
        conn.commit()
        return cursor.lastrowid


def get_job(job_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT * FROM import_jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None
    finally:
        if close:
            db.close()


def list_jobs(limit: int = 20) -> list[dict[str, Any]]:
    with connect() as conn:
        init_db(conn)
        return [dict(row) for row in conn.execute("SELECT * FROM import_jobs ORDER BY id DESC LIMIT ?", (limit,))]


def is_migration_source(source_type: str) -> bool:
    return source_type in MIGRATION_SOURCE_TYPES


def create_migration_job(source_type: str, source_name: str, translation: dict[str, Any], source_path: str = "") -> int:
    if not is_migration_source(source_type):
        raise ImportError_(f"unknown migration source type {source_type!r}")
    return create_job(source_type, source_name, [], [translation], source_path)


def migration_translation_from_job(job_id: int) -> dict[str, Any]:
    job = get_job(job_id)
    if not job:
        raise ImportError_(f"import job {job_id} not found")
    if not is_migration_source(job["source_type"]):
        raise ImportError_(f"import job {job_id} is not a migration job")
    rows = json.loads(job["raw_rows_json"])
    if not rows or not isinstance(rows[0], dict):
        raise ImportError_(f"migration job {job_id} has no translation payload")
    return rows[0]


def migration_preview_job(job_id: int, default_domain: str | None = None) -> dict[str, Any]:
    """Pure preview: classifies the stored translation and records counts on
    the job row. Never creates, updates, or deletes any destination object."""
    job = get_job(job_id)
    if not job:
        raise ImportError_(f"import job {job_id} not found")
    translation = migration_translation_from_job(job_id)
    summary = summarize_migration(translation, default_domain)
    counts = summary["counts"]
    if job["status"] not in {"uploaded", "previewed"}:
        # Re-rendering a preview of a finished job must not clobber its
        # apply report or status.
        return {"job_id": job_id, "translation": translation, "summary": summary}
    with connect() as conn:
        init_db(conn)
        status = "previewed"
        conn.execute(
            """
            UPDATE import_jobs
            SET status=?, total_rows=?, valid_rows=?, invalid_rows=?, conflict_rows=?, duplicate_rows=?, report_json=?
            WHERE id=?
            """,
            (
                status,
                counts["total_items"],
                counts["selectable"] - counts["invalid"] - counts["unsupported"],
                counts["invalid"],
                counts["conflicts"],
                counts["duplicates"],
                json.dumps(redact_sensitive({"preview": _public_summary(summary)}), default=str),
                job_id,
            ),
        )
        conn.commit()
    return {"job_id": job_id, "translation": translation, "summary": summary}


def cancel_job(job_id: int) -> None:
    job = get_job(job_id)
    if not job:
        raise ImportError_(f"import job {job_id} not found")
    if job["status"] in {"applied", "rolled_back"}:
        raise ImportError_("completed imports cannot be canceled")
    with connect() as conn:
        init_db(conn)
        conn.execute("UPDATE import_jobs SET status='canceled', finished_at=?, message='canceled by operator' WHERE id=?", (now(), job_id))
        conn.commit()


def _record_from_row(row: dict[str, str], default_domain: str) -> tuple[str, str, str, str]:
    """Returns (fqdn, record_type, value, ttl_raw) derived from a normalized row."""
    domain = row.get("domain") or default_domain
    fqdn = row.get("fqdn", "").strip()
    if not fqdn:
        hostname = row.get("hostname", "").strip()
        if not hostname:
            raise ImportError_("row has neither fqdn nor hostname")
        fqdn = local_dns.normalize_fqdn(hostname, domain)
    rtype = row.get("record_type", "").strip().upper()
    value = row.get("target", "").strip()
    if not rtype:
        if row.get("ipv4", "").strip():
            rtype, value = "A", row["ipv4"].strip()
        elif row.get("ipv6", "").strip():
            rtype, value = "AAAA", row["ipv6"].strip()
        elif value:
            try:
                ip = ipaddress.ip_address(value)
                rtype = "A" if isinstance(ip, ipaddress.IPv4Address) else "AAAA"
            except ValueError:
                rtype = "CNAME"
    elif rtype == "A" and not value:
        value = row.get("ipv4", "").strip()
    elif rtype == "AAAA" and not value:
        value = row.get("ipv6", "").strip()
    ttl = row.get("ttl", "").strip() or "300"
    return fqdn, rtype, value, ttl


def preview_job(job_id: int, column_map: dict[str, str], default_domain: str | None = None) -> dict[str, Any]:
    job = get_job(job_id)
    if not job:
        raise ImportError_(f"import job {job_id} not found")
    raw_rows = json.loads(job["raw_rows_json"])
    normalized = apply_column_map(raw_rows, column_map)
    with connect() as conn:
        local_dns.init_db(conn)
        cfg = local_dns.settings(conn)
        domain = default_domain or cfg.get("internal_domain", local_dns.DEFAULT_DOMAIN)
        valid: list[dict[str, Any]] = []
        invalid: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []
        warnings_list: list[dict[str, Any]] = []
        duplicates: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for index, row in enumerate(normalized):
            item: dict[str, Any] = {"index": index, "row": row}
            try:
                fqdn, rtype, value, ttl_raw = _record_from_row(row, domain)
                rtype, fqdn, value, ttl = local_dns.validate_record(rtype, fqdn, value, ttl_raw)
                key = (fqdn, rtype, value)
                item.update({"fqdn": fqdn, "record_type": rtype, "value": value, "ttl": ttl})
                if key in seen:
                    item["reason"] = "duplicate within this import"
                    duplicates.append(item)
                    continue
                seen.add(key)
                findings = local_dns.record_findings(conn, fqdn, rtype, value)
                conflict_messages = [message for severity, message in findings if severity == "conflict"]
                warning_messages = [message for severity, message in findings if severity == "warning"]
                if conflict_messages:
                    item["warnings"] = conflict_messages
                    conflicts.append(item)
                elif warning_messages:
                    # Unusual but valid data (e.g. a public IP address): shown
                    # separately for visibility, but imported like any other
                    # valid row -- never blocked and never counted as a
                    # conflict requiring an override/merge/replace policy.
                    item["warnings"] = warning_messages
                    warnings_list.append(item)
                    valid.append(item)
                else:
                    valid.append(item)
            except Exception as exc:
                item["error"] = str(exc)
                invalid.append(item)
        conn.execute(
            """
            UPDATE import_jobs SET status='previewed', column_map_json=?, valid_rows=?, invalid_rows=?,
                duplicate_rows=?, conflict_rows=?, warning_rows=? WHERE id=?
            """,
            (json.dumps(column_map), len(valid), len(invalid), len(duplicates), len(conflicts), len(warnings_list), job_id),
        )
        conn.commit()
    return {
        "job_id": job_id,
        "valid": valid,
        "invalid": invalid,
        "duplicates": duplicates,
        "conflicts": conflicts,
        "warnings": warnings_list,
        "domain": domain,
    }


PRE_IMPORT_BACKUP_COMMAND = ["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "backup-create"]


def create_pre_import_backup(strict: bool = False) -> str | None:
    """Create a verified pre-import safety backup through the same
    privileged, already-tested path scheduled and manual backups use
    (app/backup.py's create_backup(), run as root via the sudoers-allowlisted
    `alderpointdns_compiler.py backup-create`). This module runs inside the
    unprivileged web process, which cannot itself create a correctly-owned
    backup archive -- shelling out to scripts/backup.sh directly here would
    fail (it needs root to preserve file ownership in the archive). In strict
    mode (migration apply) a failing backup aborts the apply instead of
    continuing without a verified backup."""
    try:
        proc = subprocess.run(PRE_IMPORT_BACKUP_COMMAND, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True, timeout=120)
    except Exception as exc:
        if strict:
            raise ImportError_(f"pre-import backup failed: {exc}") from exc
        return None
    for line in reversed(proc.stdout.strip().splitlines()):
        if line.startswith("backup_path="):
            return line[len("backup_path="):]
    return None


def apply_job(job_id: int, default_policy: str = "skip", row_policies: dict[int, str] | None = None) -> dict[str, Any]:
    if default_policy not in {"skip", "merge", "replace"}:
        raise ImportError_(f"unknown policy {default_policy!r}")
    row_policies = row_policies or {}
    job = get_job(job_id)
    if not job:
        raise ImportError_(f"import job {job_id} not found")
    column_map = json.loads(job["column_map_json"])
    preview = preview_job(job_id, column_map)
    create_pre_import_backup()
    applied = 0
    skipped = 0
    failed = 0
    inserted_ids: list[int] = []
    report_rows: list[dict[str, Any]] = []
    rows_to_apply = [(item, False) for item in preview["valid"]] + [(item, True) for item in preview["conflicts"]]
    try:
        for item, is_conflict in rows_to_apply:
            policy = row_policies.get(item["index"], default_policy)
            row = item["row"]
            try:
                if is_conflict and policy == "skip":
                    skipped += 1
                    report_rows.append({**item, "outcome": "skipped"})
                    continue
                override = is_conflict and policy in ("merge", "replace")
                if is_conflict and policy == "replace":
                    with connect() as conn:
                        local_dns.init_db(conn)
                        conn.execute(
                            "DELETE FROM local_dns_records WHERE fqdn=? AND record_type=?",
                            (item["fqdn"], item["record_type"]),
                        )
                        conn.commit()
                local_dns.add_record(
                    item["record_type"], item["fqdn"], item["value"], item["ttl"],
                    row.get("comment", ""), str(row.get("enabled", "1")) != "0", override=override,
                )
                with connect() as conn:
                    local_dns.init_db(conn)
                    new_id = conn.execute(
                        "SELECT id FROM local_dns_records WHERE fqdn=? AND record_type=? AND value=?",
                        (item["fqdn"], item["record_type"], item["value"]),
                    ).fetchone()
                    if new_id:
                        inserted_ids.append(new_id["id"])
                client_alias = row.get("client_alias", "").strip()
                client_cidr = row.get("client_id_or_cidr", "").strip()
                if client_alias and client_cidr:
                    local_dns.upsert_alias(client_cidr, client_alias, "imported")
                applied += 1
                report_rows.append({**item, "outcome": "applied"})
            except Exception as exc:
                failed += 1
                report_rows.append({**item, "outcome": "failed", "error": str(exc)})
        status = "applied"
        message = f"applied={applied} skipped={skipped} failed={failed}"
    except Exception as exc:
        status = "failed"
        message = str(exc)
        raise
    finally:
        with connect() as conn:
            init_db(conn)
            conn.execute(
                """
                UPDATE import_jobs SET finished_at=?, status=?, applied_rows=?, skipped_rows=?, failed_rows=?,
                    inserted_record_ids_json=?, report_json=?, message=? WHERE id=?
                """,
                (now(), status, applied, skipped, failed, json.dumps(inserted_ids), json.dumps(report_rows, default=str), message, job_id),
            )
            conn.commit()
    return {"applied": applied, "skipped": skipped, "failed": failed, "inserted_ids": inserted_ids, "report": report_rows}


def rollback_job(job_id: int) -> int:
    job = get_job(job_id)
    if not job:
        raise ImportError_(f"import job {job_id} not found")
    if is_migration_source(job["source_type"]):
        return _rollback_migration_job(job)
    inserted_ids = json.loads(job["inserted_record_ids_json"])
    if inserted_ids:
        with connect() as conn:
            local_dns.init_db(conn)
            placeholders = ",".join("?" for _ in inserted_ids)
            conn.execute(f"DELETE FROM local_dns_records WHERE id IN ({placeholders})", inserted_ids)
            conn.commit()
    with connect() as conn:
        init_db(conn)
        conn.execute("UPDATE import_jobs SET status='rolled_back', finished_at=? WHERE id=?", (now(), job_id))
        conn.commit()
    return len(inserted_ids)


def _rollback_migration_job(job: dict[str, Any]) -> int:
    """Remove exactly what a migration apply created (custom filter rules by
    import_job_id, Local DNS records, newly added sources/aliases/upstreams)
    and restore the previous values of any object the apply updated."""
    job_id = job["id"]
    if job["status"] not in {"applied", "deploy_failed"}:
        raise ImportError_("only applied migration jobs can be rolled back")
    info = json.loads(job.get("rollback_json") or "{}")
    removed = 0
    with connect() as conn:
        init_db(conn)
        _init_filter_tables(conn)
        local_dns.init_db(conn)
        upstream_dns.init_db(conn)
        custom_rules.init_db(conn)
        clients.init_db(conn)
        with conn:
            removed += conn.execute("DELETE FROM custom_filter_rules WHERE import_job_id=?", (job_id,)).rowcount
            record_ids = [int(value) for value in info.get("local_dns_ids", [])]
            if record_ids:
                placeholders = ",".join("?" for _ in record_ids)
                removed += conn.execute(f"DELETE FROM local_dns_records WHERE id IN ({placeholders})", record_ids).rowcount
            for name in info.get("sources_added", []):
                removed += conn.execute("DELETE FROM sources WHERE name=?", (str(name),)).rowcount
            for row in info.get("sources_updated", []):
                conn.execute(
                    "UPDATE sources SET url=?, enabled=?, category=? WHERE name=?",
                    (row.get("url", ""), int(row.get("enabled", 1)), row.get("category", "ads_trackers"), row.get("name", "")),
                )
            upstream_ids = [int(value) for value in info.get("upstream_ids", [])]
            if upstream_ids:
                placeholders = ",".join("?" for _ in upstream_ids)
                removed += conn.execute(f"DELETE FROM upstream_resolvers WHERE id IN ({placeholders})", upstream_ids).rowcount
            for cidr in info.get("aliases_added", []):
                removed += conn.execute("DELETE FROM client_aliases WHERE cidr=?", (str(cidr),)).rowcount
            for row in info.get("aliases_updated", []):
                conn.execute(
                    "UPDATE client_aliases SET display_name=?, description=?, updated_at=? WHERE cidr=?",
                    (row.get("display_name", ""), row.get("description", ""), now(), row.get("cidr", "")),
                )
            client_ids = [int(value) for value in info.get("clients_added", [])]
            access_rules_touched = bool(client_ids) or bool(info.get("access_rules_added"))
            if client_ids:
                placeholders = ",".join("?" for _ in client_ids)
                removed += conn.execute(f"DELETE FROM access_rules WHERE client_id IN ({placeholders})", client_ids).rowcount
                removed += conn.execute(f"DELETE FROM client_identifiers WHERE client_id IN ({placeholders})", client_ids).rowcount
                removed += conn.execute(f"DELETE FROM clients WHERE id IN ({placeholders})", client_ids).rowcount
            access_rule_ids = [int(value) for value in info.get("access_rules_added", [])]
            if access_rule_ids:
                placeholders = ",".join("?" for _ in access_rule_ids)
                removed += conn.execute(f"DELETE FROM access_rules WHERE id IN ({placeholders})", access_rule_ids).rowcount
            previous_access_policy = info.get("access_default_policy_before")
            if previous_access_policy in {"allow", "deny"}:
                conn.execute("UPDATE access_settings SET default_policy=?, updated_at=? WHERE id=1", (previous_access_policy, now()))
                access_rules_touched = True
            conn.execute(
                "UPDATE import_jobs SET status='rolled_back', finished_at=?, message=? WHERE id=?",
                (now(), f"rolled back: removed {removed} imported object(s)", job_id),
            )
    if access_rules_touched:
        # Redeploy after the DELETEs above have committed, so dnsdist stops
        # enforcing rules for clients/rules this rollback just removed
        # instead of continuing to apply the last-deployed (now-stale)
        # policy until some unrelated future change happens to redeploy it.
        clients.deploy_access_layer()
    return removed


# ---------------------------------------------------------------------------
# AdGuard Home migration
# ---------------------------------------------------------------------------

def parse_adguard_yaml(text: str, internal_domain: str | None = None) -> dict[str, Any]:
    check_text_limits(text)
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ImportError_("not an AdGuard Home configuration file")
    return _translate_adguard_config(data, internal_domain)


class _HttpOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows redirects only to http/https URLs; any other scheme aborts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        scheme = urllib.parse.urlsplit(newurl).scheme.lower()
        if scheme not in {"http", "https"}:
            raise ImportError_(f"refusing redirect to non-HTTP(S) URL scheme {scheme!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def sanitize_adguard_base_url(base_url: str) -> str:
    """Validate and normalize an AdGuard Home base URL: http/https only, and
    any userinfo or query string is dropped so credentials can never be
    stored in job rows or reports."""
    parts = urllib.parse.urlsplit(str(base_url or "").strip())
    if parts.scheme.lower() not in {"http", "https"}:
        raise ImportError_("AdGuard Home base URL must start with http:// or https://")
    if not parts.hostname:
        raise ImportError_("AdGuard Home base URL needs a hostname")
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    if parts.port:
        host = f"{host}:{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme.lower(), host, parts.path.rstrip("/"), "", ""))


def fetch_adguard_api(base_url: str, username: str, password: str, internal_domain: str | None = None) -> dict[str, Any]:
    """Read-only fetch of an AdGuard Home instance's configuration. The
    credentials are used only for these requests and are never stored; only
    the sanitized base URL (no userinfo, no query) is ever kept. Requests are
    limited to http/https (including redirects), time-limited, and
    size-capped."""
    base_url = sanitize_adguard_base_url(base_url)
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}"}
    opener = urllib.request.build_opener(_HttpOnlyRedirectHandler())
    endpoints = {
        "filtering": "/control/filtering/status",
        "rewrites": "/control/rewrite/list",
        "clients": "/control/clients",
        "dns_info": "/control/dns_info",
    }
    raw: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for key, path in endpoints.items():
        try:
            request = urllib.request.Request(base_url + path, headers=headers)
            with opener.open(request, timeout=8) as response:
                body = response.read(MAX_API_RESPONSE_BYTES + 1)
                if len(body) > MAX_API_RESPONSE_BYTES:
                    raise ImportError_(f"response exceeds {MAX_API_RESPONSE_BYTES // (1024 * 1024)} MiB limit")
                raw[key] = json.loads(body.decode())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, ImportError_) as exc:
            errors[key] = redact_sensitive(str(exc))
    config_shaped: dict[str, Any] = {
        "filters": (raw.get("filtering") or {}).get("filters", []),
        "whitelist_filters": (raw.get("filtering") or {}).get("whitelist_filters", []),
        "user_rules": (raw.get("filtering") or {}).get("user_rules", []),
        "filtering": {"rewrites": raw.get("rewrites", [])},
        "clients": {"persistent": (raw.get("clients") or {}).get("clients", [])},
        "dns": raw.get("dns_info", {}),
    }
    result = _translate_adguard_config(config_shaped, internal_domain)
    if errors:
        result["fetch_errors"] = errors
    return result


# Keyword mapping from AdGuard filter-list names/URLs onto Alderpoint DNS's
# managed blocklist categories. Only clean matches are mapped; everything
# else lands in the default 'ads_trackers' category.
_SOURCE_CATEGORY_KEYWORDS = (
    ("malware", ("malware", "phishing", "scam", "threat", "badware", "crypto", "security", "safe browsing", "safebrowsing")),
    ("adult_content", ("adult", "porn", "nsfw", "gambling", "explicit")),
    ("iot_telemetry", ("telemetry", "iot", "smart-tv", "smarttv", "vendor tracking")),
)


def _map_source_category(name: str, url: str) -> str:
    haystack = f"{name} {url}".lower()
    for category, keywords in _SOURCE_CATEGORY_KEYWORDS:
        if any(keyword in haystack for keyword in keywords):
            return category
    return "ads_trackers"


def _classify_adguard_identifier(raw: str) -> tuple[str, str]:
    """Classifies one AdGuard client/allowed/disallowed identifier string.
    Returns (kind, value) where kind is one of: 'ipv4','ipv4_cidr','ipv6',
    'ipv6_cidr' (import as an Alderpoint identifier as-is), 'clientid'
    (already meets Alderpoint's 192-bit minimum -- import as a strong
    Alderpoint ClientID), 'clientid_weak' (hex, but under the 192-bit/48-hex
    minimum -- AdGuard accepts much shorter ClientIDs than Alderpoint does;
    preserved as an inactive finding, never activated -- see
    docs/clients-and-access.md), or 'unrecognized' (kept as a finding, not
    imported as anything active)."""
    text = str(raw).strip()
    if not text:
        return "unrecognized", text
    if all(c in "0123456789abcdefABCDEF" for c in text) and "." not in text and ":" not in text and "/" not in text:
        if len(text) >= clients.CLIENTID_MIN_HEX_LEN:
            try:
                return "clientid", clients.validate_clientid(text)
            except clients.ClientIDError:
                return "unrecognized", text
        return "clientid_weak", text.lower()
    try:
        kind, value = clients.normalize_identifier(text)
        return kind, value
    except clients.ClientsError:
        return "unrecognized", text


def _translate_adguard_config(data: dict[str, Any], internal_domain: str | None = None) -> dict[str, Any]:
    """Translate an AdGuard Home configuration (YAML upload or API-shaped)
    into the migration translation payload.

    - filters -> blocklist sources (name, URL, enabled state, and a managed
      category when the list name/URL cleanly matches one).
    - user_rules -> typed custom-rule entries; every line is preserved and
      classified later by custom_rules.parse_rule with AdGuard plain-domain
      semantics (domain + subdomains).
    - filtering.rewrites -> AdGuard's DNS Rewrites are AdGuard's own
      Local-DNS-equivalent feature, so every non-wildcard rewrite (A/AAAA or
      CNAME-style) maps to Alderpoint DNS's Local DNS model regardless of
      whether the name falls under the configured internal domain; only
      wildcard (`*.name`) rewrites, which Local DNS cannot represent, fall
      back to a subdomain rewrite custom rule (IP answers) or an explicit
      unsupported finding (CNAME-style answers).
    - whitelist_filters, domain-routed upstreams, per-client settings ->
      explicit findings, never silently dropped."""
    filtering = data.get("filtering") if isinstance(data.get("filtering"), dict) else {}
    filters = data.get("filters") or filtering.get("filters") or []
    whitelist_filters = data.get("whitelist_filters") or filtering.get("whitelist_filters") or []
    user_rules = data.get("user_rules") or filtering.get("user_rules") or []
    rewrites = filtering.get("rewrites") or data.get("rewrites") or []
    clients_block = data.get("clients") if isinstance(data.get("clients"), dict) else {}
    persistent_clients = clients_block.get("persistent") or []
    dns_block = data.get("dns") if isinstance(data.get("dns"), dict) else {}
    bootstrap_ips = []
    for raw in dns_block.get("bootstrap_dns", []) or []:
        try:
            bootstrap_ips.append(str(ipaddress.ip_address(str(raw).strip())))
        except ValueError:
            continue

    blocklist_sources = []
    for entry in filters:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("url", "imported-filter"))
        url = str(entry.get("url", ""))
        blocklist_sources.append({
            "name": name,
            "url": url,
            "enabled": bool(entry.get("enabled", True)),
            "category": _map_source_category(name, url),
        })

    allowlist_unsupported = []
    for entry in whitelist_filters:
        if not isinstance(entry, dict):
            continue
        allowlist_unsupported.append({
            "name": entry.get("name") or entry.get("url", "imported-allowlist"),
            "url": entry.get("url", ""),
            "note": "Alderpoint DNS has no allowlist-subscription object; add matching custom allow rules manually if needed.",
        })

    rule_entries: list[dict[str, Any]] = []
    unsupported_rules: list[str] = []
    for number, raw_rule in enumerate(user_rules, 1):
        line = str(raw_rule).strip()
        if not line:
            continue
        if len(line) > MAX_LINE_CHARS:
            unsupported_rules.append(f"user rule {number} exceeds {MAX_LINE_CHARS} characters and was not imported")
            continue
        rule_entries.append({
            "text": line,
            "rule": line,
            "plain_domain_subdomains": True,
            "origin": "user_rules",
            "comment": "",
        })

    # The global rewrites toggle: `filtering.rewrites_enabled`. Absent in API
    # responses and in schema versions predating the toggle -- both default
    # to AdGuard's own default of enabled, matching AdGuard's behavior when
    # the key is not present.
    rewrites_enabled_globally = bool(filtering.get("rewrites_enabled", True))
    rewrites_as_local_dns = []
    for entry in rewrites:
        if not isinstance(entry, dict):
            continue
        domain = str(entry.get("domain", "")).strip().strip(".")
        answer = str(entry.get("answer", "")).strip()
        if not domain or not answer:
            unsupported_rules.append(f"DNS rewrite is missing a domain or answer: {entry}")
            continue
        # AdGuard's own pass-through/exclusion sentinel: an `answer` of the
        # literal string "A" or "AAAA" tells AdGuard to stop matching a
        # broader rewrite for that query type rather than naming an address
        # or alias. Alderpoint DNS has no equivalent selective-exclusion
        # mechanism, so this is reported rather than misread as an address
        # or a (nonsensical) single-label CNAME target.
        if answer.upper() in {"A", "AAAA"}:
            unsupported_rules.append(
                f"DNS rewrite {domain} -> {answer}: AdGuard's '{answer.upper()}' pass-through/exclusion "
                "value has no Alderpoint DNS equivalent and was not imported"
            )
            continue
        per_item_enabled = bool(entry.get("enabled", True))
        effective_enabled = rewrites_enabled_globally and per_item_enabled
        if not rewrites_enabled_globally:
            disabled_reason = "AdGuard Home's global DNS rewrites feature (filtering.rewrites_enabled) was turned off"
        elif not per_item_enabled:
            disabled_reason = "this rewrite was disabled in AdGuard Home"
        else:
            disabled_reason = ""
        wildcard = domain.startswith("*.")
        base = domain[2:] if wildcard else domain
        try:
            ip = ipaddress.ip_address(answer)
        except ValueError:
            ip = None
        if ip is not None:
            if wildcard:
                if not effective_enabled:
                    # Local DNS has no wildcard record type, so a disabled
                    # wildcard rewrite would otherwise map to a custom
                    # $dnsrewrite rule; Alderpoint DNS's custom rule apply
                    # path has no "disabled dnsrewrite" state, so this is
                    # reported explicitly instead of silently activating it.
                    unsupported_rules.append(
                        f"DNS rewrite {domain} -> {answer}: disabled in AdGuard Home ({disabled_reason}); "
                        "disabled wildcard rewrites are reported rather than imported as an active custom rule"
                    )
                else:
                    rule_entries.append({
                        "text": f"{domain} -> {answer}",
                        "rule": f"||{base}^$dnsrewrite={ip}",
                        "plain_domain_subdomains": True,
                        "origin": "dns_rewrites",
                        "comment": f"AdGuard DNS rewrite {domain} -> {answer}",
                    })
            else:
                # Every non-wildcard AdGuard DNS rewrite is AdGuard's own
                # Local-DNS-equivalent feature and always maps to Alderpoint
                # DNS's Local DNS model, regardless of whether the name falls
                # under the configured internal domain -- Local DNS already
                # supports arbitrary external names via an auto-created
                # managed forward zone, the same as CNAME-style answers.
                rewrites_as_local_dns.append({
                    "fqdn": base,
                    "record_type": "A" if isinstance(ip, ipaddress.IPv4Address) else "AAAA",
                    "value": str(ip),
                    "ttl": 300,
                    "origin": "dns_rewrites",
                    "enabled": effective_enabled,
                    "disabled_reason": disabled_reason,
                })
        elif wildcard:
            unsupported_rules.append(f"DNS rewrite {domain} -> {answer}: wildcard CNAME-style rewrites are not supported")
        else:
            try:
                fqdn = local_dns.normalize_domain(base)
                target = local_dns.normalize_domain(answer)
            except Exception:
                unsupported_rules.append(f"DNS rewrite {domain} -> {answer}: the answer is neither an IP address nor a valid domain")
                continue
            rewrites_as_local_dns.append({
                "fqdn": fqdn,
                "record_type": "CNAME",
                "value": target,
                "ttl": 300,
                "origin": "dns_rewrites",
                "enabled": effective_enabled,
                "disabled_reason": disabled_reason,
            })

    clients_as_aliases = []
    clients_full = []
    client_scoped = []
    for client in persistent_clients:
        if not isinstance(client, dict):
            continue
        name = client.get("name", "")
        ids = client.get("ids") or []
        cidr_or_ip = next((i for i in ids if _looks_like_ip_or_cidr(i)), "")
        if name and cidr_or_ip:
            clients_as_aliases.append({"display_name": name, "cidr_or_ip": cidr_or_ip, "all_ids": ids})
        if name:
            identifiers = []
            weak_clientids = []
            unrecognized = []
            for raw_id in ids:
                kind, value = _classify_adguard_identifier(str(raw_id))
                if kind == "clientid_weak":
                    weak_clientids.append(value)
                elif kind == "unrecognized":
                    unrecognized.append(str(raw_id))
                else:
                    identifiers.append({"kind": kind, "value": value})
            if identifiers or weak_clientids:
                clients_full.append({
                    "name": name,
                    "description": "imported from AdGuard Home",
                    "identifiers": identifiers,
                    "weak_clientids": weak_clientids,
                    "unrecognized": unrecognized,
                })
        for feature in ("filtering_enabled", "safe_search", "blocked_services", "upstreams", "ignore_querylog", "ignore_statistics"):
            if client.get(feature) not in (None, False, {}):
                client_scoped.append(f"{name or cidr_or_ip}: {feature} has no Alderpoint DNS per-client equivalent yet (schema exists, not enforced at runtime)")

    # AdGuard's global allowed_clients/disallowed_clients (dns.allowed_clients
    # / dns.disallowed_clients): the source semantics are preserved exactly
    # -- an AdGuard entry becomes one Alderpoint access rule of the same
    # kind, never broadened into a wider range or merged with anything else.
    access_allowed = []
    access_denied = []
    for raw_id in dns_block.get("allowed_clients", []) or []:
        kind, value = _classify_adguard_identifier(str(raw_id))
        if kind in ("ipv4", "ipv4_cidr", "ipv6", "ipv6_cidr", "clientid"):
            access_allowed.append({"kind": kind, "value": value, "raw": str(raw_id)})
        elif kind == "clientid_weak":
            client_scoped.append(f"allowed_clients entry {raw_id!r}: ClientID is below Alderpoint's 192-bit minimum, not imported as an active allow rule")
        else:
            client_scoped.append(f"allowed_clients entry {raw_id!r}: not a recognized IPv4/IPv6/CIDR/ClientID value")
    for raw_id in dns_block.get("disallowed_clients", []) or []:
        kind, value = _classify_adguard_identifier(str(raw_id))
        if kind in ("ipv4", "ipv4_cidr", "ipv6", "ipv6_cidr", "clientid"):
            access_denied.append({"kind": kind, "value": value, "raw": str(raw_id)})
        elif kind == "clientid_weak":
            client_scoped.append(f"disallowed_clients entry {raw_id!r}: ClientID is below Alderpoint's 192-bit minimum, not imported as an active deny rule")
        else:
            client_scoped.append(f"disallowed_clients entry {raw_id!r}: not a recognized IPv4/IPv6/CIDR/ClientID value")

    untranslatable = []
    upstream_resolvers = []
    for index, raw_upstream in enumerate(dns_block.get("upstream_dns", []) or [], start=1):
        parsed = _translate_upstream_resolver(str(raw_upstream), index, bootstrap_ips)
        if parsed.get("unsupported"):
            untranslatable.append(parsed["unsupported"])
        else:
            upstream_resolvers.append(parsed)
    if filtering.get("safe_search", {}).get("enabled") if isinstance(filtering.get("safe_search"), dict) else False:
        untranslatable.append("filtering.safe_search: SafeSearch enforcement is not implemented in Alderpoint DNS")
    if filtering.get("blocked_services", {}).get("ids") if isinstance(filtering.get("blocked_services"), dict) else False:
        untranslatable.append("filtering.blocked_services: named blocked-service bundles are not implemented in Alderpoint DNS")

    return {
        "blocklist_sources": blocklist_sources,
        "allowlist_unsupported": allowlist_unsupported,
        "custom_rules": rule_entries,
        "custom_allow": [],
        "custom_block": [],
        "unsupported_rules": unsupported_rules,
        "rewrites_as_local_dns": rewrites_as_local_dns,
        "clients_as_aliases": clients_as_aliases,
        "clients_full": clients_full,
        "access_allowed": access_allowed,
        "access_denied": access_denied,
        "client_scoped": client_scoped,
        "upstream_resolvers": upstream_resolvers,
        "untranslatable": untranslatable,
    }


def _translate_upstream_resolver(value: str, index: int, bootstrap_ips: list[str]) -> dict[str, Any]:
    raw = value.strip()
    if not raw:
        return {"unsupported": "empty upstream resolver entry"}
    if raw.startswith("[/"):
        return {"unsupported": f"{raw}: domain-specific upstream routing is not implemented"}
    try:
        data = upstream_dns.validate_resolver({"name": f"Imported upstream {index}", "protocol": "doh", "address": raw, "bootstrap_ips": ", ".join(bootstrap_ips), "enabled": "1"})
        return data
    except Exception:
        pass
    lowered = raw.lower()
    if lowered.startswith(("tls://", "sdns://", "quic://", "h3://")):
        return {"unsupported": f"{raw}: upstream scheme is not directly importable yet"}
    host = raw
    port = ""
    if ":" in raw and raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
    try:
        data = upstream_dns.validate_resolver({"name": f"Imported upstream {index}", "protocol": "plain", "address": host.strip("[]"), "port": port or "53", "enabled": "1"})
        return data
    except Exception as exc:
        return {"unsupported": f"{raw}: {exc}"}


def _looks_like_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


_SOURCE_SYSTEM_BY_TYPE = {
    "adguard_yaml": "adguard",
    "adguard_api": "adguard",
    "pihole": "pihole",
    "alderpointdns_json": "import",
}


def _apply_source_item(conn: sqlite3.Connection, source: dict[str, Any], rollback_info: dict[str, Any]) -> str:
    """Insert or update one blocklist source inside the caller's transaction.
    Returns 'added', 'updated', or 'duplicate' (an existing source under a
    different name already subscribes to this exact URL -- skipped rather
    than creating a second subscription to the same feed) and records
    rollback data."""
    name = str(source.get("name", "")).strip()[:120]
    url = str(source.get("url", "")).strip()
    category = str(source.get("category", "ads_trackers")).strip() or "ads_trackers"
    enabled = 1 if source.get("enabled", True) else 0
    existing = conn.execute("SELECT name, url, enabled, category FROM sources WHERE name=?", (name,)).fetchone()
    if existing:
        rollback_info["sources_updated"].append(dict(existing))
        conn.execute("UPDATE sources SET url=?, enabled=?, category=? WHERE name=?", (url, enabled, category, name))
        return "updated"
    if conn.execute("SELECT 1 FROM sources WHERE url=?", (url,)).fetchone():
        return "duplicate"
    conn.execute("INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, ?, ?)", (name, url, enabled, category))
    rollback_info["sources_added"].append(name)
    return "added"


def _apply_local_dns_record(conn: sqlite3.Connection, record: dict[str, Any], domain: str, source_label: str, rollback_info: dict[str, Any]) -> str:
    """Insert one Local DNS record inside the caller's transaction. Returns
    'added' (clean insert), 'added_conflicting' (inserted, but a genuinely
    incompatible existing record was found -- e.g. a different address or a
    CNAME exclusivity clash -- reported, never overwritten), 'added_with_warning'
    (inserted; merely unusual but valid data, such as a public IP address,
    imported as requested), or 'duplicate' (an identical record -- same FQDN,
    type, and value -- is already present)."""
    fqdn = local_dns.normalize_fqdn(str(record.get("fqdn", "")), domain)
    rtype, fqdn, value, ttl = local_dns.validate_record(
        str(record.get("record_type", "")), fqdn, str(record.get("value", "")), record.get("ttl", 300) or 300
    )
    enabled = 1 if record.get("enabled", True) else 0
    findings = local_dns.record_findings(conn, fqdn, rtype, value)
    has_conflict = any(severity == "conflict" for severity, _ in findings)
    has_warning = any(severity == "warning" for severity, _ in findings)
    ts = now()
    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO local_dns_records(name, fqdn, record_type, value, ttl, comment, enabled, auto_ptr, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
        (fqdn.split(".", 1)[0], fqdn, rtype, value, ttl, f"imported from {source_label}", enabled, ts, ts),
    )
    if cursor.rowcount:
        rollback_info["local_dns_ids"].append(cursor.lastrowid)
        if has_conflict:
            return "added_conflicting"
        if has_warning:
            return "added_with_warning"
        return "added"
    return "duplicate"


def _apply_alias_item(conn: sqlite3.Connection, client: dict[str, Any], source_label: str, rollback_info: dict[str, Any]) -> str:
    network = str(ipaddress.ip_network(str(client.get("cidr_or_ip", "")).strip(), strict=False))
    display_name = str(client.get("display_name", "")).strip()
    if not display_name:
        raise ImportError_("client alias display name is required")
    existing = conn.execute("SELECT cidr, display_name, description FROM client_aliases WHERE cidr=?", (network,)).fetchone()
    ts = now()
    conn.execute(
        """
        INSERT INTO client_aliases(cidr, display_name, description, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cidr) DO UPDATE SET display_name=excluded.display_name, description=excluded.description, updated_at=excluded.updated_at
        """,
        (network, display_name, f"imported from {source_label}", ts, ts),
    )
    if existing:
        rollback_info["aliases_updated"].append(dict(existing))
        return "updated"
    rollback_info["aliases_added"].append(network)
    return "added"


def _apply_client_full_item(conn: sqlite3.Connection, client: dict[str, Any], source_label: str, rollback_info: dict[str, Any]) -> tuple[int, int]:
    """Creates a new persistent client with every identifier from the
    import (always a new client -- this migration path does not attempt
    to merge into an existing same-named client, to keep apply/rollback
    unambiguous; an operator can merge manually afterward if desired).
    Returns (client_id, identifiers_created)."""
    name = str(client.get("name", "")).strip()
    if not name:
        raise ImportError_("client name is required")
    ts = now()
    cur = conn.execute(
        "INSERT INTO clients(name, description, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (name, client.get("description") or f"imported from {source_label}", 1 if client.get("enabled", True) else 0, ts, ts),
    )
    client_id = cur.lastrowid
    created = 0
    for identifier in client.get("identifiers", []):
        kind, value = identifier.get("kind"), identifier.get("value")
        if not kind or not value:
            continue
        already = conn.execute("SELECT 1 FROM client_identifiers WHERE kind=? AND value=?", (kind, value)).fetchone()
        if already:
            continue
        conn.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES (?, ?, ?, ?)",
            (client_id, kind, value, ts),
        )
        created += 1
    rollback_info["clients_added"].append(client_id)
    return client_id, created


def _client_id_by_unique_name(conn: sqlite3.Connection, name: str) -> int:
    rows = conn.execute("SELECT id FROM clients WHERE name=? ORDER BY id", (name,)).fetchall()
    if not rows:
        raise ImportError_(f"client rule references missing client {name!r}")
    if len(rows) > 1:
        raise ImportError_(
            f"client rule references ambiguous client name {name!r}; rename duplicates before importing client-scoped access rules"
        )
    return int(rows[0]["id"])


def _apply_access_rule_item(conn: sqlite3.Connection, action: str, rule: dict[str, Any], rollback_info: dict[str, Any]) -> int | None:
    """Creates one allow/deny access rule from an imported IPv4/IPv6/CIDR/
    ClientID value, preserving the source kind exactly (never broadened to
    a wider range). Returns the new rule id, or None if it already exists
    (treated as a duplicate, not an error)."""
    kind, value = rule.get("kind"), rule.get("value")
    client_id = None
    if kind == "client":
        client_name = str(rule.get("client_name") or "").strip()
        if not client_name:
            return None
        client_id = _client_id_by_unique_name(conn, client_name)
        value = None
    elif kind not in ("ipv4", "ipv4_cidr", "ipv6", "ipv6_cidr", "clientid") or not value:
        return None
    existing = conn.execute(
        "SELECT id FROM access_rules WHERE action=? AND kind=? AND value IS ? AND client_id IS ?",
        (action, kind, value, client_id),
    ).fetchone()
    if existing:
        return None
    ts = now()
    cur = conn.execute(
        "INSERT INTO access_rules(action, kind, value, client_id, created_at) VALUES (?, ?, ?, ?, ?)",
        (action, kind, value, client_id, ts),
    )
    rollback_info["access_rules_added"].append(cur.lastrowid)
    return cur.lastrowid


_DESELECTION_SHORT_NAMES: dict[str, str] = {
    "blocklists": "Blocklist",
    "custom_blocks": "Custom block rule",
    "custom_allows": "Custom allow rule",
    "rewrites": "Rewrite rule",
    "regex_rules": "Regex rule",
    "local_dns": "Local DNS",
    "upstreams": "Upstream resolver",
    "client_scoped": "Client-scoped item",
    "comments": "Comment",
}


def _deselection_notes(plan: dict[str, Any], deselected_keys: list[str]) -> list[str]:
    """Explicit, itemized notes for the final result: for every category
    where the operator deselected one or more selectable items, a sentence
    naming the exact count and category -- never folded into a single
    opaque 'N deselected' total. e.g. "2 Local DNS records were not
    imported because Local DNS was deselected"."""
    deselected_set = set(deselected_keys)
    notes: list[str] = []
    for name, items in plan["categories"].items():
        count = sum(1 for item in items if item["key"] in deselected_set)
        if not count:
            continue
        short = _DESELECTION_SHORT_NAMES.get(name, MIGRATION_CATEGORIES.get(name, name))
        noun = "record" if name == "local_dns" else "item"
        plural = "s" if count != 1 else ""
        notes.append(f"{count} {short} {noun}{plural} were not imported because {short} was deselected")
    return notes


def _migration_result_label(counts: dict[str, Any]) -> str:
    """A result label that never claims a plain 'Applied' when supported,
    selected data was skipped as a duplicate, flagged as conflicting, kept
    inactive as unsupported, or left out by the operator."""
    reasons = []
    if counts.get("duplicates_skipped"):
        reasons.append("skipped duplicates")
    if counts.get("local_dns_conflicts"):
        reasons.append("conflicts")
    if counts.get("local_dns_warnings"):
        reasons.append("warnings")
    if counts.get("invalid_kept_inactive") or counts.get("unsupported_kept_inactive"):
        reasons.append("unsupported items")
    if counts.get("user_deselected"):
        reasons.append("user-deselected items")
    if not reasons:
        return "Applied"
    if len(reasons) == 1:
        return f"Applied with {reasons[0]}"
    return "Applied with " + ", ".join(reasons[:-1]) + " and " + reasons[-1]


def _component_breakdown(counts: dict[str, Any], deselection_notes: list[str]) -> str:
    """A per-component breakdown of what an apply actually did, so a plain
    'Applied' status is never the only signal available for what happened to
    selected data -- Local DNS is always itemized explicitly, even at zero,
    since a silent zero there is exactly the failure mode this guards
    against."""
    lines: list[str] = []
    blocklist_bits = []
    if counts.get("blocklists_added"):
        blocklist_bits.append(f"{counts['blocklists_added']} created")
    if counts.get("blocklists_updated"):
        blocklist_bits.append(f"{counts['blocklists_updated']} updated")
    if blocklist_bits:
        lines.append("Blocklists: " + ", ".join(blocklist_bits))
    rule_total = (
        counts.get("block_rules", 0) + counts.get("allow_rules", 0) + counts.get("rewrite_rules", 0)
        + counts.get("regex_rules", 0) + counts.get("comments", 0)
    )
    if rule_total:
        lines.append(f"Custom rules: {rule_total} created")
    local_dns_bits = [f"{counts.get('local_dns_records', 0)} created"]
    if counts.get("local_dns_conflicts"):
        local_dns_bits.append(f"{counts['local_dns_conflicts']} conflicting (kept, not overwritten)")
    if counts.get("local_dns_warnings"):
        local_dns_bits.append(f"{counts['local_dns_warnings']} imported with warnings (unusual but valid)")
    lines.append("Local DNS: " + ", ".join(local_dns_bits))
    if counts.get("upstream_resolvers"):
        lines.append(f"Upstream resolvers: {counts['upstream_resolvers']} created")
    if counts.get("client_aliases"):
        lines.append(f"Client aliases: {counts['client_aliases']} created")
    if counts.get("clients_created"):
        lines.append(
            f"Clients & Access: {counts['clients_created']} persistent client(s), "
            f"{counts.get('client_identifiers_created', 0)} identifier(s), "
            f"{counts.get('access_rules_created', 0)} access rule(s) created"
        )
    elif counts.get("access_rules_created"):
        lines.append(f"Clients & Access: {counts['access_rules_created']} access rule(s) created")
    unsupported_total = counts.get("invalid_kept_inactive", 0) + counts.get("unsupported_kept_inactive", 0)
    lines.append(f"Unsupported: {unsupported_total}")
    lines.append(f"Deselected: {counts.get('user_deselected', 0)}")
    if counts.get("duplicates_skipped"):
        lines.append(f"Duplicates skipped: {counts['duplicates_skipped']}")
    lines.extend(deselection_notes)
    return "\n".join(lines)


def apply_migration_job(
    job_id: int,
    selected: set[str] | None = None,
    default_domain: str | None = None,
) -> dict[str, Any]:
    """Apply the selected preview items in one database transaction.

    `selected` holds the stable item keys (`category:index`) the operator
    left checked; None applies every default-selected item. Validation runs
    first, then a verified pre-import backup (which must succeed), then every
    destination write — custom filter rules, blocklist sources, Local DNS
    records, client aliases, upstream resolvers — inside a single
    transaction. Any failure rolls the whole transaction back, leaves no
    partial rows anywhere, and marks the job failed with the exact stage."""
    job = get_job(job_id)
    if not job:
        raise ImportError_(f"import job {job_id} not found")
    if not is_migration_source(job["source_type"]):
        raise ImportError_(f"import job {job_id} is not a migration job")
    if job["status"] in {"applied", "rolled_back"}:
        raise ImportError_("migration job has already been applied")
    if job["status"] == "canceled":
        raise ImportError_("this migration job was canceled")
    translation = migration_translation_from_job(job_id)
    source_system = _SOURCE_SYSTEM_BY_TYPE.get(job["source_type"], "import")
    source_label = {"adguard": "AdGuard Home", "pihole": "Pi-hole"}.get(source_system, "import")
    plan = build_migration_plan(translation, default_domain)
    items = _plan_items(plan)
    if selected is None:
        selected_keys = {item["key"] for item in items if item["selected"]}
    else:
        selected_keys = {str(key) for key in selected}
    deselected = [item["key"] for item in items if item["selectable"] and item["key"] not in selected_keys]
    entries = _rule_entries(translation)
    records = list(translation.get("rewrites_as_local_dns", []))
    sources_list = list(translation.get("blocklist_sources", []))
    resolvers_list = list(translation.get("upstream_resolvers", []))
    aliases_list = list(translation.get("clients_as_aliases", []))
    clients_full_list = list(translation.get("clients_full", []))
    access_allowed_list = list(translation.get("access_allowed", []))
    access_denied_list = list(translation.get("access_denied", []))
    access_default_policy = translation.get("access_default_policy")

    counts = {
        "blocklists_added": 0,
        "blocklists_updated": 0,
        "block_rules": 0,
        "allow_rules": 0,
        "rewrite_rules": 0,
        "regex_rules": 0,
        "comments": 0,
        "local_dns_records": 0,
        "local_dns_conflicts": 0,
        "local_dns_warnings": 0,
        "upstream_resolvers": 0,
        "client_aliases": 0,
        "clients_created": 0,
        "client_identifiers_created": 0,
        "access_rules_created": 0,
        "access_default_policy_changed": 0,
        "duplicates_skipped": 0,
        "invalid_kept_inactive": 0,
        "unsupported_kept_inactive": 0,
        "user_deselected": len(deselected),
        "failed": 0,
    }
    rollback_info: dict[str, Any] = {
        "local_dns_ids": [],
        "sources_added": [],
        "sources_updated": [],
        "aliases_added": [],
        "aliases_updated": [],
        "upstream_ids": [],
        "clients_added": [],
        "access_rules_added": [],
        "access_default_policy_before": None,
    }
    failures: list[dict[str, str]] = []
    backup_path = create_pre_import_backup(strict=True)
    stage = "starting"
    conn = connect()
    # This connection's lifetime is managed manually via the `finally: conn.close()`
    # below, not by entering `with connect() as conn:` -- priming the depth counter
    # here keeps the `with conn:` transaction boundary further down from closing the
    # connection early (AlderpointDNSConnection only closes once the depth that
    # opened it reaches zero).
    conn._alderpointdns_depth = 1
    try:
        # Idempotent schema setup happens before the transaction opens, so no
        # implicit commit can split the apply.
        init_db(conn)
        _init_filter_tables(conn)
        local_dns.init_db(conn)
        upstream_dns.init_db(conn)
        custom_rules.init_db(conn)
        clients.init_db(conn)
        current_access_policy_row = conn.execute("SELECT default_policy FROM access_settings WHERE id=1").fetchone()
        current_access_policy = current_access_policy_row["default_policy"] if current_access_policy_row else "allow"
        conn.commit()
        access_layer_touched = False
        try:
            with conn:
                if access_default_policy in {"allow", "deny"} and access_default_policy != current_access_policy:
                    stage = "Clients & Access default policy"
                    rollback_info["access_default_policy_before"] = current_access_policy
                    conn.execute("UPDATE access_settings SET default_policy=?, updated_at=? WHERE id=1", (access_default_policy, now()))
                    counts["access_default_policy_changed"] = 1
                    access_layer_touched = True
                for item in items:
                    if not item["apply"] or item["key"] not in selected_keys:
                        continue
                    kind, index = item["apply"]
                    if kind == "source":
                        stage = f"blocklist source {item['source']}"
                        outcome = _apply_source_item(conn, sources_list[index], rollback_info)
                        if outcome == "added":
                            counts["blocklists_added"] += 1
                        elif outcome == "updated":
                            counts["blocklists_updated"] += 1
                        else:
                            counts["duplicates_skipped"] += 1
                    elif kind == "rule":
                        entry = entries[index]
                        stage = f"custom rule {entry['text']}"
                        results = custom_rules.add_rule(
                            entry["rule"],
                            source_system=source_system,
                            comment=entry.get("comment", "") or f"imported from {source_label}",
                            enabled=True,
                            import_job_id=job_id,
                            plain_domain_subdomains=entry["plain_domain_subdomains"],
                            conn=conn,
                        )
                        for result in results:
                            if result["status"] == "duplicate":
                                counts["duplicates_skipped"] += 1
                            elif result["validation_state"] == "invalid":
                                counts["invalid_kept_inactive"] += 1
                            elif result["validation_state"] == "unsupported":
                                counts["unsupported_kept_inactive"] += 1
                            elif result["rule_type"] == "comment":
                                counts["comments"] += 1
                            elif result["rule_type"] == "block":
                                counts["block_rules"] += 1
                            elif result["rule_type"] == "allow":
                                counts["allow_rules"] += 1
                            elif result["rule_type"] == "rewrite":
                                counts["rewrite_rules"] += 1
                            elif result["rule_type"] in {"regex_block", "regex_allow"}:
                                counts["regex_rules"] += 1
                    elif kind == "local_dns":
                        record = records[index]
                        stage = f"local DNS record {record.get('fqdn', '')}"
                        outcome = _apply_local_dns_record(conn, record, plan["domain"], source_label, rollback_info)
                        if outcome == "added":
                            counts["local_dns_records"] += 1
                        elif outcome == "added_conflicting":
                            counts["local_dns_records"] += 1
                            counts["local_dns_conflicts"] += 1
                        elif outcome == "added_with_warning":
                            counts["local_dns_records"] += 1
                            counts["local_dns_warnings"] += 1
                        else:
                            counts["duplicates_skipped"] += 1
                    elif kind == "upstream":
                        resolver = resolvers_list[index]
                        stage = f"upstream resolver {resolver.get('name', resolver.get('address', ''))}"
                        inserted = _insert_upstream_resolvers(conn, [resolver])
                        if inserted:
                            rollback_info["upstream_ids"].extend(inserted)
                            counts["upstream_resolvers"] += len(inserted)
                        else:
                            counts["duplicates_skipped"] += 1
                    elif kind == "alias":
                        client = aliases_list[index]
                        stage = f"client alias {client.get('display_name', '')}"
                        _apply_alias_item(conn, client, source_label, rollback_info)
                        counts["client_aliases"] += 1
                    elif kind == "client":
                        client = clients_full_list[index]
                        stage = f"persistent client {client.get('name', '')}"
                        _, identifiers_created = _apply_client_full_item(conn, client, source_label, rollback_info)
                        counts["clients_created"] += 1
                        counts["client_identifiers_created"] += identifiers_created
                        access_layer_touched = access_layer_touched or bool(
                            [i for i in client.get("identifiers", []) if i.get("kind") == "clientid"]
                        )
                    elif kind == "access_allow":
                        rule = access_allowed_list[index]
                        stage = f"allowed client {rule.get('raw', rule.get('value', ''))}"
                        rule_id = _apply_access_rule_item(conn, "allow", rule, rollback_info)
                        if rule_id:
                            counts["access_rules_created"] += 1
                            access_layer_touched = True
                        else:
                            counts["duplicates_skipped"] += 1
                    elif kind == "access_deny":
                        rule = access_denied_list[index]
                        stage = f"denied client {rule.get('raw', rule.get('value', ''))}"
                        rule_id = _apply_access_rule_item(conn, "deny", rule, rollback_info)
                        if rule_id:
                            counts["access_rules_created"] += 1
                            access_layer_touched = True
                        else:
                            counts["duplicates_skipped"] += 1
            if access_layer_touched:
                # Deploys after the transaction above has committed, so this
                # reads the just-applied clients/identifiers/rules. A
                # deployment failure here (e.g. dnsdist --check-config
                # rejects something) is caught by the same except below and
                # fails the whole job -- deploy_access_layer() itself never
                # leaves a broken config active (see app/clients.py).
                stage = "deploying Clients & Access policy to dnsdist"
                clients.deploy_access_layer(conn)
        except Exception as exc:
            counts["failed"] = 1
            failures.append({"stage": stage, "error": str(exc)})
            message = f"apply failed during stage: {stage}: {exc}"
            conn.execute(
                "UPDATE import_jobs SET finished_at=?, status='failed', result_label='Failed', failed_rows=1, message=?, report_json=? WHERE id=?",
                (
                    now(),
                    message,
                    json.dumps(redact_sensitive({"error": message, "stage": stage, "counts": counts, "failures": failures}), default=str),
                    job_id,
                ),
            )
            conn.commit()
            raise ImportError_(message) from exc
        applied_total = (
            counts["blocklists_added"] + counts["blocklists_updated"] + counts["block_rules"] + counts["allow_rules"]
            + counts["rewrite_rules"] + counts["regex_rules"] + counts["comments"] + counts["invalid_kept_inactive"]
            + counts["unsupported_kept_inactive"] + counts["local_dns_records"] + counts["upstream_resolvers"]
            + counts["client_aliases"] + counts["clients_created"] + counts["access_rules_created"]
        )
        notes = _deselection_notes(plan, deselected)
        result_label = _migration_result_label(counts)
        breakdown = _component_breakdown(counts, notes)
        report = {
            "applied": True,
            "backup": backup_path,
            "counts": counts,
            "deselected_keys": deselected,
            "deselection_notes": notes,
            "result_label": result_label,
            "failures": failures,
        }
        conn.execute(
            """
            UPDATE import_jobs
            SET finished_at=?, status='applied', result_label=?, applied_rows=?, skipped_rows=?, failed_rows=0,
                inserted_record_ids_json=?, rollback_json=?, report_json=?, message=?
            WHERE id=?
            """,
            (
                now(),
                result_label,
                applied_total,
                counts["duplicates_skipped"] + counts["user_deselected"],
                json.dumps(rollback_info["local_dns_ids"]),
                json.dumps(rollback_info),
                json.dumps(redact_sensitive(report), default=str),
                f"{result_label}\n\n{breakdown}",
                job_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return {"counts": counts, "rollback": rollback_info, "deselected": deselected, "backup": backup_path}


def mark_job_deploy_failed(job_id: int, message: str) -> None:
    """Record that the post-apply deploy failed. The database writes remain
    (and can be reverted with rollback_job); the previously deployed
    configuration stays active because deploy() rolls itself back."""
    with connect() as conn:
        init_db(conn)
        conn.execute(
            "UPDATE import_jobs SET status='deploy_failed', message=? WHERE id=?",
            (f"applied to database, but deployment failed: {message}", job_id),
        )
        conn.commit()


def _insert_upstream_resolvers(conn: sqlite3.Connection, resolvers: list[dict[str, Any]]) -> list[int]:
    """Insert validated upstream resolvers, skipping existing identical ones.
    Returns the inserted row ids (for rollback)."""
    inserted: list[int] = []
    existing = {
        (row["protocol"], row["address"], int(row["port"]), row["doh_path"] or "")
        for row in conn.execute("SELECT protocol, address, port, doh_path FROM upstream_resolvers")
    }
    for resolver in resolvers:
        try:
            data = upstream_dns.validate_resolver({**resolver, "enabled": resolver.get("enabled", "1")}, require_enabled_set=True)
        except Exception:
            continue
        key = (data["protocol"], data["address"], int(data["port"]), data["doh_path"] or "")
        if key in existing:
            continue
        pos = conn.execute("SELECT coalesce(max(position), 0) + 1 AS pos FROM upstream_resolvers").fetchone()["pos"]
        ts = now()
        cursor = conn.execute(
            """
            INSERT INTO upstream_resolvers(name, protocol, address, port, doh_path, tls_hostname, bootstrap_ips, enabled, position, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (data["name"], data["protocol"], data["address"], data["port"], data["doh_path"], data["tls_hostname"], data["bootstrap_ips"], int(data["enabled"]), pos, ts, ts),
        )
        inserted.append(cursor.lastrowid)
        existing.add(key)
    return inserted


def job_report(job: dict[str, Any]) -> str:
    """Sanitized, downloadable JSON report for a job: no credentials, tokens,
    URL userinfo, or query strings can appear regardless of what the stored
    report or source contained."""
    try:
        stored = json.loads(job.get("report_json") or "{}")
    except ValueError:
        stored = {}
    payload = {
        "job_id": job["id"],
        "source_type": job["source_type"],
        "source_name": sanitize_url(job["source_name"]) if "://" in str(job["source_name"]) else job["source_name"],
        "status": job["status"],
        "created_at": job["created_at"],
        "finished_at": job["finished_at"],
        "total_rows": job["total_rows"],
        "applied_rows": job["applied_rows"],
        "skipped_rows": job["skipped_rows"],
        "failed_rows": job["failed_rows"],
        "message": job["message"],
        "report": stored,
    }
    return json.dumps(redact_sensitive(payload), indent=2, default=str)
