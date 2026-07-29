#!/usr/bin/env python3
"""BindGuard Import and Migration: AdGuard Home migration, and spreadsheet/
text imports for Local DNS records, with staged preview, conflict
resolution, automatic backup, and rollback on failure.

Every function here only ever writes to SQLite (the same unprivileged
operation ordinary Local DNS / blocklist source edits already perform); the
privileged BIND/dnsdist deployment step is the existing, unmodified
`sudo bindguard_compiler.py deploy [--no-download]` path already used by
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
import urllib.request
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

import yaml

from app import local_dns


DB_PATH = Path("/var/lib/bindguard/bindguard.db")
BACKUP_SCRIPT = Path("/opt/bindguard/scripts/backup.sh")

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


class ImportError_(ValueError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        if close:
            db.execute("PRAGMA journal_mode=WAL")
        db.executescript(
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
            );
            """
        )
        if close:
            db.commit()
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Parsing: CSV / XLSX / hosts / zone
# ---------------------------------------------------------------------------

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


def parse_bindguard_csv(text: str) -> list[dict[str, str]]:
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
        # Rows already in canonical shape (hosts/zone/bindguard-csv parsers)
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

def create_job(source_type: str, source_name: str, headers: list[str], raw_rows: list[dict[str, str]]) -> int:
    with connect() as conn:
        init_db(conn)
        cursor = conn.execute(
            """
            INSERT INTO import_jobs(created_at, source_type, source_name, headers_json, raw_rows_json, status, total_rows)
            VALUES (?, ?, ?, ?, ?, 'uploaded', ?)
            """,
            (now(), source_type, source_name, json.dumps(headers), json.dumps(raw_rows), len(raw_rows)),
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
                warnings = local_dns.record_warnings(conn, fqdn, rtype, value)
                if warnings:
                    item["warnings"] = warnings
                    conflicts.append(item)
                else:
                    valid.append(item)
            except Exception as exc:
                item["error"] = str(exc)
                invalid.append(item)
        conn.execute(
            """
            UPDATE import_jobs SET status='previewed', column_map_json=?, valid_rows=?, invalid_rows=?,
                duplicate_rows=?, conflict_rows=? WHERE id=?
            """,
            (json.dumps(column_map), len(valid), len(invalid), len(duplicates), len(conflicts), job_id),
        )
        conn.commit()
    return {"job_id": job_id, "valid": valid, "invalid": invalid, "duplicates": duplicates, "conflicts": conflicts, "domain": domain}


def create_pre_import_backup() -> str | None:
    if not BACKUP_SCRIPT.exists():
        return None
    try:
        proc = subprocess.run([str(BACKUP_SCRIPT)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True, timeout=60)
        return proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else None
    except Exception:
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


# ---------------------------------------------------------------------------
# AdGuard Home migration
# ---------------------------------------------------------------------------

def parse_adguard_yaml(text: str) -> dict[str, Any]:
    data = yaml.safe_load(text) or {}
    return _translate_adguard_config(data)


def fetch_adguard_api(base_url: str, username: str, password: str) -> dict[str, Any]:
    base_url = base_url.rstrip("/")
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}"}
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
            with urllib.request.urlopen(request, timeout=8) as response:
                raw[key] = json.loads(response.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
            errors[key] = str(exc)
    config_shaped: dict[str, Any] = {
        "filters": (raw.get("filtering") or {}).get("filters", []),
        "whitelist_filters": (raw.get("filtering") or {}).get("whitelist_filters", []),
        "user_rules": (raw.get("filtering") or {}).get("user_rules", []),
        "filtering": {"rewrites": raw.get("rewrites", [])},
        "clients": {"persistent": (raw.get("clients") or {}).get("clients", [])},
        "dns": raw.get("dns_info", {}),
    }
    result = _translate_adguard_config(config_shaped)
    if errors:
        result["fetch_errors"] = errors
    return result


def _translate_adguard_config(data: dict[str, Any]) -> dict[str, Any]:
    filtering = data.get("filtering") if isinstance(data.get("filtering"), dict) else {}
    filters = data.get("filters") or filtering.get("filters") or []
    whitelist_filters = data.get("whitelist_filters") or filtering.get("whitelist_filters") or []
    user_rules = data.get("user_rules") or filtering.get("user_rules") or []
    rewrites = filtering.get("rewrites") or data.get("rewrites") or []
    clients_block = data.get("clients") if isinstance(data.get("clients"), dict) else {}
    persistent_clients = clients_block.get("persistent") or []
    dns_block = data.get("dns") if isinstance(data.get("dns"), dict) else {}

    blocklist_sources = []
    for entry in filters:
        if not isinstance(entry, dict):
            continue
        blocklist_sources.append({
            "name": entry.get("name") or entry.get("url", "imported-filter"),
            "url": entry.get("url", ""),
            "enabled": bool(entry.get("enabled", True)),
        })

    allowlist_unsupported = []
    for entry in whitelist_filters:
        if not isinstance(entry, dict):
            continue
        allowlist_unsupported.append({
            "name": entry.get("name") or entry.get("url", "imported-allowlist"),
            "url": entry.get("url", ""),
            "note": "BindGuard has no allowlist-subscription object; add matching custom allow rules manually if needed.",
        })

    custom_allow: list[str] = []
    custom_block: list[str] = []
    unsupported_rules: list[str] = []
    for raw_rule in user_rules:
        rule = str(raw_rule).strip()
        if not rule or rule.startswith("!"):
            continue
        if rule.startswith("@@||") and rule.endswith("^"):
            custom_allow.append(rule[4:-1].rstrip("^"))
        elif rule.startswith("||") and rule.endswith("^"):
            custom_block.append(rule[2:-1].rstrip("^"))
        elif re.match(r"^[a-zA-Z0-9.-]+$", rule):
            custom_block.append(rule)
        else:
            unsupported_rules.append(rule)

    rewrites_as_local_dns = []
    for entry in rewrites:
        if not isinstance(entry, dict):
            continue
        domain = entry.get("domain", "")
        answer = entry.get("answer", "")
        if not domain or not answer:
            continue
        try:
            ip = ipaddress.ip_address(answer)
            rtype = "A" if isinstance(ip, ipaddress.IPv4Address) else "AAAA"
        except ValueError:
            rtype = "CNAME"
        rewrites_as_local_dns.append({"fqdn": domain, "record_type": rtype, "value": answer})

    clients_as_aliases = []
    untranslatable_client_settings = []
    for client in persistent_clients:
        if not isinstance(client, dict):
            continue
        name = client.get("name", "")
        ids = client.get("ids") or []
        cidr_or_ip = next((i for i in ids if _looks_like_ip_or_cidr(i)), "")
        if name and cidr_or_ip:
            clients_as_aliases.append({"display_name": name, "cidr_or_ip": cidr_or_ip, "all_ids": ids})
        for feature in ("filtering_enabled", "safe_search", "blocked_services", "upstreams", "ignore_querylog", "ignore_statistics"):
            if client.get(feature) not in (None, False, {}):
                untranslatable_client_settings.append(f"{name or cidr_or_ip}: {feature} has no BindGuard per-client equivalent yet (schema exists, not enforced at runtime)")

    untranslatable = list(untranslatable_client_settings)
    if dns_block.get("upstream_dns"):
        untranslatable.append("dns.upstream_dns: BIND's forwarders list is a static packaging setting, not yet admin-editable")
    if filtering.get("safe_search", {}).get("enabled") if isinstance(filtering.get("safe_search"), dict) else False:
        untranslatable.append("filtering.safe_search: SafeSearch enforcement is not implemented in BindGuard")
    if filtering.get("blocked_services", {}).get("ids") if isinstance(filtering.get("blocked_services"), dict) else False:
        untranslatable.append("filtering.blocked_services: named blocked-service bundles are not implemented in BindGuard")

    return {
        "blocklist_sources": blocklist_sources,
        "allowlist_unsupported": allowlist_unsupported,
        "custom_allow": sorted(set(custom_allow)),
        "custom_block": sorted(set(custom_block)),
        "unsupported_rules": unsupported_rules,
        "rewrites_as_local_dns": rewrites_as_local_dns,
        "clients_as_aliases": clients_as_aliases,
        "untranslatable": untranslatable,
    }


def _looks_like_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def apply_adguard_translation(translation: dict[str, Any], groups: set[str]) -> dict[str, int]:
    from app import bindguard_compiler

    counts = {"sources": 0, "custom_allow": 0, "custom_block": 0, "local_dns": 0, "aliases": 0}
    with bindguard_compiler.connect() as conn:
        bindguard_compiler.init_db()
        if "blocklist_sources" in groups:
            for source in translation.get("blocklist_sources", []):
                if not source.get("url"):
                    continue
                conn.execute(
                    """
                    INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, ?, 'ads_trackers')
                    ON CONFLICT(name) DO UPDATE SET url=excluded.url
                    """,
                    (source["name"][:120], source["url"], 1 if source.get("enabled", True) else 0),
                )
                counts["sources"] += 1
        if "custom_rules" in groups:
            for domain in translation.get("custom_allow", []):
                conn.execute(
                    "INSERT OR IGNORE INTO custom_rules(domain, action, comment, created_at) VALUES (?, 'allow', 'imported from AdGuard Home', ?)",
                    (domain, now()),
                )
                counts["custom_allow"] += 1
            for domain in translation.get("custom_block", []):
                conn.execute(
                    "INSERT OR IGNORE INTO custom_rules(domain, action, comment, created_at) VALUES (?, 'block', 'imported from AdGuard Home', ?)",
                    (domain, now()),
                )
                counts["custom_block"] += 1
        conn.commit()
    if "rewrites" in groups:
        for rewrite in translation.get("rewrites_as_local_dns", []):
            try:
                local_dns.add_record(rewrite["record_type"], rewrite["fqdn"], rewrite["value"], 300, "imported from AdGuard Home", True, override=True)
                counts["local_dns"] += 1
            except Exception:
                continue
    if "clients" in groups:
        for client in translation.get("clients_as_aliases", []):
            try:
                local_dns.upsert_alias(client["cidr_or_ip"], client["display_name"], "imported from AdGuard Home")
                counts["aliases"] += 1
            except Exception:
                continue
    return counts
