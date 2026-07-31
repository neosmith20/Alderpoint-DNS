#!/usr/bin/env python3
"""Local authoritative DNS records and client aliases for Alderpoint DNS."""

from __future__ import annotations

import csv
import datetime as dt
import ipaddress
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any


DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
COMPILED_DIR = Path("/var/lib/alderpointdns/compiled/bind")
LOCAL_ZONE_DIR = COMPILED_DIR / "local"
LOCAL_ZONES_CONF = COMPILED_DIR / "local-zones.conf"
NAMED_LOCAL_CONF = Path("/etc/bind/named.conf.local")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
DEFAULT_DOMAIN = "home.arpa"
LOCAL_NS = "alderpointdns-local-ns"
LABEL_RE = re.compile(r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RECORD_TYPES = {"A", "AAAA", "PTR", "CNAME"}


class LocalDNSError(ValueError):
    pass


class AlderpointDNSConnection(sqlite3.Connection):
    def __enter__(self):
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 0) + 1
        return super().__enter__()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        super().__exit__(exc_type, exc_value, traceback)
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 1) - 1
        if self._alderpointdns_depth <= 0:
            self.close()


@dataclass(frozen=True)
class ZoneFile:
    zone: str
    path: Path
    text: str


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, factory=AlderpointDNSConnection, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        if close:
            db.execute("PRAGMA journal_mode=WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS local_dns_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS local_dns_records (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                fqdn TEXT NOT NULL,
                record_type TEXT NOT NULL CHECK(record_type IN ('A', 'AAAA', 'PTR', 'CNAME')),
                value TEXT NOT NULL,
                ttl INTEGER NOT NULL DEFAULT 300,
                comment TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                auto_ptr INTEGER NOT NULL DEFAULT 0,
                ptr_record_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(fqdn, record_type, value)
            );
            CREATE INDEX IF NOT EXISTS idx_local_dns_records_fqdn ON local_dns_records(fqdn);
            CREATE INDEX IF NOT EXISTS idx_local_dns_records_value ON local_dns_records(value);
            CREATE TABLE IF NOT EXISTS client_aliases (
                id INTEGER PRIMARY KEY,
                cidr TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS local_dns_deployments (
                id INTEGER PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                forward_zone TEXT,
                reverse_zones INTEGER NOT NULL DEFAULT 0,
                serial INTEGER NOT NULL DEFAULT 0,
                message TEXT NOT NULL DEFAULT '',
                validation_output TEXT NOT NULL DEFAULT ''
            );
            """
        )
        db.executemany(
            "INSERT OR IGNORE INTO local_dns_settings(key, value) VALUES (?, ?)",
            (
                ("internal_domain", DEFAULT_DOMAIN),
                ("default_ttl", "300"),
                ("server_hostname", "alderpointdns"),
                ("server_ip", detect_server_ip()),
            ),
        )
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    init_db(conn)
    close = conn is None
    db = conn or connect()
    try:
        return {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM local_dns_settings")}
    finally:
        if close:
            db.close()


def update_settings(values: dict[str, Any]) -> None:
    with connect() as conn:
        init_db(conn)
        for key, value in values.items():
            if key == "internal_domain":
                value = normalize_domain(str(value))
            if key == "default_ttl":
                value = str(validate_ttl(value))
            if key == "server_ip" and value:
                value = str(ipaddress.ip_address(str(value).strip()))
            conn.execute(
                "INSERT INTO local_dns_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )


def detect_server_ip() -> str:
    try:
        proc = run(["hostname", "-I"], check=False)
        for token in proc.stdout.split():
            ip = ipaddress.ip_address(token)
            if not ip.is_loopback and not ip.is_link_local:
                return str(ip)
    except Exception:
        pass
    return "127.0.0.1"


def normalize_domain(value: str) -> str:
    domain = value.strip().strip(".").lower()
    if domain == "local":
        raise LocalDNSError(".local conflicts with multicast DNS; use home.arpa or another internal domain")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise LocalDNSError("domain is not valid IDNA") from exc
    if not DOMAIN_RE.match(domain):
        raise LocalDNSError("domain is invalid")
    return domain


def validate_label(value: str) -> str:
    label = value.strip().strip(".").lower()
    if not LABEL_RE.match(label):
        raise LocalDNSError("hostname is invalid")
    return label


def validate_ttl(value: Any) -> int:
    try:
        ttl = int(value)
    except (TypeError, ValueError) as exc:
        raise LocalDNSError("TTL must be a number") from exc
    if ttl < 30 or ttl > 86400:
        raise LocalDNSError("TTL must be between 30 and 86400 seconds")
    return ttl


def normalize_fqdn(value: str, domain: str | None = None) -> str:
    fqdn = value.strip().strip(".").lower()
    if domain and "." not in fqdn:
        fqdn = f"{validate_label(fqdn)}.{domain}"
    return normalize_domain(fqdn)


def ptr_owner_for_ip(address: str) -> tuple[str, str]:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv4Address):
        octets = str(ip).split(".")
        return octets[3], ".".join(reversed(octets[:3])) + ".in-addr.arpa"
    nibbles = ip.reverse_pointer.split(".")
    return nibbles[0], ".".join(nibbles[1:])


def ip_network_zone(address: str) -> str:
    return ptr_owner_for_ip(address)[1]


def record_findings(conn: sqlite3.Connection, fqdn: str, record_type: str, value: str, record_id: int | None = None) -> list[tuple[str, str]]:
    """Data-quality findings for a candidate record, each tagged with a
    severity: 'conflict' for genuinely incompatible existing data that
    blocks automatic application without an explicit override, or
    'warning' for unusual-but-valid data that is imported/saved as
    requested and never blocks."""
    params: list[Any] = [fqdn]
    extra = ""
    if record_id:
        extra = " AND id<>?"
        params.append(record_id)
    findings: list[tuple[str, str]] = []
    if conn.execute(f"SELECT 1 FROM local_dns_records WHERE fqdn=?{extra} AND enabled=1 LIMIT 1", params).fetchone():
        findings.append(("conflict", "A hostname already exists."))
    if record_type == "CNAME":
        if conn.execute(f"SELECT 1 FROM local_dns_records WHERE fqdn=?{extra} AND record_type<>'CNAME' LIMIT 1", params).fetchone():
            findings.append(("conflict", "A CNAME conflicts with another record."))
    elif conn.execute(f"SELECT 1 FROM local_dns_records WHERE fqdn=?{extra} AND record_type='CNAME' LIMIT 1", params).fetchone():
        findings.append(("conflict", "This hostname already has a CNAME record."))
    if record_type in {"A", "AAAA"}:
        try:
            ip = str(ipaddress.ip_address(value))
        except ValueError:
            ip = ""
        if ip:
            ptr_owner, ptr_zone = ptr_owner_for_ip(ip)
            ptr_fqdn = f"{ptr_owner}.{ptr_zone}"
            ptr = conn.execute(
                "SELECT value FROM local_dns_records WHERE fqdn=? AND record_type='PTR' AND enabled=1",
                (ptr_fqdn,),
            ).fetchone()
            if ptr and ptr["value"].rstrip(".") != fqdn:
                findings.append(("conflict", "This IP already has a different PTR record."))
            if not ipaddress.ip_address(ip).is_private:
                findings.append(("warning", "Public IP address outside common private networks. Imported as requested."))
    if record_type == "PTR":
        if not conn.execute("SELECT 1 FROM local_dns_records WHERE fqdn=? AND record_type IN ('A','AAAA') LIMIT 1", (value.rstrip("."),)).fetchone():
            findings.append(("conflict", "The PTR target lacks a corresponding A or AAAA record."))
    return findings


def record_conflicts(conn: sqlite3.Connection, fqdn: str, record_type: str, value: str, record_id: int | None = None) -> list[str]:
    return [message for severity, message in record_findings(conn, fqdn, record_type, value, record_id) if severity == "conflict"]


def record_warnings(conn: sqlite3.Connection, fqdn: str, record_type: str, value: str, record_id: int | None = None) -> list[str]:
    """All findings (conflicts and warnings) as plain messages, for display.
    Blocking decisions must use record_conflicts() instead."""
    return [message for _severity, message in record_findings(conn, fqdn, record_type, value, record_id)]


def validate_record(record_type: str, fqdn: str, value: str, ttl: Any) -> tuple[str, str, str, int]:
    rtype = record_type.strip().upper()
    if rtype not in RECORD_TYPES:
        raise LocalDNSError("record type is not supported")
    name = normalize_domain(fqdn)
    clean_ttl = validate_ttl(ttl)
    if rtype == "A":
        ip = ipaddress.ip_address(value.strip())
        if not isinstance(ip, ipaddress.IPv4Address):
            raise LocalDNSError("A records require an IPv4 address")
        clean_value = str(ip)
    elif rtype == "AAAA":
        ip = ipaddress.ip_address(value.strip())
        if not isinstance(ip, ipaddress.IPv6Address):
            raise LocalDNSError("AAAA records require an IPv6 address")
        clean_value = str(ip)
    elif rtype in {"PTR", "CNAME"}:
        clean_value = normalize_domain(value)
    return rtype, name, clean_value, clean_ttl


def add_host(hostname: str, domain: str, address: str, ttl: Any = 300, comment: str = "", auto_ptr: bool = True, override: bool = False) -> list[str]:
    with connect() as conn:
        init_db(conn)
        with conn:
            local_domain = normalize_domain(domain or settings(conn)["internal_domain"])
            label = validate_label(hostname)
            fqdn = f"{label}.{local_domain}"
            ip = ipaddress.ip_address(address.strip())
            rtype = "A" if isinstance(ip, ipaddress.IPv4Address) else "AAAA"
            ttl_int = validate_ttl(ttl)
            findings = record_findings(conn, fqdn, rtype, str(ip))
            conflicts = [message for severity, message in findings if severity == "conflict"]
            if conflicts and not override:
                raise LocalDNSError(" ".join(conflicts))
            ts = now()
            cursor = conn.execute(
                """
                INSERT INTO local_dns_records(name, fqdn, record_type, value, ttl, comment, enabled, auto_ptr, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (label, fqdn, rtype, str(ip), ttl_int, comment or "", 1 if auto_ptr else 0, ts, ts),
            )
            ptr_id = None
            if auto_ptr:
                owner, zone = ptr_owner_for_ip(str(ip))
                ptr_fqdn = f"{owner}.{zone}"
                ptr_conflicts = record_conflicts(conn, ptr_fqdn, "PTR", fqdn)
                if ptr_conflicts and not override:
                    raise LocalDNSError(" ".join(ptr_conflicts))
                ptr_cursor = conn.execute(
                    """
                    INSERT OR REPLACE INTO local_dns_records(name, fqdn, record_type, value, ttl, comment, enabled, auto_ptr, created_at, updated_at)
                    VALUES (?, ?, 'PTR', ?, ?, ?, 1, 0, ?, ?)
                    """,
                    (owner, ptr_fqdn, fqdn, ttl_int, f"reverse for {fqdn}", ts, ts),
                )
                ptr_id = ptr_cursor.lastrowid
                conn.execute("UPDATE local_dns_records SET ptr_record_id=? WHERE id=?", (ptr_id, cursor.lastrowid))
        return [message for _severity, message in findings]


def add_record(record_type: str, fqdn: str, value: str, ttl: Any = 300, comment: str = "", enabled: bool = True, override: bool = False) -> list[str]:
    with connect() as conn:
        init_db(conn)
        with conn:
            rtype, name, clean_value, ttl_int = validate_record(record_type, fqdn, value, ttl)
            findings = record_findings(conn, name, rtype, clean_value)
            conflicts = [message for severity, message in findings if severity == "conflict"]
            if conflicts and not override:
                raise LocalDNSError(" ".join(conflicts))
            ts = now()
            conn.execute(
                """
                INSERT INTO local_dns_records(name, fqdn, record_type, value, ttl, comment, enabled, auto_ptr, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (name.split(".", 1)[0], name, rtype, clean_value, ttl_int, comment or "", 1 if enabled else 0, ts, ts),
            )
        return [message for _severity, message in findings]


def list_records(search: str = "") -> dict[str, Any]:
    with connect() as conn:
        init_db(conn)
        term = f"%{search.strip()}%"
        where = "WHERE fqdn LIKE ? OR value LIKE ? OR comment LIKE ?" if search.strip() else ""
        params = (term, term, term) if search.strip() else ()
        records = [dict(row) for row in conn.execute(f"SELECT * FROM local_dns_records {where} ORDER BY fqdn, record_type", params)]
        aliases = [dict(row) for row in conn.execute("SELECT * FROM client_aliases ORDER BY cidr")]
        deployment = conn.execute("SELECT * FROM local_dns_deployments ORDER BY id DESC LIMIT 1").fetchone()
        cfg = settings(conn)
    return {"records": records, "aliases": aliases, "deployment": deployment, "settings": cfg}


def update_record(record_id: int, record_type: str, fqdn: str, value: str, ttl: Any, comment: str, enabled: bool, override: bool = False) -> list[str]:
    with connect() as conn:
        init_db(conn)
        with conn:
            rtype, name, clean_value, ttl_int = validate_record(record_type, fqdn, value, ttl)
            findings = record_findings(conn, name, rtype, clean_value, record_id)
            conflicts = [message for severity, message in findings if severity == "conflict"]
            if conflicts and not override:
                raise LocalDNSError(" ".join(conflicts))
            conn.execute(
                """
                UPDATE local_dns_records
                SET name=?, fqdn=?, record_type=?, value=?, ttl=?, comment=?, enabled=?, updated_at=?
                WHERE id=?
                """,
                (name.split(".", 1)[0], name, rtype, clean_value, ttl_int, comment or "", 1 if enabled else 0, now(), record_id),
            )
        return [message for _severity, message in findings]


def toggle_record(record_id: int) -> None:
    with connect() as conn:
        init_db(conn)
        with conn:
            conn.execute("UPDATE local_dns_records SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?", (now(), record_id))


def delete_record(record_id: int) -> None:
    with connect() as conn:
        init_db(conn)
        with conn:
            row = conn.execute("SELECT ptr_record_id FROM local_dns_records WHERE id=?", (record_id,)).fetchone()
            conn.execute("DELETE FROM local_dns_records WHERE id=?", (record_id,))
            if row and row["ptr_record_id"]:
                conn.execute("DELETE FROM local_dns_records WHERE id=?", (row["ptr_record_id"],))


def upsert_alias(cidr: str, display_name: str, description: str = "") -> None:
    network = ipaddress.ip_network(cidr.strip(), strict=False)
    name = display_name.strip()
    if not name:
        raise LocalDNSError("display name is required")
    ts = now()
    with connect() as conn:
        init_db(conn)
        with conn:
            conn.execute(
                """
                INSERT INTO client_aliases(cidr, display_name, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cidr) DO UPDATE SET display_name=excluded.display_name, description=excluded.description, updated_at=excluded.updated_at
                """,
                (str(network), name, description or "", ts, ts),
            )


def delete_alias(alias_id: int) -> None:
    with connect() as conn:
        init_db(conn)
        with conn:
            conn.execute("DELETE FROM client_aliases WHERE id=?", (alias_id,))


def alias_for_client(client: str) -> str | None:
    try:
        ip = ipaddress.ip_address(client)
    except ValueError:
        return None
    with connect() as conn:
        init_db(conn)
        best: tuple[int, str] | None = None
        for row in conn.execute("SELECT cidr, display_name FROM client_aliases"):
            net = ipaddress.ip_network(row["cidr"], strict=False)
            if ip in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, row["display_name"])
        if best:
            return best[1]
        ptr = ptr_hostname_for_ip(conn, str(ip))
        if ptr:
            return f"{ptr} ({ip})"
    return None


def ptr_hostname_for_ip(conn: sqlite3.Connection, address: str) -> str | None:
    owner, zone = ptr_owner_for_ip(address)
    row = conn.execute(
        "SELECT value FROM local_dns_records WHERE fqdn=? AND record_type='PTR' AND enabled=1 LIMIT 1",
        (f"{owner}.{zone}",),
    ).fetchone()
    return row["value"] if row else None


def next_serial(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT serial FROM local_dns_deployments WHERE status='deployed' ORDER BY id DESC LIMIT 1").fetchone()
    current = int(row["serial"]) if row else int(time.strftime("%Y%m%d00"))
    minimum = int(time.strftime("%Y%m%d00"))
    return max(current + 1, minimum)


def rel_name(fqdn: str, zone: str) -> str:
    suffix = "." + zone
    if fqdn == zone:
        return "@"
    if fqdn.endswith(suffix):
        return fqdn[: -len(suffix)] or "@"
    return fqdn + "."


def render_zone(zone: str, records: list[sqlite3.Row], serial: int, default_ttl: int) -> str:
    ns = f"{LOCAL_NS}.{zone}."
    lines = [
        f"$ORIGIN {zone}.",
        f"$TTL {default_ttl}",
        f"@ IN SOA {ns} hostmaster.{zone}. ( {serial} 1h 15m 30d 5m )",
        f"@ IN NS {ns}",
        f"{LOCAL_NS} IN A 127.0.0.1",
        "",
    ]
    for row in records:
        name = rel_name(row["fqdn"], zone)
        target = row["value"] + "." if row["record_type"] in {"PTR", "CNAME"} else row["value"]
        lines.append(f"{name} {row['ttl']} IN {row['record_type']} {target}")
    return "\n".join(lines) + "\n"


def forward_zone_for_fqdn(fqdn: str, internal_domain: str) -> str:
    if fqdn == internal_domain or fqdn.endswith("." + internal_domain):
        return internal_domain
    labels = fqdn.split(".")
    if len(labels) < 3:
        return fqdn
    return ".".join(labels[1:])


def build_zone_files(conn: sqlite3.Connection, stage: Path, serial: int | None = None) -> list[ZoneFile]:
    cfg = settings(conn)
    domain = normalize_domain(cfg.get("internal_domain", DEFAULT_DOMAIN))
    default_ttl = validate_ttl(cfg.get("default_ttl", 300))
    zone_serial = serial or next_serial(conn)
    enabled = list(conn.execute("SELECT * FROM local_dns_records WHERE enabled=1 ORDER BY fqdn, record_type, value"))
    forward: dict[str, list[sqlite3.Row]] = {domain: []}
    for row in enabled:
        if row["record_type"] in {"A", "AAAA", "CNAME"}:
            zone = forward_zone_for_fqdn(row["fqdn"], domain)
            forward.setdefault(zone, []).append(row)
    zones = [ZoneFile(zone, stage / "local" / f"{zone}.zone", render_zone(zone, rows, zone_serial, default_ttl)) for zone, rows in sorted(forward.items())]
    reverse: dict[str, list[sqlite3.Row]] = {}
    for row in enabled:
        if row["record_type"] == "PTR":
            zone = ".".join(row["fqdn"].split(".")[1:])
            reverse.setdefault(zone, []).append(row)
    for zone, rows in sorted(reverse.items()):
        zones.append(ZoneFile(zone, stage / "local" / f"{zone}.zone", render_zone(zone, rows, zone_serial, default_ttl)))
    return zones


def render_include(zones: list[ZoneFile]) -> str:
    lines = ["// Managed by Alderpoint DNS Local DNS. Do not edit by hand.", ""]
    for zone in zones:
        final_path = LOCAL_ZONE_DIR / zone.path.name
        lines.extend(
            [
                f'zone "{zone.zone}" {{',
                "\ttype primary;",
                f'\tfile "{final_path}";',
                '\tallow-query { "alderpointdns_clients"; localhost; };',
                "\tallow-transfer { none; };",
                "};",
                "",
            ]
        )
    return "\n".join(lines)


def flush_dnsdist_packet_cache(zones: list[ZoneFile]) -> str:
    output = ""
    for zone in zones:
        command = f'pc:expungeByName("{zone.zone}.", DNSQType.ANY, true)'
        try:
            proc = run(["dnsdist", "-C", "/etc/dnsdist/dnsdist.conf", "-c", "-e", command], check=False)
            output += proc.stdout
            if proc.returncode != 0:
                output += f"dnsdist cache flush failed for {zone.zone}: {proc.stdout}\n"
        except Exception as exc:
            output += f"dnsdist cache flush unavailable for {zone.zone}: {exc}\n"
    return output


def ensure_named_include() -> None:
    include_line = f'include "{LOCAL_ZONES_CONF}";'
    current = NAMED_LOCAL_CONF.read_text() if NAMED_LOCAL_CONF.exists() else ""
    if include_line in current:
        return
    backup = BACKUP_DIR / f"named.conf.local.pre-localdns.{int(time.time())}"
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if NAMED_LOCAL_CONF.exists():
        shutil.copy2(NAMED_LOCAL_CONF, backup)
    text = current.rstrip() + "\n\n" + include_line + "\n"
    NAMED_LOCAL_CONF.write_text(text)


def deploy_zones(conn: sqlite3.Connection | None = None) -> int:
    close = conn is None
    db = conn or connect()
    init_db(db)
    started = now()
    cursor = db.execute("INSERT INTO local_dns_deployments(started_at, status, message) VALUES (?, 'running', '')", (started,))
    deployment_id = cursor.lastrowid
    db.commit()
    stage = Path(tempfile.mkdtemp(prefix="alderpointdns-localdns-", dir=str(STAGING_DIR)))
    backup = BACKUP_DIR / f"localdns.last-good.{int(time.time())}.{deployment_id}"
    status = "failed"
    message = ""
    validation_output = ""
    serial = next_serial(db)
    reverse_count = 0
    installed = False
    try:
        zones = build_zone_files(db, stage, serial)
        reverse_count = max(0, len(zones) - 1)
        for zone in zones:
            zone.path.parent.mkdir(parents=True, exist_ok=True)
            zone.path.write_text(zone.text)
            proc = run(["named-checkzone", zone.zone, str(zone.path)])
            validation_output += proc.stdout
        include_path = stage / "local-zones.conf"
        include_path.write_text(render_include(zones))
        if os.environ.get("ALDERPOINTDNS_TEST_INVALID_LOCAL_ZONE") == "1":
            zones[0].path.write_text(zones[0].path.read_text() + "invalid zone record\n")
            run(["named-checkzone", zones[0].zone, str(zones[0].path)])
        if LOCAL_ZONE_DIR.exists() or LOCAL_ZONES_CONF.exists():
            backup.mkdir(parents=True, exist_ok=True)
            if LOCAL_ZONE_DIR.exists():
                shutil.copytree(LOCAL_ZONE_DIR, backup / "local", dirs_exist_ok=True)
            if LOCAL_ZONES_CONF.exists():
                shutil.copy2(LOCAL_ZONES_CONF, backup / "local-zones.conf")
        if NAMED_LOCAL_CONF.exists():
            backup.mkdir(parents=True, exist_ok=True)
            shutil.copy2(NAMED_LOCAL_CONF, backup / "named.conf.local")
        LOCAL_ZONE_DIR.mkdir(parents=True, exist_ok=True)
        for old in LOCAL_ZONE_DIR.glob("*.zone"):
            old.unlink()
        for zone in zones:
            os.replace(zone.path, LOCAL_ZONE_DIR / zone.path.name)
        os.replace(include_path, LOCAL_ZONES_CONF)
        installed = True
        ensure_named_include()
        validation_output += run(["named-checkconf", "-p", "/etc/bind/named.conf"]).stdout
        run(["rndc", "reconfig"])
        for zone in zones:
            run(["rndc", "reload", zone.zone], check=False)
        validation_output += flush_dnsdist_packet_cache(zones)
        validate_dns_results(db)
        status = "deployed"
        message = f"deployed {len(zones)} local DNS zones"
    except Exception as exc:
        message = str(exc)
        if installed and backup.exists():
            try:
                if (backup / "local").exists():
                    if LOCAL_ZONE_DIR.exists():
                        shutil.rmtree(LOCAL_ZONE_DIR)
                    shutil.copytree(backup / "local", LOCAL_ZONE_DIR)
                if (backup / "local-zones.conf").exists():
                    shutil.copy2(backup / "local-zones.conf", LOCAL_ZONES_CONF)
                elif LOCAL_ZONES_CONF.exists():
                    LOCAL_ZONES_CONF.unlink()
                if (backup / "named.conf.local").exists():
                    shutil.copy2(backup / "named.conf.local", NAMED_LOCAL_CONF)
                if not (backup / "local").exists() and LOCAL_ZONE_DIR.exists():
                    shutil.rmtree(LOCAL_ZONE_DIR)
                run(["rndc", "reconfig"], check=False)
                status = "rolled_back"
            except Exception as rollback_exc:
                status = "rollback_failed"
                message = f"{message}; rollback failed: {rollback_exc}"
        raise
    finally:
        db.execute(
            """
            UPDATE local_dns_deployments
            SET finished_at=?, status=?, forward_zone=?, reverse_zones=?, serial=?, message=?, validation_output=?
            WHERE id=?
            """,
            (now(), status, settings(db).get("internal_domain", DEFAULT_DOMAIN), reverse_count, serial, message, validation_output[-4000:], deployment_id),
        )
        db.commit()
        shutil.rmtree(stage, ignore_errors=True)
        if close:
            db.close()
    return deployment_id


def dig_contains(command: list[str], expected: str, attempts: int = 5) -> bool:
    expected_lower = expected.rstrip(".").lower()
    for attempt in range(attempts):
        proc = run(command, check=False)
        output = proc.stdout.rstrip(".\n").lower()
        if proc.returncode == 0 and expected_lower in output:
            return True
        if attempt + 1 < attempts:
            time.sleep(0.35)
    return False


def validate_dns_results(conn: sqlite3.Connection) -> None:
    rows = list(conn.execute("SELECT * FROM local_dns_records WHERE enabled=1 AND record_type IN ('A','AAAA') ORDER BY id LIMIT 20"))
    for row in rows:
        if not dig_contains(["dig", "@127.0.0.1", "-p", "5353", row["fqdn"], row["record_type"], "+short", "+time=2", "+tries=1"], row["value"]):
            raise RuntimeError(f"forward lookup failed for {row['fqdn']}")
        ptr = conn.execute("SELECT fqdn FROM local_dns_records WHERE id=?", (row["ptr_record_id"],)).fetchone() if row["ptr_record_id"] else None
        if ptr:
            if not dig_contains(["dig", "@127.0.0.1", "-p", "5353", "-x", row["value"], "+short", "+time=2", "+tries=1"], row["fqdn"]):
                raise RuntimeError(f"reverse lookup failed for {row['value']}")


def csv_export() -> str:
    with connect() as conn:
        init_db(conn)
        out = StringIO()
        writer = csv.writer(out)
        writer.writerow(["fqdn", "record_type", "value", "ttl", "enabled", "comment"])
        for row in conn.execute("SELECT fqdn, record_type, value, ttl, enabled, comment FROM local_dns_records ORDER BY fqdn"):
            writer.writerow([row["fqdn"], row["record_type"], row["value"], row["ttl"], row["enabled"], row["comment"]])
        return out.getvalue()


def csv_preview(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(StringIO(text))
    preview: list[dict[str, Any]] = []
    with connect() as conn:
        init_db(conn)
        for line, row in enumerate(reader, 2):
            item = {"line": line, "record": row, "valid": True, "warnings": [], "error": ""}
            try:
                rtype, fqdn, value, ttl = validate_record(row.get("record_type", ""), row.get("fqdn", ""), row.get("value", ""), row.get("ttl", 300))
                item["warnings"] = record_warnings(conn, fqdn, rtype, value)
                item["record"] = {"fqdn": fqdn, "record_type": rtype, "value": value, "ttl": ttl, "enabled": row.get("enabled", "1"), "comment": row.get("comment", "")}
            except Exception as exc:
                item["valid"] = False
                item["error"] = str(exc)
            preview.append(item)
    return preview


def csv_import(text: str, override: bool = False) -> int:
    preview = csv_preview(text)
    if any(not row["valid"] for row in preview):
        raise LocalDNSError("CSV contains validation errors")
    count = 0
    for item in preview:
        record = item["record"]
        add_record(record["record_type"], record["fqdn"], record["value"], record["ttl"], record.get("comment", ""), str(record.get("enabled", "1")) != "0", override)
        count += 1
    return count


def hosts_preview(text: str, domain: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    local_domain = normalize_domain(domain)
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        item = {"line": line_number, "valid": True, "records": [], "error": ""}
        try:
            ip = ipaddress.ip_address(parts[0])
            for host in parts[1:]:
                fqdn = normalize_fqdn(host, local_domain)
                rtype = "A" if isinstance(ip, ipaddress.IPv4Address) else "AAAA"
                item["records"].append({"fqdn": fqdn, "record_type": rtype, "value": str(ip), "ttl": 300})
        except Exception as exc:
            item["valid"] = False
            item["error"] = str(exc)
        results.append(item)
    return results
