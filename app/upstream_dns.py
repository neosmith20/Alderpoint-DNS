#!/usr/bin/env python3
"""Managed upstream DNS resolvers for Alderpoint DNS."""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.service_logs import sanitize as _sanitize_secrets

DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")


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
COMPILED_DIR = Path("/var/lib/alderpointdns/compiled")
BIND_FORWARDERS_CONF = COMPILED_DIR / "bind" / "upstream-forwarders.conf"
DNSDIST_UPSTREAM_CONF = COMPILED_DIR / "dnsdist" / "upstream-forwarder.conf"
NAMED_OPTIONS_CONF = Path("/etc/bind/named.conf.options")
DNSDIST_CONF = Path("/etc/dnsdist/dnsdist.conf")
DNSDIST_PACKAGING_CONF = Path("/opt/alderpointdns/packaging/dnsdist.conf")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
LOOPBACK_FORWARDER = "127.0.0.1"
LOOPBACK_FORWARDER_PORT = 5355
TEST_DOMAIN = "cloudflare.com"
PROTOCOLS = {"plain", "dot", "doh"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class UpstreamDNSError(ValueError):
    pass


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
            CREATE TABLE IF NOT EXISTS upstream_resolvers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL CHECK(protocol IN ('plain', 'dot', 'doh')),
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                doh_path TEXT NOT NULL DEFAULT '',
                tls_hostname TEXT NOT NULL DEFAULT '',
                bootstrap_ips TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                position INTEGER NOT NULL DEFAULT 0,
                last_status TEXT NOT NULL DEFAULT 'unknown',
                last_message TEXT NOT NULL DEFAULT '',
                last_latency_ms REAL,
                last_checked_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS upstream_deployments (
                id INTEGER PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                validation_output TEXT NOT NULL DEFAULT ''
            );
            """
        )
        if not db.execute("SELECT 1 FROM upstream_resolvers LIMIT 1").fetchone():
            seed_from_named_options(db)
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def _host_is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def _normalize_host(value: str) -> str:
    host = value.strip().strip("[]").lower()
    if not host:
        raise UpstreamDNSError("resolver address is required")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UpstreamDNSError("resolver hostname is not valid IDNA") from exc
    if not DOMAIN_RE.match(host):
        raise UpstreamDNSError("resolver hostname is invalid")
    return host


def _normalize_port(value: Any, default: int) -> int:
    try:
        port = int(value or default)
    except (TypeError, ValueError):
        raise UpstreamDNSError("resolver port must be a number") from None
    if port < 1 or port > 65535:
        raise UpstreamDNSError("resolver port must be between 1 and 65535")
    return port


def _normalize_bootstrap(value: str) -> str:
    out: list[str] = []
    for raw in str(value or "").replace("\n", ",").split(","):
        raw = raw.strip()
        if not raw:
            continue
        out.append(str(ipaddress.ip_address(raw)))
    return ", ".join(out)


def _normalize_doh_url(address: str, port: Any, doh_path: str, bootstrap_ips: str, tls_hostname: str) -> dict[str, Any]:
    parsed = urlparse(address.strip())
    if parsed.scheme:
        if parsed.scheme != "https" or not parsed.hostname:
            raise UpstreamDNSError("DoH resolver URL must be an https:// URL")
        if parsed.query or parsed.fragment:
            raise UpstreamDNSError("DoH resolver URL must not include query parameters or fragments")
        host = _normalize_host(parsed.hostname)
        path = parsed.path or "/dns-query"
        parsed_port = parsed.port or 443
        bootstrap = _normalize_bootstrap(bootstrap_ips)
        if not _host_is_ip(host) and not bootstrap:
            raise UpstreamDNSError("DoH resolver hostname requires at least one bootstrap IP")
        return {"address": host, "port": parsed_port, "doh_path": path, "tls_hostname": tls_hostname.strip().lower() or host, "bootstrap_ips": bootstrap}
    host = _normalize_host(address)
    bootstrap = _normalize_bootstrap(bootstrap_ips)
    if not _host_is_ip(host) and not bootstrap:
        raise UpstreamDNSError("DoH resolver hostname requires at least one bootstrap IP")
    return {"address": host, "port": _normalize_port(port, 443), "doh_path": doh_path.strip() or "/dns-query", "tls_hostname": tls_hostname.strip().lower() or host, "bootstrap_ips": bootstrap}


def validate_resolver(values: dict[str, Any], *, require_enabled_set: bool = False) -> dict[str, Any]:
    protocol = str(values.get("protocol", "plain")).strip().lower()
    if protocol not in PROTOCOLS:
        raise UpstreamDNSError("resolver protocol must be plain, dot, or doh")
    name = str(values.get("name") or protocol.upper()).strip()
    if not name:
        raise UpstreamDNSError("friendly name is required")
    enabled = "1" if str(values.get("enabled", "0" if require_enabled_set else "1")).lower() in {"1", "true", "on", "yes"} else "0"
    if protocol == "doh":
        normalized = _normalize_doh_url(str(values.get("address", "")), values.get("port"), str(values.get("doh_path", "")), str(values.get("bootstrap_ips", "")), str(values.get("tls_hostname", "")))
    else:
        default_port = 853 if protocol == "dot" else 53
        normalized = {
            "address": _normalize_host(str(values.get("address", ""))),
            "port": _normalize_port(values.get("port"), default_port),
            "doh_path": "",
            "tls_hostname": str(values.get("tls_hostname", "")).strip().lower(),
            "bootstrap_ips": _normalize_bootstrap(str(values.get("bootstrap_ips", ""))),
        }
        if protocol == "dot" and not normalized["tls_hostname"]:
            normalized["tls_hostname"] = normalized["address"]
    if normalized["doh_path"] and not normalized["doh_path"].startswith("/"):
        raise UpstreamDNSError("DoH path must start with /")
    return {"name": name[:120], "protocol": protocol, "enabled": enabled, **normalized}


def seed_from_named_options(conn: sqlite3.Connection) -> None:
    text = NAMED_OPTIONS_CONF.read_text() if NAMED_OPTIONS_CONF.exists() else ""
    match = re.search(r"forwarders\s*(?:port\s+(\d+)\s*)?\{([^}]*)\};", text, re.S)
    servers = ["1.1.1.2", "1.0.0.2", "4.2.2.1", "4.2.2.2"]
    port = 53
    if match:
        port = int(match.group(1) or 53)
        servers = [token.strip() for token in match.group(2).replace("\n", " ").split(";") if token.strip()]
    ts = now()
    for idx, server in enumerate(servers, start=1):
        try:
            address = _normalize_host(server)
        except UpstreamDNSError:
            continue
        conn.execute(
            """
            INSERT INTO upstream_resolvers(name, protocol, address, port, enabled, position, created_at, updated_at)
            VALUES (?, 'plain', ?, ?, 1, ?, ?, ?)
            """,
            (f"Imported upstream {idx}", address, port, idx, ts, ts),
        )


def resolvers(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    init_db(conn)
    close = conn is None
    db = conn or connect()
    try:
        return [dict(row) for row in db.execute("SELECT * FROM upstream_resolvers ORDER BY position, id")]
    finally:
        if close:
            db.close()


def enabled_resolvers(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    return [row for row in resolvers(conn) if row["enabled"]]


def add_resolver(values: dict[str, Any]) -> int:
    data = validate_resolver(values, require_enabled_set=True)
    with connect() as conn:
        init_db(conn)
        pos = (conn.execute("SELECT coalesce(max(position), 0) + 1 AS pos FROM upstream_resolvers").fetchone()["pos"])
        ts = now()
        cur = conn.execute(
            """
            INSERT INTO upstream_resolvers(name, protocol, address, port, doh_path, tls_hostname, bootstrap_ips, enabled, position, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (data["name"], data["protocol"], data["address"], data["port"], data["doh_path"], data["tls_hostname"], data["bootstrap_ips"], int(data["enabled"]), pos, ts, ts),
        )
        conn.commit()
        return int(cur.lastrowid)


def update_resolver(resolver_id: int, values: dict[str, Any]) -> None:
    data = validate_resolver(values, require_enabled_set=True)
    with connect() as conn:
        init_db(conn)
        if not conn.execute("SELECT 1 FROM upstream_resolvers WHERE id=?", (resolver_id,)).fetchone():
            raise UpstreamDNSError("resolver not found")
        conn.execute(
            """
            UPDATE upstream_resolvers
            SET name=?, protocol=?, address=?, port=?, doh_path=?, tls_hostname=?, bootstrap_ips=?, enabled=?, updated_at=?
            WHERE id=?
            """,
            (data["name"], data["protocol"], data["address"], data["port"], data["doh_path"], data["tls_hostname"], data["bootstrap_ips"], int(data["enabled"]), now(), resolver_id),
        )
        conn.commit()


def delete_resolver(resolver_id: int) -> None:
    with connect() as conn:
        init_db(conn)
        conn.execute("DELETE FROM upstream_resolvers WHERE id=?", (resolver_id,))
        renumber(conn)
        conn.commit()


def set_enabled(resolver_id: int, enabled: bool) -> None:
    with connect() as conn:
        init_db(conn)
        conn.execute("UPDATE upstream_resolvers SET enabled=?, updated_at=? WHERE id=?", (1 if enabled else 0, now(), resolver_id))
        conn.commit()


def move_resolver(resolver_id: int, direction: str) -> None:
    with connect() as conn:
        init_db(conn)
        rows = conn.execute("SELECT id, position FROM upstream_resolvers ORDER BY position, id").fetchall()
        ids = [row["id"] for row in rows]
        if resolver_id not in ids:
            raise UpstreamDNSError("resolver not found")
        idx = ids.index(resolver_id)
        swap = idx - 1 if direction == "up" else idx + 1
        if 0 <= swap < len(ids):
            ids[idx], ids[swap] = ids[swap], ids[idx]
            for pos, rid in enumerate(ids, start=1):
                conn.execute("UPDATE upstream_resolvers SET position=? WHERE id=?", (pos, rid))
        conn.commit()


def renumber(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT id FROM upstream_resolvers ORDER BY position, id").fetchall()
    for pos, row in enumerate(rows, start=1):
        conn.execute("UPDATE upstream_resolvers SET position=? WHERE id=?", (pos, row["id"]))


def _lua_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _address_for_dnsdist(row: dict[str, Any]) -> str:
    bootstrap = [ip.strip() for ip in str(row.get("bootstrap_ips") or "").split(",") if ip.strip()]
    host = bootstrap[0] if row["protocol"] in {"dot", "doh"} and not _host_is_ip(row["address"]) and bootstrap else row["address"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{int(row['port'])}"


def render_dnsdist_upstreams(rows: list[dict[str, Any]]) -> str:
    lines = [
        "-- Managed by Alderpoint DNS. Generated upstream forwarder; do not edit by hand.",
        "alderpointdnsUpstreamsEnabled = true",
        f'addLocal("{LOOPBACK_FORWARDER}:{LOOPBACK_FORWARDER_PORT}", {{reusePort=true}})',
        'setPoolServerPolicy(firstAvailable, "alderpointdns_upstreams")',
    ]
    for row in rows:
        opts = [
            f"address={_lua_quote(_address_for_dnsdist(row))}",
            f"name={_lua_quote('upstream-' + str(row['id']) + '-' + re.sub(r'[^a-zA-Z0-9_-]+', '-', row['name'])[:42])}",
            'pool="alderpointdns_upstreams"',
            "checkName=\"cloudflare.com.\"",
            "checkType=\"A\"",
            "mustResolve=true",
            f"order={int(row['position'])}",
        ]
        if row["protocol"] in {"dot", "doh"}:
            opts.extend(['tls="openssl"', "validateCertificates=true", f"subjectName={_lua_quote(row['tls_hostname'] or row['address'])}"])
        if row["protocol"] == "doh":
            opts.append(f"dohPath={_lua_quote(row['doh_path'] or '/dns-query')}")
        lines.append("newServer({" + ", ".join(opts) + "})")
    return "\n".join(lines) + "\n"


def render_bind_forwarders() -> str:
    return "\n".join(
        [
            "// Managed by Alderpoint DNS. Generated upstream forwarder target; do not edit by hand.",
            f"forwarders port {LOOPBACK_FORWARDER_PORT} {{ {LOOPBACK_FORWARDER}; }};",
            "",
        ]
    )


def ensure_named_forwarders_include() -> None:
    include_line = f'\tinclude "{BIND_FORWARDERS_CONF}";'
    current = NAMED_OPTIONS_CONF.read_text()
    if str(BIND_FORWARDERS_CONF) in current:
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(NAMED_OPTIONS_CONF, BACKUP_DIR / f"named.conf.options.pre-upstream.{int(time.time())}")
    current = re.sub(r"\n\s*forwarders\s*(?:port\s+\d+\s*)?\{[^}]*\};", "", current, flags=re.S)
    marker = "forward only;"
    if marker not in current:
        raise UpstreamDNSError("named.conf.options is missing forward only;")
    current = current.replace(marker, marker + "\n" + include_line, 1)
    NAMED_OPTIONS_CONF.write_text(current)


def ensure_dnsdist_include() -> None:
    include_block = (
        f'alderpointdnsUpstreamsEnabled = false\n'
        f'local alderpointdnsUpstreamConfig = "{DNSDIST_UPSTREAM_CONF}"\n'
        'local alderpointdnsUpstreamFile = io.open(alderpointdnsUpstreamConfig, "r")\n'
        'if alderpointdnsUpstreamFile then\n'
        '  alderpointdnsUpstreamFile:close()\n'
        '  dofile(alderpointdnsUpstreamConfig)\n'
        'end\n'
    )
    current = DNSDIST_CONF.read_text() if DNSDIST_CONF.exists() else DNSDIST_PACKAGING_CONF.read_text()
    if str(DNSDIST_UPSTREAM_CONF) in current:
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if DNSDIST_CONF.exists():
        shutil.copy2(DNSDIST_CONF, BACKUP_DIR / f"dnsdist.conf.pre-upstream.{int(time.time())}")
    marker = "getPool(\"\"):setCache(pc)"
    if marker not in current:
        raise UpstreamDNSError("dnsdist.conf is missing packet-cache pool marker")
    current = current.replace(marker, 'getPool("alderpointdns_bind"):setCache(pc)\n\n' + include_block, 1)
    current = current.replace('newServer({\n  address="127.0.0.1:5354",', 'newServer({\n  address="127.0.0.1:5354",\n  pool="alderpointdns_bind",', 1)
    route_marker = "}), RCodeAction(DNSRCode.REFUSED))"
    route = 'if alderpointdnsUpstreamsEnabled then\n  addAction(DSTPortRule(5355), PoolAction("alderpointdns_upstreams"))\nend\naddAction(AllRule(), PoolAction("alderpointdns_bind"))\n\n'
    if route_marker not in current:
        raise UpstreamDNSError("dnsdist.conf is missing action marker")
    current = current.replace(route_marker, route_marker + "\n\n" + route, 1)
    DNSDIST_CONF.write_text(current)


def _write_staged(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _safe_message(text: str) -> str:
    return re.sub(r"https://([^/?#]+)[^\\s'\"]*", r"https://\\1/...", text)


def deploy_upstreams(conn: sqlite3.Connection | None = None) -> int:
    close = conn is None
    db = conn or connect()
    init_db(db)
    started = now()
    cur = db.execute("INSERT INTO upstream_deployments(started_at, status, message) VALUES (?, 'running', '')", (started,))
    deployment_id = int(cur.lastrowid)
    db.commit()
    rows = enabled_resolvers(db)
    if not rows:
        message = "at least one upstream resolver must be enabled"
        db.execute(
            "UPDATE upstream_deployments SET finished_at=?, status='failed', message=? WHERE id=?",
            (now(), message, deployment_id),
        )
        db.commit()
        if close:
            db.close()
        raise UpstreamDNSError(message)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="alderpointdns-upstreams-", dir=str(STAGING_DIR)))
    backups: list[tuple[Path, Path | None]] = []
    status = "failed"
    message = ""
    validation_output = ""
    try:
        dnsdist_staged = _write_staged(stage / "upstream-forwarder.conf", render_dnsdist_upstreams(rows))
        bind_staged = _write_staged(stage / "upstream-forwarders.conf", render_bind_forwarders())
        for live, staged in ((DNSDIST_UPSTREAM_CONF, dnsdist_staged), (BIND_FORWARDERS_CONF, bind_staged)):
            live.parent.mkdir(parents=True, exist_ok=True)
            backup = BACKUP_DIR / f"{live.name}.last-good.{int(time.time())}" if live.exists() else None
            if backup:
                shutil.copy2(live, backup)
            backups.append((live, backup))
            os.replace(staged, live)
        ensure_dnsdist_include()
        ensure_named_forwarders_include()
        validation_output += run(["dnsdist", "--check-config"]).stdout
        validation_output += run(["named-checkconf", "-p", "/etc/bind/named.conf"]).stdout
        run(["systemctl", "restart", "dnsdist"])
        run(["rndc", "reconfig"])
        start = time.monotonic()
        result = run(["dig", "@127.0.0.1", "-p", "5353", TEST_DOMAIN, "A", "+time=5", "+tries=1"], check=False)
        latency_ms = (time.monotonic() - start) * 1000.0
        if result.returncode != 0 or "status: NOERROR" not in result.stdout or "\tA\t" not in result.stdout:
            raise RuntimeError("post-deploy upstream resolution failed")
        ts = now()
        for row in rows:
            db.execute(
                "UPDATE upstream_resolvers SET last_status='healthy', last_message='resolved through active upstream set', last_latency_ms=?, last_checked_at=? WHERE id=?",
                (latency_ms, ts, row["id"]),
            )
        status = "deployed"
        message = f"deployed {len(rows)} enabled upstream resolver(s)"
    except Exception as exc:
        message = _safe_message(str(exc))
        for live, backup in backups:
            try:
                if backup and backup.exists():
                    shutil.copy2(backup, live)
                elif live.exists():
                    live.unlink()
            except OSError:
                pass
        run(["systemctl", "restart", "dnsdist"], check=False)
        run(["rndc", "reconfig"], check=False)
        status = "rolled_back"
        db.execute("UPDATE upstream_resolvers SET last_status='failed', last_message=?, last_checked_at=? WHERE enabled=1", (message[:400], now()))
        raise
    finally:
        # validation_output includes `named-checkconf -p` output, which
        # echoes the fully rendered BIND config verbatim -- including any
        # `key "name" { ...; secret "..."; };` block (RNDC/TSIG shared
        # secret) -- so this must never reach SQLite (and therefore the UI's
        # deployment history) unredacted. Sanitize the full text before
        # truncating, not after: truncating first could cut a secret in
        # half and leave a partial match the patterns no longer recognize.
        db.execute(
            "UPDATE upstream_deployments SET finished_at=?, status=?, message=?, validation_output=? WHERE id=?",
            (now(), status, _sanitize_secrets(message), _sanitize_secrets(validation_output)[-4000:], deployment_id),
        )
        db.commit()
        shutil.rmtree(stage, ignore_errors=True)
        if close:
            db.close()
    return deployment_id


def last_deployment(conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    init_db(conn)
    close = conn is None
    db = conn or connect()
    try:
        row = db.execute("SELECT * FROM upstream_deployments ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:
        if close:
            db.close()
