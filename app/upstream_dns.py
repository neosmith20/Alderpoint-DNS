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
# How long/often deploy_upstreams()'s post-deploy functional check retries
# a freshly-flushed resolution before giving up -- module-level so tests can
# shrink them instead of paying the real wall-clock wait for a deliberately
# failing case.
POST_DEPLOY_CHECK_TIMEOUT_SECONDS = 5.0
POST_DEPLOY_CHECK_RETRY_INTERVAL_SECONDS = 0.5
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


def display_resolvers(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    rows = resolvers(conn)
    for row in rows:
        if not row["enabled"]:
            row["display_status"] = "disabled"
            row["display_message"] = "Disabled"
            row["display_latency_ms"] = None
        else:
            row["display_status"] = row.get("last_status", "unknown")
            row["display_message"] = row.get("last_message", "")
            row["display_latency_ms"] = row.get("last_latency_ms")
    return rows


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


LAST_ENABLED_MESSAGE = "at least one upstream resolver must be enabled"


def _would_leave_zero_enabled(conn: sqlite3.Connection, resolver_id: int, *, disabling: bool, deleting: bool = False) -> bool:
    """True if disabling/deleting `resolver_id` right now would leave no
    enabled resolver anywhere in the table.

    This exists so every mutating entry point (set_enabled, delete_resolver,
    update_resolver) can refuse to *commit* a zero-enabled desired state in
    the first place, rather than writing it and relying on
    deploy_upstreams() to reject it after the fact. That after-the-fact
    check is still correct as a last line of defense (a scoped deploy could
    still be triggered some other way), but by itself it left a window --
    found during v1.0.1 RC live acceptance -- where set_enabled(False) had
    already committed the all-disabled row before deploy_upstreams() ever
    ran, so a *rejected* deploy still left the desired-state DB permanently
    at zero enabled resolvers (a state no later deploy of any kind could
    ever succeed from without first re-enabling something by hand)."""
    if not disabling:
        return False
    others_enabled = conn.execute(
        "SELECT count(*) FROM upstream_resolvers WHERE id != ? AND enabled=1", (resolver_id,)
    ).fetchone()[0]
    return others_enabled == 0


def update_resolver(resolver_id: int, values: dict[str, Any]) -> None:
    data = validate_resolver(values, require_enabled_set=True)
    with connect() as conn:
        init_db(conn)
        if not conn.execute("SELECT 1 FROM upstream_resolvers WHERE id=?", (resolver_id,)).fetchone():
            raise UpstreamDNSError("resolver not found")
        disabling = not bool(int(data["enabled"]))
        if _would_leave_zero_enabled(conn, resolver_id, disabling=disabling):
            raise UpstreamDNSError(LAST_ENABLED_MESSAGE)
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
        row = conn.execute("SELECT enabled FROM upstream_resolvers WHERE id=?", (resolver_id,)).fetchone()
        if row is not None and _would_leave_zero_enabled(conn, resolver_id, disabling=bool(row["enabled"]), deleting=True):
            raise UpstreamDNSError(LAST_ENABLED_MESSAGE)
        conn.execute("DELETE FROM upstream_resolvers WHERE id=?", (resolver_id,))
        renumber(conn)
        conn.commit()


def set_enabled(resolver_id: int, enabled: bool) -> None:
    with connect() as conn:
        init_db(conn)
        if _would_leave_zero_enabled(conn, resolver_id, disabling=not enabled):
            raise UpstreamDNSError(LAST_ENABLED_MESSAGE)
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
    override = str(row.get("_dnsdist_address") or "").strip()
    if override:
        host = override
    else:
        host = row["address"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{int(row['port'])}"


def _bootstrap_ips(row: dict[str, Any]) -> list[str]:
    bootstrap = [ip.strip() for ip in str(row.get("bootstrap_ips") or "").split(",") if ip.strip()]
    return bootstrap


def _resolve_backend_address(row: dict[str, Any]) -> str:
    """Return the literal backend IP dnsdist should connect to.

    dnsdist 1.9's `newServer(address=...)` is an ip:port endpoint, while
    `subjectName` supplies TLS SNI and the DoH HTTP Host. For hostname-based
    DoH/DoT resolvers, Alderpoint's bootstrap IPs are DNS resolvers used to
    resolve that hostname, not the encrypted backend endpoint itself.
    """
    address = str(row["address"])
    if row["protocol"] not in {"dot", "doh"} or _host_is_ip(address):
        return address

    bootstrap = _bootstrap_ips(row)
    if not bootstrap:
        raise UpstreamDNSError(f"{row['protocol'].upper()} resolver hostname requires at least one bootstrap IP")

    errors: list[str] = []
    for qtype in ("A", "AAAA"):
        for resolver in bootstrap:
            result = run(["dig", f"@{resolver}", address, qtype, "+short", "+time=3", "+tries=1"], check=False)
            if result.returncode != 0:
                errors.append(f"{resolver} {qtype}: dig exited {result.returncode}")
                continue
            for raw in result.stdout.splitlines():
                candidate = raw.strip().split()[0] if raw.strip() else ""
                try:
                    return str(ipaddress.ip_address(candidate))
                except ValueError:
                    continue
    detail = "; ".join(errors[:4]) if errors else "no A or AAAA address returned"
    raise UpstreamDNSError(f"bootstrap resolution failed for {address}: {detail}")


def prepare_dnsdist_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    prepared: list[dict[str, Any]] = []
    for row in rows:
        copy = dict(row)
        copy["_dnsdist_address"] = _resolve_backend_address(copy)
        prepared.append(copy)
    return prepared


def prepare_dnsdist_rows_partial(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[tuple[dict[str, Any], str]]]:
    prepared: list[dict[str, Any]] = []
    failures: list[tuple[dict[str, Any], str]] = []
    for row in rows:
        try:
            prepared.extend(prepare_dnsdist_rows([row]))
        except UpstreamDNSError as exc:
            failures.append((row, str(exc)))
    return prepared, failures


def _new_server_statement(row: dict[str, Any]) -> str:
    """Renders exactly one `newServer({...})` Lua statement for a single
    enabled resolver row. Shared by render_dnsdist_upstreams() (the static
    file dnsdist loads at startup/restart) and the live console
    reconciliation path (_console_reconcile()) so a resolver is defined
    identically regardless of which activation mechanism applies it."""
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
    return "newServer({" + ", ".join(opts) + "})"


def render_dnsdist_upstreams(rows: list[dict[str, Any]]) -> str:
    lines = [
        "-- Managed by Alderpoint DNS. Generated upstream forwarder; do not edit by hand.",
        "alderpointdnsUpstreamsEnabled = true",
        f'addLocal("{LOOPBACK_FORWARDER}:{LOOPBACK_FORWARDER_PORT}", {{reusePort=true}})',
        'setPoolServerPolicy(firstAvailable, "alderpointdns_upstreams")',
    ]
    for row in rows:
        lines.append(_new_server_statement(row))
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


def _capture_service_diagnostics(unit: str, lines: int = 60) -> str:
    """Best-effort `journalctl -u <unit>` tail, grabbed the moment a deploy
    fails so the actual reason (e.g. why `systemctl restart dnsdist` exited
    non-zero) survives in upstream_deployments.validation_output even when
    nobody can get a shell on the appliance before the journal rotates --
    exactly the gap that stalled triaging a live DoH-only restart failure
    with no local root access. Never raises: a diagnostics probe must never
    itself turn a clean rollback into a second failure."""
    try:
        result = subprocess.run(
            ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "--output=short-iso"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10, check=False,
        )
        return result.stdout
    except Exception:
        return ""


def _parse_backend_metric(value: str) -> float | None:
    value = str(value or "").strip()
    if not value or value == "-":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _backend_snapshots() -> dict[str, dict[str, Any]]:
    """Best-effort per-backend state straight from dnsdist's own
    console (`showServers()`), keyed by the exact "host:port" string
    `_address_for_dnsdist()` renders for each row -- so it can be matched
    directly against the enabled resolver set.

    This exists because the pool-level post-deploy check only proves *some*
    enabled backend is reachable (dnsdist's `firstAvailable` policy skips
    down backends transparently) -- a live incident showed a mixed
    plain+DoH deploy get recorded 'deployed' with *every* enabled row
    blanket-marked `last_status='healthy'`, even though the DoH backend was
    actually down the whole time and only the plain resolver ever answered
    anything. That was truthful about the pool as a whole but not about
    that one resolver, and the UI had no way to show the difference.

    Returns {} if the console can't be reached -- callers must treat that
    as "state unknown", never as "everything is up": marking a row healthy
    on missing data would silently reintroduce the same false-positive.

    dnsdist's Lat column is the backend's forwarded UDP query latency; TCP
    is the forwarded TCP/TLS/HTTPS backend latency. DoT/DoH upstreams use the
    TCP/TLS path, so their per-resolver latency must come from TCP, not from
    a pool-level deployment health-check timer."""
    try:
        result = run(["dnsdist", "-e", "showServers()"], check=False)
    except Exception:
        return {}
    if result.returncode != 0:
        return {}
    states: dict[str, dict[str, Any]] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 14 or not parts[0].isdigit():
            continue
        address, state = parts[2], parts[3]
        try:
            queries = int(parts[8])
        except ValueError:
            queries = 0
        states[address] = {
            "up": state.strip().lower() == "up",
            "queries": queries,
            "lat_ms": _parse_backend_metric(parts[11]),
            "tcp_ms": _parse_backend_metric(parts[12]),
        }
    return states


def _backend_up_states() -> dict[str, bool]:
    return {address: bool(snapshot["up"]) for address, snapshot in _backend_snapshots().items()}


def _latency_for_resolver(row: dict[str, Any], snapshot: dict[str, Any]) -> float | None:
    if row["protocol"] in {"dot", "doh"}:
        return snapshot.get("tcp_ms")
    return snapshot.get("lat_ms") if snapshot.get("lat_ms") is not None else snapshot.get("tcp_ms")


def _live_upstream_pool_snapshot() -> list[dict[str, str]] | None:
    """Every backend currently in dnsdist's live "alderpointdns_upstreams"
    pool, as [{"index": ..., "address": ...}, ...] straight from
    `showServers()` -- or None if the console can't be reached/parsed at
    all. An empty list (as opposed to None) means the console answered but
    the pool has no members, which _console_reconcile() treats as "this
    running process has never had upstream routing wired up" rather than
    attempting to reconcile against nothing -- see its docstring."""
    try:
        result = run(["dnsdist", "-e", "showServers()"], check=False)
    except Exception:
        return None
    if result.returncode != 0:
        return None
    entries: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        if parts[-1] != "alderpointdns_upstreams":
            continue
        entries.append({"index": parts[0], "address": parts[2]})
    return entries


def _console_reconcile(rows: list[dict[str, Any]]) -> bool:
    """Applies `rows` (the enabled resolver set) to the *live* running
    dnsdist by adding/removing backends in the "alderpointdns_upstreams"
    pool over its console -- an officially supported dnsdist runtime
    reconfiguration mechanism (`newServer()`/`rmServer()`, the exact same
    Lua functions the static config file uses at startup) -- instead of
    restarting the whole process.

    Why this exists: dns1's live upstream_deployments history and dnsdist
    journal showed that restarting dnsdist once per ordinary sequential
    upstream UI change was frequent enough to trip systemd's own
    StartLimitBurst crash-loop protection (intentionally left untouched --
    see deploy_upstreams()'s own restart fallback below). Pacing those
    restarts alone (app/webapp.py's _upstream_deploy_coordinator) is not
    enough against dns1's *actual* policy (StartLimitBurst=5 within a 60s
    window): spacing restarts far enough apart to always stay under that
    budget would make a single isolated admin click wait many seconds for
    no functional reason. dnsdist is explicitly designed to have its
    backend set changed at runtime -- it calls itself a "DNS Loadbalancer"
    and ships a console/API for exactly this -- so the right fix is to
    stop needing a restart at all for the common case: ordinary
    add/edit/toggle/move/delete of a managed upstream resolver.

    This unconditionally clears every backend currently in the pool and
    re-adds the full desired set from `rows`, rather than diffing
    field-by-field, because dnsdist's own `showServers()` output truncates
    backend *names* to a fixed display width (not a safe identity key),
    and because a full replace exactly matches what a restart already
    does -- a restart already resets every backend's health-check state
    and query counters on every deploy, so this changes no observable
    semantics other than removing the restart itself. The whole script
    runs as a single console round trip, on the order of milliseconds --
    multiple orders of magnitude faster than a process restart, with no
    frontend socket interruption at all.

    Returns True only if the live pool was confirmed, *after* the fact, to
    exactly match the desired address set -- never merely "the script
    didn't error". Returns False for anything else (console unreachable,
    pool never wired up in this process's lifetime yet, a mid-script
    failure, or a post-check mismatch); the caller must then fall back to
    a full restart, which remains protected by the same rate-limited
    coordinator either way.

    Compatibility: live-verified against both dnsdist builds Alderpoint
    supports -- 1.9.16-0+deb13u1 (the default Debian-archive package this
    project's own `Depends: dnsdist (>= 1.9.0)` targets, and the exact
    version running on the appliance that originally surfaced the
    restart-rate defect this exists to fix) and 2.1.x (the opt-in
    `install-enhanced-dnsdist` build). `showServers()`'s output format and
    every `newServer()`/`rmServer()` option this module emits behave
    identically on both -- see docs/dnsdist.md's "Managed upstream
    resolvers and the dnsdist console" section."""
    snapshot = _live_upstream_pool_snapshot()
    if not snapshot:
        # None (console unreachable) or [] (pool never wired up in this
        # process yet -- e.g. the very first upstream deploy ever on a
        # fresh install) -- either way, only a real restart can establish
        # the DSTPortRule(5355) -> alderpointdns_upstreams routing this
        # relies on; that wiring is only (re-)evaluated at dnsdist startup.
        return False
    statements = [f'rmServer(getServer({entry["index"]}))' for entry in sorted(snapshot, key=lambda e: -int(e["index"]))]
    statements.extend(_new_server_statement(row) for row in rows)
    try:
        result = run(["dnsdist", "-e", "\n".join(statements)], check=False)
    except Exception:
        return False
    if result.returncode != 0:
        return False
    after = _live_upstream_pool_snapshot()
    if after is None:
        return False
    desired_addresses = sorted(_address_for_dnsdist(row) for row in rows)
    live_addresses = sorted(entry["address"] for entry in after)
    return live_addresses == desired_addresses


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
        # Defense in depth only: with the pre-commit guards in set_enabled()/
        # delete_resolver()/update_resolver(), the desired-state DB should
        # never actually reach zero enabled rows via the normal web routes
        # any more -- see _would_leave_zero_enabled(). This still protects
        # any other caller (CLI, backup restore, replication) that mutates
        # the table directly.
        message = LAST_ENABLED_MESSAGE
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
    activation_mode = "restart"
    try:
        dnsdist_rows, render_failures = prepare_dnsdist_rows_partial(rows)
        if not dnsdist_rows:
            detail = render_failures[0][1] if render_failures else "no enabled upstream resolver could be rendered"
            raise UpstreamDNSError(f"no enabled upstream resolver could be rendered: {detail}")
        dnsdist_staged = _write_staged(stage / "upstream-forwarder.conf", render_dnsdist_upstreams(dnsdist_rows))
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
        # Prefer applying the new backend set to the already-running
        # dnsdist over its console (no process restart at all) -- see
        # _console_reconcile()'s docstring for the full rationale. Only
        # fall back to a real restart when that isn't possible (console
        # unreachable, or this process has never had upstream routing
        # wired up yet) or didn't verifiably succeed; either way the
        # static files just staged above are exactly what that restart
        # would load, so the fallback is always correct, just slower.
        if _console_reconcile(dnsdist_rows):
            activation_mode = "console"
        else:
            run(["systemctl", "restart", "dnsdist"])
            activation_mode = "restart"
        run(["rndc", "reconfig"])
        # This check must prove the *newly staged* upstream set can actually
        # resolve, not merely that BIND has some old cached answer for
        # TEST_DOMAIN lying around from before this deploy. A live incident
        # showed exactly that gap: a deploy that left dnsdist's sole
        # backend genuinely unreachable was still recorded 'deployed'
        # because BIND answered this same check from cache, without ever
        # actually asking the new upstream chain anything. `rndc flushname`
        # forces a real cache miss for TEST_DOMAIN immediately before every
        # attempt, so a NOERROR/A answer here can only have come from a
        # live round trip through the config just staged. This still
        # exercises the exact path a LAN client uses (BIND -> loopback
        # forwarder -> dnsdist -> upstream), not a synthetic shortcut, so a
        # forwarding-configuration mistake would be caught too, not just an
        # unreachable backend. A short bounded retry tolerates dnsdist's own
        # backend health check (asynchronous, runs on its own interval)
        # not having completed its very first round yet immediately after
        # restart -- a benign startup race, not evidence the backend is
        # actually down.
        deadline = time.monotonic() + POST_DEPLOY_CHECK_TIMEOUT_SECONDS
        result = None
        while True:
            run(["rndc", "flushname", TEST_DOMAIN])
            result = run(["dig", "@127.0.0.1", "-p", "5353", TEST_DOMAIN, "A", "+time=5", "+tries=1"], check=False)
            if result.returncode == 0 and "status: NOERROR" in result.stdout and "\tA\t" in result.stdout:
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(POST_DEPLOY_CHECK_RETRY_INTERVAL_SECONDS)
        if result.returncode != 0 or "status: NOERROR" not in result.stdout or "\tA\t" not in result.stdout:
            raise RuntimeError(
                "post-deploy upstream resolution failed: none of the currently enabled "
                "upstream resolvers returned a successful answer (checked against a "
                "freshly flushed cache entry, so a stale cached answer could not mask this)"
            )
        ts = now()
        for failed_row, failed_message in render_failures:
            db.execute(
                "UPDATE upstream_resolvers SET last_status='failed', last_message=?, last_checked_at=? WHERE id=?",
                (failed_message[:400], ts, failed_row["id"]),
            )
        backend_states = _backend_snapshots()
        down_count = len(render_failures)
        for row in dnsdist_rows:
            address = _address_for_dnsdist(row)
            # Unknown (console unreachable, or this address not found in
            # showServers() output) is treated as "no claim either way" --
            # never as healthy -- so a probe failure can't manufacture a
            # false-positive the way the blanket update it replaced could.
            snapshot = backend_states.get(address)
            if snapshot is None:
                continue
            if snapshot.get("up") is False:
                down_count += 1
                db.execute(
                    "UPDATE upstream_resolvers SET last_status='failed', last_message=?, last_checked_at=? WHERE id=?",
                    ("dnsdist marked this upstream unreachable; other enabled upstreams are handling traffic", ts, row["id"]),
                )
            elif snapshot.get("up") is True:
                backend_latency_ms = _latency_for_resolver(row, snapshot)
                db.execute(
                    "UPDATE upstream_resolvers SET last_status='healthy', last_message='dnsdist marked this upstream reachable', last_latency_ms=?, last_checked_at=? WHERE id=?",
                    (backend_latency_ms, ts, row["id"]),
                )
            # else: state unknown -- leave the row's last_status untouched
            # rather than guess.
        status = "deployed"
        activation_note = "applied live, no dnsdist restart" if activation_mode == "console" else "applied via dnsdist restart"
        if len(dnsdist_rows) == len(rows):
            message = f"deployed {len(rows)} enabled upstream resolver(s) ({activation_note})"
        else:
            message = f"deployed {len(dnsdist_rows)} of {len(rows)} enabled upstream resolver(s) ({activation_note})"
        if down_count:
            message += f" ({down_count} of them currently unreachable; traffic is being served by the rest)"
    except Exception as exc:
        message = _safe_message(str(exc))
        diagnostics = _capture_service_diagnostics("dnsdist")
        if diagnostics:
            validation_output += "\n\n--- journalctl -u dnsdist (captured at failure, before rollback) ---\n" + diagnostics
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
