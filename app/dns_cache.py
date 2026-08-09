#!/usr/bin/env python3
"""BIND recursive-cache tuning, flush operations, and stats for Alderpoint DNS.

BIND already provides recursive caching; this module exposes and manages the
existing cache instead of adding a second one. dnsdist's separate packet
cache (packaging/dnsdist.conf) is intentionally left alone here: it is safe
today only because Alderpoint DNS v1 applies one global RPZ policy to every
client. It must be revisited (disabled or re-keyed) before any per-client or
per-network policy is ever enforced at runtime, since its cache key does not
vary by client/policy and could otherwise leak one client's filtered answer
to another.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

from app.service_logs import sanitize as _sanitize_secrets

DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
COMPILED_DIR = Path("/var/lib/alderpointdns/compiled/bind")


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
CACHE_OPTIONS_CONF = COMPILED_DIR / "cache-options.conf"
NAMED_OPTIONS_CONF = Path("/etc/bind/named.conf.options")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
STATS_URL = "http://127.0.0.1:8053/json/v1/server"

# Well above dnsdist's configured 5s TCP / 2s UDP upstream timeouts, so a
# real slow query is never mistaken for a config error while we still catch
# genuinely broken staged config during validation.
FUNCTIONAL_TEST_TIMEOUT = 5


class DNSCacheError(ValueError):
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


def detect_total_memory_mb() -> int:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return max(1, int(line.split()[1]) // 1024)
    except (OSError, ValueError):
        pass
    return 2048


def detect_default_cache_size_mb() -> int:
    # Conservative: roughly an eighth of total RAM, bounded to [64, 512]MB, so
    # BIND's cache can never quietly balloon to consume most of a small
    # appliance VM's memory alongside dnsdist/the web app/analytics/SQLite.
    total_mb = detect_total_memory_mb()
    return max(64, min(512, total_mb // 8))


DEFAULTS = {
    "max_cache_size_mb": None,  # resolved per-VM by detect_default_cache_size_mb()
    "min_cache_ttl": "0",
    "max_cache_ttl": "604800",  # BIND's own built-in default (1 week); not an override
    "min_ncache_ttl": "0",
    "max_ncache_ttl": "10800",  # BIND's own built-in default (3 hours); not an override
    "prefetch_enabled": "0",
    "prefetch_trigger": "2",
    "prefetch_eligible": "10",
    "serve_stale_enabled": "0",
    "max_stale_ttl": "86400",
    "stale_answer_client_timeout": "off",
    "recursive_clients": "1000",
}


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        if close:
            db.execute("PRAGMA journal_mode=WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS dns_cache_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dns_cache_deployments (
                id INTEGER PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                validation_output TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS dns_cache_flushes (
                id INTEGER PRIMARY KEY,
                requested_at TEXT NOT NULL,
                finished_at TEXT,
                scope TEXT NOT NULL CHECK(scope IN ('all', 'name', 'tree')),
                target TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                message TEXT NOT NULL DEFAULT ''
            );
            """
        )
        defaults = dict(DEFAULTS)
        defaults["max_cache_size_mb"] = str(detect_default_cache_size_mb())
        db.executemany(
            "INSERT OR IGNORE INTO dns_cache_settings(key, value) VALUES (?, ?)",
            list(defaults.items()),
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
        return {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM dns_cache_settings")}
    finally:
        if close:
            db.close()


def _validate_int(name: str, value: Any, min_v: int, max_v: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise DNSCacheError(f"{name} must be an integer") from None
    if not (min_v <= parsed <= max_v):
        raise DNSCacheError(f"{name} must be between {min_v} and {max_v}")
    return parsed


def validate_settings(values: dict[str, Any]) -> dict[str, str]:
    total_mb = detect_total_memory_mb()
    # Never let the admin configure a cache larger than 3/4 of total VM RAM;
    # that is a footgun, not a legitimate tuning choice, on an appliance also
    # running dnsdist, the web app, analytics, and SQLite.
    max_size_ceiling = max(64, (total_mb * 3) // 4)
    out: dict[str, str] = {}
    out["max_cache_size_mb"] = str(_validate_int("max_cache_size_mb", values.get("max_cache_size_mb"), 16, max_size_ceiling))
    out["min_cache_ttl"] = str(_validate_int("min_cache_ttl", values.get("min_cache_ttl"), 0, 86400))
    out["max_cache_ttl"] = str(_validate_int("max_cache_ttl", values.get("max_cache_ttl"), 0, 2_592_000))
    if int(out["min_cache_ttl"]) > int(out["max_cache_ttl"]):
        raise DNSCacheError("min_cache_ttl must not exceed max_cache_ttl")
    out["min_ncache_ttl"] = str(_validate_int("min_ncache_ttl", values.get("min_ncache_ttl"), 0, 86400))
    out["max_ncache_ttl"] = str(_validate_int("max_ncache_ttl", values.get("max_ncache_ttl"), 0, 604_800))
    if int(out["min_ncache_ttl"]) > int(out["max_ncache_ttl"]):
        raise DNSCacheError("min_ncache_ttl must not exceed max_ncache_ttl")
    prefetch_enabled = str(values.get("prefetch_enabled", "0")) in {"1", "true", "on", "yes"}
    out["prefetch_enabled"] = "1" if prefetch_enabled else "0"
    out["prefetch_trigger"] = str(_validate_int("prefetch_trigger", values.get("prefetch_trigger", 2), 1, 3600))
    out["prefetch_eligible"] = str(_validate_int("prefetch_eligible", values.get("prefetch_eligible", 10), int(out["prefetch_trigger"]), 86400))
    serve_stale_enabled = str(values.get("serve_stale_enabled", "0")) in {"1", "true", "on", "yes"}
    out["serve_stale_enabled"] = "1" if serve_stale_enabled else "0"
    out["max_stale_ttl"] = str(_validate_int("max_stale_ttl", values.get("max_stale_ttl", 86400), 60, 604_800))
    timeout_raw = str(values.get("stale_answer_client_timeout", "off")).strip().lower()
    if timeout_raw in {"off", ""}:
        out["stale_answer_client_timeout"] = "off"
    else:
        out["stale_answer_client_timeout"] = str(_validate_int("stale_answer_client_timeout", timeout_raw, 0, 60_000))
    out["recursive_clients"] = str(_validate_int("recursive_clients", values.get("recursive_clients", 1000), 100, 100_000))
    return out


def update_settings(values: dict[str, Any]) -> None:
    validated = validate_settings(values)
    with connect() as conn:
        init_db(conn)
        for key, value in validated.items():
            conn.execute(
                "INSERT INTO dns_cache_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )


def render_cache_options(cfg: dict[str, str]) -> str:
    lines = [
        "// Managed by Alderpoint DNS. Generated cache tuning options; do not edit by hand.",
        f"max-cache-size {int(cfg['max_cache_size_mb'])}m;",
        f"min-cache-ttl {int(cfg['min_cache_ttl'])};",
        f"max-cache-ttl {int(cfg['max_cache_ttl'])};",
        f"min-ncache-ttl {int(cfg['min_ncache_ttl'])};",
        f"max-ncache-ttl {int(cfg['max_ncache_ttl'])};",
        f"recursive-clients {int(cfg.get('recursive_clients', DEFAULTS['recursive_clients']))};",
    ]
    if cfg.get("prefetch_enabled") == "1":
        lines.append(f"prefetch {int(cfg['prefetch_trigger'])} {int(cfg['prefetch_eligible'])};")
    else:
        # A trigger of 0 explicitly disables prefetching in BIND.
        lines.append("prefetch 0;")
    if cfg.get("serve_stale_enabled") == "1":
        lines.append("stale-answer-enable yes;")
        lines.append(f"max-stale-ttl {int(cfg['max_stale_ttl'])};")
        lines.append(f"stale-answer-client-timeout {cfg.get('stale_answer_client_timeout', 'off')};")
    else:
        lines.append("stale-answer-enable no;")
    return "\n".join(lines) + "\n"


def ensure_named_options_include() -> bool:
    """Idempotently make named.conf.options include the generated cache file.

    Returns True if a change was made (so the caller knows a backup exists).
    """
    include_line = f'\tinclude "{CACHE_OPTIONS_CONF}";'
    current = NAMED_OPTIONS_CONF.read_text() if NAMED_OPTIONS_CONF.exists() else ""
    if str(CACHE_OPTIONS_CONF) in current:
        return False
    if "options {" not in current:
        raise DNSCacheError("named.conf.options is missing an options block")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup = BACKUP_DIR / f"named.conf.options.pre-cache.{int(time.time())}"
    if NAMED_OPTIONS_CONF.exists():
        shutil.copy2(NAMED_OPTIONS_CONF, backup)
    marker = "options {"
    idx = current.index(marker) + len(marker)
    new_text = current[:idx] + "\n" + include_line + "\n" + current[idx:]
    NAMED_OPTIONS_CONF.write_text(new_text)
    return True


def dig(domain: str) -> subprocess.CompletedProcess[str]:
    return run(["dig", "@127.0.0.1", "-p", "5353", domain, "A", "+time=3", "+tries=1"], check=False)


def resolves(domain: str) -> bool:
    result = dig(domain)
    return result.returncode == 0 and "status: NOERROR" in result.stdout and "\tA\t" in result.stdout


def deploy_cache_options(conn: sqlite3.Connection | None = None) -> int:
    """Stage, validate, backup, atomically activate, health-check, and
    roll back on failure the generated BIND cache-tuning options."""
    close = conn is None
    db = conn or connect()
    init_db(db)
    started = now()
    cursor = db.execute("INSERT INTO dns_cache_deployments(started_at, status, message) VALUES (?, 'running', '')", (started,))
    deployment_id = cursor.lastrowid
    db.commit()
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="alderpointdns-cache-", dir=str(STAGING_DIR)))
    options_backup = BACKUP_DIR / f"cache-options.conf.last-good.{int(time.time())}"
    status = "failed"
    message = ""
    validation_output = ""
    installed = False
    added_include = False
    try:
        cfg = settings(db)
        content = render_cache_options(cfg)
        staged = stage / "cache-options.conf"
        staged.write_text(content)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        COMPILED_DIR.mkdir(parents=True, exist_ok=True)
        if CACHE_OPTIONS_CONF.exists():
            shutil.copy2(CACHE_OPTIONS_CONF, options_backup)
        os.replace(staged, CACHE_OPTIONS_CONF)
        installed = True
        added_include = ensure_named_options_include()
        proc = run(["named-checkconf", "-p", "/etc/bind/named.conf"])
        validation_output += proc.stdout
        run(["rndc", "reconfig"])
        if not resolves("cloudflare.com"):
            raise RuntimeError("post-deploy ordinary resolution failed after cache options reload")
        status = "deployed"
        message = f"max-cache-size={cfg['max_cache_size_mb']}m prefetch={cfg['prefetch_enabled']} serve-stale={cfg['serve_stale_enabled']}"
    except Exception as exc:
        message = str(exc)
        if installed:
            try:
                if options_backup.exists():
                    shutil.copy2(options_backup, CACHE_OPTIONS_CONF)
                elif CACHE_OPTIONS_CONF.exists():
                    CACHE_OPTIONS_CONF.unlink()
                run(["rndc", "reconfig"], check=False)
                status = "rolled_back"
            except Exception as rollback_exc:
                status = "rollback_failed"
                message = f"{message}; rollback failed: {rollback_exc}"
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
            "UPDATE dns_cache_deployments SET finished_at=?, status=?, message=?, validation_output=? WHERE id=?",
            (now(), status, _sanitize_secrets(message), _sanitize_secrets(validation_output)[-4000:], deployment_id),
        )
        db.commit()
        shutil.rmtree(stage, ignore_errors=True)
        if close:
            db.close()
    return deployment_id


VALID_FLUSH_SCOPES = {"all", "name", "tree"}


def request_flush(scope: str, target: str | None = None) -> int:
    if scope not in VALID_FLUSH_SCOPES:
        raise DNSCacheError(f"unknown flush scope {scope!r}")
    if scope in {"name", "tree"}:
        if not target or not target.strip():
            raise DNSCacheError(f"flush scope {scope!r} requires a target name")
        target = target.strip().rstrip(".").lower()
        if not all(part and len(part) <= 63 for part in target.split(".")):
            raise DNSCacheError("invalid target name")
    with connect() as conn:
        init_db(conn)
        cursor = conn.execute(
            "INSERT INTO dns_cache_flushes(requested_at, scope, target, status) VALUES (?, ?, ?, 'pending')",
            (now(), scope, target),
        )
        conn.commit()
        return cursor.lastrowid


def process_pending_flush(conn: sqlite3.Connection | None = None) -> int | None:
    """Executed by the privileged compiler process: applies the most
    recently requested pending flush and records its result."""
    close = conn is None
    db = conn or connect()
    init_db(db)
    try:
        row = db.execute("SELECT * FROM dns_cache_flushes WHERE status='pending' ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        scope, target = row["scope"], row["target"]
        status = "failed"
        message = ""
        try:
            if scope == "all":
                run(["rndc", "flush"])
                message = "flushed entire cache"
            elif scope == "name":
                run(["rndc", "flushname", target])
                message = f"flushed name {target}"
            elif scope == "tree":
                run(["rndc", "flushtree", target])
                message = f"flushed subtree {target}"
            status = "completed"
        except Exception as exc:
            message = str(exc)
        db.execute(
            "UPDATE dns_cache_flushes SET status=?, message=?, finished_at=? WHERE id=?",
            (status, message, now(), row["id"]),
        )
        # Any older pending rows (should not normally happen; only the
        # newest is ever processed) are marked skipped rather than left
        # dangling in 'pending' forever.
        db.execute(
            "UPDATE dns_cache_flushes SET status='skipped', finished_at=? WHERE status='pending' AND id!=?",
            (now(), row["id"]),
        )
        db.commit()
        return row["id"]
    finally:
        if close:
            db.close()


def bind_server_stats() -> dict[str, Any]:
    request = urllib.request.Request(STATS_URL)
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.loads(response.read().decode())


def cache_stats() -> dict[str, Any]:
    try:
        raw = bind_server_stats()
    except Exception as exc:
        return {"available": False, "error": str(exc)}
    view = (raw.get("views") or {}).get("_default") or {}
    resolver = view.get("resolver") or {}
    stats = resolver.get("cachestats") or {}
    hits = int(stats.get("CacheHits", 0))
    misses = int(stats.get("CacheMisses", 0))
    total = hits + misses
    hit_percent = (hits / total * 100) if total else 0.0
    memory_bytes = int(stats.get("TreeMemInUse", 0)) + int(stats.get("HeapMemInUse", 0))
    return {
        "available": True,
        "hits": hits,
        "misses": misses,
        "hit_percent": hit_percent,
        "nodes": int(stats.get("CacheNodes", 0)),
        "memory_bytes": memory_bytes,
        "evicted_lru": int(stats.get("DeleteLRU", 0)),
        "expired_ttl": int(stats.get("DeleteTTL", 0)),
        "raw": dict(stats),
    }


def last_deployment(conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT * FROM dns_cache_deployments ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:
        if close:
            db.close()


def recent_flushes(conn: sqlite3.Connection | None = None, limit: int = 10) -> list[dict[str, Any]]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        rows = db.execute("SELECT * FROM dns_cache_flushes ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]
    finally:
        if close:
            db.close()
