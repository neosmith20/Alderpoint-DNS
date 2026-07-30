#!/usr/bin/env python3
"""Alderpoint DNS Backup and Restore.

Builds versioned, checksummed Alderpoint DNS backup archives (tar.gz, optionally
openssl-encrypted) covering Alderpoint DNS-owned configuration, generated BIND/
dnsdist config, the SQLite database (captured through SQLite's own online
backup API so a concurrently-writing web app or analytics collector can never
produce a torn/corrupt copy), downloaded blocklists, and certificate
material. Restores are preview-first (a dry-run diff against live state),
staged, backed up, atomically activated, health-checked, and automatically
rolled back on any failure -- the same shape as app/dns_cache.py and
app/encryption.py.

Component design decision (documented per the task's request to explain the
choice rather than invent partial-SQLite files): Alderpoint DNS's SQLite database
is always captured as a single consistent online-backup copy when
``sqlite_data`` is selected, since splitting a live SQLite file into partial
per-table files is fragile and not something SQLite is designed for.
Instead, component granularity for database content is applied in two
places:

1. At backup time, two components control *stripping* rows out of the
   already-consistent backup copy before it is archived, so the archive
   itself never contains data the operator opted out of:
   - ``analytics_history`` (default off): if unset, ``query_events`` and
     ``analytics_aggregate_buckets`` are deleted from the backup copy and it
     is VACUUMed, so a routine backup does not balloon with detailed query
     history.
   - ``user_auth_data`` (default off): if unset, ``admins`` and
     ``login_attempts`` are deleted from the backup copy, since admin
     password hashes are credential material.
2. At restore time, ``sqlite_data`` gates whether the database is touched at
   all. Within that, tables that map to one of the other named components
   (``sources`` -> blocklist_source_definitions, ``custom_rules`` ->
   custom_rules, ``local_dns_records``/``local_dns_settings`` ->
   local_dns_zones, ``client_aliases`` -> client_aliases, ``admins``/
   ``login_attempts`` -> user_auth_data, ``query_events``/
   ``analytics_aggregate_buckets`` -> analytics_history) are merged
   individually, gated by their own flag, independent of the broad
   ``sqlite_data`` flag. All other tables (dns_cache_settings,
   encryption_settings, deployment history tables, policy/category tables,
   etc.) are gated only by ``sqlite_data``. This means an operator can
   restore just one narrow table (e.g. only ``custom_rules``) without ever
   touching any other table -- important on a shared appliance where other
   Alderpoint DNS subsystems may hold live settings an operator does not intend
   to disturb.

Sensitive material handling: ``/etc/alderpointdns/secrets.env`` (the web
session-signing secret), ``/etc/alderpointdns/dnsdist-api.key``, and
``/etc/alderpointdns/dnsdist-web.creds`` (dnsdist webserver/API credentials) are
all treated as key material -- they grant the same kind of access a stolen
private key would. They are included only when ``private_keys`` or
``user_auth_data`` is explicitly set, never as part of the default
``app_config`` bundle.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
BACKUP_DIR = Path("/var/lib/alderpointdns/backups")
STAGING_DIR = Path("/var/lib/alderpointdns/staging")
IMPORTS_DIR = STAGING_DIR / "backup-imports"

ETC_ALDERPOINTDNS = Path("/etc/alderpointdns")
CERT_DIR = ETC_ALDERPOINTDNS / "certs"
SECRETS_ENV = ETC_ALDERPOINTDNS / "secrets.env"
DNSDIST_API_KEY = ETC_ALDERPOINTDNS / "dnsdist-api.key"
DNSDIST_WEB_CREDS = ETC_ALDERPOINTDNS / "dnsdist-web.creds"

ETC_BIND = Path("/etc/bind")
BIND_CONF_FILES = ("named.conf", "named.conf.local", "named.conf.options")
ETC_DNSDIST = Path("/etc/dnsdist")
DNSDIST_CONF = ETC_DNSDIST / "dnsdist.conf"

COMPILED_DIR = Path("/var/lib/alderpointdns/compiled")
LOCAL_ZONE_DIR = COMPILED_DIR / "bind" / "local"
LOCAL_ZONES_CONF = COMPILED_DIR / "bind" / "local-zones.conf"
DOWNLOADS_DIR = Path("/var/lib/alderpointdns/downloads")

SYSTEMD_DIR = Path("/etc/systemd/system")
SUDOERS_FILE = Path("/etc/sudoers.d/alderpointdns")

APP_ROOT = Path("/opt/alderpointdns")

BACKUP_FORMAT_VERSION = 1
FILENAME_PREFIX = "alderpointdns-backup-"

# Archive-relative path the SQLite database is stored under. Derived from
# DB_PATH so the two can never drift apart.
DB_ARCHIVE_RELPATH = str(DB_PATH.relative_to("/"))

FUNCTIONAL_TEST_TIMEOUT = 5

COMPONENT_KEYS = (
    "app_config",
    "sqlite_data",
    "blocklist_source_definitions",
    "last_downloaded_lists",
    "custom_rules",
    "local_dns_zones",
    "client_aliases",
    "dnsdist_source_config",
    "bind_source_config",
    "certificates",
    "private_keys",
    "user_auth_data",
    "analytics_history",
)

COMPONENT_DEFAULTS = {
    "app_config": True,
    "sqlite_data": True,
    "blocklist_source_definitions": True,
    "last_downloaded_lists": True,
    "custom_rules": True,
    "local_dns_zones": True,
    "client_aliases": True,
    "dnsdist_source_config": True,
    "bind_source_config": True,
    "certificates": True,
    "private_keys": False,
    "user_auth_data": False,
    "analytics_history": False,
}

# Maps a SQLite table name to the single component flag that governs whether
# it is merged on restore. Tables not present here are governed only by the
# broad ``sqlite_data`` flag. See the module docstring for the reasoning.
TABLE_COMPONENT_MAP = {
    "sources": "blocklist_source_definitions",
    "custom_rules": "custom_rules",
    "custom_filter_rules": "custom_rules",
    "local_dns_records": "local_dns_zones",
    "local_dns_settings": "local_dns_zones",
    "client_aliases": "client_aliases",
    "admins": "user_auth_data",
    "login_attempts": "user_auth_data",
    "query_events": "analytics_history",
    "analytics_aggregate_buckets": "analytics_history",
}

# Tables intentionally never touched by restore, even when sqlite_data is
# selected -- backup/restore's own bookkeeping must never be overwritten by
# restoring an older backup's copy of itself.
TABLES_EXCLUDED_FROM_RESTORE = {
    "backup_history",
    "restore_history",
    "backup_requests",
    "backup_settings",
    "sqlite_sequence",
}

SETTINGS_DEFAULTS = {
    "schedule_enabled": "0",
    "schedule_interval_hours": "24",
    "retention_count": "7",
    "default_components": json.dumps(COMPONENT_DEFAULTS),
}

BACKUP_TIMER_OVERRIDE = SYSTEMD_DIR / "alderpointdns-backup.timer.d" / "alderpointdns.conf"


class BackupError(ValueError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def run(command: list[str], check: bool = True, input_text: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, input=input_text, env=env)


def harden_backup_file_permissions(path: Path) -> None:
    try:
        shutil.chown(path, user="root", group="alderpointdns")
    except (LookupError, PermissionError, OSError):
        pass
    os.chmod(path, 0o640)


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        if close:
            db.execute("PRAGMA journal_mode=WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS backup_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS backup_history (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                path TEXT,
                size_bytes INTEGER NOT NULL DEFAULT 0,
                components_json TEXT NOT NULL DEFAULT '{}',
                manifest_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS restore_history (
                id INTEGER PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                backup_path TEXT,
                components_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                pre_restore_backup_path TEXT,
                validation_output TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS backup_requests (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL CHECK(kind IN ('create', 'restore', 'preview')),
                requested_at TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                result_json TEXT NOT NULL DEFAULT '',
                finished_at TEXT
            );
            """
        )
        db.executemany(
            "INSERT OR IGNORE INTO backup_settings(key, value) VALUES (?, ?)",
            list(SETTINGS_DEFAULTS.items()),
        )
        # Always commit here, even when handed an existing connection: this
        # function is idempotent (CREATE TABLE IF NOT EXISTS / INSERT OR
        # IGNORE) and create_backup/restore_backup go on to open additional
        # short-lived connections to the same database file (SQLite's online
        # backup API requires a fresh source connection); leaving an
        # uncommitted implicit transaction open here would otherwise risk a
        # "database is locked" error against those.
        db.commit()
    finally:
        if close:
            db.close()


def settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    init_db(conn)
    close = conn is None
    db = conn or connect()
    try:
        return {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM backup_settings")}
    finally:
        if close:
            db.close()


def validate_settings(values: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    enabled = str(values.get("schedule_enabled", "0")) in {"1", "true", "on", "yes"}
    out["schedule_enabled"] = "1" if enabled else "0"
    try:
        interval = int(values.get("schedule_interval_hours", 24))
    except (TypeError, ValueError):
        raise BackupError("schedule_interval_hours must be an integer") from None
    if not (1 <= interval <= 24 * 30):
        raise BackupError("schedule_interval_hours must be between 1 and 720")
    out["schedule_interval_hours"] = str(interval)
    try:
        retention = int(values.get("retention_count", 7))
    except (TypeError, ValueError):
        raise BackupError("retention_count must be an integer") from None
    if not (1 <= retention <= 1000):
        raise BackupError("retention_count must be between 1 and 1000")
    out["retention_count"] = str(retention)
    return out


def update_settings(values: dict[str, Any]) -> None:
    validated = validate_settings(values)
    conn = connect()
    try:
        init_db(conn)
        for key, value in validated.items():
            conn.execute(
                "INSERT INTO backup_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
        conn.commit()
    finally:
        conn.close()


def validate_components(values: dict[str, Any] | None) -> dict[str, bool]:
    values = values or {}
    out = dict(COMPONENT_DEFAULTS)
    for key in COMPONENT_KEYS:
        if key in values:
            raw = values[key]
            out[key] = bool(raw) if not isinstance(raw, str) else raw.strip().lower() in {"1", "true", "on", "yes"}
    return out


# ---------------------------------------------------------------------------
# Manifest metadata
# ---------------------------------------------------------------------------

def alderpointdns_app_version() -> str:
    version_file = APP_ROOT / "VERSION"
    proc = run(["git", "-C", str(APP_ROOT), "rev-parse", "--short", "HEAD"], check=False)
    commit = proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else "unknown"
    # VERSION holds the current semver (e.g. "0.4.0-beta.2"); a hyphenated
    # pre-release suffix means this build has not had a stable release yet.
    marker = "unreleased"
    if version_file.exists():
        version = version_file.read_text().strip()
        if version and "-" not in version:
            marker = "released"
    return f"{marker}+git.{commit}"


def database_schema_version(conn: sqlite3.Connection) -> str:
    # No formal schema-migration table exists in this project. A stable hash
    # of every CREATE TABLE statement is used as a schema fingerprint: it
    # changes whenever the schema changes and is deterministic, without
    # requiring us to invent a fake migration counter.
    rows = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    blob = "\n".join(f"{row[0]}:{row[1]}" for row in rows)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# SQLite online backup
# ---------------------------------------------------------------------------

def sqlite_backup_copy(dest: Path, include_analytics: bool, include_auth: bool) -> None:
    """Capture a consistent copy of the live database using SQLite's online
    backup API (not a raw file copy), then optionally strip sensitive/large
    tables from the copy and VACUUM to actually shrink the file."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    src = sqlite3.connect(DB_PATH)
    try:
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    stripped = False
    conn = sqlite3.connect(dest)
    try:
        table_names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not include_analytics:
            for table in ("query_events", "analytics_aggregate_buckets"):
                if table in table_names:
                    conn.execute(f"DELETE FROM {table}")
                    stripped = True
        if not include_auth:
            for table in ("admins", "login_attempts"):
                if table in table_names:
                    conn.execute(f"DELETE FROM {table}")
                    stripped = True
        conn.commit()
        if stripped:
            conn.execute("VACUUM")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Component -> file selection (backup side)
# ---------------------------------------------------------------------------

def _walk_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    if root.is_file():
        return [root]
    return [p for p in sorted(root.rglob("*")) if p.is_file()]


def select_files(components: dict[str, bool]) -> dict[str, Path]:
    """Return {archive-relative-path: absolute source path} for every
    filesystem entry selected by the given components. Paths are always
    relative to '/' so they can be tarred with a single ``-C /``."""
    entries: dict[str, Path] = {}

    def add(path: Path) -> None:
        if path.exists() and path.is_file():
            entries[str(path.relative_to("/"))] = path

    if components.get("app_config"):
        for path in _walk_files(COMPILED_DIR):
            add(path)
        for name in ("alderpointdns.service", "alderpointdns-analytics.service"):
            add(SYSTEMD_DIR / name)
        for name in ("alderpointdns.service.d", "alderpointdns-analytics.service.d", "dnsdist.service.d"):
            for path in _walk_files(SYSTEMD_DIR / name):
                add(path)
        add(SUDOERS_FILE)

    if components.get("local_dns_zones"):
        for path in _walk_files(LOCAL_ZONE_DIR):
            add(path)
        add(LOCAL_ZONES_CONF)

    if components.get("last_downloaded_lists"):
        for path in _walk_files(DOWNLOADS_DIR):
            add(path)

    if components.get("dnsdist_source_config"):
        add(DNSDIST_CONF)

    if components.get("bind_source_config"):
        for name in BIND_CONF_FILES:
            add(ETC_BIND / name)

    if CERT_DIR.exists():
        for path in sorted(CERT_DIR.iterdir()):
            if not path.is_file():
                continue
            if path.suffix == ".crt":
                if components.get("certificates"):
                    add(path)
            else:
                if components.get("private_keys"):
                    add(path)

    if components.get("private_keys") or components.get("user_auth_data"):
        for path in (SECRETS_ENV, DNSDIST_API_KEY, DNSDIST_WEB_CREDS):
            add(path)

    return entries


# ---------------------------------------------------------------------------
# Create backup
# ---------------------------------------------------------------------------

def _record_backup_history(db: sqlite3.Connection, created_at: str, path: str | None, size_bytes: int, components: dict[str, bool], manifest: dict[str, Any] | None, status: str, message: str) -> int:
    cursor = db.execute(
        "INSERT INTO backup_history(created_at, path, size_bytes, components_json, manifest_json, status, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (created_at, path, size_bytes, json.dumps(components), json.dumps(manifest or {}), status, message),
    )
    db.commit()
    return cursor.lastrowid


def create_backup(components: dict[str, bool] | None = None, password: str | None = None, conn: sqlite3.Connection | None = None) -> Path:
    close = conn is None
    db = conn or connect()
    init_db(db)
    components = validate_components(components)
    created_at = now()
    status = "failed"
    message = ""
    final_path: Path | None = None
    manifest: dict[str, Any] = {}
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="alderpointdns-backup-", dir=str(STAGING_DIR)))
    try:
        included_components = [key for key in COMPONENT_KEYS if components.get(key)]
        checksums: dict[str, str] = {}
        tar_pairs: list[tuple[Path, str]] = []  # (base_dir, relpath)

        file_entries = select_files(components)
        for relpath, source in sorted(file_entries.items()):
            checksums[relpath] = sha256_file(source)
            tar_pairs.append((Path("/"), relpath))

        if components.get("sqlite_data"):
            staged_db = stage / DB_ARCHIVE_RELPATH
            sqlite_backup_copy(
                staged_db,
                include_analytics=bool(components.get("analytics_history")),
                include_auth=bool(components.get("user_auth_data")),
            )
            relpath = DB_ARCHIVE_RELPATH
            checksums[relpath] = sha256_file(staged_db)
            tar_pairs.append((stage, relpath))

        schema_version = database_schema_version(db)

        manifest = {
            "backup_format_version": BACKUP_FORMAT_VERSION,
            "alderpointdns_app_version": alderpointdns_app_version(),
            "database_schema_version": schema_version,
            "created_at": created_at,
            "source_node_id": socket.gethostname(),
            "included_components": included_components,
            "sha256_checksums": checksums,
        }
        manifest_path = stage / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
        tar_pairs.append((stage, "manifest.json"))

        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        tmp_archive = stage / f"{FILENAME_PREFIX}{stamp}.tar.gz"
        tar_args = ["tar", "-czf", str(tmp_archive)]
        for base, relpath in tar_pairs:
            tar_args += ["-C", str(base), relpath]
        run(tar_args)

        final_name = tmp_archive.name
        if password:
            final_name = encrypt_archive_inplace(tmp_archive, password)
        final_path = BACKUP_DIR / final_name
        os.replace(tmp_archive if not password else stage / final_name, final_path)
        harden_backup_file_permissions(final_path)

        size_bytes = final_path.stat().st_size
        status = "deployed"
        message = f"backup created with components: {', '.join(included_components)}"
        _record_backup_history(db, created_at, str(final_path), size_bytes, components, manifest, status, message)
        _fix_backup_dir_permissions()
        return final_path
    except Exception as exc:
        message = str(exc)
        _record_backup_history(db, created_at, str(final_path) if final_path else None, 0, components, manifest, "failed", message)
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        if close:
            db.close()


def _fix_backup_dir_permissions() -> None:
    """Make every backup file readable by the alderpointdns group, including
    orphaned files created by the older scripts/backup.sh (root:root 0640),
    so the web process can list and serve downloads without a sudo round
    trip per download."""
    if not BACKUP_DIR.exists():
        return
    for path in BACKUP_DIR.iterdir():
        if path.is_file() and path.name.startswith(FILENAME_PREFIX):
            harden_backup_file_permissions(path)


# ---------------------------------------------------------------------------
# Encryption (openssl aes-256-cbc + pbkdf2 -- audited, already-installed tool,
# no hand-rolled crypto)
# ---------------------------------------------------------------------------

OPENSSL_ENC_ARGS = ["-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt"]


def encrypt_archive_inplace(path: Path, password: str) -> str:
    """Encrypt path in place (replacing it with a .enc sibling) and return
    the new filename."""
    enc_path = path.with_name(path.name + ".enc")
    run(["openssl", "enc"] + OPENSSL_ENC_ARGS + ["-pass", "stdin", "-in", str(path), "-out", str(enc_path)], input_text=password)
    path.unlink()
    return enc_path.name


def decrypt_archive(path: Path, password: str, dest: Path) -> Path:
    run(["openssl", "enc", "-d"] + OPENSSL_ENC_ARGS + ["-pass", "stdin", "-in", str(path), "-out", str(dest)], input_text=password)
    return dest


def is_encrypted_name(name: str) -> bool:
    return name.endswith(".enc")


# ---------------------------------------------------------------------------
# Listing / lookup
# ---------------------------------------------------------------------------

def list_backups(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        rows = [dict(row) for row in db.execute("SELECT * FROM backup_history ORDER BY id DESC")]
        for row in rows:
            try:
                comps = json.loads(row.get("components_json") or "{}")
                selected = [key for key in COMPONENT_KEYS if comps.get(key)]
            except json.JSONDecodeError:
                selected = []
            row["components_summary"] = f"{len(selected)} of {len(COMPONENT_KEYS)} components" if selected else "unknown"
        known_paths = {row["path"] for row in rows if row["path"]}
        if BACKUP_DIR.exists():
            for path in sorted(BACKUP_DIR.iterdir(), reverse=True):
                if not path.is_file() or not path.name.startswith(FILENAME_PREFIX):
                    continue
                if str(path) in known_paths:
                    continue
                stat = path.stat()
                rows.append(
                    {
                        "id": None,
                        "created_at": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).replace(microsecond=0).isoformat(),
                        "path": str(path),
                        "size_bytes": stat.st_size,
                        "components_json": "{}",
                        "manifest_json": "{}",
                        "status": "legacy",
                        "message": "discovered on disk; not created through this backup history (e.g. scripts/backup.sh, or created before this feature existed)",
                        "components_summary": "legacy (pre-dates this page)",
                    }
                )
        rows.sort(key=lambda row: row["created_at"], reverse=True)
        return rows
    finally:
        if close:
            db.close()


def find_backup_path(identifier: str) -> Path:
    """Resolve a backup by history id, filename, or absolute path, always
    confined to BACKUP_DIR or the staging imports directory."""
    candidate: Path | None = None
    if identifier.isdigit():
        conn = connect()
        try:
            init_db(conn)
            row = conn.execute("SELECT path FROM backup_history WHERE id=?", (int(identifier),)).fetchone()
            if row and row["path"]:
                candidate = Path(row["path"])
        finally:
            conn.close()
    else:
        raw = Path(identifier)
        name = raw.name
        for base in (BACKUP_DIR, IMPORTS_DIR):
            probe = base / name
            if probe.exists():
                candidate = probe
                break
        if candidate is None and raw.is_absolute():
            candidate = raw
    if candidate is None:
        raise BackupError(f"backup not found: {identifier}")
    resolved = candidate.resolve()
    allowed_roots = (BACKUP_DIR.resolve(), IMPORTS_DIR.resolve())
    if not any(str(resolved).startswith(str(root) + "/") or resolved == root for root in allowed_roots):
        raise BackupError("refusing to operate on a backup outside managed backup directories")
    if not resolved.exists():
        raise BackupError(f"backup file missing: {resolved}")
    return resolved


def stage_import(filename: str, data: bytes) -> Path:
    IMPORTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename).name or "uploaded-backup.tar.gz"
    if not (safe_name.endswith(".tar.gz") or safe_name.endswith(".tar.gz.enc")):
        raise BackupError("uploaded backup must be a .tar.gz or .tar.gz.enc file")
    dest = IMPORTS_DIR / f"{int(time.time())}-{safe_name}"
    dest.write_bytes(data)
    os.chmod(dest, 0o640)
    return dest


def delete_backup(identifier: str) -> None:
    path = find_backup_path(identifier)
    path.unlink(missing_ok=True)
    conn = connect()
    try:
        init_db(conn)
        conn.execute("DELETE FROM backup_history WHERE path=?", (str(path),))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Extract (shared by preview and restore)
# ---------------------------------------------------------------------------

def extract_backup(path: Path, password: str | None, dest_dir: Path) -> dict[str, Any]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    source = path
    if is_encrypted_name(path.name):
        if not password:
            raise BackupError("this backup is password-encrypted; a password is required")
        plain = dest_dir.parent / f"{dest_dir.name}.tar.gz"
        decrypt_archive(path, password, plain)
        source = plain
    elif password:
        raise BackupError("a password was provided but this backup is not encrypted")
    try:
        run(["tar", "-xzf", str(source), "-C", str(dest_dir)])
    except subprocess.CalledProcessError as exc:
        raise BackupError(f"backup archive is corrupt or password is wrong: {exc.stdout}") from None
    manifest_path = dest_dir / "manifest.json"
    if not manifest_path.exists():
        raise BackupError("backup archive is missing manifest.json")
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as exc:
        raise BackupError(f"backup manifest is not valid JSON: {exc}") from None
    checksums = manifest.get("sha256_checksums", {})
    mismatches = []
    for relpath, expected in checksums.items():
        candidate = dest_dir / relpath
        if not candidate.exists():
            mismatches.append(f"{relpath}: missing from archive")
            continue
        actual = sha256_file(candidate)
        if actual != expected:
            mismatches.append(f"{relpath}: checksum mismatch")
    if mismatches:
        raise BackupError("backup integrity check failed: " + "; ".join(mismatches[:10]))
    return manifest


# ---------------------------------------------------------------------------
# Preview / dry-run restore
# ---------------------------------------------------------------------------

def _file_diff(live: Path, staged: Path) -> str:
    live_ok = live.exists()
    staged_ok = staged.exists()
    if not live_ok and not staged_ok:
        return "unchanged (absent on both)"
    if not live_ok:
        return "would be created"
    if not staged_ok:
        return "not present in this backup (would be left alone)"
    if sha256_file(live) == sha256_file(staged):
        return "unchanged"
    return "would be modified"


def preview_restore(path: Path, password: str | None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        extract_dir = Path(tmp) / "extract"
        manifest = extract_backup(path, password, extract_dir)

        compat_warnings = []
        fmt_version = manifest.get("backup_format_version")
        compatible = fmt_version == BACKUP_FORMAT_VERSION
        if not compatible:
            compat_warnings.append(f"backup_format_version {fmt_version} does not match current version {BACKUP_FORMAT_VERSION}")
        conn = connect()
        try:
            init_db(conn)
            live_schema = database_schema_version(conn)
        finally:
            conn.close()
        if manifest.get("database_schema_version") and manifest.get("database_schema_version") != live_schema:
            compat_warnings.append("database schema fingerprint differs from this install; some tables may not exist yet on one side")
        manifest_app_version = manifest.get("alderpointdns_app_version")
        if manifest_app_version and manifest_app_version != alderpointdns_app_version():
            compat_warnings.append(f"backup was created by {manifest_app_version}, this install is {alderpointdns_app_version()}")

        included = set(manifest.get("included_components", []))

        table_diffs: list[dict[str, Any]] = []
        staged_db = extract_dir / DB_ARCHIVE_RELPATH
        if staged_db.exists():
            backup_conn = sqlite3.connect(staged_db)
            backup_conn.row_factory = sqlite3.Row
            live_conn = connect()
            try:
                init_db(live_conn)
                backup_tables = {row[0] for row in backup_conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                live_tables = {row[0] for row in live_conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                for table in sorted(backup_tables | live_tables):
                    if table in TABLES_EXCLUDED_FROM_RESTORE or table == "sqlite_sequence":
                        continue
                    backup_count = backup_conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] if table in backup_tables else None
                    live_count = live_conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] if table in live_tables else None
                    if backup_count == live_count:
                        continue
                    table_diffs.append(
                        {
                            "table": table,
                            "component": TABLE_COMPONENT_MAP.get(table, "sqlite_data"),
                            "live_rows": live_count,
                            "backup_rows": backup_count,
                        }
                    )
            finally:
                live_conn.close()
                backup_conn.close()

        file_diffs: list[dict[str, str]] = []
        for relpath in sorted(manifest.get("sha256_checksums", {})):
            if relpath == DB_ARCHIVE_RELPATH:
                continue
            staged_file = extract_dir / relpath
            live_file = Path("/") / relpath
            diff = _file_diff(live_file, staged_file)
            if diff != "unchanged":
                file_diffs.append({"path": relpath, "diff": diff})

        return {
            "manifest": manifest,
            "compatible": compatible,
            "warnings": compat_warnings,
            "included_components": sorted(included),
            "table_diffs": table_diffs,
            "file_diffs": file_diffs,
            "file_diff_count": len(file_diffs),
            "unchanged_file_count": len(manifest.get("sha256_checksums", {})) - len(file_diffs) - (1 if staged_db.exists() else 0),
        }


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------

def dig(domain: str, port: str = "53") -> subprocess.CompletedProcess[str]:
    return run(["dig", "@127.0.0.1", "-p", port, domain, "A", "+time=3", "+tries=1"], check=False)


def resolves(domain: str, port: str = "53") -> bool:
    result = dig(domain, port)
    return result.returncode == 0 and "status: NOERROR" in result.stdout and "\tA\t" in result.stdout


def _copy_with_ownership(src: str | Path, dest: str | Path) -> None:
    """shutil.copy2 preserves content/mode/times but NOT owner/group, which
    matters here: e.g. dnsdist.conf must stay root:_dnsdist or the dnsdist
    process (running as _dnsdist) cannot read its own config after a
    restore. Extraction from the tar archive (run as root) does preserve
    original ownership on the staged copy, so mirror it onto the live path
    explicitly rather than relying on copy2's defaults. Accepts str paths
    too, since shutil.copytree's copy_function callback is invoked with
    strings, not Path objects."""
    shutil.copy2(src, dest)
    src_stat = os.stat(src)
    try:
        os.chown(dest, src_stat.st_uid, src_stat.st_gid)
    except (PermissionError, LookupError):
        pass


def _copytree_with_ownership(src: Path, dest: Path) -> None:
    shutil.copytree(src, dest, copy_function=_copy_with_ownership)
    for root, _dirs, _files in os.walk(dest):
        rel = Path(root).relative_to(dest)
        src_dir = src / rel
        try:
            os.chown(root, src_dir.stat().st_uid, src_dir.stat().st_gid)
        except (PermissionError, LookupError, FileNotFoundError):
            pass


def _replace_path(live: Path, staged: Path, backups: list[tuple[Path, Path]]) -> None:
    """Back up the current live file/dir (if any) then atomically install
    the staged copy. Appends (live, backup_location) to `backups` for
    rollback."""
    if not staged.exists():
        return
    live.parent.mkdir(parents=True, exist_ok=True)
    backup_target = BACKUP_DIR / f"{live.name}.pre-restore.{int(time.time() * 1000)}"
    if live.exists():
        shutil.move(str(live), str(backup_target))
        backups.append((live, backup_target))
    else:
        backups.append((live, Path("")))  # marks "did not exist before"
    if staged.is_dir():
        _copytree_with_ownership(staged, live)
    else:
        _copy_with_ownership(staged, live)


def _rollback_paths(backups: list[tuple[Path, Path]]) -> None:
    for live, backup_target in reversed(backups):
        try:
            if live.exists():
                if live.is_dir():
                    shutil.rmtree(live)
                else:
                    live.unlink()
            if backup_target != Path("") and backup_target.exists():
                shutil.move(str(backup_target), str(live))
        except Exception:
            continue


def _merge_database(staged_db: Path, components: dict[str, bool]) -> list[str]:
    """Merge selected tables from a backed-up database copy into the live
    database, table by table, via ATTACH + per-table replace. Tables mapped
    in TABLE_COMPONENT_MAP are gated only by their own specific component
    flag; every other table is gated by the broad ``sqlite_data`` flag. This
    intentionally allows restoring a single narrow table (e.g. just
    custom_rules) even when sqlite_data is off, so a restore never has to
    touch tables an operator did not select. See the module docstring."""
    if not staged_db.exists():
        return []
    merged_tables: list[str] = []
    live_conn = connect()
    try:
        live_conn.execute("ATTACH DATABASE ? AS backupdb", (str(staged_db),))
        try:
            backup_tables = {
                row[0]
                for row in live_conn.execute("SELECT name FROM backupdb.sqlite_master WHERE type='table'")
            }
            for table in sorted(backup_tables):
                if table in TABLES_EXCLUDED_FROM_RESTORE:
                    continue
                gating_component = TABLE_COMPONENT_MAP.get(table, "sqlite_data")
                if not components.get(gating_component, True):
                    continue
                live_tables = {row[0] for row in live_conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if table not in live_tables:
                    continue
                # Copy only the columns both schemas share, named explicitly.
                # A bare `INSERT ... SELECT *` breaks as soon as a schema
                # migration adds a column (e.g. deployments.trigger for
                # scheduled filter updates, import_jobs.source_path): an
                # archive taken before the migration then has fewer columns
                # than the live table and SQLite rejects the insert, failing
                # an otherwise valid restore. Columns missing from the archive
                # keep their column default.
                live_columns = [row["name"] for row in live_conn.execute(f"PRAGMA table_info({table})")]
                archive_columns = {row["name"] for row in live_conn.execute(f"PRAGMA backupdb.table_info({table})")}
                shared = [name for name in live_columns if name in archive_columns]
                if not shared:
                    continue
                column_list = ", ".join(f'"{name}"' for name in shared)
                live_conn.execute(f"DELETE FROM {table}")
                live_conn.execute(f"INSERT INTO {table}({column_list}) SELECT {column_list} FROM backupdb.{table}")
                merged_tables.append(table)
            live_conn.commit()
        finally:
            live_conn.execute("DETACH DATABASE backupdb")
    finally:
        live_conn.close()
    return merged_tables


def restore_backup(path: Path, password: str | None, components: dict[str, bool] | None, conn: sqlite3.Connection | None = None) -> int:
    close = conn is None
    db = conn or connect()
    init_db(db)
    components = validate_components(components)
    started = now()
    cursor = db.execute(
        "INSERT INTO restore_history(started_at, backup_path, components_json, status, message) VALUES (?, ?, ?, 'running', '')",
        (started, str(path), json.dumps(components)),
    )
    restore_id = cursor.lastrowid
    db.commit()

    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    status = "failed"
    message = ""
    validation_output = ""
    pre_restore_backup_path: Path | None = None
    file_backups: list[tuple[Path, Path]] = []
    merged_tables: list[str] = []
    named_touched = False
    dnsdist_touched = False
    systemd_touched = False
    db_touched = False

    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        extract_dir = Path(tmp) / "extract"
        try:
            manifest = extract_backup(path, password, extract_dir)
            available = set(manifest.get("included_components", []))
            effective = {key: bool(components.get(key)) and key in available for key in COMPONENT_KEYS}

            # A pre-restore safety net: always take a full backup of the
            # current live state before changing anything, unless the
            # request explicitly targets nothing at all.
            try:
                pre_restore_backup_path = create_backup(dict.fromkeys(COMPONENT_KEYS, True), password=None, conn=db)
            except Exception as exc:
                raise BackupError(f"could not take pre-restore safety backup, aborting restore: {exc}") from None

            compiled_source = extract_dir / "var/lib/alderpointdns/compiled"
            rpz_zone_label = "alderpointdns.rpz"

            # Cheap standalone pre-activation checks (no include resolution
            # needed): validate any staged zone files in isolation before
            # touching anything live.
            for zone_file in sorted((compiled_source / "bind").glob("**/*.rpz")) if effective.get("app_config") else []:
                run(["named-checkzone", rpz_zone_label, str(zone_file)])
                validation_output += f"named-checkzone {zone_file.name}: ok\n"

            # Stage -> backup -> atomically activate each selected, present
            # filesystem component.
            if effective.get("app_config"):
                staged_compiled = compiled_source
                _replace_path(COMPILED_DIR, staged_compiled, file_backups)
                for name in ("alderpointdns.service", "alderpointdns-analytics.service"):
                    staged = extract_dir / "etc" / "systemd" / "system" / name
                    if staged.exists():
                        _replace_path(SYSTEMD_DIR / name, staged, file_backups)
                        systemd_touched = True
                for name in ("alderpointdns.service.d", "alderpointdns-analytics.service.d", "dnsdist.service.d"):
                    staged = extract_dir / "etc" / "systemd" / "system" / name
                    if staged.exists():
                        _replace_path(SYSTEMD_DIR / name, staged, file_backups)
                        systemd_touched = True
                        if name == "dnsdist.service.d":
                            dnsdist_touched = True
                staged_sudoers = extract_dir / "etc" / "sudoers.d" / "alderpointdns"
                if staged_sudoers.exists():
                    _replace_path(SUDOERS_FILE, staged_sudoers, file_backups)
                named_touched = True

            if effective.get("local_dns_zones"):
                staged = extract_dir / "var/lib/alderpointdns/compiled/bind/local"
                if staged.exists():
                    _replace_path(LOCAL_ZONE_DIR, staged, file_backups)
                    named_touched = True
                staged_conf = extract_dir / "var/lib/alderpointdns/compiled/bind/local-zones.conf"
                if staged_conf.exists():
                    _replace_path(LOCAL_ZONES_CONF, staged_conf, file_backups)
                    named_touched = True

            if effective.get("last_downloaded_lists"):
                staged = extract_dir / "var/lib/alderpointdns/downloads"
                _replace_path(DOWNLOADS_DIR, staged, file_backups)

            if effective.get("dnsdist_source_config"):
                staged = extract_dir / "etc" / "dnsdist" / "dnsdist.conf"
                if staged.exists():
                    _replace_path(DNSDIST_CONF, staged, file_backups)
                    dnsdist_touched = True

            if effective.get("bind_source_config"):
                for name in BIND_CONF_FILES:
                    staged = extract_dir / "etc" / "bind" / name
                    if staged.exists():
                        _replace_path(ETC_BIND / name, staged, file_backups)
                        named_touched = True

            staged_cert_dir = extract_dir / "etc/alderpointdns/certs"
            if staged_cert_dir.exists():
                for staged_file in sorted(staged_cert_dir.iterdir()):
                    if not staged_file.is_file():
                        continue
                    is_public = staged_file.suffix == ".crt"
                    if is_public and not effective.get("certificates"):
                        continue
                    if not is_public and not effective.get("private_keys"):
                        continue
                    _replace_path(CERT_DIR / staged_file.name, staged_file, file_backups)
                    dnsdist_touched = True

            if effective.get("private_keys") or effective.get("user_auth_data"):
                for name in ("secrets.env", "dnsdist-api.key", "dnsdist-web.creds"):
                    staged = extract_dir / f"etc/alderpointdns/{name}"
                    if staged.exists():
                        _replace_path(ETC_ALDERPOINTDNS / name, staged, file_backups)

            staged_db = extract_dir / DB_ARCHIVE_RELPATH
            merged_tables = _merge_database(staged_db, effective)
            if merged_tables:
                db_touched = True

            if os.environ.get("ALDERPOINTDNS_TEST_FORCE_RESTORE_FAIL") == "1":
                raise RuntimeError("forced restore failure for rollback test")

            if named_touched:
                proc = run(["named-checkconf", "-p", "/etc/bind/named.conf"])
                validation_output += proc.stdout
            if dnsdist_touched:
                proc = run(["dnsdist", "--check-config", "-C", str(DNSDIST_CONF)])
                validation_output += proc.stdout
            if SUDOERS_FILE.exists():
                proc = run(["visudo", "-cf", str(SUDOERS_FILE)])
                validation_output += proc.stdout

            if systemd_touched:
                run(["systemctl", "daemon-reload"])
            if named_touched:
                run(["systemctl", "restart", "named"])
            if dnsdist_touched:
                run(["systemctl", "restart", "dnsdist"])
            if db_touched or systemd_touched:
                run(["systemctl", "restart", "alderpointdns-analytics"], check=False)
                run(["systemctl", "restart", "alderpointdns"], check=False)

            if named_touched and not _wait_active("named", timeout=20):
                raise RuntimeError("named did not become active after restore")
            if dnsdist_touched and not _wait_active("dnsdist", timeout=20):
                raise RuntimeError("dnsdist did not become active after restore")

            if not resolves("cloudflare.com", "53"):
                raise RuntimeError("post-restore plain DNS functional test failed on port 53")

            status = "deployed"
            message = f"restored components: {', '.join(k for k, v in effective.items() if v)}; merged db tables: {', '.join(merged_tables) if merged_tables else 'none'}"
        except Exception as exc:
            message = str(exc)
            try:
                _rollback_paths(file_backups)
                if pre_restore_backup_path is not None and (merged_tables or db_touched):
                    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as rtmp:
                        rextract = Path(rtmp) / "rextract"
                        extract_backup(pre_restore_backup_path, None, rextract)
                        rdb = rextract / DB_ARCHIVE_RELPATH
                        _merge_database(rdb, dict.fromkeys(COMPONENT_KEYS, True))
                if systemd_touched:
                    run(["systemctl", "daemon-reload"], check=False)
                if named_touched:
                    run(["systemctl", "restart", "named"], check=False)
                if dnsdist_touched:
                    run(["systemctl", "restart", "dnsdist"], check=False)
                if db_touched or systemd_touched:
                    run(["systemctl", "restart", "alderpointdns-analytics"], check=False)
                    run(["systemctl", "restart", "alderpointdns"], check=False)
                if resolves("cloudflare.com", "53"):
                    status = "rolled_back"
                else:
                    status = "rollback_failed"
                    message = f"{message}; rollback restart did not restore working DNS"
            except Exception as rollback_exc:
                status = "rollback_failed"
                message = f"{message}; rollback failed: {rollback_exc}"
        finally:
            db.execute(
                "UPDATE restore_history SET finished_at=?, status=?, message=?, pre_restore_backup_path=?, validation_output=? WHERE id=?",
                (now(), status, message, str(pre_restore_backup_path) if pre_restore_backup_path else None, validation_output[-4000:], restore_id),
            )
            db.commit()
            _fix_backup_dir_permissions()
            if close:
                db.close()
    if status not in ("deployed", "unchanged"):
        raise RuntimeError(message)
    return restore_id


def _wait_active(service: str, timeout: int = 15) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(["systemctl", "is-active", service], check=False)
        if result.stdout.strip() == "active":
            return True
        time.sleep(0.5)
    return run(["systemctl", "is-active", service], check=False).stdout.strip() == "active"


def last_backup(conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT * FROM backup_history ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:
        if close:
            db.close()


def last_restore(conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute("SELECT * FROM restore_history ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def prune_backups(retention_count: int | None = None, conn: sqlite3.Connection | None = None) -> list[str]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        if retention_count is None:
            retention_count = int(settings(db).get("retention_count", 7))
        rows = list(db.execute("SELECT id, path FROM backup_history WHERE status IN ('deployed','unchanged') ORDER BY id DESC"))
        pruned = []
        for row in rows[retention_count:]:
            if row["path"]:
                candidate = Path(row["path"])
                if candidate.exists():
                    candidate.unlink()
                pruned.append(row["path"])
            db.execute("DELETE FROM backup_history WHERE id=?", (row["id"],))
        db.commit()
        return pruned
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Scheduled timer deployment
# ---------------------------------------------------------------------------

def deploy_backup_schedule(conn: sqlite3.Connection | None = None) -> str:
    close = conn is None
    db = conn or connect()
    init_db(db)
    try:
        cfg = settings(db)
        interval = int(cfg.get("schedule_interval_hours", 24))
        enabled = cfg.get("schedule_enabled") == "1"
        BACKUP_TIMER_OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
        BACKUP_TIMER_OVERRIDE.write_text(
            "[Timer]\n"
            f"OnBootSec={interval}h\n"
            f"OnUnitActiveSec={interval}h\n"
        )
        run(["systemctl", "daemon-reload"])
        if enabled:
            run(["systemctl", "enable", "--now", "alderpointdns-backup.timer"])
            state = "enabled"
        else:
            run(["systemctl", "disable", "--now", "alderpointdns-backup.timer"], check=False)
            state = "disabled"
        return f"backup schedule {state}, interval={interval}h, retention={cfg.get('retention_count')}"
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Request / response (unprivileged web process -> privileged compiler)
# ---------------------------------------------------------------------------

def _pending_password_file(kind: str) -> Path:
    return STAGING_DIR / f"pending-backup-password-{kind}"


def request_backup(kind: str, payload: dict[str, Any], password: str | None = None) -> int:
    if kind not in {"create", "restore", "preview"}:
        raise BackupError(f"unknown backup request kind {kind!r}")
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        init_db(conn)
        cursor = conn.execute(
            "INSERT INTO backup_requests(kind, requested_at, payload_json, status) VALUES (?, ?, ?, 'pending')",
            (kind, now(), json.dumps(payload)),
        )
        conn.commit()
        request_id = cursor.lastrowid
    finally:
        conn.close()
    password_file = _pending_password_file(kind)
    if password:
        password_file.write_text(password)
        os.chmod(password_file, 0o600)
    elif password_file.exists():
        password_file.unlink()
    return request_id


def _consume_password(kind: str) -> str | None:
    password_file = _pending_password_file(kind)
    if not password_file.exists():
        return None
    try:
        value = password_file.read_text()
        return value or None
    finally:
        password_file.unlink(missing_ok=True)


def process_pending_request(kind: str, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    """Executed by the privileged compiler process: applies the most
    recently requested pending backup/restore/preview action."""
    close = conn is None
    db = conn or connect()
    init_db(db)
    try:
        row = db.execute(
            "SELECT * FROM backup_requests WHERE kind=? AND status='pending' ORDER BY id DESC LIMIT 1",
            (kind,),
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"] or "{}")
        password = _consume_password(kind)
        result: dict[str, Any] = {}
        status = "failed"
        try:
            if kind == "create":
                components = validate_components(payload.get("components"))
                archive = create_backup(components, password=password, conn=db)
                result = {"path": str(archive)}
                status = "done"
            elif kind == "restore":
                components = validate_components(payload.get("components"))
                backup_path = find_backup_path(payload["path"])
                restore_id = restore_backup(backup_path, password, components, conn=db)
                result = {"restore_id": restore_id}
                status = "done"
            elif kind == "preview":
                backup_path = find_backup_path(payload["path"])
                result = preview_restore(backup_path, password)
                status = "done"
        except Exception as exc:
            result = {"error": str(exc)}
            status = "failed"
        db.execute(
            "UPDATE backup_requests SET status=?, result_json=?, finished_at=? WHERE id=?",
            (status, json.dumps(result, default=str), now(), row["id"]),
        )
        # Newest-request-wins, matching dns_cache's flush pattern: any older
        # still-pending rows of the same kind are marked skipped.
        db.execute(
            "UPDATE backup_requests SET status='skipped', finished_at=? WHERE kind=? AND status='pending' AND id!=?",
            (now(), kind, row["id"]),
        )
        db.commit()
        return {"id": row["id"], "status": status, "result": result}
    finally:
        if close:
            db.close()


def latest_request_result(kind: str, request_id: int | None = None, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        if request_id is not None:
            row = db.execute("SELECT * FROM backup_requests WHERE id=?", (request_id,)).fetchone()
        else:
            row = db.execute("SELECT * FROM backup_requests WHERE kind=? ORDER BY id DESC LIMIT 1", (kind,)).fetchone()
        return dict(row) if row else None
    finally:
        if close:
            db.close()
