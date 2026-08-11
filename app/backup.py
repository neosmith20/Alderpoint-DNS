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
   - ``user_auth_data`` (default off): if unset, ``admins``,
     ``login_attempts``, ``sessions``, and ``admin_audit_log`` are deleted
     from the backup copy, since admin password hashes are credential
     material and session/audit rows are account-security state tied to a
     specific point in time.
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
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO, Callable

from app import upstream_dns
from app.service_logs import sanitize as _sanitize_secrets


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
DPKG_PACKAGE_NAME = "alderpointdns"

BACKUP_FORMAT_VERSION = 1
FILENAME_PREFIX = "alderpointdns-backup-"

# ---------------------------------------------------------------------------
# Native backup upload/extraction size policy
#
# This is a *separate* policy from app/importer.py's MAX_UPLOAD_BYTES (10
# MiB), which exists for CSV/spreadsheet/text/AdGuard-YAML imports through
# the Import & Migration page. Those uploads are always small, hand-edited,
# or paginated text; a native Alderpoint DNS backup is a full, versioned
# archive of this server's configuration and (optionally) its SQLite
# database, and Analytics History naturally makes that archive grow as a
# server ages -- a long-running production install's backup can legitimately
# be hundreds of MiB. Sharing importer.py's 10 MiB cap with backup restore
# is the exact bug this module works around: a backup upload must never be
# rejected at that limit.
#
# Defaults chosen for real Alderpoint DNS backup growth: routine backups
# (no analytics_history) are typically a few MiB; a year of Analytics
# History on a busy resolver is realistically in the tens-to-low-hundreds
# of MiB range. 4 GiB gives multiple years of headroom without allowing an
# unbounded upload. Both values are administrator-configurable (within a
# hard ceiling) via backup_settings, in case a particular deployment's
# analytics retention grows unusually large.
DEFAULT_MAX_UPLOAD_MIB = 4096  # 4 GiB
HARD_CEILING_MAX_UPLOAD_MIB = 51200  # 50 GiB -- never allow "unlimited"
DEFAULT_MAX_EXTRACTED_MIB = 16384  # 16 GiB -- extracted/uncompressed ceiling
HARD_CEILING_MAX_EXTRACTED_MIB = 204800  # 200 GiB

# Bounded chunk size used when streaming an upload to disk. This is the
# entire memory footprint of a backup upload, independent of archive size:
# a 20 MiB backup and a 4 GiB backup both ever hold at most this many bytes
# in the FastAPI/web process's memory at once.
UPLOAD_CHUNK_BYTES = 4 * 1024 * 1024  # 4 MiB

# Multiplier applied to the declared/streamed archive size when checking
# free disk space before accepting an upload: staging needs room for the
# compressed archive itself, its extracted contents, and (during restore)
# a fresh pre-restore safety backup, all of which can transiently coexist.
FREE_SPACE_UPLOAD_MULTIPLIER = 2
FREE_SPACE_EXTRACT_MULTIPLIER = 1.2
# Conservative up-front floor used when a client didn't supply a usable
# Content-Length hint: catches "this disk has essentially no space left"
# without demanding room for a full max-size upload that may never
# materialize. The per-chunk counter in the upload loop enforces the real
# max_upload_bytes() limit regardless of this floor, and the free-space
# check re-runs (with the real archive size) before extraction.
FREE_SPACE_NO_HINT_CHECK_BYTES = 512 * 1024 * 1024
FREE_SPACE_RECHECK_INTERVAL_BYTES = 256 * 1024 * 1024

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
    "sessions": "user_auth_data",
    "admin_audit_log": "user_auth_data",
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
    "max_upload_mib": str(DEFAULT_MAX_UPLOAD_MIB),
    "max_extracted_mib": str(DEFAULT_MAX_EXTRACTED_MIB),
}

BACKUP_TIMER_OVERRIDE = SYSTEMD_DIR / "alderpointdns-backup.timer.d" / "alderpointdns.conf"


class BackupError(ValueError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def run(command: list[str], check: bool = True, input_text: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, input=input_text, env=env)


def harden_backup_file_permissions(path: Path) -> None:
    try:
        shutil.chown(path, user="root", group="alderpointdns")
    except (LookupError, PermissionError, OSError):
        pass
    os.chmod(path, 0o640)


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] if isinstance(row, sqlite3.Row) else row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN "{column}" {definition}')


# ---------------------------------------------------------------------------
# Restore worker identity / heartbeat
#
# A restore that dies (killed process, host reboot, OOM) must never leave its
# restore_history row stuck at status='running' forever -- that's exactly
# what happened to the real 296.47 MiB / 2.8M-row restore this hardening
# responds to (see docs/backup-recovery.md and the forensic recovery notes):
# its row sat at status='running', finished_at=NULL, indefinitely, because
# nothing ever recorded who was supposed to be working on it or gave later
# code a way to tell "still going" from "abandoned".
#
# The authoritative signal is worker identity, not elapsed time: a
# (pid, process-start-time, boot id) triple recorded when the restore begins.
# A restore is only ever *reaped* when that exact process can no longer be
# found alive -- a wall-clock/heartbeat-age check alone is deliberately never
# sufficient to fail a restore, so a legitimately huge, slow-but-progressing
# restore is never killed just for taking a long time. heartbeat_at is
# recorded for observability (surfacing "no progress in N minutes, worker
# still alive" to an operator) but is not, by itself, a failure trigger.
STALE_HEARTBEAT_SECONDS = 300  # informational threshold only; see above


def _current_boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def _process_start_ticks(pid: int) -> int | None:
    """Field 22 (starttime, in clock ticks since boot) of /proc/<pid>/stat --
    stable identity for a PID even across reuse, since a process's starttime
    can't be forged or coincide with another process's by chance the way a
    bare PID can once the original exits and the number is recycled."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    # comm (arg 2) is parenthesized and may itself contain spaces/parens;
    # split on the *last* ')' to get past it reliably.
    rest = raw.rsplit(")", 1)[-1].split()
    try:
        return int(rest[19])  # index 19 of the post-comm fields == stat field 22
    except (IndexError, ValueError):
        return None


def _worker_identity() -> tuple[int, int | None, str]:
    pid = os.getpid()
    return pid, _process_start_ticks(pid), _current_boot_id()


def _worker_alive(pid: int | None, start_ticks: int | None, boot_id: str | None) -> bool:
    """True only if `pid` is (still) the exact process that recorded this
    identity -- not merely if some process with that number happens to
    exist. A missing/empty boot_id or pid (rows from before this migration,
    or a host that's since rebooted) is never considered alive."""
    if not pid or pid <= 0 or not boot_id or boot_id != _current_boot_id():
        return False
    current_ticks = _process_start_ticks(pid)
    if current_ticks is None:
        return False
    if start_ticks is not None and current_ticks != start_ticks:
        return False
    return True


def _touch_restore(
    db: sqlite3.Connection,
    restore_id: int,
    *,
    phase: str | None = None,
    detail: str | None = None,
    current: int | None = None,
    total: int | None = None,
    staging_dir: str | None = None,
    promoted: bool = False,
    pre_restore_backup_path: str | None = None,
) -> None:
    """Records a heartbeat plus (optionally) phase/progress/staging-dir for
    a running restore. Called at phase transitions and at bounded intervals
    within long-running phases -- never per-row -- so this stays cheap even
    across a multi-million-row analytics restore. `promoted=True` also
    stamps promoted_at -- call this only once, immediately after the
    atomic database swap actually succeeds. `pre_restore_backup_path`
    should be recorded as soon as that backup exists on disk, not only in
    the final UPDATE at the very end of restore_backup() -- a worker killed
    before reaching that final write would otherwise leave an operator
    unable to find its own safety backup from the row, even though the
    backup file itself is sitting right there in BACKUP_DIR."""
    sets = ["heartbeat_at=?"]
    params: list[Any] = [now()]
    if phase is not None:
        sets.append("phase=?")
        params.append(phase)
    if detail is not None:
        sets.append("phase_detail=?")
        params.append(detail)
    if current is not None:
        sets.append("progress_current=?")
        params.append(current)
    if total is not None:
        sets.append("progress_total=?")
        params.append(total)
    if staging_dir is not None:
        sets.append("staging_dir=?")
        params.append(staging_dir)
    if promoted:
        sets.append("promoted_at=?")
        params.append(now())
    if pre_restore_backup_path is not None:
        sets.append("pre_restore_backup_path=?")
        params.append(pre_restore_backup_path)
    params.append(restore_id)
    db.execute(f"UPDATE restore_history SET {', '.join(sets)} WHERE id=?", params)
    db.commit()


def reap_abandoned_restores(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    """Finds restore_history rows stuck at status='running' whose recorded
    worker is provably no longer alive (process gone, PID reused, or a
    reboot happened since it started) and marks them 'interrupted' with a
    diagnostic message and finished_at set, then best-effort cleans up their
    staging directory. Called on application startup and whenever Backup &
    Restore status is fetched (backup.last_restore()), so an abandoned
    restore is caught promptly without needing an operator to notice.

    Deliberately does NOT act on any row whose worker is still alive, no
    matter how long it's been running -- see the worker-identity docstring
    above.

    promoted_at is the authoritative signal for what an abandoned restore
    actually did to the live database (see restore_backup()'s staged/
    atomic-promotion architecture):
      - NULL: the worker died before the atomic database swap ever
        happened. The live database was never touched -- safe to say so
        plainly, and safe to just retry the restore.
      - set: the swap already committed before the worker died (most
        likely mid service-restart/postcheck, the only steps that happen
        after promotion). The live database now IS the restored one; that
        is not undone here (see restore_backup()'s "post-promotion
        failure" handling for why an automatic data rollback is not
        attempted). This is the one case where reaping also best-effort
        restarts the services a promoted-but-interrupted restore may have
        left stopped.
    """
    close = conn is None
    db = conn or connect()
    init_db(db)
    reaped: list[dict[str, Any]] = []
    try:
        rows = db.execute("SELECT * FROM restore_history WHERE status='running'").fetchall()
        for row in rows:
            if _worker_alive(row["worker_pid"], row["worker_start_ticks"], row["worker_boot_id"]):
                continue
            worker_desc = (
                f"pid {row['worker_pid']} (started {row['started_at']})"
                if row["worker_pid"]
                else "no worker identity recorded (pre-dates lifecycle tracking or was never set)"
            )
            already_promoted = bool(row["promoted_at"])
            if already_promoted:
                impact = (
                    "the database swap had ALREADY COMMITTED before the worker disappeared -- "
                    "the live database now reflects the restored content; this was not automatically "
                    "rolled back (only already-validated database changes are ever promoted, so this "
                    "is a service/health-recovery situation, not a data-integrity one). Attempting to "
                    "restart alderpointdns and alderpointdns-analytics now; check "
                    "`systemctl status named dnsdist alderpointdns alderpointdns-analytics` and re-run "
                    "postcheck manually if needed."
                )
            else:
                impact = "the live database was NOT modified (the atomic promotion step never ran) -- safe to retry this restore."
            message = (
                f"restore worker disappeared -- {worker_desc} is no longer running; "
                f"marked interrupted during {'startup' if close else 'status'} check at {now()}. "
                f"Last known phase: {row['phase'] or 'unknown'}"
                + (f" ({row['phase_detail']})" if row["phase_detail"] else "")
                + f". Last heartbeat: {row['heartbeat_at'] or 'never recorded'}. "
                + impact
            )
            db.execute(
                "UPDATE restore_history SET status='interrupted', finished_at=?, message=? WHERE id=?",
                (now(), message, row["id"]),
            )
            cleaned = _cleanup_abandoned_staging(row["staging_dir"])
            if already_promoted:
                run(["systemctl", "restart", "alderpointdns-analytics"], check=False)
                run(["systemctl", "restart", "alderpointdns"], check=False)
            reaped.append({"id": row["id"], "message": message, "staging_cleaned": cleaned, "already_promoted": already_promoted})
        db.commit()
    finally:
        if close:
            db.close()
    return reaped


def _cleanup_abandoned_staging(staging_dir: str | None) -> bool:
    """Removes a dead restore's extraction staging directory. Refuses to
    touch anything that isn't a direct child of STAGING_DIR -- never the
    uploaded/source archive (BACKUP_DIR), never a pre-restore safety backup
    (also BACKUP_DIR), never STAGING_DIR itself, and never any path outside
    STAGING_DIR at all -- so a corrupted/malicious staging_dir value can
    never turn this into an arbitrary-path delete."""
    if not staging_dir:
        return False
    try:
        candidate = Path(staging_dir).resolve()
        staging_root = STAGING_DIR.resolve()
    except OSError:
        return False
    if candidate == staging_root or staging_root not in candidate.parents:
        return False
    if not candidate.exists():
        return False
    try:
        shutil.rmtree(candidate)
        return True
    except OSError:
        return False


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
        # restore_history lifecycle-tracking columns, added after the table
        # already existed in the field -- ALTER TABLE, not part of the
        # CREATE TABLE IF NOT EXISTS above, so upgrading installs migrate in
        # place rather than silently keeping the old, heartbeat-less shape.
        # See restore_backup()/reap_abandoned_restores() for how these are
        # used to tell "still working" apart from "worker disappeared"
        # without relying on a single wall-clock timeout.
        for column, definition in (
            ("worker_pid", "INTEGER"),
            ("worker_start_ticks", "INTEGER"),
            ("worker_boot_id", "TEXT"),
            ("heartbeat_at", "TEXT"),
            ("phase", "TEXT NOT NULL DEFAULT 'validating'"),
            ("phase_detail", "TEXT NOT NULL DEFAULT ''"),
            ("progress_current", "INTEGER"),
            ("progress_total", "INTEGER"),
            ("staging_dir", "TEXT"),
            # Set once, the instant the atomic filesystem swap that commits
            # a restore's database changes to the live file actually
            # succeeds -- see _promote_working_db()/PROMOTION_COMMITTED_PHASES.
            # This is the authoritative "point of no return" marker: a
            # restore that dies with this NULL never touched the live
            # database; a restore that dies with this set already has.
            ("promoted_at", "TEXT"),
        ):
            _ensure_column(db, "restore_history", column, definition)
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
    if "max_upload_mib" in values:
        try:
            max_upload = int(values.get("max_upload_mib", DEFAULT_MAX_UPLOAD_MIB))
        except (TypeError, ValueError):
            raise BackupError("max_upload_mib must be an integer") from None
        if not (64 <= max_upload <= HARD_CEILING_MAX_UPLOAD_MIB):
            raise BackupError(f"max_upload_mib must be between 64 and {HARD_CEILING_MAX_UPLOAD_MIB}")
        out["max_upload_mib"] = str(max_upload)
    if "max_extracted_mib" in values:
        try:
            max_extracted = int(values.get("max_extracted_mib", DEFAULT_MAX_EXTRACTED_MIB))
        except (TypeError, ValueError):
            raise BackupError("max_extracted_mib must be an integer") from None
        if not (64 <= max_extracted <= HARD_CEILING_MAX_EXTRACTED_MIB):
            raise BackupError(f"max_extracted_mib must be between 64 and {HARD_CEILING_MAX_EXTRACTED_MIB}")
        out["max_extracted_mib"] = str(max_extracted)
    return out


def max_upload_bytes(conn: sqlite3.Connection | None = None) -> int:
    try:
        return int(settings(conn).get("max_upload_mib", DEFAULT_MAX_UPLOAD_MIB)) * 1024 * 1024
    except (TypeError, ValueError):
        return DEFAULT_MAX_UPLOAD_MIB * 1024 * 1024


def max_extracted_bytes_setting(conn: sqlite3.Connection | None = None) -> int:
    try:
        return int(settings(conn).get("max_extracted_mib", DEFAULT_MAX_EXTRACTED_MIB)) * 1024 * 1024
    except (TypeError, ValueError):
        return DEFAULT_MAX_EXTRACTED_MIB * 1024 * 1024


def _check_free_space(required_bytes: int, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(target_dir)
    if usage.free < required_bytes:
        raise BackupError(
            f"insufficient free disk space in {target_dir}: "
            f"{usage.free // (1024 * 1024)} MiB available, "
            f"at least {required_bytes // (1024 * 1024)} MiB required"
        )


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

# Debian/semver-ish version strings only: letters, digits, and the small
# set of separators both schemes use ('.', '+', '~', '_', '-'). Guards
# against a truncated/binary/garbage VERSION file being echoed verbatim
# into a backup manifest as if it were a real version.
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~_-]{0,63}$")


def _read_version_file() -> str | None:
    """Packaged installs ship an authoritative VERSION file (see
    packaging/debian/install); this never requires git or dpkg and is the
    preferred source."""
    try:
        raw = (APP_ROOT / "VERSION").read_text()
    except OSError:
        return None
    version = raw.strip()
    if version and _VERSION_RE.match(version):
        return version
    return None


def _read_dpkg_version() -> str | None:
    """Ask dpkg for the actually-installed package version. Returns None on
    non-Debian/source checkouts where the package was never dpkg-installed
    -- that's the normal, expected case for a dev checkout, not a fallback
    failure."""
    try:
        proc = run(["dpkg-query", "-W", "-f=${Version}", DPKG_PACKAGE_NAME], check=False)
    except (FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    version = proc.stdout.strip()
    return version or None


# scripts/build-deb.sh derives the Debian package Version deterministically
# from the VERSION file's semver-style pre-release tag:
#   0.4.0-beta.6  ->  0.4.0~beta6-1   (sed 's/-([A-Za-z]+)\.([0-9]+)/~\1\2/';
#   "-1" appended as the Debian revision). Reversed here so a dpkg-reported
#   version can be compared against a VERSION-file-style string. Handles any
#   pre-release tag (beta, dev, rc, ...), not just "beta" -- see
#   docs/versioning.md.
_DPKG_PRERELEASE_RE = re.compile(r"~([A-Za-z]+)(\d+)")


def _dpkg_version_to_source_form(dpkg_version: str) -> str:
    upstream = dpkg_version.rsplit("-", 1)[0] if "-" in dpkg_version else dpkg_version
    return _DPKG_PRERELEASE_RE.sub(r"-\1.\2", upstream)


def _git_dev_metadata() -> str | None:
    """Optional short commit hash, included only for development checkouts.
    Packaged installs at /opt/alderpointdns are plain files, not a git
    clone, and must not require a git binary at all -- both checks below
    (binary present, .git present) must pass before git is ever invoked,
    and any failure to run it is swallowed rather than surfaced, since a
    missing dev-metadata suffix must never fail backup creation."""
    if not shutil.which("git") or not (APP_ROOT / ".git").exists():
        return None
    try:
        proc = run(["git", "-C", str(APP_ROOT), "rev-parse", "--short", "HEAD"], check=False)
    except (FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    commit = proc.stdout.strip()
    return commit or None


def version_source_status() -> dict[str, Any]:
    """Resolve the canonical application version and report both
    contributing sources. See docs/versioning.md for the full model;
    summary:

    - The VERSION file (see packaging/debian/install) is the primary
      source: it's what scripts/build-deb.sh itself derives the Debian
      package Version from at build time, so on any package built and
      installed through the normal pipeline the two already agree by
      construction -- this call doesn't need to (and, to stay a fast,
      dependency-free read on every backup, does not) prefer one over the
      other in that normal case.
    - dpkg's own record is consulted as a fallback when VERSION is
      missing/unreadable/malformed (e.g. a stripped-down or corrupted
      package tree) and, regardless of fallback use, is *compared* against
      the file so unexpected drift between "what the files say" and "what
      dpkg thinks is installed" -- e.g. a dpkg-managed path that got
      hand-edited or overlaid outside of dpkg after install -- is detected
      and logged rather than silently ignored. That drift is exactly the
      failure mode that would make a future Software Updates version
      comparison unreliable if left unnoticed.
    """
    file_version = _read_version_file()
    dpkg_version = _read_dpkg_version()
    normalized_dpkg = _dpkg_version_to_source_form(dpkg_version) if dpkg_version else None

    mismatch = bool(file_version and normalized_dpkg and file_version != normalized_dpkg)
    if file_version:
        resolved, source = file_version, "version_file"
    elif normalized_dpkg:
        resolved, source = normalized_dpkg, "dpkg"
    else:
        resolved, source = "unknown", "none"

    return {
        "resolved": resolved,
        "source": source,
        "file_version": file_version,
        "dpkg_version": dpkg_version,
        "dpkg_version_normalized": normalized_dpkg,
        "mismatch": mismatch,
    }


def alderpointdns_app_version() -> str:
    file_version = _read_version_file()
    version = file_version or _read_dpkg_version() or "unknown"
    if file_version:
        # Only worth the extra dpkg-query (and the drift check) when we
        # actually have something to compare the file against; skip it
        # entirely on hosts with no VERSION file at all, where dpkg was
        # already consulted above as the sole source.
        dpkg_version = _read_dpkg_version()
        if dpkg_version and _dpkg_version_to_source_form(dpkg_version) != file_version:
            print(
                f"<4>alderpointdns: VERSION file ({file_version!r}) does not match the "
                f"dpkg-installed package version ({dpkg_version!r}, normalized "
                f"{_dpkg_version_to_source_form(dpkg_version)!r}); using the VERSION file. "
                "This is expected on a dev checkout overlaid on a dpkg-managed install path; "
                "otherwise it indicates drift a future version-update check should not ignore.",
                file=sys.stderr,
                flush=True,
            )
    commit = _git_dev_metadata()
    return f"{version}+git.{commit}" if commit else version


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

def sqlite_backup_copy(dest: Path, include_analytics: bool, include_auth: bool, include_private_keys: bool = True) -> None:
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
            for table in ("admins", "login_attempts", "sessions", "admin_audit_log"):
                if table in table_names:
                    conn.execute(f"DELETE FROM {table}")
                    stripped = True
        if not include_private_keys and "notification_providers" in table_names:
            # Notification provider secrets (SMTP passwords, webhook URLs --
            # most webhook URLs embed a bearer-equivalent token) are
            # credential material, like TLS private keys and dnsdist API
            # credentials. Only the secret is blanked, not the whole row, so
            # provider names/config and event subscriptions survive a
            # restore -- the operator just re-enters the secret.
            conn.execute("UPDATE notification_providers SET secret=''")
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


def create_backup(
    components: dict[str, bool] | None = None,
    password: str | None = None,
    conn: sqlite3.Connection | None = None,
    purpose: str | None = None,
    purpose_metadata: dict[str, Any] | None = None,
) -> Path:
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
                include_private_keys=bool(components.get("private_keys")),
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
            # "manual" (the default) covers both the interactive web Create
            # Backup action and a bare CLI `backup-create` invocation;
            # "scheduled" and "pre_upgrade" are set by their respective
            # callers (deploy_backup_schedule()'s timer, and
            # app/software_updates.py's mandatory pre-upgrade backup step)
            # so a backup can be identified by why it exists, purely as
            # metadata -- restore never branches on this field.
            "purpose": purpose or "manual",
            "purpose_metadata": purpose_metadata or {},
        }
        manifest_path = stage / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
        tar_pairs.append((stage, "manifest.json"))

        # Filename timestamp uses the server's configured local time (not
        # UTC) so an administrator can identify a backup by filename alone
        # without mentally converting timezones -- purely cosmetic: restore
        # never parses or depends on this stamp, only on the backup_history
        # row (by id) or the literal filename returned here, both matched
        # verbatim regardless of what the stamp says. The numeric
        # +HHMM/-HHMM offset (not a zone abbreviation) keeps this
        # filesystem-safe and unambiguous even without tzdata available.
        stamp = dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S%z")
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
        if purpose and purpose != "manual":
            message = f"[{purpose}] {message}"
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


def _validate_upload_filename(filename: str) -> str:
    safe_name = Path(filename).name or "uploaded-backup.tar.gz"
    if not (safe_name.endswith(".tar.gz") or safe_name.endswith(".tar.gz.enc")):
        raise BackupError("uploaded backup must be a .tar.gz or .tar.gz.enc file")
    return safe_name


def stage_import(filename: str, data: bytes, conn: sqlite3.Connection | None = None) -> Path:
    """Synchronous, buffer-based staging path kept for tests and any
    non-streaming/CLI caller that already holds the archive in memory.
    Production web uploads use begin_streamed_upload()/
    finalize_streamed_upload() instead, which never buffer the whole
    archive in the web process. Both paths enforce the same size policy
    (max_upload_bytes(), separate from app/importer.py's 10 MiB text/
    spreadsheet import cap) and write with restrictive permissions from the
    first byte, never a world/group-readable temp file."""
    if not data:
        raise BackupError("uploaded file is empty")
    safe_name = _validate_upload_filename(filename)
    max_bytes = max_upload_bytes(conn)
    if len(data) > max_bytes:
        raise BackupError(f"uploaded backup exceeds the {max_bytes // (1024 * 1024)} MiB backup upload limit")
    IMPORTS_DIR.mkdir(parents=True, exist_ok=True)
    _check_free_space(int(len(data) * FREE_SPACE_UPLOAD_MULTIPLIER), IMPORTS_DIR)
    dest = IMPORTS_DIR / f"{int(time.time())}-{safe_name}"
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    os.chmod(dest, 0o640)
    return dest


def begin_streamed_upload(filename: str, content_length_hint: int | None = None, conn: sqlite3.Connection | None = None) -> tuple[Path, int, str]:
    """Start a bounded-memory, chunked upload: creates an empty 0600 temp
    file confined to IMPORTS_DIR and returns (tmp_path, max_bytes,
    safe_name) for the caller (an async web route) to stream chunks into.
    No filesystem destination is ever derived from user input beyond the
    basename used for the final, timestamp-prefixed filename -- the
    directory is always IMPORTS_DIR, never a user-supplied path.

    content_length_hint, when the client supplied a Content-Length header,
    lets an oversized upload be rejected before any bytes are written; the
    per-chunk counter in finalize enforces the real limit regardless of
    whether a (possibly absent or inaccurate, e.g. for chunked/multipart
    bodies) hint was available."""
    safe_name = _validate_upload_filename(filename)
    max_bytes = max_upload_bytes(conn)
    if content_length_hint is not None and content_length_hint > max_bytes:
        raise BackupError(f"uploaded backup exceeds the {max_bytes // (1024 * 1024)} MiB backup upload limit")
    IMPORTS_DIR.mkdir(parents=True, exist_ok=True)
    required = int(content_length_hint * FREE_SPACE_UPLOAD_MULTIPLIER) if content_length_hint else FREE_SPACE_NO_HINT_CHECK_BYTES
    _check_free_space(required, IMPORTS_DIR)
    fd, tmp_name = tempfile.mkstemp(prefix=".alderpointdns-upload-", dir=str(IMPORTS_DIR))
    os.close(fd)
    os.chmod(tmp_name, 0o600)
    return Path(tmp_name), max_bytes, safe_name


def finalize_streamed_upload(tmp_path: Path, safe_name: str) -> Path:
    """Atomically install a completed streamed upload under its final,
    collision-resistant name and harden its permissions. Called only after
    every chunk has been written and the size limit has been enforced."""
    dest = IMPORTS_DIR / f"{int(time.time())}-{safe_name}"
    os.replace(tmp_path, dest)
    os.chmod(dest, 0o640)
    return dest


def check_upload_free_space(target_dir: Path, remaining_hint: int) -> None:
    """Called periodically (every FREE_SPACE_RECHECK_INTERVAL_BYTES) by the
    web route's chunked-write loop for uploads large enough, or without an
    accurate enough Content-Length, that disk space could still run out
    mid-stream after the initial check in begin_streamed_upload()."""
    _check_free_space(min(remaining_hint, FREE_SPACE_NO_HINT_CHECK_BYTES), target_dir)


def abort_streamed_upload(tmp_path: Path) -> None:
    """Best-effort cleanup for a failed or interrupted streamed upload
    (size exceeded, client disconnect, decode error, etc.)."""
    tmp_path.unlink(missing_ok=True)


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

_REQUIRED_MANIFEST_KEYS = ("backup_format_version", "alderpointdns_app_version", "created_at", "included_components", "sha256_checksums")


def _reject_unsafe_member(member: tarfile.TarInfo, dest_dir: Path) -> None:
    """Members our own create_backup() never produces (symlinks, hardlinks,
    device/fifo/character-special files) and any path that would escape
    dest_dir (absolute paths, ../ traversal, or a traversal hidden behind a
    symlinked intermediate directory) are rejected outright. Every backup
    this code has ever produced contains only plain files and directories,
    so this is not a compatibility risk for legitimate archives -- only for
    a maliciously or corruptly crafted one."""
    name = member.name
    if name.startswith("/") or name.startswith("..") or "/../" in f"/{name}/":
        raise BackupError(f"backup archive contains an unsafe path: {name}")
    resolved = os.path.normpath(os.path.join(str(dest_dir), name))
    if resolved != str(dest_dir) and not resolved.startswith(str(dest_dir) + os.sep):
        raise BackupError(f"backup archive contains a path outside the staging directory: {name}")
    if member.issym() or member.islnk():
        raise BackupError(f"backup archive contains a symlink/hardlink, which is not permitted: {name}")
    if not (member.isfile() or member.isdir()):
        raise BackupError(f"backup archive contains an unsupported member type (device/fifo/special file): {name}")


def _scan_and_extract(tar: tarfile.TarFile, dest_dir: Path, max_extracted_bytes: int) -> None:
    members = tar.getmembers()
    total = 0
    for member in members:
        _reject_unsafe_member(member, dest_dir)
        if member.isfile():
            total += member.size
        if total > max_extracted_bytes:
            raise BackupError(
                f"backup archive's extracted size exceeds the {max_extracted_bytes // (1024 * 1024)} MiB "
                "limit (possible archive bomb); rejecting before writing further data"
            )
    _check_free_space(int(total * FREE_SPACE_EXTRACT_MULTIPLIER), dest_dir)
    # Every member has already been individually validated above; Python's
    # own "data" extraction filter (PEP 706) is applied as defense in depth
    # on top of that explicit allow-list check.
    tar.extractall(dest_dir, members=members, filter="data")


def extract_backup(path: Path, password: str | None, dest_dir: Path, max_extracted_bytes: int | None = None) -> dict[str, Any]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    max_extracted_bytes = max_extracted_bytes if max_extracted_bytes is not None else max_extracted_bytes_setting()
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
        with tarfile.open(source, "r:gz") as tar:
            # Fail fast on anything that isn't recognizably an Alderpoint DNS
            # native backup before extracting a single byte of file content.
            manifest_member = None
            for candidate in ("manifest.json", "./manifest.json"):
                try:
                    manifest_member = tar.getmember(candidate)
                    break
                except KeyError:
                    continue
            if manifest_member is None:
                raise BackupError("not an Alderpoint DNS native backup archive (missing manifest.json)")
            manifest_fh = tar.extractfile(manifest_member)
            if manifest_fh is None:
                raise BackupError("not an Alderpoint DNS native backup archive (manifest.json is not a regular file)")
            try:
                manifest = json.loads(manifest_fh.read().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise BackupError(f"backup manifest is not valid JSON: {exc}") from None
            missing_keys = [key for key in _REQUIRED_MANIFEST_KEYS if key not in manifest]
            if missing_keys:
                raise BackupError(f"backup manifest is missing required field(s): {', '.join(missing_keys)}")
            _scan_and_extract(tar, dest_dir, max_extracted_bytes)
    except tarfile.ReadError as exc:
        raise BackupError(f"backup archive is corrupt, truncated, or the password is wrong: {exc}") from None
    except (tarfile.ExtractError, tarfile.FilterError) as exc:
        raise BackupError(f"backup archive rejected by safe-extraction checks: {exc}") from None
    except EOFError as exc:
        raise BackupError(f"backup archive is truncated: {exc}") from None
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
        raise BackupError("backup integrity check failed (truncated/corrupt/tampered archive): " + "; ".join(mismatches[:10]))
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
        component_status = [
            {"key": key, "label": key.replace("_", " ").title(), "included": key in included}
            for key in COMPONENT_KEYS
        ]

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
            "component_status": component_status,
            "archive_size_bytes": path.stat().st_size,
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


# ---------------------------------------------------------------------------
# Runtime ownership normalization for restored files
#
# `tar.extractall(..., filter="data")` (see _scan_and_extract) deliberately
# ignores whatever uid/gid a backup archive's members claim -- trusting
# archive-supplied numeric ownership would let a backup file dictate
# arbitrary on-disk ownership on restore, and every extracted file instead
# ends up owned by the extracting process itself: root:root, since restore
# always runs as root. A backup archive's numeric ownership would not be
# portable across appliances even if it *were* trusted: system accounts
# like `_dnsdist`/`bind`/`alderpointdns` are created with `adduser
# --system`, which allocates the next available UID/GID independently on
# each install, so the same *name* can hold a different numeric ID on the
# appliance a backup came from than on the one it's restored to.
#
# The pre-1.0.1 restore code mirrored whatever ownership the *staged,
# already-extracted* file happened to have (root:root, per the above)
# straight onto the live destination -- correct for the many restored
# paths that genuinely are root:root (dnsdist.conf, /etc/bind/*.conf,
# systemd units, sudoers.d/alderpointdns, compiled BIND content: none of
# these need a second system account to read them, and BIND/systemd/sudo
# themselves read their own config as root before dropping privileges),
# but silently wrong for the small set of files that are intentionally
# NOT root:root because a *different*, unprivileged system account must
# be able to read them directly: dnsdist's TLS private key (must be
# readable by the `_dnsdist` account dnsdist actually runs as) and
# alderpointdns's own session/API secrets (must be readable by the
# `alderpointdns` account the web app itself runs as). This is the exact
# failure found on a real restore: a restored TLS private key landed
# root:root 0640, `dnsdist --check-config` validated it fine (config
# syntax doesn't care who can read a referenced file), but the live
# `_dnsdist`-user daemon then failed to start with "Permission denied"
# opening it.
#
# RUNTIME_OWNERSHIP_POLICY is therefore consulted *by name*, resolved
# fresh on the destination appliance via shutil.chown, never by copying a
# numeric uid/gid from anywhere -- correct regardless of what UID/GID
# those accounts happen to be allocated locally. A path with no policy
# entry falls back to mirroring the staged file's ownership (root:root,
# already safe and correct for those paths).
def _runtime_ownership_for(dest: Path) -> tuple[str, str, int] | None:
    """(owner, group, mode) `dest` must have on this appliance for its
    actual runtime reader to work, or None if extraction's default
    root:root is already correct for it. Mirrors the exact policy
    app/encryption.py's _write_owned()/ensure_local_ca()/
    ensure_dnscrypt_provider_keys() and packaging/debian/postinst apply
    when these files are first created (see docs/security.md)."""
    if dest.parent == CERT_DIR:
        # CA private key and the DNSCrypt *provider* (issuing) private key
        # are never loaded by the live dnsdist process -- only used
        # offline to sign/issue other material -- so, like every other
        # root-owned secret in this table, they stay root:root, most
        # restrictive.
        if dest.name in ("alderpointdns-ca.key", "dnscrypt-provider.private"):
            return ("root", "root", 0o600)
        if dest.suffix in (".key", ".private"):
            # The TLS-serving key, the uploaded key, and the DNSCrypt
            # resolver key are all opened directly by the live dnsdist
            # process.
            return ("root", "_dnsdist", 0o640)
        return ("root", "_dnsdist", 0o644)  # certs/public keys/serial file: not secret, but match creation-time group for consistency
    if dest in (SECRETS_ENV, DNSDIST_API_KEY, DNSDIST_WEB_CREDS):
        # Read directly by the unprivileged alderpointdns.service process
        # itself (session secret at startup, dnsdist API/web credentials
        # for its own outbound calls to dnsdist) -- see app/webapp.py's
        # SECRET_FILE handling.
        return ("root", "alderpointdns", 0o640)
    if dest == COMPILED_DIR:
        return ("alderpointdns", "alderpointdns", 0o755)
    return None


def _apply_runtime_ownership(dest: Path) -> None:
    policy = _runtime_ownership_for(dest)
    if policy is None:
        return
    owner, group, mode = policy
    try:
        shutil.chown(dest, user=owner, group=group)
    except (LookupError, PermissionError, OSError):
        pass
    try:
        os.chmod(dest, mode)
    except OSError:
        pass


def _apply_runtime_ownership_recursive(path: Path) -> None:
    """Used after rollback moves a pre-restore backup back into place: even
    though a plain move preserves whatever ownership that backup already
    had (normally already correct, since it was the live file before the
    restore attempted to replace it), re-normalizing here too means
    rollback's guarantee -- "this appliance's runtime accounts can read
    what they need" -- does not silently depend on the pre-restore state
    having been correct in the first place."""
    if not path.exists():
        return
    if path.is_dir():
        for root, _dirs, files in os.walk(path):
            root_path = Path(root)
            _apply_runtime_ownership(root_path)
            for name in files:
                _apply_runtime_ownership(root_path / name)
    else:
        _apply_runtime_ownership(path)


def _verify_runtime_readable(path: Path, user: str) -> bool:
    """Prove, via a real subprocess actually running as `user`, that the
    account can open `path` for reading -- the only reliable way to
    validate this. Reimplementing Unix permission-bit logic in Python
    would mean separately handling owner/group/other bits and
    supplementary group membership, and could silently drift from what
    the kernel actually enforces; asking the kernel directly, as the real
    account, cannot drift. `dnsdist --check-config`/`named-checkconf`
    validate only config *syntax* -- they do not open referenced files as
    the account that will actually need to read them at runtime, which is
    exactly the gap a real restore hit: a private key landed root:root,
    config validation passed, and the live `_dnsdist`-user daemon then
    failed at startup with "Permission denied".

    Restore always runs as root, so `sudo -u <user> -g <user>` needs no
    extra sudoers entry (root can already run as any user); this never
    logs or returns file content, only whether the open succeeded."""
    proc = run(["sudo", "-u", user, "-g", user, "--", "/usr/bin/test", "-r", str(path)], check=False)
    return proc.returncode == 0


def _copy_with_ownership(src: str | Path, dest: str | Path) -> None:
    """shutil.copy2 preserves content/mode/times but NOT owner/group, which
    matters here: e.g. dnsdist.conf must stay root:root (see
    _runtime_ownership_for's module docstring) or a handful of runtime-
    read files must land owned by the specific unprivileged account that
    actually reads them, or the corresponding service cannot start after
    a restore. Accepts str paths too, since shutil.copytree's
    copy_function callback is invoked with strings, not Path objects."""
    shutil.copy2(src, dest)
    dest_path = Path(dest)
    if _runtime_ownership_for(dest_path) is not None:
        _apply_runtime_ownership(dest_path)
        return
    # No specific policy for this path: mirror the staged (already
    # extracted, therefore already root:root-safe) file's ownership, as
    # before.
    src_stat = os.stat(src)
    try:
        os.chown(dest, src_stat.st_uid, src_stat.st_gid)
    except (PermissionError, LookupError):
        pass


def _copytree_with_ownership(src: Path, dest: Path) -> None:
    shutil.copytree(src, dest, copy_function=_copy_with_ownership)
    for root, _dirs, _files in os.walk(dest):
        root_path = Path(root)
        if _runtime_ownership_for(root_path) is not None:
            _apply_runtime_ownership(root_path)
            continue
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
                # Same normalization forward restore applies (see
                # _runtime_ownership_for's docstring) -- a plain move
                # preserves whatever ownership the pre-restore file
                # already had, which is normally already correct, but
                # rollback's guarantee that this appliance's runtime
                # accounts can read what they need should not silently
                # depend on that having been true beforehand.
                _apply_runtime_ownership_recursive(live)
        except Exception:
            continue


# Row-count threshold above which a table is copied in committed chunks
# (with heartbeat/progress between them) instead of one uncommitted
# DELETE+INSERT. Profiling against a synthetic 2.8M-row query_events table
# (docs/backup-recovery.md "Large analytics restore" section) showed the
# straight INSERT...SELECT itself is fast (tens of thousands of rows/sec,
# unindexed-lookup-free -- EXPLAIN QUERY PLAN shows a plain table scan); the
# real forensic failure mode was a single, multi-hour, *never-committed*
# transaction with no observable progress and no way to tell "still working"
# from "abandoned" if the process died.
#
# Chunking here commits independently per chunk -- fine because, per the
# staged/atomic-promotion architecture below, this always targets a private
# WORKING database copy that nothing else can see or write to, never the
# live database directly. A partially-merged working db from an interrupted
# chunk sequence is simply discarded; the live db is untouched until the
# separate, all-or-nothing promotion step at the very end.
CHUNK_ROW_THRESHOLD = 50_000
CHUNK_SIZE = 200_000

# Filename (inside a restore's own staging subdirectory) for the private
# working copy of the live database. Kept inside STAGING_DIR/<tmp>/ (not a
# top-level name) so the existing per-restore staging_dir tracking and
# _cleanup_abandoned_staging() confinement already cover discarding it if
# the restore is abandoned before promotion -- no separate cleanup path
# needed.
WORKING_DB_FILENAME = "working.db"

# Phases reachable only once the atomic database swap has already
# committed. reap_abandoned_restores() also consults promoted_at directly
# (the authoritative signal); this set exists for callers/tests that want
# to reason about phase names specifically.
PROMOTION_COMMITTED_PHASES = frozenset({"promoted", "restarting_services", "postcheck"})


def _create_working_db(dest: Path) -> None:
    """Creates a private, consistent working copy of the live database using
    SQLite's own online backup API (Connection.backup(), the same mechanism
    sqlite_backup_copy() uses for regular backup creation) -- safe against a
    live, concurrently-written WAL-mode database, unlike a raw file copy
    (which could copy a torn mix of main-db-file and in-flight WAL
    content). Every expensive merge in this restore happens against this
    copy; the live database file is not opened for writing again until the
    brief, already-validated final promotion."""
    if dest.exists():
        dest.unlink()
    src = connect()
    try:
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def _checkpoint_and_remove_wal(db_path: Path) -> None:
    """Folds a WAL-mode database's WAL file fully into its main file and
    removes the (now-empty) -wal/-shm sidecars. Required before either side
    of the promotion swap: the atomic rename below only replaces the single
    main db file, so anything still sitting in a WAL/SHM sidecar would
    silently vanish (if left behind by the old file) or point at content
    that no longer matches the new main file's header/salt (if a stale
    sidecar were left at the destination path) -- either way, exactly the
    "ambiguous mixture of old DB/new WAL or new DB/old WAL" this exists to
    prevent."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(db_path) + suffix)
        if sidecar.exists():
            try:
                sidecar.unlink()
            except OSError:
                pass


def _acquire_exclusive_live_lock(timeout: float = 30.0) -> sqlite3.Connection:
    """Opens a dedicated connection to the live database and forces it to
    hold an OS-level exclusive lock (PRAGMA locking_mode=EXCLUSIVE plus a
    no-op immediate write transaction to force acquisition rather than
    waiting for the first real access), retrying with backoff. This is the
    actual writer-quiescing mechanism for the brief promotion window: every
    real writer of this database -- the web app, the analytics collector,
    and every scheduled backup/filter-update/notify/software-update-check
    timer job -- opens a fresh connection per operation rather than holding
    one open (see app/webapp.py's db()), so while this lock is held, any of
    their writes blocks (and ultimately fails via its own busy_timeout)
    until this connection is closed. In WAL mode, EXCLUSIVE locking mode
    additionally blocks other connections' *reads*, not just writes, for
    the same reason.

    Deliberately NOT implemented via `systemctl stop alderpointdns.service`:
    this code runs as (or as a descendant of) that very service's
    sudo-escalated privileged helper, and systemd's default
    KillMode=control-group sends a stop's SIGTERM to every process in the
    unit's cgroup -- including this restore worker itself. Stopping
    alderpointdns-analytics.service (a separate unit, safe to stop from
    here) is still done as a courtesy alongside this to cut down on wasted
    retries, but SQLite's own locking is what actually guarantees
    exclusivity, uniformly, for every writer above without needing to
    enumerate each one -- including ones (the timer-triggered oneshots)
    this code never explicitly names."""
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        conn = connect()
        try:
            conn.execute("PRAGMA locking_mode=EXCLUSIVE")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("COMMIT")
            return conn
        except sqlite3.OperationalError as exc:
            last_exc = exc
            conn.close()
            time.sleep(0.5)
    raise BackupError(f"could not acquire exclusive access to the live database for promotion: {last_exc}")


def _resync_live_state_into_working(live_conn: sqlite3.Connection, working_db_path: Path, merged_tables: list[str]) -> None:
    """Copies the CURRENT content of every table NOT touched by the
    backup-archive merge (excluded/unselected components, and this
    restore's own bookkeeping tables -- backup_history, restore_history,
    backup_requests, backup_settings, always excluded from the archive
    merge itself) from the live database into the working copy, immediately
    before promotion.

    The working copy was snapshotted before the (potentially lengthy)
    merge began; anything the live database's *other* writers did in the
    meantime -- new sessions, new analytics rows if analytics_history
    wasn't part of this restore, another admin's edits, this restore's own
    progress updates -- would otherwise be silently lost when the working
    copy becomes the new live file. Must be called while `live_conn` holds
    the exclusive lock from _acquire_exclusive_live_lock(), so this read is
    a final, consistent snapshot taken immediately before the swap, not
    just "reasonably recent"."""
    live_conn.execute("ATTACH DATABASE ? AS workingdb", (str(working_db_path),))
    try:
        merged = set(merged_tables)
        live_tables = {row[0] for row in live_conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        working_tables = {row[0] for row in live_conn.execute("SELECT name FROM workingdb.sqlite_master WHERE type='table'")}
        for table in sorted((live_tables - merged) & working_tables):
            live_conn.execute(f"DELETE FROM workingdb.{table}")
            live_conn.execute(f"INSERT INTO workingdb.{table} SELECT * FROM main.{table}")
        live_conn.commit()
    finally:
        live_conn.execute("DETACH DATABASE workingdb")


def _promote_working_db(live_lock: sqlite3.Connection, working_db_path: Path, live_db_path: Path) -> None:
    """Atomically replaces the live database file with the fully validated
    working copy. Must be called only while `live_lock` (from
    _acquire_exclusive_live_lock()) is still open -- callers close it
    (releasing the lock) only after this returns. Preconditions the caller
    is responsible for: the working copy has already passed PRAGMA
    quick_check, and _resync_live_state_into_working() has already been
    run against it.

    The live database's own checkpoint is done through `live_lock` itself,
    not a second, separate connection: a fresh sqlite3.connect() to the
    same file would itself be blocked by (or block) the exclusive lock
    `live_lock` is holding -- a real bug caught by an interruption test
    against this exact function, not by inspection.

    Uses a plain filesystem rename (os.replace), not a SQLite-level
    mechanism, for the swap itself: POSIX rename() on the same filesystem
    is atomic (any process opening the path mid-rename gets either the
    fully-old or fully-new file, never a torn mix), and by this point both
    databases have already been checkpointed to a single main file with no
    outstanding WAL -- so there is no sidecar file that could end up
    mismatched with whichever main file ends up at this path."""
    live_lock.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    _checkpoint_and_remove_wal(working_db_path)
    live_stat = live_db_path.stat()
    os.replace(working_db_path, live_db_path)
    try:
        os.chown(live_db_path, live_stat.st_uid, live_stat.st_gid)
    except (PermissionError, OSError):
        pass
    try:
        os.chmod(live_db_path, stat.S_IMODE(live_stat.st_mode))
    except OSError:
        pass
    # Belt-and-suspenders: the checkpoint above already truncated these to
    # nothing, but remove them outright so a fresh connection never has any
    # sidecar to reconcile against the just-promoted main file.
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(live_db_path) + suffix)
        if sidecar.exists():
            try:
                sidecar.unlink()
            except OSError:
                pass


def _integer_pk_column(live_conn: sqlite3.Connection, table: str) -> str | None:
    """The single INTEGER PRIMARY KEY column (a rowid alias), if any --
    chunking by contiguous id ranges only works for such a column, since
    it's the one column SQLite can range-scan via its own rowid btree
    without a separate index and without OFFSET's linear skip cost."""
    pk_cols = [row["name"] for row in live_conn.execute(f"PRAGMA table_info({table})") if row["pk"] == 1]
    if len(pk_cols) != 1:
        return None
    col = pk_cols[0]
    col_type = next(row["type"] for row in live_conn.execute(f"PRAGMA table_info({table})") if row["name"] == col)
    return col if col_type.upper() in ("INTEGER", "INT") else None


def _merge_database(
    staged_db: Path,
    components: dict[str, bool],
    target_db_path: Path,
    progress_cb: Callable[[str, str, int, int], None] | None = None,
) -> list[str]:
    """Merge selected tables from a backed-up database copy into
    `target_db_path`, table by table, via ATTACH + per-table replace.
    Tables mapped in TABLE_COMPONENT_MAP are gated only by their own
    specific component flag; every other table is gated by the broad
    ``sqlite_data`` flag. This intentionally allows restoring a single
    narrow table (e.g. just custom_rules) even when sqlite_data is off, so
    a restore never has to touch tables an operator did not select. See
    the module docstring.

    `target_db_path` is always the restore's private working database copy
    (see _create_working_db()/restore_backup()'s staged/atomic-promotion
    architecture) -- never the live database directly. Large tables are
    always copied in independently committed chunks (see
    CHUNK_ROW_THRESHOLD) for real mid-restore progress; this is safe here
    specifically *because* nothing else can see or write to a private
    working copy, unlike the live database, which real concurrent writers
    (the web app, the analytics collector) do touch. A stress test against
    a concurrent writer reproduced a real UNIQUE-constraint failure when an
    earlier version of this function chunked directly against the live
    database -- see docs/backup-recovery.md "Large analytics restore".

    `progress_cb(phase, table, current, total)` is called before/after each
    table (and, for large chunked tables, between chunks) so a caller can
    surface durable heartbeat/progress."""
    if not staged_db.exists():
        return []
    merged_tables: list[str] = []
    target_conn = sqlite3.connect(target_db_path, timeout=5.0)
    target_conn.row_factory = sqlite3.Row
    try:
        target_conn.execute("ATTACH DATABASE ? AS backupdb", (str(staged_db),))
        try:
            backup_tables = {
                row[0]
                for row in target_conn.execute("SELECT name FROM backupdb.sqlite_master WHERE type='table'")
            }
            for table in sorted(backup_tables):
                if table in TABLES_EXCLUDED_FROM_RESTORE:
                    continue
                gating_component = TABLE_COMPONENT_MAP.get(table, "sqlite_data")
                if not components.get(gating_component, True):
                    continue
                target_tables = {row[0] for row in target_conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if table not in target_tables:
                    continue
                # Copy only the columns both schemas share, named explicitly.
                # A bare `INSERT ... SELECT *` breaks as soon as a schema
                # migration adds a column (e.g. deployments.trigger for
                # scheduled filter updates, import_jobs.source_path): an
                # archive taken before the migration then has fewer columns
                # than the target table and SQLite rejects the insert,
                # failing an otherwise valid restore. Columns missing from
                # the archive keep their column default.
                target_columns = [row["name"] for row in target_conn.execute(f"PRAGMA table_info({table})")]
                archive_columns = {row["name"] for row in target_conn.execute(f"PRAGMA backupdb.table_info({table})")}
                shared = [name for name in target_columns if name in archive_columns]
                if not shared:
                    continue
                column_list = ", ".join(f'"{name}"' for name in shared)
                phase = "restoring_analytics" if gating_component == "analytics_history" else "restoring_database"
                row_count = target_conn.execute(f"SELECT count(*) FROM backupdb.{table}").fetchone()[0]
                pk_col = _integer_pk_column(target_conn, table)
                if progress_cb:
                    progress_cb(phase, table, 0, row_count)
                target_conn.execute(f"DELETE FROM {table}")
                if pk_col and row_count > CHUNK_ROW_THRESHOLD:
                    copied = 0
                    id_range = target_conn.execute(f'SELECT min("{pk_col}"), max("{pk_col}") FROM backupdb.{table}').fetchone()
                    lo, hi = id_range[0], id_range[1]
                    target_conn.commit()  # commit the DELETE alone before starting committed chunks
                    window_start = lo
                    while window_start <= hi:
                        window_end = min(window_start + CHUNK_SIZE - 1, hi)
                        target_conn.execute(
                            f'INSERT INTO {table}({column_list}) SELECT {column_list} FROM backupdb.{table} '
                            f'WHERE "{pk_col}" BETWEEN ? AND ?',
                            (window_start, window_end),
                        )
                        target_conn.commit()
                        copied = target_conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                        if progress_cb:
                            progress_cb(phase, table, copied, row_count)
                        window_start = window_end + 1
                else:
                    target_conn.execute(f"INSERT INTO {table}({column_list}) SELECT {column_list} FROM backupdb.{table}")
                    target_conn.commit()
                    copied = row_count
                if copied != row_count:
                    raise BackupError(f"restore merge for table {table!r} copied {copied} of {row_count} expected rows")
                if progress_cb:
                    progress_cb(phase, table, row_count, row_count)
                merged_tables.append(table)
        finally:
            target_conn.execute("DETACH DATABASE backupdb")
            target_conn.commit()
    finally:
        target_conn.close()
    return merged_tables


def restore_backup(path: Path, password: str | None, components: dict[str, bool] | None, conn: sqlite3.Connection | None = None) -> int:
    """Staged/atomic-promotion restore. The database side of a restore never
    touches the live database until a single, brief, already-fully-validated
    promotion step at the very end:

      1. pre-restore safety backup (unchanged)
      2. filesystem components staged -> backed up -> live, validated,
         named/dnsdist restarted (unchanged in spirit; still individually
         rollback-able via file_backups/_rollback_paths)
      3. a private WORKING COPY of the live database is made
         (_create_working_db, SQLite's own online backup API)
      4. every selected table is merged from the backup archive into that
         working copy -- never the live db -- in independently committed
         chunks for real progress on large tables (see _merge_database)
      5. PRAGMA quick_check runs against the working copy
      6. only once all of the above has succeeded: every other writer is
         quiesced (_acquire_exclusive_live_lock), the *current* live state
         of every table NOT touched by the merge is copied into the working
         copy (_resync_live_state_into_working, closing the gap between
         when the working copy was snapshotted and now), both databases are
         checkpointed to a single file, and the working copy atomically
         replaces the live file (_promote_working_db)
      7. services are restarted and DNS is health-checked

    A restore interrupted at any point before step 6's swap leaves the live
    database completely untouched -- there is nothing to roll back, because
    nothing was ever changed. A restore interrupted during or after the
    swap has already committed its (already-validated) database changes;
    see the `promoted` handling in the except block below for why that
    case does not attempt an automatic *data* rollback."""
    close = conn is None
    db = conn or connect()
    init_db(db)
    # Reap anything left stuck 'running' from a previous, now-dead worker
    # before starting a new restore -- otherwise last_restore()/the UI would
    # keep reporting a phantom in-progress restore alongside this real one.
    reap_abandoned_restores(db)
    components = validate_components(components)
    started = now()
    worker_pid, worker_start_ticks, worker_boot_id = _worker_identity()
    cursor = db.execute(
        "INSERT INTO restore_history(started_at, backup_path, components_json, status, message, worker_pid, worker_start_ticks, worker_boot_id, heartbeat_at, phase) "
        "VALUES (?, ?, ?, 'running', '', ?, ?, ?, ?, 'validating')",
        (started, str(path), json.dumps(components), worker_pid, worker_start_ticks, worker_boot_id, started),
    )
    restore_id = cursor.lastrowid
    db.commit()

    def touch(phase: str | None = None, detail: str | None = None, current: int | None = None, total: int | None = None, staging_dir: str | None = None, promoted: bool = False, pre_restore_backup_path: str | None = None) -> None:
        _touch_restore(db, restore_id, phase=phase, detail=detail, current=current, total=total, staging_dir=staging_dir, promoted=promoted, pre_restore_backup_path=pre_restore_backup_path)

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
    restored_dnsdist_key_paths: list[Path] = []
    restored_alderpointdns_secret_paths: list[Path] = []
    db_touched = False
    analytics_collector_paused = False
    promoted = False  # the one bit that decides which failure branch below applies
    db_reopened_after_lock = False  # once true, `db` is always ours to close, regardless of `close`

    with tempfile.TemporaryDirectory(dir=str(STAGING_DIR)) as tmp:
        extract_dir = Path(tmp) / "extract"
        working_db_path = Path(tmp) / WORKING_DB_FILENAME
        touch(phase="extracting", staging_dir=tmp)
        try:
            manifest = extract_backup(path, password, extract_dir)
            fmt_version = manifest.get("backup_format_version")
            if fmt_version != BACKUP_FORMAT_VERSION:
                raise BackupError(
                    f"backup_format_version {fmt_version!r} is not compatible with this install's "
                    f"format version {BACKUP_FORMAT_VERSION}; preview the backup for full compatibility "
                    "details before restoring"
                )
            available = set(manifest.get("included_components", []))
            effective = {key: bool(components.get(key)) and key in available for key in COMPONENT_KEYS}

            # A pre-restore safety net: always take a full backup of the
            # current live state before changing anything, unless the
            # request explicitly targets nothing at all.
            touch(phase="pre_restore_backup")
            try:
                pre_restore_backup_path = create_backup(dict.fromkeys(COMPONENT_KEYS, True), password=None, conn=db)
            except Exception as exc:
                raise BackupError(f"could not take pre-restore safety backup, aborting restore: {exc}") from None
            touch(pre_restore_backup_path=str(pre_restore_backup_path))

            touch(phase="restoring_configuration")
            # Every extract_dir / "..." lookup below is built from the same
            # module-level path constants select_files() uses to decide
            # what goes *into* the archive in the first place
            # (entries[str(path.relative_to("/"))] = path) -- never a
            # separately hardcoded string literal. Keeping restore's read
            # side and create_backup's write side derived from one shared
            # source of truth means they cannot silently drift apart, and
            # (this is what surfaced the drift) lets tests that redirect
            # these constants to an isolated tmp sandbox actually exercise
            # this code path at all, rather than every staged.exists()
            # check below silently evaluating False against a path that
            # only ever matched the real, unredirected production layout.
            compiled_source = extract_dir / COMPILED_DIR.relative_to("/")
            rpz_zone_label = "alderpointdns.rpz"

            # Cheap standalone pre-activation checks (no include resolution
            # needed): validate any staged zone files in isolation before
            # touching anything live.
            for zone_file in sorted((compiled_source / "bind").glob("**/*.rpz")) if effective.get("app_config") else []:
                run(["named-checkzone", rpz_zone_label, str(zone_file)])
                validation_output += f"named-checkzone {zone_file.name}: ok\n"

            # Stage -> backup -> atomically activate each selected, present
            # filesystem component. Individually rollback-able via
            # file_backups regardless of what happens to the database below
            # -- this part of a restore was never the source of the
            # multi-hour hang this architecture responds to, and keeps its
            # existing direct-to-live-with-per-file-backup shape.
            if effective.get("app_config"):
                staged_compiled = compiled_source
                _replace_path(COMPILED_DIR, staged_compiled, file_backups)
                for name in ("alderpointdns.service", "alderpointdns-analytics.service"):
                    staged = extract_dir / SYSTEMD_DIR.relative_to("/") / name
                    if staged.exists():
                        _replace_path(SYSTEMD_DIR / name, staged, file_backups)
                        systemd_touched = True
                for name in ("alderpointdns.service.d", "alderpointdns-analytics.service.d", "dnsdist.service.d"):
                    staged = extract_dir / SYSTEMD_DIR.relative_to("/") / name
                    if staged.exists():
                        _replace_path(SYSTEMD_DIR / name, staged, file_backups)
                        systemd_touched = True
                        if name == "dnsdist.service.d":
                            dnsdist_touched = True
                staged_sudoers = extract_dir / SUDOERS_FILE.relative_to("/")
                if staged_sudoers.exists():
                    _replace_path(SUDOERS_FILE, staged_sudoers, file_backups)
                named_touched = True

            if effective.get("local_dns_zones"):
                staged = extract_dir / LOCAL_ZONE_DIR.relative_to("/")
                if staged.exists():
                    _replace_path(LOCAL_ZONE_DIR, staged, file_backups)
                    named_touched = True
                staged_conf = extract_dir / LOCAL_ZONES_CONF.relative_to("/")
                if staged_conf.exists():
                    _replace_path(LOCAL_ZONES_CONF, staged_conf, file_backups)
                    named_touched = True

            if effective.get("last_downloaded_lists"):
                staged = extract_dir / DOWNLOADS_DIR.relative_to("/")
                _replace_path(DOWNLOADS_DIR, staged, file_backups)

            if effective.get("dnsdist_source_config"):
                staged = extract_dir / DNSDIST_CONF.relative_to("/")
                if staged.exists():
                    _replace_path(DNSDIST_CONF, staged, file_backups)
                    dnsdist_touched = True

            if effective.get("bind_source_config"):
                for name in BIND_CONF_FILES:
                    staged = extract_dir / ETC_BIND.relative_to("/") / name
                    if staged.exists():
                        _replace_path(ETC_BIND / name, staged, file_backups)
                        named_touched = True

            staged_cert_dir = extract_dir / CERT_DIR.relative_to("/")
            if staged_cert_dir.exists():
                for staged_file in sorted(staged_cert_dir.iterdir()):
                    if not staged_file.is_file():
                        continue
                    is_public = staged_file.suffix == ".crt"
                    if is_public and not effective.get("certificates"):
                        continue
                    if not is_public and not effective.get("private_keys"):
                        continue
                    dest = CERT_DIR / staged_file.name
                    _replace_path(dest, staged_file, file_backups)
                    dnsdist_touched = True
                    policy = _runtime_ownership_for(dest)
                    if policy is not None and policy[1] == "_dnsdist" and not is_public:
                        restored_dnsdist_key_paths.append(dest)

            if effective.get("private_keys") or effective.get("user_auth_data"):
                for name in ("secrets.env", "dnsdist-api.key", "dnsdist-web.creds"):
                    staged = extract_dir / ETC_ALDERPOINTDNS.relative_to("/") / name
                    if staged.exists():
                        dest = ETC_ALDERPOINTDNS / name
                        _replace_path(dest, staged, file_backups)
                        restored_alderpointdns_secret_paths.append(dest)

            # File-component validation and named/dnsdist restart happen
            # here, still entirely before the database is touched in any
            # way -- if any of this fails, the except block below rolls
            # back exactly the file changes made above and the live
            # database is never even opened for writing.
            if named_touched:
                proc = run(["named-checkconf", "-p", "/etc/bind/named.conf"])
                validation_output += proc.stdout
            if dnsdist_touched:
                proc = run(["dnsdist", "--check-config", "-C", str(DNSDIST_CONF)])
                validation_output += proc.stdout
            if SUDOERS_FILE.exists():
                proc = run(["visudo", "-cf", str(SUDOERS_FILE)])
                validation_output += proc.stdout
            # `dnsdist --check-config`/`named-checkconf` above only prove
            # the config is syntactically valid -- not that the runtime
            # account actually reads it. This is the exact validation gap
            # a real restore hit: a private key landed root:root, config
            # validation passed, and the live _dnsdist-user daemon then
            # failed at startup with "Permission denied". Prove the real
            # runtime identity can actually open every restored secret
            # this restore just wrote, before committing to a restart --
            # never by re-deriving Unix permission-bit logic in Python
            # (owner/group/other bits, supplementary group membership),
            # which could silently drift from what the kernel enforces,
            # but by asking the kernel directly via a real subprocess
            # running as that account. See _verify_runtime_readable's
            # docstring; never logs file *content*, only path + pass/fail.
            for key_path in restored_dnsdist_key_paths:
                if not key_path.exists():
                    continue
                readable = _verify_runtime_readable(key_path, "_dnsdist")
                validation_output += f"dnsdist runtime-read check for {key_path.name}: {'ok' if readable else 'FAILED'}\n"
                if not readable:
                    raise RuntimeError(
                        f"restored private key {key_path.name} is not readable by the dnsdist runtime "
                        "user (_dnsdist) after ownership normalization -- refusing to restart dnsdist"
                    )
            for secret_path in restored_alderpointdns_secret_paths:
                if not secret_path.exists():
                    continue
                readable = _verify_runtime_readable(secret_path, "alderpointdns")
                validation_output += f"alderpointdns runtime-read check for {secret_path.name}: {'ok' if readable else 'FAILED'}\n"
                if not readable:
                    raise RuntimeError(
                        f"restored secret {secret_path.name} is not readable by the alderpointdns runtime "
                        "user after ownership normalization -- refusing to proceed"
                    )
            if systemd_touched:
                run(["systemctl", "daemon-reload"])
            if named_touched:
                run(["systemctl", "restart", "named"])
                if not _wait_active("named", timeout=20):
                    raise RuntimeError("named did not become active after restore")
            if dnsdist_touched:
                run(["systemctl", "restart", "dnsdist"])
                if not _wait_active("dnsdist", timeout=20):
                    raise RuntimeError("dnsdist did not become active after restore")

            # ---- database: staged merge against a private working copy ----
            staged_db = extract_dir / DB_ARCHIVE_RELPATH
            if staged_db.exists():
                touch(phase="preparing_working_db")
                _create_working_db(working_db_path)

                # Best-effort courtesy stop, purely to cut down on wasted
                # analytics-writer retries during the exclusive-lock window
                # later -- correctness does not depend on this succeeding;
                # see _acquire_exclusive_live_lock()'s docstring for why
                # alderpointdns.service itself is never stopped this way.
                if effective.get("analytics_history"):
                    run(["systemctl", "stop", "alderpointdns-analytics"], check=False)
                    analytics_collector_paused = True
                    _wait_inactive("alderpointdns-analytics", timeout=10)

                def merge_progress(phase: str, table: str, current: int, total: int) -> None:
                    touch(phase=phase, detail=table, current=current, total=total)
                    pause_marker = os.environ.get("ALDERPOINTDNS_TEST_PAUSE_DURING_MERGE")
                    if pause_marker and 0 < current < total:
                        Path(pause_marker).write_text(now())
                        time.sleep(30)  # long enough for an external test to SIGKILL this process

                merged_tables = _merge_database(staged_db, effective, target_db_path=working_db_path, progress_cb=merge_progress)
                if merged_tables:
                    db_touched = True

                if os.environ.get("ALDERPOINTDNS_TEST_FORCE_RESTORE_FAIL") == "1":
                    raise RuntimeError("forced restore failure for rollback test")

                if db_touched:
                    touch(phase="validating_database")
                    quick_check_conn = sqlite3.connect(working_db_path)
                    try:
                        quick_check_result = quick_check_conn.execute("PRAGMA quick_check").fetchone()[0]
                    finally:
                        quick_check_conn.close()
                    validation_output += f"PRAGMA quick_check (working copy): {quick_check_result}\n"
                    if quick_check_result != "ok":
                        raise RuntimeError(f"working-copy database integrity check failed before promotion: {quick_check_result}")

                    # ---- promotion: the only step allowed to touch the live db file ----
                    touch(phase="promoting")
                    if os.environ.get("ALDERPOINTDNS_TEST_FAIL_BEFORE_PROMOTE") == "1":
                        raise RuntimeError("forced pre-promotion failure for interruption test")
                    pause_marker = os.environ.get("ALDERPOINTDNS_TEST_PAUSE_BEFORE_PROMOTE")
                    if pause_marker:
                        Path(pause_marker).write_text(now())
                        time.sleep(30)  # long enough for an external test to SIGKILL this process
                    # WAL's EXCLUSIVE locking mode requires being the ONLY
                    # open connection to the database file -- even our own
                    # idle bookkeeping connection (`db`) blocks it, not just
                    # other processes' connections. It must be closed
                    # before attempting the lock, and a fresh one opened
                    # again afterward no matter what happens in between
                    # (lock acquired and released cleanly, lock acquisition
                    # itself failed, or promotion failed after acquiring
                    # it) -- every other code path past this point,
                    # including the except/finally blocks below, needs a
                    # working `db` to write through. A caller-supplied
                    # `conn` is closed here too, not just our own: there is
                    # no way to hold the exclusive lock while any
                    # connection to the file remains open, borrowed or not.
                    # process_pending_request() knows to reopen its own
                    # copy unconditionally after calling into a restore for
                    # exactly this reason.
                    db.close()
                    try:
                        live_lock = _acquire_exclusive_live_lock()
                        try:
                            _resync_live_state_into_working(live_lock, working_db_path, merged_tables)
                            if os.environ.get("ALDERPOINTDNS_TEST_FAIL_DURING_PROMOTE") == "1":
                                raise RuntimeError("forced mid-promotion failure for interruption test")
                            _promote_working_db(live_lock, working_db_path, DB_PATH)
                            promoted = True
                        finally:
                            live_lock.close()
                    finally:
                        db = connect()
                        db_reopened_after_lock = True
                    touch(phase="promoted", promoted=True)

            if os.environ.get("ALDERPOINTDNS_TEST_FAIL_AFTER_PROMOTE") == "1" and promoted:
                raise RuntimeError("forced post-promotion failure for interruption test")
            pause_marker = os.environ.get("ALDERPOINTDNS_TEST_PAUSE_AFTER_PROMOTE")
            if pause_marker and promoted:
                Path(pause_marker).write_text(now())
                time.sleep(30)  # long enough for an external test to SIGKILL this process

            touch(phase="restarting_services")
            if db_touched or analytics_collector_paused:
                run(["systemctl", "restart", "alderpointdns-analytics"], check=False)
                analytics_collector_paused = False
            if db_touched or systemd_touched:
                run(["systemctl", "restart", "alderpointdns"], check=False)

            # Reconcile managed upstream DNS resolvers against whatever this
            # restore actually put in place. upstream_resolvers/
            # upstream_deployments aren't in TABLE_COMPONENT_MAP, so they
            # ride along with the broad `sqlite_data` flag specifically (not
            # e.g. `custom_rules` or `local_dns_zones`, which merge their own
            # tables under their own component flags without ever touching
            # sqlite_data-gated tables) -- see _merge_database()'s
            # `TABLE_COMPONENT_MAP.get(table, "sqlite_data")` gating. The
            # *generated* runtime files that must match those rows
            # (compiled/dnsdist/upstream-forwarder.conf,
            # compiled/bind/upstream-forwarders.conf) live under the
            # separately-selectable `app_config` component, and the base
            # configs those generated files get include-wired into live
            # under `dnsdist_source_config`/`bind_source_config`. Any
            # restore that selects one of these without the others -- or a
            # cross-appliance restore where the source and destination
            # appliance simply had different resolver configs at their last
            # deploy -- can leave upstream_resolvers.enabled describing a
            # set of resolvers that no longer matches (or was never applied
            # to) the live dnsdist config. Unconditionally regenerating from
            # the now-restored database, right here, is the same
            # reconciliation the rest of the app already performs after
            # every ordinary upstream edit (see webapp.py's
            # deploy_no_download_or_raise() calls) -- restore must not be a
            # second, divergent path that can silently skip it. Deliberately
            # gated on `effective.get("sqlite_data")` rather than the
            # broader `promoted` flag: `promoted` is true for *any*
            # db-touching restore (e.g. a custom_rules-only restore, whose
            # own gating component is "custom_rules", not "sqlite_data"),
            # and coupling an entirely unrelated restore's success to
            # upstream DNS reachability would itself be a new, needless
            # failure mode this fix must not introduce. A failure here
            # (e.g. every restored resolver being genuinely unreachable
            # from this appliance) is deliberately handled by the same
            # promoted/not-promoted branches below as the plain DNS
            # postcheck a few lines down: never a silent no-op, and never a
            # reason to roll back an already-validated database.
            if effective.get("sqlite_data") or any(effective.get(key) for key in ("app_config", "dnsdist_source_config", "bind_source_config")):
                touch(phase="reconciling_upstream")
                upstream_dns.deploy_upstreams(db)

            touch(phase="postcheck")
            if not resolves("cloudflare.com", "53"):
                raise RuntimeError("post-restore plain DNS functional test failed on port 53")

            status = "deployed"
            message = f"restored components: {', '.join(k for k, v in effective.items() if v)}; merged db tables: {', '.join(merged_tables) if merged_tables else 'none'}"
        except Exception as exc:
            message = str(exc)
            if not promoted:
                # Nothing was ever promoted -- the live database was never
                # opened for writing by this restore. Only the filesystem
                # components (if any) need rolling back.
                touch(phase="failed", detail=message[:200])
                try:
                    _rollback_paths(file_backups)
                    if systemd_touched:
                        run(["systemctl", "daemon-reload"], check=False)
                    if named_touched:
                        run(["systemctl", "restart", "named"], check=False)
                    if dnsdist_touched:
                        run(["systemctl", "restart", "dnsdist"], check=False)
                    if analytics_collector_paused:
                        run(["systemctl", "restart", "alderpointdns-analytics"], check=False)
                        analytics_collector_paused = False
                    if resolves("cloudflare.com", "53"):
                        status = "rolled_back"
                    else:
                        status = "rollback_failed"
                        message = f"{message}; rollback restart did not restore working DNS"
                except Exception as rollback_exc:
                    status = "rollback_failed"
                    message = f"{message}; rollback failed: {rollback_exc}"
            else:
                # The database swap already committed. It was only ever
                # promoted after passing PRAGMA quick_check, so this is a
                # service/health-recovery situation, not a data-integrity
                # one -- automatically reverting an already-validated
                # database because a later, unrelated step (a service
                # restart, the final DNS postcheck) failed would itself be
                # the riskier action. Never pretend a rollback happened
                # when it did not: no data rollback is attempted here.
                touch(phase="promoted_recovery_required", detail=message[:200])
                try:
                    run(["systemctl", "restart", "alderpointdns-analytics"], check=False)
                    analytics_collector_paused = False
                    run(["systemctl", "restart", "alderpointdns"], check=False)
                except Exception:
                    pass
                status = "promoted_recovery_required"
                message = (
                    f"{message}; the database was already promoted to the live file before this failure -- "
                    "it was NOT rolled back (only an already-validated database is ever promoted, so this is "
                    "a service/health-recovery situation, not a data-integrity one). Service restarts were "
                    "attempted automatically; check `systemctl status named dnsdist alderpointdns "
                    "alderpointdns-analytics` and DNS resolution manually. Pre-restore safety backup retained "
                    f"at {pre_restore_backup_path} if you need to manually restore the prior state."
                )
        finally:
            # Belt-and-suspenders: if anything above left the collector
            # paused without reaching a restart call, never leave it
            # stopped -- a restore's failure must not silently disable
            # ongoing analytics collection.
            if analytics_collector_paused:
                run(["systemctl", "restart", "alderpointdns-analytics"], check=False)
            touch(phase="cleanup")
            # tempfile.TemporaryDirectory is about to remove `tmp` (and, if
            # promotion never reached working_db_path, the working copy
            # along with it) on its own __exit__ (we're still inside its
            # `with` block); clear staging_dir now so a later
            # abandoned-restore sweep never tries to rmtree a path that's
            # already gone (harmless either way -- _cleanup_abandoned_staging()
            # no-ops on a missing path -- but this keeps the row accurate
            # for anyone reading it directly).
            terminal_phase = "completed" if status in ("deployed", "unchanged") else status if status == "promoted_recovery_required" else "failed"
            # validation_output includes `named-checkconf -p /etc/bind/named.conf`
            # output, which echoes the fully rendered BIND config verbatim --
            # including any `key "name" { ...; secret "..."; };` block
            # (RNDC/TSIG shared secret) -- so this must never reach SQLite
            # (and therefore the UI's restore history) unredacted. `message`
            # is sanitized too: it can embed subprocess output via an
            # exception's str() (e.g. a CalledProcessError's stdout). Applied
            # to the *full* text before truncation, not after -- truncating
            # first could cut a secret in half and leave a partial match the
            # patterns below no longer recognize.
            db.execute(
                "UPDATE restore_history SET finished_at=?, status=?, message=?, pre_restore_backup_path=?, validation_output=?, phase=?, staging_dir=NULL WHERE id=?",
                (now(), status, _sanitize_secrets(message), str(pre_restore_backup_path) if pre_restore_backup_path else None, _sanitize_secrets(validation_output)[-4000:], terminal_phase, restore_id),
            )
            db.commit()
            _fix_backup_dir_permissions()
            # `close` alone isn't enough here: once the promotion attempt
            # closes the original `db` (see above -- required for the
            # exclusive-lock acquisition, whether or not promotion itself
            # went on to succeed), `db` is unconditionally reassigned to a
            # fresh connection this function opened itself; that one is
            # always ours to close, or a caller-supplied `conn`'s promotion
            # path leaks an fd every restore.
            if close or db_reopened_after_lock:
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


def _wait_inactive(service: str, timeout: int = 10) -> bool:
    """True only once systemctl confirms `service` is fully stopped -- used
    to gate _merge_database's chunked/incrementally-committed path, which
    is only safe with no other writer touching the same tables. Requesting
    a stop is not the same as confirming it happened (the unit could still
    be mid-`ExecStop`, or the request itself could silently no-op)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(["systemctl", "is-active", service], check=False)
        if result.stdout.strip() in ("inactive", "failed"):
            return True
        time.sleep(0.5)
    return run(["systemctl", "is-active", service], check=False).stdout.strip() in ("inactive", "failed")


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
        # Catch an abandoned restore the moment status is viewed, not only
        # at the next application startup -- see reap_abandoned_restores().
        reap_abandoned_restores(db)
        row = db.execute("SELECT * FROM restore_history ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return None
        result = dict(row)
        if result.get("status") == "running":
            heartbeat_at = result.get("heartbeat_at")
            if heartbeat_at:
                try:
                    age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(heartbeat_at)).total_seconds()
                    result["heartbeat_stale_suspected"] = age > STALE_HEARTBEAT_SECONDS
                except ValueError:
                    result["heartbeat_stale_suspected"] = False
            else:
                result["heartbeat_stale_suspected"] = False
        return result
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
    reopened = False
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
        if kind == "restore":
            # restore_backup()'s staged/atomic-promotion architecture may
            # have replaced the live database file out from under `db`
            # partway through the call above (see its docstring) -- `db`
            # was opened before that could happen, so it could now be
            # bound to a stale, unlinked inode. Reopen unconditionally
            # before the writes below: cheap, and correct whether or not a
            # promotion actually occurred this time.
            if close:
                db.close()
            db = connect()
            reopened = True
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
        if close or reopened:
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
