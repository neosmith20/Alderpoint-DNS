#!/usr/bin/env python3
"""Software Updates: discover, validate, and install newer Alderpoint DNS
Debian packages, either from a GitHub Releases feed or a manually uploaded
.deb, through one narrow privileged runner -- never from the unprivileged
web process directly.

Privilege model (matches app/network_config.py and app/backup.py): the web
process (running as the unprivileged `alderpointdns` user) only ever
validates a request and writes a row to `software_update_jobs`. A fixed,
argument-free sudoers entry lets it trigger the actual work as root:

  - `sudo alderpointdns_compiler.py update-check` runs synchronously (it
    never restarts anything) and is safe to call directly from an HTTP
    request.
  - Actually installing a package restarts `alderpointdns.service` --
    this web process's own service -- partway through, which would kill a
    child `sudo` process invoked directly from a request. So installs are
    never run as a child of the web request at all: the web process asks
    `sudo systemctl start --no-block alderpointdns-software-update.service`
    to start a wholly independent systemd unit (own cgroup, owned by PID 1, not a
    descendant of alderpointdns.service), which execs this module's
    `run_pending_job()` as root and survives alderpointdns.service being
    restarted or killed out from under it. The browser reconnects and
    reads job progress from the durable `software_update_jobs` /
    `software_update_events` tables -- never from the process that started
    it.

Two independent version comparisons are used on purpose (see
docs/versioning.md): `compare_semver()` for release/channel ranking
(GitHub release vs. resolved application version), and
`dpkg --compare-versions` for the actual package-install safety gate,
since that is the exact comparison `apt`/`dpkg` will perform.

The private-repo GitHub credential (if configured) lives in a root-owned,
mode-0600 file at CREDENTIAL_FILE and is read only by this module, which
always runs as root. It is never passed to, rendered by, or readable by
the unprivileged web process, never included in diagnostics/job records,
and any text derived from it (Authorization headers, exception messages
from an HTTP client that might echo request headers) is redacted before
being stored or logged.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from app import backup

DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
APP_ROOT = Path("/opt/alderpointdns")
DPKG_PACKAGE_NAME = "alderpointdns"

# Automatic-check scheduling (root, via alderpointdns_compiler.py
# update-check-schedule-deploy): same shape as app/filter_schedule.py's
# timer drop-in mechanism -- a packaged unit with a safe fixed default,
# overridden at runtime by a drop-in rendered from the stored setting.
# Deliberately never a raw f-string of untrusted operator text: the only
# things that ever reach the drop-in are auto_check_enabled (a bool) and
# check_interval_hours (an int already range-clamped by update_settings()),
# so no unit name, path, or shell metacharacter can reach systemd this way.
SYSTEMD_DIR = Path("/etc/systemd/system")
CHECK_TIMER_UNIT = "alderpointdns-software-update-check.timer"
CHECK_TIMER_OVERRIDE_DIR = SYSTEMD_DIR / f"{CHECK_TIMER_UNIT}.d"
CHECK_TIMER_OVERRIDE = CHECK_TIMER_OVERRIDE_DIR / "alderpointdns.conf"
MIN_CHECK_INTERVAL_HOURS = 1
MAX_CHECK_INTERVAL_HOURS = 168

# Root-only staging for verified, ready-to-install packages -- distinct
# from UPLOAD_STAGING_DIR below, which the unprivileged web process itself
# writes into. Only run_pending_job() (root) ever reads or writes here.
STAGED_DIR = Path("/var/lib/alderpointdns/software-updates/staged")

# The unprivileged web process streams a manually uploaded .deb here (a
# subdirectory it already has write access to, matching backup.py's
# IMPORTS_DIR / dns_cache.py's STAGING_DIR pattern); the privileged runner
# picks it up by the exact path recorded on the job row, never a path
# supplied fresh by any later request.
UPLOAD_STAGING_DIR = Path("/var/lib/alderpointdns/staging/software-updates")
MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # .deb packages are small; generous
UPLOAD_CHUNK_BYTES = 4 * 1024 * 1024

CREDENTIAL_FILE = Path("/etc/alderpointdns/software-updates.env")

# The project's own canonical repository. Not a release tag, beta number, or
# asset filename/URL -- those are always discovered from the GitHub API
# response, never hardcoded. Overridable via software_update_settings for
# forks/dev. Matches the repository the README's Quick Start install command
# downloads from -- see docs/software-updates.md.
DEFAULT_GITHUB_REPO = "neosmith20/Alderpoint-DNS"
GITHUB_API_BASE = "https://api.github.com"

CONNECT_TIMEOUT = 20

# Packages whose unexpected removal in a simulated/real install means abort
# -- same intent as app/dnsdist_upgrade.py's CRITICAL_PACKAGES.
CRITICAL_PACKAGES = {"alderpointdns", "bind9", "bind9-utils", "dnsdist", "libssl3", "libc6", "python3"}

PHASES = (
    "pending", "checking", "downloading", "validating", "backing_up",
    "simulating", "installing", "restarting", "postcheck", "completed", "failed",
)

PHASE_DISPLAY_MESSAGES = {
    "pending": "Starting update...",
    "checking": "Checking...",
    "downloading": "Downloading...",
    "validating": "Verifying package...",
    "backing_up": "Creating pre-upgrade backup...",
    "simulating": "Simulating upgrade...",
    "installing": "Installing...",
    "restarting": "Restarting services...",
    "postcheck": "Running post-upgrade health checks...",
    "completed": "Completed.",
    "failed": "Failed.",
}

# Phases from "installing" onward are the ones where apt-get may have
# actually started mutating installed package state -- see
# reap_abandoned_jobs()'s differing message for a job found stuck in one of
# these versus an earlier, pre-apt phase.
PACKAGE_STATE_UNCERTAIN_PHASES = frozenset({"installing", "restarting", "postcheck"})

# A job sits at phase='pending' -- with no worker identity recorded yet --
# from the moment the unprivileged web process creates its row until
# run_pending_job() (running as root inside the independently-dispatched
# alderpointdns-software-update.service unit) actually picks it up and
# stamps worker_pid/worker_start_ticks/worker_boot_id, a few hundred
# milliseconds to a few seconds later under normal load. reap_abandoned_jobs()
# must never treat a job still inside that ordinary dispatch window as
# abandoned merely because it has no worker identity yet -- that's not a
# "worker died" question, since no worker has been assigned at all yet, so
# the worker-identity-liveness check the rest of this function relies on
# doesn't apply. This grace period exists only to eventually catch the rarer
# case where dispatch itself silently failed (e.g. `systemctl start` was
# accepted but the unit never actually ran) and a job would otherwise sit at
# 'pending' forever.
PENDING_DISPATCH_GRACE_SECONDS = 120

DEFAULT_SETTINGS = {
    "auto_check_enabled": "1",
    "unattended_install_enabled": "0",
    "channel": "stable",  # "stable" | "prerelease"
    "github_repo": DEFAULT_GITHUB_REPO,
    "last_checked_at": "",
    "last_check_error": "",
    "latest_release_json": "{}",
    "check_interval_hours": "6",
}

# A friendly fixed set for the Check Interval selector -- matches
# app/filter_schedule.py's INTERVAL_CHOICES presentation. Any value in
# [MIN_CHECK_INTERVAL_HOURS, MAX_CHECK_INTERVAL_HOURS] is still accepted and
# safely clamped (a hand-crafted request bypassing the <select> is never
# trusted beyond that range either), so this list is a UI convenience, not
# the sole validation.
CHECK_INTERVAL_CHOICES: tuple[tuple[str, str], ...] = (
    ("1", "1 Hour"),
    ("6", "6 Hours"),
    ("12", "12 Hours"),
    ("24", "1 Day"),
    ("168", "1 Week"),
)


class SoftwareUpdateError(ValueError):
    """Raised for any fail-closed abort in the update flow. str(exc) is
    safe to show an administrator and to store in job diagnostics -- never
    build one of these from raw credential-file content."""


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _seconds_since(timestamp: str | None) -> float | None:
    if not timestamp:
        return None
    try:
        then = dt.datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=dt.timezone.utc)
    return (dt.datetime.now(dt.timezone.utc) - then).total_seconds()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def run(command: list[str], check: bool = True, timeout: int | None = 60, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, timeout=timeout, input=input_text)


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        if close:
            db.execute("PRAGMA journal_mode=WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS software_update_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS software_update_jobs (
                id INTEGER PRIMARY KEY,
                operation TEXT NOT NULL CHECK(operation IN ('github', 'manual')),
                requested_at TEXT NOT NULL,
                requested_by TEXT NOT NULL DEFAULT '',
                current_version TEXT NOT NULL DEFAULT '',
                candidate_version TEXT NOT NULL DEFAULT '',
                release_json TEXT NOT NULL DEFAULT '{}',
                uploaded_path TEXT,
                expected_sha256 TEXT,
                staged_path TEXT,
                staged_sha256 TEXT,
                backup_id INTEGER,
                backup_path TEXT,
                phase TEXT NOT NULL DEFAULT 'pending',
                result TEXT,
                error TEXT NOT NULL DEFAULT '',
                diagnostics_json TEXT NOT NULL DEFAULT '{}',
                started_at TEXT,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS software_update_events (
                id INTEGER PRIMARY KEY,
                job_id INTEGER NOT NULL,
                ts TEXT NOT NULL,
                phase TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT ''
            );
            """
        )
        # software_update_jobs worker-identity columns, added after the
        # table already existed in the field -- ALTER TABLE, not part of
        # CREATE TABLE IF NOT EXISTS above, so upgrading installs migrate
        # in place. Mirrors app/backup.py's restore_history worker-identity
        # columns/reap_abandoned_restores() exactly: a job whose runner
        # (alderpointdns-software-update.service) is killed or crashes
        # (OOM, host reboot, `systemctl stop`) must never leave its row
        # stuck at a non-terminal phase forever -- see reap_abandoned_jobs().
        for column, definition in (
            ("worker_pid", "INTEGER"),
            ("worker_start_ticks", "INTEGER"),
            ("worker_boot_id", "TEXT"),
        ):
            backup._ensure_column(db, "software_update_jobs", column, definition)
        db.commit()
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        rows = {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM software_update_settings")}
        merged = dict(DEFAULT_SETTINGS)
        merged.update(rows)
        return merged
    finally:
        if close:
            db.close()


def update_settings(values: dict[str, Any], conn: sqlite3.Connection | None = None) -> dict[str, str]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        current = settings(db)
        if "auto_check_enabled" in values:
            current["auto_check_enabled"] = "1" if _truthy(values["auto_check_enabled"]) else "0"
        if "unattended_install_enabled" in values:
            current["unattended_install_enabled"] = "1" if _truthy(values["unattended_install_enabled"]) else "0"
        if "channel" in values:
            channel = str(values["channel"]).strip().lower()
            if channel not in ("stable", "prerelease"):
                raise SoftwareUpdateError("channel must be 'stable' or 'prerelease'")
            current["channel"] = channel
        if "check_interval_hours" in values:
            try:
                interval = int(values["check_interval_hours"])
            except (TypeError, ValueError):
                raise SoftwareUpdateError("check_interval_hours must be an integer") from None
            if not (1 <= interval <= 168):
                raise SoftwareUpdateError("check_interval_hours must be between 1 and 168")
            current["check_interval_hours"] = str(interval)
        for key in ("auto_check_enabled", "unattended_install_enabled", "channel", "check_interval_hours"):
            db.execute(
                "INSERT INTO software_update_settings(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, current[key]),
            )
        db.commit()
        return current
    finally:
        if close:
            db.close()


def check_timer_drop_in_content(hours: int) -> str:
    return f"[Timer]\nOnBootSec=10m\nOnUnitActiveSec={hours}h\n"


def deploy_check_schedule(conn: sqlite3.Connection | None = None) -> str:
    """Renders/removes the automatic-check timer drop-in from the stored
    settings and (re)applies it via systemctl -- the privileged half of
    "check_interval_hours actually controls the cadence" and "disabling
    automatic checking actually stops scheduled checks". Called by
    update-check-schedule-deploy (root, via a fixed sudoers entry) after
    every settings save, and once at package install/upgrade (postinst),
    exactly mirroring filter_schedule.deploy_filter_schedule()'s shape.

    Only ever installs the update-run job -- never runs one itself, and
    the timer it manages (CHECK_TIMER_UNIT) only ever points at
    `update-check`, never `update-run`; see packaging/*-check.service.
    """
    close = conn is None
    db = conn or connect()
    init_db(db)
    try:
        cfg = settings(db)
        enabled = _truthy(cfg.get("auto_check_enabled", "1"))
        hours = _clamped_check_interval_hours(cfg)
        if not enabled:
            # Removed entirely (not merely left stopped) so nothing stale
            # lingers if the package is later reinstalled/upgraded without
            # this settings row surviving -- mirrors
            # deploy_filter_schedule()'s DISABLED handling exactly.
            CHECK_TIMER_OVERRIDE.unlink(missing_ok=True)
            run(["systemctl", "daemon-reload"])
            # check=False: disabling a timer that was never enabled (a
            # fresh install with checking off from the start) must not
            # fail the request.
            run(["systemctl", "disable", "--now", CHECK_TIMER_UNIT], check=False)
            state = "disabled"
        else:
            CHECK_TIMER_OVERRIDE_DIR.mkdir(parents=True, exist_ok=True)
            CHECK_TIMER_OVERRIDE.write_text(check_timer_drop_in_content(hours))
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", "--now", CHECK_TIMER_UNIT])
            state = "enabled"
        return json.dumps({"state": state, "interval_hours": hours, "timer": CHECK_TIMER_UNIT})
    finally:
        if close:
            db.close()


def _clamped_check_interval_hours(cfg: dict[str, str]) -> int:
    try:
        hours = int(cfg.get("check_interval_hours", DEFAULT_SETTINGS["check_interval_hours"]))
    except (TypeError, ValueError):
        hours = int(DEFAULT_SETTINGS["check_interval_hours"])
    return max(MIN_CHECK_INTERVAL_HOURS, min(MAX_CHECK_INTERVAL_HOURS, hours))


def next_check_at() -> str | None:
    """Best-effort next scheduled automatic-check time, or None when it
    can't be determined (systemd unavailable, timer not deployed/inactive)
    -- mirrors filter_schedule.next_run_at() exactly, including preferring
    `systemctl list-timers` JSON (which projects a monotonic
    OnUnitActiveSec timer onto the wall clock) over the raw
    NextElapseUSecRealtime property. Unprivileged: `systemctl
    list-timers`/`show` need no special permissions to read."""
    try:
        result = run(["systemctl", "list-timers", CHECK_TIMER_UNIT, "--all", "-o", "json"], check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 0:
        parsed = _parse_next_from_timers_json(result.stdout or "")
        if parsed:
            return parsed
    try:
        result = run(["systemctl", "show", CHECK_TIMER_UNIT, "--property=NextElapseUSecRealtime"], check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return _parse_next_elapse(result.stdout or "")


def _parse_next_elapse(output: str) -> str | None:
    for line in (output or "").splitlines():
        key, sep, value = line.partition("=")
        if not sep or key.strip() != "NextElapseUSecRealtime":
            continue
        value = value.strip()
        if not value or value in {"n/a", "0"}:
            return None
        return value
    return None


def _parse_next_from_timers_json(output: str) -> str | None:
    try:
        entries = json.loads(output or "[]")
    except ValueError:
        return None
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("unit") != CHECK_TIMER_UNIT:
            continue
        next_usec = entry.get("next")
        if isinstance(next_usec, int) and next_usec > 0:
            stamp = dt.datetime.fromtimestamp(next_usec / 1_000_000, dt.timezone.utc)
            return stamp.replace(microsecond=0).isoformat()
    return None


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _set_setting(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute(
        "INSERT INTO software_update_settings(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


# ---------------------------------------------------------------------------
# Version model: SemVer comparison (release/channel ranking) -- kept
# strictly separate from dpkg --compare-versions (package-install safety
# gate, below). See docs/versioning.md.
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def parse_semver(version: str) -> tuple[int, int, int, tuple[str, ...] | None]:
    """Parses a SemVer 2.0.0 string (optionally `v`-prefixed, as GitHub tags
    commonly are). Raises SoftwareUpdateError on anything malformed --
    callers must treat that as "reject this version", never guess."""
    match = _SEMVER_RE.match((version or "").strip())
    if not match:
        raise SoftwareUpdateError(f"malformed version string: {version!r}")
    major, minor, patch = int(match["major"]), int(match["minor"]), int(match["patch"])
    prerelease = tuple(match["prerelease"].split(".")) if match["prerelease"] else None
    return major, minor, patch, prerelease


def _prerelease_identifier_key(ident: str) -> tuple[int, int, str]:
    # SemVer precedence rule: purely-numeric identifiers compare
    # numerically and are always lower than any alphanumeric identifier.
    if ident.isdigit():
        return (0, int(ident), "")
    return (1, 0, ident)


def compare_semver(a: str, b: str) -> int:
    """Returns -1/0/1 for a<b / a==b / a>b, per SemVer 2.0.0 precedence:
    core version first, then prerelease (a version *with* a prerelease tag
    is always lower than the same core version with none), then
    identifier-by-identifier. Build metadata (+...) is ignored, exactly as
    SemVer specifies. Raises SoftwareUpdateError if either is malformed."""
    a_major, a_minor, a_patch, a_pre = parse_semver(a)
    b_major, b_minor, b_patch, b_pre = parse_semver(b)
    a_core, b_core = (a_major, a_minor, a_patch), (b_major, b_minor, b_patch)
    if a_core != b_core:
        return -1 if a_core < b_core else 1
    if a_pre is None and b_pre is None:
        return 0
    if a_pre is None:
        return 1  # a is the final release of the same core version: newer
    if b_pre is None:
        return -1
    a_keys = [_prerelease_identifier_key(p) for p in a_pre]
    b_keys = [_prerelease_identifier_key(p) for p in b_pre]
    for ak, bk in zip(a_keys, b_keys):
        if ak != bk:
            return -1 if ak < bk else 1
    if len(a_keys) != len(b_keys):
        return -1 if len(a_keys) < len(b_keys) else 1
    return 0


def dpkg_compare(a: str, op: str, b: str) -> bool:
    """Wraps `dpkg --compare-versions a op b` (op in lt/le/eq/ne/ge/gt) --
    the exact comparison apt/dpkg itself will perform, used only for the
    package-install safety gate, never for release/channel ranking."""
    try:
        proc = run(["dpkg", "--compare-versions", a, op, b], check=False, timeout=10)
    except (OSError, FileNotFoundError) as exc:
        raise SoftwareUpdateError(f"dpkg --compare-versions failed to run: {exc}") from None
    return proc.returncode == 0


# ---------------------------------------------------------------------------
# Debian <-> source version-tag form (reused from app/backup.py's
# generalized -<tag>.<N> <-> ~<tag><N> substitution)
# ---------------------------------------------------------------------------

def source_version_to_deb_form(version: str) -> str:
    """Mirrors scripts/build-deb.sh's derivation exactly, so a GitHub
    release's tag (source-version form, e.g. "0.5.0-dev.1") can be
    compared against what dpkg would call the package built from it
    ("0.5.0~dev1-1")."""
    upstream = re.sub(r"-([A-Za-z]+)\.([0-9]+)", r"~\1\2", version.lstrip("v"))
    return f"{upstream}-1"


# ---------------------------------------------------------------------------
# Installed-state detection
# ---------------------------------------------------------------------------

def installed_package_version() -> str | None:
    """None means this is not a dpkg-managed install (a source checkout)
    -- distinct from any failure; both are treated as "cannot determine",
    which is the correct signal to disable install actions."""
    try:
        proc = run(["dpkg-query", "-W", "-f=${Version}", DPKG_PACKAGE_NAME], check=False, timeout=10)
    except (OSError, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def is_dpkg_managed() -> bool:
    return installed_package_version() is not None


def installed_version_status() -> dict[str, Any]:
    """Wraps backup.version_source_status() (the canonical source) plus
    dpkg-managed detection. mismatch=True is a hard stop for any
    *automatic* update decision -- see docs/versioning.md."""
    status = dict(backup.version_source_status())
    status["dpkg_managed"] = is_dpkg_managed()
    return status


# ---------------------------------------------------------------------------
# GitHub credential (private-repo development operation)
# ---------------------------------------------------------------------------

def _read_github_token() -> str | None:
    """Reads GITHUB_TOKEN=... from CREDENTIAL_FILE. Refuses (returns None,
    logs nothing containing the value) unless the file is owned by root
    and not group/other-readable -- defense in depth against a
    misconfigured install leaving a token world-readable."""
    try:
        st = CREDENTIAL_FILE.stat()
    except OSError:
        return None
    if st.st_uid != 0 or (st.st_mode & 0o077):
        return None
    try:
        text = CREDENTIAL_FILE.read_text()
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == "GITHUB_TOKEN":
            token = value.strip().strip('"').strip("'")
            return token or None
    return None


def redact(text: str) -> str:
    """Strips anything that looks like an Authorization header or a raw
    GitHub token from text before it is stored in job diagnostics or
    logged -- applied to every piece of text derived from an HTTP
    exception or subprocess output that might otherwise echo it back."""
    text = re.sub(r"(?i)authorization:\s*\S+", "Authorization: [redacted]", text)
    text = re.sub(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "[redacted-token]", text)
    token = _read_github_token()
    if token:
        text = text.replace(token, "[redacted-token]")
    return text


def credential_status() -> dict[str, Any]:
    """Safe-to-render summary for the web UI: never the token itself."""
    try:
        st = CREDENTIAL_FILE.stat()
        exists = True
        secure = st.st_uid == 0 and not (st.st_mode & 0o077)
    except OSError:
        exists = False
        secure = False
    return {"configured": exists and secure and _read_github_token() is not None, "file_exists": exists, "permissions_ok": secure}


# ---------------------------------------------------------------------------
# GitHub release discovery
# ---------------------------------------------------------------------------

def _github_get(path: str, token: str | None) -> Any:
    url = f"{GITHUB_API_BASE}{path}"
    headers = {"User-Agent": "Alderpoint DNS Software Updates/1", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = redact(exc.read().decode("utf-8", "replace")[:500]) if exc.fp else ""
        raise SoftwareUpdateError(f"GitHub API request failed ({exc.code}): {detail or exc.reason}") from None
    except urllib.error.URLError as exc:
        raise SoftwareUpdateError(f"GitHub is unavailable: {redact(str(exc.reason))}") from None
    except TimeoutError:
        raise SoftwareUpdateError("GitHub request timed out") from None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise SoftwareUpdateError("GitHub returned a malformed (non-JSON) response") from None


def list_releases(repo: str, token: str | None) -> list[dict[str, Any]]:
    data = _github_get(f"/repos/{repo}/releases?per_page=30", token)
    if not isinstance(data, list):
        raise SoftwareUpdateError("GitHub returned a malformed releases response (expected a list)")
    return data


_DEB_ASSET_RE = re.compile(r"^alderpointdns_(?P<version>[^_]+)_(?P<arch>all|amd64)\.deb$")


def _deb_asset_version(asset: dict[str, Any]) -> str | None:
    match = _DEB_ASSET_RE.match(str(asset.get("name", "")))
    return match["version"] if match else None


def _expected_deb_asset_version(release: dict[str, Any]) -> str | None:
    tag_version = _release_semver(release)
    return source_version_to_deb_form(tag_version) if tag_version is not None else None


def select_release_assets(release: dict[str, Any], expected_deb_version: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Selects one Alderpoint .deb asset and one SHA256SUMS asset.

    Alderpoint releases may contain both the canonical versioned package
    (alderpointdns_<dpkg-version>_<arch>.deb) and a byte-identical
    alderpointdns_latest_all.deb alias. Prefer the exact versioned package
    for the release, use the latest alias only as a fallback, and still
    reject genuinely ambiguous versioned packages rather than guessing.
    """
    assets = release.get("assets") or []
    debs = [a for a in assets if isinstance(a, dict) and _DEB_ASSET_RE.match(str(a.get("name", "")))]
    sums = [a for a in assets if isinstance(a, dict) and a.get("name") == "SHA256SUMS"]
    if len(sums) != 1:
        raise SoftwareUpdateError(f"expected exactly one SHA256SUMS asset, found {len(sums)}")
    if not debs:
        raise SoftwareUpdateError("expected one compatible Alderpoint DNS .deb asset, found 0")

    expected = expected_deb_version or _expected_deb_asset_version(release)
    versioned = [asset for asset in debs if _deb_asset_version(asset) != "latest"]
    aliases = [asset for asset in debs if _deb_asset_version(asset) == "latest"]

    selected: dict[str, Any] | None = None
    if expected:
        exact = [asset for asset in versioned if _deb_asset_version(asset) == expected]
        if len(exact) > 1:
            names = sorted(str(asset.get("name", "")) for asset in exact)
            raise SoftwareUpdateError(f"ambiguous Alderpoint DNS .deb assets for version {expected!r}: {names}")
        if exact:
            selected = exact[0]
        elif versioned:
            names = sorted(str(asset.get("name", "")) for asset in versioned)
            raise SoftwareUpdateError(f"expected Alderpoint DNS package asset for version {expected!r}, found {names}")
    else:
        if len(versioned) > 1:
            names = sorted(str(asset.get("name", "")) for asset in versioned)
            raise SoftwareUpdateError(f"ambiguous Alderpoint DNS .deb assets: {names}")
        if versioned:
            selected = versioned[0]

    if selected is None:
        if len(aliases) != 1:
            raise SoftwareUpdateError(f"expected one compatible Alderpoint DNS .deb asset, found {len(debs)}")
        selected = aliases[0]
    return selected, sums[0]


def _release_semver(release: dict[str, Any]) -> str | None:
    tag = str(release.get("tag_name") or "").strip()
    try:
        parse_semver(tag)
    except SoftwareUpdateError:
        return None
    return tag.lstrip("v")


def select_candidate_release(releases: list[dict[str, Any]], channel: str, installed_resolved_version: str) -> dict[str, Any] | None:
    """Applies channel policy, rejects drafts/malformed tags, SemVer-sorts,
    and requires the winner to be strictly newer than the installed
    version (never a downgrade, never the same version). Returns None
    ("no update available") rather than the installed release itself."""
    candidates: list[tuple[str, dict[str, Any]]] = []
    for release in releases:
        if release.get("draft"):
            continue
        is_prerelease = bool(release.get("prerelease"))
        if channel == "stable" and is_prerelease:
            continue
        version = _release_semver(release)
        if version is None:
            continue
        candidates.append((version, release))
    if not candidates:
        return None
    candidates.sort(key=lambda pair: _semver_sort_key(pair[0]))
    best_version, best_release = candidates[-1]
    try:
        newer = compare_semver(best_version, installed_resolved_version) > 0
    except SoftwareUpdateError:
        # Installed version itself doesn't parse as SemVer (e.g. a
        # pre-1.0 beta before this model existed) -- fail closed rather
        # than guess; the administrator sees "unable to compare".
        return None
    return best_release if newer else None


def _semver_sort_key(version: str):
    major, minor, patch, pre = parse_semver(version)
    if pre is None:
        return (major, minor, patch, 1, ())
    return (major, minor, patch, 0, tuple(_prerelease_identifier_key(p) for p in pre))


# ---------------------------------------------------------------------------
# Download + checksum
# ---------------------------------------------------------------------------

def _download_asset(asset: dict[str, Any], dest: Path, token: str | None) -> None:
    url = asset.get("url") or asset.get("browser_download_url")
    if not url:
        raise SoftwareUpdateError("release asset has no download URL")
    headers = {"User-Agent": "Alderpoint DNS Software Updates/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # Release *assets* (as opposed to arbitrary metadata) need the octet
    # stream Accept header on the API asset URL to get raw bytes rather
    # than a JSON description, matching GitHub's documented asset-download
    # flow for private repositories.
    headers["Accept"] = "application/octet-stream"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT) as response, dest.open("wb") as fh:
            while True:
                chunk = response.read(UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                fh.write(chunk)
    except urllib.error.URLError as exc:
        raise SoftwareUpdateError(f"download failed: {redact(str(exc.reason))}") from None
    except TimeoutError:
        raise SoftwareUpdateError("download timed out") from None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(UPLOAD_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _parse_sha256sums(text: str, filename: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts
        name = name.strip().lstrip("*")
        if name == filename or name.endswith(f"/{filename}"):
            return digest.lower()
    raise SoftwareUpdateError(f"SHA256SUMS does not contain an entry for {filename!r}")


def stage_release(release: dict[str, Any], token: str | None) -> tuple[Path, str]:
    """Downloads the release's .deb and SHA256SUMS assets into STAGED_DIR
    (root-only), verifies the checksum, and returns (deb_path, sha256).
    Raises on any mismatch -- never installs an unverifiable package."""
    deb_asset, sums_asset = select_release_assets(release)
    STAGED_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STAGED_DIR, 0o700)
    deb_path = STAGED_DIR / deb_asset["name"]
    sums_path = STAGED_DIR / "SHA256SUMS"
    _download_asset(deb_asset, deb_path, token)
    _download_asset(sums_asset, sums_path, token)
    expected = _parse_sha256sums(sums_path.read_text(errors="replace"), deb_asset["name"])
    actual = sha256_file(deb_path)
    if actual != expected:
        deb_path.unlink(missing_ok=True)
        raise SoftwareUpdateError(f"checksum mismatch for {deb_asset['name']}: expected {expected}, got {actual}")
    os.chmod(deb_path, 0o600)
    return deb_path, actual


# ---------------------------------------------------------------------------
# Manual upload (unprivileged side: streamed, bounded-memory staging)
# ---------------------------------------------------------------------------

def begin_manual_upload(filename: str) -> tuple[Path, int]:
    name = os.path.basename(filename or "")
    if not name.endswith(".deb") or "/" in filename or name in (".", ".."):
        raise SoftwareUpdateError("uploaded file must be a .deb package")
    UPLOAD_STAGING_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".alderpointdns-update-upload-", dir=str(UPLOAD_STAGING_DIR))
    os.close(fd)
    os.chmod(tmp_name, 0o600)
    return Path(tmp_name), MAX_UPLOAD_BYTES


def finalize_manual_upload(tmp_path: Path, filename: str) -> Path:
    name = os.path.basename(filename or "upload.deb")
    dest = UPLOAD_STAGING_DIR / f"{int(time.time())}-{name}"
    os.replace(tmp_path, dest)
    os.chmod(dest, 0o640)
    return dest


def abort_manual_upload(tmp_path: Path) -> None:
    tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Package inspection / APT simulation (package-install safety gate)
# ---------------------------------------------------------------------------

def inspect_deb(path: Path) -> dict[str, str]:
    try:
        proc = run(["dpkg-deb", "-f", str(path), "Package", "Version", "Architecture"], check=False, timeout=15)
    except (OSError, FileNotFoundError) as exc:
        raise SoftwareUpdateError(f"dpkg-deb failed to run: {exc}") from None
    if proc.returncode != 0:
        raise SoftwareUpdateError(f"dpkg-deb could not inspect the package (is it a valid .deb?): {proc.stdout}")
    fields: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    return fields


REMOVAL_RE = re.compile(r"^Remv\s+(\S+)", re.M)


def simulate_install(deb_path: Path) -> str:
    try:
        result = run(["apt-get", "install", "-s", "-y", "-o", "Dpkg::Options::=--force-confold", str(deb_path)], check=False, timeout=90)
    except (OSError, FileNotFoundError) as exc:
        raise SoftwareUpdateError(f"apt simulation failed to run: {exc}") from None
    if result.returncode != 0:
        raise SoftwareUpdateError(f"apt simulation failed: {result.stdout}")
    output = result.stdout or ""
    removed = {name.split(":")[0].split("[")[0] for name in REMOVAL_RE.findall(output)}
    unsafe = removed & CRITICAL_PACKAGES - {"alderpointdns"}  # alderpointdns itself is expected to be reinstalled/upgraded, never "removed"
    if "alderpointdns" in removed:
        unsafe.add("alderpointdns")
    if unsafe:
        raise SoftwareUpdateError(f"simulated install would remove critical package(s) {sorted(unsafe)}; refusing to proceed")
    return output


def validate_candidate_package(deb_path: Path, expected_version: str | None) -> dict[str, str]:
    """Runs every 1-11-step validation from the design (package name,
    architecture, version-corresponds-to-release, newer-than-installed)
    except the APT simulation itself, which the caller runs separately so
    it can be captured into job diagnostics under its own phase."""
    fields = inspect_deb(deb_path)
    if fields.get("Package") != DPKG_PACKAGE_NAME:
        raise SoftwareUpdateError(f"package name mismatch: expected {DPKG_PACKAGE_NAME!r}, got {fields.get('Package')!r}")
    if fields.get("Architecture") not in ("all", "amd64"):
        raise SoftwareUpdateError(f"unsupported package architecture: {fields.get('Architecture')!r}")
    candidate_version = fields.get("Version", "")
    if expected_version is not None:
        expected_deb_version = source_version_to_deb_form(expected_version)
        if not dpkg_compare(candidate_version, "eq", expected_deb_version):
            raise SoftwareUpdateError(
                f"package version {candidate_version!r} does not correspond to the expected release version {expected_deb_version!r}"
            )
    installed = installed_package_version()
    if installed is None:
        raise SoftwareUpdateError("Software Updates: unmanaged source installation -- cannot install a package here")
    if dpkg_compare(candidate_version, "eq", installed):
        raise SoftwareUpdateError(f"candidate version {candidate_version!r} is the same as the installed version; refusing a no-op reinstall via the updater")
    if not dpkg_compare(candidate_version, "gt", installed):
        raise SoftwareUpdateError(f"candidate version {candidate_version!r} is not newer than the installed version {installed!r}; refusing to downgrade")
    return fields


# ---------------------------------------------------------------------------
# Post-upgrade health check
# ---------------------------------------------------------------------------

SERVICES = ("alderpointdns", "alderpointdns-analytics", "named", "dnsdist")
SQLITE_HEALTH_BUSY_TIMEOUT_MS = 5000
SQLITE_HEALTH_ATTEMPTS = 6
SQLITE_HEALTH_RETRY_DELAY_SECONDS = 2
UPDATER_EXTERNAL_EXECUTABLE_CONTRACT = {
    "apt-get": "supported Debian/Ubuntu package manager",
    "dig": "bind9-dnsutils package dependency",
    "dpkg": "Debian/Ubuntu base package manager",
    "dpkg-deb": "Debian/Ubuntu base package manager",
    "dpkg-query": "Debian/Ubuntu base package manager",
    "systemctl": "systemd service manager on supported appliances",
    "update-postcheck": "Alderpoint DNS packaged compiler entry point executed with the current Python interpreter",
}


def _service_active(unit: str) -> bool:
    try:
        proc = run(["systemctl", "is-active", unit], check=False, timeout=10)
    except (OSError, FileNotFoundError):
        return False
    return proc.stdout.strip() == "active"


# Transient lock/contention conditions that should be retried rather than
# treated as a hard failure. SQLite reports these two distinct families:
#
#   SQLITE_BUSY   ("database is locked")        -- another connection holds
#                                                   a write lock (e.g. a
#                                                   checkpoint, a migration,
#                                                   an analytics writer).
#   SQLITE_LOCKED ("database table is locked")   -- a conflicting lock from
#                                                   *within the same process*
#                                                   (shared cache) or a
#                                                   table-level conflict.
#
# Both are ordinary, expected side effects of services restarting/writing
# around a package upgrade, not evidence of corruption, and both must be
# retried identically. Real corruption is reported by `PRAGMA quick_check`
# returning non-"ok" rows (see the `integrity_check_failed` branch below),
# never by raising one of these exceptions.
_SQLITE_RETRYABLE_ERROR_TYPES = ("database_busy", "database_locked")


def _classify_sqlite_operational_error(exc: sqlite3.OperationalError) -> tuple[str, str]:
    """Classify an OperationalError from PRAGMA quick_check.

    Prefers the structured `sqlite_errorcode`/`sqlite_errorname` attributes
    that Python's sqlite3 module exposes (Python 3.11+, available on all
    Alderpoint-supported interpreters) since they identify the exact SQLite
    result code regardless of message wording/localization. Falls back to
    substring matching on the exception message for interpreters/drivers
    that don't populate those attributes.

    Returns (error_type, message).
    """
    message = redact(str(exc))[:1000]
    errorname = str(getattr(exc, "sqlite_errorname", "") or "")
    if errorname.startswith("SQLITE_BUSY"):
        return "database_busy", message
    if errorname.startswith("SQLITE_LOCKED"):
        return "database_locked", message
    if errorname:
        # We got a structured result code and it is neither BUSY nor
        # LOCKED -- do not fall through to fuzzy message matching, which
        # could misclassify an unrelated operational error as transient.
        return "sqlite_error", message
    lowered = message.lower()
    if "table is locked" in lowered:
        return "database_locked", message
    if "database is locked" in lowered or "database is busy" in lowered or "database locked" in lowered:
        return "database_busy", message
    return "sqlite_error", message


def _database_quick_check() -> dict[str, Any]:
    path = str(DB_PATH)
    last_failure: dict[str, Any] | None = None
    for attempt in range(1, SQLITE_HEALTH_ATTEMPTS + 1):
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(path, timeout=SQLITE_HEALTH_BUSY_TIMEOUT_MS / 1000)
            conn.execute(f"PRAGMA busy_timeout={SQLITE_HEALTH_BUSY_TIMEOUT_MS}")
            rows = conn.execute("PRAGMA quick_check").fetchall()
        except sqlite3.OperationalError as exc:
            error_type, message = _classify_sqlite_operational_error(exc)
            last_failure = {"ok": False, "path": path, "attempts": attempt, "error_type": error_type, "message": message}
        except sqlite3.DatabaseError as exc:
            return {
                "ok": False,
                "path": path,
                "attempts": attempt,
                "error_type": "sqlite_error",
                "message": redact(str(exc))[:1000],
            }
        else:
            values = [str(row[0]) for row in rows if row and row[0] is not None]
            output = "\n".join(values).strip()
            if output == "ok":
                return {"ok": True, "path": path, "attempts": attempt, "result": "ok"}
            return {
                "ok": False,
                "path": path,
                "attempts": attempt,
                "error_type": "integrity_check_failed",
                "result": redact(output)[:1000] or "PRAGMA quick_check returned no rows.",
            }
        finally:
            if conn is not None:
                conn.close()
        if attempt < SQLITE_HEALTH_ATTEMPTS and last_failure and last_failure.get("error_type") in _SQLITE_RETRYABLE_ERROR_TYPES:
            time.sleep(SQLITE_HEALTH_RETRY_DELAY_SECONDS)
            continue
        break
    return last_failure or {
        "ok": False,
        "path": path,
        "attempts": SQLITE_HEALTH_ATTEMPTS,
        "error_type": "unknown",
        "message": "SQLite quick_check did not produce a result.",
    }


def _quick_check_ok() -> bool:
    return bool(_database_quick_check().get("ok"))


def _health_failure_summary(health: dict[str, Any]) -> str:
    failures: list[str] = []
    services = health.get("services")
    if isinstance(services, dict):
        failed_services = [unit for unit, active in services.items() if not active]
        if failed_services:
            failures.append("inactive services: " + ", ".join(failed_services))
    if not health.get("database_quick_check_ok", True):
        db_check = health.get("database_quick_check")
        if isinstance(db_check, dict):
            detail = db_check.get("message") or db_check.get("result") or db_check.get("error_type") or "failed"
            failures.append(f"database quick_check failed ({detail})")
        else:
            failures.append("database quick_check failed")
    if not health.get("dns_resolution_ok", True):
        failures.append("DNS resolution failed")
    if not health.get("webapp_responding", True):
        failures.append("web app health endpoint did not respond")
    if health.get("installed_version_matches_expected") is False:
        failures.append(
            "installed package version does not match expected "
            f"({health.get('installed_dpkg_version') or 'unknown'} installed)"
        )
    return "; ".join(failures) or "post-upgrade health verification failed"


def _installed_but_health_failed(health: dict[str, Any]) -> bool:
    return bool(health and health.get("ok") is False and health.get("installed_version_matches_expected") is True)


def _job_diagnostics(job: dict[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(job.get("diagnostics_json") or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}


def _job_installed_but_health_failed(job: dict[str, Any]) -> bool:
    if job.get("result") == "installed_health_failed":
        return True
    diagnostics = _job_diagnostics(job)
    health = diagnostics.get("post_upgrade_health")
    return isinstance(health, dict) and _installed_but_health_failed(health)


def _job_health_summary(job: dict[str, Any]) -> str:
    diagnostics = _job_diagnostics(job)
    health = diagnostics.get("post_upgrade_health")
    return _health_failure_summary(health) if isinstance(health, dict) and not health.get("ok", True) else ""


def _job_status_label(job: dict[str, Any]) -> str:
    if _job_installed_but_health_failed(job):
        return "Update installed, but post-upgrade health verification failed"
    phase = str(job.get("phase") or "")
    if phase == "completed":
        return "Update successful"
    if phase == "failed":
        return "Update failed"
    return phase or "pending"


def _job_status_tone(job: dict[str, Any]) -> str:
    if _job_installed_but_health_failed(job):
        return "warning"
    phase = str(job.get("phase") or "")
    if phase == "completed":
        return "healthy"
    if phase == "failed":
        return "down"
    return "neutral"


def _job_is_historical(job: dict[str, Any], last_checked_at: str | None) -> bool:
    """A terminal (completed/failed) job is "historical" once a newer
    administrator action has happened since it finished -- concretely, a
    later successful Check for Updates. Timestamps are all
    `now()`-formatted (UTC, fixed-offset ISO 8601), so plain string
    comparison is chronological.

    This is what turns a real field scenario -- an old failed manual
    Update Job, still the only row in software_update_jobs, sitting
    untouched while a fresh, successful Check for Updates later discovers
    a newer release -- into "Previous Update Job #4, failed on <date>"
    instead of a current-looking failure. A job with no newer check since
    it finished (e.g. an install that just failed moments ago) is never
    historical: it is still the most relevant thing on the page."""
    phase = job.get("phase")
    if phase not in ("completed", "failed"):
        return False
    completed_at = job.get("completed_at")
    if not completed_at or not last_checked_at:
        return False
    return last_checked_at > completed_at


def _job_view(job: dict[str, Any], events: list[sqlite3.Row] | None = None, last_checked_at: str | None = None) -> dict[str, Any]:
    view = dict(job)
    events = events or []
    view["active"] = view.get("phase") not in ("completed", "failed")
    view["status_label"] = _job_status_label(view)
    view["status_tone"] = _job_status_tone(view)
    view["health_summary"] = _job_health_summary(view)
    view["display_message"] = _job_display_message(view, events)
    view["historical"] = _job_is_historical(view, last_checked_at)
    return view


def _resolution_ok() -> bool:
    try:
        proc = run(["dig", "+short", "+time=3", "+tries=1", "example.com", "@127.0.0.1"], check=False, timeout=10)
    except (OSError, FileNotFoundError):
        return False
    return proc.returncode == 0 and bool(proc.stdout.strip())


def _webapp_healthz_ok() -> bool:
    # Confirms the restarted web process is actually accepting local
    # connections again, not merely that systemd reports it "active"
    # (which it does as soon as the process starts, before uvicorn has
    # finished binding/serving).
    req = urllib.request.Request("http://127.0.0.1:3000/healthz", headers={"User-Agent": "Alderpoint DNS Software Updates/1"})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def post_upgrade_health_check(expected_deb_version: str | None = None) -> dict[str, Any]:
    services = {unit: _service_active(unit) for unit in SERVICES}
    installed = installed_package_version()
    database_quick_check = _database_quick_check()
    result: dict[str, Any] = {
        "services": services,
        "services_ok": all(services.values()),
        "database_quick_check_ok": bool(database_quick_check.get("ok")),
        "database_quick_check": database_quick_check,
        "dns_resolution_ok": _resolution_ok(),
        "webapp_responding": _webapp_healthz_ok(),
        "installed_dpkg_version": installed,
        "application_version": backup.alderpointdns_app_version(),
    }
    if expected_deb_version is not None:
        result["installed_version_matches_expected"] = installed is not None and dpkg_compare(installed, "eq", expected_deb_version)
    result["ok"] = bool(
        result["services_ok"] and result["database_quick_check_ok"] and result["dns_resolution_ok"]
        and result["webapp_responding"] and result.get("installed_version_matches_expected", True)
    )
    return result


def post_upgrade_health_check_json(expected_deb_version: str | None = None) -> str:
    """CLI-safe wrapper used by the post-install runner subprocess."""
    return json.dumps(post_upgrade_health_check(expected_deb_version=expected_deb_version), default=str)


def run_fresh_post_upgrade_health_check(expected_deb_version: str | None = None) -> dict[str, Any]:
    """Run post-upgrade health in a fresh installed-code Python process.

    The software-update runner is intentionally long-lived across
    apt-get install because it must survive alderpointdns.service being
    restarted. That also means modules imported before apt runs remain the
    old version in memory. The health check must execute the newly
    installed package code, so the runner shells out to the installed
    compiler entry point after apt succeeds and parses the JSON result.
    """
    command = [sys.executable, "/opt/alderpointdns/app/alderpointdns_compiler.py", "update-postcheck"]
    if expected_deb_version is not None:
        command.extend(["--expected-deb-version", expected_deb_version])
    try:
        proc = run(command, check=False, timeout=90)
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "postcheck_process_ok": False,
            "postcheck_process_error": "fresh post-upgrade health check timed out",
            "expected_deb_version": expected_deb_version,
        }
    except (OSError, FileNotFoundError) as exc:
        return {
            "ok": False,
            "postcheck_process_ok": False,
            "postcheck_process_error": redact(str(exc))[:400],
            "expected_deb_version": expected_deb_version,
        }
    output = (proc.stdout or "").strip()
    if proc.returncode != 0:
        return {
            "ok": False,
            "postcheck_process_ok": False,
            "postcheck_process_error": redact(output)[:1000] or f"fresh post-upgrade health check exited with status {proc.returncode}",
            "postcheck_process_returncode": proc.returncode,
            "expected_deb_version": expected_deb_version,
        }
    try:
        health = json.loads(output)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "postcheck_process_ok": False,
            "postcheck_process_error": "fresh post-upgrade health check returned invalid JSON",
            "postcheck_process_output": redact(output)[:1000],
            "expected_deb_version": expected_deb_version,
        }
    if not isinstance(health, dict):
        return {
            "ok": False,
            "postcheck_process_ok": False,
            "postcheck_process_error": "fresh post-upgrade health check returned a non-object result",
            "expected_deb_version": expected_deb_version,
        }
    health["postcheck_process_ok"] = True
    health["postcheck_process_command"] = "update-postcheck"
    return health


# ---------------------------------------------------------------------------
# Jobs / events (durable state, read by the web process across restarts)
# ---------------------------------------------------------------------------

def _record_event(db: sqlite3.Connection, job_id: int, phase: str, message: str) -> None:
    db.execute(
        "INSERT INTO software_update_events(job_id, ts, phase, message) VALUES (?, ?, ?, ?)",
        (job_id, now(), phase, redact(message)),
    )


def _set_phase(db: sqlite3.Connection, job_id: int, phase: str, message: str = "") -> None:
    db.execute("UPDATE software_update_jobs SET phase=? WHERE id=?", (phase, job_id))
    _record_event(db, job_id, phase, message)
    db.commit()


def create_github_job(release: dict[str, Any], requested_by: str = "") -> int:
    """Called by the unprivileged web process to record a pending install
    job for a GitHub-discovered release; contains no filesystem paths,
    shell fragments, or URLs the privileged runner will trust blindly --
    it re-derives the asset URLs itself from release_json."""
    status = installed_version_status()
    conn = connect()
    try:
        init_db(conn)
        cur = conn.execute(
            "INSERT INTO software_update_jobs(operation, requested_at, requested_by, current_version, candidate_version, release_json, phase) "
            "VALUES ('github', ?, ?, ?, ?, ?, 'pending')",
            (now(), requested_by, status.get("resolved", "unknown"), (release.get("tag_name") or "").lstrip("v"), json.dumps(release)),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def create_manual_job(uploaded_path: Path, expected_sha256: str | None, requested_by: str = "") -> int:
    status = installed_version_status()
    conn = connect()
    try:
        init_db(conn)
        cur = conn.execute(
            "INSERT INTO software_update_jobs(operation, requested_at, requested_by, current_version, uploaded_path, expected_sha256, phase) "
            "VALUES ('manual', ?, ?, ?, ?, ?, 'pending')",
            (now(), requested_by, status.get("resolved", "unknown"), str(uploaded_path), expected_sha256),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_job(job_id: int, conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        return db.execute("SELECT * FROM software_update_jobs WHERE id=?", (job_id,)).fetchone()
    finally:
        if close:
            db.close()


def latest_job(conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        return db.execute("SELECT * FROM software_update_jobs ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        if close:
            db.close()


def job_events(job_id: int, conn: sqlite3.Connection | None = None) -> list[sqlite3.Row]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        return list(db.execute("SELECT * FROM software_update_events WHERE job_id=? ORDER BY id", (job_id,)))
    finally:
        if close:
            db.close()


def _job_display_message(job: dict[str, Any], events: list[sqlite3.Row]) -> str:
    phase = str(job.get("phase") or "")
    if phase == "failed" and job.get("error"):
        return str(job["error"])
    if phase == "downloading" and job.get("candidate_version"):
        return f"Downloading v{job['candidate_version']}..."
    if events:
        message = str(events[-1]["message"] or "").strip()
        if message:
            return message[0].upper() + message[1:] if message[0].islower() else message
    return PHASE_DISPLAY_MESSAGES.get(phase, phase or "Unknown")


def job_status_payload(conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Small local polling payload for the Software Updates page.

    This reads only durable local state; it never runs an update check,
    download, install, or GitHub request. It intentionally avoids
    update_status() so polling does not also query timer metadata every
    few seconds.
    """
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        reap_abandoned_jobs(db)
        version_status = installed_version_status()
        row = latest_job(db)
        payload: dict[str, Any] = {
            "installed_version": version_status.get("resolved", ""),
            "installed_dpkg_version": version_status.get("dpkg_version", ""),
            "job": None,
        }
        if row is None:
            return payload
        events = job_events(row["id"], db)
        job = dict(row)
        job_view = _job_view(job, events, last_checked_at=settings(db).get("last_checked_at"))
        payload["job"] = {
            "id": job_view["id"],
            "operation": job_view["operation"],
            "requested_at": job_view["requested_at"],
            "requested_by": job_view["requested_by"],
            "current_version": job_view["current_version"],
            "candidate_version": job_view["candidate_version"],
            "backup_path": job_view["backup_path"],
            "phase": job_view["phase"],
            "result": job_view["result"],
            "error": job_view["error"],
            "completed_at": job_view["completed_at"],
            "active": job_view["active"],
            "display_message": job_view["display_message"],
            "status_label": job_view["status_label"],
            "status_tone": job_view["status_tone"],
            "health_summary": job_view["health_summary"],
            "historical": job_view["historical"],
            "events": [
                {"ts": event["ts"], "phase": event["phase"], "message": event["message"]}
                for event in events
            ],
        }
        return payload
    finally:
        if close:
            db.close()


def _redact_structure(value: Any) -> Any:
    """Recursively applies redact() to every string in a dict/list, so a
    caller merging a subprocess-output string, or a health-check dict that
    might one day include free-text, into diagnostics can never
    accidentally store an unredacted credential -- redaction happens here
    unconditionally, not only at each individual call site."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: _redact_structure(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_redact_structure(item) for item in value]
    return value


def _diagnostics_merge(db: sqlite3.Connection, job_id: int, extra: dict[str, Any]) -> None:
    row = db.execute("SELECT diagnostics_json FROM software_update_jobs WHERE id=?", (job_id,)).fetchone()
    current = json.loads(row["diagnostics_json"] or "{}") if row else {}
    current.update(_redact_structure(extra))
    db.execute("UPDATE software_update_jobs SET diagnostics_json=? WHERE id=?", (json.dumps(current, default=str), job_id))
    db.commit()


def _fail_job(db: sqlite3.Connection, job_id: int, error: str) -> None:
    message = redact(str(error))
    db.execute(
        "UPDATE software_update_jobs SET phase='failed', result='failed', error=?, completed_at=? WHERE id=?",
        (message, now(), job_id),
    )
    _record_event(db, job_id, "failed", message)
    db.commit()


def reap_abandoned_jobs(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    """Finds software_update_jobs rows stuck at a non-terminal phase whose
    recorded worker (the alderpointdns-software-update.service process that
    called run_pending_job()) is provably no longer alive -- process gone,
    PID reused, or a reboot happened since it started -- and fails them with
    a diagnostic message, exactly mirroring app/backup.py's
    reap_abandoned_restores()/worker-identity design (see its docstring for
    the full rationale). Called on application startup and whenever
    Software Updates status is fetched (update_status()), so an abandoned
    job (killed runner, OOM, `systemctl stop`, host crash mid-install)
    never leaves the page reporting "in progress" -- and, critically, never
    leaves the install/upload routes' "an update is already in progress"
    gate permanently blocking every future update -- forever.

    Deliberately does NOT act on any row whose worker is still alive, no
    matter how long it's been running -- a slow download/apt run is never
    killed just for taking a long time. A job still at phase='pending' with
    no worker identity recorded yet is likewise left alone unless
    PENDING_DISPATCH_GRACE_SECONDS has elapsed since it was requested --
    that phase, uniquely, is a normal, expected (if usually brief) window
    between the web request creating the row and the independently
    dispatched runner unit actually picking it up, not evidence of a dead
    worker (see PENDING_DISPATCH_GRACE_SECONDS's docstring above).

    Never attempts any package/service recovery itself: unlike a restore's
    atomic database promotion, there is no single point-of-no-return this
    module controls once apt-get is invoked, so a job reaped while still in
    an early phase (before "installing") is safe to say made no package
    changes; one reaped from "installing" onward must be reported as
    package-state-uncertain, requiring administrator verification
    (`dpkg -l alderpointdns`, `systemctl status`) rather than an assumption
    either way.
    """
    close = conn is None
    db = conn or connect()
    init_db(db)
    reaped: list[dict[str, Any]] = []
    try:
        rows = db.execute(
            "SELECT * FROM software_update_jobs WHERE phase NOT IN ('completed', 'failed')"
        ).fetchall()
        for row in rows:
            if backup._worker_alive(row["worker_pid"], row["worker_start_ticks"], row["worker_boot_id"]):
                continue
            if row["phase"] == "pending" and not row["worker_pid"]:
                requested_age = _seconds_since(row["requested_at"])
                if requested_age is None or requested_age < PENDING_DISPATCH_GRACE_SECONDS:
                    continue
            worker_desc = (
                f"pid {row['worker_pid']} (started {row['started_at']})"
                if row["worker_pid"]
                else "no worker identity recorded (pre-dates lifecycle tracking, or the job never actually started)"
            )
            if row["phase"] in PACKAGE_STATE_UNCERTAIN_PHASES:
                message = (
                    f"update job {row['id']} was abandoned: its worker ({worker_desc}) is no longer running, "
                    f"and it had already reached phase {row['phase']!r} -- the package installation may have been "
                    "partially applied. Verify actual installed state ('dpkg -l alderpointdns', 'systemctl status "
                    "alderpointdns alderpointdns-analytics named dnsdist') before assuming either success or "
                    "failure; the pre-upgrade backup was retained if one was recorded on this job."
                )
            else:
                message = (
                    f"update job {row['id']} was abandoned: its worker ({worker_desc}) is no longer running, "
                    f"but it had not yet reached the 'installing' phase (was {row['phase']!r}) -- no package "
                    "changes were made; it is safe to retry."
                )
            db.execute(
                "UPDATE software_update_jobs SET phase='failed', result='failed', error=?, completed_at=? WHERE id=?",
                (message, now(), row["id"]),
            )
            _record_event(db, row["id"], "failed", message)
            reaped.append({"id": row["id"], "message": message})
        if reaped:
            db.commit()
        return reaped
    finally:
        if close:
            db.close()


def run_pending_job() -> dict[str, Any] | None:
    """The privileged runner's entry point (update-run CLI subcommand,
    always root). Picks up the most recently created job still in
    'pending' phase and drives it through every phase. Returns None if
    there is no pending job (a no-op, not an error -- e.g. the web process
    already started this unit for an older job that finished)."""
    conn = connect()
    try:
        init_db(conn)
        row = conn.execute("SELECT * FROM software_update_jobs WHERE phase='pending' ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        job_id = row["id"]
        worker_pid, worker_start_ticks, worker_boot_id = backup._worker_identity()
        conn.execute(
            "UPDATE software_update_jobs SET started_at=?, worker_pid=?, worker_start_ticks=?, worker_boot_id=? WHERE id=?",
            (now(), worker_pid, worker_start_ticks, worker_boot_id, job_id),
        )
        conn.commit()
        try:
            _run_job(conn, dict(row))
        except SoftwareUpdateError as exc:
            _fail_job(conn, job_id, str(exc))
        except Exception as exc:  # noqa: BLE001 - job diagnostics must capture unexpected failures too
            _fail_job(conn, job_id, f"unexpected error: {exc}")
        return dict(get_job(job_id, conn))
    finally:
        conn.close()


def _run_job(db: sqlite3.Connection, job: dict[str, Any]) -> None:
    job_id = job["id"]

    status = installed_version_status()
    if status.get("mismatch"):
        raise SoftwareUpdateError(
            "installed VERSION/dpkg version drift detected; refusing to proceed automatically -- "
            f"file={status.get('file_version')!r} dpkg={status.get('dpkg_version')!r}"
        )
    if not status.get("dpkg_managed"):
        raise SoftwareUpdateError("Software Updates: unmanaged source installation -- cannot install a package here")

    _set_phase(db, job_id, "checking", "validating job and installed state")
    expected_version: str | None = None
    deb_asset_name: str | None = None
    token = _read_github_token()

    if job["operation"] == "github":
        release = json.loads(job["release_json"] or "{}")
        if not release:
            raise SoftwareUpdateError("job has no release metadata")
        expected_version = (release.get("tag_name") or "").lstrip("v")
        _set_phase(db, job_id, "downloading", f"downloading {expected_version} from GitHub")
        deb_path, deb_sha256 = stage_release(release, token)
    else:
        uploaded_path = Path(job["uploaded_path"])
        if not uploaded_path.is_file() or uploaded_path.parent.resolve() != UPLOAD_STAGING_DIR.resolve():
            raise SoftwareUpdateError("uploaded package path is missing or not confined to the upload staging directory")
        _set_phase(db, job_id, "downloading", "using manually uploaded package")
        STAGED_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        deb_path = STAGED_DIR / uploaded_path.name
        shutil.copy2(uploaded_path, deb_path)
        os.chmod(deb_path, 0o600)
        deb_sha256 = sha256_file(deb_path)
        expected_sha256 = job.get("expected_sha256")
        matched_official = False
        if token or _is_reachable_repo():
            try:
                fields_preview = inspect_deb(deb_path)
                candidate_tag = fields_preview.get("Version", "")
                release = _find_release_for_deb_version(candidate_tag, token)
                if release is not None:
                    _, sums_asset = select_release_assets(release)
                    sums_path = STAGED_DIR / "SHA256SUMS.verify"
                    _download_asset(sums_asset, sums_path, token)
                    expected_official = _parse_sha256sums(sums_path.read_text(errors="replace"), _deb_asset_name_for(release))
                    matched_official = expected_official.lower() == deb_sha256.lower()
                    expected_version = (release.get("tag_name") or "").lstrip("v")
            except SoftwareUpdateError:
                matched_official = False
        if not matched_official:
            if not expected_sha256:
                raise SoftwareUpdateError(
                    "could not automatically verify this upload against an official GitHub release "
                    "(offline, private repo unreachable, or no matching release found); "
                    "provide an expected SHA-256 checksum to proceed"
                )
            if expected_sha256.strip().lower() != deb_sha256.lower():
                raise SoftwareUpdateError(f"uploaded package checksum {deb_sha256} does not match the provided expected checksum")
    deb_asset_name = deb_path.name

    db.execute("UPDATE software_update_jobs SET staged_path=?, staged_sha256=? WHERE id=?", (str(deb_path), deb_sha256, job_id))
    db.commit()

    _set_phase(db, job_id, "validating", f"validating {deb_asset_name}")
    fields = validate_candidate_package(deb_path, expected_version)
    candidate_deb_version = fields["Version"]
    db.execute("UPDATE software_update_jobs SET candidate_version=? WHERE id=?", (candidate_deb_version, job_id))
    db.commit()

    _set_phase(db, job_id, "backing_up", "creating mandatory pre-upgrade backup")
    try:
        backup_path = backup.create_backup(
            purpose="pre_upgrade",
            purpose_metadata={"job_id": job_id, "from_version": job["current_version"], "to_version": candidate_deb_version},
        )
    except Exception as exc:
        raise SoftwareUpdateError(f"pre-upgrade backup failed; aborting update (no changes made): {exc}") from None
    backup_row = backup.last_backup()
    backup_id = backup_row.get("id") if backup_row else None
    db.execute("UPDATE software_update_jobs SET backup_id=?, backup_path=? WHERE id=?", (backup_id, str(backup_path), job_id))
    db.commit()

    _set_phase(db, job_id, "simulating", "running apt simulation")
    sim_output = simulate_install(deb_path)
    _diagnostics_merge(db, job_id, {"apt_simulate_output": redact(sim_output)[:8000]})

    _set_phase(db, job_id, "installing", "installing package via apt")
    try:
        install_proc = run(["apt-get", "install", "-y", "-o", "Dpkg::Options::=--force-confold", str(deb_path)], check=True, timeout=300)
    except subprocess.CalledProcessError as exc:
        _diagnostics_merge(db, job_id, {"apt_install_output": redact(exc.output or "")[:8000]})
        raise SoftwareUpdateError(f"apt-get install failed: {redact(exc.output or '')[:2000]}") from None
    except subprocess.TimeoutExpired:
        raise SoftwareUpdateError("apt-get install timed out") from None
    _diagnostics_merge(db, job_id, {"apt_install_output": redact(install_proc.stdout or "")[:8000]})

    # postinst already (unconditionally) restarts alderpointdns,
    # alderpointdns-analytics, named, and dnsdist as part of the apt-get
    # install call above -- this runner is a separate systemd unit from
    # alderpointdns.service, so it survives that restart. Give the
    # restarted services a brief window to settle before checking health.
    _set_phase(db, job_id, "restarting", "waiting for services to restart")
    time.sleep(3)
    for _ in range(20):
        if all(_service_active(unit) for unit in SERVICES):
            break
        time.sleep(1)

    _set_phase(db, job_id, "postcheck", "running post-upgrade health check with newly installed code")
    health = run_fresh_post_upgrade_health_check(expected_deb_version=candidate_deb_version)
    _diagnostics_merge(db, job_id, {"post_upgrade_health": health})
    if not health["ok"]:
        health_summary = _health_failure_summary(health)
        if _installed_but_health_failed(health):
            result = "installed_health_failed"
            error = (
                f"Update installed, but post-upgrade health verification failed: {health_summary}. "
                f"Pre-upgrade backup retained at {backup_path}."
            )
            event_message = "update installed, but post-upgrade health verification failed; pre-upgrade backup was retained"
        else:
            result = "failed"
            error = f"post-upgrade health check failed: {health_summary}; details: {json.dumps(health, default=str)}"
            event_message = "post-upgrade health check failed; pre-upgrade backup was retained"
        db.execute(
            "UPDATE software_update_jobs SET phase='failed', result=?, error=?, completed_at=? WHERE id=?",
            (result, error, now(), job_id),
        )
        _record_event(db, job_id, "failed", event_message)
        db.commit()
        return

    db.execute("UPDATE software_update_jobs SET phase='completed', result='success', completed_at=? WHERE id=?", (now(), job_id))
    _record_event(db, job_id, "completed", f"update to {candidate_deb_version} completed successfully")
    db.commit()


def _is_reachable_repo() -> bool:
    try:
        socket.create_connection(("api.github.com", 443), timeout=3).close()
        return True
    except OSError:
        return False


def _deb_asset_name_for(release: dict[str, Any]) -> str:
    deb_asset, _ = select_release_assets(release)
    return deb_asset["name"]


def _find_release_for_deb_version(candidate_deb_version: str, token: str | None) -> dict[str, Any] | None:
    repo = settings().get("github_repo", DEFAULT_GITHUB_REPO)
    try:
        releases = list_releases(repo, token)
    except SoftwareUpdateError:
        return None
    for release in releases:
        if release.get("draft"):
            continue
        tag_version = _release_semver(release)
        if tag_version is None:
            continue
        if dpkg_compare(candidate_deb_version, "eq", source_version_to_deb_form(tag_version)):
            return release
    return None


# ---------------------------------------------------------------------------
# Update check (the "Check for Updates" action + the scheduled timer)
# ---------------------------------------------------------------------------

# Non-blocking: a "Check for Updates" click that lands while the
# scheduled timer's own update-check happens to already be running (or
# vice versa) must not queue up and re-run the exact same check a moment
# later -- it should simply report that a check is already in flight and
# let the caller re-read whatever the in-flight check is about to write.
# Unlike deploy()'s blocking DEPLOY_LOCK (which serializes genuinely
# different work that must eventually all happen), two concurrent
# update-checks are redundant by definition -- they'd both just re-fetch
# the same GitHub releases feed and write the same settings.
CHECK_LOCK = Path("/var/lib/alderpointdns/software-updates/check.lock")


def run_check(force: bool = False) -> dict[str, Any]:
    CHECK_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with CHECK_LOCK.open("w") as lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return {"skipped": True, "reason": "a check is already in progress"}
        try:
            return _run_check_locked(force=force)
        finally:
            fcntl.flock(lock_handle, fcntl.LOCK_UN)


def _run_check_locked(force: bool) -> dict[str, Any]:
    conn = connect()
    try:
        init_db(conn)
        cfg = settings(conn)
        if not force and not _truthy(cfg.get("auto_check_enabled", "1")):
            return {"skipped": True, "reason": "automatic checking is disabled"}
        status = installed_version_status()
        result: dict[str, Any] = {"checked_at": now()}
        try:
            token = _read_github_token()
            repo = cfg.get("github_repo", DEFAULT_GITHUB_REPO)
            releases = list_releases(repo, token)
            candidate = select_candidate_release(releases, cfg.get("channel", "stable"), status.get("resolved", "unknown"))
            _set_setting(conn, "last_checked_at", result["checked_at"])
            _set_setting(conn, "last_check_error", "")
            _set_setting(conn, "latest_release_json", json.dumps(candidate) if candidate else "{}")
            conn.commit()
            result["update_available"] = candidate is not None
            result["candidate"] = candidate
        except SoftwareUpdateError as exc:
            message = redact(str(exc))
            _set_setting(conn, "last_checked_at", result["checked_at"])
            _set_setting(conn, "last_check_error", message)
            conn.commit()
            result["update_available"] = False
            result["error"] = message
        return result
    finally:
        conn.close()


def update_status(conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Everything the Software Updates page needs to render."""
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        # See reap_abandoned_jobs()'s docstring: called here (in addition
        # to the application-startup hook) so a job whose runner died
        # since the last check is caught the moment anything asks for
        # Software Updates status, not only at the next restart.
        reap_abandoned_jobs(db)
        cfg = settings(db)
        version_status = installed_version_status()
        try:
            latest = json.loads(cfg.get("latest_release_json", "{}"))
        except json.JSONDecodeError:
            latest = {}
        job = latest_job(db)
        events = job_events(job["id"], db) if job else []
        auto_check_enabled = _truthy(cfg.get("auto_check_enabled", "1"))
        return {
            "settings": cfg,
            "version_status": version_status,
            "credential": credential_status(),
            "latest_release": latest or None,
            "update_available": bool(latest),
            "job": _job_view(dict(job), events, last_checked_at=cfg.get("last_checked_at")) if job else None,
            "job_events": events,
            "check_interval_hours": _clamped_check_interval_hours(cfg),
            # Only queried when checking is actually on -- a disabled
            # schedule must not display a next-check time at all, matching
            # filter_schedule_context()'s equivalent guard.
            "next_check_at": next_check_at() if auto_check_enabled else None,
        }
    finally:
        if close:
            db.close()
