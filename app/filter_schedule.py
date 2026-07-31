#!/usr/bin/env python3
"""Alderpoint DNS automatic filter (blocklist) update scheduling.

Holds the global Filter Update Interval setting and the systemd timer
deployment for it, in the same shape as app/backup.py's scheduled-backup
support: a small key/value settings table in the shared Alderpoint DNS
database, a packaged ``alderpointdns-filter-update.timer`` carrying safe
defaults, and a runtime systemd drop-in
(``/etc/systemd/system/alderpointdns-filter-update.timer.d/alderpointdns.conf``)
regenerated from the stored setting whenever the operator saves the schedule.

The interval is a fixed, server-side allowlist (see ``INTERVAL_CHOICES``).
Only values from that allowlist ever reach the drop-in file or a systemctl
argument -- operator input is validated to one of those canonical keys first
and the timer expression is then looked up from ``INTERVAL_HOURS``, so no
user-supplied text (arbitrary numbers, cron/systemd expressions, unit names,
paths, shell metacharacters) can be written into a unit file or passed to
systemd.

The timer runs ``alderpointdns_compiler.py filter-update-run``, which delegates
to the compiler's normal ``deploy()`` pipeline: it downloads only enabled
sources, recompiles the RPZ, validates it, activates it atomically,
health-checks DNS, rolls back on failure, and records a ``deployments`` row
(marked ``trigger='scheduled'``). ``deploy()`` holds an exclusive flock, so a
timer run can never overlap a manual deploy or another timer run, and a single
failed download leaves the other lists updating with the last valid policy
still active.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Any


DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")
SYSTEMD_DIR = Path("/etc/systemd/system")

TIMER_UNIT = "alderpointdns-filter-update.timer"
FILTER_TIMER_OVERRIDE_DIR = SYSTEMD_DIR / f"{TIMER_UNIT}.d"
FILTER_TIMER_OVERRIDE = FILTER_TIMER_OVERRIDE_DIR / "alderpointdns.conf"

DISABLED = "disabled"

# The complete, fixed set of selectable intervals: canonical stored value ->
# operator-visible label. Stored values are the interval in hours as text
# (matching the TEXT key/value settings table), plus the sentinel "disabled".
INTERVAL_CHOICES: tuple[tuple[str, str], ...] = (
    (DISABLED, "Disabled — No Updates"),
    ("1", "1 Hour"),
    ("12", "12 Hours"),
    ("24", "1 Day"),
    ("72", "3 Days"),
    ("168", "1 Week"),
)

INTERVAL_LABELS = dict(INTERVAL_CHOICES)
INTERVAL_VALUES = tuple(value for value, _ in INTERVAL_CHOICES)

# Canonical value -> hours actually written into the timer drop-in. The
# drop-in is always rendered from this mapping, never from operator input.
INTERVAL_HOURS: dict[str, int] = {"1": 1, "12": 12, "24": 24, "72": 72, "168": 168}

DEFAULT_INTERVAL = "24"

SETTINGS_DEFAULTS = {
    "interval_hours": DEFAULT_INTERVAL,
    "last_attempt": "",
    "last_success": "",
    "last_result": "",
}

MAX_RESULT_CHARS = 500
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://\S*")


class FilterScheduleError(ValueError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check)


def init_db(conn: sqlite3.Connection | None = None) -> None:
    """Creates the settings table and seeds defaults.

    Idempotent: an already-stored valid interval is never overwritten, so a
    reinstall/upgrade keeps the operator's cadence. A stored value that is not
    in the fixed allowlist (a hand-edited or corrupted row) is reset to the
    fresh-install default rather than being trusted.
    """
    close = conn is None
    db = conn or connect()
    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS filter_update_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        db.executemany(
            "INSERT OR IGNORE INTO filter_update_settings(key, value) VALUES (?, ?)",
            list(SETTINGS_DEFAULTS.items()),
        )
        row = db.execute("SELECT value FROM filter_update_settings WHERE key='interval_hours'").fetchone()
        if row is not None and row["value"] not in INTERVAL_VALUES:
            db.execute(
                "UPDATE filter_update_settings SET value=? WHERE key='interval_hours'",
                (DEFAULT_INTERVAL,),
            )
        db.commit()
    finally:
        if close:
            db.close()


def settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    init_db(conn)
    close = conn is None
    db = conn or connect()
    try:
        return {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM filter_update_settings")}
    finally:
        if close:
            db.close()


def validate_interval(raw: Any) -> str:
    """Maps operator input to one of the fixed canonical values.

    Anything else -- an interval that is merely numeric, a cron or systemd
    time expression, a unit name, a path, or shell text -- is rejected.
    """
    if isinstance(raw, bool):
        raise FilterScheduleError(_interval_error())
    if isinstance(raw, int):
        candidate = str(raw)
    elif isinstance(raw, str):
        candidate = raw.strip().lower()
    else:
        raise FilterScheduleError(_interval_error())
    if candidate not in INTERVAL_VALUES:
        raise FilterScheduleError(_interval_error())
    return candidate


def _interval_error() -> str:
    labels = ", ".join(label for _, label in INTERVAL_CHOICES)
    return f"filter update interval must be one of: {labels}"


def validate_settings(values: dict[str, Any]) -> dict[str, str]:
    return {"interval_hours": validate_interval(values.get("interval_hours", DEFAULT_INTERVAL))}


def update_settings(values: dict[str, Any]) -> None:
    validated = validate_settings(values)
    conn = connect()
    try:
        init_db(conn)
        for key, value in validated.items():
            conn.execute(
                "INSERT INTO filter_update_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
        conn.commit()
    finally:
        conn.close()


def interval_value(cfg: dict[str, str] | None = None) -> str:
    cfg = cfg if cfg is not None else settings()
    candidate = cfg.get("interval_hours", DEFAULT_INTERVAL)
    return candidate if candidate in INTERVAL_VALUES else DEFAULT_INTERVAL


def is_enabled(cfg: dict[str, str] | None = None) -> bool:
    return interval_value(cfg) != DISABLED


def interval_label(value: str) -> str:
    return INTERVAL_LABELS.get(value, INTERVAL_LABELS[DEFAULT_INTERVAL])


def drop_in_content(value: str) -> str:
    hours = INTERVAL_HOURS[value]
    return "[Timer]\n" f"OnBootSec={hours}h\n" f"OnUnitActiveSec={hours}h\n"


# ---------------------------------------------------------------------------
# Timer deployment (root, via alderpointdns_compiler.py filter-schedule-deploy)
# ---------------------------------------------------------------------------

def deploy_filter_schedule(conn: sqlite3.Connection | None = None) -> str:
    close = conn is None
    db = conn or connect()
    init_db(db)
    try:
        value = interval_value(settings(db))
        if value == DISABLED:
            # Remove the drop-in entirely so nothing stale is left behind; the
            # packaged unit keeps its own safe default and the timer itself is
            # stopped and disabled below.
            FILTER_TIMER_OVERRIDE.unlink(missing_ok=True)
        else:
            FILTER_TIMER_OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
            FILTER_TIMER_OVERRIDE.write_text(drop_in_content(value))
        run(["systemctl", "daemon-reload"])
        if value == DISABLED:
            # check=False mirrors deploy_backup_schedule(): disabling a timer
            # that was never enabled must not fail the request.
            run(["systemctl", "disable", "--now", TIMER_UNIT], check=False)
            state = "disabled"
        else:
            run(["systemctl", "enable", "--now", TIMER_UNIT])
            state = "enabled"
        return json.dumps(
            {
                "state": state,
                "interval": value,
                "interval_label": interval_label(value),
                "timer": TIMER_UNIT,
            }
        )
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Scheduled-run bookkeeping
# ---------------------------------------------------------------------------

def _set(key: str, value: str, conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        db.execute(
            "INSERT INTO filter_update_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        db.commit()
    finally:
        if close:
            db.close()


def record_attempt(conn: sqlite3.Connection | None = None) -> str:
    stamp = now()
    _set("last_attempt", stamp, conn)
    return stamp


def record_success(conn: sqlite3.Connection | None = None) -> str:
    stamp = now()
    _set("last_success", stamp, conn)
    return stamp


def sanitize_message(text: str) -> str:
    """Strips URLs (which can carry list-subscription tokens or credentials)
    and truncates, so stored automatic-run summaries only ever hold counts and
    a short error description -- never query data or secrets."""
    cleaned = _URL_RE.sub("[url removed]", (text or "").strip())
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > MAX_RESULT_CHARS:
        cleaned = cleaned[:MAX_RESULT_CHARS] + "..."
    return cleaned


def record_result(
    status: str,
    active_domains: int = 0,
    error: str = "",
    deployment_id: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "finished_at": now(),
        "status": status,
        "active_domains": int(active_domains or 0),
        "error": sanitize_message(error),
    }
    if deployment_id is not None:
        result["deployment_id"] = int(deployment_id)
    _set("last_result", json.dumps(result), conn)
    return result


def last_result(cfg: dict[str, str] | None = None) -> dict[str, Any] | None:
    cfg = cfg if cfg is not None else settings()
    raw = cfg.get("last_result") or ""
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


# ---------------------------------------------------------------------------
# Next-run reporting (unprivileged: `systemctl show` needs no privileges)
# ---------------------------------------------------------------------------

def parse_next_elapse(output: str) -> str | None:
    for line in (output or "").splitlines():
        key, sep, value = line.partition("=")
        if not sep or key.strip() != "NextElapseUSecRealtime":
            continue
        value = value.strip()
        if not value or value in {"n/a", "0"}:
            return None
        return value
    return None


def parse_next_from_timers_json(output: str) -> str | None:
    try:
        entries = json.loads(output or "[]")
    except ValueError:
        return None
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("unit") != TIMER_UNIT:
            continue
        next_usec = entry.get("next")
        if isinstance(next_usec, int) and next_usec > 0:
            stamp = dt.datetime.fromtimestamp(next_usec / 1_000_000, dt.timezone.utc)
            return stamp.replace(microsecond=0).isoformat()
    return None


def next_run_at() -> str | None:
    """Best-effort next scheduled elapse, or None when it cannot be
    determined (systemd unavailable, unit not installed yet, timer inactive).
    Never raises: the Blocklists page must render regardless.

    Monotonic timers (OnBootSec/OnUnitActiveSec, which is what the filter
    update drop-in writes) have an empty NextElapseUSecRealtime property;
    only `systemctl list-timers` projects their next elapse onto the wall
    clock, so prefer its JSON output and keep the property parse as a
    fallback for systemd versions without JSON list-timers output."""
    try:
        result = run(["systemctl", "list-timers", TIMER_UNIT, "--all", "-o", "json"], check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 0:
        parsed = parse_next_from_timers_json(result.stdout or "")
        if parsed:
            return parsed
    try:
        result = run(["systemctl", "show", TIMER_UNIT, "--property=NextElapseUSecRealtime"], check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return parse_next_elapse(result.stdout or "")
