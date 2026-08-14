#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Path as PathParam, Request, Response, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

from app import analytics, auth, backup, clients as clients_model, custom_rules as custom_rules_model, dns_cache, encryption, filter_schedule, importer, local_dns, network_config, notifications, replication, software_updates, upstream_dns
from app import blocklist_categories
from app import service_logs
from app.alderpointdns_compiler import (
    AlderpointDNSConnection,
    DB_PATH,
    HEALTH_ERROR,
    HEALTH_UNSUPPORTED_FORMAT,
    HEALTH_USING_CACHED,
    HEALTH_WARNING,
    add_source,
    init_db,
    normalize_domain,
    source_health,
)
from app.db_retry import DatabaseBusyError, is_lock_error, retry_on_locked


ROOT = Path("/opt/alderpointdns")
TEMPLATES = Jinja2Templates(directory=str(ROOT / "web" / "templates"))
STATIC_DIR = ROOT / "web" / "static"
SESSION_MAX_AGE = 8 * 60 * 60
SECRET_FILE = Path("/etc/alderpointdns/secrets.env")
app = FastAPI(title="Alderpoint DNS")


def static_asset_fingerprint(directory: Path) -> str:
    """A short content hash of every file actually shipped under
    web/static, computed once (see STATIC_ASSET_FINGERPRINT below) from the
    real bytes on disk -- not from the installed package version string.
    An appliance upgrade always changes the files under web/static/ when
    (and only when) it actually changes them, which is exactly what needs
    to invalidate a browser's cache; the package version alone can't be
    trusted for that (a version bump with no front-end change would force
    every returning browser to refetch unnecessarily, and -- the actual
    bug this fixes -- nothing about the version string is otherwise tied
    to what a browser has cached under a fixed, unversioned /static/app.js
    URL in the first place).

    Appended as a cache-busting query string (see static_url()) to every
    /static asset URL templates emit: a browser that already cached the
    current bytes under the current URL keeps reusing them with zero
    network round-trips (see VersionedStaticFiles below), while a real
    Alderpoint package upgrade that changes app.js/app.css always produces
    a new URL a fresh page load fetches for real -- no Ctrl+Shift+R or
    manual cache clear required. Confirmed live: the installed app.js on
    disk and http://127.0.0.1:3000/static/app.js both already reflected a
    new build, but a browser tab left open across the upgrade kept
    executing the old cached app.js at the old, unchanged URL until a hard
    refresh -- the bug was the fixed URL, not anything server-side about
    what bytes it served.
    """
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(directory).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


STATIC_ASSET_FINGERPRINT = static_asset_fingerprint(STATIC_DIR)


def static_url(filename: str) -> str:
    return f"/static/{filename}?v={STATIC_ASSET_FINGERPRINT}"


TEMPLATES.env.globals["static_url"] = static_url


class VersionedStaticFiles(StaticFiles):
    """Identical to StaticFiles except: a request carrying the `v=`
    cache-busting query parameter static_url() appends gets a long-lived,
    immutable Cache-Control -- safe because that query parameter *is* a
    hash of the exact bytes being served, so the same URL can never
    legitimately resolve to different content later. A request for the
    bare, unversioned path (a stale bookmark, a direct curl, anything not
    generated through static_url()) gets Starlette's ordinary
    ETag/Last-Modified conditional-GET behavior unchanged -- never told to
    cache for a year on nothing but a guess."""

    def file_response(self, full_path, stat_result, scope, status_code: int = 200):
        response = super().file_response(full_path, stat_result, scope, status_code)
        if b"v=" in scope.get("query_string", b""):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response


app.mount("/static", VersionedStaticFiles(directory=str(STATIC_DIR)), name="static")


def secure_session_cookie_enabled() -> bool:
    return os.getenv("ALDERPOINTDNS_COOKIE_SECURE", "").strip().lower() in {"1", "true", "yes", "on"}


def _log(priority: int, message: str) -> None:
    """Emits a line prefixed with its syslog priority (systemd's default
    SyslogLevelPrefix=yes strips and honors "<N>" on stdout/stderr), matching
    the convention used by app/analytics.py's collector diagnostics."""
    print(f"<{priority}>webapp: {message}", file=sys.stderr, flush=True)


@app.on_event("startup")
def _ensure_schema() -> None:
    # Schema creation/migration happens exactly once per process lifetime,
    # here -- never inside db(), which is called on essentially every
    # request. init_db() is itself cheap and interprocess-lock-protected
    # once the database is already at its current schema version, so this
    # is safe even when multiple alderpointdns processes start concurrently.
    init_db()


@app.on_event("startup")
def _replication_autostart() -> None:
    # Re-establishes the primary listener or replica poller thread after a
    # service restart, matching whichever role was previously configured.
    # Deliberately best-effort (replication.autostart() never raises): a
    # replication bug must never prevent alderpointdns.service from starting.
    replication.autostart()


@app.on_event("startup")
def _upstream_probe_autostart() -> None:
    # Lightweight direct upstream probes are background telemetry only:
    # they read configured resolver rows and update probe_* fields, but
    # never mutate dnsdist's runtime configuration or restart services.
    upstream_dns.start_upstream_probe_scheduler()


@app.on_event("startup")
def _reap_abandoned_restores() -> None:
    # A restore that was mid-flight when this process (or the whole host)
    # died would otherwise sit at status='running' forever -- this is
    # exactly what happened to the real large-analytics restore that
    # motivated this check (see docs/backup-recovery.md). last_restore()
    # also reaps on every view, but startup is the one moment guaranteed to
    # run after a host reboot or service restart, so an abandoned restore
    # from before that event is caught immediately rather than waiting for
    # someone to open the Backup & Restore page. Best-effort: must never
    # prevent the web service from starting.
    try:
        reaped = backup.reap_abandoned_restores()
        for entry in reaped:
            _log(4, f"reaped abandoned restore id={entry['id']}: {entry['message']}")
    except Exception as exc:  # noqa: BLE001
        _log(3, f"reap_abandoned_restores failed at startup: {exc}")


@app.on_event("startup")
def _reap_abandoned_software_update_jobs() -> None:
    # Mirrors _reap_abandoned_restores() above exactly, for
    # software_update_jobs: a job whose runner (alderpointdns-software-
    # update.service) died mid-flight would otherwise sit at a
    # non-terminal phase forever, permanently blocking every future
    # install/upload attempt behind the "an update is already in
    # progress" gate. software_updates.update_status() also reaps on
    # every view; startup additionally catches one abandoned by a host
    # reboot or service restart before anyone opens the page.
    try:
        reaped = software_updates.reap_abandoned_jobs()
        for entry in reaped:
            _log(4, f"reaped abandoned software update job id={entry['id']}: {entry['message']}")
    except Exception as exc:  # noqa: BLE001
        _log(3, f"reap_abandoned_jobs failed at startup: {exc}")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def format_local_datetime(iso_str: str | None) -> str:
    """Renders a canonical UTC/ISO-8601 timestamp (as stored in the
    database and in backup manifests) for display in the server's
    configured local timezone, e.g. "Aug 8, 2026 at 6:47 PM MDT". Purely a
    display transform -- registered as the `local_time` Jinja filter and
    never used for anything that affects correctness (backup/restore
    lookups always match by history id or the literal, unparsed filename;
    manifest.json and backup_history.created_at stay UTC/ISO-8601)."""
    if not iso_str:
        return ""
    try:
        parsed = dt.datetime.fromisoformat(iso_str)
    except ValueError:
        return iso_str
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    # .astimezone() with no argument converts to the system's configured
    # local timezone (TZ env var, falling back to /etc/localtime) -- this
    # process never stores or guesses a timezone of its own.
    local = parsed.astimezone()
    hour12 = local.hour % 12 or 12
    ampm = "AM" if local.hour < 12 else "PM"
    # Avoid %-d/%-I (glibc-only strftime extensions) for portability.
    tz_label = local.strftime("%Z") or local.strftime("%z") or "UTC"
    return f"{local.strftime('%b')} {local.day}, {local.year} at {hour12}:{local.minute:02d} {ampm} {tz_label}"


# Registered here (not only inside render()) so every consumer of the
# module-level TEMPLATES object -- including scripts that call
# TEMPLATES.get_template(...).render(...) directly (tests/test_web_smoke.sh,
# tests/test_encryption_layout.sh) rather than going through render() below
# -- gets the filter without having to know it exists. render() additionally
# re-applies it with setdefault() for the handful of tests that replace
# webapp.TEMPLATES with a brand new Jinja2Templates instance at runtime.
TEMPLATES.env.filters["local_time"] = format_local_datetime


def get_secret() -> str:
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    if SECRET_FILE.exists():
        for line in SECRET_FILE.read_text().splitlines():
            if line.startswith("ALDERPOINTDNS_SESSION_SECRET="):
                return line.split("=", 1)[1].strip()
    secret = secrets.token_urlsafe(48)
    with SECRET_FILE.open("a") as handle:
        handle.write(f"ALDERPOINTDNS_SESSION_SECRET={secret}\n")
    os.chmod(SECRET_FILE, 0o640)
    return secret


serializer = URLSafeTimedSerializer(get_secret(), salt="alderpointdns-session")


def db() -> sqlite3.Connection:
    """Returns a connection meant to be used as `with db() as conn: ...`.
    AlderpointDNSConnection.__exit__ closes the connection in addition to the
    stdlib's commit/rollback-on-exit -- a bare sqlite3.Connection here would
    leak an fd per call, since its context manager only commits/rolls back.

    This is a pure connection factory: it must not create tables, run
    migrations, or change the journal mode. Schema is guaranteed to already
    exist by the app-startup `_ensure_schema()` hook (see above) and by
    package install/upgrade (which already invoke init_db()); repeating that
    work on every request is what caused a routine authenticated request to
    contend with a long-running writer for SQLite's single writer lock."""
    conn = sqlite3.connect(DB_PATH, factory=AlderpointDNSConnection, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def audit_log(conn: sqlite3.Connection, admin_id: int | None, username: str, action: str, success: bool, ip: str | None, detail: str = "") -> None:
    """Records an administrative security action. Never pass password or
    hash content in `detail` -- only short, non-secret context."""
    conn.execute(
        "INSERT INTO admin_audit_log(at, admin_id, username, action, success, ip, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (utc_now(), admin_id, username, action, 1 if success else 0, ip, detail),
    )


def _session_id_from_cookie(request: Request) -> str | None:
    raw = request.cookies.get("alderpointdns_session")
    if not raw:
        return None
    try:
        return serializer.loads(raw, max_age=SESSION_MAX_AGE).get("sid")
    except BadSignature:
        return None


def signed_session(request: Request) -> dict[str, Any]:
    """The current server-side session row (joined with the admin username
    when authenticated), keyed only by an opaque id carried in the signed
    cookie -- never the session's mutable state itself. Returns {} for a
    missing, invalid, or expired session."""
    session_id = _session_id_from_cookie(request)
    if not session_id:
        return {}
    with db() as conn:
        row = conn.execute(
            """
            SELECT sessions.id AS id, sessions.admin_id AS admin_id, sessions.csrf AS csrf,
                   sessions.created_at AS created_at, sessions.last_seen_at AS last_seen_at,
                   sessions.ip AS ip, sessions.user_agent AS user_agent, admins.username AS admin
            FROM sessions LEFT JOIN admins ON admins.id = sessions.admin_id
            WHERE sessions.id = ?
            """,
            (session_id,),
        ).fetchone()
    return dict(row) if row else {}


_ANON_SESSION_MAX_AGE_SECONDS = 6 * 60 * 60


def _create_session_row(request: Request, admin_id: int | None) -> dict[str, Any]:
    """Creates and persists a new session row (authenticated when `admin_id`
    is given, otherwise an anonymous pre-login session that exists solely to
    hold a stable CSRF token for the setup/login forms). Does not touch the
    response; call _set_session_cookie() separately."""
    session_id = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    ts = utc_now()
    ip = request.client.host if request.client else None
    user_agent = (request.headers.get("user-agent") or "")[:300]
    anon_cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=_ANON_SESSION_MAX_AGE_SECONDS)).isoformat()
    auth_cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=SESSION_MAX_AGE)).isoformat()
    with db() as conn:
        # Anonymous (pre-login) session rows are created on every first
        # visit to an unauthenticated page; authenticated rows outlive their
        # cookie's own itsdangerous max_age once a browser stops using them.
        # Both are pruned opportunistically here so the table never
        # accumulates unbounded stale rows.
        conn.execute("DELETE FROM sessions WHERE admin_id IS NULL AND created_at < ?", (anon_cutoff,))
        conn.execute("DELETE FROM sessions WHERE admin_id IS NOT NULL AND last_seen_at < ?", (auth_cutoff,))
        conn.execute(
            "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, admin_id, ts, ts, ip, user_agent, csrf),
        )
    return {"id": session_id, "admin_id": admin_id, "csrf": csrf, "created_at": ts, "last_seen_at": ts, "ip": ip, "user_agent": user_agent}


def _set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        "alderpointdns_session",
        serializer.dumps({"sid": session_id}),
        httponly=True,
        samesite="strict",
        secure=secure_session_cookie_enabled(),
        max_age=SESSION_MAX_AGE,
    )


def set_session(request: Request, response: Response, admin_id: int) -> str:
    """Starts a fresh authenticated session (a new row, never reusing a
    pre-login anonymous one) and returns its CSRF token."""
    session = _create_session_row(request, admin_id)
    _set_session_cookie(response, session["id"])
    return session["csrf"]


def clear_session(request: Request, response: Response) -> None:
    session_id = _session_id_from_cookie(request)
    if session_id:
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    response.delete_cookie("alderpointdns_session")


def revoke_other_sessions(admin_id: int, keep_session_id: str) -> int:
    with db() as conn:
        cursor = conn.execute("DELETE FROM sessions WHERE admin_id=? AND id<>?", (admin_id, keep_session_id))
        return cursor.rowcount


def admin_count() -> int:
    with db() as conn:
        return conn.execute("SELECT count(*) FROM admins").fetchone()[0]


def current_admin(request: Request) -> sqlite3.Row:
    session = signed_session(request)
    admin_id = session.get("admin_id")
    if not admin_id:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    with db() as conn:
        row = conn.execute("SELECT * FROM admins WHERE id=?", (admin_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        # last_seen_at is noncritical bookkeeping: a page load must still
        # succeed and authentication must still hold even if a concurrent
        # long-running writer (a deploy, backup, or blocklist update) is
        # holding SQLite's writer lock. Retry briefly, then skip this one
        # update and log a warning rather than failing the request.
        try:
            retry_on_locked(
                lambda: conn.execute("UPDATE sessions SET last_seen_at=? WHERE id=?", (utc_now(), session["id"])),
                attempts=3,
                base_delay=0.02,
                max_delay=0.2,
            )
        except DatabaseBusyError:
            _log(4, f"skipped last_seen_at update for session {session['id']}: database busy")
    return row


def check_csrf(request: Request, token: str) -> None:
    if not token or signed_session(request).get("csrf") != token:
        raise HTTPException(status_code=403, detail="invalid csrf token")


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def run(command: list[str]) -> tuple[int, str]:
    proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout[-4000:]


def service_state(name: str) -> str:
    code, out = run(["systemctl", "is-active", name])
    return out.strip() if code == 0 else "inactive"


def analytics_collector_state() -> str:
    """Like service_state("alderpointdns-analytics"), but also catches the
    "active but dead" case: systemd can report the unit as active while its
    writer thread has silently stopped making progress (e.g. terminated
    after a database-lock storm exceeded its retry budget, per
    analytics.Collector.writer_loop). Falls back to the plain systemd state
    whenever the heartbeat is missing or fresh, so a normal boot/upgrade
    window before the first writer cycle never reads as failed."""
    state = service_state("alderpointdns-analytics")
    if state != "active":
        return state
    health = analytics.writer_health()
    if health["status"] == "unknown":
        return state
    if health["stale"] or health["status"] == "dead":
        return "failed"
    return state


def status_tone(state: str) -> str:
    normalized = (state or "").lower()
    if normalized in {"active", "listening", "enabled", "present", "healthy", "passed"}:
        return "healthy"
    if normalized in {"inactive", "failed", "missing", "invalid", "down"}:
        return "down"
    if "unavailable" in normalized:
        return "unavailable"
    return "degraded"


def protection_state(active_rules: int, bind_state: str, dnsdist_state: str, collector_state: str) -> dict[str, str]:
    if bind_state != "active" or dnsdist_state != "active":
        return {"label": "Degraded", "tone": "degraded"}
    if active_rules <= 0:
        return {"label": "Disabled", "tone": "down"}
    if collector_state != "active":
        return {"label": "Degraded", "tone": "degraded"}
    return {"label": "Active", "tone": "healthy"}


def global_service_status() -> dict[str, str]:
    try:
        alderpointdns_state = service_state("alderpointdns")
        bind_state = service_state("named")
        dnsdist_state = service_state("dnsdist")
        collector_state = analytics_collector_state()
    except Exception:
        return {"label": "Unknown", "tone": "unavailable", "detail": "service status unavailable"}
    core = {"Alderpoint DNS": alderpointdns_state, "BIND": bind_state, "dnsdist": dnsdist_state}
    if all(state == "active" for state in core.values()) and collector_state == "active":
        return {"label": "Active", "tone": "healthy", "detail": "all core services active"}
    if any(state in {"failed", "inactive"} for state in core.values()):
        down = ", ".join(name for name, state in core.items() if state != "active")
        return {"label": "Inactive", "tone": "down", "detail": f"core service down: {down}"}
    if collector_state != "active":
        return {"label": "Degraded", "tone": "degraded", "detail": "analytics collector is not active"}
    return {"label": "Degraded", "tone": "degraded", "detail": "one or more services are not fully healthy"}


def analytics_category_breakdown(range_key: str) -> list[dict[str, Any]]:
    analytics.init_analytics_db()
    since = analytics.utc_now() - analytics.range_seconds(range_key)
    with analytics.connect() as conn:
        rows = conn.execute(
            """
            SELECT coalesce(nullif(block_category, ''), 'Unavailable') AS label, count(*) AS value
            FROM query_events
            WHERE blocked=1 AND ts >= ?
            GROUP BY label
            ORDER BY value DESC
            LIMIT 8
            """,
            (since,),
        ).fetchall()
    return [dict(row) for row in rows]


def system_health(bind_state: str | None = None, dnsdist_state: str | None = None, alderpointdns_state: str | None = None) -> list[dict[str, str]]:
    named = bind_state or service_state("named")
    dnsdist_current = dnsdist_state or service_state("dnsdist")
    alderpointdns_current = alderpointdns_state or service_state("alderpointdns")
    collector = analytics_collector_state()
    backend = "healthy" if named == "active" and dnsdist_current == "active" else "degraded"
    cert = cert_status()["state"]
    db_state = "healthy" if analytics.db_size() > 0 else "unavailable"
    return [
        {"name": "BIND", "state": "Healthy" if named == "active" else "Down", "tone": status_tone(named)},
        {"name": "dnsdist", "state": "Healthy" if dnsdist_current == "active" else "Down", "tone": status_tone(dnsdist_current)},
        {"name": "Alderpoint DNS", "state": "Healthy" if alderpointdns_current == "active" else "Down", "tone": status_tone(alderpointdns_current)},
        {"name": "Analytics collector", "state": "Healthy" if collector == "active" else "Down", "tone": status_tone(collector)},
        {"name": "Backend health", "state": "Healthy" if backend == "healthy" else "Degraded", "tone": backend},
        {"name": "DNSSEC", "state": "Unavailable", "tone": "unavailable"},
        {"name": "Certificate", "state": "Healthy" if cert == "present" else cert.title(), "tone": status_tone(cert)},
        {"name": "Database", "state": "Healthy" if db_state == "healthy" else "Unavailable", "tone": db_state},
    ]


def compiler_status() -> dict[str, Any]:
    with db() as conn:
        sources = conn.execute("SELECT * FROM sources ORDER BY id").fetchall()
        rules = conn.execute("SELECT * FROM custom_filter_rules ORDER BY id DESC").fetchall()
        deployment = conn.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
    return {"sources": sources, "rules": rules, "deployment": deployment}


class _DeployCoordinator:
    """Ensures at most one caller in this process is ever actually spawning
    a given runtime-mutating alderpointdns_compiler.py subcommand at a time,
    and coalesces bursts of callers that arrive while one is already
    in flight into a single trailing re-run instead of one queued run per
    caller.

    Root cause this exists for (v1.0.1 RC acceptance): every DNS Settings
    control -- upstream add/edit/toggle/move/delete among them -- invoked
    `subprocess.run(["sudo", ".../alderpointdns_compiler.py", "deploy", ...])`
    directly and synchronously from its own request-handling thread.
    FastAPI/Starlette runs sync route handlers in a threadpool, so an
    administrator clicking several checkboxes before the first click's
    request had even returned span up that many *concurrent* subprocesses.
    alderpointdns_compiler.deploy_lock() (an flock()) already guarantees
    those subprocesses never actually mutate runtime config at the same
    time -- which is why the incident never corrupted anything -- but each
    extra one still queues up and re-runs the *entire* pipeline it was
    given, back to back, for as long as clicks kept arriving: exactly the
    "extremely slow" UI and pile of "database is locked" / HTTP 400 /
    repeated dnsdist restarts the incident reported.

    A coordinator instance owns exactly one underlying operation (e.g. the
    full deploy, or the scoped upstream-only deploy). The first caller to
    arrive actually runs it; every caller that arrives while that run is
    still in flight does not spawn a second subprocess at all -- it marks
    the run as needing one more pass and waits (bounded) for that pass,
    which then reflects everyone's latest saved state in a single pipeline
    execution rather than one per click. Different coordinators (e.g. the
    full-deploy one and the upstream-only one) can each have a run in
    flight at once from this process's point of view; alderpointdns_compiler's
    own deploy_lock() is still the cross-process, cross-pipeline-kind
    backstop that serializes those against each other and against any
    other invocation (cron timers, a manual sudo'd CLI call, package
    upgrade) -- this class only removes the *redundant, pile-up* case, it
    does not replace that lock.
    """

    def __init__(self, run_once, wait_timeout: float = 180.0, busy_message: str = "a deployment is already in progress; your change was saved and will be applied automatically once it finishes", min_interval_seconds: float = 0.0, should_pace=None):
        self._run_once = run_once
        self._wait_timeout = wait_timeout
        self._busy_message = busy_message
        # See the "restart-rate limiting" note below `run()` for why this
        # exists and how it interacts with coalescing.
        self._min_interval_seconds = min_interval_seconds
        # should_pace(result: tuple[int, str]) -> bool: decides whether a
        # completed run counts toward the min_interval_seconds cooldown at
        # all. Defaults to "every run counts" (unconditional pacing), which
        # is correct for a coordinator whose underlying operation always
        # does the one rate-limited thing it exists to pace. It is NOT
        # correct once an operation can satisfy the same request two
        # different ways with very different costs -- see
        # _upstream_deploy_coordinator, where most runs apply live over
        # dnsdist's console (no restart, nothing to pace) and only a rare
        # fallback actually restarts dnsdist (the thing that must be
        # paced). Pacing every run unconditionally there would throttle
        # ordinary sequential clicks to one every min_interval_seconds
        # even when no restart ever happened -- an earlier version of this
        # fix did exactly that and turned 8 ordinary sequential toggles
        # into a 123-second wait for nothing.
        self._should_pace = should_pace or (lambda result: True)
        self._cv = threading.Condition()
        self._in_flight = False
        self._coalesced = False
        self._round = 0
        self._result: tuple[int, str] | None = None
        self._error: BaseException | None = None
        self._last_finished: float | None = None

    def run(self) -> tuple[int, str]:
        with self._cv:
            if self._in_flight:
                self._coalesced = True
                target_round = self._round + 1
                deadline = time.monotonic() + self._wait_timeout
                while self._round < target_round:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError(self._busy_message)
                    self._cv.wait(remaining)
                if self._error is not None:
                    raise self._error
                return self._result
            self._in_flight = True

        while True:
            # Restart-rate limiting (v1.0.1 RC #3 continuation): a burst of
            # ordinary, *sequential* UI clicks -- each one returning before
            # the next arrives, so nothing above is ever "in flight" to
            # coalesce against -- previously still triggered one full
            # `systemctl restart dnsdist` per click. Live dns1 acceptance
            # showed five clicks in under ten seconds is enough to trip
            # systemd's StartLimitBurst on dnsdist.service (a real, intended
            # crash-loop protection this code must never weaken or bypass --
            # see docs/testing.md). Instead, when `min_interval_seconds` is
            # set, every actual `run_once()` call (the first one included)
            # is spaced at least that far apart from the previous one's
            # completion; a caller arriving before that spacing has elapsed
            # is *already* holding `_in_flight`, so any further caller in
            # the meantime coalesces the normal way above -- this sleep
            # doesn't add a new queue, it just gives coalescing a wider
            # window to catch a fast sequential burst in, converging it to
            # one restart every `min_interval_seconds` instead of one per
            # click. It never delays a truly isolated click by more than
            # `min_interval_seconds`, and never delays the very first click
            # after an idle period at all. Critically, `_last_finished` is
            # only set below when `_should_pace(result)` says this
            # particular run actually did the rate-limited thing -- a run
            # that didn't (e.g. applied live over dnsdist's console, no
            # restart at all) leaves it untouched, so it never starts a
            # cooldown the next call would have to wait out.
            if self._min_interval_seconds and self._last_finished is not None:
                remaining_cooldown = self._min_interval_seconds - (time.monotonic() - self._last_finished)
                if remaining_cooldown > 0:
                    time.sleep(remaining_cooldown)
            result: tuple[int, str] | None = None
            error: BaseException | None = None
            try:
                result = self._run_once()
            except BaseException as exc:  # pragma: no cover - run() -> subprocess.run doesn't normally raise
                error = exc
            with self._cv:
                self._round += 1
                self._result = result
                self._error = error
                # Conservative on error: if run_once() raised, we can't
                # know whether a restart happened before the failure, so
                # this round still counts toward the cooldown.
                if error is not None or self._should_pace(result):
                    self._last_finished = time.monotonic()
                run_again = self._coalesced
                self._coalesced = False
                if not run_again:
                    self._in_flight = False
                self._cv.notify_all()
            if not run_again:
                if error is not None:
                    raise error
                return result


def deploy_no_download() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "deploy", "--no-download"])


def protection_enable_reuse() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "protection-enable-reuse"])


_deploy_coordinator = _DeployCoordinator(lambda: deploy_no_download())


def deploy_no_download_or_raise() -> None:
    code, out = _deploy_coordinator.run()
    if code != 0:
        raise RuntimeError(out.strip() or "deployment failed")


def upstream_deploy() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "upstream-deploy"])


# min_interval_seconds=16.0: this is now only a defense-in-depth backstop,
# not the primary fix -- app.upstream_dns.deploy_upstreams() applies
# ordinary upstream changes to the already-running dnsdist over its
# console (see _console_reconcile()'s docstring), so a normal add/edit/
# toggle/move/delete never restarts dnsdist at all and this spacing is
# almost never actually waited on. It only matters for the rare case where
# every deploy in a burst falls back to a real restart (console
# unreachable, or the very first upstream deploy ever on a fresh install,
# which still needs one restart to wire up routing). dns1's *actual*
# installed dnsdist.service policy is StartLimitBurst=5 within a 60s
# window (not systemd's 10s default) -- 5 restarts spaced 16s apart span
# 64s, so 16s spacing guarantees an all-restart fallback burst can never
# fit 5 restarts inside any rolling 60s window, with real margin either
# side of the boundary. An isolated click (the overwhelmingly common case,
# and the only one that matters for UX) is never delayed by this at all
# since it always takes the console path.
def _upstream_deploy_used_a_restart(result: tuple[int, str]) -> bool:
    """True unless this deploy's own subprocess output says, in so many
    words, that it applied live without restarting dnsdist (see
    _run_upstream_deploy_for_cli() in alderpointdns_compiler.py and
    upstream_dns.deploy_upstreams()'s _console_reconcile() docstring).
    Conservative by construction: a failed run, an unparseable/unexpected
    output, or an explicit restart all count as "yes, pace this" -- only a
    confirmed non-restart success skips pacing."""
    code, out = result
    return not (code == 0 and "no dnsdist restart" in out)


_upstream_deploy_coordinator = _DeployCoordinator(lambda: upstream_deploy(), min_interval_seconds=16.0, should_pace=_upstream_deploy_used_a_restart)


def upstream_deploy_or_raise() -> None:
    """Deploys only the managed-upstream-resolver stage
    (upstream_dns.deploy_upstreams): render/stage/promote the dnsdist and
    BIND upstream-forwarder config, validate it, restart dnsdist, reload
    BIND, and run its own post-deploy functional DNS check (dig through
    BIND, which forwards through the freshly-deployed upstream chain) --
    without redownloading/recompiling the blocklist RPZ, redeploying local
    DNS zones, BIND cache tuning, or the custom-rules dnsdist layer. None of
    those subsystems' own health checks or generated files depend on which
    upstream resolvers are enabled (only the reverse was ever true -- see
    the deploy-ordering fix's comment in alderpointdns_compiler.deploy()),
    and upstream_dns.deploy_upstreams() already owns its own last-good
    rollback and upstream_deployments history end to end. Routing ordinary
    upstream add/edit/toggle/move/delete through the entire
    alderpointdns_compiler.py deploy pipeline was needless cost inherited
    from the generic settings-save convention, not a real dependency --
    identified investigating the v1.0.1 RC concurrency incident, where it
    meant a single checkbox click could take 20-90 seconds and legitimately
    overlap with someone else's unrelated blocklist/local-DNS/cache change.

    Also rate-limited (see _upstream_deploy_coordinator's
    min_interval_seconds): a burst of ordinary sequential clicks converges
    to the fewest dnsdist restarts needed to reach the final desired state,
    instead of one restart per click -- found necessary when a real burst
    of upstream toggles on dns1 restarted dnsdist often enough, quickly
    enough, to trip systemd's own StartLimitBurst crash-loop protection."""
    code, out = _upstream_deploy_coordinator.run()
    if code != 0:
        raise RuntimeError(out.strip() or "upstream deployment failed")


def cache_flush_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "cache-flush"])


_cache_flush_coordinator = _DeployCoordinator(lambda: cache_flush_apply(), busy_message="a cache flush is already in progress; please try again shortly")


def cache_flush_apply_or_raise() -> None:
    code, out = _cache_flush_coordinator.run()
    if code != 0:
        raise RuntimeError(out.strip() or "cache flush failed")


def cache_options_deploy() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "cache-deploy"])


_cache_options_coordinator = _DeployCoordinator(lambda: cache_options_deploy(), busy_message="a cache deployment is already in progress; your change was saved and will be applied automatically once it finishes")


def cache_options_deploy_or_raise() -> None:
    """Deploys only the BIND cache-tuning options (dns_cache.deploy_cache_options),
    not the full blocklist/RPZ/dnsdist filtering pipeline. Cache tuning has no
    dependency on blocklist content, so a cache-only settings change should
    never redownload, recompile, and re-validate the entire filtering policy --
    doing so wasted time and made a transient live-domain hiccup in the
    filtering postcheck falsely block an unrelated cache setting change."""
    code, out = _cache_options_coordinator.run()
    if code != 0:
        raise RuntimeError(out.strip() or "cache deployment failed")


def encryption_deploy_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "encryption-deploy"])


def access_policy_deploy_apply() -> tuple[int, str]:
    """The web process runs unprivileged (user `alderpointdns`) and cannot
    write /var/lib/alderpointdns/compiled/dnsdist/*, write
    /etc/dnsdist/dnsdist.conf, or `systemctl restart dnsdist` itself -- all
    of which app.clients.deploy_access_layer() needs to do. Like every
    other privileged deploy path in this app, it runs as root through the
    narrow sudoers allowlist (packaging/sudoers-alderpointdns) instead."""
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "access-policy-deploy"])


def dnsdist_stats() -> dict[str, Any]:
    try:
        creds = Path("/etc/alderpointdns/dnsdist-web.creds").read_text().strip()
        api_key = Path("/etc/alderpointdns/dnsdist-api.key").read_text().strip()
        request = urllib.request.Request("http://127.0.0.1:8083/jsonstat?command=stats")
        request.add_header("Authorization", "Basic " + base64.b64encode(creds.encode()).decode())
        request.add_header("x-api-key", api_key)
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.loads(response.read().decode())
    except Exception:
        return {}


def dnsdist_version_info() -> dict[str, Any]:
    code, out = run(["dnsdist", "--version"])
    lines = out.splitlines()
    features = ""
    for line in lines:
        if line.startswith("Enabled features:"):
            features = line.split(":", 1)[1].strip()
    return {
        "ok": code == 0,
        "version": lines[0] if lines else "unknown",
        "features": features,
        "feature_set": set(features.split()),
    }


def _ss_listener_dump() -> tuple[int, str]:
    """Runs `ss -H -ltnup` and returns its full, untruncated output.

    Deliberately does not go through the shared run() helper: run() keeps
    only the last 4000 characters of output, which is fine for short status
    commands but silently drops early lines -- including the plain UDP 53
    listener, which `ss` tends to print near the top -- once the socket
    table is long enough (observed in practice on a host with a normal
    number of other listening services). A dropped line here means a real
    listener is invisible to every check below it, not just truncated
    display text. A dedicated function (rather than inlining this in
    listener_addresses()) keeps that one difference from run() isolated and
    lets tests substitute canned `ss` output without needing a real socket
    table on the test host.
    """
    try:
        proc = subprocess.run(["ss", "-H", "-ltnup"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except (OSError, FileNotFoundError):
        return 1, ""
    return proc.returncode, proc.stdout


def listener_addresses() -> set[tuple[str, str]]:
    """Return the set of (transport, local-address:port) pairs dnsdist (and
    everything else) is actually listening on, e.g. ("tcp", "0.0.0.0:443") or
    ("udp", "[::]:853").

    `ss -H -ltnup` reports both TCP and UDP listeners in its Netid column
    (tcp/tcp6/udp/udp6); a caller that only keeps the local address (as this
    function previously did) can't tell a TCP listener on 443 from a UDP one
    on the same port, which caused DoH's TCP socket to be reported as
    satisfying the DoH3 UDP check, and DoT's TCP socket to satisfy DoQ.
    """
    code, out = _ss_listener_dump()
    if code != 0:
        return set()
    listeners: set[tuple[str, str]] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            netid = parts[0].lower()
            if netid.startswith("tcp"):
                transport = "tcp"
            elif netid.startswith("udp"):
                transport = "udp"
            else:
                continue
            listeners.add((transport, parts[4]))
    return listeners


def _expected_sockets(transport: str, port: str, cfg: dict[str, str]) -> list[tuple[str, str]]:
    expected: list[tuple[str, str]] = []
    listen_ipv4 = cfg.get("listen_ipv4", "0.0.0.0")
    listen_ipv6 = cfg.get("listen_ipv6", "::")
    if listen_ipv4:
        expected.append((transport, f"{listen_ipv4}:{port}"))
    if listen_ipv6:
        expected.append((transport, f"[{listen_ipv6}]:{port}"))
    return expected


def _socket_coverage(listeners: set[tuple[str, str]], expected: list[tuple[str, str]]) -> str:
    """"full" if every expected (transport, address) socket is listening,
    "none" if none are, "partial" otherwise (e.g. IPv4 up, IPv6 down)."""
    if not expected:
        return "none"
    present = [e for e in expected if e in listeners]
    if len(present) == len(expected):
        return "full"
    if not present:
        return "none"
    return "partial"


def _last_protocol_test_results() -> dict[str, str]:
    deployment = encryption.last_deployment()
    if not deployment:
        return {}
    raw = deployment.get("protocol_tests") or ""
    try:
        import ast

        parsed = ast.literal_eval(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, SyntaxError):
        return {}


def file_contains(path: Path, needle: str) -> bool:
    try:
        return needle in path.read_text()
    except Exception:
        return False


def cert_status() -> dict[str, str]:
    cert = Path("/etc/alderpointdns/certs/alderpointdns-lab.crt")
    key = Path("/etc/alderpointdns/certs/alderpointdns-lab.key")
    if not cert.exists() or not key.exists():
        return {"state": "missing", "detail": "certificate and key must both be present"}
    code, out = run(["openssl", "x509", "-noout", "-subject", "-dates", "-in", str(cert)])
    if code != 0:
        return {"state": "invalid", "detail": out.strip() or "certificate could not be parsed"}
    return {
        "state": "present",
        "detail": "certificate parses successfully; private key match is verified by the acceptance suite",
    }


def dns_allow_all_enabled() -> bool:
    if os.getenv("ALDERPOINTDNS_DNS_ALLOW_ALL") == "1":
        return True
    for path in (
        Path("/etc/systemd/system/dnsdist.service.d/alderpointdns.conf"),
        Path("/etc/systemd/system/dnsdist.service.d/override.conf"),
    ):
        try:
            if "ALDERPOINTDNS_DNS_ALLOW_ALL=1" in path.read_text():
                return True
        except Exception:
            continue
    return False


def proxy_backend_enabled() -> bool:
    for config in (Path("/etc/dnsdist/dnsdist.conf"), ROOT / "packaging" / "dnsdist.conf"):
        if file_contains(config, 'address="127.0.0.1:5354"') and file_contains(config, "useProxyProtocol=true"):
            return True
    return False


# The PROXYv2 backend hop that lets BIND log/see the real client address
# instead of dnsdist's own loopback address: dnsdist.conf forwards to this
# socket with useProxyProtocol=true (proxy_backend_enabled(), above), and
# packaging/named.conf.options has BIND listen on it with
# `listen-on port 5354 proxy plain`.
PROXY_BACKEND_SOCKET = "127.0.0.1:5354"


def client_address_preservation_status() -> dict[str, str]:
    """Configuration/listener status for the dnsdist -> BIND PROXYv2 backend
    hop that lets BIND log/see the real client address.

    This deliberately does NOT claim to prove that a real client address has
    actually traversed dnsdist -> PROXYv2 -> BIND -- doing that from a
    production web request would mean firing a live self-test DNS query
    (with a spoofed source address) on every page load, which this
    intentionally does not do. It reports only what it can truthfully prove
    from two production-owned signals protocol_statuses() already relies on
    for every other listener:

    - proxy_backend_enabled() proves dnsdist.conf is *configured* to forward
      through the PROXYv2 backend.
    - a live socket check (listener_addresses(), the same ss-backed helper
      used elsewhere in this module) proves BIND's PROXYv2 listener is
      *actually up* right now, not just present in a config file on disk.

    The full behavioral proof -- that a real client address actually
    survives the hop -- is exercised by the separate shell acceptance suite
    (tests/test_dnsdist_frontend.sh, still run in CI/pre-release testing,
    unaffected by this function). This used to be inferred here too, from
    the presence-on-disk of that same script -- a development/test artifact
    the production package should not need to ship or depend on, and one
    that was never actually *run* by this check to begin with (only checked
    for existing) -- which is what motivated replacing it with the honest,
    dependency-free configuration/listener signal below.
    """
    detail = f"PROXYv2 forwarding configured; BIND backend listener {PROXY_BACKEND_SOCKET} (tcp+udp)"
    if not proxy_backend_enabled():
        return {"state": "Not configured", "detail": "PROXYv2 forwarding is not configured in dnsdist.conf"}
    listeners = listener_addresses()
    expected = [("tcp", PROXY_BACKEND_SOCKET), ("udp", PROXY_BACKEND_SOCKET)]
    if _socket_coverage(listeners, expected) == "full":
        return {"state": "Configured", "detail": f"{detail} is up"}
    return {
        "state": "Listener unavailable",
        "detail": f"PROXYv2 forwarding is configured, but the BIND backend listener {PROXY_BACKEND_SOCKET} (tcp+udp) is not fully up",
    }


# (name, capability key in encryption.dnsdist_capabilities(), enabled-flag
# key in encryption.settings(), port-setting key, transport, endpoint label,
# protocol_tests key from encryption.test_protocols())
PROTOCOL_SPECS: tuple[tuple[str, str | None, str | None, str | None, str, str, str], ...] = (
    ("Plain DNS", None, None, None, "both", "53/udp, 53/tcp", "plain"),
    ("DoH", "doh", "doh_enabled", "doh_port", "tcp", "443/tcp", "doh"),
    ("DoT", "dot", "dot_enabled", "dot_port", "tcp", "853/tcp", "dot"),
    ("DoQ", "doq", "doq_enabled", "doq_port", "udp", "853/udp", "doq"),
    ("DoH3", "doh3", "doh3_enabled", "doh3_port", "udp", "443/udp", "doh3"),
)

# Internal runtime state -> user-facing label and status-badge tone. Never
# render the internal state key itself to a user.
RUNTIME_STATUS_LABELS: dict[str, tuple[str, str]] = {
    "unsupported": ("Unavailable", "unavailable"),
    "disabled": ("Disabled", "neutral"),
    "configured": ("Configured but not listening", "degraded"),
    "listening": ("Listening", "healthy"),
    "degraded": ("Degraded", "down"),
}


def protocol_statuses() -> list[dict[str, str]]:
    """Authoritative encrypted-DNS protocol status for the UI.

    "Available"/"enabled" is decided from Alderpoint's own configured state
    (encryption.settings(), the database Encryption Settings writes and
    deploy_encryption() reads -- never from grepping the generated dnsdist.conf
    for a variable name, which only proves the name exists in a template, not
    that dnsdist actually enabled anything). "Listening" is decided from a
    transport-and-port-specific socket check (listener_addresses()) so a TCP
    listener on a shared port (DoH/443, DoT/853) can never satisfy a UDP
    protocol's (DoH3/443, DoQ/853) listening check or vice versa.
    """
    version = dnsdist_version_info()
    caps = encryption.dnsdist_capabilities()
    cfg = encryption.settings()
    listeners = listener_addresses()
    last_tests = _last_protocol_test_results()
    protocols = []
    for name, cap_key, enabled_key, port_key, transport, endpoint, test_key in PROTOCOL_SPECS:
        available = True if cap_key is None else bool(caps.get(cap_key))
        enabled = True if enabled_key is None else cfg.get(enabled_key) == "1"
        if transport == "both":
            expected = _expected_sockets("udp", "53", cfg) + _expected_sockets("tcp", "53", cfg)
        else:
            port = cfg.get(port_key, "") if port_key else ""
            expected = _expected_sockets(transport, port, cfg)
        coverage = _socket_coverage(listeners, expected)
        if not available:
            state = "unsupported"
        elif not enabled:
            state = "degraded" if coverage != "none" else "disabled"
        elif coverage == "full":
            state = "listening"
        elif coverage == "none":
            state = "configured"
        else:
            state = "degraded"
        runtime_label, tone = RUNTIME_STATUS_LABELS[state]
        if not available:
            verification = "Capability detection tested"
        elif not enabled or state != "listening":
            verification = "Not run"
        else:
            result = last_tests.get(test_key)
            if result == "ok":
                # DoH/DoT/Plain DNS are additionally exercised end-to-end by
                # the shell acceptance suite (tests/test_dnsdist_frontend.sh)
                # on every run; DoQ/DoH3 only get a live query when a
                # capable test client is installed (encryption.test_protocols),
                # so their "ok" is reported distinctly as a real network
                # verification rather than folded into the same generic label.
                verification = "Automated checks included" if name in ("Plain DNS", "DoH", "DoT") else "Live query verified"
            else:
                verification = "Configuration validated"
        protocols.append(
            {
                "name": name,
                "endpoint": endpoint,
                "port": endpoint,
                "build_support": "Available" if available else "Not supported by installed dnsdist",
                "runtime_status": runtime_label,
                "verification": verification,
                "state": state,
                "tone": tone,
                "available": available,
                "enabled": enabled,
            }
        )
    return protocols


def render(request: Request, template: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    # setdefault, not a one-time module-load registration: some tests
    # replace webapp.TEMPLATES with a fresh Jinja2Templates instance
    # (e.g. to point at an isolated directory), which would otherwise
    # start without the local_time filter registered.
    TEMPLATES.env.filters.setdefault("local_time", format_local_datetime)
    TEMPLATES.env.filters.setdefault("dns_safe_label", clients_model.clientid_dns_label)
    TEMPLATES.env.globals.setdefault("static_url", static_url)
    session = signed_session(request)
    new_anonymous_session = not session
    if new_anonymous_session:
        # No valid session cookie yet (first visit, or an authenticated
        # session that expired/was revoked): mint an anonymous session now so
        # the CSRF token embedded in this page's forms (setup, login) is
        # bound to something persisted server-side and will actually
        # validate on submit, rather than a value that was only ever shown
        # to the browser.
        session = _create_session_row(request, None)
    context.update(
        {
            "request": request,
            "admin": session.get("admin"),
            "csrf": session.get("csrf"),
            "setup_required": admin_count() == 0,
            "global_status": global_service_status() if session.get("admin") else {"label": "Unknown", "tone": "unavailable", "detail": "not authenticated"},
        }
    )
    response = TEMPLATES.TemplateResponse(template, context, status_code=status_code)
    if new_anonymous_session:
        _set_session_cookie(response, session["id"])
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    accepts = request.headers.get("accept", "")
    if "text/html" not in accepts:
        # jsonable_encoder, not exc.errors() verbatim: pydantic v2 embeds
        # the raw underlying exception object in some error dicts' `ctx`
        # (e.g. a bare ValueError a malformed multipart part's parser
        # raised), which plain json.dumps cannot serialize -- turning a
        # normal 422 into a 500 from inside this handler itself. This is
        # exactly the wrapping FastAPI's own default validation exception
        # handler applies; this override skipped it.
        return JSONResponse({"detail": jsonable_encoder(exc.errors())}, status_code=422)
    if request.url.path.startswith("/import"):
        return import_error(
            request,
            "That import or migration link is not valid. Return to Import and Migration and choose a current job or workflow.",
            status_code=404,
        )
    return render(request, "import_migration.html", error="The requested page is not valid.", jobs=[], job=None, preview=None, adguard=None, migration_summary=None, status_code=404)


@app.exception_handler(DatabaseBusyError)
async def database_busy_exception_handler(request: Request, exc: DatabaseBusyError):
    """A write exhausted its bounded busy-retry budget. Return a controlled,
    specific response rather than letting the exception propagate into a
    generic 500 with a raw traceback."""
    _log(3, f"database busy handling {request.method} {request.url.path}: {exc}")
    accepts = request.headers.get("accept", "")
    if "text/html" not in accepts:
        return JSONResponse({"detail": "The database is temporarily busy. Please try again in a moment."}, status_code=503)
    return PlainTextResponse("The database is temporarily busy. Please try again in a moment.", status_code=503)


@app.exception_handler(sqlite3.OperationalError)
async def sqlite_operational_error_handler(request: Request, exc: sqlite3.OperationalError):
    """Catches any sqlite3.OperationalError that reaches a route handler
    without having gone through retry_on_locked() -- never render the raw
    exception/traceback to the browser. A locked/busy database gets the same
    controlled 503 as DatabaseBusyError; anything else still gets a plain,
    traceback-free error rather than Starlette's default page."""
    if is_lock_error(exc):
        return await database_busy_exception_handler(request, DatabaseBusyError(str(exc)))
    _log(3, f"unhandled sqlite error handling {request.method} {request.url.path}: {exc}")
    accepts = request.headers.get("accept", "")
    if "text/html" not in accepts:
        return JSONResponse({"detail": "An internal error occurred."}, status_code=500)
    return PlainTextResponse("An internal error occurred.", status_code=500)


@app.get("/status/summary")
def status_summary(_: sqlite3.Row = Depends(current_admin)):
    return JSONResponse(global_service_status())


@app.get("/healthz")
def healthz() -> JSONResponse:
    # Deliberately unauthenticated (a liveness probe must work before any
    # session exists) and deliberately minimal: no admin/session/analytics
    # data, nothing an unauthenticated caller couldn't already infer from
    # `systemctl is-active alderpointdns`. Used by
    # app/software_updates.py's post-upgrade health check to confirm the
    # web process itself is actually accepting local connections again
    # after a restart, not just that systemd reports the unit active.
    return JSONResponse({"status": "ok", "version": backup.alderpointdns_app_version()})


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, _: sqlite3.Row = Depends(current_admin)):
    status = compiler_status()
    enabled_sources = [s for s in status["sources"] if s["enabled"]]
    deployment = status["deployment"]
    active_rules = deployment["active_domains"] if deployment else 0
    range_key = request.query_params.get("range", "24h")
    data = analytics.dashboard_data(range_key)
    bind_state = service_state("named")
    dnsdist_state = service_state("dnsdist")
    alderpointdns_state = service_state("alderpointdns")
    collector_state = analytics_collector_state()
    protection = protection_state(active_rules, bind_state, dnsdist_state, collector_state)
    chart_points = [
        {
            "t": row["bucket_start"],
            "total": row["total_queries"],
            "blocked": row["blocked_queries"],
            "allowed": row["allowed_queries"],
            "errors": row["nxdomain"] + row["servfail"] + row["refused"],
            "rate_limited": row["dropped_requests"] + row["rate_limited_requests"],
        }
        for row in data["buckets"]
    ]
    return render(
        request,
        "dashboard.html",
        alderpointdns=alderpointdns_state,
        bind=bind_state,
        dnsdist=dnsdist_state,
        collector=collector_state,
        enabled_sources=len(enabled_sources),
        active_rules=active_rules,
        deployment=deployment,
        sources=status["sources"],
        analytics=data,
        chart_json=json.dumps(chart_points),
        category_breakdown=analytics_category_breakdown(range_key),
        protection=protection,
        system_health=system_health(bind_state, dnsdist_state, alderpointdns_state),
        cache_stats=dns_cache.cache_stats(),
        last_refresh=utc_now(),
    )


@app.get("/clients", response_class=HTMLResponse)
def clients(request: Request, _: sqlite3.Row = Depends(current_admin)):
    range_key = request.query_params.get("range", "24h")
    return render(request, "clients.html", clients=analytics.clients_data(range_key))


@app.get("/analytics/chart-data")
def analytics_chart_data(request: Request, _: sqlite3.Row = Depends(current_admin)):
    data = analytics.dashboard_data(request.query_params.get("range", "24h"))
    return JSONResponse(
        {
            "range": data["range"],
            "series": [
                {
                    "t": row["bucket_start"],
                    "total": row["total_queries"],
                    "blocked": row["blocked_queries"],
                    "allowed": row["allowed_queries"],
                    "errors": row["nxdomain"] + row["servfail"] + row["refused"],
                    "rate_limited": row["dropped_requests"] + row["rate_limited_requests"],
                }
                for row in data["buckets"]
            ],
        }
    )


@app.post("/protection/toggle")
def protection_toggle(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    status = compiler_status()
    deployment = status["deployment"]
    active_rules = deployment["active_domains"] if deployment else 0
    enable = active_rules <= 0
    with db() as conn:
        conn.execute("UPDATE sources SET enabled=?", (1 if enable else 0,))
        conn.execute("UPDATE custom_rules SET enabled=?", (1 if enable else 0,))
        if enable:
            conn.execute("UPDATE custom_filter_rules SET enabled=1 WHERE validation_state='valid'")
        else:
            conn.execute("UPDATE custom_filter_rules SET enabled=0")
    if enable:
        code, _out = protection_enable_reuse()
        if code == 0:
            return redirect("/")
    deploy_no_download()
    return redirect("/")


@app.get("/setup", response_class=HTMLResponse)
def setup_get(request: Request):
    if admin_count() > 0:
        return redirect("/login")
    local_dns.init_db()
    return render(request, "setup.html", error=None, username="admin", local_dns=local_dns.settings())


@app.post("/setup")
def setup_post(
    request: Request,
    csrf: str = Form(...),
    username: str = Form("admin"),
    password: str = Form(...),
    confirm_password: str = Form(...),
    create_local_dns: str = Form("0"),
    server_hostname: str = Form("alderpointdns"),
    server_ip: str = Form(""),
):
    if admin_count() > 0:
        return redirect("/login")
    check_csrf(request, csrf)
    clean_username = username.strip() or "admin"
    error = auth.validate_password_length(password)
    if not error and password != confirm_password:
        error = "Passwords do not match."
    if error:
        local_dns.init_db()
        return render(request, "setup.html", error=error, username=clean_username, local_dns=local_dns.settings(), status_code=400)
    with db() as conn:
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            (clean_username, auth.hash_password(password), utc_now()),
        )
    if create_local_dns == "1":
        cfg = local_dns.settings()
        ip = server_ip.strip() or cfg.get("server_ip") or local_dns.detect_server_ip()
        host = server_hostname.strip() or "alderpointdns"
        local_dns.update_settings({"server_hostname": host, "server_ip": ip})
        local_dns.add_host(host, cfg.get("internal_domain", "home.arpa"), ip, cfg.get("default_ttl", 300), "Alderpoint DNS server", True, True)
        local_dns.upsert_alias(ip, "Alderpoint DNS", "Alderpoint DNS DNS appliance")
    return redirect("/login")


# Fixed vocabulary, not the raw query string: `reason` only ever selects one
# of these known, pre-written messages -- never echoes arbitrary request
# text back into the page.
LOGIN_NOTICES = {
    "restore": "Restore completed. Authentication/session data changed, so you need to sign in again.",
}


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    if admin_count() == 0:
        return redirect("/setup")
    notice = LOGIN_NOTICES.get(request.query_params.get("reason", ""))
    return render(request, "login.html", error=None, notice=notice)


@app.post("/login")
def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else "unknown"
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=15)).isoformat()
    with db() as conn:
        failures = conn.execute(
            "SELECT count(*) FROM login_attempts WHERE ip=? AND success=0 AND attempted_at>?",
            (ip, cutoff),
        ).fetchone()[0]
        if failures >= 8:
            return render(request, "login.html", error="Too many failed attempts. Try later.")
        row = conn.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        ok = bool(row) and auth.verify_password(row["password_hash"], password)
        conn.execute("INSERT INTO login_attempts(ip, attempted_at, success) VALUES (?, ?, ?)", (ip, utc_now(), 1 if ok else 0))
    if not ok:
        return render(request, "login.html", error="Invalid username or password.")
    response = redirect("/")
    set_session(request, response, row["id"])
    return response


@app.post("/logout")
def logout(request: Request):
    response = redirect("/login")
    clear_session(request, response)
    return response


def filter_schedule_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "filter-schedule-deploy"])


def filter_schedule_apply_or_raise() -> None:
    code, out = filter_schedule_apply()
    if code != 0:
        raise RuntimeError(out.strip() or "filter update schedule deployment failed")


def filter_schedule_context() -> dict[str, Any]:
    cfg = filter_schedule.settings()
    value = filter_schedule.interval_value(cfg)
    enabled = value != filter_schedule.DISABLED
    return {
        "options": filter_schedule.INTERVAL_CHOICES,
        "interval": value,
        "interval_label": filter_schedule.interval_label(value),
        "enabled": enabled,
        "last_attempt": cfg.get("last_attempt") or "",
        "last_success": cfg.get("last_success") or "",
        "last_result": filter_schedule.last_result(cfg),
        # Only queried when scheduling is on; a disabled schedule must not
        # display a next-run time at all.
        "next_run": filter_schedule.next_run_at() if enabled else None,
    }


# Health states that mean "this source is not currently in good shape" --
# used to decide whether a past automatic-update failure is still relevant
# to what's on screen right now, or has been superseded by later successful
# fetches (manual or automatic).
_DEGRADED_HEALTH_STATES = {HEALTH_ERROR, HEALTH_WARNING, HEALTH_UNSUPPORTED_FORMAT, HEALTH_USING_CACHED}


def automatic_update_banner(sources: list[dict[str, Any]], fs: dict[str, Any]) -> dict[str, Any] | None:
    """"Last automatic update" only ever reflects the most recent *timer*
    run (see filter_schedule.record_result(), only called from
    filter_update_run()) -- "Update All Now" and per-source "Update now"
    intentionally do not overwrite it, so this must never be presented as
    if it were live current-source health. Without this, a real failure
    recorded by one automatic run stayed on screen, worded as if still
    happening, for the entire interval until the next scheduled run --
    even after every implicated source had since been refreshed
    successfully (by hand or by a later timer run). History is still
    shown (never erased), just no longer framed as an ongoing problem
    once nothing currently enabled is actually unhealthy."""
    last = fs.get("last_result")
    if not last or not last.get("error"):
        return None
    currently_degraded = any(s["health"]["state"] in _DEGRADED_HEALTH_STATES for s in sources if s.get("enabled"))
    return {
        "status": last.get("status"),
        "finished_at": last.get("finished_at"),
        "error": last.get("error"),
        "resolved": not currently_degraded,
    }


def enrich_sources(sources: list[sqlite3.Row]) -> list[dict[str, Any]]:
    """Attaches the derived health state and a safely-parsed rejected-sample
    list to each source row for template rendering. Templates need the
    computed label/tone (source_health), not just the raw last_error column
    the old "Healthy unless last_error" badge logic relied on."""
    enriched = []
    for row in sources:
        item = dict(row)
        item["health"] = source_health(row)
        try:
            item["rejected_samples_parsed"] = json.loads(item.get("rejected_samples") or "[]")
        except (TypeError, ValueError):
            item["rejected_samples_parsed"] = []
        enriched.append(item)
    return enriched


def blocklists_error(request: Request, message: str) -> HTMLResponse:
    sources = enrich_sources(compiler_status()["sources"])
    fs = filter_schedule_context()
    return render(
        request,
        "blocklists.html",
        sources=sources,
        categories=blocklist_categories.list_categories(),
        category_error=message,
        category_filter="",
        status_filter="",
        search="",
        sort="name",
        filter_schedule=fs,
        automatic_update_banner=automatic_update_banner(sources, fs),
        status_code=400,
    )


def resolve_category_key(requested: str) -> str:
    clean = (requested or "").strip()
    known_keys = {row["key"] for row in blocklist_categories.list_categories()}
    return clean if clean in known_keys else blocklist_categories.UNCATEGORIZED_KEY


@app.get("/blocklists", response_class=HTMLResponse)
def blocklists(request: Request, _: sqlite3.Row = Depends(current_admin)):
    blocklist_categories.migrate_existing_categories()
    all_sources = enrich_sources(compiler_status()["sources"])
    fs = filter_schedule_context()
    banner = automatic_update_banner(all_sources, fs)
    sources = all_sources
    category_filter = request.query_params.get("category", "")
    status_filter = request.query_params.get("status", "")
    search = request.query_params.get("search", "").strip().lower()
    sort = request.query_params.get("sort", "name")
    if category_filter:
        sources = [s for s in sources if s["category"] == category_filter]
    if status_filter == "enabled":
        sources = [s for s in sources if s["enabled"]]
    elif status_filter == "disabled":
        sources = [s for s in sources if not s["enabled"]]
    elif status_filter == "error":
        sources = [s for s in sources if s["last_error"]]
    if search:
        sources = [s for s in sources if search in s["name"].lower() or search in s["url"].lower()]
    sort_keys = {
        "name": lambda s: s["name"].lower(),
        "category": lambda s: s["category"] or "",
        "updated": lambda s: s["last_success"] or "",
        "rules": lambda s: s["unique_active_domains"] or 0,
    }
    sources = sorted(sources, key=sort_keys.get(sort, sort_keys["name"]), reverse=sort == "updated" or sort == "rules")
    return render(
        request,
        "blocklists.html",
        sources=sources,
        categories=blocklist_categories.list_categories(),
        category_error=None,
        category_filter=category_filter,
        status_filter=status_filter,
        search=search,
        sort=sort,
        filter_schedule=fs,
        # Computed against every source (before category/status/search
        # narrow what's *displayed* below), so a filter can never hide the
        # one source that would have proven a historical automatic-update
        # failure resolved -- or, symmetrically, hide the one still-failing
        # source that keeps it genuinely current.
        automatic_update_banner=banner,
    )


@app.post("/blocklists/add")
def blocklist_add(request: Request, name: str = Form(...), url: str = Form(...), category: str = Form(""), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    clean_category = resolve_category_key(category)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO sources(name, url, enabled, category)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(name) DO UPDATE SET url=excluded.url, category=excluded.category
            """,
            (name.strip(), url.strip(), clean_category),
        )
    return redirect("/blocklists")


@app.post("/blocklists/categories/add")
def blocklist_category_add(request: Request, name: str = Form(...), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        blocklist_categories.create_category(name)
    except blocklist_categories.CategoryError as exc:
        return blocklists_error(request, str(exc))
    return redirect("/blocklists")


@app.post("/blocklists/categories/{key}/rename")
def blocklist_category_rename(request: Request, key: str, name: str = Form(...), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        blocklist_categories.rename_category(key, name)
    except blocklist_categories.CategoryError as exc:
        return blocklists_error(request, str(exc))
    return redirect("/blocklists")


@app.post("/blocklists/categories/{key}/merge")
def blocklist_category_merge(request: Request, key: str, target: str = Form(...), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        blocklist_categories.merge_category(key, target)
    except blocklist_categories.CategoryError as exc:
        return blocklists_error(request, str(exc))
    return redirect("/blocklists")


@app.post("/blocklists/categories/{key}/delete")
def blocklist_category_delete(request: Request, key: str, reassign_to: str = Form(""), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        blocklist_categories.delete_category(key, reassign_to.strip() or None)
    except blocklist_categories.CategoryError as exc:
        return blocklists_error(request, str(exc))
    return redirect("/blocklists")


@app.post("/blocklists/{source_id}/toggle")
def blocklist_toggle(request: Request, source_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    with db() as conn:
        conn.execute("UPDATE sources SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (source_id,))
    return redirect("/blocklists")


@app.post("/blocklists/{source_id}/edit")
def blocklist_edit(
    request: Request,
    source_id: int,
    name: str = Form(...),
    url: str = Form(...),
    category: str = Form(""),
    csrf: str = Form(...),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    clean_name = name.strip()
    clean_url = url.strip()
    clean_category = resolve_category_key(category)
    if not clean_name or not clean_url:
        raise HTTPException(status_code=400, detail="source name and url are required")
    try:
        with db() as conn:
            conn.execute(
                "UPDATE sources SET name=?, url=?, category=? WHERE id=?",
                (clean_name, clean_url, clean_category, source_id),
            )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=400, detail="source name already exists") from exc
    return redirect("/blocklists")


@app.post("/blocklists/{source_id}/update")
def blocklist_update_one(request: Request, source_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    run(["/opt/alderpointdns/app/alderpointdns_compiler.py", "update-source", str(source_id)])
    return redirect("/blocklists")


@app.post("/blocklists/{source_id}/delete")
def blocklist_delete(request: Request, source_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    with db() as conn:
        conn.execute("DELETE FROM sources WHERE id=?", (source_id,))
    return redirect("/blocklists")


@app.post("/blocklists/update")
def blocklist_update(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "update-sources"])
    return redirect("/blocklists")


@app.post("/blocklists/schedule")
def blocklist_schedule(request: Request, csrf: str = Form(...), interval: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    """Saves the global Filter Update Interval and redeploys the systemd
    timer immediately. Manual per-source updates and Update All Now stay
    available regardless of this setting."""
    check_csrf(request, csrf)
    try:
        filter_schedule.update_settings({"interval_hours": interval})
        filter_schedule_apply_or_raise()
    except Exception as exc:
        return blocklists_error(request, str(exc))
    return redirect("/blocklists")


@app.post("/deploy")
def deploy(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "deploy"])
    return redirect("/")


def custom_rules_context(request: Request, **extra: Any) -> dict[str, Any]:
    search = request.query_params.get("search", "").strip()
    type_filter = request.query_params.get("type", "")
    status_filter = request.query_params.get("status", "")
    context: dict[str, Any] = {
        "rules": custom_rules_model.list_rules(search=search, rule_type=type_filter, status=status_filter),
        "counts": custom_rules_model.rule_counts(),
        "search": search,
        "type_filter": type_filter,
        "status_filter": status_filter,
        "error": None,
        "notice": None,
        "bulk_results": None,
        "test_result": None,
        "test_domain": "",
    }
    context.update(extra)
    return context


def custom_rules_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    return render(request, "custom_rules.html", **custom_rules_context(request, error=message), status_code=status_code)


@app.get("/custom-rules", response_class=HTMLResponse)
def custom_rules(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "custom_rules.html", **custom_rules_context(request))


@app.post("/custom-rules/add")
def custom_add(request: Request, rule_text: str = Form(...), comment: str = Form(""), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        results = custom_rules_model.add_rule(rule_text, source_system="manual", comment=comment)
        if not results:
            return custom_rules_error(request, "Enter a rule to add.")
        stored_inactive = [r for r in results if r["validation_state"] != "valid"]
        active_added = [r for r in results if r["status"] == "added" and r["validation_state"] == "valid" and r["rule_type"] != "comment"]
        if active_added:
            deploy_no_download_or_raise()
        if stored_inactive:
            reasons = "; ".join(f"{r['rule_text']}: {r['reason']}" for r in stored_inactive)
            return render(
                request,
                "custom_rules.html",
                **custom_rules_context(request, notice=f"Rule saved but kept inactive ({stored_inactive[0]['validation_state']}): {reasons}"),
            )
        if all(r["status"] == "duplicate" for r in results):
            return custom_rules_error(request, "An identical rule already exists.")
    except Exception as exc:
        return custom_rules_error(request, str(exc))
    return redirect("/custom-rules")


@app.post("/custom-rules/bulk")
def custom_bulk_add(request: Request, rules_text: str = Form(...), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        summary = custom_rules_model.add_rules_bulk(rules_text, source_system="manual")
        if summary["added_active"]:
            deploy_no_download_or_raise()
    except Exception as exc:
        return custom_rules_error(request, str(exc))
    return render(request, "custom_rules.html", **custom_rules_context(request, bulk_results=summary))


@app.post("/custom-rules/test")
def custom_test(request: Request, domain: str = Form(...), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    with db() as conn:
        result = custom_rules_model.evaluate_domain(conn, domain)
        conn.commit()
    return render(request, "custom_rules.html", **custom_rules_context(request, test_result=result, test_domain=domain))


@app.post("/custom-rules/selected")
def custom_selected(request: Request, op: str = Form(...), ids: list[int] = Form([]), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    if not ids:
        return custom_rules_error(request, "Select at least one rule first.")
    try:
        if op == "enable":
            custom_rules_model.bulk_set_enabled(ids, True)
        elif op == "disable":
            custom_rules_model.bulk_set_enabled(ids, False)
        elif op == "delete":
            custom_rules_model.bulk_delete(ids)
        else:
            raise HTTPException(status_code=400, detail="unknown bulk operation")
        deploy_no_download_or_raise()
    except HTTPException:
        raise
    except Exception as exc:
        return custom_rules_error(request, str(exc))
    return redirect("/custom-rules")


@app.post("/custom-rules/add-from-query")
def custom_add_from_query(
    request: Request,
    action: str = Form(...),
    domain: str = Form(...),
    csrf: str = Form(...),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    normalized = normalize_domain(domain)
    if not normalized or action not in {"allow", "block"}:
        raise HTTPException(status_code=400, detail="invalid custom rule")
    text = ("@@||" if action == "allow" else "||") + normalized + "^"
    custom_rules_model.add_rule(text, source_system="manual", comment="created from query log")
    deploy_no_download()
    return redirect("/query-log")


@app.post("/custom-rules/{rule_id}/edit")
def custom_edit(
    request: Request,
    rule_id: int,
    rule_text: str = Form(...),
    comment: str = Form(""),
    enabled: str = Form("0"),
    csrf: str = Form(...),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        custom_rules_model.update_rule(rule_id, rule_text, comment, enabled == "1")
        deploy_no_download_or_raise()
    except Exception as exc:
        return custom_rules_error(request, str(exc))
    return redirect("/custom-rules")


@app.post("/custom-rules/{rule_id}/toggle")
def custom_toggle(request: Request, rule_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        custom_rules_model.toggle_rule(rule_id)
        deploy_no_download_or_raise()
    except Exception as exc:
        return custom_rules_error(request, str(exc))
    return redirect("/custom-rules")


@app.post("/custom-rules/{rule_id}/delete")
def custom_delete(request: Request, rule_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        custom_rules_model.delete_rule(rule_id)
        deploy_no_download_or_raise()
    except Exception as exc:
        return custom_rules_error(request, str(exc))
    return redirect("/custom-rules")


def local_dns_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    context = local_dns.list_records(request.query_params.get("search", ""))
    context.update({"error": message, "preview": None, "hosts_preview": None})
    return render(request, "local_dns.html", **context, status_code=status_code)


@app.get("/local-dns", response_class=HTMLResponse)
def local_dns_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = local_dns.list_records(request.query_params.get("search", ""))
    context.update({"error": None, "preview": None, "hosts_preview": None})
    return render(request, "local_dns.html", **context)


@app.post("/local-dns/settings")
def local_dns_settings_post(
    request: Request,
    csrf: str = Form(...),
    internal_domain: str = Form("home.arpa"),
    default_ttl: int = Form(300),
    server_hostname: str = Form("alderpointdns"),
    server_ip: str = Form(""),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        local_dns.update_settings(
            {
                "internal_domain": internal_domain,
                "default_ttl": default_ttl,
                "server_hostname": server_hostname.strip() or "alderpointdns",
                "server_ip": server_ip.strip() or local_dns.detect_server_ip(),
            }
        )
        deploy_no_download()
    except Exception as exc:
        return local_dns_error(request, str(exc))
    return redirect("/local-dns")


@app.post("/local-dns/server-record")
def local_dns_server_record(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        cfg = local_dns.settings()
        host = cfg.get("server_hostname", "alderpointdns")
        ip = cfg.get("server_ip") or local_dns.detect_server_ip()
        local_dns.add_host(host, cfg.get("internal_domain", "home.arpa"), ip, cfg.get("default_ttl", 300), "Alderpoint DNS server", True, True)
        local_dns.upsert_alias(ip, "Alderpoint DNS", "Alderpoint DNS DNS appliance")
        deploy_no_download()
    except Exception as exc:
        return local_dns_error(request, str(exc))
    return redirect("/local-dns")


@app.post("/local-dns/hosts")
def local_dns_add_host(
    request: Request,
    csrf: str = Form(...),
    hostname: str = Form(...),
    domain: str = Form("home.arpa"),
    address: str = Form(...),
    ttl: int = Form(300),
    comment: str = Form(""),
    auto_ptr: str = Form("0"),
    override: str = Form("0"),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        local_dns.add_host(hostname, domain, address, ttl, comment, auto_ptr == "1", override == "1")
        deploy_no_download()
    except Exception as exc:
        return local_dns_error(request, str(exc))
    return redirect("/local-dns")


@app.post("/local-dns/records")
def local_dns_add_record(
    request: Request,
    csrf: str = Form(...),
    record_type: str = Form(...),
    fqdn: str = Form(...),
    value: str = Form(...),
    ttl: int = Form(300),
    comment: str = Form(""),
    enabled: str = Form("0"),
    override: str = Form("0"),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        local_dns.add_record(record_type, fqdn, value, ttl, comment, enabled == "1", override == "1")
        deploy_no_download()
    except Exception as exc:
        return local_dns_error(request, str(exc))
    return redirect("/local-dns")


@app.post("/local-dns/records/{record_id}/edit")
def local_dns_edit_record(
    request: Request,
    record_id: int,
    csrf: str = Form(...),
    record_type: str = Form(...),
    fqdn: str = Form(...),
    value: str = Form(...),
    ttl: int = Form(300),
    comment: str = Form(""),
    enabled: str = Form("0"),
    override: str = Form("0"),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        local_dns.update_record(record_id, record_type, fqdn, value, ttl, comment, enabled == "1", override == "1")
        deploy_no_download()
    except Exception as exc:
        return local_dns_error(request, str(exc))
    return redirect("/local-dns")


@app.post("/local-dns/records/{record_id}/toggle")
def local_dns_toggle_record(request: Request, record_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    local_dns.toggle_record(record_id)
    deploy_no_download()
    return redirect("/local-dns")


@app.post("/local-dns/records/{record_id}/delete")
def local_dns_delete_record(request: Request, record_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    local_dns.delete_record(record_id)
    deploy_no_download()
    return redirect("/local-dns")


@app.post("/local-dns/aliases")
def local_dns_add_alias(
    request: Request,
    csrf: str = Form(...),
    cidr: str = Form(...),
    display_name: str = Form(...),
    description: str = Form(""),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        local_dns.upsert_alias(cidr, display_name, description)
    except Exception as exc:
        return local_dns_error(request, str(exc))
    return redirect("/local-dns")


@app.post("/local-dns/aliases/{alias_id}/delete")
def local_dns_delete_alias(request: Request, alias_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    local_dns.delete_alias(alias_id)
    return redirect("/local-dns")


@app.post("/local-dns/import/preview")
def local_dns_import_preview(request: Request, csrf: str = Form(...), csv_text: str = Form(""), hosts_text: str = Form(""), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    context = local_dns.list_records("")
    try:
        preview = local_dns.csv_preview(csv_text) if csv_text.strip() else None
        hosts = local_dns.hosts_preview(hosts_text, context["settings"].get("internal_domain", "home.arpa")) if hosts_text.strip() else None
    except Exception as exc:
        return local_dns_error(request, str(exc))
    context.update({"error": None, "preview": preview, "hosts_preview": hosts, "csv_text": csv_text, "hosts_text": hosts_text})
    return render(request, "local_dns.html", **context)


@app.post("/local-dns/import")
def local_dns_import_apply(request: Request, csrf: str = Form(...), csv_text: str = Form(""), override: str = Form("0"), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        local_dns.csv_import(csv_text, override == "1")
        deploy_no_download()
    except Exception as exc:
        return local_dns_error(request, str(exc))
    return redirect("/local-dns")


@app.get("/local-dns/export")
def local_dns_export(_: sqlite3.Row = Depends(current_admin)):
    return PlainTextResponse(local_dns.csv_export(), media_type="text/csv")


def clients_access_context() -> dict[str, Any]:
    rules = clients_model.list_access_rules()
    clients_list = clients_model.list_clients()
    clients_by_id = {c["id"]: c for c in clients_list}
    default_policy = clients_model.get_default_policy()
    for client in clients_list:
        client["effective"] = clients_model.effective_access_for_client(client, rules, clients_by_id, default_policy)
    return {
        "clients": clients_list,
        "rules": rules,
        "default_policy": default_policy,
        "clientid_min_hex": clients_model.CLIENTID_MIN_HEX_LEN,
        "clientid_max_hex": clients_model.CLIENTID_MAX_HEX_LEN,
    }


def clients_access_error(request: Request, message: str, status_code: int = 400, **extra: Any) -> HTMLResponse:
    context = clients_access_context()
    context.update({"error": message, "generated_clientid": None})
    context.update(extra)
    return render(request, "clients_access.html", **context, status_code=status_code)


def _deploy_access_or_error(request: Request, success_redirect: str) -> HTMLResponse:
    """Shared tail for every Clients & Access mutation route: deploy the
    freshly-written database state to dnsdist, and if that fails, surface
    the failure to the admin instead of silently leaving dnsdist on a
    stale policy (the DB row the caller just wrote is NOT rolled back --
    same convention as local_dns's deploy_no_download(), so the object
    exists and can be retried/fixed without re-entering it)."""
    code, out = access_policy_deploy_apply()
    if code != 0:
        return clients_access_error(request, f"saved, but deploying to dnsdist failed: {out.strip()}")
    return redirect(success_redirect)


@app.get("/clients-access", response_class=HTMLResponse)
def clients_access_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = clients_access_context()
    context.update({"error": None, "generated_clientid": None})
    return render(request, "clients_access.html", **context)


@app.post("/clients-access/policy")
def clients_access_policy_post(
    request: Request,
    csrf: str = Form(...),
    default_policy: str = Form(...),
    confirm: str = Form("0"),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    if default_policy == "deny" and confirm != "1":
        return clients_access_error(
            request,
            "Switching to Default Deny requires explicit confirmation -- review the Allowed entries below, "
            "then check the confirmation box and submit again. Loopback (127.0.0.1/::1) stays reachable "
            "automatically so Alderpoint's own health checks are not locked out; nothing else is.",
        )
    try:
        clients_model.set_default_policy(default_policy)
    except clients_model.ClientsError as exc:
        return clients_access_error(request, str(exc))
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "access_default_policy_changed", True, ip, f"policy={default_policy}")
    return _deploy_access_or_error(request, "/clients-access")


@app.post("/clients-access/clients")
def clients_access_create_client(
    request: Request,
    csrf: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    identifiers: str = Form(""),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    raw_identifiers = [line.strip() for line in identifiers.splitlines() if line.strip()]
    try:
        client_id = clients_model.create_client(name, description, raw_identifiers)
    except clients_model.ClientsError as exc:
        return clients_access_error(request, str(exc))
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "client_created", True, ip, f"name={name.strip()[:80]} identifiers={len(raw_identifiers)}")
    return _deploy_access_or_error(request, "/clients-access")


@app.post("/clients-access/clients/{client_id}/edit")
def clients_access_edit_client(
    request: Request,
    client_id: int,
    csrf: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    enabled: str = Form("1"),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    try:
        clients_model.update_client(client_id, name, description, enabled == "1")
    except clients_model.ClientsError as exc:
        return clients_access_error(request, str(exc))
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "client_updated", True, ip, f"client_id={client_id}")
    return _deploy_access_or_error(request, "/clients-access")


@app.post("/clients-access/clients/{client_id}/toggle")
def clients_access_toggle_client(
    request: Request, client_id: int, csrf: str = Form(...), enabled: str = Form(...), admin: sqlite3.Row = Depends(current_admin)
):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    try:
        clients_model.set_client_enabled(client_id, enabled == "1")
    except clients_model.ClientsError as exc:
        return clients_access_error(request, str(exc))
    with db() as conn:
        action = "client_enabled" if enabled == "1" else "client_disabled"
        audit_log(conn, admin["id"], admin["username"], action, True, ip, f"client_id={client_id}")
    return _deploy_access_or_error(request, "/clients-access")


@app.post("/clients-access/clients/{client_id}/delete")
def clients_access_delete_client(request: Request, client_id: int, csrf: str = Form(...), admin: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    try:
        clients_model.delete_client(client_id)
    except clients_model.ClientsError as exc:
        return clients_access_error(request, str(exc))
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "client_deleted", True, ip, f"client_id={client_id}")
    return _deploy_access_or_error(request, "/clients-access")


@app.post("/clients-access/clients/{client_id}/identifiers")
def clients_access_add_identifier(
    request: Request,
    client_id: int,
    csrf: str = Form(...),
    value: str = Form(""),
    generate_bits: str = Form(""),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    generated: str | None = None
    try:
        if generate_bits:
            bits = int(generate_bits)
            generated = clients_model.generate_clientid(bits)
            clients_model.add_identifier(client_id, generated)
            # The value itself is shown once in the response page below for
            # the admin to copy -- never written to the audit log or any
            # other log, only the fact that one was generated/assigned.
            with db() as conn:
                audit_log(conn, admin["id"], admin["username"], "clientid_generated", True, ip, f"client_id={client_id} bits={bits}")
        else:
            clients_model.add_identifier(client_id, value)
            with db() as conn:
                audit_log(conn, admin["id"], admin["username"], "identifier_added", True, ip, f"client_id={client_id}")
    except clients_model.ClientsError as exc:
        return clients_access_error(request, str(exc))
    code, out = access_policy_deploy_apply()
    if code != 0:
        return clients_access_error(request, f"saved, but deploying to dnsdist failed: {out.strip()}", generated_clientid=generated)
    if generated:
        context = clients_access_context()
        context.update({"error": None, "generated_clientid": generated, "generated_bits": len(generated) * 4})
        return render(request, "clients_access.html", **context)
    return redirect("/clients-access")


@app.post("/clients-access/identifiers/{identifier_id}/delete")
def clients_access_delete_identifier(request: Request, identifier_id: int, csrf: str = Form(...), admin: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    try:
        clients_model.remove_identifier(identifier_id)
    except clients_model.ClientsError as exc:
        return clients_access_error(request, str(exc))
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "identifier_removed", True, ip, f"identifier_id={identifier_id}")
    return _deploy_access_or_error(request, "/clients-access")


@app.post("/clients-access/rules")
def clients_access_add_rule(
    request: Request,
    csrf: str = Form(...),
    action: str = Form(...),
    kind: str = Form(...),
    value: str = Form(""),
    client_id: str = Form(""),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    try:
        rule_id = clients_model.add_access_rule(action, kind, value or None, int(client_id) if client_id else None)
    except clients_model.ClientsError as exc:
        return clients_access_error(request, str(exc))
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "access_rule_added", True, ip, f"rule_id={rule_id} action={action} kind={kind}")
    return _deploy_access_or_error(request, "/clients-access")


@app.post("/clients-access/rules/{rule_id}/delete")
def clients_access_delete_rule(request: Request, rule_id: int, csrf: str = Form(...), admin: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    try:
        clients_model.remove_access_rule(rule_id)
    except clients_model.ClientsError as exc:
        return clients_access_error(request, str(exc))
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "access_rule_removed", True, ip, f"rule_id={rule_id}")
    return _deploy_access_or_error(request, "/clients-access")


def dns_cache_context() -> dict[str, Any]:
    return {
        "cache": dns_cache.settings(),
        "stats": dns_cache.cache_stats(),
        "deployment": dns_cache.last_deployment(),
        "flushes": dns_cache.recent_flushes(),
        "total_memory_mb": dns_cache.detect_total_memory_mb(),
    }


def dns_cache_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    context = dns_cache_context()
    context.update({"error": message})
    return render(request, "dns_cache.html", **context, status_code=status_code)


@app.get("/dns-cache", response_class=HTMLResponse)
def dns_cache_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = dns_cache_context()
    context.update({"error": None})
    return render(request, "dns_cache.html", **context)


@app.post("/dns-cache/settings")
def dns_cache_settings_post(
    request: Request,
    csrf: str = Form(...),
    max_cache_size_mb: int = Form(...),
    min_cache_ttl: int = Form(...),
    max_cache_ttl: int = Form(...),
    min_ncache_ttl: int = Form(...),
    max_ncache_ttl: int = Form(...),
    prefetch_enabled: str = Form("0"),
    prefetch_trigger: int = Form(2),
    prefetch_eligible: int = Form(10),
    serve_stale_enabled: str = Form("0"),
    max_stale_ttl: int = Form(86400),
    stale_answer_client_timeout: str = Form("off"),
    recursive_clients: int = Form(1000),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        dns_cache.update_settings(
            {
                "max_cache_size_mb": max_cache_size_mb,
                "min_cache_ttl": min_cache_ttl,
                "max_cache_ttl": max_cache_ttl,
                "min_ncache_ttl": min_ncache_ttl,
                "max_ncache_ttl": max_ncache_ttl,
                "prefetch_enabled": prefetch_enabled,
                "prefetch_trigger": prefetch_trigger,
                "prefetch_eligible": prefetch_eligible,
                "serve_stale_enabled": serve_stale_enabled,
                "max_stale_ttl": max_stale_ttl,
                "stale_answer_client_timeout": stale_answer_client_timeout,
                "recursive_clients": recursive_clients,
            }
        )
        cache_options_deploy_or_raise()
    except Exception as exc:
        return dns_cache_error(request, str(exc))
    return redirect("/dns-cache")


@app.post("/dns-cache/flush")
def dns_cache_flush_all(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        dns_cache.request_flush("all")
        cache_flush_apply_or_raise()
    except Exception as exc:
        return dns_cache_error(request, str(exc))
    return redirect("/dns-cache")


@app.post("/dns-cache/flush-name")
def dns_cache_flush_name(request: Request, csrf: str = Form(...), name: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        dns_cache.request_flush("name", name)
        cache_flush_apply_or_raise()
    except Exception as exc:
        return dns_cache_error(request, str(exc))
    return redirect("/dns-cache")


@app.post("/dns-cache/flush-tree")
def dns_cache_flush_tree(request: Request, csrf: str = Form(...), name: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        dns_cache.request_flush("tree", name)
        cache_flush_apply_or_raise()
    except Exception as exc:
        return dns_cache_error(request, str(exc))
    return redirect("/dns-cache")


def encryption_context() -> dict[str, Any]:
    cfg = encryption.settings()
    cert_path, _key_path = encryption.resolve_active_cert_paths(cfg)
    return {
        "cfg": cfg,
        "cert": encryption.cert_info(cert_path),
        "deployment": encryption.last_deployment(),
        "connection_info": encryption.connection_info(cfg),
        "dnscrypt_fingerprint": encryption.dnscrypt_provider_fingerprint(),
        "capabilities": encryption.dnsdist_capabilities(),
    }


def encryption_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    context = encryption_context()
    context.update({"error": message})
    return render(request, "encryption.html", **context, status_code=status_code)


def _deploy_encryption_or_error(request: Request, admin: sqlite3.Row, action: str, detail: str, success_redirect: str = "/encryption") -> Any:
    """Shared tail for every /encryption/* mutation route: deploy the
    freshly-staged settings/certificate to dnsdist via the privileged
    encryption-deploy CLI subcommand, and audit-log + surface the *actual*
    result -- never redirect to a success page (or stay silent) when
    encryption_deploy_apply()'s (code, output) says deployment failed. The
    DB row/staged material the caller already wrote is not itself rolled
    back here (app.encryption.deploy_encryption() has its own last-known-good
    rollback for the dnsdist config and any newly promoted cert/key
    material); this only ensures the admin is told the truth about whether
    that deployment actually completed. Mirrors
    _deploy_access_or_error()'s convention for /clients-access/*."""
    ip = request.client.host if request.client else None
    try:
        code, out = encryption_deploy_apply()
    except Exception as exc:
        code, out = 1, str(exc)
    output_tail = out.strip()
    with db() as conn:
        audit_log(
            conn,
            admin["id"],
            admin["username"],
            action,
            code == 0,
            ip,
            detail if code == 0 else f"{detail}; deploy failed: {output_tail[-500:]}",
        )
    if code != 0:
        # jinja2 autoescapes {{ error }} in encryption.html, so raw
        # subprocess/dnsdist output ending up here (which can legitimately
        # contain '<', '&', etc. from e.g. a dnsdist --check-config Lua
        # error) can never be interpreted as markup by the browser -- it is
        # always shown as inert text, not sanitized/stripped here.
        return encryption_error(request, f"{detail} was saved, but deploying it to dnsdist failed: {output_tail}")
    return redirect(success_redirect)


@app.get("/encryption", response_class=HTMLResponse)
def encryption_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = encryption_context()
    context.update({"error": None})
    return render(request, "encryption.html", **context)


@app.post("/encryption/settings")
def encryption_settings_post(
    request: Request,
    csrf: str = Form(...),
    server_hostname: str = Form(...),
    bootstrap_ip: str = Form(""),
    listen_ipv4: str = Form("0.0.0.0"),
    listen_ipv6: str = Form("::"),
    doh_enabled: str = Form("0"),
    doh3_enabled: str = Form("0"),
    dot_enabled: str = Form("0"),
    doq_enabled: str = Form("0"),
    dnscrypt_enabled: str = Form("0"),
    doh_path: str = Form("/dns-query"),
    doh_port: int = Form(443),
    doh3_port: int = Form(443),
    dot_port: int = Form(853),
    doq_port: int = Form(853),
    dnscrypt_port: int = Form(5443),
    dnscrypt_provider: str = Form("2.dnscrypt-cert.alderpointdns.local"),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        cfg = encryption.settings()
        submitted = {
            **cfg,
            "server_hostname": server_hostname,
            "bootstrap_ip": bootstrap_ip,
            "listen_ipv4": listen_ipv4,
            "listen_ipv6": listen_ipv6,
            "doh_enabled": doh_enabled,
            "doh3_enabled": doh3_enabled,
            "dot_enabled": dot_enabled,
            "doq_enabled": doq_enabled,
            "dnscrypt_enabled": dnscrypt_enabled,
            "doh_path": doh_path,
            "doh_port": doh_port,
            "doh3_port": doh3_port,
            "dot_port": dot_port,
            "doq_port": doq_port,
            "dnscrypt_port": dnscrypt_port,
            "dnscrypt_provider": dnscrypt_provider,
        }
        # A forged/crafted POST could set doq_enabled=1 even though the
        # form control is rendered disabled for an unsupported protocol;
        # enforce the same authoritative capability check here so it can
        # never be persisted as enabled, not just hidden in the UI.
        submitted, _capability_warnings = encryption.enforce_capabilities(submitted)
        encryption.update_settings(submitted)
    except Exception as exc:
        return encryption_error(request, str(exc))
    return _deploy_encryption_or_error(request, admin, "encryption_settings_changed", f"encryption settings for {server_hostname}")


@app.post("/encryption/certificate/self-signed")
def encryption_cert_self_signed(request: Request, csrf: str = Form(...), admin: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        encryption.update_settings({**encryption.settings(), "cert_mode": "self_signed"})
        encryption.request_cert_action("generate_self_signed")
    except Exception as exc:
        return encryption_error(request, str(exc))
    return _deploy_encryption_or_error(request, admin, "encryption_cert_self_signed", "self-signed certificate generation")


@app.post("/encryption/certificate/local-ca")
def encryption_cert_local_ca(request: Request, csrf: str = Form(...), admin: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        encryption.update_settings({**encryption.settings(), "cert_mode": "local_ca"})
        encryption.request_cert_action("generate_local_ca")
    except Exception as exc:
        return encryption_error(request, str(exc))
    return _deploy_encryption_or_error(request, admin, "encryption_cert_local_ca", "local CA certificate issuance")


@app.post("/encryption/certificate/upload")
async def encryption_cert_upload(
    request: Request,
    csrf: str = Form(...),
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()
        if not cert_bytes or not key_bytes:
            raise encryption.EncryptionError("both a certificate file and a key file are required")
        encryption.request_cert_upload(cert_bytes, key_bytes)
        encryption.update_settings({**encryption.settings(), "cert_mode": "uploaded"})
    except Exception as exc:
        return encryption_error(request, str(exc))
    return _deploy_encryption_or_error(request, admin, "encryption_cert_uploaded", "uploaded certificate/key")


@app.post("/encryption/certificate/existing-path")
def encryption_cert_existing_path(
    request: Request,
    csrf: str = Form(...),
    cert_path: str = Form(...),
    key_path: str = Form(...),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        encryption.update_settings({**encryption.settings(), "cert_mode": "existing_path", "cert_path": cert_path, "key_path": key_path})
    except Exception as exc:
        return encryption_error(request, str(exc))
    return _deploy_encryption_or_error(request, admin, "encryption_cert_existing_path", f"existing-path certificate {cert_path}")


@app.get("/encryption/certificate/download")
def encryption_cert_download(_: sqlite3.Row = Depends(current_admin)):
    cfg = encryption.settings()
    cert_path, _key_path = encryption.resolve_active_cert_paths(cfg)
    if not cert_path.exists():
        raise HTTPException(status_code=404, detail="no certificate deployed")
    return PlainTextResponse(cert_path.read_text(), media_type="application/x-pem-file")


@app.get("/encryption/apple/{protocol}.mobileconfig")
def encryption_apple_profile(protocol: str, _: sqlite3.Row = Depends(current_admin)):
    if protocol not in {"doh", "dot"}:
        raise HTTPException(status_code=404, detail="unknown profile")
    cfg = encryption.settings()
    if cfg.get(f"{protocol}_enabled") != "1":
        raise HTTPException(status_code=400, detail=f"{protocol} is not enabled")
    content = encryption.apple_mobileconfig(cfg, protocol)
    return Response(content=content, media_type="application/x-apple-aspen-config")


@app.get("/dns-settings", response_class=HTMLResponse)
def dns_settings(request: Request, _: sqlite3.Row = Depends(current_admin)):
    version = dnsdist_version_info()
    proxy_backend = proxy_backend_enabled()
    client_address_test = client_address_preservation_status()
    return render(
        request,
        "dns_settings.html",
        backend="127.0.0.1:5353 plain health/recovery, 127.0.0.1:5354 PROXYv2",
        allowed_clients=[
            "RFC1918 private networks",
            "loopback",
            "fc00::/7",
            f"Allow all: {'Enabled' if dns_allow_all_enabled() else 'Disabled'}",
        ],
        maintenance="1.1.1.2, 1.0.0.2, 4.2.2.1, 4.2.2.2",
        hostname="alderpointdns.local",
        doh_path="/dns-query",
        dnsdist_version=version["version"],
        dnsdist_features=version["features"],
        dnsdist_capabilities=encryption.dnsdist_capabilities(),
        protocols=protocol_statuses(),
        cert=cert_status(),
        proxy_backend="enabled" if proxy_backend else "not enabled",
        client_address_test=client_address_test,
        upstream_resolvers=upstream_dns.display_resolvers(),
        upstream_deployment=upstream_dns.last_deployment(),
        upstream_error=None,
        upstream_telemetry_poll_ms=int(upstream_dns.UPSTREAM_TELEMETRY_POLL_SECONDS * 1000),
    )


def dns_settings_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    response = dns_settings(request, current_admin(request))
    response.status_code = status_code
    body = response.body.decode()
    body = body.replace('<section class="grid">', f'<div class="alert error">{message}</div>\n<section class="grid">', 1)
    return HTMLResponse(body, status_code=status_code)


@app.get("/dns-settings/upstreams/telemetry")
def upstream_telemetry(_: sqlite3.Row = Depends(current_admin)):
    return JSONResponse({"resolvers": upstream_dns.probe_telemetry()})


@app.post("/dns-settings/upstreams/add")
def upstream_add(
    request: Request,
    csrf: str = Form(...),
    name: str = Form(...),
    protocol: str = Form(...),
    address: str = Form(...),
    port: str = Form(""),
    doh_path: str = Form(""),
    tls_hostname: str = Form(""),
    bootstrap_ips: str = Form(""),
    enabled: str = Form("0"),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        upstream_dns.add_resolver({"name": name, "protocol": protocol, "address": address, "port": port, "doh_path": doh_path, "tls_hostname": tls_hostname, "bootstrap_ips": bootstrap_ips, "enabled": enabled})
        upstream_deploy_or_raise()
    except Exception as exc:
        return dns_settings_error(request, str(exc))
    return redirect("/dns-settings")


@app.post("/dns-settings/upstreams/{resolver_id}/edit")
def upstream_edit(
    request: Request,
    resolver_id: int,
    csrf: str = Form(...),
    name: str = Form(...),
    protocol: str = Form(...),
    address: str = Form(...),
    port: str = Form(""),
    doh_path: str = Form(""),
    tls_hostname: str = Form(""),
    bootstrap_ips: str = Form(""),
    enabled: str = Form("0"),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        upstream_dns.update_resolver(resolver_id, {"name": name, "protocol": protocol, "address": address, "port": port, "doh_path": doh_path, "tls_hostname": tls_hostname, "bootstrap_ips": bootstrap_ips, "enabled": enabled})
        upstream_deploy_or_raise()
    except Exception as exc:
        return dns_settings_error(request, str(exc))
    return redirect("/dns-settings")


@app.post("/dns-settings/upstreams/{resolver_id}/toggle")
def upstream_toggle(request: Request, resolver_id: int, csrf: str = Form(...), enabled: str = Form("0"), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        upstream_dns.set_enabled(resolver_id, enabled == "1")
        upstream_deploy_or_raise()
    except Exception as exc:
        return dns_settings_error(request, str(exc))
    return redirect("/dns-settings")


@app.post("/dns-settings/upstreams/{resolver_id}/move")
def upstream_move(request: Request, resolver_id: int, csrf: str = Form(...), direction: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        upstream_dns.move_resolver(resolver_id, direction)
        upstream_deploy_or_raise()
    except Exception as exc:
        return dns_settings_error(request, str(exc))
    return redirect("/dns-settings")


@app.post("/dns-settings/upstreams/{resolver_id}/delete")
def upstream_delete(request: Request, resolver_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        upstream_dns.delete_resolver(resolver_id)
        upstream_deploy_or_raise()
    except Exception as exc:
        return dns_settings_error(request, str(exc))
    return redirect("/dns-settings")


def import_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    context = {"error": message, "jobs": importer.list_jobs(), "job": None, "preview": None, "adguard": None, "migration_summary": None}
    return render(request, "import_migration.html", **context, status_code=status_code)


@app.get("/import", response_class=HTMLResponse)
def import_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "import_migration.html", error=None, jobs=importer.list_jobs(), job=None, preview=None, adguard=None, migration_summary=None)


@app.get("/import/migration", response_class=HTMLResponse)
def import_migration_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return import_page(request, _)


@app.post("/import/upload")
async def import_upload(
    request: Request,
    csrf: str = Form(...),
    source_type: str = Form(...),
    default_domain: str = Form(""),
    upload: UploadFile = File(...),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    source_path: Path | None = None
    try:
        data = await upload.read()
        source_path = importer.stage_uploaded_source(upload.filename or source_type, data)
        cfg = local_dns.settings()
        domain = default_domain.strip() or cfg.get("internal_domain", "home.arpa")
        if source_type == "csv":
            headers, rows = importer.parse_csv_text(data.decode("utf-8-sig", errors="replace"))
            column_map = importer.auto_map_columns(headers)
        elif source_type == "alderpointdns_csv":
            rows = importer.parse_alderpointdns_csv(data.decode("utf-8-sig", errors="replace"))
            headers, column_map = [], {}
        elif source_type == "xlsx":
            headers, rows = importer.parse_xlsx_bytes(data)
            column_map = importer.auto_map_columns(headers)
        elif source_type == "hosts":
            rows = importer.parse_hosts_text(data.decode("utf-8", errors="replace"), domain)
            headers, column_map = [], {}
        elif source_type == "zone":
            rows = importer.parse_zone_text(data.decode("utf-8", errors="replace"), domain)
            headers, column_map = [], {}
        elif source_type == "pihole":
            translation = importer.parse_pihole_text(data.decode("utf-8", errors="replace"), domain)
            job_id = importer.create_migration_job("pihole", upload.filename or "Pi-hole import", translation, str(source_path))
            importer.migration_preview_job(job_id, domain)
            return redirect(f"/import/jobs/{job_id}/preview")
        elif source_type == "alderpointdns_json":
            translation = importer.parse_alderpointdns_native_json(data.decode("utf-8", errors="replace"))
            job_id = importer.create_migration_job("alderpointdns_json", upload.filename or "Alderpoint DNS native JSON", translation, str(source_path))
            importer.migration_preview_job(job_id, domain)
            return redirect(f"/import/jobs/{job_id}/preview")
        else:
            raise importer.ImportError_(f"unknown source type {source_type!r}")
        if not rows:
            raise importer.ImportError_("no rows found in uploaded file")
        job_id = importer.create_job(source_type, upload.filename or source_type, headers, rows, str(source_path))
        preview = importer.preview_job(job_id, column_map, domain)
    except Exception as exc:
        if source_path and source_path.exists():
            source_path.unlink(missing_ok=True)
        return import_error(request, str(exc))
    return redirect(f"/import/jobs/{job_id}")


@app.get("/import/export/alderpointdns.json")
def import_export_alderpointdns(_: sqlite3.Row = Depends(current_admin)):
    return PlainTextResponse(importer.export_alderpointdns_native(), media_type="application/json")


@app.get("/import/jobs/{job_id}", response_class=HTMLResponse)
def import_job_page(request: Request, job_id: int = PathParam(..., gt=0), _: sqlite3.Row = Depends(current_admin)):
    job = importer.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="import job not found")
    if importer.is_migration_source(job["source_type"]) and job["status"] in ("uploaded", "previewed"):
        return redirect(f"/import/jobs/{job_id}/preview")
    headers = json.loads(job["headers_json"]) if job["headers_json"] else []
    column_map = json.loads(job["column_map_json"]) if job["column_map_json"] else (importer.auto_map_columns(headers) if headers else {})
    preview = None
    if job["status"] in ("uploaded", "previewed"):
        preview = importer.preview_job(job_id, column_map)
        job = importer.get_job(job_id)
    return render(request, "import_migration.html", error=None, jobs=importer.list_jobs(), job=job, headers=headers, column_map=column_map, canonical_fields=importer.CANONICAL_FIELDS, preview=preview, adguard=None, migration_summary=None, migration_job_id=None)


@app.get("/import/jobs/{job_id}/status")
def import_job_status(job_id: int = PathParam(..., gt=0), _: sqlite3.Row = Depends(current_admin)):
    job = importer.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="import job not found")
    return JSONResponse({key: job[key] for key in ("id", "source_type", "source_name", "status", "total_rows", "valid_rows", "invalid_rows", "duplicate_rows", "conflict_rows", "applied_rows", "skipped_rows", "failed_rows", "message")})


@app.get("/import/jobs/{job_id}/preview", response_class=HTMLResponse)
def import_job_preview(request: Request, job_id: int = PathParam(..., gt=0), _: sqlite3.Row = Depends(current_admin)):
    job = importer.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="import job not found")
    if importer.is_migration_source(job["source_type"]):
        try:
            result = importer.migration_preview_job(job_id)
            job = importer.get_job(job_id)
        except Exception as exc:
            return import_error(request, str(exc))
        title = {
            "adguard_yaml": "AdGuard Home Migration Preview",
            "adguard_api": "AdGuard Home Migration Preview",
            "pihole": "Pi-hole Migration Preview",
            "alderpointdns_json": "Alderpoint DNS Native Import Preview",
        }.get(job["source_type"], "Migration Preview")
        return render(request, "import_migration.html", error=None, jobs=importer.list_jobs(), job=None, preview=None, adguard=result["translation"], migration_summary=result["summary"], migration_title=title, source_path=job["source_path"], migration_job_id=job_id)
    return import_job_page(request, job_id, _)


@app.post("/import/jobs/{job_id}/remap")
async def import_job_remap(request: Request, job_id: int = PathParam(..., gt=0), _: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    try:
        column_map = {field: str(form.get(f"map_{field}", "")) for field in importer.CANONICAL_FIELDS if form.get(f"map_{field}")}
        importer.preview_job(job_id, column_map)
    except Exception as exc:
        return import_error(request, str(exc))
    return redirect(f"/import/jobs/{job_id}")


@app.post("/import/jobs/{job_id}/apply")
async def import_job_apply(request: Request, job_id: int = PathParam(..., gt=0), _: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    is_migration = False
    try:
        job = importer.get_job(job_id)
        if not job:
            raise importer.ImportError_(f"import job {job_id} not found")
        is_migration = importer.is_migration_source(job["source_type"])
        if is_migration:
            # The preview form posts one `sel` value per checked item key
            # (`category:index`) plus an `itemized` marker so an empty
            # selection is distinguishable from a keyless (apply-defaults)
            # request.
            selected = set(form.getlist("sel")) if "itemized" in form else None
            importer.apply_migration_job(job_id, selected=selected)
        else:
            default_policy = str(form.get("default_policy", "skip"))
            importer.apply_job(job_id, default_policy=default_policy)
    except Exception as exc:
        return import_error(request, str(exc))
    try:
        deploy_no_download_or_raise()
    except Exception as exc:
        if is_migration:
            # The database writes stay (deploy() already rolled the compiled
            # config back to the previous good state); record the outcome so
            # the operator can roll the database back or retry.
            importer.mark_job_deploy_failed(job_id, str(exc))
            return import_error(
                request,
                f"The import was applied to the database, but deployment failed: {exc} "
                "The previously deployed configuration remains active. "
                "Use \"Roll back this import\" to revert the imported data, or retry the deployment.",
            )
        return import_error(request, str(exc))
    return redirect(f"/import/jobs/{job_id}")


@app.post("/import/jobs/{job_id}/rollback")
def import_job_rollback(request: Request, job_id: int = PathParam(..., gt=0), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        importer.rollback_job(job_id)
        deploy_no_download_or_raise()
    except Exception as exc:
        return import_error(request, str(exc))
    return redirect(f"/import/jobs/{job_id}")


@app.post("/import/jobs/{job_id}/cancel")
def import_job_cancel(request: Request, job_id: int = PathParam(..., gt=0), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        importer.cancel_job(job_id)
    except Exception as exc:
        return import_error(request, str(exc))
    return redirect("/import")


@app.get("/import/jobs/{job_id}/report")
def import_job_report(job_id: int = PathParam(..., gt=0), _: sqlite3.Row = Depends(current_admin)):
    job = importer.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="import job not found")
    return PlainTextResponse(
        importer.job_report(job),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="import-job-{job_id}-report.json"'},
    )


@app.post("/import/migration/adguard/yaml")
async def import_adguard_yaml(request: Request, csrf: str = Form(...), upload: UploadFile = File(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    source_path: Path | None = None
    try:
        data = await upload.read()
        source_path = importer.stage_uploaded_source(upload.filename or "AdGuardHome.yaml", data)
        text = data.decode("utf-8", errors="replace")
        translation = importer.parse_adguard_yaml(text)
        job_id = importer.create_migration_job("adguard_yaml", upload.filename or "AdGuardHome.yaml", translation, str(source_path))
        importer.migration_preview_job(job_id)
    except Exception as exc:
        if source_path and source_path.exists():
            source_path.unlink(missing_ok=True)
        return import_error(request, str(exc))
    return redirect(f"/import/jobs/{job_id}/preview")


@app.post("/import/migration/adguard/api")
def import_adguard_api(request: Request, csrf: str = Form(...), base_url: str = Form(...), username: str = Form(...), password: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        translation = importer.fetch_adguard_api(base_url, username, password)
        # Only the sanitized base URL (scheme + host + port, no userinfo or
        # query string) is ever stored on the job row; the credentials are
        # used solely for the fetch above.
        job_id = importer.create_migration_job("adguard_api", importer.sanitize_adguard_base_url(base_url), translation)
        importer.migration_preview_job(job_id)
    except Exception as exc:
        return import_error(request, str(exc))
    return redirect(f"/import/jobs/{job_id}/preview")

# ---------------------------------------------------------------------------
# Backup and Restore
# ---------------------------------------------------------------------------

def backup_component_flags(form: Any) -> dict[str, bool]:
    return {key: str(form.get(key, "")).strip().lower() in {"1", "true", "on", "yes"} for key in backup.COMPONENT_KEYS}


def backup_create_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "backup-create"])


def backup_restore_apply() -> tuple[int, str]:
    # Deliberately NOT `sudo alderpointdns_compiler.py backup-restore`
    # directly: a restore's app_config component restarts
    # alderpointdns.service (this process's own service) partway through,
    # which would kill a direct sudo child of this request -- exactly the
    # real failure found on a live appliance restore: the sudo-spawned
    # restore worker vanished the instant alderpointdns.service's cgroup
    # was torn down and restarted mid-restore, right after the database
    # had already been promoted (status=interrupted,
    # phase=restarting_services, promoted_at non-null). `systemctl start`
    # hands the work to an independent unit (its own cgroup, owned by
    # PID 1) that survives that restart -- see
    # packaging/alderpointdns-backup-restore.service and
    # software_updates_start_install_runner()'s identical, already-
    # established pattern (including why --no-block is required, not
    # optional, there).
    return run(["sudo", "systemctl", "start", "--no-block", "alderpointdns-backup-restore.service"])


def backup_preview_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "backup-preview"])


def backup_schedule_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "backup-schedule-deploy"])


def backup_context() -> dict[str, Any]:
    return {
        "backups": backup.list_backups(),
        "backup_settings": backup.settings(),
        "last_backup": backup.last_backup(),
        "last_restore": backup.last_restore(),
        "component_keys": backup.COMPONENT_KEYS,
        "component_defaults": backup.COMPONENT_DEFAULTS,
    }


def backup_error(request: Request, message: str, status_code: int = 400, **extra: Any) -> HTMLResponse:
    context = backup_context()
    context.update({"error": message, "preview": None, "preview_source": None, "imported": None, "auto_download_url": None})
    context.update(extra)
    return render(request, "backup.html", **context, status_code=status_code)


def _auto_download_url(request: Request) -> str | None:
    """Resolves the `download` query param (set only by backup_create_route
    right after a successful create) to a same-origin download URL, using
    the same find_backup_path() confinement/lookup the manual Download
    button and the download route itself use -- never trusts the query
    param blindly, and never fires for a nonexistent/foreign path."""
    identifier = request.query_params.get("download", "").strip()
    if not identifier:
        return None
    try:
        backup.find_backup_path(identifier)
    except backup.BackupError:
        return None
    return f"/backup/{identifier}/download"


@app.get("/backup", response_class=HTMLResponse)
def backup_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = backup_context()
    context.update({
        "error": None,
        "preview": None,
        "preview_source": None,
        "imported": request.query_params.get("imported"),
        "auto_download_url": _auto_download_url(request),
    })
    return render(request, "backup.html", **context)


@app.get("/backup/restore/status", response_class=HTMLResponse)
def backup_restore_status_partial(request: Request, _: sqlite3.Row = Depends(current_admin)):
    """Polled by backup.html while a restore is in flight (see the inline
    script there). Deliberately gated by current_admin like every other
    page here: if the restore being polled replaced the session-signing
    secret or the sessions table itself, this naturally 303s to /login the
    same way any other page would -- the poller detects that redirect and
    is what actually sends the browser there on purpose, instead of a
    fetch() silently following it and handing back /login's HTML as if it
    were this fragment."""
    return render(request, "backup_last_restore_card.html", last_restore=backup.last_restore())


@app.post("/backup/create")
async def backup_create_route(request: Request, _: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    try:
        components = backup_component_flags(form)
        if components.get("private_keys") and str(form.get("confirm_private_keys", "")).strip().lower() not in {"1", "true", "on", "yes"}:
            raise backup.BackupError("including private keys requires checking the explicit confirmation box")
        password = str(form.get("password", "")).strip() or None
        backup.request_backup("create", {"components": components}, password)
        backup_create_apply()
    except Exception as exc:
        return backup_error(request, str(exc))
    # Auto-download only fires for a backup that genuinely finished
    # ("deployed"); a failed create() (caught above only if request_backup/
    # backup_create_apply themselves raised -- a create that ran but ended
    # status='failed' does not) must not trigger a download of nothing/a
    # partial file.
    created = backup.last_backup()
    if created and created.get("status") == "deployed" and created.get("id") is not None:
        return redirect(f"/backup?download={created['id']}")
    return redirect("/backup")


@app.post("/backup/import")
async def backup_import_route(request: Request, csrf: str = Form(...), upload: UploadFile = File(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    # Streamed in bounded chunks straight to a restrictive-permission
    # staging file -- never buffered whole in this process's memory,
    # regardless of archive size. See backup.begin_streamed_upload's
    # docstring. A native backup upload is governed by its own size policy
    # (backup.max_upload_bytes()), separate from app/importer.py's 10 MiB
    # spreadsheet/text-import cap: Analytics History legitimately makes a
    # long-running server's backup large, and that must never be rejected
    # at the import-page's limit.
    content_length_hint: int | None = None
    raw_length = request.headers.get("content-length")
    if raw_length and raw_length.isdigit():
        content_length_hint = int(raw_length)
    tmp_path: Path | None = None
    try:
        tmp_path, max_bytes, safe_name = backup.begin_streamed_upload(upload.filename or "uploaded-backup.tar.gz", content_length_hint)
        total = 0
        since_last_space_check = 0
        with tmp_path.open("wb") as fh:
            while True:
                chunk = await upload.read(backup.UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                since_last_space_check += len(chunk)
                if total > max_bytes:
                    raise backup.BackupError(f"uploaded backup exceeds the {max_bytes // (1024 * 1024)} MiB backup upload limit")
                fh.write(chunk)
                # Re-check free space periodically (not just up front) for
                # uploads large enough, or without a Content-Length hint
                # accurate enough, that the disk could fill up mid-stream.
                if since_last_space_check >= backup.FREE_SPACE_RECHECK_INTERVAL_BYTES:
                    since_last_space_check = 0
                    backup.check_upload_free_space(tmp_path.parent, remaining_hint=max_bytes - total)
        if total == 0:
            raise backup.BackupError("uploaded file is empty")
        path = backup.finalize_streamed_upload(tmp_path, safe_name)
        tmp_path = None
    except Exception as exc:
        if tmp_path is not None:
            backup.abort_streamed_upload(tmp_path)
        return backup_error(request, str(exc))
    return redirect(f"/backup?imported={path.name}")


@app.post("/backup/preview")
async def backup_preview_route(request: Request, _: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    source = str(form.get("source", "")).strip()
    password = str(form.get("password", "")).strip() or None
    try:
        if not source:
            raise backup.BackupError("choose a backup to preview")
        backup.request_backup("preview", {"path": source}, password)
        backup_preview_apply()
        result = backup.latest_request_result("preview")
        if not result or result.get("status") != "done":
            raise backup.BackupError("preview did not complete; check /system logs")
        payload = json.loads(result["result_json"] or "{}")
        if "error" in payload:
            raise backup.BackupError(payload["error"])
    except Exception as exc:
        return backup_error(request, str(exc))
    context = backup_context()
    context.update({"error": None, "preview": payload, "preview_source": source, "imported": None})
    return render(request, "backup.html", **context)


@app.post("/backup/restore")
async def backup_restore_route(request: Request, _: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    try:
        source = str(form.get("source", "")).strip()
        if not source:
            raise backup.BackupError("choose a backup to restore")
        components = backup_component_flags(form)
        password = str(form.get("password", "")).strip() or None
        backup.request_backup("restore", {"path": source, "components": components}, password)
        # backup_restore_apply() now only *starts* the independent
        # alderpointdns-backup-restore.service runner (systemctl start
        # --no-block) and returns immediately -- it does not wait for the
        # restore to finish, exactly like software_updates_install_route()
        # never waits for an install to finish. A restore that touches
        # app_config restarts alderpointdns.service (this request's own
        # process) partway through, so this request must never block on
        # (or synchronously report) the restore's outcome; only the exit
        # status of *starting* the runner is checked here. The actual
        # outcome is durable state in restore_history that the "Last
        # Restore" card (backup_context()) reads on the next page load.
        code, output = backup_restore_apply()
        if code != 0:
            raise backup.BackupError(f"failed to start the restore runner: {output}")
    except Exception as exc:
        return backup_error(request, str(exc))
    # `restore_started=1` tells backup.html to start polling the Last
    # Restore card immediately, even though the worker (a separate,
    # just-started systemd unit) may not have inserted its restore_history
    # row yet -- without it, a page load that lands in that brief gap would
    # see no in-progress restore at all and never start polling.
    return redirect("/backup?restore_started=1")


@app.get("/backup/{identifier}/download")
def backup_download_route(identifier: str, _: sqlite3.Row = Depends(current_admin)):
    try:
        path = backup.find_backup_path(identifier)
    except backup.BackupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(str(path), filename=path.name, media_type="application/octet-stream")


@app.post("/backup/{identifier}/delete")
def backup_delete_route(request: Request, identifier: str, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        backup.delete_backup(identifier)
    except Exception as exc:
        return backup_error(request, str(exc))
    return redirect("/backup")


@app.post("/backup/schedule")
def backup_schedule_route(
    request: Request,
    csrf: str = Form(...),
    schedule_enabled: str = Form("0"),
    schedule_interval_hours: int = Form(24),
    retention_count: int = Form(7),
    max_upload_mib: int | None = Form(None),
    max_extracted_mib: int | None = Form(None),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        values: dict[str, Any] = {
            "schedule_enabled": schedule_enabled,
            "schedule_interval_hours": schedule_interval_hours,
            "retention_count": retention_count,
        }
        if max_upload_mib is not None:
            values["max_upload_mib"] = max_upload_mib
        if max_extracted_mib is not None:
            values["max_extracted_mib"] = max_extracted_mib
        backup.update_settings(values)
        backup_schedule_apply()
    except Exception as exc:
        return backup_error(request, str(exc))
    return redirect("/backup")


def replication_primary_init_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "replication-primary-init"])


def replication_context() -> dict[str, Any]:
    cfg = replication.settings()
    context: dict[str, Any] = {"cfg": cfg}
    if cfg.get("role") == "primary":
        context["enrollments"] = replication.list_enrollments()
        context["replicas"] = replication.list_replicas()
        context["latest_generation"] = replication.latest_generation()
        context["listener_running"] = replication.ensure_primary_listener_running()
    elif cfg.get("role") == "replica":
        context["sync_history"] = replication.sync_history()
    return context


def replication_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    context = replication_context()
    context.update({"error": message})
    return render(request, "replication.html", **context, status_code=status_code)


@app.get("/replication", response_class=HTMLResponse)
def replication_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = replication_context()
    context.update({"error": None})
    return render(request, "replication.html", **context)


@app.post("/replication/role")
def replication_role_post(request: Request, csrf: str = Form(...), role: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        previous = replication.settings().get("role")
        replication.set_role(role)
        if role == "primary" and previous != "primary":
            replication.stop_replica_poller()
            replication_primary_init_apply()
            replication.ensure_primary_listener_running()
        elif role == "replica" and previous != "replica":
            replication.stop_primary_listener()
            replication.ensure_replica_poller_running()
        elif role == "standalone":
            replication.stop_primary_listener()
            replication.stop_replica_poller()
    except Exception as exc:
        return replication_error(request, str(exc))
    return redirect("/replication")


@app.post("/replication/token")
def replication_token_post(request: Request, csrf: str = Form(...), node_name: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        replication.ensure_primary_listener_running()
        token = replication.generate_enrollment_token(node_name)
    except Exception as exc:
        return replication_error(request, str(exc))
    context = replication_context()
    context.update({"error": None, "issued_token": token})
    return render(request, "replication.html", **context)


@app.post("/replication/enrollment/{enrollment_id}/revoke")
def replication_enrollment_revoke(request: Request, enrollment_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        replication.revoke_enrollment(enrollment_id)
    except Exception as exc:
        return replication_error(request, str(exc))
    return redirect("/replication")


@app.post("/replication/replica/{replica_id}/status")
def replication_replica_status(request: Request, replica_id: int, csrf: str = Form(...), status: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        replication.set_replica_status(replica_id, status)
    except Exception as exc:
        return replication_error(request, str(exc))
    return redirect("/replication")


@app.post("/replication/connect")
def replication_connect_post(
    request: Request,
    csrf: str = Form(...),
    primary_host: str = Form(...),
    primary_port: int = Form(...),
    token: str = Form(...),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        enrolled = replication.enroll_with_primary(primary_host, primary_port, token)
        replication.store_enrollment_material(f"{primary_host}:{primary_port}", enrolled)
        replication.stop_primary_listener()
        replication.ensure_replica_poller_running()
    except Exception as exc:
        return replication_error(request, str(exc))
    return redirect("/replication")


@app.post("/replication/sync-now")
def replication_sync_now_post(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        replication.trigger_sync_now()
    except Exception as exc:
        return replication_error(request, str(exc))
    return redirect("/replication")


@app.post("/replication/drift-check")
def replication_drift_check_post(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        replication.trigger_drift_check()
    except Exception as exc:
        return replication_error(request, str(exc))
    return redirect("/replication")


@app.post("/replication/pause")
def replication_pause_post(request: Request, csrf: str = Form(...), paused: str = Form("0"), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        replication.update_settings({"paused": "1" if paused == "1" else "0"})
    except Exception as exc:
        return replication_error(request, str(exc))
    return redirect("/replication")


@app.post("/replication/settings")
def replication_settings_post(
    request: Request,
    csrf: str = Form(...),
    poll_interval_seconds: int = Form(60),
    listen_host: str = Form("0.0.0.0"),
    listen_port: int = Form(8843),
    include_encryption_settings: str = Form("0"),
    include_certificates: str = Form("0"),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        replication.update_settings(
            {
                "poll_interval_seconds": poll_interval_seconds,
                "listen_host": listen_host,
                "listen_port": listen_port,
                "include_encryption_settings": include_encryption_settings,
                "include_certificates": include_certificates,
            }
        )
    except Exception as exc:
        return replication_error(request, str(exc))
    return redirect("/replication")


def fetch_service_log_entries(unit: str) -> tuple[bool, list[dict[str, Any]] | str]:
    if unit not in service_logs.ALLOWED_UNITS:
        return False, "this service is not on the supported log allowlist"
    # Deliberately keep stdout and stderr separate here (unlike the shared
    # run() helper, which merges them for admin actions where any output is
    # useful to surface). The "logs" subcommand's stdout must be strict JSON;
    # sudo itself can print unrelated warnings to stderr (e.g. hostname
    # resolution notices) that would otherwise corrupt the parse.
    proc = subprocess.run(
        ["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "logs", unit],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return False, "log access is not available right now; the log-access helper did not run successfully"
    try:
        entries = json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError):
        return False, "log data could not be read"
    if not isinstance(entries, list):
        return False, "log data could not be read"
    return True, entries


def system_logs_context(request: Request) -> dict[str, Any]:
    service = request.query_params.get("service", "alderpointdns")
    if service not in service_logs.ALLOWED_UNITS:
        service = "alderpointdns"
    severity = request.query_params.get("severity", "all")
    if severity not in ("all", *service_logs.SEVERITY_LEVELS.keys()):
        severity = "all"
    try:
        lines = int(request.query_params.get("lines", "100"))
    except ValueError:
        lines = 100
    lines = max(10, min(service_logs.MAX_LINES_FETCHED, lines))
    ok, result = fetch_service_log_entries(service)
    if not ok:
        return {"available": False, "error": result, "service": service, "severity": severity, "lines": lines, "entries": []}
    entries = service_logs.filter_entries(result, severity, lines)
    return {"available": True, "error": None, "service": service, "severity": severity, "lines": lines, "entries": entries}


@app.get("/system", response_class=HTMLResponse)
def system_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    named = service_state("named")
    dnsdist = service_state("dnsdist")
    alderpointdns = service_state("alderpointdns")
    return render(
        request,
        "system.html",
        named=named,
        dnsdist=dnsdist,
        alderpointdns=alderpointdns,
        health=system_health(named, dnsdist, alderpointdns),
        logs=system_logs_context(request),
        compiler=compiler_status(),
    )


@app.get("/system/logs", response_class=HTMLResponse)
def system_logs_partial(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "system_logs_results.html", logs=system_logs_context(request))


def administration_context(admin: sqlite3.Row, session: dict[str, Any]) -> dict[str, Any]:
    with db() as conn:
        session_rows = conn.execute(
            "SELECT id, created_at, last_seen_at, ip, user_agent FROM sessions WHERE admin_id=? ORDER BY last_seen_at DESC",
            (admin["id"],),
        ).fetchall()
        audit_rows = conn.execute(
            "SELECT at, action, success, ip, detail FROM admin_audit_log WHERE admin_id=? ORDER BY id DESC LIMIT 25",
            (admin["id"],),
        ).fetchall()
    return {
        "admin_username": admin["username"],
        "sessions": [
            {
                "created_at": row["created_at"],
                "last_seen_at": row["last_seen_at"],
                "ip": row["ip"] or "unknown",
                "user_agent": row["user_agent"] or "unknown",
                "is_current": row["id"] == session.get("id"),
            }
            for row in session_rows
        ],
        "audit_entries": audit_rows,
    }


def administration_error(request: Request, admin: sqlite3.Row, session: dict[str, Any], message: str, status_code: int = 400) -> HTMLResponse:
    context = administration_context(admin, session)
    context["error"] = message
    return render(request, "administration.html", **context, status_code=status_code)


@app.get("/system/administration", response_class=HTMLResponse)
def administration_page(request: Request, admin: sqlite3.Row = Depends(current_admin)):
    session = signed_session(request)
    context = administration_context(admin, session)
    context["error"] = None
    return render(request, "administration.html", **context)


@app.post("/system/administration/password")
def administration_change_password(
    request: Request,
    csrf: str = Form(...),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_new_password: str = Form(...),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    session = signed_session(request)
    ip = request.client.host if request.client else None
    if not auth.verify_password(admin["password_hash"], current_password):
        with db() as conn:
            audit_log(conn, admin["id"], admin["username"], "password_change", False, ip, "current password incorrect")
        return administration_error(request, admin, session, "Current password is incorrect.")
    length_error = auth.validate_password_length(new_password)
    if length_error:
        with db() as conn:
            audit_log(conn, admin["id"], admin["username"], "password_change", False, ip, "new password too short")
        return administration_error(request, admin, session, length_error)
    if new_password != confirm_new_password:
        with db() as conn:
            audit_log(conn, admin["id"], admin["username"], "password_change", False, ip, "new passwords did not match")
        return administration_error(request, admin, session, "New passwords do not match.")
    with db() as conn:
        conn.execute("UPDATE admins SET password_hash=? WHERE id=?", (auth.hash_password(new_password), admin["id"]))
        revoked = conn.execute("DELETE FROM sessions WHERE admin_id=? AND id<>?", (admin["id"], session.get("id"))).rowcount
        audit_log(conn, admin["id"], admin["username"], "password_change", True, ip, f"{revoked} other session(s) revoked")
    return redirect("/system/administration")


@app.post("/system/administration/revoke-sessions")
def administration_revoke_sessions(request: Request, csrf: str = Form(...), admin: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    session = signed_session(request)
    ip = request.client.host if request.client else None
    revoked = revoke_other_sessions(admin["id"], session.get("id"))
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "sessions_revoked", True, ip, f"{revoked} other session(s) revoked")
    return redirect("/system/administration")


def network_apply_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "network-apply"])


def network_confirm_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "network-confirm"])


def network_context() -> dict[str, Any]:
    current = network_config.read_current_config()
    pending = network_config.read_rollback_state()
    return {
        "current": current,
        "pending": pending,
    }


@app.get("/system/network", response_class=HTMLResponse)
def network_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = network_context()
    context.update({"error": None})
    return render(request, "system_network.html", **context)


@app.post("/system/network/apply")
async def network_apply_route(request: Request, _: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    try:
        interface = str(form.get("interface", "")).strip()
        ipv4_mode = str(form.get("ipv4_mode", "unchanged")).strip()
        ipv6_mode = str(form.get("ipv6_mode", "unchanged")).strip()
        payload = {
            "interface": interface,
            "ipv4_mode": ipv4_mode,
            "ipv4_address": str(form.get("ipv4_address", "")).strip() or None,
            "ipv4_prefix": int(form["ipv4_prefix"]) if str(form.get("ipv4_prefix", "")).strip() else None,
            "ipv4_gateway": str(form.get("ipv4_gateway", "")).strip() or None,
            "ipv6_mode": ipv6_mode,
            "ipv6_address": str(form.get("ipv6_address", "")).strip() or None,
            "ipv6_prefix": int(form["ipv6_prefix"]) if str(form.get("ipv6_prefix", "")).strip() else None,
            "ipv6_gateway": str(form.get("ipv6_gateway", "")).strip() or None,
        }
        # Defense-in-depth: the same validation the privileged helper runs,
        # so an obviously-bad submission gets a friendly error immediately
        # rather than a round trip through sudo. The privileged side (which
        # is the one that actually matters for security) always re-validates
        # independently before touching anything.
        network_config.validate_proposed(
            payload["interface"], payload["ipv4_mode"], payload["ipv4_address"], payload["ipv4_prefix"], payload["ipv4_gateway"],
            payload["ipv6_mode"], payload["ipv6_address"], payload["ipv6_prefix"], payload["ipv6_gateway"],
        )
        network_config.request_change(payload)
        network_apply_apply()
        result = network_config.latest_request_result("apply")
        if not result or result.get("status") != "done":
            raise network_config.NetworkConfigError("network configuration change did not complete; check the privileged helper's logs")
        payload_result = json.loads(result["result_json"] or "{}")
        if "error" in payload_result:
            raise network_config.NetworkConfigError(payload_result["error"])
    except Exception as exc:
        context = network_context()
        context.update({"error": str(exc)})
        return render(request, "system_network.html", status_code=400, **context)
    return redirect("/system/network")


@app.post("/system/network/confirm")
async def network_confirm_route(request: Request, _: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    try:
        network_config.request_confirm()
        network_confirm_apply()
        result = network_config.latest_request_result("confirm")
        if not result or result.get("status") != "done":
            raise network_config.NetworkConfigError("confirmation did not complete; check the privileged helper's logs")
    except Exception as exc:
        context = network_context()
        context.update({"error": str(exc)})
        return render(request, "system_network.html", status_code=400, **context)
    return redirect("/system/network")


# ---------------------------------------------------------------------------
# Software Updates
# ---------------------------------------------------------------------------

def software_updates_check_apply(force: bool) -> tuple[int, str]:
    args = ["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "update-check"]
    if force:
        args.append("--force")
    return run(args)


def software_updates_check_schedule_apply() -> tuple[int, str]:
    # Mirrors filter_schedule_apply() exactly: redeploys the automatic-check
    # timer drop-in from whatever was just saved to
    # auto_check_enabled/check_interval_hours. Safe to call directly via
    # sudo from the request handler (like update-check itself) -- this
    # only ever writes a timer drop-in and calls systemctl
    # enable/disable/daemon-reload, never restarts alderpointdns.service.
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "update-check-schedule-deploy"])


def software_updates_check_schedule_apply_or_raise() -> None:
    code, out = software_updates_check_schedule_apply()
    if code != 0:
        raise software_updates.SoftwareUpdateError(out.strip() or "automatic-check schedule deployment failed")


def software_updates_start_install_runner() -> tuple[int, str]:
    # Deliberately NOT `sudo alderpointdns_compiler.py update-run` directly:
    # installing restarts alderpointdns.service (this process's own
    # service) partway through, which would kill a direct sudo child of
    # this request. `systemctl start` hands the work to an independent
    # unit (its own cgroup, owned by PID 1) that survives that restart --
    # see app/software_updates.py's module docstring and
    # packaging/alderpointdns-software-update.service.
    #
    # --no-block is required, not optional: `systemctl start` on a
    # Type=oneshot unit is synchronous by default (it waits for the job to
    # finish before returning), which would defeat the entire point of an
    # independent runner -- this HTTP request (and the sudo child waiting
    # on it) would itself be killed when alderpointdns.service restarts
    # partway through the very install this call kicked off, exactly the
    # failure mode this design exists to avoid. Confirmed against a real
    # disposable-VM install (see the completion report): without
    # --no-block, a same-process restart during install left this call
    # blocked until the unit exited, reporting "control process exited
    # with error" back to the browser instead of returning immediately.
    return run(["sudo", "systemctl", "start", "--no-block", "alderpointdns-software-update.service"])


def software_updates_context(request: Request) -> dict[str, Any]:
    status = software_updates.update_status()
    context = dict(status)
    context["csrf"] = signed_session(request)["csrf"]
    context["check_interval_choices"] = software_updates.CHECK_INTERVAL_CHOICES
    return context


@app.get("/system/administration/software-updates", response_class=HTMLResponse)
def software_updates_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = software_updates_context(request)
    context["error"] = None
    return render(request, "system_software_updates.html", **context)


@app.get("/system/administration/software-updates/job", response_class=HTMLResponse)
def software_updates_job_partial(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = software_updates_context(request)
    return render(request, "system_software_updates_job.html", **context)


@app.get("/system/administration/software-updates/job/status", response_class=JSONResponse)
def software_updates_job_status(_: sqlite3.Row = Depends(current_admin)):
    return JSONResponse(software_updates.job_status_payload())


def software_updates_error(request: Request, message: str) -> HTMLResponse:
    context = software_updates_context(request)
    context["error"] = message
    return render(request, "system_software_updates.html", status_code=400, **context)


@app.post("/system/administration/software-updates/settings")
async def software_updates_settings_route(request: Request, admin: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    ip = request.client.host if request.client else None
    try:
        software_updates.update_settings(
            {
                "auto_check_enabled": form.get("auto_check_enabled", "0"),
                "channel": str(form.get("channel", "stable")),
                "check_interval_hours": form.get("check_interval_hours", software_updates.DEFAULT_SETTINGS["check_interval_hours"]),
            }
        )
        # Redeploys the automatic-check timer drop-in from what was just
        # saved -- without this, changing the interval or toggling
        # automatic checking off would update the database but never
        # actually change the running schedule. See
        # software_updates.deploy_check_schedule().
        software_updates_check_schedule_apply_or_raise()
    except software_updates.SoftwareUpdateError as exc:
        with db() as conn:
            audit_log(conn, admin["id"], admin["username"], "software_update_settings_change", False, ip, str(exc))
        return software_updates_error(request, str(exc))
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "software_update_settings_change", True, ip, "")
    return redirect("/system/administration/software-updates")


@app.post("/system/administration/software-updates/check")
async def software_updates_check_route(request: Request, admin: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    ip = request.client.host if request.client else None
    code, output = software_updates_check_apply(force=True)
    with db() as conn:
        audit_log(conn, admin["id"], admin["username"], "software_update_check", code == 0, ip, output[-500:])
    if code != 0:
        return software_updates_error(request, f"update check failed: {output}")
    return redirect("/system/administration/software-updates")


@app.post("/system/administration/software-updates/install")
async def software_updates_install_route(request: Request, admin: sqlite3.Row = Depends(current_admin)):
    form = await request.form()
    check_csrf(request, str(form.get("csrf", "")))
    ip = request.client.host if request.client else None
    try:
        status = software_updates.update_status()
        release = status.get("latest_release")
        if not release:
            raise software_updates.SoftwareUpdateError("no update is currently available -- check for updates first")
        if not status["version_status"].get("dpkg_managed"):
            raise software_updates.SoftwareUpdateError("Software Updates: unmanaged source installation -- cannot install a package here")
        if status["version_status"].get("mismatch"):
            raise software_updates.SoftwareUpdateError("installed VERSION/dpkg version drift detected -- resolve this before installing an update")
        existing_job = status.get("job")
        if existing_job and existing_job.get("phase") not in ("completed", "failed"):
            raise software_updates.SoftwareUpdateError("an update is already in progress")
        job_id = software_updates.create_github_job(release, requested_by=admin["username"])
        code, output = software_updates_start_install_runner()
        with db() as conn:
            audit_log(conn, admin["id"], admin["username"], "software_update_install", code == 0, ip, f"job_id={job_id} release={release.get('tag_name')}")
        if code != 0:
            raise software_updates.SoftwareUpdateError(f"failed to start the update runner: {output}")
    except software_updates.SoftwareUpdateError as exc:
        with db() as conn:
            audit_log(conn, admin["id"], admin["username"], "software_update_install", False, ip, str(exc))
        return software_updates_error(request, str(exc))
    return redirect("/system/administration/software-updates")


@app.post("/system/administration/software-updates/upload")
async def software_updates_upload_route(
    request: Request,
    csrf: str = Form(...),
    expected_sha256: str = Form(""),
    upload: UploadFile = File(...),
    admin: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else None
    tmp_path: Path | None = None
    try:
        status = software_updates.update_status()
        if not status["version_status"].get("dpkg_managed"):
            raise software_updates.SoftwareUpdateError("Software Updates: unmanaged source installation -- cannot install a package here")
        existing_job = status.get("job")
        if existing_job and existing_job.get("phase") not in ("completed", "failed"):
            raise software_updates.SoftwareUpdateError("an update is already in progress")
        # Streamed in bounded chunks to a restrictive-permission staging
        # file -- never buffered whole in this process's memory,
        # regardless of package size. Mirrors app/backup.py's
        # begin_streamed_upload/finalize_streamed_upload pattern.
        tmp_path, max_bytes = software_updates.begin_manual_upload(upload.filename or "upload.deb")
        total = 0
        with tmp_path.open("wb") as fh:
            while True:
                chunk = await upload.read(software_updates.UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise software_updates.SoftwareUpdateError(f"uploaded package exceeds the {max_bytes // (1024 * 1024)} MiB limit")
                fh.write(chunk)
        if total == 0:
            raise software_updates.SoftwareUpdateError("uploaded file is empty")
        uploaded_path = software_updates.finalize_manual_upload(tmp_path, upload.filename or "upload.deb")
        tmp_path = None
        job_id = software_updates.create_manual_job(uploaded_path, expected_sha256.strip() or None, requested_by=admin["username"])
        code, output = software_updates_start_install_runner()
        with db() as conn:
            audit_log(conn, admin["id"], admin["username"], "software_update_manual_upload", code == 0, ip, f"job_id={job_id} filename={uploaded_path.name}")
        if code != 0:
            raise software_updates.SoftwareUpdateError(f"failed to start the update runner: {output}")
    except Exception as exc:
        if tmp_path is not None:
            software_updates.abort_manual_upload(tmp_path)
        with db() as conn:
            audit_log(conn, admin["id"], admin["username"], "software_update_manual_upload", False, ip, str(exc))
        return software_updates_error(request, str(exc))
    return redirect("/system/administration/software-updates")


def notifications_context() -> dict[str, Any]:
    return {
        "providers": notifications.list_providers(),
        "subscriptions": notifications.list_subscriptions(),
        "event_categories": [
            {"key": key, "label": info["label"], "wired": info["wired"], "default_severity": info["default_severity"]}
            for key, info in notifications.EVENT_CATEGORIES.items()
        ],
        "severities": notifications.SEVERITIES,
        "webhook_presets": notifications.WEBHOOK_PRESETS,
        "notification_settings": notifications.settings(),
        "delivery_history": notifications.history(limit=50),
    }


def notifications_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    context = notifications_context()
    context["error"] = message
    return render(request, "notifications.html", **context, status_code=status_code)


@app.get("/system/notifications", response_class=HTMLResponse)
def notifications_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = notifications_context()
    context["error"] = None
    return render(request, "notifications.html", **context)


@app.post("/system/notifications/providers/smtp")
def notifications_add_smtp_provider(
    request: Request,
    csrf: str = Form(...),
    name: str = Form(...),
    smtp_host: str = Form(...),
    smtp_port: int = Form(587),
    smtp_use_tls: str = Form("0"),
    smtp_from: str = Form(...),
    smtp_to: str = Form(...),
    smtp_username: str = Form(""),
    secret: str = Form(""),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    config = {"host": smtp_host, "port": smtp_port, "use_tls": smtp_use_tls == "1", "from_addr": smtp_from, "to_addrs": smtp_to, "username": smtp_username}
    try:
        notifications.add_provider("smtp", name, config, secret)
    except Exception as exc:
        return notifications_error(request, str(exc))
    return redirect("/system/notifications")


@app.post("/system/notifications/providers/webhook")
def notifications_add_webhook_provider(
    request: Request,
    csrf: str = Form(...),
    name: str = Form(...),
    webhook_preset: str = Form("generic"),
    secret: str = Form(...),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        notifications.add_provider("webhook", name, {"preset": webhook_preset}, secret)
    except Exception as exc:
        return notifications_error(request, str(exc))
    return redirect("/system/notifications")


@app.post("/system/notifications/providers/{provider_id}/edit")
def notifications_edit_provider(
    request: Request,
    provider_id: int = PathParam(..., gt=0),
    csrf: str = Form(...),
    name: str = Form(...),
    secret: str = Form(""),
    enabled: str = Form("0"),
    smtp_host: str = Form(""),
    smtp_port: int = Form(587),
    smtp_use_tls: str = Form("0"),
    smtp_from: str = Form(""),
    smtp_to: str = Form(""),
    smtp_username: str = Form(""),
    webhook_preset: str = Form("generic"),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        row = notifications.get_provider_row(provider_id)
        if not row:
            raise notifications.NotificationError("notification provider not found")
        if row["kind"] == "smtp":
            config = {"host": smtp_host, "port": smtp_port, "use_tls": smtp_use_tls == "1", "from_addr": smtp_from, "to_addrs": smtp_to, "username": smtp_username}
        else:
            config = {"preset": webhook_preset}
        notifications.update_provider(provider_id, name=name, config=config, secret=secret, enabled=enabled == "1")
    except Exception as exc:
        return notifications_error(request, str(exc))
    return redirect("/system/notifications")


@app.post("/system/notifications/providers/{provider_id}/toggle")
def notifications_toggle_provider(request: Request, provider_id: int = PathParam(..., gt=0), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    notifications.toggle_provider(provider_id)
    return redirect("/system/notifications")


@app.post("/system/notifications/providers/{provider_id}/delete")
def notifications_delete_provider(request: Request, provider_id: int = PathParam(..., gt=0), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    notifications.delete_provider(provider_id)
    return redirect("/system/notifications")


@app.post("/system/notifications/providers/{provider_id}/test")
def notifications_test_provider(request: Request, provider_id: int = PathParam(..., gt=0), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        ok, error = notifications.send_test(provider_id)
    except Exception as exc:
        return notifications_error(request, str(exc))
    if not ok:
        return notifications_error(request, f"Test notification failed: {error}")
    return redirect("/system/notifications")


@app.post("/system/notifications/providers/{provider_id}/clear-failure")
def notifications_clear_failure(request: Request, provider_id: int = PathParam(..., gt=0), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    notifications.clear_provider_failure(provider_id)
    return redirect("/system/notifications")


@app.post("/system/notifications/subscriptions")
def notifications_add_subscription(
    request: Request,
    csrf: str = Form(...),
    provider_id: int = Form(...),
    event_category: str = Form(...),
    min_severity: str = Form("warning"),
    enabled: str = Form("1"),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        notifications.set_subscription(provider_id, event_category, min_severity, enabled == "1")
    except Exception as exc:
        return notifications_error(request, str(exc))
    return redirect("/system/notifications")


@app.post("/system/notifications/subscriptions/{subscription_id}/delete")
def notifications_delete_subscription(request: Request, subscription_id: int = PathParam(..., gt=0), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    notifications.delete_subscription(subscription_id)
    return redirect("/system/notifications")


@app.post("/system/notifications/settings")
def notifications_settings_post(request: Request, csrf: str = Form(...), cooldown_minutes: int = Form(30), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        notifications.update_settings({"cooldown_minutes": cooldown_minutes})
    except Exception as exc:
        return notifications_error(request, str(exc))
    return redirect("/system/notifications")


def query_log_context(request: Request) -> dict[str, Any]:
    limit = min(500, max(10, int(request.query_params.get("limit", "50"))))
    page = max(1, int(request.query_params.get("page", "1")))
    filters = {
        "search": request.query_params.get("search", ""),
        "client": request.query_params.get("client", ""),
        "domain": request.query_params.get("domain", ""),
        "qtype": request.query_params.get("qtype", ""),
        "protocol": request.query_params.get("protocol", ""),
        "blocked": request.query_params.get("blocked", ""),
        "rcode": request.query_params.get("rcode", ""),
    }
    return {"log": analytics.query_log(filters, page, limit)}


@app.get("/query-log", response_class=HTMLResponse)
def query_log(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "query_log.html", **query_log_context(request))


@app.get("/query-log/partial", response_class=HTMLResponse)
def query_log_partial(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "query_log_results.html", **query_log_context(request))


@app.get("/statistics-settings", response_class=HTMLResponse)
def statistics_settings(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "statistics_settings.html", settings=analytics.settings(), db_size=analytics.db_size())


@app.post("/statistics-settings")
def statistics_settings_post(
    request: Request,
    csrf: str = Form(...),
    analytics_enabled: str = Form("0"),
    detailed_query_logging_enabled: str = Form("0"),
    privacy_mode: str = Form("full"),
    detailed_retention_days: int = Form(7),
    aggregate_retention_days: int = Form(90),
    db_size_limit_bytes: int = Form(268435456),
    client_anonymization: str = Form("truncate"),
    collection_interval: int = Form(15),
    recent_query_limit: int = Form(100),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    analytics.update_settings(
        {
            "analytics_enabled": "1" if analytics_enabled == "1" else "0",
            "detailed_query_logging_enabled": "1" if detailed_query_logging_enabled == "1" else "0",
            "privacy_mode": privacy_mode,
            "detailed_retention_days": max(0, detailed_retention_days),
            "aggregate_retention_days": max(1, aggregate_retention_days),
            "db_size_limit_bytes": max(1048576, db_size_limit_bytes),
            "client_anonymization": client_anonymization,
            "collection_interval": max(5, collection_interval),
            "recent_query_limit": max(10, recent_query_limit),
        }
    )
    return redirect("/statistics-settings")


@app.post("/statistics-settings/clear")
def statistics_clear(request: Request, confirm: str = Form(""), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    if confirm != "CLEAR":
        raise HTTPException(status_code=400, detail="confirmation must be CLEAR")
    analytics.clear_statistics()
    return redirect("/statistics-settings")


@app.get("/statistics-settings/export")
def statistics_export(_: sqlite3.Row = Depends(current_admin)):
    return PlainTextResponse(analytics.export_statistics(), media_type="application/json")
