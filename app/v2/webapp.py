"""Alderpoint DNS V2 management/API service.

A real, installed-path-only FastAPI application exposing the already-real
V2 backend (policy store/compiler/runtime, analytics, secrets,
notifications, migration) over native HTTPS, plus the packaged V2
management UI served from the same origin.

Service boundary (§2): every route here goes through a real service/
repository layer (policy_store, policy_service, analytics_service,
notification_store, secret_store, migration_convert, runtime_compile) --
no raw SQL in a route handler, no direct filesystem hacks. Nothing here is
in the DNS packet hot path: every mutation that affects DNS answers goes
through runtime_compile.recompile_and_promote(), which stages + validates
against the REAL installed dnsdist binary before ever touching the live
compiled-runtime path, and control.db is only committed once that
succeeds (see _mutate_and_promote below) -- a failed compile leaves BOTH
control.db and the live runtime exactly as they were.

All paths below default to the real installed locations
(/etc/alderpointdns-v2, /var/lib/alderpointdns-v2) but can be overridden
via the same ALDERPOINTDNS_V2_*_ROOT environment variables
scripts/v2/alderpointdns_v2_ctl.py already uses, for testing.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel, Field

from app import dnsdist_upgrade
from app.db_retry import DatabaseBusyError, is_lock_error, retry_on_locked
from app.v2 import analytics_deps
from app.v2 import control_db
from app.v2 import dnscrypt_provisioning
from app.v2 import migration_convert
from app.v2 import node_identity
from app.v2 import notification_store
from app.v2 import observed_clients
from app.v2 import policy_service
from app.v2 import policy_store as store
from app.v2 import replication_v2
from app.v2 import runtime_compile
from app.v2 import tls_cert
from app.v2.analytics_service import AnalyticsService
from app.v2.auth_concurrency import HashConcurrencyLimiter, TooManyConcurrentHashesError
from app.v2.auth_hash import hash_password, verify_and_maybe_rehash
from app.v2.blocking_response import InvalidBlockingResponseError
from app.v2.dns_name_validate import InvalidDnsNameError
from app.v2 import config as v2config
from app.v2.dnsdist_gen import DnsdistGenError
from app.v2.network_match import InvalidNetworkError
from app.v2.policy_model import InvalidPolicyError, PolicyLayer
from app.v2.policy_store import PolicyStoreError
from app.v2.runtime_compile import RuntimeCompileError
from app.v2.secret_store import SecretStore, SecretStoreMissingError

# --- installed layout (mirrors scripts/v2/alderpointdns_v2_ctl.py) --------

APP_ROOT = Path(os.environ.get("ALDERPOINTDNS_V2_APP_ROOT", "/opt/alderpointdns-v2"))
CONFIG_DIR = Path(os.environ.get("ALDERPOINTDNS_V2_CONFIG_ROOT", "/etc/alderpointdns-v2"))
STATE_DIR = Path(os.environ.get("ALDERPOINTDNS_V2_STATE_ROOT", "/var/lib/alderpointdns-v2"))
MODULE_DIR = Path(__file__).resolve().parent
UI_DIR = MODULE_DIR / "ui"

CONFIG_FILE = CONFIG_DIR / "alderpointdns.yaml"
CONTROL_DB = STATE_DIR / "control.db"
SECRETS_DIR = STATE_DIR / "secrets"
ANALYTICS_PARQUET_DIR = STATE_DIR / "analytics" / "queries"
ANALYTICS_AGGREGATES_DB = STATE_DIR / "analytics" / "aggregates.db"
STAGING_DIR = STATE_DIR / "staging"
COMPILED_DNSDIST_CONF = STATE_DIR / "compiled" / "dnsdist.conf"
CERTS_DIR = STATE_DIR / "certs"
ACTIVE_CERT_PATH = CERTS_DIR / "server.crt"
ACTIVE_KEY_PATH = CERTS_DIR / "server.key"
BOOTSTRAP_TOKEN_PATH = STATE_DIR / "bootstrap-setup-token"
TIER_B_STATE_FILE = STATE_DIR / "tierb" / "working-set.json"
# Mirrors scripts/v2/alderpointdns_v2_ctl.py's own REPLICATION_* paths --
# this node's own replication mTLS material, needed by the
# /api/replication/issue-peer-cert enrollment endpoint below.
REPLICATION_DIR = STATE_DIR / "replication"
REPLICATION_SERVER_CERT_PATH = REPLICATION_DIR / "server.crt"
REPLICATION_CA_PATH = REPLICATION_DIR / "trust-ca.pem"
SCHEDULE_STATE_FILE = STATE_DIR / "schedule" / "schedule-transition-state.json"

SESSION_SECRET_ID = "web-session-signing-key"
BACKUP_KEY_SECRET_ID = "secret-backup-encryption-key"
SESSION_COOKIE_NAME = "alderpointdns_v2_session"
SESSION_MAX_AGE = 8 * 60 * 60  # 8 hours, matches V1's precedent

_hash_limiter = HashConcurrencyLimiter()
_LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60
_LOGIN_FAILURE_MAX = 5


def _secure_cookies_enabled() -> bool:
    # Overridable for local curl-over-plain-HTTPS-with-self-signed-cert
    # testing where a client's TLS trust store rejects the cert but the
    # session/cookie mechanics still need exercising; the REAL installed
    # service always serves HTTPS-only (see docs/v2/management-plane.md),
    # so Secure=true is the correct default in production.
    return os.environ.get("ALDERPOINTDNS_V2_COOKIE_SECURE", "1").strip().lower() not in ("0", "false", "no")


def _get_or_create_session_secret() -> str:
    secrets = SecretStore(SECRETS_DIR)
    if secrets.exists(SESSION_SECRET_ID):
        return secrets.get(SESSION_SECRET_ID)
    import secrets as _secrets_mod

    value = _secrets_mod.token_urlsafe(48)
    try:
        secrets.create(value, secret_id=SESSION_SECRET_ID)
    except Exception:
        # Lost a create race with another worker process -- read back
        # whatever won instead of failing startup.
        pass
    return secrets.get(SESSION_SECRET_ID)


_serializer: Optional[URLSafeTimedSerializer] = None


def _serializer_instance() -> URLSafeTimedSerializer:
    global _serializer
    if _serializer is None:
        _serializer = URLSafeTimedSerializer(_get_or_create_session_secret(), salt="alderpointdns-v2-session")
    return _serializer


# --- app + security headers -------------------------------------------------

app = FastAPI(title="Alderpoint DNS V2 Management API", docs_url=None, redoc_url=None, openapi_url=None)
if UI_DIR.exists():
    app.mount("/ui-static", StaticFiles(directory=str(UI_DIR)), name="ui-static")


# Found during adversarial security testing: no request body size limit
# existed anywhere in this app -- a single authenticated request (valid
# session + CSRF token, so bounded to an already-logged-in admin, not an
# arbitrary unauthenticated caller, but still a real gap) with an
# oversized field value was accepted all the way through ASGI/Starlette/
# Pydantic parsing before being rejected by a field-level validator, and
# Pydantic's default validation-error response echoes the full rejected
# value back verbatim -- a 5 MB request produced a ~5 MB response, exact
# reflection. No legitimate request this API ever needs to accept is
# anywhere close to this size (the largest real payload is a TLS
# certificate+key PEM pair, a few KB at most). Rejects on the declared
# Content-Length before any parsing happens; does not (yet) defend
# against a client lying about Content-Length while streaming more via
# chunked transfer encoding -- a real remaining gap for a future pass,
# not claimed as full protection here.
MAX_REQUEST_BODY_BYTES = 1_000_000


@app.middleware("http")
async def _reject_oversized_requests(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError:
            declared_size = None
        if declared_size is not None and declared_size > MAX_REQUEST_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={"error": "payload_too_large", "detail": "request body exceeds the maximum accepted size"},
            )
    return await call_next(request)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path.startswith("/api/") or request.url.path.startswith("/replication/"):
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    # §9: HSTS is deliberately NOT set. This service has no separate
    # plaintext HTTP listener to redirect from (HTTPS-only, see module
    # docstring / docs/v2/management-plane.md "HTTP strategy") and the
    # bootstrap certificate is self-signed -- an HSTS header sent to a
    # browser that then can't get a trusted handshake on a later visit
    # (cert regenerated, appliance reinstalled, browser trust store
    # cleared) is exactly the "permanently locks an administrator out"
    # failure mode §9 warns against. Revisit once a non-self-signed
    # default is the common case.
    return response


# --- request context: control.db connection + secret store -----------------


@contextmanager
def _db():
    # create_if_missing=False: see control_db.connect()'s own docstring
    # and docs/v2/control-db-silent-recreation-fix.md -- a real,
    # already-initialized appliance's control.db going missing must
    # never be silently, invisibly replaced by an empty one indistinguishable
    # from a genuine fresh install.
    CONTROL_DB.parent.mkdir(parents=True, exist_ok=True)
    with control_db.connect(CONTROL_DB, create_if_missing=False) as conn:
        yield conn


def _secrets() -> SecretStore:
    # create_if_missing=False: see SecretStore.__init__'s own docstring
    # and docs/v2/control-db-silent-recreation-fix.md -- a real,
    # already-initialized appliance's secret store going missing must
    # never be silently, invisibly replaced by an empty one.
    return SecretStore(SECRETS_DIR, create_if_missing=False)


def _ensure_extended_schemas() -> None:
    # Real defect found and fixed live during this workstream's
    # failure-domain/chaos pass (docs/v2/control-db-silent-recreation-
    # fix.md): every ensure_schema() below starts with
    # control_db.initialize(path), which -- like control_db.connect()
    # itself -- silently creates an empty control.db if the path
    # doesn't exist. This function is called from nearly every request
    # handler in this module, so guarding only _db() (webapp.py's other
    # connect() call site) was NOT sufficient on its own -- this path
    # would have silently recreated a missing control.db regardless.
    # Same fail-closed contract as _db(): a real, previously-
    # initialized appliance's control.db must never simply not exist.
    if not CONTROL_DB.exists():
        raise control_db.ControlDbMissingError(
            f"control.db not found at {CONTROL_DB} -- refusing to silently create a new, empty "
            "database in its place"
        )
    node_identity.ensure_schema(CONTROL_DB)
    observed_clients.ensure_schema(CONTROL_DB)
    replication_v2.ensure_schema(CONTROL_DB)


def _client_ip(request: Request) -> str:
    # §8: no X-Forwarded-* trust -- this service has no configured trusted
    # proxy in this pass, so the only client identity ever used is the
    # real TCP peer address.
    return request.client.host if request.client else "unknown"


# --- errors: structured, never a traceback (§36) ----------------------------


class ApiError(HTTPException):
    def __init__(self, status_code: int, error: str, detail: str = ""):
        super().__init__(status_code=status_code, detail={"error": error, "detail": detail})


# Every real validation error type this module's routes can raise is a
# ValueError subclass (PolicyStoreError, InvalidPolicyError,
# InvalidNetworkError, InvalidDnsNameError, InvalidBlockingResponseError,
# DnsdistGenError) -- registered on the concrete ValueError base rather
# than the bare ``Exception`` class deliberately: Starlette's
# ServerErrorMiddleware (which handles bare ``Exception``) re-raises after
# building its response so an ASGI server can log it, which a real client
# never sees (it gets the built response) but which matters for handler
# *registration* -- an exception handler bound to a specific, expected
# error type is invoked by ExceptionMiddleware, the inner layer, and its
# response is what actually reaches the client with no re-raise involved.


@app.exception_handler(ValueError)
async def _validation_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"error": "validation_error", "detail": str(exc)})


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, dict) else {"error": "http_error", "detail": str(exc.detail)}
    return JSONResponse(status_code=exc.status_code, content=detail)


@app.exception_handler(RuntimeCompileError)
async def _runtime_compile_error_handler(request: Request, exc: RuntimeCompileError):
    return JSONResponse(
        status_code=409,
        content={"error": "runtime_promotion_failed", "detail": "the change was not applied: the generated DNS runtime failed validation, and the previously working configuration remains active"},
    )


# Real defect found live during this workstream's hardware/performance
# matrix re-verification (docs/v2/login-database-locked-under-load-fix.md):
# under real combined DNS + analytics + concurrent-login load, a write
# inside /api/login (recording the login attempt for the brute-force
# lockout counter) hit real SQLite write-lock contention that outlasted
# even the 5-second busy_timeout already configured
# (app/v2/control_db.py) -- surfacing as an unhandled
# sqlite3.OperationalError -> a raw 500, turning an otherwise-genuinely-
# successful, already-Argon2id-verified login into a client-visible
# crash. V1 already solved this exact class of problem
# (app/db_retry.py's own module docstring/tests/test_db_hotpath_and_
# busy_recovery.py) -- reused verbatim rather than reimplemented (see
# scripts/build-v2-deb.sh for why it's a safe, stdlib-only, no-V1-
# dependency addition to what V2 ships). Two-layer defense, matching
# V1's own real, production-proven shape: retry_on_locked() bounds and
# backs off individual writes that are expected to occasionally
# contend (below), and these two handlers are the belt-and-suspenders
# net for anything that still gets through -- a controlled 503, never
# a raw traceback.
@app.exception_handler(DatabaseBusyError)
async def _database_busy_handler(request: Request, exc: DatabaseBusyError):
    return JSONResponse(
        status_code=503,
        content={"error": "database_busy", "detail": "the database is temporarily busy, please retry shortly"},
    )


@app.exception_handler(sqlite3.OperationalError)
async def _sqlite_operational_error_handler(request: Request, exc: sqlite3.OperationalError):
    if is_lock_error(exc):
        return await _database_busy_handler(request, DatabaseBusyError(str(exc)))
    return JSONResponse(status_code=500, content={"error": "internal_error", "detail": "an internal error occurred"})


@app.exception_handler(control_db.ControlDbMissingError)
async def _control_db_missing_handler(request: Request, exc: control_db.ControlDbMissingError):
    # Never a silent "setup required" -- this specific, distinct error
    # code exists so an admin/monitoring system can tell "control.db
    # went missing" apart from a genuinely fresh, never-configured
    # appliance. See control_db.connect()'s own docstring and
    # docs/v2/control-db-silent-recreation-fix.md.
    return JSONResponse(
        status_code=500,
        content={
            "error": "control_db_missing",
            "detail": "the appliance's control database is missing or unreachable -- this is not a "
            "fresh install; do not proceed through setup, investigate the appliance's storage first",
        },
    )


@app.exception_handler(SecretStoreMissingError)
async def _secret_store_missing_handler(request: Request, exc: SecretStoreMissingError):
    # Same real defect, same fix shape, applied to the protected secret
    # store -- see SecretStore.__init__'s own docstring and
    # docs/v2/control-db-silent-recreation-fix.md.
    return JSONResponse(
        status_code=500,
        content={
            "error": "secret_store_missing",
            "detail": "the appliance's secret store is missing or unreachable -- this is not a "
            "fresh install; real secret material may be orphaned, investigate the appliance's "
            "storage before proceeding",
        },
    )


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    # Anything else: a safe, generic 500 -- never the traceback, filesystem
    # paths, SQL text, or crypto material (§36).
    return JSONResponse(status_code=500, content={"error": "internal_error", "detail": "an internal error occurred"})


# --- sessions / auth (§10-14) -----------------------------------------------


def _create_session_row(conn: sqlite3.Connection, admin_id: Optional[int], request: Request) -> dict:
    import secrets as _secrets_mod
    import uuid

    session_id = uuid.uuid4().hex
    csrf = _secrets_mod.token_urlsafe(24)
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (session_id, admin_id, ts, ts, _client_ip(request), request.headers.get("user-agent", ""), csrf),
    )
    return {"id": session_id, "csrf": csrf}


def _set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        SESSION_COOKIE_NAME,
        _serializer_instance().dumps({"sid": session_id}),
        httponly=True,
        samesite="strict",
        secure=_secure_cookies_enabled(),
        max_age=SESSION_MAX_AGE,
    )


def _session_id_from_cookie(request: Request) -> Optional[str]:
    raw = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw:
        return None
    try:
        data = _serializer_instance().loads(raw, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return None
    return data.get("sid")


def current_session(request: Request, conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    session_id = _session_id_from_cookie(request)
    if not session_id:
        return None
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
    conn.row_factory = None
    return row


def current_admin(request: Request):
    """FastAPI dependency: 401 if not authenticated. Also bumps
    last_seen_at (bounded per-request write, matching V1's precedent)."""
    with _db() as conn:
        session = current_session(request, conn)
        if session is None or session["admin_id"] is None:
            raise ApiError(401, "unauthenticated", "login required")
        conn.execute("UPDATE sessions SET last_seen_at=? WHERE id=?", (datetime.now(timezone.utc).isoformat(), session["id"]))
        admin = conn.execute("SELECT * FROM admins WHERE id=?", (session["admin_id"],)).fetchone()
        if admin is None:
            raise ApiError(401, "unauthenticated", "account no longer exists")
        return {"admin_id": session["admin_id"], "session_id": session["id"], "csrf": session["csrf"]}


def check_csrf(admin: dict, x_csrf_token: Optional[str]) -> None:
    # Constant-time comparison (found during adversarial security testing):
    # a plain `!=` here leaks a timing signal proportional to the matching
    # prefix length of a 32-byte urlsafe token. The practical exposure is
    # narrow (an attacker needs an already-valid session cookie to reach
    # this check at all, at which point CSRF is one of several problems),
    # but every other secret-equality check in this codebase already uses
    # hmac.compare_digest (see /api/setup's bootstrap-token check) -- this
    # was the one inconsistent case, fixed for defense in depth rather than
    # left as an unexplained exception to that pattern.
    if not x_csrf_token or not hmac.compare_digest(x_csrf_token, admin["csrf"]):
        raise ApiError(403, "invalid_csrf_token", "missing or incorrect X-CSRF-Token header")


CsrfHeader = Header(None, alias="X-CSRF-Token")


# --- UI shell ---------------------------------------------------------------


def _ui_index() -> str:
    index = UI_DIR / "index.html"
    if not index.exists():
        raise ApiError(404, "ui_not_available", "the V2 UI assets are not installed")
    return index.read_text(encoding="utf-8")


@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
@app.get("/ui/{path:path}", response_class=HTMLResponse)
def ui_app(path: str = ""):
    return HTMLResponse(_ui_index())


# --- setup / bootstrap (§11) -------------------------------------------------


class SetupRequest(BaseModel):
    setup_token: str
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=12, max_length=256)


@app.get("/api/setup/status")
def setup_status():
    with _db() as conn:
        count = conn.execute("SELECT count(*) FROM admins").fetchone()[0]
    return {"setup_required": count == 0}


@app.post("/api/setup")
def setup(req: SetupRequest, request: Request):
    with _db() as conn:
        count = conn.execute("SELECT count(*) FROM admins").fetchone()[0]
        if count > 0:
            raise ApiError(409, "already_configured", "initial setup has already been completed")
        if not BOOTSTRAP_TOKEN_PATH.exists():
            raise ApiError(409, "setup_unavailable", "no bootstrap setup token is available")
        expected = BOOTSTRAP_TOKEN_PATH.read_text(encoding="utf-8").strip()
        if not expected or not hmac.compare_digest(expected, req.setup_token.strip()):
            raise ApiError(403, "invalid_setup_token", "incorrect setup token")
        password_hash = hash_password(req.password, limiter=_hash_limiter)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            (req.username, password_hash, now),
        )
    # One-time: invalidate immediately after successful use (§11).
    try:
        BOOTSTRAP_TOKEN_PATH.unlink()
    except FileNotFoundError:
        pass
    return {"status": "created"}


# --- login / logout (§10, §12, §14) -----------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


def _recent_login_failures(conn: sqlite3.Connection, ip: str) -> int:
    cutoff = time.time() - _LOGIN_FAILURE_WINDOW_SECONDS
    cutoff_iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
    row = conn.execute(
        "SELECT count(*) FROM login_attempts WHERE ip=? AND success=0 AND attempted_at >= ?", (ip, cutoff_iso)
    ).fetchone()
    return row[0]


def _record_login_attempt(conn: sqlite3.Connection, ip: str, success: bool) -> None:
    conn.execute(
        "INSERT INTO login_attempts(ip, attempted_at, success) VALUES (?, ?, ?)",
        (ip, datetime.now(timezone.utc).isoformat(), 1 if success else 0),
    )
    # Bounded table (§14 "must not create an unbounded in-memory
    # attacker-controlled structure" -- same principle applied to the
    # persisted table): drop anything older than the failure window times
    # a small safety margin.
    cutoff_iso = datetime.fromtimestamp(time.time() - _LOGIN_FAILURE_WINDOW_SECONDS * 4, tz=timezone.utc).isoformat()
    conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff_iso,))


@app.post("/api/login")
def login(req: LoginRequest, request: Request, response: Response):
    ip = _client_ip(request)
    with _db() as conn:
        if _recent_login_failures(conn, ip) >= _LOGIN_FAILURE_MAX:
            raise ApiError(429, "rate_limited", "too many failed login attempts; try again later")
        row = conn.execute("SELECT * FROM admins WHERE username=?", (req.username,)).fetchone()
        try:
            ok = False
            new_hash = None
            if row is not None:
                (_, username, password_hash, _created_at) = row
                result, new_hash = verify_and_maybe_rehash(password_hash, req.password, limiter=_hash_limiter)
                ok = result.ok
        except TooManyConcurrentHashesError:
            raise ApiError(503, "auth_busy", "too many concurrent authentication attempts, retry shortly")
        # Real defect found live under real combined DNS+analytics+
        # concurrent-login load (docs/v2/login-database-locked-under-
        # load-fix.md): these writes can hit real SQLite write-lock
        # contention outlasting the 5s busy_timeout already configured
        # -- bounded retry-with-backoff (V1's own proven app/db_retry.py,
        # reused verbatim) rather than letting an otherwise-genuinely-
        # successful, already-verified login crash with a raw 500.
        retry_on_locked(lambda: _record_login_attempt(conn, ip, ok))
        if not ok:
            raise ApiError(401, "invalid_credentials", "incorrect username or password")
        admin_id = row[0]
        if new_hash is not None:
            retry_on_locked(lambda: conn.execute("UPDATE admins SET password_hash=? WHERE id=?", (new_hash, admin_id)))
        # §12 "session rotation after login": always a brand-new session
        # row, never reusing a pre-login one.
        session = retry_on_locked(lambda: _create_session_row(conn, admin_id, request))
    _set_session_cookie(response, session["id"])
    return {"status": "ok", "csrf": session["csrf"]}


@app.post("/api/logout")
def logout(request: Request, response: Response, admin=Depends(current_admin)):
    with _db() as conn:
        conn.execute("DELETE FROM sessions WHERE id=?", (admin["session_id"],))
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"status": "ok"}


@app.get("/api/session")
def session_status(admin=Depends(current_admin)):
    with _db() as conn:
        row = conn.execute("SELECT username FROM admins WHERE id=?", (admin["admin_id"],)).fetchone()
    return {"authenticated": True, "username": row[0] if row else "", "csrf": admin["csrf"]}


# --- health (§16) ------------------------------------------------------------


@app.get("/api/health")
def health():
    result: dict[str, Any] = {"status": "ok", "components": {}}
    try:
        version = control_db.schema_version(CONTROL_DB)
        result["components"]["control_db"] = {"status": "ok", "schema_version": version}
    except Exception as exc:
        result["components"]["control_db"] = {"status": "unavailable", "detail": str(exc)}
        result["status"] = "degraded"

    dep_health = analytics_deps.check_health()
    result["components"]["analytics"] = {
        "status": "degraded" if dep_health.degraded else "ok",
        "pyarrow_available": dep_health.pyarrow_available,
        "duckdb_available": dep_health.duckdb_available,
    }
    if dep_health.degraded:
        # Degraded analytics never demotes overall status below
        # "degraded" -- DNS-relevant components are reported separately
        # and are what actually matters for appliance health (§16).
        result["status"] = "degraded" if result["status"] == "ok" else result["status"]

    result["components"]["compiled_runtime"] = {
        "present": COMPILED_DNSDIST_CONF.exists(),
        "last_modified": (
            datetime.fromtimestamp(COMPILED_DNSDIST_CONF.stat().st_mtime, tz=timezone.utc).isoformat()
            if COMPILED_DNSDIST_CONF.exists() else None
        ),
    }
    result["components"]["tier_b"] = {"state_present": TIER_B_STATE_FILE.exists()}
    result["components"]["schedule_worker"] = {"state_present": SCHEDULE_STATE_FILE.exists()}
    try:
        _ensure_extended_schemas()
        with _db() as conn:
            result["components"]["node_identity"] = {"node_id": node_identity.get_or_create(conn).node_id}
            result["components"]["client_discovery"] = observed_clients.stats(conn)
            result["components"]["replication"] = {"peers": len(replication_v2.list_peers(conn))}
    except Exception as exc:
        result["components"]["replication_discovery"] = {"status": "unavailable", "detail": str(exc)}
        result["status"] = "degraded"
    return result


# --- runtime recompile helper (§18) ------------------------------------------


def _configured_listen_address() -> str:
    """The real appliance-configured DNS listen address ("host:port"),
    same source and same fallback as
    scripts/v2/alderpointdns_v2_ctl.py's install-time bootstrap compiler
    (``_default_dnsdist_config_text``). Without this, every live policy
    mutation through this API would silently fall back to
    runtime_compile.recompile_and_promote()'s own default
    ("127.0.0.1:53") instead of the configured listener -- rebinding
    dnsdist to loopback-only and cutting off every real LAN client the
    next time an admin changes any policy, without any error or warning
    (found live during RC1 clean-install acceptance testing)."""
    cfg = v2config.load_file(CONFIG_FILE) if CONFIG_FILE.exists() else v2config.AlderpointV2Config()
    listener = cfg.listeners[0] if cfg.listeners else v2config.Listener(protocol="udp", address="0.0.0.0", port=53)
    return f"{listener.address}:{listener.port}"


DNSCRYPT_CERT_PATH = CERTS_DIR / "dnscrypt-resolver.cert"
DNSCRYPT_KEY_PATH = CERTS_DIR / "dnscrypt-resolver.key"


def _materialize_dnscrypt_files(settings: "store.DnscryptSettings") -> bool:
    """Writes the real resolver cert/key files ``addDNSCryptBind`` needs
    to disk, freshly, from stored material -- cert bytes are public
    (stored directly in control.db, see DnscryptSettings' own docstring)
    but the resolver private key is protected secret material, fetched
    from the SecretStore fresh every compile rather than cached on disk
    permanently outside a recompile cycle, matching how DoT/DoH/DoQ/DoH3
    already reuse ACTIVE_CERT_PATH/ACTIVE_KEY_PATH (materialized files,
    not secret-store-direct dnsdist reads -- dnsdist has no notion of
    this application's secret store). Returns False (no files written)
    when identity/cert material doesn't exist yet -- never raises, same
    fail-safe contract as the cert_ready check the other four transports
    use."""
    if not settings.identity_provisioned:
        return False
    import base64

    try:
        resolver_key_b64 = _secrets().get(settings.resolver_secret_id)
        cert_bytes = base64.b64decode(settings.cert_b64)
        resolver_key_bytes = base64.b64decode(resolver_key_b64)
    except Exception:
        # Secret went missing/corrupt (e.g. a restore that predates this
        # secret, or manual tampering) -- fail safe to "no DNSCrypt
        # listener this compile," same as a missing TLS cert does for
        # the other four, never crash the whole recompile over it.
        return False
    CERTS_DIR.mkdir(parents=True, exist_ok=True, mode=0o750)
    tmp_cert = DNSCRYPT_CERT_PATH.parent / f".{DNSCRYPT_CERT_PATH.name}.tmp"
    tmp_key = DNSCRYPT_KEY_PATH.parent / f".{DNSCRYPT_KEY_PATH.name}.tmp"
    tmp_cert.write_bytes(cert_bytes)
    tmp_cert.chmod(0o644)
    os.replace(tmp_cert, DNSCRYPT_CERT_PATH)
    tmp_key.write_bytes(resolver_key_bytes)
    tmp_key.chmod(0o600)
    os.replace(tmp_key, DNSCRYPT_KEY_PATH)
    return True


def _encrypted_transport_configs(conn) -> tuple[
    Optional[runtime_compile.DotConfig], Optional[runtime_compile.DohConfig],
    Optional[runtime_compile.DoqConfig], Optional[runtime_compile.Doh3Config],
    Optional[runtime_compile.DnscryptConfig],
]:
    """Builds the real DoT/DoH/DoQ listener configs for this recompile
    from the real admin-configured settings (see
    ``/api/dns-transports``), reusing the appliance's existing
    management TLS cert/key -- see docs/v2/encrypted-transport-parity-
    gap.md for why this exists and dnsdist_policy_runtime.DotConfig/
    DohConfig/DoqConfig's own docstrings for why no separate key
    material is provisioned. Each returns ``None`` (no listener emitted
    at all) when disabled or when the cert/key aren't provisioned yet
    (a fresh install before ``ensure-tls-cert`` has ever run) -- never
    raises here; a missing cert must not break every other policy
    mutation.
    """
    settings = store.load_dns_transport_settings(conn)
    cert_ready = ACTIVE_CERT_PATH.exists() and ACTIVE_KEY_PATH.exists()
    dot = (
        runtime_compile.DotConfig(
            enabled=True, port=settings.dot_port, cert_path=str(ACTIVE_CERT_PATH), key_path=str(ACTIVE_KEY_PATH)
        )
        if settings.dot_enabled and cert_ready
        else None
    )
    doh = (
        runtime_compile.DohConfig(
            enabled=True, port=settings.doh_port, cert_path=str(ACTIVE_CERT_PATH), key_path=str(ACTIVE_KEY_PATH),
            path=settings.doh_path,
        )
        if settings.doh_enabled and cert_ready
        else None
    )
    doq = (
        runtime_compile.DoqConfig(
            enabled=True, port=settings.doq_port, cert_path=str(ACTIVE_CERT_PATH), key_path=str(ACTIVE_KEY_PATH)
        )
        if settings.doq_enabled and cert_ready
        else None
    )
    doh3 = (
        runtime_compile.Doh3Config(
            enabled=True, port=settings.doh3_port, cert_path=str(ACTIVE_CERT_PATH), key_path=str(ACTIVE_KEY_PATH)
        )
        if settings.doh3_enabled and cert_ready
        else None
    )
    dnscrypt_settings = store.load_dnscrypt_settings(conn)
    dnscrypt = (
        runtime_compile.DnscryptConfig(
            enabled=True, port=dnscrypt_settings.port, provider_name=dnscrypt_settings.provider_name,
            cert_path=str(DNSCRYPT_CERT_PATH), key_path=str(DNSCRYPT_KEY_PATH),
        )
        if dnscrypt_settings.enabled and _materialize_dnscrypt_files(dnscrypt_settings)
        else None
    )
    return dot, doh, doq, doh3, dnscrypt


def _mutate_and_promote(mutate_fn) -> runtime_compile.RuntimeCompileResult:
    """Runs ``mutate_fn(conn)`` (a control.db write) and
    runtime_compile.recompile_and_promote() inside ONE transaction: the
    write is only committed if the real dnsdist validation+promotion also
    succeeds. On any failure, everything rolls back -- control.db is left
    exactly as it was, and the previously working compiled runtime remains
    live (recompile_and_promote itself never touches the live path until
    its own validation passes, so a failure there has touched nothing on
    disk either).
    """
    with _db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            mutate_fn(conn)
            dot, doh, doq, doh3, dnscrypt = _encrypted_transport_configs(conn)
            result = runtime_compile.recompile_and_promote(
                conn, STAGING_DIR, COMPILED_DNSDIST_CONF,
                listen_address=_configured_listen_address(), dot=dot, doh=doh, doq=doq, doh3=doh3, dnscrypt=dnscrypt,
            )
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
        return result


# --- networks (§19) -----------------------------------------------------


class NetworkCreate(BaseModel):
    network_id: str = Field(min_length=1, max_length=64)
    cidr: str


@app.get("/api/networks")
def list_networks(admin=Depends(current_admin)):
    with _db() as conn:
        rows = conn.execute("SELECT network_id, cidr FROM policy_networks ORDER BY network_id").fetchall()
        result = []
        for network_id, cidr in rows:
            layer = store.load_policy_layer(conn, "network", network_id)
            result.append({"network_id": network_id, "cidr": cidr, "policy": _policy_layer_dict(layer)})
    return {"networks": result}


@app.post("/api/networks")
def create_network(req: NetworkCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    result = _mutate_and_promote(lambda conn: store.create_network(conn, req.network_id, req.cidr))
    return {"status": "created", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


# --- global + network policy (§18) --------------------------------------


class PolicyLayerUpdate(BaseModel):
    filtering_profile_id: Optional[str] = None
    safesearch_mode: Optional[str] = None
    parental_policy_id: Optional[str] = None
    security_policy_id: Optional[str] = None
    service_blocking_ruleset_id: Optional[str] = None
    blocking_response_mode: Optional[str] = None
    upstream_profile_id: Optional[str] = None
    fallback_strategy: Optional[str] = None
    ecs_mode: Optional[str] = None
    domain_routing_ruleset_id: Optional[str] = None
    query_log_enabled: Optional[bool] = None
    statistics_enabled: Optional[bool] = None


def _policy_layer_dict(layer: PolicyLayer) -> dict[str, Any]:
    return {f.name: getattr(layer, f.name) for f in __import__("dataclasses").fields(layer)}


@app.get("/api/policy/global")
def get_global_policy(admin=Depends(current_admin)):
    with _db() as conn:
        layer = store.load_policy_layer(conn, "global", "singleton")
    return {"policy": _policy_layer_dict(layer)}


@app.put("/api/policy/global")
def put_global_policy(req: PolicyLayerUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    layer = PolicyLayer(**req.model_dump())
    result = _mutate_and_promote(lambda conn: store.save_policy_layer(conn, "global", "singleton", layer))
    return {"status": "updated", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


# --- DNS transports (§ encrypted-transport-parity-gap continuation) -----


class DnsTransportSettingsUpdate(BaseModel):
    dot_enabled: bool = False
    dot_port: int = Field(default=853, ge=1, le=65535)
    doh_enabled: bool = False
    doh_port: int = Field(default=443, ge=1, le=65535)
    doh_path: str = Field(default="/dns-query", min_length=1, max_length=255, pattern=r"^/.*$")
    doq_enabled: bool = False
    doq_port: int = Field(default=853, ge=1, le=65535)
    doh3_enabled: bool = False
    doh3_port: int = Field(default=443, ge=1, le=65535)
    dnscrypt_enabled: bool = False
    dnscrypt_port: int = Field(default=5443, ge=1, le=65535)
    # Real hardening found during this session's own adversarial security
    # pass on this new surface: without a character-set restriction,
    # values containing NUL bytes, backslashes, or newlines were accepted
    # by this model and only caught later, if at all, by real dnsdist
    # --check-config (which does correctly reject an embedded raw
    # newline -- confirmed live, no Lua/RCE injection was actually
    # achievable, addDNSCryptBind's provider-name argument is always
    # safely escaped by _lua_string -- but relying solely on that
    # downstream safety net for a value with no legitimate reason to
    # contain such bytes is unnecessary risk surface). Restricted to the
    # real character set a DNS name (this value's actual purpose --
    # clients query it) can ever legitimately contain.
    dnscrypt_provider_name: str = Field(
        default="2.dnscrypt-cert.alderpointdns-v2.local", min_length=1, max_length=255,
        pattern=r"^[A-Za-z0-9._-]+$",
    )


@app.get("/api/dns-transports")
def get_dns_transports(admin=Depends(current_admin)):
    with _db() as conn:
        settings = store.load_dns_transport_settings(conn)
        dnscrypt_settings = store.load_dnscrypt_settings(conn)
    # Real dnsdist-build capability detection (docs/v2/doh3-transport-
    # implemented.md) -- reuses app.dnsdist_upgrade.dnsdist_capabilities(),
    # the same `dnsdist --version` feature-list parser V1's own
    # app/encryption.py and the opt-in `install-enhanced-dnsdist` command
    # already use, rather than a second implementation. DoQ/DoH3 remain
    # togglable regardless of what this reports (the generated config's
    # own SafeCapabilityCall wrapper degrades safely either way) -- this
    # is surfaced so the admin UI can show *why* a protocol isn't
    # actually answering queries on a build that lacks it.
    caps = dnsdist_upgrade.dnsdist_capabilities()
    dnscrypt_fingerprint = None
    if dnscrypt_settings.provider_public_key_b64:
        import base64

        dnscrypt_fingerprint = dnscrypt_provisioning.provider_fingerprint(
            base64.b64decode(dnscrypt_settings.provider_public_key_b64)
        )
    return {
        "dot_enabled": settings.dot_enabled,
        "dot_port": settings.dot_port,
        "doh_enabled": settings.doh_enabled,
        "doh_port": settings.doh_port,
        "doh_path": settings.doh_path,
        "doq_enabled": settings.doq_enabled,
        "doq_port": settings.doq_port,
        "doh3_enabled": settings.doh3_enabled,
        "doh3_port": settings.doh3_port,
        "dnscrypt_enabled": dnscrypt_settings.enabled,
        "dnscrypt_port": dnscrypt_settings.port,
        "dnscrypt_provider_name": dnscrypt_settings.provider_name,
        "dnscrypt_identity_provisioned": dnscrypt_settings.identity_provisioned,
        "dnscrypt_fingerprint": dnscrypt_fingerprint,
        "dnscrypt_cert_serial": dnscrypt_settings.cert_serial,
        "dnscrypt_cert_valid_until": dnscrypt_settings.cert_valid_until,
        "cert_provisioned": ACTIVE_CERT_PATH.exists() and ACTIVE_KEY_PATH.exists(),
        "dnsdist_version": dnsdist_upgrade.dnsdist_version(),
        "doq_supported": caps.get("doq", False),
        "doh3_supported": caps.get("doh3", False),
        "dnscrypt_supported": caps.get("dnscrypt", False),
    }


# Real defect found live during RC21 acceptance testing: requesting a
# DoT/DoH port that collides with an already-bound appliance port
# (tried the management API's own 8443) passed real dnsdist --check-
# config validation (a syntax check, not a bind attempt) and got
# promoted successfully, but the *live* dnsdist process then crash-
# looped trying to bind the already-occupied port -- taking down real
# DNS answering entirely (confirmed live: "connection refused" on
# port 53, NRestarts climbing), not just the misconfigured listener.
# This is exactly the kind of failure this architecture's own
# recompile_and_promote() invariant ("a known-good runtime always
# remains active on failure") is supposed to prevent, but a runtime
# bind conflict is invisible to --check-config's static validation, so
# it must be caught here, before promotion, by checking against every
# other real fixed port this appliance itself already binds.
_RESERVED_APPLIANCE_PORTS = {
    8443: "the management HTTPS API",
    9443: "the mTLS replication service",
    1053: "the discovery/dns-observer ingress",
    5391: "the analytics protobuf receiver",
}


def _validate_dns_transport_ports(req: "DnsTransportSettingsUpdate") -> None:
    # DoQ binds UDP (addDOQLocal), while DoT/DoH bind TCP (addTLSLocal/
    # addDOHLocal) -- real, standard DNS practice (RFC 9250) is for DoQ
    # to share the *same numeric port* as DoT (both default to 853
    # here, deliberately) since they occupy separate TCP/UDP namespaces
    # and never actually collide. Only TCP-based listeners are checked
    # against each other for a literal same-port conflict; DoQ is only
    # checked against this appliance's own reserved ports and the
    # plain DNS listener (conservative -- treated as reserved even
    # where the real conflict would only be TCP-side, since being
    # overly cautious here is safe and being wrong the other way took
    # down real DNS live on RC21).
    tcp_requested: list[tuple[str, int]] = []
    all_requested: list[tuple[str, int]] = []
    if req.dot_enabled:
        tcp_requested.append(("dot_port", req.dot_port))
        all_requested.append(("dot_port", req.dot_port))
    if req.doh_enabled:
        tcp_requested.append(("doh_port", req.doh_port))
        all_requested.append(("doh_port", req.doh_port))
    if req.doq_enabled:
        all_requested.append(("doq_port", req.doq_port))
    if req.doh3_enabled:
        # QUIC-transported (UDP), same as DoQ -- not checked against the
        # TCP-only conflict set below, only against this appliance's own
        # reserved ports and the plain DNS listener.
        all_requested.append(("doh3_port", req.doh3_port))
    if req.dnscrypt_enabled:
        # dnsdist's real addDNSCryptBind binds BOTH UDP and TCP on the
        # same port -- checked against the TCP pairwise-conflict set too
        # (not just DoQ/DoH3's UDP-only treatment), conservative in the
        # same direction RC21's real live incident already proved is the
        # safe one to err on.
        tcp_requested.append(("dnscrypt_port", req.dnscrypt_port))
        all_requested.append(("dnscrypt_port", req.dnscrypt_port))
    dns_port = int(_configured_listen_address().rsplit(":", 1)[-1])
    for field, port in all_requested:
        if port in _RESERVED_APPLIANCE_PORTS:
            raise ApiError(
                400, "port_conflict",
                f"{field}={port} conflicts with {_RESERVED_APPLIANCE_PORTS[port]}, which already uses that port",
            )
        if port == dns_port:
            raise ApiError(400, "port_conflict", f"{field}={port} conflicts with the plain DNS listener")
    for i, (field_a, port_a) in enumerate(tcp_requested):
        for field_b, port_b in tcp_requested[i + 1:]:
            if port_a == port_b:
                raise ApiError(400, "port_conflict", f"{field_a} and {field_b} must be different when both are enabled")


@app.put("/api/dns-transports")
def put_dns_transports(
    req: DnsTransportSettingsUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader
):
    check_csrf(admin, x_csrf_token)
    _validate_dns_transport_ports(req)
    settings = store.DnsTransportSettings(
        dot_enabled=req.dot_enabled, dot_port=req.dot_port,
        doh_enabled=req.doh_enabled, doh_port=req.doh_port, doh_path=req.doh_path,
        doq_enabled=req.doq_enabled, doq_port=req.doq_port,
        doh3_enabled=req.doh3_enabled, doh3_port=req.doh3_port,
    )

    def _mutate(conn):
        store.save_dns_transport_settings(conn, settings)
        existing_dnscrypt = store.load_dnscrypt_settings(conn)
        # Real, deliberate guard (matching this workstream's established
        # posture for consequential crypto/trust actions -- see
        # app/dnsdist_upgrade.py's own "never automatic" install-
        # enhanced-dnsdist design): enabling DNSCrypt before a provider
        # identity has ever been issued is rejected with a clear error
        # rather than silently auto-generating one as a side effect of a
        # checkbox toggle -- generate it explicitly via
        # POST /api/dns-transports/dnscrypt/rotate first.
        if req.dnscrypt_enabled and not existing_dnscrypt.identity_provisioned:
            raise ApiError(
                409, "dnscrypt_not_provisioned",
                "DNSCrypt has no provider identity/certificate yet -- "
                "call POST /api/dns-transports/dnscrypt/rotate first",
            )
        existing_dnscrypt.enabled = req.dnscrypt_enabled
        existing_dnscrypt.port = req.dnscrypt_port
        existing_dnscrypt.provider_name = req.dnscrypt_provider_name
        store.save_dnscrypt_settings(conn, existing_dnscrypt)

    result = _mutate_and_promote(_mutate)
    return {"status": "updated", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


class DnscryptRotateRequest(BaseModel):
    rotate_provider: bool = False


_DNSCRYPT_CERT_VALIDITY_DAYS = 397  # matches app/v2/tls_cert.py's own bounded-but-not-forever rationale


@app.post("/api/dns-transports/dnscrypt/rotate")
def rotate_dnscrypt(
    req: DnscryptRotateRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader
):
    """Issues real DNSCrypt provider/resolver key material via the real
    dnsdist binary (app/v2/dnscrypt_provisioning.py) -- see
    docs/v2/dnscrypt-transport-implemented.md for the full design and why
    generation always goes through dnsdist itself. ``rotate_provider``
    defaults to False (issue a fresh resolver certificate under the
    EXISTING provider identity -- the routine action, e.g. before the
    current certificate expires) since rotating the provider identity
    itself invalidates every previously-pinned client's stamp and should
    never happen as a side effect of a routine cert renewal.
    """
    check_csrf(admin, x_csrf_token)
    import base64
    import time

    secrets_store = _secrets()
    # Real defect found live during this session's own adversarial
    # security pass on this new surface: SecretStore.create() writes
    # directly to disk and is NOT part of _mutate_and_promote's SQL
    # transaction -- confirmed live, forcing recompile_and_promote to
    # fail after _mutate had already generated and stored real key
    # material: control.db correctly rolled back to unprovisioned state,
    # but the newly-created provider/resolver secret files were left on
    # disk, referenced by nothing, permanently orphaned (real key
    # material with no lifecycle, never rotated, never cleaned up -- a
    # genuine secret-hygiene defect, not just a resource leak). Every
    # secret this function creates is now tracked here regardless of
    # outcome so a failure path can clean up exactly what THIS attempt
    # created, never anything from a prior successful rotation.
    holder: dict = {"new_secret_ids": []}

    def _mutate(conn):
        existing = store.load_dnscrypt_settings(conn)
        need_new_provider = req.rotate_provider or not existing.identity_provisioned
        if need_new_provider:
            public_key, private_key = dnscrypt_provisioning.generate_provider_keypair()
            new_provider_secret_id = secrets_store.create(base64.b64encode(private_key).decode())
            holder["new_secret_ids"].append(new_provider_secret_id)
            old_provider_secret_id = existing.provider_secret_id
            existing.provider_secret_id = new_provider_secret_id
            existing.provider_public_key_b64 = base64.b64encode(public_key).decode()
            existing.cert_serial = 0  # a new provider identity restarts the resolver-cert serial sequence
        else:
            if not existing.provider_secret_id:
                raise ApiError(409, "dnscrypt_not_provisioned", "no provider identity exists to sign a certificate with")
            provider_private_key = base64.b64decode(secrets_store.get(existing.provider_secret_id))
            old_provider_secret_id = None
        provider_private_key_bytes = (
            private_key if need_new_provider else provider_private_key
        )
        now = int(time.time())
        serial = existing.cert_serial + 1
        valid_until = now + _DNSCRYPT_CERT_VALIDITY_DAYS * 86400
        cert_bytes, resolver_key = dnscrypt_provisioning.generate_resolver_certificate(
            provider_private_key_bytes, serial=serial, valid_from=now, valid_until=valid_until
        )
        new_resolver_secret_id = secrets_store.create(base64.b64encode(resolver_key).decode())
        holder["new_secret_ids"].append(new_resolver_secret_id)
        old_resolver_secret_id = existing.resolver_secret_id
        existing.resolver_secret_id = new_resolver_secret_id
        existing.cert_b64 = base64.b64encode(cert_bytes).decode()
        existing.cert_serial = serial
        existing.cert_valid_from = now
        existing.cert_valid_until = valid_until
        store.save_dnscrypt_settings(conn, existing)
        # Old secrets are deleted only after save_dnscrypt_settings above
        # has recorded the new references -- if anything after this point
        # fails, _mutate_and_promote's transaction rolls the control.db
        # write back, but a SecretStore delete is not itself part of that
        # SQL transaction; deleting the OLD secret only (never the new
        # one) after the new reference is durably about to be recorded
        # is the safest ordering available without a two-phase secret
        # store, matching the "individually reversible steps" standard
        # used elsewhere in this session (app/dnsdist_upgrade.py).
        holder["old_secret_ids"] = [s for s in (old_provider_secret_id, old_resolver_secret_id) if s]
        holder["rotated_provider"] = need_new_provider

    try:
        result = _mutate_and_promote(_mutate)
    except BaseException:
        for new_id in holder.get("new_secret_ids", []):
            try:
                secrets_store.delete(new_id)
            except Exception:
                pass  # best-effort; a leaked-on-cleanup-failure secret is still strictly
                # better than never having attempted cleanup at all
        raise
    for old_id in holder.get("old_secret_ids", []):
        try:
            secrets_store.delete(old_id)
        except Exception:
            pass  # best-effort cleanup; an orphaned old secret is inert, never reused
    with _db() as conn:
        settings = store.load_dnscrypt_settings(conn)
    fingerprint = dnscrypt_provisioning.provider_fingerprint(base64.b64decode(settings.provider_public_key_b64))
    return {
        "status": "rotated",
        "rotated_provider": holder["rotated_provider"],
        "fingerprint": fingerprint,
        "cert_serial": settings.cert_serial,
        "cert_valid_until": settings.cert_valid_until,
        "runtime": {"promoted": result.promoted, "binding_count": result.binding_count},
    }


@app.put("/api/policy/network/{network_id}")
def put_network_policy(network_id: str, req: PolicyLayerUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    layer = PolicyLayer(**req.model_dump())
    result = _mutate_and_promote(lambda conn: store.save_policy_layer(conn, "network", network_id, layer))
    return {"status": "updated", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


class GroupCreate(BaseModel):
    group_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    priority: int = 100


@app.get("/api/groups")
def list_groups(admin=Depends(current_admin)):
    with _db() as conn:
        rows = conn.execute("SELECT group_id, name, priority FROM policy_groups ORDER BY priority, name").fetchall()
        groups = []
        for group_id, name, priority in rows:
            members = conn.execute(
                """
                SELECT c.id, c.name
                FROM clients c
                JOIN policy_client_group_membership m ON m.client_id = c.id
                JOIN policy_groups g ON g.id = m.policy_group_row_id
                WHERE g.group_id = ?
                ORDER BY c.name
                """,
                (group_id,),
            ).fetchall()
            groups.append(
                {
                    "group_id": group_id,
                    "name": name,
                    "priority": priority,
                    "members": [{"id": r[0], "name": r[1]} for r in members],
                    "policy": _policy_layer_dict(store.load_policy_layer(conn, "group", group_id)),
                }
            )
    return {"groups": groups}


@app.post("/api/groups")
def create_group(req: GroupCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        store.create_group(conn, req.group_id, req.name, req.priority)
    return {"status": "created"}


@app.put("/api/policy/group/{group_id}")
def put_group_policy(group_id: str, req: PolicyLayerUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    layer = PolicyLayer(**req.model_dump())
    result = _mutate_and_promote(lambda conn: store.save_policy_layer(conn, "group", group_id, layer))
    return {"status": "updated", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


# --- clients + effective-policy explain (§21-22) -----------------------


class ClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = ""


@app.get("/api/clients")
def list_clients(admin=Depends(current_admin)):
    with _db() as conn:
        rows = conn.execute("SELECT id, name, description, enabled FROM clients ORDER BY id").fetchall()
        clients = []
        for client_id, name, description, enabled in rows:
            identifiers = conn.execute(
                "SELECT kind, value FROM client_identifiers WHERE client_id=? ORDER BY kind, value", (client_id,)
            ).fetchall()
            groups = store.load_groups_for_client(conn, client_id)
            clients.append(
                {
                    "id": client_id,
                    "name": name,
                    "description": description,
                    "enabled": bool(enabled),
                    "identifiers": [{"kind": r[0], "value": r[1]} for r in identifiers],
                    "groups": [{"group_id": g.group_id, "name": g.name, "priority": g.priority} for g in groups],
                    "policy": _policy_layer_dict(store.load_policy_layer(conn, "client", str(client_id))),
                }
            )
    return {"clients": clients}


@app.post("/api/clients")
def create_client(req: ClientCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    now = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO clients(name, description, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
            (req.name, req.description, now, now),
        )
        client_id = cur.lastrowid
    return {"status": "created", "client_id": client_id}


class ClientIdentifierCreate(BaseModel):
    kind: str
    value: str


@app.post("/api/clients/{client_id}/identifiers")
def add_client_identifier(client_id: int, req: ClientIdentifierCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    if req.kind not in ("ipv4", "ipv4_cidr", "ipv6", "ipv6_cidr", "clientid"):
        raise ApiError(400, "validation_error", "invalid identifier kind")
    if req.kind in ("ipv4", "ipv6"):
        ipaddress.ip_address(req.value)
    elif req.kind in ("ipv4_cidr", "ipv6_cidr"):
        ipaddress.ip_network(req.value, strict=False)
    now = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        exists = conn.execute("SELECT 1 FROM clients WHERE id=?", (client_id,)).fetchone()
        if not exists:
            raise ApiError(404, "not_found", "unknown client")
        try:
            conn.execute(
                "INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES (?, ?, ?, ?)",
                (client_id, req.kind, req.value, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "identifier_conflict", "that client identifier is already assigned") from exc
    return {"status": "created"}


class ClientGroupMembershipIn(BaseModel):
    group_id: str = Field(min_length=1, max_length=64)


@app.post("/api/clients/{client_id}/groups")
def add_client_group(client_id: int, req: ClientGroupMembershipIn, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        exists = conn.execute("SELECT 1 FROM clients WHERE id=?", (client_id,)).fetchone()
        if not exists:
            raise ApiError(404, "not_found", "unknown client")
        store.add_client_to_group(conn, client_id, req.group_id)
    return {"status": "created"}


@app.put("/api/policy/client/{client_id}")
def put_client_policy(client_id: int, req: PolicyLayerUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    layer = PolicyLayer(**req.model_dump())
    result = _mutate_and_promote(lambda conn: store.save_policy_layer(conn, "client", str(client_id), layer))
    return {"status": "updated", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


@app.get("/api/policy/explain")
def explain(client_id: int, client_ip: Optional[str] = None, admin=Depends(current_admin)):
    with _db() as conn:
        ctx = policy_service.ClientResolutionContext(client_id=client_id, client_ip=client_ip)
        return policy_service.explain_policy_for_client(conn, ctx, now=datetime.now(timezone.utc))


# --- upstream profiles + domain routing (§26-27) -------------------------


class UpstreamEndpointIn(BaseModel):
    address: str
    tls_hostname: Optional[str] = None
    priority: int = 0
    weight: int = 1
    doh_path: Optional[str] = None


class UpstreamProfileCreate(BaseModel):
    upstream_profile_id: str = Field(min_length=1, max_length=64)
    name: str
    transport: str
    strategy: str = "ordered"
    endpoints: list[UpstreamEndpointIn]


@app.get("/api/upstreams")
def list_upstreams(admin=Depends(current_admin)):
    with _db() as conn:
        rows = conn.execute("SELECT upstream_profile_id, name, transport, strategy FROM upstream_profiles ORDER BY upstream_profile_id").fetchall()
        upstreams = []
        for upstream_profile_id, name, transport, strategy in rows:
            ep_rows = conn.execute(
                "SELECT address, tls_hostname, priority, weight, doh_path FROM upstream_endpoints "
                "WHERE upstream_profile_row_id=(SELECT id FROM upstream_profiles WHERE upstream_profile_id=?) "
                "ORDER BY priority, address",
                (upstream_profile_id,),
            ).fetchall()
            upstreams.append(
                {
                    "upstream_profile_id": upstream_profile_id,
                    "name": name,
                    "transport": transport,
                    "strategy": strategy,
                    "endpoints": [
                        {"address": e[0], "tls_hostname": e[1], "priority": e[2], "weight": e[3], "doh_path": e[4]}
                        for e in ep_rows
                    ],
                }
            )
    return {"upstreams": upstreams}


@app.post("/api/upstreams")
def create_upstream(req: UpstreamProfileCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    endpoints = [
        store.UpstreamEndpointRecord(e.address, e.tls_hostname, e.priority, e.weight, None, e.doh_path)
        for e in req.endpoints
    ]
    with _db() as conn:
        store.create_upstream_profile(conn, req.upstream_profile_id, req.name, req.transport, endpoints, strategy=req.strategy)
    return {"status": "created"}


class DomainRoutingCreate(BaseModel):
    rule_id: str
    suffix_domain: str
    upstream_profile_id: str


@app.get("/api/domain-routing")
def list_domain_routes(admin=Depends(current_admin)):
    with _db() as conn:
        rows = conn.execute(
            "SELECT ruleset_id, match_kind, domain, upstream_profile_id FROM domain_routing_rules "
            "ORDER BY ruleset_id, domain"
        ).fetchall()
    return {
        "routes": [
            {"ruleset_id": r[0], "match_kind": r[1], "domain": r[2], "upstream_profile_id": r[3]} for r in rows
        ]
    }


@app.post("/api/domain-routing")
def create_domain_route(req: DomainRoutingCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)

    def _mutate(conn):
        store.add_domain_routing_rule(conn, req.rule_id, "suffix", req.suffix_domain, req.upstream_profile_id)

    result = _mutate_and_promote(_mutate)
    return {"status": "created", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


# --- services / blocking rulesets (§24) -----------------------------------


class ServiceDomainIn(BaseModel):
    match_kind: str
    domain: str


class ServiceCreate(BaseModel):
    service_id: str
    display_name: str
    category: str = ""
    domains: list[ServiceDomainIn]


@app.post("/api/services")
def create_service(req: ServiceCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        store.create_service(conn, req.service_id, req.display_name, [(d.match_kind, d.domain) for d in req.domains], category=req.category)
    return {"status": "created"}


@app.get("/api/services")
def list_services(admin=Depends(current_admin)):
    with _db() as conn:
        rows = conn.execute("SELECT id, service_id, display_name, category FROM service_definitions ORDER BY category, display_name").fetchall()
        services = []
        for row_id, service_id, display_name, category in rows:
            domains = conn.execute(
                "SELECT match_kind, domain FROM service_domains WHERE service_row_id=? ORDER BY match_kind, domain",
                (row_id,),
            ).fetchall()
            services.append(
                {
                    "service_id": service_id,
                    "display_name": display_name,
                    "category": category,
                    "domains": [{"match_kind": d[0], "domain": d[1]} for d in domains],
                }
            )
    return {"services": services}


class ServiceRulesetCreate(BaseModel):
    ruleset_id: str
    service_ids: list[str]


@app.post("/api/service-rulesets")
def create_service_ruleset(req: ServiceRulesetCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        store.create_service_ruleset(conn, req.ruleset_id, req.service_ids)
    return {"status": "created"}


@app.get("/api/service-rulesets")
def list_service_rulesets(admin=Depends(current_admin)):
    with _db() as conn:
        rows = conn.execute("SELECT id, ruleset_id FROM service_blocking_rulesets ORDER BY ruleset_id").fetchall()
        rulesets = []
        for row_id, ruleset_id in rows:
            members = conn.execute(
                """
                SELECT s.service_id, s.display_name
                FROM service_blocking_ruleset_members m
                JOIN service_definitions s ON s.id = m.service_row_id
                WHERE m.ruleset_row_id=?
                ORDER BY s.display_name
                """,
                (row_id,),
            ).fetchall()
            rulesets.append({"ruleset_id": ruleset_id, "services": [{"service_id": m[0], "display_name": m[1]} for m in members]})
    return {"rulesets": rulesets}


# --- schedules (§23) --------------------------------------------------------


class ScheduleWindowIn(BaseModel):
    start: str  # "HH:MM"
    end: str
    weekdays: list[int]


class ScheduleCreate(BaseModel):
    schedule_id: str
    timezone: str
    windows: list[ScheduleWindowIn]


@app.post("/api/schedules")
def create_schedule_route(req: ScheduleCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    from datetime import time as dt_time

    from app.v2.schedule_policy import ScheduleWindow

    windows = []
    for w in req.windows:
        h1, m1 = (int(x) for x in w.start.split(":"))
        h2, m2 = (int(x) for x in w.end.split(":"))
        windows.append(ScheduleWindow(start=dt_time(h1, m1), end=dt_time(h2, m2), weekdays=frozenset(w.weekdays)))
    with _db() as conn:
        store.create_schedule(conn, req.schedule_id, req.timezone, windows)
    return {"status": "created"}


@app.get("/api/schedules")
def list_schedules(admin=Depends(current_admin)):
    with _db() as conn:
        rows = conn.execute("SELECT id, schedule_id, timezone FROM policy_schedules ORDER BY schedule_id").fetchall()
        schedules = []
        for row_id, schedule_id, timezone_name in rows:
            windows = conn.execute(
                "SELECT start_time, end_time, weekdays FROM policy_schedule_windows WHERE schedule_row_id=? ORDER BY start_time",
                (row_id,),
            ).fetchall()
            schedules.append(
                {
                    "schedule_id": schedule_id,
                    "timezone": timezone_name,
                    "windows": [{"start": w[0], "end": w[1], "weekdays": w[2]} for w in windows],
                    "policy": _policy_layer_dict(store.load_policy_layer(conn, "schedule", schedule_id)),
                }
            )
    return {"schedules": schedules}


@app.put("/api/policy/schedule/{schedule_id}")
def put_schedule_policy(schedule_id: str, req: PolicyLayerUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    layer = PolicyLayer(**req.model_dump())
    result = _mutate_and_promote(lambda conn: store.save_policy_layer(conn, "schedule", schedule_id, layer))
    return {"status": "updated", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


class LocalDnsRecordCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    record_type: str
    value: str = Field(min_length=1, max_length=255)
    ttl: int = Field(default=300, ge=30, le=86400)
    enabled: bool = True


def _ensure_local_dns_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS local_dns_records (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            record_type TEXT NOT NULL CHECK(record_type IN ('A','AAAA','CNAME','PTR')),
            value TEXT NOT NULL,
            ttl INTEGER NOT NULL DEFAULT 300,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(name, record_type, value)
        )
        """
    )


@app.get("/api/local-dns")
def list_local_dns(admin=Depends(current_admin)):
    with _db() as conn:
        _ensure_local_dns_schema(conn)
        rows = conn.execute(
            "SELECT id, name, record_type, value, ttl, enabled FROM local_dns_records ORDER BY name, record_type, value LIMIT 500"
        ).fetchall()
    return {"records": [{"id": r[0], "name": r[1], "record_type": r[2], "value": r[3], "ttl": r[4], "enabled": bool(r[5])} for r in rows]}


@app.post("/api/local-dns")
def create_local_dns(req: LocalDnsRecordCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    if req.record_type not in ("A", "AAAA", "CNAME", "PTR"):
        raise ApiError(400, "validation_error", "invalid record type")
    if req.record_type == "A":
        ipaddress.IPv4Address(req.value)
    elif req.record_type == "AAAA":
        ipaddress.IPv6Address(req.value)
    elif req.record_type in ("CNAME", "PTR"):
        from app.v2.dns_name_validate import validate_dns_name

        validate_dns_name(req.value)

    from app.v2.dns_name_validate import validate_dns_name

    validate_dns_name(req.name)

    def _mutate(conn):
        _ensure_local_dns_schema(conn)
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO local_dns_records(name, record_type, value, ttl, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (req.name.strip(".").lower(), req.record_type, req.value, req.ttl, int(req.enabled), now, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "duplicate_record", "that Local DNS record already exists") from exc

    result = _mutate_and_promote(_mutate)
    return {"status": "created", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


# --- analytics (§28) ---------------------------------------------------


def _analytics_service() -> AnalyticsService:
    return AnalyticsService(parquet_root=ANALYTICS_PARQUET_DIR, aggregates_path=ANALYTICS_AGGREGATES_DB)


def _query_result_to_dict(qr) -> dict:
    return {"rows": qr.rows, "columns": qr.columns, "degraded": qr.degraded, "degraded_reason": qr.degraded_reason}


def _forced_analytics_degraded() -> str:
    return os.environ.get("ALDERPOINTDNS_V2_FORCE_ANALYTICS_DEGRADED", "").strip()


@app.get("/api/analytics/recent")
def analytics_recent(minutes: float = 60.0, admin=Depends(current_admin)):
    if reason := _forced_analytics_degraded():
        return {"rows": [], "columns": [], "degraded": True, "degraded_reason": reason}
    svc = _analytics_service()
    try:
        return _query_result_to_dict(svc.recent_query_log(minutes=minutes))
    finally:
        svc.close()


@app.get("/api/analytics/query-log")
def analytics_query_log(
    minutes: float = 1440.0,
    domain: Optional[str] = None,
    search: Optional[str] = None,
    client: Optional[str] = None,
    qtype: Optional[str] = None,
    protocol: Optional[str] = None,
    blocked_only: bool = False,
    rcode: Optional[str] = None,
    upstream: Optional[str] = None,
    cache_status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    admin=Depends(current_admin),
):
    if reason := _forced_analytics_degraded():
        return {
            "rows": [],
            "columns": [],
            "degraded": True,
            "degraded_reason": reason,
            "limit": max(1, min(int(limit), 500)),
            "offset": max(0, min(int(offset), 100_000)),
            "filters": {"minutes": minutes, "search": search or ""},
        }
    filters: dict[str, Any] = {}
    for key, value in (
        ("domain", domain),
        ("client", client),
        ("qtype", qtype),
        ("protocol", protocol),
        ("rcode", rcode),
        ("upstream", upstream),
        ("cache_status", cache_status),
    ):
        if value not in (None, ""):
            filters[key] = str(value)[:256]
    if blocked_only:
        filters["blocked"] = True
    minutes = max(1.0, min(float(minutes), 31 * 24 * 60.0))
    limit = max(1, min(int(limit), 500))
    offset = max(0, min(int(offset), 100_000))
    svc = _analytics_service()
    try:
        result = svc.recent_query_log(minutes=minutes, filters=filters, limit=limit, offset=offset)
    finally:
        svc.close()

    rows = result.rows
    # Full-text contains filtering is intentionally post-query and bounded:
    # the allowlisted equality filters above are applied by DuckDB; this
    # optional operator search never widens the backend scan.
    if search:
        needle = str(search).lower()[:256]
        rows = [r for r in rows if needle in " ".join(str(v).lower() for v in r)]
    return {
        "rows": rows,
        "columns": result.columns,
        "degraded": result.degraded,
        "degraded_reason": result.degraded_reason,
        "limit": limit,
        "offset": offset,
        "filters": {"minutes": minutes, **filters, "search": search or ""},
    }


@app.get("/api/analytics/top-domains")
def analytics_top_domains(minutes: float = 60.0, limit: int = 20, admin=Depends(current_admin)):
    if reason := _forced_analytics_degraded():
        return {"rows": [], "columns": [], "degraded": True, "degraded_reason": reason}
    now = time.time()
    svc = _analytics_service()
    try:
        return _query_result_to_dict(svc.top_domains(now - minutes * 60, now, limit=limit))
    finally:
        svc.close()


# --- notifications (§29) ------------------------------------------------


class NotificationProviderCreate(BaseModel):
    provider_id: str
    kind: str
    display_name: str
    endpoint: str
    secret_value: Optional[str] = None


@app.get("/api/notifications")
def list_notifications(admin=Depends(current_admin)):
    with _db() as conn:
        notification_store.ensure_schema(CONTROL_DB)
        providers = notification_store.list_providers(conn)
    return {"providers": [p.redacted() for p in providers]}


@app.post("/api/notifications")
def create_notification(req: NotificationProviderCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    secrets = _secrets()
    with _db() as conn:
        notification_store.ensure_schema(CONTROL_DB)
        metadata = notification_store.create_provider(
            conn, secrets, req.provider_id, req.kind, req.display_name, req.endpoint, secret_value=req.secret_value
        )
    return {"status": "created", "provider": metadata.redacted()}


# --- backup (§30-31) ------------------------------------------------------


def _backup_dir() -> Path:
    path = STATE_DIR / "backups"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _backup_path_from_name(name: str) -> Path:
    if "/" in name or "\\" in name or name.startswith(".") or not name.endswith(".enc"):
        raise ApiError(400, "validation_error", "invalid backup name")
    path = (_backup_dir() / name).resolve()
    if path.parent != _backup_dir().resolve():
        raise ApiError(400, "validation_error", "invalid backup name")
    return path


def _backup_key(secrets: SecretStore) -> bytes:
    from cryptography.fernet import Fernet

    if not secrets.exists(BACKUP_KEY_SECRET_ID):
        secrets.create(Fernet.generate_key().decode("ascii"), secret_id=BACKUP_KEY_SECRET_ID)
    return secrets.get(BACKUP_KEY_SECRET_ID).encode("ascii")


class SecretRestoreRequest(BaseModel):
    confirmation: str
    overwrite: bool = False


@app.get("/api/backup/secrets")
def list_secret_backups(admin=Depends(current_admin)):
    rows = []
    for p in sorted(_backup_dir().glob("*.enc"), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = p.stat()
        rows.append({
            "name": p.name,
            "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        })
    with _db() as conn:
        jobs = conn.execute(
            "SELECT id, started_at, finished_at, status, backup_path, detail_json "
            "FROM restore_jobs ORDER BY id DESC LIMIT 20"
        ).fetchall()
    return {
        "backups": rows,
        "restore_jobs": [
            {
                "id": r[0],
                "started_at": r[1],
                "finished_at": r[2],
                "status": r[3],
                "backup_name": Path(r[4]).name if r[4] else "",
                "detail": json.loads(r[5] or "{}"),
            }
            for r in jobs
        ],
    }


@app.post("/api/backup/secrets")
def create_secret_backup(admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    from app.v2 import secret_backup

    secrets = _secrets()
    key = _backup_key(secrets)
    backup_dir = _backup_dir()
    backup_path = backup_dir / f"secrets-{int(time.time())}.enc"
    result = secret_backup.create_encrypted_backup(secrets, backup_path, key)
    with _db() as conn:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO backup_jobs(started_at, finished_at, status, path, detail_json) VALUES (?, ?, ?, ?, ?)",
            (now, now, "succeeded", str(backup_path), json.dumps({"secret_count": result.secret_count})),
        )
    # §30: no plaintext secret export -- only a count and a server-side
    # path are returned, never contents.
    return {"status": "created", "name": backup_path.name, "secret_count": result.secret_count, "created_at": result.created_at}


@app.post("/api/backup/secrets/{name}/validate")
def validate_secret_backup(name: str, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    from app.v2 import secret_backup

    path = _backup_path_from_name(name)
    if not path.exists():
        raise ApiError(404, "not_found", "backup not found")
    secrets = _secrets()
    try:
        count = secret_backup.restore_encrypted_backup(path, _backup_key(secrets), SecretStore(STATE_DIR / "backup-validation-scratch"), overwrite=True)
    except secret_backup.SecretBackupError as exc:
        raise ApiError(400, "backup_invalid", str(exc)) from exc
    scratch = STATE_DIR / "backup-validation-scratch"
    for child in scratch.glob("*"):
        child.unlink()
    return {"status": "valid", "backup_name": name, "secret_count": count, "size_bytes": path.stat().st_size}


@app.post("/api/backup/secrets/{name}/restore")
def restore_secret_backup(name: str, req: SecretRestoreRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    from app.v2 import secret_backup

    if req.confirmation != name:
        raise ApiError(400, "confirmation_required", "type the exact backup file name to restore")
    path = _backup_path_from_name(name)
    if not path.exists():
        raise ApiError(404, "not_found", "backup not found")
    started = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO restore_jobs(started_at, status, backup_path, detail_json) VALUES (?, ?, ?, ?)",
            (started, "running", str(path), json.dumps({"overwrite": req.overwrite})),
        )
        job_id = cur.lastrowid
    try:
        restored = secret_backup.restore_encrypted_backup(path, _backup_key(_secrets()), _secrets(), overwrite=req.overwrite)
    except secret_backup.SecretBackupError as exc:
        finished = datetime.now(timezone.utc).isoformat()
        with _db() as conn:
            conn.execute(
                "UPDATE restore_jobs SET finished_at = ?, status = ?, detail_json = ? WHERE id = ?",
                (finished, "failed", json.dumps({"error": str(exc), "overwrite": req.overwrite}), job_id),
            )
        raise ApiError(400, "restore_failed", str(exc)) from exc
    finished = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        conn.execute(
            "UPDATE restore_jobs SET finished_at = ?, status = ?, detail_json = ? WHERE id = ?",
            (finished, "succeeded", json.dumps({"secret_count": restored, "overwrite": req.overwrite}), job_id),
        )
    return {"status": "succeeded", "job_id": job_id, "backup_name": name, "secret_count": restored}


# --- replication (§4C) ------------------------------------------------------


class NodeIdentityUpdate(BaseModel):
    display_name: str = Field(max_length=128)


@app.get("/api/node-identity")
def node_identity_status(admin=Depends(current_admin)):
    _ensure_extended_schemas()
    with _db() as conn:
        ident = node_identity.get_or_create(conn)
    return {
        "node_id": ident.node_id,
        "display_name": ident.display_name,
        "created_at": ident.created_at,
        "regenerated_at": ident.regenerated_at,
        "restore_clone_semantics": "backup restore retains node_id; active clones must explicitly regenerate identity before adding replication trust",
    }


@app.put("/api/node-identity/display-name")
def node_identity_display_name(req: NodeIdentityUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    _ensure_extended_schemas()
    with _db() as conn:
        ident = node_identity.set_display_name(conn, req.display_name)
    return {"node_id": ident.node_id, "display_name": ident.display_name}


class ReplicationPeerUpsert(BaseModel):
    peer_node_id: str = Field(min_length=1, max_length=128)
    display_name: str = Field(default="", max_length=128)
    url: str
    ca_pem: str
    expected_cert_sha256: str = Field(min_length=64, max_length=64)
    # Required for direction="bidirectional" (this peer may push TO
    # us): the fingerprint of the cert THIS peer presents as ITS client
    # identity, from issue_peer_client_cert() run on THIS node for that
    # peer's node_id -- deliberately a separate field from
    # expected_cert_sha256 (that peer's own, different, server cert
    # fingerprint) -- see replication_v2.upsert_peer's docstring for
    # the real bidirectional-trust defect this closes.
    expected_incoming_cert_sha256: str = ""
    client_cert_pem: str = ""
    client_key_pem: str = ""
    authorized: bool = True
    direction: str = "bidirectional"


@app.get("/api/replication/peers")
def replication_peers(admin=Depends(current_admin)):
    _ensure_extended_schemas()
    with _db() as conn:
        peers = [p.public_dict() for p in replication_v2.list_peers(conn)]
    return {"peers": peers}


@app.put("/api/replication/peers/{peer_node_id}")
def replication_upsert_peer(peer_node_id: str, req: ReplicationPeerUpsert, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    if peer_node_id != req.peer_node_id:
        raise ApiError(400, "validation_error", "path peer id does not match body")
    _ensure_extended_schemas()
    with _db() as conn:
        replication_v2.upsert_peer(conn, **req.model_dump())
    return {"status": "saved"}


@app.delete("/api/replication/peers/{peer_node_id}")
def replication_delete_peer(peer_node_id: str, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    _ensure_extended_schemas()
    with _db() as conn:
        replication_v2.remove_peer(conn, peer_node_id)
    return {"status": "removed"}


@app.get("/api/replication/health")
def replication_health(admin=Depends(current_admin)):
    _ensure_extended_schemas()
    with _db() as conn:
        ident = node_identity.get_or_create(conn)
        peers = [p.public_dict() for p in replication_v2.list_peers(conn)]
    return {"node_id": ident.node_id, "protocol_version": replication_v2.PROTOCOL_VERSION, "peers": peers}


@app.post("/api/replication/peers/{peer_node_id}/sync")
def replication_sync(peer_node_id: str, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    _ensure_extended_schemas()
    temp_root = STATE_DIR / "replication" / "tmp"
    with _db() as conn:
        result = replication_v2.push_to_peer(conn, _secrets(), peer_node_id, temp_root)
    return {"status": "ok", "result": result}


class IssuePeerCertRequest(BaseModel):
    # Real node_ids are always UUID4 strings (node_identity.py); this is
    # deliberately a little more permissive than strict UUID (allows
    # future non-UUID identifiers) while still refusing to embed
    # arbitrary attacker-controlled text into a real X.509 certificate's
    # CN field -- found live during RC11 security spot-checking: a
    # value like "../../etc/passwd" was accepted and issued into a real
    # cert with no functional exploit path found (never used as a
    # filesystem path or interpreted by anything other than being
    # embedded as a CN string), but tightened anyway since there is no
    # legitimate reason a real node_id ever needs those characters.
    remote_node_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    server_name: str = Field(default="localhost", max_length=255)


@app.post("/api/replication/issue-peer-cert")
def replication_issue_peer_cert(req: IssuePeerCertRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    """The real replication peer-enrollment step (previously missing
    entirely -- found live during RC3 replication acceptance testing,
    see docs/v2/replication-real-two-node-acceptance.md): issues a cert
    signed by THIS node's own replication CA for req.remote_node_id to
    use as its client cert when connecting to THIS node. Returns
    everything the remote node's administrator needs to paste into that
    node's peer record for this one (PUT /api/replication/peers/{this
    node's id}, direction="push"): this node's ca_pem, this node's own
    server-cert fingerprint, the freshly issued client cert+key, and
    that cert's own fingerprint (issued_cert_sha256). For a real
    bidirectional relationship, call this on BOTH nodes and combine
    fields from both responses -- see replication_v2.upsert_peer's
    docstring for why expected_cert_sha256 and
    expected_incoming_cert_sha256 are two different real certificates,
    not the same value twice. Never returns this node's own CA *key* --
    only ever the issued leaf cert/key pair.
    """
    check_csrf(admin, x_csrf_token)
    if not REPLICATION_CA_PATH.exists() or not REPLICATION_SERVER_CERT_PATH.exists():
        raise ApiError(409, "replication_not_initialized", "replication TLS material not initialized on this node")
    ca_pem = REPLICATION_CA_PATH.read_text(encoding="utf-8")
    try:
        cert_pem, key_pem = replication_v2.issue_peer_client_cert(
            _secrets(), ca_pem, req.remote_node_id, server_name=req.server_name
        )
    except replication_v2.ReplicationEnrollmentError as exc:
        raise ApiError(409, "no_persisted_ca_key", str(exc))
    _ensure_extended_schemas()
    with _db() as conn:
        ident = node_identity.get_or_create(conn)
    return {
        "this_node_id": ident.node_id,
        "issued_for_node_id": req.remote_node_id,
        "ca_pem": ca_pem,
        "expected_cert_sha256": replication_v2.cert_fingerprint_sha256(REPLICATION_SERVER_CERT_PATH.read_text(encoding="utf-8")),
        "client_cert_pem": cert_pem,
        "client_key_pem": key_pem,
        "issued_cert_sha256": replication_v2.cert_fingerprint_sha256(cert_pem),
    }


# --- observed client discovery (§4C) ----------------------------------------


class ObserveClientRequest(BaseModel):
    source_ip: str
    hostname_candidate: str = ""
    hostname_source: str = "api-test"


@app.post("/api/discovery/observe")
def discovery_observe(req: ObserveClientRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    _ensure_extended_schemas()
    # Management-injected observation exists for tests and integrations; real
    # DNS workers use the same observed_clients.apply_observations path.
    with _db() as conn:
        observed_clients.apply_observations(
            conn,
            [observed_clients.Observation(req.source_ip, req.hostname_candidate, req.hostname_source, time.time())],
        )
    return {"status": "observed"}


@app.get("/api/discovery/observed-clients")
def discovery_list(limit: int = 100, offset: int = 0, search: str = "", admin=Depends(current_admin)):
    _ensure_extended_schemas()
    with _db() as conn:
        return observed_clients.list_observed(conn, limit=limit, offset=offset, search=search)


@app.get("/api/discovery/observed-clients/{source_ip}")
def discovery_detail(source_ip: str, admin=Depends(current_admin)):
    _ensure_extended_schemas()
    with _db() as conn:
        return observed_clients.get_observed(conn, source_ip)


@app.delete("/api/discovery/observed-clients/{source_ip}")
def discovery_forget(source_ip: str, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    _ensure_extended_schemas()
    with _db() as conn:
        observed_clients.forget(conn, source_ip)
    return {"status": "forgotten"}


class DiscoverySettingsUpdate(BaseModel):
    max_entries: Optional[int] = None
    expiry_days: Optional[int] = None


@app.get("/api/discovery/status")
def discovery_status(admin=Depends(current_admin)):
    _ensure_extended_schemas()
    with _db() as conn:
        return observed_clients.stats(conn)


@app.put("/api/discovery/settings")
def discovery_settings(req: DiscoverySettingsUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    _ensure_extended_schemas()
    with _db() as conn:
        observed_clients.update_settings(conn, max_entries=req.max_entries, expiry_days=req.expiry_days)
        observed_clients.enforce_retention(conn)
        return observed_clients.stats(conn)


class PromoteObservedRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=128)
    groups: list[str] = []
    policy_override: dict[str, Any] = {}


@app.post("/api/discovery/observed-clients/{source_ip}/promote")
def discovery_promote(source_ip: str, req: PromoteObservedRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    _ensure_extended_schemas()

    def _mutate(conn):
        return observed_clients.promote(
            conn,
            source_ip,
            display_name=req.display_name,
            groups=req.groups,
            policy_override=req.policy_override or None,
        )

    holder = {}
    result = _mutate_and_promote(lambda conn: holder.setdefault("client_id", _mutate(conn)))
    return {"status": "promoted", "client_id": holder["client_id"], "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


# --- migration (§32, read-only preview in this pass) ------------------------


@app.get("/api/migration/detect")
def migration_detect(source_path: str, admin=Depends(current_admin)):
    try:
        info = migration_convert.detect_source(Path(source_path))
    except migration_convert.MigrationConvertError as exc:
        raise ApiError(400, "unsupported_source", str(exc))
    return {
        "detected_version": info.detected_version,
        "classification": info.classification,
        "missing_optional": list(info.missing_optional),
        "table_count": info.table_count,
    }


# --- system status (§33) -----------------------------------------------


@app.get("/api/system/status")
def system_status(admin=Depends(current_admin)):
    import shutil as _shutil

    version_file = APP_ROOT / "VERSION"
    disk = _shutil.disk_usage(str(STATE_DIR)) if STATE_DIR.exists() else None
    return {
        "version": version_file.read_text().strip() if version_file.exists() else "unknown",
        "storage": {"total": disk.total, "used": disk.used, "free": disk.free} if disk else None,
        "compiled_runtime_present": COMPILED_DNSDIST_CONF.exists(),
    }


# --- TLS certificate management (§5, §42) -----------------------------------


class TlsReplaceRequest(BaseModel):
    certificate_pem: str
    private_key_pem: str


@app.get("/api/tls/status")
def tls_status(admin=Depends(current_admin)):
    info = tls_cert.load_active_cert_info(ACTIVE_CERT_PATH, ACTIVE_KEY_PATH)
    if info is None:
        return {"active": False}
    return {
        "active": True,
        "subject": info.subject,
        "not_valid_before": info.not_valid_before,
        "not_valid_after": info.not_valid_after,
        "san": list(info.san),
        "is_self_signed": info.is_self_signed,
    }


@app.post("/api/tls/replace")
def tls_replace(req: TlsReplaceRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    try:
        info = tls_cert.stage_validate_promote(
            req.certificate_pem.encode("utf-8"), req.private_key_pem.encode("utf-8"), ACTIVE_CERT_PATH, ACTIVE_KEY_PATH
        )
    except tls_cert.TlsCertError as exc:
        # §5: invalid replacement must not destroy the currently working
        # certificate -- stage_validate_promote() never touches the live
        # paths until validation succeeds, so nothing was changed here.
        raise ApiError(400, "invalid_certificate", str(exc))
    # §42: the running uvicorn process does not hot-reload TLS material --
    # a restart is required to actually serve the new certificate. This is
    # standard behavior for a process-level TLS listener, not a defect;
    # the promoted files are what any subsequent restart will load.
    return {
        "status": "promoted", "restart_required": True,
        "subject": info.subject, "not_valid_after": info.not_valid_after,
    }
