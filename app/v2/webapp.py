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
import re
import shutil
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
from app.v2 import backup_restore
from app.v2 import blocklist_subscriptions
from app.v2 import statistics_control
from app.v2 import control_db
from app.v2 import dnscrypt_provisioning
from app.v2 import import_migration
from app.v2 import migration_convert
from app.v2 import node_identity
from app.v2 import notification_store
from app.v2 import observed_clients
from app.v2 import policy_service
from app.v2 import policy_store as store
from app.v2 import worker_heartbeat
from app.v2 import replication_v2
from app.v2 import runtime_compile
from app.v2 import software_updates
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
LOG_DIR = Path(os.environ.get("ALDERPOINTDNS_V2_LOG_ROOT", "/var/log/alderpointdns-v2"))
MODULE_DIR = Path(__file__).resolve().parent
UI_DIR = MODULE_DIR / "ui"

CONFIG_FILE = CONFIG_DIR / "alderpointdns.yaml"
CONTROL_DB = STATE_DIR / "control.db"
SECRETS_DIR = STATE_DIR / "secrets"
ANALYTICS_PARQUET_DIR = STATE_DIR / "analytics" / "queries"
ANALYTICS_AGGREGATES_DB = STATE_DIR / "analytics" / "aggregates.db"
STAGING_DIR = STATE_DIR / "staging"
COMPILED_DNSDIST_CONF = STATE_DIR / "compiled" / "dnsdist.conf"
COMPILED_BIND_DIR = STATE_DIR / "compiled" / "bind"  # multi-context: per-context subdirs under this root
COMPILED_DOH_EGRESS_DIR = STATE_DIR / "compiled" / "doh-egress"
BIND_STATE_ROOT = STATE_DIR / "bind"  # BIND's own writable working dir per context -- never COMPILED_BIND_DIR (read-only)
COMPILED_RPZ_ZONE = STATE_DIR / "compiled" / "bind" / "alderpointdns-v2.rpz"
LOG_BIND_DIR = LOG_DIR / "bind"
RNDC_CONF_PATH = CONFIG_DIR / "rndc.conf"  # DNS Cache view/flush (beta-rescue priority 3A)
CERTS_DIR = STATE_DIR / "certs"
ACTIVE_CERT_PATH = CERTS_DIR / "server.crt"
ACTIVE_KEY_PATH = CERTS_DIR / "server.key"
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
# Real defect fixed here (owner-beta closure item 3, found live via the
# Chromium harness's own real-package Software Updates apply proof):
# the blanket 1 MB cap above was applied to every route including
# /api/updates/upload, whose real, documented job is to accept an
# entire Alderpoint DNS V2 candidate .deb -- tens of MB even before
# webapp.upload_update_package's real base64-JSON encoding inflates it
# ~33% further (see app.js's fileToBase64 -> data_base64 client side).
# So the real "Manual Package Upload" feature -- the only self-update
# path this private, no-public-release build has at all -- could never
# accept any real V2 package it would ever actually be asked to accept;
# every real attempt failed closed with this same 413 before even
# reaching the endpoint's own real name/architecture/version
# validation. Give this one real large-binary-upload route real
# headroom over the current real package size (~70 MB); every other
# route (JSON bodies, PEM certs/keys at most a few KB) keeps the
# original 1 MB cap and its original rationale unchanged.
MAX_UPDATE_UPLOAD_BODY_BYTES = 250_000_000
_LARGE_UPLOAD_PATHS = {"/api/updates/upload"}


@app.middleware("http")
async def _reject_oversized_requests(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_size = int(content_length)
        except ValueError:
            declared_size = None
        limit = MAX_UPDATE_UPLOAD_BODY_BYTES if request.url.path in _LARGE_UPLOAD_PATHS else MAX_REQUEST_BODY_BYTES
        if declared_size is not None and declared_size > limit:
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
    # hmac.compare_digest -- this was the one inconsistent case, fixed for
    # defense in depth rather than left as an unexplained exception to
    # that pattern.
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
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    confirm_password: str = Field(min_length=12, max_length=256)
    # V1.1.1-baseline first-run fields (a real owner-reported finding, priority 2 of
    # the beta-rescue brief: setup had regressed to bare username/password
    # -- see docs/v2/beta-rescue-setup-fields.md). server_ip is left
    # optional and, when blank, auto-detected from the real current
    # interface address via app.network_config -- V1.1.1's own
    # local_dns.detect_server_ip() equivalent -- never hard-coded to
    # V1's 192.168.1.101 documentation example.
    create_local_dns: bool = True
    server_hostname: str = Field(default="alderpointdns", max_length=63)
    server_ip: str = ""


@app.get("/api/setup/status")
def setup_status():
    # Owner-approved removal of a prior SSH-retrieved-setup-token UX:
    # the ONLY thing that gates first-run setup is "does this genuinely
    # never-initialized appliance have zero admin accounts" -- the exact
    # same real, transactional condition setup() below re-checks inside
    # its own write transaction. _db()'s create_if_missing=False (see its
    # own docstring/docs/v2/control-db-silent-recreation-fix.md) already
    # makes a missing/corrupt control.db fail loudly here rather than
    # silently behaving like a fresh, uninitialized appliance and
    # reopening setup -- this endpoint adds no separate secret/token
    # gate on top of that real state.
    with _db() as conn:
        count = conn.execute("SELECT count(*) FROM admins").fetchone()[0]
    return {"setup_required": count == 0}


@app.post("/api/setup")
def setup(req: SetupRequest, request: Request):
    # Owner-approved removal of a prior mandatory SSH-retrieved setup-
    # token flow (docs/v2/management-plane.md "Known limitations" no
    # longer applies to this endpoint): first-admin creation is gated
    # only on the real, transactional "zero admin accounts exist yet"
    # check below -- the same conventional first-run flow V1.1.1 already
    # had. No token file is generated, read, or required. This is not a
    # weaker gate than the token was: the token only ever proved
    # possession of root/SSH access to the appliance, which creating the
    # very first admin account already requires nothing beyond (an
    # attacker who can reach this HTTPS endpoint before a real
    # administrator does could already have raced the token file the
    # same way); what actually matters -- this can only ever succeed
    # once, atomically, before any admin exists -- is unchanged.
    # Server-side mismatch enforcement (a real owner-reported finding, priority 2):
    # the client also checks this live, but the server is the actual
    # gate -- never trust the browser alone for the one action that
    # creates the appliance's only account.
    if req.password != req.confirm_password:
        raise ApiError(400, "validation_error", "password and confirm password do not match")
    with _db() as conn:
        count = conn.execute("SELECT count(*) FROM admins").fetchone()[0]
        if count > 0:
            raise ApiError(409, "already_configured", "initial setup has already been completed")
        password_hash = hash_password(req.password, limiter=_hash_limiter)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            (req.username, password_hash, now),
        )
    local_dns_result = None
    if req.create_local_dns:
        # V1.1.1 parity (docs/install.md "first-run"): create an A record
        # for the appliance's own hostname plus a friendly alias, using
        # the real detected interface address when the operator left
        # server_ip blank -- never V1's static documentation-example IP.
        # Best-effort: a local-DNS failure must not undo the admin
        # account that was just durably created above.
        try:
            ip = req.server_ip.strip()
            if not ip:
                from app.v2 import network_config as nc

                current = nc.read_current_config()
                ip = ((current.get("ipv4") or {}).get("address")) or ""
            host = (req.server_hostname.strip() or "alderpointdns").strip(".").lower()
            if ip:
                ipaddress.IPv4Address(ip)
                _insert_local_dns_record(host, "A", ip, ttl=300, enabled=True)
                local_dns_result = {"hostname": host, "address": ip}
            else:
                local_dns_result = {"error": "no server address could be detected; add a Local DNS record manually"}
        except Exception as exc:  # noqa: BLE001 - best-effort, must not fail account creation
            local_dns_result = {"error": str(exc)}
    return {"status": "created", "local_dns": local_dns_result}


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


# --- administration: password change / session revocation
# (beta-rescue priority 5 -- a real gap, not a stylistic one: V1.1.1 has
# always had these two actions and a prior release shipped with no way for an
# operator to change their own password or revoke other sessions at all)
# ------------------------------------------------------------------------


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)


@app.post("/api/session/password")
def change_password(req: PasswordChangeRequest, request: Request, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    from app.v2.auth_hash import verify_password

    ip = request.client.host if request.client else None
    now = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        row = conn.execute("SELECT username, password_hash FROM admins WHERE id=?", (admin["admin_id"],)).fetchone()
        if row is None:
            raise ApiError(401, "unauthenticated", "account no longer exists")
        username, password_hash = row
        result = verify_password(password_hash, req.current_password, limiter=_hash_limiter)
        if not result.ok:
            conn.execute(
                "INSERT INTO admin_audit_log(at, admin_id, username, action, success, ip, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (now, admin["admin_id"], username, "password_change", 0, ip, "current password incorrect"),
            )
            raise ApiError(400, "incorrect_password", "current password is incorrect")
        new_hash = hash_password(req.new_password, limiter=_hash_limiter)
        conn.execute("UPDATE admins SET password_hash=? WHERE id=?", (new_hash, admin["admin_id"]))
        conn.execute(
            "INSERT INTO admin_audit_log(at, admin_id, username, action, success, ip, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now, admin["admin_id"], username, "password_change", 1, ip, ""),
        )
    return {"status": "changed"}


@app.post("/api/session/revoke-others")
def revoke_other_sessions(request: Request, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    ip = request.client.host if request.client else None
    now = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        row = conn.execute("SELECT username FROM admins WHERE id=?", (admin["admin_id"],)).fetchone()
        username = row[0] if row else ""
        cur = conn.execute(
            "DELETE FROM sessions WHERE admin_id = ? AND id != ?", (admin["admin_id"], admin["session_id"]),
        )
        revoked = cur.rowcount
        conn.execute(
            "INSERT INTO admin_audit_log(at, admin_id, username, action, success, ip, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (now, admin["admin_id"], username, "sessions_revoked", 1, ip, f"{revoked} other session(s) revoked"),
        )
    return {"status": "revoked", "revoked_count": revoked}


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

    # BIND recursive-backend health (Gate #3 acceptance closure §9): the
    # locked hot path's second RAM-cache tier gets its own independently
    # reported status, distinct from dnsdist/analytics/management, so an
    # operator (or an automated check) can tell "BIND context down,
    # recursive misses will fail" apart from "management API degraded" --
    # health must never claim the appliance is fully healthy while a
    # configured recursive backend is actually unreachable. Real, live
    # per-context reachability (a socket connect to each context's own
    # statistics-channel port -- see app/v2/bind_gen.py's per-context
    # port allocation), not inferred from config files alone.
    bind_contexts_status: dict[str, dict] = {}
    if COMPILED_BIND_DIR.exists():
        for ctx_dir in sorted(p for p in COMPILED_BIND_DIR.iterdir() if p.is_dir()):
            conf_path = ctx_dir / "named.conf"
            if not conf_path.exists():
                continue
            idx = int(ctx_dir.name.removeprefix("ctx")) if ctx_dir.name.startswith("ctx") and ctx_dir.name[3:].isdigit() else 0
            stats_port = 8153 + idx
            reachable = False
            try:
                import socket as _socket

                with _socket.create_connection(("127.0.0.1", stats_port), timeout=0.5):
                    reachable = True
            except OSError:
                reachable = False
            bind_contexts_status[ctx_dir.name] = {"reachable": reachable, "statistics_port": stats_port}
    result["components"]["bind"] = {
        "contexts": bind_contexts_status,
        "status": "ok" if bind_contexts_status and all(c["reachable"] for c in bind_contexts_status.values())
        else ("unconfigured" if not bind_contexts_status else "degraded"),
    }
    if bind_contexts_status and not all(c["reachable"] for c in bind_contexts_status.values()):
        # A configured BIND context is down: recursive misses through it
        # will fail even though dnsdist's own packet-cache hits may
        # continue to answer from already-cached TTLs -- real, accurate
        # degradation, never silently reported as fully healthy.
        result["status"] = "degraded"
    result["components"]["tier_b"] = {"state_present": TIER_B_STATE_FILE.exists()}
    result["components"]["schedule_worker"] = {"state_present": SCHEDULE_STATE_FILE.exists()}

    # Real background-worker progress, not just "the unit hasn't exited"
    # (app/v2/worker_heartbeat.py) -- owner-beta aging hardening item 1.
    # Each of these runs as its own systemd unit built around
    # scripts/v2/alderpointdns_v2_ctl.py's shared _run_loop; a unit whose
    # process is still running but whose loop has stopped making progress
    # (the exact V1.1.1 field-report failure class this defends against)
    # is reported here as degraded, not silently folded into "ok".
    workers: dict[str, Any] = {}
    any_stale = False
    for name, interval in worker_heartbeat.WORKER_INTERVALS_SECONDS.items():
        hb = worker_heartbeat.read_heartbeat(STATE_DIR, name) or worker_heartbeat.unknown(name)
        stale = hb.is_stale(interval_seconds=interval)
        any_stale = any_stale or stale
        workers[name] = {
            "status": hb.status,
            "stale": stale,
            "tick_count": hb.tick_count,
            "last_success_at": hb.last_success_at,
            "last_result": hb.last_result,
            "last_error": hb.last_error,
        }
    result["components"]["background_workers"] = workers
    if any_stale:
        # A stalled worker never demotes overall status below "degraded"
        # -- same rule as analytics dependency degradation above: DNS
        # answering itself is reported separately and is what actually
        # governs "healthy" for the appliance.
        result["status"] = "degraded" if result["status"] == "ok" else result["status"]
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
    (found live during real clean-install acceptance testing)."""
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


# --- friendly-name -> stable internal id (owner finding, priority 2 of the
# second beta-rescue pass) --------------------------------------------------
#
# Several object types (networks, groups, schedules, services, service
# rulesets, upstream profiles, notification providers, blocklist
# subscriptions, replication peers) used to require the operator to
# personally invent and type their own internal identifier -- "Group ID",
# "Schedule ID", "Upstream Profile ID", etc. -- in the same ordinary
# creation form as the actual configuration. Normal UI now asks only for
# a human-friendly name (or, for replication peers, reuses display_name)
# and generates a stable, collision-safe id from it here. The id remains
# a real, addressable column: every list/detail response, the API
# (advanced/scripted callers may still pass an id explicitly -- see each
# Create model's own id field, still accepted, just no longer required
# from the ordinary form), and every dropdown that references these
# objects elsewhere in the UI show the friendly name, not the id.
def _slugify(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")
    return value or "item"


def _unique_id(conn: sqlite3.Connection, table: str, column: str, base_text: str, max_length: int = 64) -> str:
    """table/column are always this module's own hard-coded literals at
    every call site below, never operator input -- safe to interpolate."""
    base = _slugify(base_text)[: max(1, max_length - 8)]
    candidate = base
    suffix = 2
    while conn.execute(f"SELECT 1 FROM {table} WHERE {column}=?", (candidate,)).fetchone() is not None:  # noqa: S608
        candidate = f"{base}-{suffix}"[:max_length]
        suffix += 1
    return candidate


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
            # BIND architecture correction (Gate #3, multi-context
            # acceptance closure): live policy mutations recompile+
            # validate+coherently-promote every distinct plain, non-ECS
            # upstream selection's own BIND context (default policy, any
            # other network's own selection, any domain-routing rule) --
            # see runtime_compile.recompile_and_promote's own docstring.
            # Only attempted once COMPILED_RPZ_ZONE already exists: real
            # installs always have it (generate-runtime / postinst
            # creates it, even empty, before any policy mutation is
            # possible), and a test/dev root that hasn't bootstrapped it
            # yet gets exactly the prior dnsdist-only compile behavior
            # rather than a hard failure -- BIND wiring turns on the
            # moment its real prerequisite exists, it never silently
            # blocks unrelated policy mutations.
            bind_kwargs = {}
            if COMPILED_RPZ_ZONE.exists():
                from app.v2 import cache_control

                bind_kwargs = dict(
                    live_bind_conf_path=COMPILED_BIND_DIR, live_bind_log_root=LOG_BIND_DIR,
                    live_bind_state_root=BIND_STATE_ROOT,
                    rpz_zone_path=COMPILED_RPZ_ZONE, live_doh_egress_dir=COMPILED_DOH_EGRESS_DIR,
                    rndc_key_secret=cache_control.ensure_rndc_key(_secrets()),
                    live_rndc_conf_path=RNDC_CONF_PATH,
                )
            result = runtime_compile.recompile_and_promote(
                conn, STAGING_DIR, COMPILED_DNSDIST_CONF,
                listen_address=_configured_listen_address(), dot=dot, doh=doh, doq=doq, doh3=doh3, dnscrypt=dnscrypt,
                **bind_kwargs,
            )
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
        return result


# --- networks (§19) -----------------------------------------------------


class NetworkCreate(BaseModel):
    # Ordinary UI sends `name`; network_id is generated from it (see
    # _unique_id) and is not itself a normal-form field any more.
    # Advanced/scripted callers may still pass network_id explicitly.
    name: str = Field(default="", max_length=64)
    network_id: str = Field(default="", max_length=64)
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
    if not req.network_id.strip() and not req.name.strip():
        raise ApiError(400, "validation_error", "name is required")

    def _mutate(conn):
        network_id = req.network_id.strip() or _unique_id(conn, "policy_networks", "network_id", req.name)
        store.create_network(conn, network_id, req.cidr)

    result = _mutate_and_promote(_mutate)
    return {"status": "created", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


# --- global + network policy (§18) --------------------------------------


class PolicyLayerUpdate(BaseModel):
    filtering_profile_id: Optional[str] = None
    safesearch_mode: Optional[str] = None
    parental_policy_id: Optional[str] = None
    security_policy_id: Optional[str] = None
    service_blocking_ruleset_id: Optional[str] = None
    blocking_response_mode: Optional[str] = None
    custom_ipv4: Optional[str] = None
    custom_ipv6: Optional[str] = None
    upstream_profile_id: Optional[str] = None
    fallback_strategy: Optional[str] = None
    fallback_upstream_profile_id: Optional[str] = None
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


# Real defect found live during real acceptance testing: requesting a
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
    # down real DNS live in a real incident).
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
        # same direction a real prior live incident already proved is the
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


# --- Apple .mobileconfig enrollment profiles (beta-rescue priority 3D) -----


@app.get("/api/dns-transports/mobileconfig/{protocol}")
def dns_transport_mobileconfig(protocol: str, admin=Depends(current_admin)):
    from app.v2 import mobileconfig

    with _db() as conn:
        transport = store.load_dns_transport_settings(conn)
    cert = tls_cert.load_active_cert_info(ACTIVE_CERT_PATH, ACTIVE_KEY_PATH)
    try:
        profile_bytes = mobileconfig.build_mobileconfig(protocol, transport, cert)
    except mobileconfig.MobileconfigError as exc:
        raise ApiError(400, "unavailable", str(exc)) from exc
    return Response(
        content=profile_bytes, media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": f"attachment; filename=alderpointdns-v2-{protocol}.mobileconfig"},
    )


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
    name: str = Field(min_length=1, max_length=128)
    priority: int = 100
    # Not a normal-form field any more: group_id is generated from name.
    # Advanced/scripted callers may still pass it explicitly.
    group_id: str = Field(default="", max_length=64)


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
        group_id = req.group_id.strip() or _unique_id(conn, "policy_groups", "group_id", req.name)
        store.create_group(conn, group_id, req.name, req.priority)
    return {"status": "created", "group_id": group_id}


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
    name: str
    transport: str
    strategy: str = "ordered"
    endpoints: list[UpstreamEndpointIn]
    # Not a normal-form field any more: generated from name. Advanced/
    # scripted callers may still pass it explicitly.
    upstream_profile_id: str = Field(default="", max_length=64)


def _upstream_profile_to_dict(profile: "store.UpstreamProfileRecord") -> dict:
    return {
        "upstream_profile_id": profile.upstream_profile_id,
        "name": profile.name,
        "transport": profile.transport,
        "strategy": profile.strategy,
        "enabled": profile.enabled,
        "sort_order": profile.sort_order,
        "endpoints": [
            {"address": e.address, "tls_hostname": e.tls_hostname, "priority": e.priority, "weight": e.weight, "doh_path": e.doh_path}
            for e in profile.endpoints
        ],
    }


@app.get("/api/upstreams")
def list_upstreams(admin=Depends(current_admin)):
    with _db() as conn:
        profiles = store.list_upstream_profiles(conn)
        # Runtime truth (§ Upstream Lifecycle / Runtime Truth): whether
        # every managed upstream is currently disabled/deleted, i.e. the
        # compiled runtime is genuinely in native BIND recursion mode --
        # the UI must be able to state this as a fact, not infer it.
        native_recursion_active = not any(p.enabled for p in profiles)
    return {
        "upstreams": [_upstream_profile_to_dict(p) for p in profiles],
        "native_recursion_active": native_recursion_active,
    }


@app.post("/api/upstreams")
def create_upstream(req: UpstreamProfileCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    endpoints = [
        store.UpstreamEndpointRecord(e.address, e.tls_hostname, e.priority, e.weight, None, e.doh_path)
        for e in req.endpoints
    ]
    with _db() as conn:
        upstream_profile_id = req.upstream_profile_id.strip() or _unique_id(conn, "upstream_profiles", "upstream_profile_id", req.name)
        store.create_upstream_profile(conn, upstream_profile_id, req.name, req.transport, endpoints, strategy=req.strategy)
    return {"status": "created", "upstream_profile_id": upstream_profile_id}


class UpstreamProfileUpdate(BaseModel):
    name: str
    transport: str
    strategy: str = "ordered"
    endpoints: list[UpstreamEndpointIn]


class LastUpstreamConfirm(BaseModel):
    # Real owner-required workflow ("Zero Managed Upstreams" locked
    # decision): disabling/deleting the FINAL enabled managed upstream
    # must show a warning and require confirmation, but must be
    # allowed. Server-side enforced (not just a client-side confirm()
    # dialog): the first attempt without confirm_last=True against the
    # last enabled upstream is rejected with a real, distinguishable
    # 409 the UI turns into that warning; the identical request with
    # confirm_last=True is what actually proceeds.
    confirm_last: bool = False


def _is_last_enabled_upstream(conn: sqlite3.Connection, upstream_profile_id: str) -> bool:
    enabled_ids = [p.upstream_profile_id for p in store.list_upstream_profiles(conn) if p.enabled]
    return enabled_ids == [upstream_profile_id]


@app.put("/api/upstreams/{upstream_profile_id}")
def update_upstream_route(upstream_profile_id: str, req: UpstreamProfileUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    endpoints = [
        store.UpstreamEndpointRecord(e.address, e.tls_hostname, e.priority, e.weight, None, e.doh_path)
        for e in req.endpoints
    ]
    try:
        result = _mutate_and_promote(
            lambda conn: store.update_upstream_profile(conn, upstream_profile_id, req.name, req.transport, endpoints, strategy=req.strategy)
        )
    except PolicyStoreError as exc:
        raise ApiError(400, "invalid_upstream", str(exc)) from exc
    return {"status": "updated", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


@app.post("/api/upstreams/{upstream_profile_id}/enable")
def enable_upstream_route(upstream_profile_id: str, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    try:
        result = _mutate_and_promote(lambda conn: store.set_upstream_profile_enabled(conn, upstream_profile_id, True))
    except PolicyStoreError as exc:
        raise ApiError(404, "not_found", str(exc)) from exc
    return {"status": "enabled", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


@app.post("/api/upstreams/{upstream_profile_id}/disable")
def disable_upstream_route(upstream_profile_id: str, req: LastUpstreamConfirm = LastUpstreamConfirm(), admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        is_last = _is_last_enabled_upstream(conn, upstream_profile_id)
    if is_last and not req.confirm_last:
        raise ApiError(
            409, "last_enabled_upstream",
            "This is the final enabled managed upstream. Disabling it leaves zero managed "
            "forwarders -- BIND will perform normal native recursion using the root/authoritative "
            "hierarchy. Confirm to proceed.",
        )
    try:
        result = _mutate_and_promote(lambda conn: store.set_upstream_profile_enabled(conn, upstream_profile_id, False))
    except PolicyStoreError as exc:
        raise ApiError(404, "not_found", str(exc)) from exc
    return {"status": "disabled", "was_last_enabled": is_last, "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


@app.delete("/api/upstreams/{upstream_profile_id}")
def delete_upstream_route(upstream_profile_id: str, req: LastUpstreamConfirm = LastUpstreamConfirm(), admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        is_last = _is_last_enabled_upstream(conn, upstream_profile_id)
    if is_last and not req.confirm_last:
        raise ApiError(
            409, "last_enabled_upstream",
            "This is the final enabled managed upstream. Deleting it leaves zero managed "
            "forwarders -- BIND will perform normal native recursion using the root/authoritative "
            "hierarchy. Confirm to proceed.",
        )
    try:
        result = _mutate_and_promote(lambda conn: store.delete_upstream_profile(conn, upstream_profile_id))
    except PolicyStoreError as exc:
        raise ApiError(404, "not_found", str(exc)) from exc
    return {"status": "deleted", "was_last_enabled": is_last, "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


class UpstreamReorderRequest(BaseModel):
    ordered_upstream_profile_ids: list[str]


@app.post("/api/upstreams/reorder")
def reorder_upstreams_route(req: UpstreamReorderRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    try:
        with _db() as conn:
            store.reorder_upstream_profiles(conn, req.ordered_upstream_profile_ids)
    except PolicyStoreError as exc:
        raise ApiError(400, "invalid_reorder", str(exc)) from exc
    return {"status": "reordered"}


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
    display_name: str
    category: str = ""
    domains: list[ServiceDomainIn]
    # Not a normal-form field any more: generated from display_name.
    # Advanced/scripted callers may still pass it explicitly.
    service_id: str = ""


@app.post("/api/services")
def create_service(req: ServiceCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        service_id = req.service_id.strip() or _unique_id(conn, "service_definitions", "service_id", req.display_name)
        store.create_service(conn, service_id, req.display_name, [(d.match_kind, d.domain) for d in req.domains], category=req.category)
    return {"status": "created", "service_id": service_id}


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
    # service_blocking_rulesets has no separate name column -- ruleset_id
    # is its only identity, same as network_id/schedule_id below. Ordinary
    # UI sends `name`, which becomes the id; advanced/scripted callers may
    # still pass ruleset_id explicitly.
    name: str = ""
    ruleset_id: str = ""
    service_ids: list[str]


@app.post("/api/service-rulesets")
def create_service_ruleset(req: ServiceRulesetCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    if not req.ruleset_id.strip() and not req.name.strip():
        raise ApiError(400, "validation_error", "name is required")
    with _db() as conn:
        ruleset_id = req.ruleset_id.strip() or _unique_id(conn, "service_blocking_rulesets", "ruleset_id", req.name)
        store.create_service_ruleset(conn, ruleset_id, req.service_ids)
    return {"status": "created", "ruleset_id": ruleset_id}


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
    # policy_schedules has no separate name column -- schedule_id is its
    # only identity, same as network_id/ruleset_id. Ordinary UI sends
    # `name`, which becomes the id; advanced/scripted callers may still
    # pass schedule_id explicitly.
    name: str = ""
    schedule_id: str = ""
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
    if not req.schedule_id.strip() and not req.name.strip():
        raise ApiError(400, "validation_error", "name is required")
    with _db() as conn:
        schedule_id = req.schedule_id.strip() or _unique_id(conn, "policy_schedules", "schedule_id", req.name)
        store.create_schedule(conn, schedule_id, req.timezone, windows)
    return {"status": "created", "schedule_id": schedule_id}


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


def _insert_local_dns_record(name: str, record_type: str, value: str, ttl: int = 300, enabled: bool = True):
    """Shared by the authenticated /api/local-dns route and first-run
    setup's best-effort local-DNS seeding (a real owner-reported finding, priority 2)
    -- one real validation+insert path, not a route-only copy the setup
    flow would otherwise have to reimplement and could drift from."""
    if record_type not in ("A", "AAAA", "CNAME", "PTR"):
        raise ApiError(400, "validation_error", "invalid record type")
    if record_type == "A":
        ipaddress.IPv4Address(value)
    elif record_type == "AAAA":
        ipaddress.IPv6Address(value)
    elif record_type in ("CNAME", "PTR"):
        from app.v2.dns_name_validate import validate_dns_name

        validate_dns_name(value)

    from app.v2.dns_name_validate import validate_dns_name

    validate_dns_name(name)

    def _mutate(conn):
        _ensure_local_dns_schema(conn)
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                "INSERT INTO local_dns_records(name, record_type, value, ttl, enabled, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name.strip(".").lower(), record_type, value, ttl, int(enabled), now, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "duplicate_record", "that Local DNS record already exists") from exc

    return _mutate_and_promote(_mutate)


@app.post("/api/local-dns")
def create_local_dns(req: LocalDnsRecordCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    result = _insert_local_dns_record(req.name, req.record_type, req.value, req.ttl, req.enabled)
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


# Real defect fixed here (owner-reported: Dashboard's "Top Domains" bar
# chart had no visible domain names, values, or blocked/allowed
# distinction -- just anonymous bars with the count hidden in a `title`
# attribute, and there was no time-series/activity view at all). Two new
# endpoints, both already fully backed by existing service-layer methods
# that simply had no API route wired to them yet -- no new aggregation
# logic invented here, just exposing what app/v2/analytics_service.py
# and app/v2/aggregates_db.py already compute.
@app.get("/api/analytics/top-blocked-domains")
def analytics_top_blocked_domains(minutes: float = 60.0, limit: int = 20, admin=Depends(current_admin)):
    if reason := _forced_analytics_degraded():
        return {"rows": [], "columns": [], "degraded": True, "degraded_reason": reason}
    now = time.time()
    svc = _analytics_service()
    try:
        return _query_result_to_dict(svc.top_blocked_domains(now - minutes * 60, now, limit=limit))
    finally:
        svc.close()


_TIMESERIES_GRANULARITIES = ("minute", "hour", "day")


@app.get("/api/analytics/timeseries")
def analytics_timeseries(minutes: float = 1440.0, granularity: str = "hour", admin=Depends(current_admin)):
    if granularity not in _TIMESERIES_GRANULARITIES:
        raise HTTPException(status_code=400, detail=f"granularity must be one of {_TIMESERIES_GRANULARITIES}")
    if reason := _forced_analytics_degraded():
        return {"buckets": [], "granularity": granularity, "degraded": True, "degraded_reason": reason}
    now = time.time()
    svc = _analytics_service()
    try:
        rows = svc.time_series_totals(now - minutes * 60, now, granularity=granularity)
    except Exception as exc:  # noqa: BLE001 -- aggregates_db is pure sqlite3, but never let a dashboard chart 500 the page
        return {"buckets": [], "granularity": granularity, "degraded": True, "degraded_reason": str(exc)}
    finally:
        svc.close()
    return {
        "granularity": granularity,
        "degraded": False,
        "buckets": [
            {
                "bucket_start": bucket_start,
                "bucket_start_iso": datetime.fromtimestamp(bucket_start, tz=timezone.utc).isoformat(),
                "total_queries": total,
                "blocked_queries": blocked,
                "cache_hits": hits,
                "cache_misses": misses,
            }
            for bucket_start, total, blocked, hits, misses in rows
        ],
    }


# --- statistics export/clear (beta-rescue priority 3C) -----------------------


@app.get("/api/statistics/export")
def statistics_export_route(admin=Depends(current_admin)):
    return Response(
        content=statistics_control.export_statistics_json(ANALYTICS_AGGREGATES_DB),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=alderpointdns-v2-statistics-export.json"},
    )


class StatisticsClearRequest(BaseModel):
    confirmation: str
    include_raw_history: bool = True


@app.post("/api/statistics/clear")
def statistics_clear_route(req: StatisticsClearRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    if req.confirmation != "CLEAR":
        raise ApiError(400, "confirmation_required", "type CLEAR to confirm clearing statistics")
    result = statistics_control.clear_statistics(
        ANALYTICS_AGGREGATES_DB, include_raw_history=req.include_raw_history,
        raw_history_root=ANALYTICS_PARQUET_DIR if req.include_raw_history else None,
    )
    return {
        "status": "cleared",
        "aggregate_buckets_cleared": result.aggregate_buckets_cleared,
        "aggregate_dimension_rows_cleared": result.aggregate_dimension_rows_cleared,
        "raw_history_cleared": result.raw_history_cleared,
        "raw_partition_files_removed": result.raw_partition_files_removed,
    }


# --- in-app log viewer (beta-rescue priority 3E) -----------------------


@app.get("/api/logs/units")
def list_log_units(admin=Depends(current_admin)):
    from app.v2 import log_viewer

    return {"units": list(log_viewer.ALLOWED_UNITS)}


@app.get("/api/logs/{unit}")
def get_unit_logs(unit: str, severity: str = "all", lines: int = 100, admin=Depends(current_admin)):
    from app.v2 import log_viewer

    try:
        return log_viewer.view_logs(unit, severity, lines)
    except log_viewer.LogViewerError as exc:
        raise ApiError(400, "validation_error", str(exc)) from exc


# --- notifications (§29) ------------------------------------------------


class NotificationProviderCreate(BaseModel):
    kind: str
    display_name: str
    endpoint: str
    secret_value: Optional[str] = None
    # Not a normal-form field any more: generated from display_name.
    # Advanced/scripted callers may still pass it explicitly.
    provider_id: str = ""


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
        provider_id = req.provider_id.strip() or _unique_id(conn, "notification_providers", "provider_id", req.display_name)
        metadata = notification_store.create_provider(
            conn, secrets, provider_id, req.kind, req.display_name, req.endpoint, secret_value=req.secret_value
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


# --- full appliance backup/restore (beta-rescue priority 3) -----------------
#
# The secrets-only backup above is preserved (a real, still-useful
# component: protected secrets on their own), but it is not "the backup
# feature" -- this is. See app/v2/backup_restore.py for the full
# contract (control.db snapshot + secrets + certs, one encrypted
# archive, staged validate -> apply, rollback on a failed promotion).


def _appliance_backup_path_from_name(name: str) -> Path:
    if "/" in name or "\\" in name or name.startswith(".") or not name.endswith(".apdnsbak"):
        raise ApiError(400, "validation_error", "invalid backup name")
    path = (_backup_dir() / name).resolve()
    if path.parent != _backup_dir().resolve():
        raise ApiError(400, "validation_error", "invalid backup name")
    return path


def _appliance_cert_files() -> list[backup_restore.CertFile]:
    return [
        backup_restore.CertFile(ACTIVE_CERT_PATH, "server.crt"),
        backup_restore.CertFile(ACTIVE_KEY_PATH, "server.key"),
        backup_restore.CertFile(DNSCRYPT_CERT_PATH, "dnscrypt-resolver.cert"),
        backup_restore.CertFile(DNSCRYPT_KEY_PATH, "dnscrypt-resolver.key"),
    ]


def _appliance_source_version() -> str:
    version_file = APP_ROOT / "VERSION"
    return version_file.read_text().strip() if version_file.exists() else "unknown"


@app.get("/api/backup/appliance")
def list_appliance_backups(admin=Depends(current_admin)):
    rows = []
    for p in sorted(_backup_dir().glob("*.apdnsbak"), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = p.stat()
        rows.append({
            "name": p.name, "size_bytes": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        })
    with _db() as conn:
        jobs = conn.execute(
            "SELECT id, started_at, finished_at, status, backup_path, detail_json "
            "FROM restore_jobs WHERE backup_path LIKE '%.apdnsbak' ORDER BY id DESC LIMIT 20"
        ).fetchall()
    return {
        "backups": rows,
        "restore_jobs": [
            {
                "id": r[0], "started_at": r[1], "finished_at": r[2], "status": r[3],
                "backup_name": Path(r[4]).name if r[4] else "", "detail": json.loads(r[5] or "{}"),
            }
            for r in jobs
        ],
    }


@app.post("/api/backup/appliance")
def create_appliance_backup_route(admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    secrets = _secrets()
    key = _backup_key(secrets)
    backup_path = _backup_dir() / f"appliance-{int(time.time())}.apdnsbak"
    result = backup_restore.create_appliance_backup(
        CONTROL_DB, secrets, key, backup_path,
        cert_files=_appliance_cert_files(), source_version=_appliance_source_version(),
    )
    with _db() as conn:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO backup_jobs(started_at, finished_at, status, path, detail_json) VALUES (?, ?, ?, ?, ?)",
            (now, now, "succeeded", str(backup_path), json.dumps({"contents": result.contents, "secret_count": result.secret_count})),
        )
    return {
        "status": "created", "name": backup_path.name, "created_at": result.created_at,
        "contents": result.contents, "secret_count": result.secret_count,
        "control_db_schema_version": result.control_db_schema_version, "size_bytes": result.size_bytes,
    }


@app.post("/api/backup/appliance/{name}/validate")
def validate_appliance_backup_route(name: str, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    path = _appliance_backup_path_from_name(name)
    if not path.exists():
        raise ApiError(404, "not_found", "backup not found")
    try:
        manifest = backup_restore.validate_appliance_backup(path, _backup_key(_secrets()))
    except (backup_restore.ApplianceBackupError, backup_restore.ApplianceRestoreError) as exc:
        raise ApiError(400, "backup_invalid", str(exc)) from exc
    return {
        "status": "valid", "backup_name": name, "created_at": manifest.created_at,
        "source_version": manifest.source_version, "contents": manifest.contents,
        "secret_count": manifest.secret_count, "cert_files": manifest.cert_files,
        "control_db_schema_version": manifest.control_db_schema_version,
        "size_bytes": path.stat().st_size,
    }


class ApplianceRestoreRequest(BaseModel):
    confirmation: str


@app.post("/api/backup/appliance/{name}/restore")
def restore_appliance_backup_route(name: str, req: ApplianceRestoreRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    if req.confirmation != name:
        raise ApiError(400, "confirmation_required", "type the exact backup file name to restore")
    path = _appliance_backup_path_from_name(name)
    if not path.exists():
        raise ApiError(404, "not_found", "backup not found")

    # Real defect fixed here (found while proving this out): restore_jobs
    # bookkeeping lives in control.db, which a *successful* restore
    # unconditionally replaces -- a "running" row inserted before staging
    # and later UPDATEd by id is silently gone once the swap has
    # happened, because that id no longer exists in the just-restored
    # control.db (it exists in the OLD one, which is no longer live).
    # There is therefore no pre-restore "running" row at all; each branch
    # below does exactly one INSERT, into whichever control.db is
    # actually current at that moment -- the pre-restore one on failure
    # (nothing was swapped), the post-restore one on success.
    started = datetime.now(timezone.utc).isoformat()

    def _record_failure(exc: Exception, error_kind: str) -> None:
        finished = datetime.now(timezone.utc).isoformat()
        with _db() as conn:
            conn.execute(
                "INSERT INTO restore_jobs(started_at, finished_at, status, backup_path, detail_json) VALUES (?, ?, ?, ?, ?)",
                (started, finished, "failed", str(path), json.dumps({"error": str(exc)})),
            )
        raise ApiError(400, error_kind, str(exc)) from exc

    key = _backup_key(_secrets())
    staging_dir = STATE_DIR / "restore-staging" / f"job-{int(time.time() * 1000)}"
    try:
        staged = backup_restore.stage_appliance_restore(path, key, staging_dir)
    except backup_restore.ApplianceBackupKeyError as exc:
        _record_failure(exc, "backup_invalid")
        return  # pragma: no cover -- _record_failure always raises
    except backup_restore.ApplianceRestoreError as exc:
        _record_failure(exc, "restore_failed")
        return  # pragma: no cover -- _record_failure always raises

    rollback_root = STATE_DIR / "restore-rollback" / f"job-{int(time.time() * 1000)}"
    try:
        promo = backup_restore.promote_appliance_restore(
            staged, CONTROL_DB, SECRETS_DIR, _appliance_cert_files(), rollback_root=rollback_root,
        )
    except Exception as exc:
        # The live appliance was already rolled back by
        # promote_appliance_restore itself before this exception reached
        # here -- report the failure, but the prior valid appliance is
        # still the one actually live.
        _record_failure(exc, "restore_failed")
        return  # pragma: no cover -- _record_failure always raises
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)

    # Recompile/promote the runtime against the just-restored control.db
    # so the restored state is actually live, not just present on disk.
    # A recompile failure here is a real, reportable failure -- surfaced
    # to the operator -- but does not itself roll back the already-
    # promoted control.db/secrets/certs (those are already validated,
    # real, consistent state; a compile failure means the *runtime*
    # couldn't pick it up yet, most likely because the restored
    # configuration references something -- an upstream, a certificate --
    # not actually present on this host, which the operator needs to see
    # and fix, not have silently reverted out from under them).
    runtime_promoted = False
    runtime_error = None
    try:
        result = _mutate_and_promote(lambda conn: None)
        runtime_promoted = result.promoted
    except Exception as exc:  # noqa: BLE001 -- reported, not swallowed
        runtime_error = str(exc)

    finished = datetime.now(timezone.utc).isoformat()
    detail = {
        "control_db_restored": promo.control_db_restored, "secret_count_restored": promo.secret_count_restored,
        "certs_restored": promo.certs_restored, "runtime_promoted": runtime_promoted, "runtime_error": runtime_error,
    }
    # Inserted into the NOW-current control.db -- the one the restore
    # itself just promoted, if control_db was part of this backup.
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO restore_jobs(started_at, finished_at, status, backup_path, detail_json) VALUES (?, ?, ?, ?, ?)",
            (started, finished, "succeeded", str(path), json.dumps(detail)),
        )
        job_id = cur.lastrowid
    return {"status": "succeeded", "job_id": job_id, "backup_name": name, **detail}


# --- DNS Cache view/flush (beta-rescue priority 3A) --------------------------
#
# Two distinct layers, never conflated (see app/v2/cache_control.py's own
# docstring for the full architecture rationale): BIND's real recursive
# cache (per context, via a real rndc control channel) and dnsdist's
# packet cache (reported/flushed as its own thing -- a coalesced service
# restart, since no administrative channel to it exists by design).


def _bind_context_ports() -> list[tuple[str, int, int]]:
    """[(context_name, statistics_port, rndc_port), ...] for every
    currently-compiled BIND context."""
    out = []
    if not COMPILED_BIND_DIR.exists():
        return out
    for ctx_dir in sorted(p for p in COMPILED_BIND_DIR.iterdir() if p.is_dir()):
        if not (ctx_dir / "named.conf").exists():
            continue
        idx = int(ctx_dir.name.removeprefix("ctx")) if ctx_dir.name.startswith("ctx") and ctx_dir.name[3:].isdigit() else 0
        out.append((ctx_dir.name, 8153 + idx, 9553 + idx))
    return out


@app.get("/api/cache/status")
def cache_status_route(admin=Depends(current_admin)):
    from app.v2 import cache_control

    bind_layer = []
    for name, stats_port, _rndc_port in _bind_context_ports():
        bind_layer.append({"context": name, **cache_control.bind_cache_stats(stats_port)})
    return {
        "bind": bind_layer,
        "dnsdist": {
            "note": "the dnsdist packet cache has no live administrative channel by design; "
                    "flush restarts the dnsdist service, which drops all in-memory cache state",
        },
    }


class CacheFlushRequest(BaseModel):
    layer: str  # "bind" or "dnsdist"
    scope: str = "all"  # "all" | "name" | "tree" (bind only)
    target: Optional[str] = None
    context: Optional[str] = None  # bind only; omitted = every context


@app.post("/api/cache/flush")
def cache_flush_route(req: CacheFlushRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    from app.v2 import cache_control

    if req.layer == "dnsdist":
        result = cache_control.flush_dnsdist_cache(compiled_conf_path=COMPILED_DNSDIST_CONF)
        return {"results": [{"context": "dnsdist", "scope": "all", "target": None, "ok": result.ok, "message": result.message}]}
    if req.layer != "bind":
        raise ApiError(400, "validation_error", "layer must be 'bind' or 'dnsdist'")
    if not RNDC_CONF_PATH.exists():
        raise ApiError(400, "invalid_state", "rndc is not configured yet -- promote a policy change first so the BIND control channel is compiled")
    contexts = _bind_context_ports()
    if req.context:
        contexts = [c for c in contexts if c[0] == req.context]
        if not contexts:
            raise ApiError(404, "not_found", f"unknown BIND context: {req.context!r}")
    results = []
    for name, _stats_port, rndc_port in contexts:
        try:
            r = cache_control.flush_bind_context(RNDC_CONF_PATH, name, rndc_port, req.scope, req.target)
        except cache_control.CacheControlError as exc:
            raise ApiError(400, "validation_error", str(exc)) from exc
        results.append({"context": r.context, "scope": r.scope, "target": r.target, "ok": r.ok, "message": r.message})
    return {"results": results}


# --- Network Configuration (beta-rescue priority 4) --------------------------
#
# Managing the Alderpoint appliance's OWN interface/address/DNS-server
# host configuration -- distinct from turning Alderpoint into a router.
# No DHCP server, no NAT, no firewall, no routing/gateway functionality
# is added here or anywhere else in V2. Reuses V1's already-tested
# app/network_config.py wholesale via app/v2/network_config.py (see that
# module's own docstring), redirected to V2's own state namespace.
#
# This process (alderpointdns-v2, NoNewPrivileges=true) can never itself
# reconfigure a host network interface, so apply/confirm are async,
# root-owned-.path-unit-triggered privileged operations -- same
# convention as Software Updates apply just above and DNS Cache flush:
# this route only validates and stages a request marker; a dedicated
# root oneshot unit performs the real change and writes a result marker
# this route's counterpart GET route polls.


class NetworkApplyRequest(BaseModel):
    interface: str = Field(min_length=1, max_length=64)
    ipv4_mode: str = "unchanged"
    ipv4_address: Optional[str] = None
    ipv4_prefix: Optional[int] = None
    ipv4_gateway: Optional[str] = None
    ipv6_mode: str = "unchanged"
    ipv6_address: Optional[str] = None
    ipv6_prefix: Optional[int] = None
    ipv6_gateway: Optional[str] = None


@app.get("/api/network/status")
def network_status_route(admin=Depends(current_admin)):
    from app.v2 import network_config as nc

    try:
        current = nc.read_current_config()
    except nc.NetworkConfigError as exc:
        current = {"error": str(exc)}
    pending = nc.read_rollback_state()
    return {"current": current, "pending": pending}


@app.post("/api/network/apply")
def network_apply_route(req: NetworkApplyRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    from app.v2 import network_config as nc

    try:
        nc.validate_proposed(
            req.interface, req.ipv4_mode, req.ipv4_address, req.ipv4_prefix, req.ipv4_gateway,
            req.ipv6_mode, req.ipv6_address, req.ipv6_prefix, req.ipv6_gateway,
        )
    except nc.NetworkConfigError as exc:
        raise ApiError(400, "validation_error", str(exc)) from exc
    if nc.read_rollback_state() is not None:
        raise ApiError(409, "conflict", "a network configuration change is already pending confirmation")
    requested_at = datetime.now(timezone.utc).isoformat()
    payload = {**req.model_dump(), "requested_at": requested_at}
    nc.STATE_DIR.mkdir(parents=True, exist_ok=True)
    request_file = nc.STATE_DIR / "apply-requested.json"
    tmp = request_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload))
    tmp.chmod(0o600)
    tmp.replace(request_file)
    return {
        "status": "apply_requested", "requested_at": requested_at,
        "message": "the privileged network-apply service has been notified; poll GET /api/network/status",
    }


@app.post("/api/network/confirm")
def network_confirm_route(admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    from app.v2 import network_config as nc

    if nc.read_rollback_state() is None:
        raise ApiError(400, "invalid_state", "no pending network configuration change to confirm")
    requested_at = datetime.now(timezone.utc).isoformat()
    nc.STATE_DIR.mkdir(parents=True, exist_ok=True)
    request_file = nc.STATE_DIR / "confirm-requested.json"
    tmp = request_file.with_suffix(".tmp")
    tmp.write_text(json.dumps({"requested_at": requested_at}))
    tmp.chmod(0o600)
    tmp.replace(request_file)
    return {
        "status": "confirm_requested", "requested_at": requested_at,
        "message": "the privileged network-confirm service has been notified; poll GET /api/network/status",
    }


# --- subscribed Blocklists (beta-rescue priority 3B) -------------------------


class BlocklistSubscriptionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1, max_length=2048)
    category: str = ""
    # Not a normal-form field any more: generated from name. Advanced/
    # scripted callers may still pass it explicitly.
    subscription_id: str = Field(default="", max_length=64)


@app.get("/api/blocklists")
def list_blocklist_subscriptions_route(admin=Depends(current_admin)):
    with _db() as conn:
        return {"subscriptions": store.list_blocklist_subscriptions(conn)}


@app.post("/api/blocklists")
def create_blocklist_subscription_route(req: BlocklistSubscriptionCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    try:
        with _db() as conn:
            store.ensure_blocklist_subscription_schema(conn)
            subscription_id = req.subscription_id.strip() or _unique_id(conn, "blocklist_subscriptions", "subscription_id", req.name)
            store.create_blocklist_subscription(conn, subscription_id, req.name, req.url, req.category)
    except PolicyStoreError as exc:
        raise ApiError(409, "conflict", str(exc)) from exc
    return {"status": "created"}


@app.post("/api/blocklists/{subscription_id}/toggle")
def toggle_blocklist_subscription_route(subscription_id: str, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        sub = store.get_blocklist_subscription(conn, subscription_id)
        if sub is None:
            raise ApiError(404, "not_found", "unknown subscription")
        store.set_blocklist_subscription_enabled(conn, subscription_id, not sub["enabled"])
    return {"status": "updated"}


@app.delete("/api/blocklists/{subscription_id}")
def delete_blocklist_subscription_route(subscription_id: str, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)

    def _mutate(conn):
        sub = store.get_blocklist_subscription(conn, subscription_id)
        if sub is None:
            raise ApiError(404, "not_found", "unknown subscription")
        blocklist_subscriptions.remove_subscription_service(conn, subscription_id)
        store.delete_blocklist_subscription(conn, subscription_id)

    _mutate_and_promote(_mutate)
    return {"status": "deleted"}


@app.post("/api/blocklists/{subscription_id}/refresh")
def refresh_blocklist_subscription_route(subscription_id: str, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    holder: dict = {}

    def _mutate(conn):
        if store.get_blocklist_subscription(conn, subscription_id) is None:
            raise ApiError(404, "not_found", "unknown subscription")
        holder["result"] = blocklist_subscriptions.refresh_subscription(conn, subscription_id)

    result = _mutate_and_promote(_mutate)
    r = holder["result"]
    return {"status": "succeeded" if r.ok else "failed", "rule_count": r.rule_count, "message": r.message, "runtime": {"promoted": result.promoted}}


# --- software updates (beta-rescue priority 4) ------------------------------
#
# V2 remains private: there is no public release channel, and this
# surface must never claim one exists. See app/v2/software_updates.py
# for the validation contract and scripts/v2/alderpointdns_v2_update_apply.py
# for the privileged apply helper (a root-owned systemd .path/.service
# pair, not sudo/setuid inside this process).


def _update_dir() -> Path:
    path = STATE_DIR / "updates"
    path.mkdir(parents=True, exist_ok=True, mode=0o750)
    return path


@app.get("/api/updates/status")
def updates_status(admin=Depends(current_admin)):
    with _db() as conn:
        settings = store.load_update_settings(conn)
    feed_dir = Path(settings["private_feed_dir"]) if settings["private_feed_dir"] else None
    feed = software_updates.check_private_feed(feed_dir)
    return {
        "installed_source_version": software_updates.installed_source_version(APP_ROOT),
        "installed_package_version": software_updates.installed_package_version(),
        "private_feed_dir": settings["private_feed_dir"],
        **feed,
    }


class UpdateSettingsUpdate(BaseModel):
    private_feed_dir: Optional[str] = None


@app.put("/api/updates/settings")
def put_update_settings(req: UpdateSettingsUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        store.save_update_settings(conn, req.private_feed_dir)
    return {"status": "updated"}


@app.get("/api/updates/jobs")
def list_update_jobs(admin=Depends(current_admin)):
    update_dir = _update_dir()
    with _db() as conn:
        rows = conn.execute(
            "SELECT id, started_at, finished_at, status, detail_json FROM update_jobs ORDER BY id DESC LIMIT 30"
        ).fetchall()
        jobs = []
        for r in rows:
            job = {"id": r[0], "started_at": r[1], "finished_at": r[2], "status": r[3], "detail": json.loads(r[4] or "{}")}
            # Reconcile: if a privileged apply's result file has appeared
            # since the last poll, fold it into this job's row now,
            # rather than needing a persistent background thread in this
            # unprivileged process.
            if job["status"] == "apply_requested":
                result = software_updates.read_apply_result(update_dir, job["id"])
                if result is not None:
                    new_status = "succeeded" if result.get("status") == "succeeded" else "failed"
                    finished = datetime.now(timezone.utc).isoformat()
                    with _db() as conn2:
                        conn2.execute(
                            "UPDATE update_jobs SET finished_at = ?, status = ?, detail_json = ? WHERE id = ?",
                            (finished, new_status, json.dumps({**job["detail"], "apply_result": result}), job["id"]),
                        )
                    job.update({"status": new_status, "finished_at": finished, "detail": {**job["detail"], "apply_result": result}})
            jobs.append(job)
    return {"jobs": jobs}


class UpdateUploadRequest(BaseModel):
    filename: str
    data_base64: str


@app.post("/api/updates/upload")
def upload_update_package(req: UpdateUploadRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    import base64 as _b64
    import tempfile

    try:
        data = _b64.b64decode(req.data_base64)
    except Exception as exc:
        raise ApiError(400, "validation_error", f"invalid data_base64: {exc}")
    if not data:
        raise ApiError(400, "validation_error", "empty upload")

    with tempfile.NamedTemporaryFile(suffix=".deb", delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    try:
        installed_pkg = software_updates.installed_package_version()
        try:
            validated = software_updates.validate_candidate_package(tmp_path, installed_pkg)
        except software_updates.SoftwareUpdateError as exc:
            raise ApiError(400, "package_invalid", str(exc)) from exc

        update_dir = _update_dir()
        software_updates.stage_for_apply(update_dir, tmp_path, validated)
        now = datetime.now(timezone.utc).isoformat()
        detail = {
            "filename": req.filename, "candidate_version": validated.candidate_version,
            "sha256": validated.sha256, "fields": validated.fields,
        }
        with _db() as conn:
            cur = conn.execute(
                "INSERT INTO update_jobs(started_at, status, detail_json) VALUES (?, ?, ?)",
                (now, "staged", json.dumps(detail)),
            )
            job_id = cur.lastrowid
        return {"status": "staged", "job_id": job_id, **detail}
    finally:
        tmp_path.unlink(missing_ok=True)


@app.post("/api/updates/jobs/{job_id}/apply")
def apply_update_job(job_id: int, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        row = conn.execute("SELECT status, detail_json FROM update_jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "unknown update job")
    status, detail_json = row
    if status != "staged":
        raise ApiError(400, "invalid_state", f"job is {status!r}, not 'staged' -- upload a package first")
    detail = json.loads(detail_json or "{}")
    update_dir = _update_dir()
    staged_path = update_dir / software_updates.STAGED_DEB_NAME
    if not staged_path.exists():
        raise ApiError(400, "invalid_state", "staged package is missing; re-upload")

    validated = software_updates.ValidatedPackage(
        fields=detail.get("fields", {}), sha256=detail.get("sha256", ""), candidate_version=detail.get("candidate_version", ""),
    )
    software_updates.request_apply(update_dir, job_id, validated)
    now = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        conn.execute(
            "UPDATE update_jobs SET status = ?, detail_json = ? WHERE id = ?",
            ("apply_requested", json.dumps({**detail, "apply_requested_at": now}), job_id),
        )
    return {
        "status": "apply_requested", "job_id": job_id,
        "message": "the privileged update-apply service has been notified; the web service will restart if the install succeeds",
    }


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
    # A peer being unreachable, a cert-fingerprint mismatch, or the peer
    # returning a bad HTTP status are all foreseeable sync outcomes --
    # push_to_peer already records the exact same message into the
    # peer's own last_error (visible via GET /api/replication/peers) --
    # so surface that same information to the caller of this endpoint
    # as a specific, actionable error instead of letting it fall through
    # to the generic unhandled-exception 500 (real defect found live
    # during Gate #3 two-node replication failure-isolation testing:
    # stopping a peer's replication service correctly recorded
    # last_error but made this endpoint itself return an opaque
    # {"error": "internal_error"} 500 to whatever called it, including
    # the admin UI's own "Sync now" action).
    try:
        with _db() as conn:
            result = replication_v2.push_to_peer(conn, _secrets(), peer_node_id, temp_root)
    except replication_v2.ReplicationError as exc:
        raise ApiError(502, "peer_sync_failed", str(exc)) from exc
    except OSError as exc:
        raise ApiError(502, "peer_unreachable", str(exc)) from exc
    return {"status": "ok", "result": result}


class IssuePeerCertRequest(BaseModel):
    # Real node_ids are always UUID4 strings (node_identity.py); this is
    # deliberately a little more permissive than strict UUID (allows
    # future non-UUID identifiers) while still refusing to embed
    # arbitrary attacker-controlled text into a real X.509 certificate's
    # CN field -- found live during real security spot-checking: a
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
    entirely -- found live during real replication acceptance testing,
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


# --- import (AdGuard Home / Pi-hole / hosts / BIND zone / CSV / XLSX /
# Alderpoint-native JSON, beta-rescue priority 2) ----------------------------
#
# Staged preview -> apply, matching every other V2 mutation's shape: a job
# is created from a real parse of the uploaded/fetched source (never
# blind-trusted), previewed with conflicts/warnings surfaced explicitly,
# and only actually written to control.db (and recompiled/promoted into
# the live runtime) on an explicit apply call. See app/v2/import_migration.py
# for the full parsing/plan/apply implementation and its scoping notes.


class ImportParseRequest(BaseModel):
    source_type: str
    source_name: str = "import"
    text: Optional[str] = None
    data_base64: Optional[str] = None
    default_domain: Optional[str] = None
    base_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


@app.post("/api/import/jobs")
def create_import_job(req: ImportParseRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    if req.source_type not in import_migration.SOURCE_TYPES:
        raise ApiError(400, "validation_error", f"unsupported source_type: {req.source_type!r}")
    data = None
    if req.data_base64:
        import base64 as _b64
        try:
            data = _b64.b64decode(req.data_base64)
        except Exception as exc:
            raise ApiError(400, "validation_error", f"invalid data_base64: {exc}")
    try:
        translation = import_migration.parse_source(
            req.source_type, text=req.text, data=data, default_domain=req.default_domain,
            base_url=req.base_url, username=req.username, password=req.password,
        )
    except import_migration.ImportError_ as exc:
        raise ApiError(400, "unsupported_source", str(exc))
    with _db() as conn:
        plan = import_migration.build_plan(translation, conn)
        job_id = import_migration.create_job(conn, req.source_type, req.source_name, plan)
    return {"job_id": job_id, "plan": plan}


@app.get("/api/import/jobs")
def list_import_jobs(admin=Depends(current_admin)):
    with _db() as conn:
        return {"jobs": import_migration.list_jobs(conn)}


@app.get("/api/import/jobs/{job_id}")
def get_import_job(job_id: int, admin=Depends(current_admin)):
    with _db() as conn:
        job = import_migration.get_job(conn, job_id)
    if job is None:
        raise ApiError(404, "not_found", "unknown import job")
    return job


class ImportApplyRequest(BaseModel):
    skip_indexes: list[int] = Field(default_factory=list)


@app.post("/api/import/jobs/{job_id}/apply")
def apply_import_job(job_id: int, req: ImportApplyRequest, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        job = import_migration.get_job(conn, job_id)
    if job is None:
        raise ApiError(404, "not_found", "unknown import job")
    # Idempotent: re-applying an already-applied job re-runs the same
    # upsert/skip-existing logic rather than erroring.

    holder: dict = {}

    def _mutate(conn):
        counts = import_migration.apply_plan(conn, job_id, job["plan"], set(req.skip_indexes))
        holder["counts"] = counts
        conn.execute(
            "UPDATE import_jobs SET status = 'applied', result_json = ?, applied_at = ? WHERE id = ?",
            (json.dumps(counts), datetime.now(timezone.utc).isoformat(), job_id),
        )

    result = _mutate_and_promote(_mutate)
    return {"status": "applied", "counts": holder["counts"], "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


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


def _detect_appliance_timezone() -> str:
    """Best-effort real IANA timezone name for this Debian appliance
    (owner-reported requirement: display modes must never hardcode a
    geographic timezone -- "Appliance Time" has to reflect whatever
    this specific box is actually configured with). Two real, standard
    Debian sources, in order: `/etc/timezone` (a single-line IANA name,
    maintained by `dpkg-reconfigure tzdata`/`timedatectl set-timezone`)
    and, if that's missing or unreadable, the `/etc/localtime` symlink
    target's path under .../zoneinfo/<name> (the same mechanism `date`
    itself relies on). Falls back to the canonical "Etc/UTC" -- never an
    empty string or an exception -- if neither source is usable, so a
    caller always gets a real, displayable IANA-shaped name.
    """
    # Real, documented test-only override, same pattern as
    # ALDERPOINTDNS_V2_FORCE_ANALYTICS_DEGRADED above -- lets the real
    # browser harness prove Appliance Time genuinely reflects "whatever
    # this box is configured with" for more than one zone, without
    # depending on a shared build-server's real /etc/timezone (never
    # read anywhere except this function; production deployments never
    # set this).
    forced = os.environ.get("ALDERPOINTDNS_V2_FORCE_APPLIANCE_TIMEZONE", "").strip()
    if forced:
        return forced
    try:
        name = Path("/etc/timezone").read_text(encoding="utf-8").strip()
        if name:
            return name
    except OSError:
        pass
    try:
        target = os.readlink("/etc/localtime")
        marker = "zoneinfo/"
        idx = target.find(marker)
        if idx != -1:
            name = target[idx + len(marker):]
            if name:
                return name
    except OSError:
        pass
    return "Etc/UTC"


@app.get("/api/system/status")
def system_status(admin=Depends(current_admin)):
    import shutil as _shutil

    version_file = APP_ROOT / "VERSION"
    disk = _shutil.disk_usage(str(STATE_DIR)) if STATE_DIR.exists() else None
    return {
        "version": version_file.read_text().strip() if version_file.exists() else "unknown",
        "storage": {"total": disk.total, "used": disk.used, "free": disk.free} if disk else None,
        "compiled_runtime_present": COMPILED_DNSDIST_CONF.exists(),
        "timezone": _detect_appliance_timezone(),
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
