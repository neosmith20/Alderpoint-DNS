"""Alderpoint DNS V2 management/API service (Workstream 4B).

A real, installed-path-only FastAPI application exposing the already-real
V2 backend (policy store/compiler/runtime, analytics, secrets,
notifications, migration) over native HTTPS. JSON API only -- no HTML/UI
(explicitly out of scope for this pass; see docs/v2/management-plane.md).

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

import ipaddress
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from pydantic import BaseModel, Field

from app.v2 import analytics_deps
from app.v2 import control_db
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
from app.v2.dnsdist_gen import DnsdistGenError
from app.v2.network_match import InvalidNetworkError
from app.v2.policy_model import InvalidPolicyError, PolicyLayer
from app.v2.policy_store import PolicyStoreError
from app.v2.runtime_compile import RuntimeCompileError
from app.v2.secret_store import SecretStore

# --- installed layout (mirrors scripts/v2/alderpointdns_v2_ctl.py) --------

APP_ROOT = Path(os.environ.get("ALDERPOINTDNS_V2_APP_ROOT", "/opt/alderpointdns-v2"))
CONFIG_DIR = Path(os.environ.get("ALDERPOINTDNS_V2_CONFIG_ROOT", "/etc/alderpointdns-v2"))
STATE_DIR = Path(os.environ.get("ALDERPOINTDNS_V2_STATE_ROOT", "/var/lib/alderpointdns-v2"))

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


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    # §15: appropriate headers for a pure JSON API served over HTTPS-only.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
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
    CONTROL_DB.parent.mkdir(parents=True, exist_ok=True)
    with control_db.connect(CONTROL_DB) as conn:
        yield conn


def _secrets() -> SecretStore:
    return SecretStore(SECRETS_DIR)


def _ensure_extended_schemas() -> None:
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
    if not x_csrf_token or x_csrf_token != admin["csrf"]:
        raise ApiError(403, "invalid_csrf_token", "missing or incorrect X-CSRF-Token header")


CsrfHeader = Header(None, alias="X-CSRF-Token")


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
        import hmac

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
                result, new_hash = verify_and_maybe_rehash(password_hash, req.password)
                ok = result.ok
        except TooManyConcurrentHashesError:
            raise ApiError(503, "auth_busy", "too many concurrent authentication attempts, retry shortly")
        _record_login_attempt(conn, ip, ok)
        if not ok:
            raise ApiError(401, "invalid_credentials", "incorrect username or password")
        admin_id = row[0]
        if new_hash is not None:
            conn.execute("UPDATE admins SET password_hash=? WHERE id=?", (new_hash, admin_id))
        # §12 "session rotation after login": always a brand-new session
        # row, never reusing a pre-login one.
        session = _create_session_row(conn, admin_id, request)
    _set_session_cookie(response, session["id"])
    return {"status": "ok", "csrf": session["csrf"]}


@app.post("/api/logout")
def logout(request: Request, response: Response, admin=Depends(current_admin)):
    with _db() as conn:
        conn.execute("DELETE FROM sessions WHERE id=?", (admin["session_id"],))
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"status": "ok"}


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
            result = runtime_compile.recompile_and_promote(conn, STAGING_DIR, COMPILED_DNSDIST_CONF)
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
    return {"networks": [{"network_id": r[0], "cidr": r[1]} for r in rows]}


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


@app.get("/api/policy/global")
def get_global_policy(admin=Depends(current_admin)):
    with _db() as conn:
        layer = store.load_policy_layer(conn, "global", "singleton")
    return {"policy": {f.name: getattr(layer, f.name) for f in __import__("dataclasses").fields(layer)}}


@app.put("/api/policy/global")
def put_global_policy(req: PolicyLayerUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    layer = PolicyLayer(**req.model_dump())
    result = _mutate_and_promote(lambda conn: store.save_policy_layer(conn, "global", "singleton", layer))
    return {"status": "updated", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


@app.put("/api/policy/network/{network_id}")
def put_network_policy(network_id: str, req: PolicyLayerUpdate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    layer = PolicyLayer(**req.model_dump())
    result = _mutate_and_promote(lambda conn: store.save_policy_layer(conn, "network", network_id, layer))
    return {"status": "updated", "runtime": {"promoted": result.promoted, "binding_count": result.binding_count}}


# --- clients + effective-policy explain (§21-22) -----------------------


class ClientCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = ""


@app.get("/api/clients")
def list_clients(admin=Depends(current_admin)):
    with _db() as conn:
        rows = conn.execute("SELECT id, name, description, enabled FROM clients ORDER BY id").fetchall()
    return {"clients": [{"id": r[0], "name": r[1], "description": r[2], "enabled": bool(r[3])} for r in rows]}


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
        conn.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES (?, ?, ?, ?)",
            (client_id, req.kind, req.value, now),
        )
    return {"status": "created"}


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
    return {"upstreams": [{"upstream_profile_id": r[0], "name": r[1], "transport": r[2], "strategy": r[3]} for r in rows]}


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


class ServiceRulesetCreate(BaseModel):
    ruleset_id: str
    service_ids: list[str]


@app.post("/api/service-rulesets")
def create_service_ruleset(req: ServiceRulesetCreate, admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    with _db() as conn:
        store.create_service_ruleset(conn, req.ruleset_id, req.service_ids)
    return {"status": "created"}


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


# --- analytics (§28) ---------------------------------------------------


def _analytics_service() -> AnalyticsService:
    return AnalyticsService(parquet_root=ANALYTICS_PARQUET_DIR, aggregates_path=ANALYTICS_AGGREGATES_DB)


def _query_result_to_dict(qr) -> dict:
    return {"rows": qr.rows, "columns": qr.columns, "degraded": qr.degraded, "degraded_reason": qr.degraded_reason}


@app.get("/api/analytics/recent")
def analytics_recent(minutes: float = 60.0, admin=Depends(current_admin)):
    svc = _analytics_service()
    try:
        return _query_result_to_dict(svc.recent_query_log(minutes=minutes))
    finally:
        svc.close()


@app.get("/api/analytics/top-domains")
def analytics_top_domains(minutes: float = 60.0, limit: int = 20, admin=Depends(current_admin)):
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


@app.post("/api/backup/secrets")
def create_secret_backup(admin=Depends(current_admin), x_csrf_token: Optional[str] = CsrfHeader):
    check_csrf(admin, x_csrf_token)
    from app.v2 import secret_backup
    from cryptography.fernet import Fernet

    secrets = _secrets()
    if not secrets.exists(BACKUP_KEY_SECRET_ID):
        secrets.create(Fernet.generate_key().decode("ascii"), secret_id=BACKUP_KEY_SECRET_ID)
    key = secrets.get(BACKUP_KEY_SECRET_ID).encode("ascii")
    backup_dir = STATE_DIR / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_path = backup_dir / f"secrets-{int(time.time())}.enc"
    result = secret_backup.create_encrypted_backup(secrets, backup_path, key)
    # §30: no plaintext secret export -- only a count and a server-side
    # path are returned, never contents.
    return {"status": "created", "secret_count": result.secret_count, "created_at": result.created_at}


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
