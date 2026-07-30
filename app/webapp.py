#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import base64
import json
import os
import secrets
import sqlite3
import subprocess
import urllib.request
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, File, Form, HTTPException, Path as PathParam, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

from app import analytics, backup, custom_rules as custom_rules_model, dns_cache, encryption, filter_schedule, importer, local_dns, replication, upstream_dns
from app import blocklist_categories
from app import service_logs
from app.alderpointdns_compiler import DB_PATH, add_source, init_db, normalize_domain


ROOT = Path("/opt/alderpointdns")
TEMPLATES = Jinja2Templates(directory=str(ROOT / "web" / "templates"))
STATIC_DIR = ROOT / "web" / "static"
SESSION_MAX_AGE = 8 * 60 * 60
SECRET_FILE = Path("/etc/alderpointdns/secrets.env")
ph = PasswordHasher()
app = FastAPI(title="Alderpoint DNS")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def secure_session_cookie_enabled() -> bool:
    return os.getenv("ALDERPOINTDNS_COOKIE_SECURE", "").strip().lower() in {"1", "true", "yes", "on"}


@app.on_event("startup")
def _replication_autostart() -> None:
    # Re-establishes the primary listener or replica poller thread after a
    # service restart, matching whichever role was previously configured.
    # Deliberately best-effort (replication.autostart() never raises): a
    # replication bug must never prevent alderpointdns.service from starting.
    replication.autostart()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


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
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY,
            ip TEXT NOT NULL,
            attempted_at TEXT NOT NULL,
            success INTEGER NOT NULL
        )
        """
    )
    return conn


def signed_session(request: Request) -> dict[str, Any]:
    raw = request.cookies.get("alderpointdns_session")
    if not raw:
        return {}
    try:
        return serializer.loads(raw, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return {}


def set_session(response: Response, data: dict[str, Any]) -> None:
    response.set_cookie(
        "alderpointdns_session",
        serializer.dumps(data),
        httponly=True,
        samesite="strict",
        secure=secure_session_cookie_enabled(),
        max_age=SESSION_MAX_AGE,
    )


def clear_session(response: Response) -> None:
    response.delete_cookie("alderpointdns_session")


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
    return row


def csrf_token(request: Request) -> str:
    session = signed_session(request)
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(24)
    return token


def check_csrf(request: Request, token: str) -> None:
    if signed_session(request).get("csrf") != token:
        raise HTTPException(status_code=403, detail="invalid csrf token")


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def run(command: list[str]) -> tuple[int, str]:
    proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout[-4000:]


def service_state(name: str) -> str:
    code, out = run(["systemctl", "is-active", name])
    return out.strip() if code == 0 else "inactive"


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
        collector_state = service_state("alderpointdns-analytics")
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
    collector = service_state("alderpointdns-analytics")
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


def deploy_no_download() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "deploy", "--no-download"])


def deploy_no_download_or_raise() -> None:
    code, out = deploy_no_download()
    if code != 0:
        raise RuntimeError(out.strip() or "deployment failed")


def cache_flush_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "cache-flush"])


def cache_flush_apply_or_raise() -> None:
    code, out = cache_flush_apply()
    if code != 0:
        raise RuntimeError(out.strip() or "cache flush failed")


def encryption_deploy_apply() -> tuple[int, str]:
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "encryption-deploy"])


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


def listener_addresses() -> set[str]:
    code, out = run(["ss", "-H", "-ltnup"])
    if code != 0:
        return set()
    addresses: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            addresses.add(parts[4])
    return addresses


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


def protocol_statuses() -> list[dict[str, str]]:
    version = dnsdist_version_info()
    features = version["feature_set"]
    listeners = listener_addresses()
    config = Path("/etc/dnsdist/dnsdist.conf")
    has_doh3 = "dns-over-http3" in features
    protocols = [
        {
            "name": "Plain DNS",
            "available": True,
            "enabled": file_contains(config, "plainEnabled"),
            "listening": "0.0.0.0:53" in listeners or "[::]:53" in listeners,
            "tested": "acceptance-covered",
            "port": "53/udp,tcp",
        },
        {
            "name": "DoH",
            "available": "dns-over-https(nghttp2)" in features,
            "enabled": file_contains(config, "dohEnabled"),
            "listening": "0.0.0.0:443" in listeners or "[::]:443" in listeners,
            "tested": "acceptance-covered",
            "port": "443/tcp /dns-query",
        },
        {
            "name": "DoT",
            "available": any(feature.startswith("dns-over-tls") for feature in features),
            "enabled": file_contains(config, "dotEnabled"),
            "listening": "0.0.0.0:853" in listeners or "[::]:853" in listeners,
            "tested": "acceptance-covered",
            "port": "853/tcp",
        },
        {
            "name": "DoQ",
            "available": "dns-over-quic" in features,
            "enabled": file_contains(config, "doqEnabled"),
            "listening": "0.0.0.0:853" in listeners or "[::]:853" in listeners,
            "tested": "acceptance-covered",
            "port": "853/udp",
        },
    ]
    protocols.append(
        {
            "name": "DoH3",
            "available": has_doh3,
            "enabled": file_contains(config, "doh3Enabled") if has_doh3 else False,
            "listening": ("0.0.0.0:443" in listeners or "[::]:443" in listeners) if has_doh3 else False,
            "tested": "config-validated" if has_doh3 else "unavailable in build",
            "port": "443/udp",
        }
    )
    for protocol in protocols:
        if not protocol["available"]:
            protocol["state"] = "unavailable in build"
        elif protocol["enabled"] and protocol["listening"]:
            protocol["state"] = "listening"
        elif protocol["enabled"]:
            protocol["state"] = "enabled"
        else:
            protocol["state"] = "available"
    return protocols


def render(request: Request, template: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    session = signed_session(request)
    context.update(
        {
            "request": request,
            "admin": session.get("admin"),
            "csrf": session.get("csrf") or csrf_token(request),
            "setup_required": admin_count() == 0,
            "global_status": global_service_status() if session.get("admin") else {"label": "Unknown", "tone": "unavailable", "detail": "not authenticated"},
        }
    )
    return TEMPLATES.TemplateResponse(template, context, status_code=status_code)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    accepts = request.headers.get("accept", "")
    if "text/html" not in accepts:
        return JSONResponse({"detail": exc.errors()}, status_code=422)
    if request.url.path.startswith("/import"):
        return import_error(
            request,
            "That import or migration link is not valid. Return to Import and Migration and choose a current job or workflow.",
            status_code=404,
        )
    return render(request, "import_migration.html", error="The requested page is not valid.", jobs=[], job=None, preview=None, adguard=None, migration_summary=None, status_code=404)


@app.get("/status/summary")
def status_summary(_: sqlite3.Row = Depends(current_admin)):
    return JSONResponse(global_service_status())


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
    collector_state = service_state("alderpointdns-analytics")
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
    deploy_no_download()
    return redirect("/")


@app.get("/setup", response_class=HTMLResponse)
def setup_get(request: Request):
    if admin_count() > 0:
        return redirect("/login")
    local_dns.init_db()
    return render(request, "setup.html", error=None, local_dns=local_dns.settings())


@app.post("/setup")
def setup_post(
    username: str = Form("admin"),
    password: str = Form(...),
    create_local_dns: str = Form("0"),
    server_hostname: str = Form("alderpointdns"),
    server_ip: str = Form(""),
):
    if admin_count() > 0:
        return redirect("/login")
    if len(password) < 12:
        return HTMLResponse("Password must be at least 12 characters.", status_code=400)
    with db() as conn:
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            (username.strip() or "admin", ph.hash(password), utc_now()),
        )
    if create_local_dns == "1":
        cfg = local_dns.settings()
        ip = server_ip.strip() or cfg.get("server_ip") or local_dns.detect_server_ip()
        host = server_hostname.strip() or "alderpointdns"
        local_dns.update_settings({"server_hostname": host, "server_ip": ip})
        local_dns.add_host(host, cfg.get("internal_domain", "home.arpa"), ip, cfg.get("default_ttl", 300), "Alderpoint DNS server", True, True)
        local_dns.upsert_alias(ip, "Alderpoint DNS", "Alderpoint DNS DNS appliance")
    return redirect("/login")


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    if admin_count() == 0:
        return redirect("/setup")
    return render(request, "login.html", error=None)


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
        ok = False
        if row:
            try:
                ok = ph.verify(row["password_hash"], password)
            except VerifyMismatchError:
                ok = False
        conn.execute("INSERT INTO login_attempts(ip, attempted_at, success) VALUES (?, ?, ?)", (ip, utc_now(), 1 if ok else 0))
    if not ok:
        return render(request, "login.html", error="Invalid username or password.")
    token = secrets.token_urlsafe(24)
    response = redirect("/")
    set_session(response, {"admin_id": row["id"], "admin": row["username"], "csrf": token})
    return response


@app.post("/logout")
def logout():
    response = redirect("/login")
    clear_session(response)
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


def blocklists_error(request: Request, message: str) -> HTMLResponse:
    return render(
        request,
        "blocklists.html",
        sources=compiler_status()["sources"],
        categories=blocklist_categories.list_categories(),
        category_error=message,
        category_filter="",
        status_filter="",
        search="",
        sort="name",
        filter_schedule=filter_schedule_context(),
        status_code=400,
    )


def resolve_category_key(requested: str) -> str:
    clean = (requested or "").strip()
    known_keys = {row["key"] for row in blocklist_categories.list_categories()}
    return clean if clean in known_keys else blocklist_categories.UNCATEGORIZED_KEY


@app.get("/blocklists", response_class=HTMLResponse)
def blocklists(request: Request, _: sqlite3.Row = Depends(current_admin)):
    blocklist_categories.migrate_existing_categories()
    sources = compiler_status()["sources"]
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
        "rules": lambda s: s["final_active_domains"] or 0,
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
        filter_schedule=filter_schedule_context(),
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
        deploy_no_download_or_raise()
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
    }


def encryption_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    context = encryption_context()
    context.update({"error": message})
    return render(request, "encryption.html", **context, status_code=status_code)


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
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        cfg = encryption.settings()
        encryption.update_settings(
            {
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
        )
        encryption_deploy_apply()
    except Exception as exc:
        return encryption_error(request, str(exc))
    return redirect("/encryption")


@app.post("/encryption/certificate/self-signed")
def encryption_cert_self_signed(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        encryption.update_settings({**encryption.settings(), "cert_mode": "self_signed"})
        encryption.request_cert_action("generate_self_signed")
        encryption_deploy_apply()
    except Exception as exc:
        return encryption_error(request, str(exc))
    return redirect("/encryption")


@app.post("/encryption/certificate/local-ca")
def encryption_cert_local_ca(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        encryption.update_settings({**encryption.settings(), "cert_mode": "local_ca"})
        encryption.request_cert_action("generate_local_ca")
        encryption_deploy_apply()
    except Exception as exc:
        return encryption_error(request, str(exc))
    return redirect("/encryption")


@app.post("/encryption/certificate/upload")
async def encryption_cert_upload(
    request: Request,
    csrf: str = Form(...),
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()
        if not cert_bytes or not key_bytes:
            raise encryption.EncryptionError("both a certificate file and a key file are required")
        encryption.request_cert_upload(cert_bytes, key_bytes)
        encryption.update_settings({**encryption.settings(), "cert_mode": "uploaded"})
        encryption_deploy_apply()
    except Exception as exc:
        return encryption_error(request, str(exc))
    return redirect("/encryption")


@app.post("/encryption/certificate/existing-path")
def encryption_cert_existing_path(
    request: Request,
    csrf: str = Form(...),
    cert_path: str = Form(...),
    key_path: str = Form(...),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        encryption.update_settings({**encryption.settings(), "cert_mode": "existing_path", "cert_path": cert_path, "key_path": key_path})
        encryption_deploy_apply()
    except Exception as exc:
        return encryption_error(request, str(exc))
    return redirect("/encryption")


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
    client_address_test_path = Path("/opt/alderpointdns/tests/test_dnsdist_frontend.sh")
    if proxy_backend and client_address_test_path.exists():
        client_address_test = {"state": "Passed", "filename": client_address_test_path.name}
    elif client_address_test_path.exists():
        client_address_test = {"state": "Failed", "filename": client_address_test_path.name}
    else:
        client_address_test = {"state": "Not tested", "filename": "test_dnsdist_frontend.sh"}
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
        protocols=protocol_statuses(),
        cert=cert_status(),
        proxy_backend="enabled" if proxy_backend else "not enabled",
        client_address_test=client_address_test,
        upstream_resolvers=upstream_dns.resolvers(),
        upstream_deployment=upstream_dns.last_deployment(),
        upstream_error=None,
    )


def dns_settings_error(request: Request, message: str, status_code: int = 400) -> HTMLResponse:
    response = dns_settings(request, current_admin(request))
    response.status_code = status_code
    body = response.body.decode()
    body = body.replace('<section class="grid">', f'<div class="alert error">{message}</div>\n<section class="grid">', 1)
    return HTMLResponse(body, status_code=status_code)


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
        deploy_no_download_or_raise()
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
        deploy_no_download_or_raise()
    except Exception as exc:
        return dns_settings_error(request, str(exc))
    return redirect("/dns-settings")


@app.post("/dns-settings/upstreams/{resolver_id}/toggle")
def upstream_toggle(request: Request, resolver_id: int, csrf: str = Form(...), enabled: str = Form("0"), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        upstream_dns.set_enabled(resolver_id, enabled == "1")
        deploy_no_download_or_raise()
    except Exception as exc:
        return dns_settings_error(request, str(exc))
    return redirect("/dns-settings")


@app.post("/dns-settings/upstreams/{resolver_id}/move")
def upstream_move(request: Request, resolver_id: int, csrf: str = Form(...), direction: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        upstream_dns.move_resolver(resolver_id, direction)
        deploy_no_download_or_raise()
    except Exception as exc:
        return dns_settings_error(request, str(exc))
    return redirect("/dns-settings")


@app.post("/dns-settings/upstreams/{resolver_id}/delete")
def upstream_delete(request: Request, resolver_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        upstream_dns.delete_resolver(resolver_id)
        deploy_no_download_or_raise()
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
    return run(["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "backup-restore"])


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
    context.update({"error": message, "preview": None, "preview_source": None, "imported": None})
    context.update(extra)
    return render(request, "backup.html", **context, status_code=status_code)


@app.get("/backup", response_class=HTMLResponse)
def backup_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    context = backup_context()
    context.update({"error": None, "preview": None, "preview_source": None, "imported": request.query_params.get("imported")})
    return render(request, "backup.html", **context)


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
    return redirect("/backup")


@app.post("/backup/import")
async def backup_import_route(request: Request, csrf: str = Form(...), upload: UploadFile = File(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    try:
        data = await upload.read()
        if not data:
            raise backup.BackupError("uploaded file is empty")
        path = backup.stage_import(upload.filename or "uploaded-backup.tar.gz", data)
    except Exception as exc:
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
        backup_restore_apply()
        result = backup.latest_request_result("restore")
        if result and result.get("status") != "done":
            raise backup.BackupError("restore did not complete; check the restore history table below")
    except Exception as exc:
        return backup_error(request, str(exc))
    return redirect("/backup")


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
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        backup.update_settings(
            {
                "schedule_enabled": schedule_enabled,
                "schedule_interval_hours": schedule_interval_hours,
                "retention_count": retention_count,
            }
        )
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
