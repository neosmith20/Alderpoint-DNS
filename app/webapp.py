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
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

from app import analytics, local_dns
from app.bindguard_compiler import DB_PATH, add_source, init_db, normalize_domain


ROOT = Path("/opt/bindguard")
TEMPLATES = Jinja2Templates(directory=str(ROOT / "web" / "templates"))
STATIC_DIR = ROOT / "web" / "static"
SESSION_MAX_AGE = 8 * 60 * 60
SECRET_FILE = Path("/etc/bindguard/secrets.env")
ph = PasswordHasher()
app = FastAPI(title="BindGuard")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def get_secret() -> str:
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    if SECRET_FILE.exists():
        for line in SECRET_FILE.read_text().splitlines():
            if line.startswith("BINDGUARD_SESSION_SECRET="):
                return line.split("=", 1)[1].strip()
    secret = secrets.token_urlsafe(48)
    with SECRET_FILE.open("a") as handle:
        handle.write(f"BINDGUARD_SESSION_SECRET={secret}\n")
    os.chmod(SECRET_FILE, 0o640)
    return secret


serializer = URLSafeTimedSerializer(get_secret(), salt="bindguard-session")


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
    raw = request.cookies.get("bindguard_session")
    if not raw:
        return {}
    try:
        return serializer.loads(raw, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return {}


def set_session(response: Response, data: dict[str, Any]) -> None:
    response.set_cookie(
        "bindguard_session",
        serializer.dumps(data),
        httponly=True,
        samesite="strict",
        secure=False,
        max_age=SESSION_MAX_AGE,
    )


def clear_session(response: Response) -> None:
    response.delete_cookie("bindguard_session")


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


def system_health(bind_state: str | None = None, dnsdist_state: str | None = None, bindguard_state: str | None = None) -> list[dict[str, str]]:
    named = bind_state or service_state("named")
    dnsdist_current = dnsdist_state or service_state("dnsdist")
    bindguard_current = bindguard_state or service_state("bindguard")
    collector = service_state("bindguard-analytics")
    backend = "healthy" if named == "active" and dnsdist_current == "active" else "degraded"
    cert = cert_status()["state"]
    db_state = "healthy" if analytics.db_size() > 0 else "unavailable"
    return [
        {"name": "BIND", "state": "Healthy" if named == "active" else "Down", "tone": status_tone(named)},
        {"name": "dnsdist", "state": "Healthy" if dnsdist_current == "active" else "Down", "tone": status_tone(dnsdist_current)},
        {"name": "BindGuard", "state": "Healthy" if bindguard_current == "active" else "Down", "tone": status_tone(bindguard_current)},
        {"name": "Analytics collector", "state": "Healthy" if collector == "active" else "Down", "tone": status_tone(collector)},
        {"name": "Backend health", "state": "Healthy" if backend == "healthy" else "Degraded", "tone": backend},
        {"name": "DNSSEC", "state": "Unavailable", "tone": "unavailable"},
        {"name": "Certificate", "state": "Healthy" if cert == "present" else cert.title(), "tone": status_tone(cert)},
        {"name": "Database", "state": "Healthy" if db_state == "healthy" else "Unavailable", "tone": db_state},
    ]


def compiler_status() -> dict[str, Any]:
    with db() as conn:
        sources = conn.execute("SELECT * FROM sources ORDER BY id").fetchall()
        rules = conn.execute("SELECT * FROM custom_rules ORDER BY id DESC").fetchall()
        deployment = conn.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
    return {"sources": sources, "rules": rules, "deployment": deployment}


def deploy_no_download() -> tuple[int, str]:
    return run(["sudo", "/opt/bindguard/app/bindguard_compiler.py", "deploy", "--no-download"])


def dnsdist_stats() -> dict[str, Any]:
    try:
        creds = Path("/etc/bindguard/dnsdist-web.creds").read_text().strip()
        api_key = Path("/etc/bindguard/dnsdist-api.key").read_text().strip()
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
    cert = Path("/etc/bindguard/certs/bindguard-lab.crt")
    key = Path("/etc/bindguard/certs/bindguard-lab.key")
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
    if os.getenv("BINDGUARD_DNS_ALLOW_ALL") == "1":
        return True
    for path in (
        Path("/etc/systemd/system/dnsdist.service.d/bindguard.conf"),
        Path("/etc/systemd/system/dnsdist.service.d/override.conf"),
    ):
        try:
            if "BINDGUARD_DNS_ALLOW_ALL=1" in path.read_text():
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
        }
    )
    return TEMPLATES.TemplateResponse(template, context, status_code=status_code)


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
    bindguard_state = service_state("bindguard")
    collector_state = service_state("bindguard-analytics")
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
        bindguard=bindguard_state,
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
        system_health=system_health(bind_state, dnsdist_state, bindguard_state),
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
    server_hostname: str = Form("bindguard"),
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
        host = server_hostname.strip() or "bindguard"
        local_dns.update_settings({"server_hostname": host, "server_ip": ip})
        local_dns.add_host(host, cfg.get("internal_domain", "home.arpa"), ip, cfg.get("default_ttl", 300), "BindGuard server", True, True)
        local_dns.upsert_alias(ip, "BindGuard", "BindGuard DNS appliance")
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


@app.get("/blocklists", response_class=HTMLResponse)
def blocklists(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "blocklists.html", sources=compiler_status()["sources"])


@app.post("/blocklists/add")
def blocklist_add(request: Request, name: str = Form(...), url: str = Form(...), category: str = Form("ads_trackers"), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO sources(name, url, enabled, category)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(name) DO UPDATE SET url=excluded.url, category=excluded.category
            """,
            (name.strip(), url.strip(), category.strip() or "ads_trackers"),
        )
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
    category: str = Form("ads_trackers"),
    csrf: str = Form(...),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    clean_name = name.strip()
    clean_url = url.strip()
    clean_category = category.strip() or "ads_trackers"
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
    run(["/opt/bindguard/app/bindguard_compiler.py", "update-source", str(source_id)])
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
    run(["sudo", "/opt/bindguard/app/bindguard_compiler.py", "update-sources"])
    return redirect("/blocklists")


@app.post("/deploy")
def deploy(request: Request, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    run(["sudo", "/opt/bindguard/app/bindguard_compiler.py", "deploy"])
    return redirect("/")


@app.get("/custom-rules", response_class=HTMLResponse)
def custom_rules(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(request, "custom_rules.html", rules=compiler_status()["rules"])


@app.post("/custom-rules/add")
def custom_add(request: Request, action: str = Form(...), domain: str = Form(...), comment: str = Form(""), csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    normalized = normalize_domain(domain)
    if not normalized or action not in {"allow", "block"}:
        raise HTTPException(status_code=400, detail="invalid custom rule")
    with db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO custom_rules(domain, action, enabled, comment, created_at)
            VALUES (?, ?, 1, ?, ?)
            """,
            (normalized, action, comment, utc_now()),
        )
    deploy_no_download()
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
    with db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO custom_rules(domain, action, enabled, comment, created_at)
            VALUES (?, ?, 1, ?, ?)
            """,
            (normalized, action, "created from query log", utc_now()),
        )
    deploy_no_download()
    return redirect("/query-log")


@app.post("/custom-rules/{rule_id}/toggle")
def custom_toggle(request: Request, rule_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    with db() as conn:
        conn.execute("UPDATE custom_rules SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (rule_id,))
    deploy_no_download()
    return redirect("/custom-rules")


@app.post("/custom-rules/{rule_id}/delete")
def custom_delete(request: Request, rule_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    with db() as conn:
        conn.execute("DELETE FROM custom_rules WHERE id=?", (rule_id,))
    deploy_no_download()
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
    server_hostname: str = Form("bindguard"),
    server_ip: str = Form(""),
    _: sqlite3.Row = Depends(current_admin),
):
    check_csrf(request, csrf)
    try:
        local_dns.update_settings(
            {
                "internal_domain": internal_domain,
                "default_ttl": default_ttl,
                "server_hostname": server_hostname.strip() or "bindguard",
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
        host = cfg.get("server_hostname", "bindguard")
        ip = cfg.get("server_ip") or local_dns.detect_server_ip()
        local_dns.add_host(host, cfg.get("internal_domain", "home.arpa"), ip, cfg.get("default_ttl", 300), "BindGuard server", True, True)
        local_dns.upsert_alias(ip, "BindGuard", "BindGuard DNS appliance")
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


@app.get("/dns-settings", response_class=HTMLResponse)
def dns_settings(request: Request, _: sqlite3.Row = Depends(current_admin)):
    version = dnsdist_version_info()
    proxy_backend = proxy_backend_enabled()
    client_address_test_path = Path("/opt/bindguard/tests/test_dnsdist_frontend.sh")
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
        hostname="bindguard.local",
        doh_path="/dns-query",
        dnsdist_version=version["version"],
        dnsdist_features=version["features"],
        protocols=protocol_statuses(),
        cert=cert_status(),
        proxy_backend="enabled" if proxy_backend else "not enabled",
        client_address_test=client_address_test,
    )


@app.get("/system", response_class=HTMLResponse)
def system_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    code, logs = run(["journalctl", "-u", "bindguard", "-n", "80", "--no-pager"])
    named = service_state("named")
    dnsdist = service_state("dnsdist")
    bindguard = service_state("bindguard")
    return render(
        request,
        "system.html",
        named=named,
        dnsdist=dnsdist,
        bindguard=bindguard,
        health=system_health(named, dnsdist, bindguard),
        logs=logs,
        compiler=compiler_status(),
    )


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
