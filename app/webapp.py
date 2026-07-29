#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import os
import secrets
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

from app.bindguard_compiler import DB_PATH, add_source, init_db, normalize_domain


ROOT = Path("/opt/bindguard")
TEMPLATES = Jinja2Templates(directory=str(ROOT / "web" / "templates"))
SESSION_MAX_AGE = 8 * 60 * 60
SECRET_FILE = Path("/etc/bindguard/secrets.env")
ph = PasswordHasher()
app = FastAPI(title="BindGuard")


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


def compiler_status() -> dict[str, Any]:
    with db() as conn:
        sources = conn.execute("SELECT * FROM sources ORDER BY id").fetchall()
        rules = conn.execute("SELECT * FROM custom_rules ORDER BY id DESC").fetchall()
        deployment = conn.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
    return {"sources": sources, "rules": rules, "deployment": deployment}


def render(request: Request, template: str, **context: Any) -> HTMLResponse:
    session = signed_session(request)
    context.update(
        {
            "request": request,
            "admin": session.get("admin"),
            "csrf": session.get("csrf") or csrf_token(request),
            "setup_required": admin_count() == 0,
        }
    )
    return TEMPLATES.TemplateResponse(template, context)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, _: sqlite3.Row = Depends(current_admin)):
    status = compiler_status()
    enabled_sources = [s for s in status["sources"] if s["enabled"]]
    deployment = status["deployment"]
    active_rules = deployment["active_domains"] if deployment else 0
    return render(
        request,
        "dashboard.html",
        bindguard="active",
        bind=service_state("named"),
        dnsdist=service_state("dnsdist"),
        enabled_sources=len(enabled_sources),
        active_rules=active_rules,
        deployment=deployment,
        sources=status["sources"],
    )


@app.get("/setup", response_class=HTMLResponse)
def setup_get(request: Request):
    if admin_count() > 0:
        return redirect("/login")
    return render(request, "setup.html", error=None)


@app.post("/setup")
def setup_post(username: str = Form("admin"), password: str = Form(...)):
    if admin_count() > 0:
        return redirect("/login")
    if len(password) < 12:
        return HTMLResponse("Password must be at least 12 characters.", status_code=400)
    with db() as conn:
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            (username.strip() or "admin", ph.hash(password), utc_now()),
        )
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
    run(["sudo", "/opt/bindguard/app/bindguard_compiler.py", "deploy", "--no-download"])
    return redirect("/custom-rules")


@app.post("/custom-rules/{rule_id}/toggle")
def custom_toggle(request: Request, rule_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    with db() as conn:
        conn.execute("UPDATE custom_rules SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (rule_id,))
    run(["sudo", "/opt/bindguard/app/bindguard_compiler.py", "deploy", "--no-download"])
    return redirect("/custom-rules")


@app.post("/custom-rules/{rule_id}/delete")
def custom_delete(request: Request, rule_id: int, csrf: str = Form(...), _: sqlite3.Row = Depends(current_admin)):
    check_csrf(request, csrf)
    with db() as conn:
        conn.execute("DELETE FROM custom_rules WHERE id=?", (rule_id,))
    run(["sudo", "/opt/bindguard/app/bindguard_compiler.py", "deploy", "--no-download"])
    return redirect("/custom-rules")


@app.get("/dns-settings", response_class=HTMLResponse)
def dns_settings(request: Request, _: sqlite3.Row = Depends(current_admin)):
    return render(
        request,
        "dns_settings.html",
        backend="127.0.0.1:5353",
        allowed_clients="127.0.0.0/8, ::1/128",
        maintenance="1.1.1.2, 1.0.0.2, 4.2.2.1, 4.2.2.2",
        hostname="bindguard.local",
        doh_path="/dns-query",
    )


@app.get("/system", response_class=HTMLResponse)
def system_page(request: Request, _: sqlite3.Row = Depends(current_admin)):
    code, logs = run(["journalctl", "-u", "bindguard", "-n", "80", "--no-pager"])
    return render(
        request,
        "system.html",
        named=service_state("named"),
        dnsdist=service_state("dnsdist"),
        bindguard=service_state("bindguard"),
        logs=logs,
        compiler=compiler_status(),
    )
