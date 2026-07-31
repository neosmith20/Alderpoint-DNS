#!/usr/bin/env python3
"""Provider-neutral notification framework for Alderpoint DNS.

Two underlying provider kinds -- SMTP email and generic HTTP webhook -- back
every supported destination. Discord/Slack/Microsoft Teams/ntfy/Gotify/
Pushover are all webhook providers with a ``preset`` selecting how the
message is formatted for that service, not separate provider types.

Secret handling: a webhook's URL is itself a bearer credential for most of
these services (Discord/Slack/Teams/ntfy-with-auth/Gotify embed a token
directly in the URL; Pushover needs an app token and user key), so the
entire ``secret`` column -- not a separate "token" field -- is what's masked
and never rendered back to the browser, mirroring app/encryption.py's rule
that private key contents are never rendered back. Non-secret shape (host,
port, from/to addresses, preset choice) lives in ``config_json`` and is
freely displayed. There is no field-level encryption-at-rest here (this
codebase has none for any DB-stored secret); protection is the same trust
boundary as the rest of the database file: `alderpointdns:alderpointdns`
ownership and restrictive permissions, set up at install time.

Messages sent to any provider are built only from a fixed set of fields
(severity, host, component, summary, when it began, whether it recovered, an
optional admin link) -- never raw configuration, passwords, API keys, or DNS
query contents.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import smtplib
import sqlite3
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx

DB_PATH = Path("/var/lib/alderpointdns/alderpointdns.db")


class AlderpointDNSConnection(sqlite3.Connection):
    """Closes on exit like a plain connection factory would, but only once
    the outermost `with` block exits -- dispatch() and others reuse an
    already-open connection as their own nested `with conn: ...` transaction
    boundary, which would otherwise have the connection closed out from
    under them by the first nested block's __exit__."""

    def __enter__(self):
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 0) + 1
        return super().__enter__()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        super().__exit__(exc_type, exc_value, traceback)
        self._alderpointdns_depth = getattr(self, "_alderpointdns_depth", 1) - 1
        if self._alderpointdns_depth <= 0:
            self.close()

SEVERITIES = ("info", "warning", "critical")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

PROVIDER_KINDS = ("smtp", "webhook")
WEBHOOK_PRESETS = ("generic", "discord", "slack", "teams", "ntfy", "gotify", "pushover")

# The full event catalog shown in the subscription UI. "wired" categories
# have a real checker (see app/notify_check.py); the rest are defined so
# operators can see and pre-configure them, but nothing evaluates them yet
# -- see docs/known-limitations.md.
EVENT_CATEGORIES: dict[str, dict[str, Any]] = {
    "service_unavailable": {"label": "named, dnsdist, Alderpoint DNS web, or analytics service unavailable", "wired": True, "default_severity": "critical"},
    "service_repeated_restart": {"label": "Repeated service restart", "wired": True, "default_severity": "warning"},
    "resolver_degraded": {"label": "Upstream resolver degraded", "wired": True, "default_severity": "warning"},
    "resolver_all_unavailable": {"label": "All upstream resolvers unavailable", "wired": True, "default_severity": "critical"},
    "blocklist_update_failure": {"label": "Blocklist update failure", "wired": True, "default_severity": "warning"},
    "deploy_failure": {"label": "Configuration compilation or deployment failure", "wired": True, "default_severity": "critical"},
    "backup_failure": {"label": "Backup failure", "wired": True, "default_severity": "warning"},
    "replication_delayed": {"label": "Replication delayed or failed", "wired": True, "default_severity": "warning"},
    "tls_cert_expiring": {"label": "TLS certificate approaching expiration", "wired": False, "default_severity": "warning"},
    "low_disk_space": {"label": "Low disk space", "wired": False, "default_severity": "warning"},
    "abnormal_servfail_rate": {"label": "Abnormal SERVFAIL rate", "wired": False, "default_severity": "warning"},
}

DEFAULT_COOLDOWN_MINUTES = 30


class NotificationError(ValueError):
    pass


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    """Returns a connection meant to be used as `with connect() as conn: ...`
    (AlderpointDNSConnection.__exit__ closes it in addition to the stdlib's
    commit/rollback-on-exit) -- callers holding the connection open across a
    function body instead use `db.close()` in a `finally` block themselves."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, factory=AlderpointDNSConnection, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        db.execute(
            "INSERT OR IGNORE INTO notification_settings(key, value) VALUES ('cooldown_minutes', ?)",
            (str(DEFAULT_COOLDOWN_MINUTES),),
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_providers (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL DEFAULT '{}',
                secret TEXT NOT NULL DEFAULT '',
                last_test_at TEXT,
                last_test_ok INTEGER,
                last_failure_at TEXT,
                last_failure_error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_subscriptions (
                id INTEGER PRIMARY KEY,
                provider_id INTEGER NOT NULL,
                event_category TEXT NOT NULL,
                min_severity TEXT NOT NULL DEFAULT 'warning',
                enabled INTEGER NOT NULL DEFAULT 1,
                cooldown_minutes INTEGER,
                UNIQUE(provider_id, event_category)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_rate_state (
                event_category TEXT NOT NULL,
                provider_id INTEGER NOT NULL,
                last_sent_at TEXT,
                last_fingerprint TEXT,
                suppressed_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(event_category, provider_id)
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_history (
                id INTEGER PRIMARY KEY,
                at TEXT NOT NULL,
                event_category TEXT NOT NULL,
                severity TEXT NOT NULL,
                host TEXT NOT NULL DEFAULT '',
                component TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL DEFAULT '',
                began_at TEXT,
                recovered INTEGER NOT NULL DEFAULT 0,
                admin_link TEXT NOT NULL DEFAULT '',
                provider_id INTEGER,
                provider_name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                error TEXT NOT NULL DEFAULT ''
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_check_state (
                event_category TEXT NOT NULL,
                component TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT '',
                extra TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                PRIMARY KEY(event_category, component)
            )
            """
        )
        if close:
            db.commit()
    finally:
        if close:
            db.close()


def settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        return {row["key"]: row["value"] for row in db.execute("SELECT key, value FROM notification_settings")}
    finally:
        if close:
            db.close()


def update_settings(values: dict[str, Any]) -> None:
    with connect() as conn:
        init_db(conn)
        with conn:
            if "cooldown_minutes" in values:
                minutes = int(values["cooldown_minutes"])
                if minutes < 0 or minutes > 24 * 60:
                    raise NotificationError("cooldown must be between 0 and 1440 minutes")
                conn.execute(
                    "INSERT INTO notification_settings(key, value) VALUES ('cooldown_minutes', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(minutes),),
                )


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------

def _validate_provider(kind: str, config: dict[str, Any]) -> dict[str, Any]:
    if kind not in PROVIDER_KINDS:
        raise NotificationError(f"unknown provider kind {kind!r}")
    clean: dict[str, Any] = {}
    if kind == "smtp":
        host = str(config.get("host", "")).strip()
        if not host:
            raise NotificationError("SMTP host is required")
        try:
            port = int(config.get("port", 587))
        except (TypeError, ValueError):
            raise NotificationError("SMTP port must be a number") from None
        if not (1 <= port <= 65535):
            raise NotificationError("SMTP port must be between 1 and 65535")
        from_addr = str(config.get("from_addr", "")).strip()
        to_addrs = str(config.get("to_addrs", "")).strip()
        if not from_addr or not to_addrs:
            raise NotificationError("SMTP sender and at least one recipient are required")
        clean = {
            "host": host,
            "port": port,
            "use_tls": bool(config.get("use_tls", True)),
            "from_addr": from_addr,
            "to_addrs": to_addrs,
            "username": str(config.get("username", "")).strip(),
        }
    else:
        preset = str(config.get("preset", "generic")).strip().lower()
        if preset not in WEBHOOK_PRESETS:
            raise NotificationError(f"unknown webhook preset {preset!r}")
        clean = {"preset": preset}
    return clean


def add_provider(kind: str, name: str, config: dict[str, Any], secret: str, enabled: bool = True) -> int:
    clean_name = (name or "").strip()
    if not clean_name:
        raise NotificationError("provider name is required")
    clean_config = _validate_provider(kind, config)
    if not (secret or "").strip() and kind == "webhook":
        raise NotificationError("webhook URL is required")
    with connect() as conn:
        init_db(conn)
        with conn:
            ts = now()
            cursor = conn.execute(
                "INSERT INTO notification_providers(kind, name, enabled, config_json, secret, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (kind, clean_name, 1 if enabled else 0, json.dumps(clean_config), secret or "", ts, ts),
            )
            return cursor.lastrowid


_UNSET = object()


def update_provider(
    provider_id: int,
    name: str | None = None,
    config: dict[str, Any] | None = None,
    secret: Any = _UNSET,
    enabled: bool | None = None,
) -> None:
    """`secret` left unset (the default) preserves the stored secret --
    matches the write-only masked-field UX (a blank "leave unchanged" input
    in the edit form) used elsewhere (app/encryption.py's cert upload)."""
    with connect() as conn:
        init_db(conn)
        row = conn.execute("SELECT * FROM notification_providers WHERE id=?", (provider_id,)).fetchone()
        if not row:
            raise NotificationError(f"notification provider {provider_id} not found")
        with conn:
            new_name = (name or "").strip() or row["name"]
            new_config = _validate_provider(row["kind"], config) if config is not None else json.loads(row["config_json"])
            new_secret = row["secret"] if secret is _UNSET or secret is None or secret == "" else secret
            new_enabled = row["enabled"] if enabled is None else (1 if enabled else 0)
            conn.execute(
                "UPDATE notification_providers SET name=?, config_json=?, secret=?, enabled=?, updated_at=? WHERE id=?",
                (new_name, json.dumps(new_config), new_secret, new_enabled, now(), provider_id),
            )


def delete_provider(provider_id: int) -> None:
    with connect() as conn:
        init_db(conn)
        with conn:
            conn.execute("DELETE FROM notification_subscriptions WHERE provider_id=?", (provider_id,))
            conn.execute("DELETE FROM notification_rate_state WHERE provider_id=?", (provider_id,))
            conn.execute("DELETE FROM notification_providers WHERE id=?", (provider_id,))


def toggle_provider(provider_id: int) -> None:
    with connect() as conn:
        init_db(conn)
        with conn:
            conn.execute("UPDATE notification_providers SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?", (now(), provider_id))


def clear_provider_failure(provider_id: int) -> None:
    with connect() as conn:
        init_db(conn)
        with conn:
            conn.execute("UPDATE notification_providers SET last_failure_at=NULL, last_failure_error='' WHERE id=?", (provider_id,))


def _public_provider(row: sqlite3.Row) -> dict[str, Any]:
    """A provider dict safe to render: never includes `secret`."""
    return {
        "id": row["id"],
        "kind": row["kind"],
        "name": row["name"],
        "enabled": bool(row["enabled"]),
        "config": json.loads(row["config_json"]),
        "has_secret": bool(row["secret"]),
        "last_test_at": row["last_test_at"],
        "last_test_ok": None if row["last_test_ok"] is None else bool(row["last_test_ok"]),
        "last_failure_at": row["last_failure_at"],
        "last_failure_error": row["last_failure_error"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_providers(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        return [_public_provider(row) for row in db.execute("SELECT * FROM notification_providers ORDER BY name")]
    finally:
        if close:
            db.close()


def get_provider_row(provider_id: int, conn: sqlite3.Connection | None = None) -> sqlite3.Row | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        return db.execute("SELECT * FROM notification_providers WHERE id=?", (provider_id,)).fetchone()
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------

def set_subscription(provider_id: int, event_category: str, min_severity: str, enabled: bool, cooldown_minutes: int | None = None) -> None:
    if event_category not in EVENT_CATEGORIES:
        raise NotificationError(f"unknown event category {event_category!r}")
    if min_severity not in SEVERITIES:
        raise NotificationError(f"unknown severity {min_severity!r}")
    with connect() as conn:
        init_db(conn)
        with conn:
            conn.execute(
                """
                INSERT INTO notification_subscriptions(provider_id, event_category, min_severity, enabled, cooldown_minutes)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(provider_id, event_category) DO UPDATE SET
                    min_severity=excluded.min_severity, enabled=excluded.enabled, cooldown_minutes=excluded.cooldown_minutes
                """,
                (provider_id, event_category, min_severity, 1 if enabled else 0, cooldown_minutes),
            )


def delete_subscription(subscription_id: int) -> None:
    with connect() as conn:
        init_db(conn)
        with conn:
            conn.execute("DELETE FROM notification_subscriptions WHERE id=?", (subscription_id,))


def list_subscriptions(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        rows = db.execute(
            """
            SELECT notification_subscriptions.*, notification_providers.name AS provider_name, notification_providers.kind AS provider_kind
            FROM notification_subscriptions JOIN notification_providers ON notification_providers.id = notification_subscriptions.provider_id
            ORDER BY notification_providers.name, notification_subscriptions.event_category
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Message formatting and delivery
# ---------------------------------------------------------------------------

@dataclass
class NotificationMessage:
    event_category: str
    severity: str
    host: str
    component: str
    summary: str
    began_at: str
    recovered: bool = False
    admin_link: str = ""

    def title(self) -> str:
        prefix = "RECOVERED" if self.recovered else self.severity.upper()
        return f"[{prefix}] {self.component}: {self.summary}"

    def body_lines(self) -> list[str]:
        lines = [
            f"Severity: {'recovered' if self.recovered else self.severity}",
            f"Host: {self.host}",
            f"Component: {self.component}",
            f"What happened: {self.summary}",
            f"Began: {self.began_at}",
            f"Recovered: {'yes' if self.recovered else 'no'}",
        ]
        if self.admin_link:
            lines.append(f"Details: {self.admin_link}")
        return lines


def _send_smtp(provider_config: dict[str, Any], secret: str, message: NotificationMessage) -> None:
    msg = EmailMessage()
    msg["Subject"] = message.title()
    msg["From"] = provider_config["from_addr"]
    to_addrs = [addr.strip() for addr in provider_config["to_addrs"].split(",") if addr.strip()]
    msg["To"] = ", ".join(to_addrs)
    msg.set_content("\n".join(message.body_lines()))
    with smtplib.SMTP(provider_config["host"], provider_config["port"], timeout=10) as client:
        if provider_config.get("use_tls"):
            client.starttls()
        username = provider_config.get("username")
        if username and secret:
            client.login(username, secret)
        client.send_message(msg, to_addrs=to_addrs)


_SEVERITY_COLOR = {"info": "4a90d9", "warning": "e3a008", "critical": "e02424"}


def _webhook_payload(preset: str, message: NotificationMessage) -> tuple[dict[str, Any] | None, str | None, dict[str, str]]:
    """Returns (json_body, text_body, extra_headers); exactly one of
    json_body/text_body is set."""
    title = message.title()
    body = "\n".join(message.body_lines())
    if preset == "discord":
        return {"content": f"**{title}**\n{body}"}, None, {}
    if preset == "slack":
        return {"text": f"*{title}*\n{body}"}, None, {}
    if preset == "teams":
        return (
            {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": title,
                "themeColor": _SEVERITY_COLOR.get(message.severity, "4a90d9"),
                "title": title,
                "text": body.replace("\n", "\n\n"),
            },
            None,
            {},
        )
    if preset == "ntfy":
        priority = {"info": "3", "warning": "4", "critical": "5"}.get(message.severity, "3")
        return None, body, {"Title": title, "Priority": priority}
    if preset == "gotify":
        priority = {"info": 2, "warning": 5, "critical": 9}.get(message.severity, 5)
        return {"title": title, "message": body, "priority": priority}, None, {}
    if preset == "pushover":
        # Handled specially by _send_webhook (form-encoded with token/user).
        return {"title": title, "message": body}, None, {}
    return (
        {
            "event_category": message.event_category,
            "severity": message.severity,
            "host": message.host,
            "component": message.component,
            "summary": message.summary,
            "began_at": message.began_at,
            "recovered": message.recovered,
            "admin_link": message.admin_link,
        },
        None,
        {},
    )


def _send_webhook(provider_config: dict[str, Any], secret: str, message: NotificationMessage) -> None:
    preset = provider_config.get("preset", "generic")
    json_body, text_body, headers = _webhook_payload(preset, message)
    with httpx.Client(timeout=10) as client:
        if preset == "pushover":
            if ":" not in secret:
                raise NotificationError("Pushover secret must be '<user_key>:<app_token>'")
            user_key, app_token = secret.split(":", 1)
            form = dict(json_body or {})
            form.update({"token": app_token, "user": user_key})
            response = client.post("https://api.pushover.net/1/messages.json", data=form)
        elif json_body is not None:
            response = client.post(secret, json=json_body, headers=headers)
        else:
            response = client.post(secret, content=text_body, headers=headers)
        response.raise_for_status()


def send_provider(provider: sqlite3.Row, message: NotificationMessage) -> tuple[bool, str]:
    """Sends `message` through `provider` directly, bypassing subscriptions/
    cooldown -- used for both real dispatch (per-subscription) and the
    "send test notification" UI action."""
    config = json.loads(provider["config_json"])
    try:
        if provider["kind"] == "smtp":
            _send_smtp(config, provider["secret"], message)
        else:
            _send_webhook(config, provider["secret"], message)
        return True, ""
    except Exception as exc:  # noqa: BLE001 - surfaced as delivery failure, not a crash
        return False, str(exc)


def send_test(provider_id: int) -> tuple[bool, str]:
    with connect() as conn:
        init_db(conn)
        provider = conn.execute("SELECT * FROM notification_providers WHERE id=?", (provider_id,)).fetchone()
        if not provider:
            raise NotificationError(f"notification provider {provider_id} not found")
        message = NotificationMessage(
            event_category="test",
            severity="info",
            host="this appliance",
            component="Notifications",
            summary="Test notification from Alderpoint DNS",
            began_at=now(),
        )
        ok, error = send_provider(provider, message)
        with conn:
            conn.execute(
                "UPDATE notification_providers SET last_test_at=?, last_test_ok=?, last_failure_at=?, last_failure_error=? WHERE id=?",
                (now(), 1 if ok else 0, None if ok else now(), "" if ok else error, provider_id),
            )
            conn.execute(
                "INSERT INTO notification_history(at, event_category, severity, host, component, message, began_at, recovered, admin_link, provider_id, provider_name, status, error) VALUES (?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?, ?, ?)",
                (now(), "test", "info", message.host, message.component, message.summary, message.began_at, provider_id, provider["name"], "sent" if ok else "failed", error),
            )
        return ok, error


# ---------------------------------------------------------------------------
# Dispatch: subscriptions, cooldown/dedup, recovery, history
# ---------------------------------------------------------------------------

def _fingerprint(event_category: str, component: str) -> str:
    return hashlib.sha256(f"{event_category}:{component}".encode()).hexdigest()[:16]


def dispatch(
    event_category: str,
    severity: str,
    component: str,
    summary: str,
    began_at: str | None = None,
    recovered: bool = False,
    admin_link: str = "",
    host: str = "this appliance",
) -> list[dict[str, Any]]:
    """Sends `summary` to every enabled subscription for `event_category` at
    or above its configured minimum severity, applying cooldown/duplicate
    suppression (bypassed for recovery notices, which are rare and always
    delivered), and records every outcome (sent/suppressed/failed) to
    notification_history. Returns the per-provider outcomes."""
    if severity not in SEVERITIES:
        raise NotificationError(f"unknown severity {severity!r}")
    began_at = began_at or now()
    message = NotificationMessage(event_category, severity, host, component, summary, began_at, recovered, admin_link)
    fingerprint = _fingerprint(event_category, component)
    results: list[dict[str, Any]] = []
    with connect() as conn:
        init_db(conn)
        cooldown_default = int(settings(conn).get("cooldown_minutes", DEFAULT_COOLDOWN_MINUTES))
        subs = conn.execute(
            """
            SELECT notification_subscriptions.*, notification_providers.*, notification_subscriptions.id AS subscription_id
            FROM notification_subscriptions JOIN notification_providers ON notification_providers.id = notification_subscriptions.provider_id
            WHERE notification_subscriptions.event_category=? AND notification_subscriptions.enabled=1 AND notification_providers.enabled=1
            """,
            (event_category,),
        ).fetchall()
        for sub in subs:
            if _SEVERITY_RANK[severity] < _SEVERITY_RANK[sub["min_severity"]]:
                continue
            provider_id = sub["provider_id"]
            cooldown_minutes = sub["cooldown_minutes"] if sub["cooldown_minutes"] is not None else cooldown_default
            state = conn.execute(
                "SELECT * FROM notification_rate_state WHERE event_category=? AND provider_id=?",
                (event_category, provider_id),
            ).fetchone()
            suppress = False
            if not recovered and state and state["last_fingerprint"] == fingerprint and state["last_sent_at"]:
                elapsed = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(state["last_sent_at"])).total_seconds()
                if elapsed < cooldown_minutes * 60:
                    suppress = True
            if suppress:
                with conn:
                    conn.execute(
                        "UPDATE notification_rate_state SET suppressed_count=suppressed_count+1 WHERE event_category=? AND provider_id=?",
                        (event_category, provider_id),
                    )
                    conn.execute(
                        "INSERT INTO notification_history(at, event_category, severity, host, component, message, began_at, recovered, admin_link, provider_id, provider_name, status, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'suppressed', '')",
                        (now(), event_category, severity, host, component, summary, began_at, 1 if recovered else 0, admin_link, provider_id, sub["name"]),
                    )
                results.append({"provider_id": provider_id, "provider_name": sub["name"], "status": "suppressed"})
                continue
            ok, error = send_provider(sub, message)
            with conn:
                conn.execute(
                    "INSERT INTO notification_rate_state(event_category, provider_id, last_sent_at, last_fingerprint, suppressed_count) VALUES (?, ?, ?, ?, 0) "
                    "ON CONFLICT(event_category, provider_id) DO UPDATE SET last_sent_at=excluded.last_sent_at, last_fingerprint=excluded.last_fingerprint, suppressed_count=0",
                    (event_category, provider_id, now(), fingerprint),
                )
                conn.execute(
                    "INSERT INTO notification_history(at, event_category, severity, host, component, message, began_at, recovered, admin_link, provider_id, provider_name, status, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (now(), event_category, severity, host, component, summary, began_at, 1 if recovered else 0, admin_link, provider_id, sub["name"], "sent" if ok else "failed", error),
                )
                conn.execute(
                    "UPDATE notification_providers SET last_failure_at=?, last_failure_error=? WHERE id=?",
                    (None if ok else now(), "" if ok else error, provider_id),
                )
            results.append({"provider_id": provider_id, "provider_name": sub["name"], "status": "sent" if ok else "failed", "error": error})
    return results


def history(limit: int = 100, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        rows = db.execute("SELECT * FROM notification_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]
    finally:
        if close:
            db.close()


# ---------------------------------------------------------------------------
# Checker state (used by app/notify_check.py for edge detection)
# ---------------------------------------------------------------------------

def get_check_state(event_category: str, component: str, conn: sqlite3.Connection | None = None) -> str | None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        row = db.execute(
            "SELECT state FROM notification_check_state WHERE event_category=? AND component=?",
            (event_category, component),
        ).fetchone()
        return row["state"] if row else None
    finally:
        if close:
            db.close()


def set_check_state(event_category: str, component: str, state: str, conn: sqlite3.Connection | None = None) -> None:
    close = conn is None
    db = conn or connect()
    try:
        init_db(db)
        with db:
            db.execute(
                "INSERT INTO notification_check_state(event_category, component, state, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(event_category, component) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at",
                (event_category, component, state, now()),
            )
    finally:
        if close:
            db.close()
