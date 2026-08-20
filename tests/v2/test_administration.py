"""Tests for the administration password-change/session-revocation
routes (beta-rescue priority 5 parity-audit fix): RC43 had no way for an
operator to change their own password or revoke other sessions at all,
a real gap against V1.1.1's always-present Administration page.
"""

from __future__ import annotations

import importlib
import sys

from app.v2 import control_db, policy_store as store


def _fresh_webapp(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    control_db.initialize(tmp_path / "state" / "control.db")
    store.ensure_schema(tmp_path / "state" / "control.db")
    sys.modules.pop("app.v2.webapp", None)
    return importlib.import_module("app.v2.webapp")


def _client(webapp):
    from fastapi.testclient import TestClient

    return TestClient(webapp.app)


def _setup_login(client):
    client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12"})
    r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
    return r.json()["csrf"]


class TestPasswordChange:
    def test_change_password_then_old_password_no_longer_works(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        csrf = _setup_login(client)

        r = client.post(
            "/api/session/password",
            json={"current_password": "correcthorsebattery12", "new_password": "brandnewpassword99"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text

        client.post("/api/logout", headers={"X-CSRF-Token": csrf})
        failed = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert failed.status_code == 401

        ok = client.post("/api/login", json={"username": "admin", "password": "brandnewpassword99"})
        assert ok.status_code == 200

    def test_wrong_current_password_is_rejected(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        csrf = _setup_login(client)
        r = client.post(
            "/api/session/password",
            json={"current_password": "totally-wrong", "new_password": "brandnewpassword99"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "incorrect_password"

        # Old password still works -- the rejected attempt changed nothing.
        client.post("/api/logout", headers={"X-CSRF-Token": csrf})
        still_ok = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert still_ok.status_code == 200

    def test_too_short_new_password_is_rejected(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        csrf = _setup_login(client)
        r = client.post(
            "/api/session/password",
            json={"current_password": "correcthorsebattery12", "new_password": "short"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 422  # pydantic min_length validation

    def test_password_change_is_audit_logged(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        csrf = _setup_login(client)
        client.post(
            "/api/session/password",
            json={"current_password": "correcthorsebattery12", "new_password": "brandnewpassword99"},
            headers={"X-CSRF-Token": csrf},
        )
        with control_db.connect(tmp_path / "state" / "control.db") as conn:
            rows = conn.execute("SELECT action, success FROM admin_audit_log WHERE action='password_change'").fetchall()
        assert rows == [("password_change", 1)]


class TestRevokeOtherSessions:
    def test_revokes_other_sessions_but_not_this_one(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        csrf = _setup_login(client)

        # A second "session" (another login as the same admin, e.g. a
        # different browser).
        from fastapi.testclient import TestClient

        client2 = TestClient(webapp.app)
        r2 = client2.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert r2.status_code == 200

        r = client.post("/api/session/revoke-others", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200
        assert r.json()["revoked_count"] == 1

        # This session (client) is still valid.
        assert client.get("/api/session").status_code == 200
        # The other session (client2) is no longer valid.
        assert client2.get("/api/session").status_code == 401

    def test_unauthenticated_routes_are_rejected(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        assert client.post("/api/session/password", json={"current_password": "x", "new_password": "y" * 12}).status_code == 401
        assert client.post("/api/session/revoke-others").status_code == 401
