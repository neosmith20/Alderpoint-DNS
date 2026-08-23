"""Tests for the appliance's real, detected IANA timezone (owner-reported
requirement: the "Appliance Time" timestamp display mode must reflect
whatever this specific Debian box is actually configured with -- never a
hardcoded geographic timezone anywhere in the product).
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
    client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
    r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
    return r.json()["csrf"]


class TestDetectApplianceTimezone:
    def test_reads_real_etc_timezone_file(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        fake_tz_file = tmp_path / "timezone"
        fake_tz_file.write_text("America/Denver\n", encoding="utf-8")
        monkeypatch.setattr(webapp, "Path", webapp.Path)  # no-op, keeps Path importable for the closure below

        import pathlib

        real_path_init = pathlib.Path

        def _fake_path(p, *args):
            if str(p) == "/etc/timezone":
                return fake_tz_file
            return real_path_init(p, *args)

        monkeypatch.setattr(webapp, "Path", _fake_path)
        assert webapp._detect_appliance_timezone() == "America/Denver"

    def test_falls_back_to_localtime_symlink_when_etc_timezone_missing(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        import pathlib

        real_path_init = pathlib.Path

        def _fake_path(p, *args):
            if str(p) == "/etc/timezone":
                return real_path_init(str(tmp_path / "does-not-exist"))
            return real_path_init(p, *args)

        monkeypatch.setattr(webapp, "Path", _fake_path)
        monkeypatch.setattr(webapp.os, "readlink", lambda p: "/usr/share/zoneinfo/Europe/London" if p == "/etc/localtime" else (_ for _ in ()).throw(OSError()))
        assert webapp._detect_appliance_timezone() == "Europe/London"

    def test_falls_back_to_etc_utc_when_neither_source_is_usable(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        import pathlib

        real_path_init = pathlib.Path

        def _fake_path(p, *args):
            if str(p) == "/etc/timezone":
                return real_path_init(str(tmp_path / "does-not-exist"))
            return real_path_init(p, *args)

        monkeypatch.setattr(webapp, "Path", _fake_path)

        def _raise(_p):
            raise OSError("no such symlink")

        monkeypatch.setattr(webapp.os, "readlink", _raise)
        assert webapp._detect_appliance_timezone() == "Etc/UTC"


class TestForcedApplianceTimezoneOverride:
    def test_env_override_wins_over_real_detection(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        monkeypatch.setenv("ALDERPOINTDNS_V2_FORCE_APPLIANCE_TIMEZONE", "Asia/Tokyo")
        assert webapp._detect_appliance_timezone() == "Asia/Tokyo"


class TestSystemStatusRoute:
    def test_exposes_timezone_to_an_authenticated_admin(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        _setup_login(client)
        r = client.get("/api/system/status")
        assert r.status_code == 200, r.text
        body = r.json()
        assert "timezone" in body
        assert isinstance(body["timezone"], str) and body["timezone"]

    def test_requires_auth(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        r = client.get("/api/system/status")
        assert r.status_code in (401, 403)
