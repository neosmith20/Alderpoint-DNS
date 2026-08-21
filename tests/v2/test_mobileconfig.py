"""Tests for app/v2/mobileconfig.py (beta-rescue priority 3D: Apple
.mobileconfig enrollment profiles). Real plistlib-generated profiles,
real gating on transport enablement and real certificate state, never
advertising a disabled transport, never carrying key material.
"""

from __future__ import annotations

import plistlib

import pytest

from app.v2 import mobileconfig
from app.v2 import tls_cert
from app.v2.policy_store import DnsTransportSettings


def _cert_info(san=("dns.example.appliance",)):
    return tls_cert.CertInfo(
        subject="CN=Test", not_valid_before="2026-01-01T00:00:00", not_valid_after="2027-01-01T00:00:00",
        san=san, is_self_signed=True,
    )


class TestBuildMobileconfig:
    def test_doh_profile_when_enabled(self):
        transport = DnsTransportSettings(doh_enabled=True, doh_port=443, doh_path="/dns-query")
        profile_bytes = mobileconfig.build_mobileconfig("doh", transport, _cert_info())
        parsed = plistlib.loads(profile_bytes)
        assert parsed["PayloadType"] == "Configuration"
        payload = parsed["PayloadContent"][0]
        assert payload["DNSProtocol"] == "HTTPS"
        assert payload["ServerURL"] == "https://dns.example.appliance:443/dns-query"
        assert payload["ServerName"] == "dns.example.appliance"

    def test_dot_profile_when_enabled(self):
        transport = DnsTransportSettings(dot_enabled=True)
        profile_bytes = mobileconfig.build_mobileconfig("dot", transport, _cert_info())
        parsed = plistlib.loads(profile_bytes)
        payload = parsed["PayloadContent"][0]
        assert payload["DNSProtocol"] == "TLS"
        assert payload["ServerName"] == "dns.example.appliance"

    def test_refuses_disabled_transport(self):
        transport = DnsTransportSettings(doh_enabled=False)
        with pytest.raises(mobileconfig.MobileconfigError, match="not enabled"):
            mobileconfig.build_mobileconfig("doh", transport, _cert_info())

    def test_refuses_unsupported_protocol(self):
        transport = DnsTransportSettings(doh_enabled=True)
        with pytest.raises(mobileconfig.MobileconfigError, match="unsupported protocol"):
            mobileconfig.build_mobileconfig("doq", transport, _cert_info())

    def test_refuses_when_no_certificate_configured(self):
        transport = DnsTransportSettings(doh_enabled=True)
        with pytest.raises(mobileconfig.MobileconfigError, match="certificate"):
            mobileconfig.build_mobileconfig("doh", transport, None)

    def test_profile_never_contains_key_material(self):
        transport = DnsTransportSettings(dot_enabled=True)
        profile_bytes = mobileconfig.build_mobileconfig("dot", transport, _cert_info())
        text = profile_bytes.decode("utf-8", errors="ignore").upper()
        assert "PRIVATE KEY" not in text
        assert "BEGIN RSA" not in text
        assert "BEGIN EC" not in text


class TestMobileconfigApiRoute:
    def _fresh_webapp(self, tmp_path, monkeypatch):
        import importlib
        import sys

        from app.v2 import control_db, policy_store

        monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
        (tmp_path / "state").mkdir(parents=True, exist_ok=True)
        control_db.initialize(tmp_path / "state" / "control.db")
        policy_store.ensure_schema(tmp_path / "state" / "control.db")
        sys.modules.pop("app.v2.webapp", None)
        return importlib.import_module("app.v2.webapp")

    def test_disabled_transport_returns_clean_400_not_a_broken_download(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        r = client.get("/api/dns-transports/mobileconfig/doh")
        assert r.status_code == 400
        assert r.json()["error"] == "unavailable"

    def test_enabled_doh_with_real_cert_produces_a_real_downloadable_profile(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]

        # A real active cert is generated at first admin creation
        # (self-signed) in the real appliance -- here, materialize it the
        # same way for a real, non-mocked CertInfo.
        cert, key = tls_cert.generate_self_signed(("dns.test.appliance",))
        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        webapp.ACTIVE_CERT_PATH.write_bytes(cert)
        webapp.ACTIVE_KEY_PATH.write_bytes(key)

        enable = client.put("/api/dns-transports", json={"doh_enabled": True}, headers={"X-CSRF-Token": csrf})
        assert enable.status_code == 200, enable.text

        profile = client.get("/api/dns-transports/mobileconfig/doh")
        assert profile.status_code == 200, profile.text
        parsed = plistlib.loads(profile.content)
        assert parsed["PayloadContent"][0]["ServerName"] == "dns.test.appliance"

    def test_unauthenticated_route_is_rejected(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        assert client.get("/api/dns-transports/mobileconfig/doh").status_code == 401
