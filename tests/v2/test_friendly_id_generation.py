"""Owner RC45 finding, priority 2 of the second beta-rescue pass: normal
operator forms used to require typing an internal identifier (Network ID,
Group ID, Service ID, Ruleset ID, Schedule ID, Upstream Profile ID,
Notification Provider ID, Blocklist Subscription ID) alongside the actual
configuration. This proves the real fix: creating each of these object
types through the ordinary (name-only) shape succeeds, generates a
sensible id, is collision-safe against a second object with the same
name, and that an explicit id is still honored for advanced/scripted
callers (API back-compat)."""

import importlib
import sys

import pytest


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    sb = tmp_path
    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(sb / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(sb / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(sb / "var" / "lib"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")

    (sb / "var" / "lib").mkdir(parents=True, exist_ok=True)
    from app.v2 import control_db, policy_store

    dbpath = str(sb / "var" / "lib" / "control.db")
    control_db.initialize(dbpath)
    policy_store.ensure_schema(dbpath)

    for mod in list(sys.modules):
        if mod == "app.v2.webapp":
            del sys.modules[mod]
    webapp = importlib.import_module("app.v2.webapp")

    from fastapi.testclient import TestClient

    yield webapp, TestClient(webapp.app)


def _setup_and_login(client, username="admin", password="correcthorsebattery12"):
    r = client.post("/api/setup", json={"username": username, "password": password, "confirm_password": password})
    assert r.status_code == 200, r.text
    r = client.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf"]


class TestFriendlyIdGeneration:
    def test_network_created_from_name_alone(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        r = client.post("/api/networks", json={"name": "Office Network", "cidr": "10.0.0.0/24"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        networks = client.get("/api/networks", headers={"X-CSRF-Token": csrf}).json()["networks"]
        assert any(n["network_id"] == "office-network" for n in networks), networks

    def test_network_name_collision_gets_distinct_id(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        client.post("/api/networks", json={"name": "Guest", "cidr": "10.0.1.0/24"}, headers={"X-CSRF-Token": csrf})
        r2 = client.post("/api/networks", json={"name": "Guest", "cidr": "10.0.2.0/24"}, headers={"X-CSRF-Token": csrf})
        assert r2.status_code == 200, r2.text
        ids = {n["network_id"] for n in client.get("/api/networks", headers={"X-CSRF-Token": csrf}).json()["networks"]}
        assert {"guest", "guest-2"} <= ids, ids

    def test_network_explicit_id_still_honored(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        r = client.post("/api/networks", json={"network_id": "custom-lan", "cidr": "10.0.3.0/24"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        ids = {n["network_id"] for n in client.get("/api/networks", headers={"X-CSRF-Token": csrf}).json()["networks"]}
        assert "custom-lan" in ids

    def test_network_without_name_or_id_rejected_cleanly(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        r = client.post("/api/networks", json={"cidr": "10.0.4.0/24"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 400
        assert r.json()["error"] == "validation_error"

    def test_group_created_from_name_alone(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        r = client.post("/api/groups", json={"name": "Kids"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        assert r.json()["group_id"] == "kids"
        groups = client.get("/api/groups", headers={"X-CSRF-Token": csrf}).json()["groups"]
        assert any(g["group_id"] == "kids" and g["name"] == "Kids" for g in groups), groups

    def test_service_created_from_display_name_alone(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        r = client.post(
            "/api/services",
            json={"display_name": "TikTok", "domains": [{"match_kind": "suffix", "domain": "tiktok.com"}]},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        assert r.json()["service_id"] == "tiktok"

    def test_service_ruleset_created_from_name_alone(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        client.post(
            "/api/services",
            json={"display_name": "TikTok", "domains": [{"match_kind": "suffix", "domain": "tiktok.com"}]},
            headers={"X-CSRF-Token": csrf},
        )
        r = client.post(
            "/api/service-rulesets", json={"name": "Social Media", "service_ids": ["tiktok"]}, headers={"X-CSRF-Token": csrf}
        )
        assert r.status_code == 200, r.text
        assert r.json()["ruleset_id"] == "social-media"

    def test_schedule_created_from_name_alone(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        r = client.post(
            "/api/schedules",
            json={"name": "School Hours", "timezone": "UTC", "windows": [{"start": "08:00", "end": "15:00", "weekdays": [0, 1, 2, 3, 4]}]},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        assert r.json()["schedule_id"] == "school-hours"

    def test_upstream_profile_created_from_name_alone(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        r = client.post(
            "/api/upstreams",
            json={
                "name": "Cloudflare",
                "transport": "plain",
                "strategy": "ordered",
                "endpoints": [{"address": "1.1.1.1:53"}],
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        assert r.json()["upstream_profile_id"] == "cloudflare"

    def test_notification_provider_created_from_display_name_alone(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        r = client.post(
            "/api/notifications",
            json={"display_name": "Ops Slack", "kind": "webhook", "endpoint": "https://hooks.example/x"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        assert r.json()["provider"]["provider_id"] == "ops-slack"

    def test_blocklist_subscription_created_from_name_alone(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(client)
        r = client.post(
            "/api/blocklists",
            json={"name": "StevenBlack Unified Hosts", "url": "https://example.com/hosts.txt", "category": "ads_trackers"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        subs = client.get("/api/blocklists", headers={"X-CSRF-Token": csrf}).json()["subscriptions"]
        assert any(s["subscription_id"] == "stevenblack-unified-hosts" for s in subs), subs
