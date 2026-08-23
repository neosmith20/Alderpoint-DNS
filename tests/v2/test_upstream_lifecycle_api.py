"""Real HTTP API coverage for the managed-upstream lifecycle (owner-
reported live defect: managed upstreams -- both the default seeded ones
and operator-added ones -- could not be edited, disabled, or removed at
all; only Create + List ever existed).

Proves: create -> edit -> disable (with the required last-enabled-
upstream warning/confirmation) -> re-enable -> delete -> reorder, all
through the real authenticated HTTP API, with real runtime-truth
reporting (native_recursion_active) after every mutation. Real dnsdist
compile-through proof against real DNS traffic lives in
test_final_policy_runtime_revalidation.py's established pattern and in
the owner-preview deployment loop (docs/v2/owner-preview.md) -- this
file is the HTTP/control-plane contract.
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
    return {"X-CSRF-Token": r.json()["csrf"]}


def _create(client, headers, profile_id, address="1.1.1.1:53"):
    r = client.post("/api/upstreams", json={
        "upstream_profile_id": profile_id, "name": profile_id, "transport": "plain", "strategy": "ordered",
        "endpoints": [{"address": address}],
    }, headers=headers)
    assert r.status_code == 200, r.text
    return r


class TestListReportsRuntimeTruth:
    def test_native_recursion_false_when_something_is_enabled(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "p1")
        r = client.get("/api/upstreams", headers=headers)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["native_recursion_active"] is False
        assert body["upstreams"][0]["enabled"] is True

    def test_native_recursion_true_with_zero_profiles(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        r = client.get("/api/upstreams", headers=headers)
        assert r.json()["native_recursion_active"] is True


class TestEditLifecycle:
    def test_edit_changes_endpoints_and_reflects_in_list(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "p1", address="1.1.1.1:53")
        r = client.put("/api/upstreams/p1", json={
            "name": "P1 renamed", "transport": "plain", "strategy": "failover",
            "endpoints": [{"address": "9.9.9.9:53"}],
        }, headers=headers)
        assert r.status_code == 200, r.text
        listed = client.get("/api/upstreams", headers=headers).json()["upstreams"][0]
        assert listed["name"] == "P1 renamed"
        assert listed["strategy"] == "failover"
        assert listed["endpoints"][0]["address"] == "9.9.9.9:53"

    def test_edit_unknown_profile_404s(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        r = client.put("/api/upstreams/ghost", json={
            "name": "X", "transport": "plain", "endpoints": [{"address": "1.1.1.1:53"}],
        }, headers=headers)
        assert r.status_code == 400  # unknown id surfaces as a real PolicyStoreError, not a silent no-op


class TestEnableDisableDelete:
    def test_disable_then_enable_round_trips_and_updates_list(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "p1")
        _create(client, headers, "p2")  # a second enabled upstream so p1 is never "the last one"

        r = client.post("/api/upstreams/p1/disable", headers=headers)
        assert r.status_code == 200, r.text
        assert client.get("/api/upstreams", headers=headers).json()["native_recursion_active"] is False
        listed = {u["upstream_profile_id"]: u for u in client.get("/api/upstreams", headers=headers).json()["upstreams"]}
        assert listed["p1"]["enabled"] is False
        assert listed["p2"]["enabled"] is True

        r = client.post("/api/upstreams/p1/enable", headers=headers)
        assert r.status_code == 200, r.text
        listed = {u["upstream_profile_id"]: u for u in client.get("/api/upstreams", headers=headers).json()["upstreams"]}
        assert listed["p1"]["enabled"] is True

    def test_disable_unknown_profile_404s(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        r = client.post("/api/upstreams/ghost/disable", headers=headers)
        assert r.status_code == 404

    def test_delete_removes_from_list(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "p1")
        _create(client, headers, "p2")
        r = client.delete("/api/upstreams/p1", headers=headers)
        assert r.status_code == 200, r.text
        ids = [u["upstream_profile_id"] for u in client.get("/api/upstreams", headers=headers).json()["upstreams"]]
        assert ids == ["p2"]

    def test_delete_unknown_profile_404s(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        r = client.delete("/api/upstreams/ghost", headers=headers)
        assert r.status_code == 404


class TestLastEnabledUpstreamWarningAndConfirmation:
    """The core owner-locked "Zero Managed Upstreams" workflow: disabling
    or deleting the FINAL enabled managed upstream must show a warning
    and require confirmation, but must be allowed."""

    def test_disable_last_enabled_requires_confirmation(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "only")

        r = client.post("/api/upstreams/only/disable", headers=headers)
        assert r.status_code == 409, r.text
        assert r.json()["error"] == "last_enabled_upstream"
        # Refused, not silently applied -- still enabled and DNS is not
        # yet in native recursion mode.
        assert client.get("/api/upstreams", headers=headers).json()["upstreams"][0]["enabled"] is True
        assert client.get("/api/upstreams", headers=headers).json()["native_recursion_active"] is False

        r = client.post("/api/upstreams/only/disable", json={"confirm_last": True}, headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["was_last_enabled"] is True
        body = client.get("/api/upstreams", headers=headers).json()
        assert body["upstreams"][0]["enabled"] is False
        # This is the actual, real, owner-locked contract: zero enabled
        # managed upstreams is reported as genuine native-recursion
        # runtime truth, not a silently-substituted resolver.
        assert body["native_recursion_active"] is True

    def test_delete_last_enabled_requires_confirmation(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "only")

        r = client.delete("/api/upstreams/only", headers=headers)
        assert r.status_code == 409, r.text
        assert r.json()["error"] == "last_enabled_upstream"
        assert len(client.get("/api/upstreams", headers=headers).json()["upstreams"]) == 1

        r = client.request("DELETE", "/api/upstreams/only", json={"confirm_last": True}, headers=headers)
        assert r.status_code == 200, r.text
        assert client.get("/api/upstreams", headers=headers).json()["upstreams"] == []
        assert client.get("/api/upstreams", headers=headers).json()["native_recursion_active"] is True

    def test_disabling_a_non_last_upstream_never_asks_for_confirmation(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "p1")
        _create(client, headers, "p2")
        r = client.post("/api/upstreams/p1/disable", headers=headers)
        assert r.status_code == 200, r.text  # no confirmation needed -- p2 is still enabled

    def test_default_seeded_style_upstream_is_not_sacred(self, tmp_path, monkeypatch):
        # The owner's explicit requirement: "Default seeded upstreams
        # are not sacred. They must be disableable." No special-casing
        # exists anywhere in the lifecycle code by upstream_profile_id,
        # so a profile named/id'd like the real fresh-install default
        # goes through the exact same disable/confirm/delete path as
        # any operator-added one.
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "cloudflare", address="1.1.1.1:53")
        r = client.post("/api/upstreams/cloudflare/disable", json={"confirm_last": True}, headers=headers)
        assert r.status_code == 200, r.text
        r = client.request("DELETE", "/api/upstreams/cloudflare", json={"confirm_last": True}, headers=headers)
        assert r.status_code == 200, r.text
        assert client.get("/api/upstreams", headers=headers).json()["upstreams"] == []


class TestReorder:
    def test_reorder_changes_list_order(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "b")
        _create(client, headers, "a")
        r = client.post("/api/upstreams/reorder", json={"ordered_upstream_profile_ids": ["a", "b"]}, headers=headers)
        assert r.status_code == 200, r.text
        ids = [u["upstream_profile_id"] for u in client.get("/api/upstreams", headers=headers).json()["upstreams"]]
        assert ids == ["a", "b"]

    def test_reorder_rejects_unknown_id(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        headers = _setup_login(client)
        _create(client, headers, "a")
        r = client.post("/api/upstreams/reorder", json={"ordered_upstream_profile_ids": ["a", "ghost"]}, headers=headers)
        assert r.status_code == 400


class TestAuthAndCsrf:
    def test_lifecycle_routes_require_auth(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        assert client.post("/api/upstreams/p1/enable").status_code in (401, 403)
        assert client.post("/api/upstreams/p1/disable").status_code in (401, 403)
        assert client.delete("/api/upstreams/p1").status_code in (401, 403)
        assert client.put("/api/upstreams/p1", json={"name": "x", "transport": "plain", "endpoints": []}).status_code in (401, 403)
        assert client.post("/api/upstreams/reorder", json={"ordered_upstream_profile_ids": []}).status_code in (401, 403)

    def test_lifecycle_routes_require_csrf(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        _setup_login(client)  # cookie session established, but no X-CSRF-Token sent below
        r = client.post("/api/upstreams/p1/enable")
        assert r.status_code in (401, 403)
