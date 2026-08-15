import importlib
import sys


def _fresh_webapp(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    from app.v2 import control_db, policy_store

    control_db.initialize(tmp_path / "state" / "control.db")
    policy_store.ensure_schema(tmp_path / "state" / "control.db")
    sys.modules.pop("app.v2.webapp", None)
    return importlib.import_module("app.v2.webapp")


def _client(webapp):
    from fastapi.testclient import TestClient

    return TestClient(webapp.app)


def _setup_login(webapp, client):
    webapp.BOOTSTRAP_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    webapp.BOOTSTRAP_TOKEN_PATH.write_text("setup-token")
    r = client.post(
        "/api/setup",
        json={"setup_token": "setup-token", "username": "admin", "password": "correcthorsebattery12"},
    )
    assert r.status_code == 200, r.text
    r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
    assert r.status_code == 200, r.text
    return r.json()["csrf"]


def test_ui_shell_and_static_assets_are_served(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)

    r = client.get("/")
    assert r.status_code == 200
    assert "Alderpoint DNS" in r.text
    assert "/ui-static/app.css" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]

    css = client.get("/ui-static/app.css")
    js = client.get("/ui-static/app.js")
    assert css.status_code == 200
    assert js.status_code == 200
    assert "purple" not in css.text.lower()


def test_session_endpoint_returns_csrf_for_refresh_recovery(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    csrf = _setup_login(webapp, client)

    r = client.get("/api/session")
    assert r.status_code == 200
    assert r.json()["csrf"] == csrf
    assert r.json()["username"] == "admin"


def test_ui_supporting_inventory_routes_are_authenticated(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    for path in (
        "/api/groups",
        "/api/services",
        "/api/service-rulesets",
        "/api/schedules",
        "/api/domain-routing",
        "/api/local-dns",
    ):
        assert client.get(path).status_code == 401, path


def test_ui_create_flow_uses_real_csrf_and_runtime_promote(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    csrf = _setup_login(webapp, client)

    r = client.post("/api/groups", json={"group_id": "staff", "name": "Staff", "priority": 50}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    r = client.post("/api/clients", json={"name": "Workstation", "description": ""}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    client_id = r.json()["client_id"]
    r = client.post(f"/api/clients/{client_id}/groups", json={"group_id": "staff"}, headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, r.text
    r = client.put(
        f"/api/policy/client/{client_id}",
        json={"safesearch_mode": "strict", "query_log_enabled": False},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.text
    assert r.json()["runtime"]["promoted"] is True

    clients = client.get("/api/clients").json()["clients"]
    assert clients[0]["groups"][0]["group_id"] == "staff"
    assert clients[0]["policy"]["safesearch_mode"] == "strict"
    assert clients[0]["policy"]["query_log_enabled"] is False


def test_duplicate_identifier_returns_structured_conflict_not_500(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    csrf = _setup_login(webapp, client)

    first = client.post("/api/clients", json={"name": "One", "description": ""}, headers={"X-CSRF-Token": csrf})
    second = client.post("/api/clients", json={"name": "Two", "description": ""}, headers={"X-CSRF-Token": csrf})
    assert first.status_code == 200
    assert second.status_code == 200

    payload = {"kind": "ipv4", "value": "10.0.0.44"}
    r1 = client.post(f"/api/clients/{first.json()['client_id']}/identifiers", json=payload, headers={"X-CSRF-Token": csrf})
    r2 = client.post(f"/api/clients/{second.json()['client_id']}/identifiers", json=payload, headers={"X-CSRF-Token": csrf})
    assert r1.status_code == 200
    assert r2.status_code == 409
    assert r2.json()["error"] == "identifier_conflict"


def test_ui_assets_do_not_contain_internal_design_commentary():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "app" / "v2" / "ui"
    prohibited = ("AI-generated UI", "vibecoding", "vibecoded", "Claude", "CC", "Dex")
    combined = "\n".join(p.read_text(encoding="utf-8") for p in root.glob("*") if p.is_file())
    for term in prohibited:
        assert term not in combined
