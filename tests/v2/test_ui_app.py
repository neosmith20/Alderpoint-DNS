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
    r = client.post(
        "/api/setup",
        json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"},
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


def test_backup_page_does_not_auto_probe_default_migration_path(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)

    js = client.get("/ui-static/app.js")
    assert js.status_code == 200
    assert "/api/migration/detect?source_path=/var/lib/alderpointdns/alderpointdns.db" not in js.text
    assert "/api/migration/detect?source_path=${encodeURIComponent(body.source_path)}" in js.text


def test_dashboard_live_initializes_after_panel_exists_and_has_terminal_states(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    js = client.get("/ui-static/app.js").text
    assert "setTimeout(() => {" in js
    assert "liveActivityShell()" in js
    assert "Connected - no recent activity" in js
    assert "Reconnecting" in js
    assert "Queries this second:" in js
    assert "QPS (10s avg):" in js
    assert "Blocked (10s):" in js
    assert "rolling_10s_qps" in js
    assert "rolling_10s_blocked_percent" in js
    assert "/api/analytics/live-activity?seconds=300&bucket_seconds=1" in js
    assert "dashboard-live-svg-host" in js
    assert "overlap_skips" in js


def test_dashboard_live_axis_labels_are_measured_not_fixed_stride(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    js = client.get("/ui-static/app.js").text
    css = client.get("/ui-static/app.css").text
    assert "chooseXAxisTicks" in js
    assert "measureSvgAxisLabel" in js
    assert "measureText" in js
    assert "labelEvery" not in js
    assert ".live-toolbar" in css
    assert "flex-wrap: wrap" in css


def test_performance_report_uses_navigation_ids_and_excludes_background_live(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    js = client.get("/ui-static/app.js").text
    assert "navigation_id" in js
    assert "!e.background" in js
    assert "navigationId: `live-${token}`" in js
    assert "live_render_health" in js


def test_upstream_table_defaults_to_display_order_and_does_not_truncate_addresses(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    js = client.get("/ui-static/app.js").text
    css = client.get("/ui-static/app.css").text
    assert 'data-grid-id="upstream-profiles" data-grid-default-sort-column="1" data-grid-default-sort-direction="asc" data-grid-ignore-stored-sort="1"' in js
    assert "endpoint-chip" in js
    assert 'class="mono truncate"' not in js
    assert ".endpoint-chip" in css


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


def test_query_log_endpoint_uses_bounded_server_side_filters(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_FORCE_ANALYTICS_DEGRADED", "test degraded")
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    _setup_login(webapp, client)

    r = client.get(
        "/api/analytics/query-log",
        params={
            "minutes": "60",
            "domain": "example.com",
            "client": "10.0.0.10",
            "qtype": "A",
            "protocol": "udp",
            "blocked_only": "true",
            "rcode": "0",
            "upstream": "default",
            "cache_status": "miss",
            "limit": "9999",
            "offset": "2",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["degraded"] is True
    assert body["degraded_reason"] == "test degraded"
    assert body["limit"] == 500
    assert body["offset"] == 2


def test_secret_backup_restore_api_workflow_records_status(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)
    csrf = _setup_login(webapp, client)
    webapp._secrets().create("canary-value", secret_id="operator-canary")

    created = client.post("/api/backup/secrets", headers={"X-CSRF-Token": csrf})
    assert created.status_code == 200, created.text
    name = created.json()["name"]

    listed = client.get("/api/backup/secrets")
    assert listed.status_code == 200
    assert listed.json()["backups"][0]["name"] == name

    validated = client.post(f"/api/backup/secrets/{name}/validate", headers={"X-CSRF-Token": csrf})
    assert validated.status_code == 200, validated.text
    assert validated.json()["secret_count"] >= 1

    rejected = client.post(
        f"/api/backup/secrets/{name}/restore",
        json={"confirmation": "wrong", "overwrite": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert rejected.status_code == 400
    assert rejected.json()["error"] == "confirmation_required"

    restored = client.post(
        f"/api/backup/secrets/{name}/restore",
        json={"confirmation": name, "overwrite": True},
        headers={"X-CSRF-Token": csrf},
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["status"] == "succeeded"
    jobs = client.get("/api/backup/secrets").json()["restore_jobs"]
    assert jobs[0]["status"] == "succeeded"


def test_packaged_dnsdist_unit_is_part_of_v2_lifecycle():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    unit = root / "packaging/v2/alderpointdns-v2-dnsdist.service"
    path_unit = root / "packaging/v2/alderpointdns-v2-dnsdist-reload.path"
    assert unit.exists()
    assert path_unit.exists()
    text = unit.read_text(encoding="utf-8")
    assert "/var/lib/alderpointdns-v2/compiled/dnsdist.conf" in text
    assert "alderpointdns-v2-web" not in text
    assert "ALDERPOINTDNS_V2_FORCE_ANALYTICS_DEGRADED" not in text
    assert "/var/lib/alderpointdns-v2/compiled/dnsdist.conf" in path_unit.read_text(encoding="utf-8")

    for rel in ("packaging/v2/postinst", "packaging/v2/prerm", "packaging/v2/postrm", "scripts/build-v2-deb.sh"):
        content = (root / rel).read_text(encoding="utf-8")
        assert "alderpointdns-v2-dnsdist" in content


def test_ui_assets_do_not_contain_internal_design_commentary():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "app" / "v2" / "ui"
    prohibited = ("AI-generated UI", "vibecoding", "vibecoded", "Claude", "CC", "Dex")
    combined = "\n".join(p.read_text(encoding="utf-8") for p in root.glob("*") if p.is_file())
    for term in prohibited:
        assert term not in combined
