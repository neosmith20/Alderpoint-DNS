from __future__ import annotations

import importlib
import sys
from pathlib import Path

from app.v2 import control_db
from app.v2 import dns_performance
from app.v2 import policy_store as store


def test_summarize_reports_dns_latency_percentiles_and_rcodes():
    samples = [
        {"ok": True, "latency_ms": 1.0, "rcode": 0},
        {"ok": True, "latency_ms": 2.0, "rcode": 0},
        {"ok": True, "latency_ms": 3.0, "rcode": 3},
        {"ok": False, "timeout": True, "latency_ms": 2000.0},
        {"ok": False, "latency_ms": 4.0, "rcode": 2},
    ]

    summary = dns_performance.summarize(samples)

    assert summary["count"] == 5
    assert summary["success"] == 3
    assert summary["timeouts"] == 1
    assert summary["errors"] == 2
    assert summary["p50_ms"] == 2.0
    assert summary["p95_ms"] == 3.0
    assert summary["p99_ms"] == 3.0
    assert summary["nxdomain"] == 1
    assert summary["servfail"] == 1


def test_report_storage_is_bounded_json_file(tmp_path):
    path = tmp_path / "dns-performance" / "latest-report.json"
    report = {"schema": 1, "generated_at": "2026-08-24T00:00:00Z", "cases": []}

    dns_performance.save_report(report, path)

    assert dns_performance.read_report(path) == report
    assert path.stat().st_mode & 0o777 == 0o640


def test_dns_performance_api_is_authenticated_and_reports_shape(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    control_db.initialize(tmp_path / "state" / "control.db")
    store.ensure_schema(tmp_path / "state" / "control.db")
    sys.modules.pop("app.v2.webapp", None)
    sys.modules.pop("app.v2.dns_performance", None)
    webapp = importlib.import_module("app.v2.webapp")
    webapp._bind_context_ports = lambda: []

    client = TestClient(webapp.app)
    assert client.get("/api/dns/performance").status_code == 401
    client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
    login = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
    csrf = login.json()["csrf"]

    response = client.get("/api/dns/performance")

    assert response.status_code == 200
    data = response.json()
    assert data["benchmark_running"] is False
    assert data["report"] is None
    assert data["bind_cache"] == []
    assert "packet-cache behavior is measured" in data["dnsdist"]["note"]

    cleared = client.delete("/api/dns/performance", headers={"X-CSRF-Token": csrf})
    assert cleared.status_code == 200


def test_system_status_ui_exposes_dns_performance_controls():
    source = (Path(__file__).parents[2] / "app" / "v2" / "ui" / "app.js").read_text(encoding="utf-8")

    assert "data-run-dns-benchmark" in source
    assert "data-copy-dns-perf" in source
    assert "data-clear-dns-perf" in source
    assert "dnsPerformancePanel" in source
