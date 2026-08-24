"""Tests for the Dashboard chart API routes (owner-reported fix: Top
Domains rendered anonymous bars with counts hidden in a `title`
attribute, and no real time-series activity view existed at all).

Both /api/analytics/top-blocked-domains and /api/analytics/timeseries
are thin API wiring over service-layer methods
(AnalyticsService.top_blocked_domains / .time_series_totals) that
already existed and were already tested at that layer -- these tests
prove the HTTP route itself: auth-gated, well-formed response shape,
and a real granularity-validation error, not the underlying
aggregation logic again.
"""

from __future__ import annotations

import importlib
import sys

from app.v2 import aggregates_db, control_db, policy_store as store


def _fresh_webapp(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    (tmp_path / "state" / "analytics").mkdir(parents=True, exist_ok=True)
    control_db.initialize(tmp_path / "state" / "control.db")
    store.ensure_schema(tmp_path / "state" / "control.db")
    # A real fresh install already has this schema created (the worker
    # that maintains it starts from boot) -- matches real appliance
    # state rather than a nonexistent-file edge case this route's own
    # degraded-handling already covers separately.
    aggregates_db.initialize(tmp_path / "state" / "analytics" / "aggregates.db")
    sys.modules.pop("app.v2.webapp", None)
    return importlib.import_module("app.v2.webapp")


def _client(webapp):
    from fastapi.testclient import TestClient

    return TestClient(webapp.app)


def _setup_login(client):
    client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
    r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
    return r.json()["csrf"]


class TestTopBlockedDomains:
    def test_requires_auth(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        r = client.get("/api/analytics/top-blocked-domains")
        assert r.status_code in (401, 403)

    def test_returns_well_formed_result_shape_on_a_fresh_appliance(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        _setup_login(client)
        r = client.get("/api/analytics/top-blocked-domains?minutes=60&limit=10")
        assert r.status_code == 200, r.text
        body = r.json()
        assert "rows" in body and "columns" in body
        assert isinstance(body["rows"], list)


class TestTimeseries:
    def test_requires_auth(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        r = client.get("/api/analytics/timeseries")
        assert r.status_code in (401, 403)

    def test_returns_well_formed_bucket_shape_on_a_fresh_appliance(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        _setup_login(client)
        r = client.get("/api/analytics/timeseries?minutes=1440&granularity=hour")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["granularity"] == "hour"
        assert body["degraded"] is False
        assert body["buckets"]  # fixed rolling frame, even with no traffic
        assert all(b["total_queries"] == 0 for b in body["buckets"])

    def test_invalid_granularity_is_a_real_400_not_a_500(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        _setup_login(client)
        r = client.get("/api/analytics/timeseries?granularity=fortnight")
        assert r.status_code == 400

    def test_populated_bucket_reports_real_totals_not_fabricated_from_top_domains(self, tmp_path, monkeypatch):
        # Proves the response actually reflects real bucketed
        # query/blocked counts from aggregates_db, not a client-side
        # reshaping of the unrelated ranked top-domains dataset.
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        _setup_login(client)
        import time

        now = time.time()
        aggregates_db.record_batch(
            webapp.ANALYTICS_AGGREGATES_DB,
            [
                {"ts": now, "domain": "example.com", "blocked": False, "cache_status": "hit",
                 "protocol": "udp", "qtype": "A", "client": "10.0.0.5", "rcode": "NOERROR", "upstream": "u1"},
                {"ts": now, "domain": "ads.example", "blocked": True, "cache_status": "miss",
                 "protocol": "udp", "qtype": "A", "client": "10.0.0.5", "rcode": "NXDOMAIN", "upstream": "u1"},
            ],
            granularity="hour",
        )
        r = client.get("/api/analytics/timeseries?minutes=1440&granularity=hour")
        assert r.status_code == 200, r.text
        buckets = r.json()["buckets"]
        populated = [b for b in buckets if b["total_queries"]]
        assert len(populated) == 1
        assert populated[0]["total_queries"] == 2
        assert populated[0]["blocked_queries"] == 1
        assert "bucket_start_iso" in buckets[0]

    def test_last_hour_minute_buckets_include_current_open_bucket_and_top_domains(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        _setup_login(client)
        import time

        now = time.time()
        aggregates_db.record_batch(
            webapp.ANALYTICS_AGGREGATES_DB,
            [
                {"ts": now - 10, "domain": "current.example", "blocked": False, "cache_status": "hit",
                 "protocol": "udp", "qtype": "A", "client": "10.0.0.5", "rcode": "NOERROR", "upstream": "u1"},
                {"ts": now - 30, "domain": "current.example", "blocked": False, "cache_status": "miss",
                 "protocol": "udp", "qtype": "A", "client": "10.0.0.5", "rcode": "NOERROR", "upstream": "u1"},
            ],
            granularity="minute",
        )
        r = client.get("/api/analytics/timeseries?minutes=60&granularity=minute")
        assert r.status_code == 200, r.text
        buckets = r.json()["buckets"]
        assert len(buckets) >= 60
        assert buckets[-1]["bucket_start"] <= int(now)
        assert sum(b["total_queries"] for b in buckets) == 2

        top = client.get("/api/analytics/top-domains?minutes=60&limit=5")
        assert top.status_code == 200, top.text
        assert top.json()["rows"][0] == ["current.example", 2]

    def test_live_activity_uses_bounded_recent_window(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        _setup_login(client)
        import time

        now = time.time()
        aggregates_db.record_live_batch(
            webapp.ANALYTICS_AGGREGATES_DB,
            [{"ts": now, "domain": "live.example", "blocked": True, "cache_status": "miss",
              "protocol": "udp", "qtype": "A", "client": "10.0.0.5", "rcode": "NXDOMAIN", "upstream": "u1"}],
        )
        r = client.get("/api/analytics/live-activity?seconds=180&bucket_seconds=1")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["transport"] == "bounded_polling"
        assert body["bucket_seconds"] == 1
        assert sum(b["blocked_queries"] for b in body["buckets"]) == 1

    def test_live_activity_reports_real_per_second_pattern_before_minute_closes(self, tmp_path, monkeypatch):
        webapp = _fresh_webapp(tmp_path, monkeypatch)
        client = _client(webapp)
        _setup_login(client)
        import time

        base = int(time.time()) - 20
        records = (
            [{"ts": base, "domain": "a.example", "blocked": False, "cache_status": "miss",
              "protocol": "udp", "qtype": "A", "client": "10.0.0.5", "rcode": "NOERROR", "upstream": "u1"} for _ in range(5)]
            + [{"ts": base + 2, "domain": "c.example", "blocked": False, "cache_status": "miss",
                "protocol": "udp", "qtype": "A", "client": "10.0.0.5", "rcode": "NOERROR", "upstream": "u1"} for _ in range(10)]
            + [{"ts": base + 3, "domain": "d.example", "blocked": True, "cache_status": "miss",
                "protocol": "udp", "qtype": "A", "client": "10.0.0.5", "rcode": "NXDOMAIN", "upstream": "u1"} for _ in range(4)]
        )
        aggregates_db.record_live_batch(webapp.ANALYTICS_AGGREGATES_DB, records, now=base + 4)
        r = client.get("/api/analytics/live-activity?seconds=60&bucket_seconds=1")
        assert r.status_code == 200, r.text
        buckets = {b["bucket_start"]: b for b in r.json()["buckets"]}
        assert buckets[base]["total_queries"] == 5
        assert buckets[base + 1]["total_queries"] == 0
        assert buckets[base + 2]["total_queries"] == 10
        assert buckets[base + 3]["blocked_queries"] == 4
