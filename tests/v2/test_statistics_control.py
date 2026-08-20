"""Tests for app/v2/statistics_control.py (beta-rescue priority 3C:
Statistics export/clear). Real aggregates.db, real named-field export,
real clear with an explicit, reported raw-history inclusion/exclusion.
"""

from __future__ import annotations

import json

import pytest

from app.v2 import aggregates_db, statistics_control


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "aggregates.db"
    aggregates_db.initialize(path)
    return path


class TestExport:
    def test_export_has_stable_named_fields_and_excludes_raw_history(self, db):
        result = statistics_control.export_statistics(db)
        assert result["format_version"] == 1
        assert "aggregate_time_buckets" in result
        assert "aggregate_dimension_counts" in result
        assert result["raw_query_history_included"] is False

    def test_export_json_round_trips(self, db):
        text = statistics_control.export_statistics_json(db)
        parsed = json.loads(text)
        assert parsed["format_version"] == 1

    def test_export_with_real_recorded_data(self, db):
        conn = __import__("sqlite3").connect(str(db))
        try:
            conn.execute(
                "INSERT INTO time_buckets (bucket_start, granularity, total_queries, blocked_queries, cache_hits, cache_misses) VALUES (1000, 'hour', 50, 5, 30, 20)"
            )
            conn.commit()
        finally:
            conn.close()
        result = statistics_control.export_statistics(db)
        assert len(result["aggregate_time_buckets"]) == 1
        assert result["aggregate_time_buckets"][0]["total_queries"] == 50

    def test_export_missing_db_does_not_crash(self, tmp_path):
        result = statistics_control.export_statistics(tmp_path / "does-not-exist.db")
        assert result["aggregate_time_buckets"] == []


class TestClear:
    def _seed(self, db):
        conn = __import__("sqlite3").connect(str(db))
        try:
            conn.execute(
                "INSERT INTO time_buckets (bucket_start, granularity, total_queries, blocked_queries, cache_hits, cache_misses) VALUES (1000, 'hour', 50, 5, 30, 20)"
            )
            conn.execute("INSERT INTO dimension_counts (bucket_start, granularity, dimension, value, count) VALUES (1000, 'hour', 'qtype', 'A', 40)")
            conn.commit()
        finally:
            conn.close()

    def test_clear_aggregates_only_reports_raw_history_untouched(self, db):
        self._seed(db)
        result = statistics_control.clear_statistics(db, include_raw_history=False)
        assert result.aggregate_buckets_cleared == 1
        assert result.aggregate_dimension_rows_cleared == 1
        assert result.raw_history_cleared is False
        assert result.raw_partition_files_removed == 0

        after = statistics_control.export_statistics(db)
        assert after["aggregate_time_buckets"] == []

    def test_clear_with_raw_history_removes_real_parquet_files(self, db, tmp_path):
        self._seed(db)
        raw_root = tmp_path / "queries"
        (raw_root / "part1").mkdir(parents=True)
        (raw_root / "part1" / "data.parquet").write_bytes(b"fake parquet bytes")
        (raw_root / "part2").mkdir(parents=True)
        (raw_root / "part2" / "data.parquet").write_bytes(b"fake parquet bytes")

        result = statistics_control.clear_statistics(db, include_raw_history=True, raw_history_root=raw_root)
        assert result.raw_history_cleared is True
        assert result.raw_partition_files_removed == 2
        assert not list(raw_root.rglob("*.parquet"))

    def test_clear_never_silently_leaves_half_the_history_behind(self, db, tmp_path):
        """The specific lesson the brief calls out by name: a caller
        asking to clear raw history too must get an accurate count back,
        not an implicit assumption that aggregates-only was enough."""
        self._seed(db)
        raw_root = tmp_path / "queries"
        raw_root.mkdir()
        (raw_root / "data.parquet").write_bytes(b"x")
        result = statistics_control.clear_statistics(db, include_raw_history=False, raw_history_root=raw_root)
        assert result.raw_history_cleared is False
        assert (raw_root / "data.parquet").exists()  # explicitly excluded -> explicitly untouched


class TestStatisticsApiRoutes:
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

    def test_export_and_clear_over_http(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]

        export = client.get("/api/statistics/export")
        assert export.status_code == 200
        assert export.json()["format_version"] == 1

        rejected = client.post("/api/statistics/clear", json={"confirmation": "wrong"}, headers={"X-CSRF-Token": csrf})
        assert rejected.status_code == 400
        assert rejected.json()["error"] == "confirmation_required"

        cleared = client.post("/api/statistics/clear", json={"confirmation": "CLEAR", "include_raw_history": False}, headers={"X-CSRF-Token": csrf})
        assert cleared.status_code == 200, cleared.text
        assert cleared.json()["raw_history_cleared"] is False

    def test_unauthenticated_routes_are_rejected(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        assert client.get("/api/statistics/export").status_code == 401
        assert client.post("/api/statistics/clear", json={"confirmation": "CLEAR"}).status_code == 401
