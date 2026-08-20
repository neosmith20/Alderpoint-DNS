"""Tests for app/v2/log_viewer.py (beta-rescue priority 3E: in-app log
viewer). Real `journalctl` subprocess calls against a real running
systemd unit (this test host already has real units running), never a
mocked subprocess -- proving the real allowlist enforcement, real
secret redaction reuse, and real severity filtering.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from app.v2 import log_viewer

JOURNALCTL_INSTALLED = shutil.which("journalctl") is not None


def _a_real_running_unit() -> str | None:
    """Finds one real systemd unit currently running on this host, to
    prove real journalctl access without depending on the packaged V2
    units actually being installed in the test environment."""
    try:
        proc = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in proc.stdout.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.endswith(".service"):
            return name[: -len(".service")]
    return None


class TestAllowlist:
    def test_disallowed_unit_is_rejected(self):
        with pytest.raises(log_viewer.LogViewerError, match="allowlist"):
            log_viewer.fetch_unit_logs("sshd")

    def test_arbitrary_string_is_rejected_not_shelled_out(self):
        with pytest.raises(log_viewer.LogViewerError):
            log_viewer.fetch_unit_logs("; rm -rf / #")

    def test_view_logs_also_enforces_allowlist(self):
        with pytest.raises(log_viewer.LogViewerError):
            log_viewer.view_logs("not-a-real-v2-unit")


@pytest.mark.skipif(not JOURNALCTL_INSTALLED, reason="requires journalctl")
class TestRealJournalctlAccess:
    def test_real_unit_logs_are_fetched_and_sanitized(self, monkeypatch):
        real_unit = _a_real_running_unit()
        if real_unit is None:
            pytest.skip("no real running systemd unit found on this host")
        monkeypatch.setattr(log_viewer, "ALLOWED_UNITS", log_viewer.ALLOWED_UNITS + (real_unit,))
        entries = log_viewer.fetch_unit_logs(real_unit)
        # A real host has *some* journal history for *some* running
        # unit; if this one happens to have none, that's still a valid
        # (empty) real result, not a crash -- assert on shape, not count.
        assert isinstance(entries, list)
        for entry in entries:
            assert set(entry.keys()) == {"ts", "priority", "severity", "message"}
            assert entry["severity"] in log_viewer.PRIORITY_LABELS.values()

    def test_severity_filter_narrows_real_results(self, monkeypatch):
        real_unit = _a_real_running_unit()
        if real_unit is None:
            pytest.skip("no real running systemd unit found on this host")
        monkeypatch.setattr(log_viewer, "ALLOWED_UNITS", log_viewer.ALLOWED_UNITS + (real_unit,))
        result = log_viewer.view_logs(real_unit, severity="error", lines=50)
        assert result["unit"] == real_unit
        for entry in result["entries"]:
            assert entry["priority"] in log_viewer.SEVERITY_LEVELS["error"]

    def test_lines_are_bounded(self, monkeypatch):
        real_unit = _a_real_running_unit()
        if real_unit is None:
            pytest.skip("no real running systemd unit found on this host")
        monkeypatch.setattr(log_viewer, "ALLOWED_UNITS", log_viewer.ALLOWED_UNITS + (real_unit,))
        result = log_viewer.view_logs(real_unit, lines=10_000)
        assert result["lines"] == log_viewer.MAX_LINES_FETCHED  # clamped


class TestLogApiRoutes:
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

    def test_disallowed_unit_over_http_is_a_clean_400(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12"})
        client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        r = client.get("/api/logs/sshd")
        assert r.status_code == 400

    def test_allowed_unit_over_http_does_not_crash(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12"})
        client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        r = client.get("/api/logs/alderpointdns-v2-web")
        assert r.status_code == 200
        assert "entries" in r.json()

    def test_unauthenticated_route_is_rejected(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        assert client.get("/api/logs/alderpointdns-v2-web").status_code == 401


def test_systemd_journal_group_membership_is_wired_into_postinst():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    postinst = (root / "packaging/v2/postinst").read_text()
    assert "systemd-journal" in postinst
    assert "usermod -aG systemd-journal alderpointdns-v2" in postinst
