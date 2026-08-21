"""Real, direct coverage of scripts/v2/soak_harness.py's own building
blocks (owner-beta closure item 2). The harness itself is an operational
tool meant to run against a real installed appliance's systemd units over
an extended soak, which is out of scope for the unit suite -- what's
tested here is that its parts are each individually correct: a real DNS
query against a real listener, a real API client against the real V2
webapp, and that process/database sampling degrades gracefully (never
raises) when a unit or file genuinely isn't there, which is exactly what
must happen the first time it runs against a container that hasn't
finished booting every unit yet.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

_repo_root = Path(__file__).resolve().parent.parent.parent
_spec = importlib.util.spec_from_file_location("soak_harness", _repo_root / "scripts" / "v2" / "soak_harness.py")
soak_harness = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = soak_harness  # dataclasses needs this module registered to resolve type hints
_spec.loader.exec_module(soak_harness)


class TestProcSample:
    def test_own_pid_reports_alive_with_real_numbers(self):
        import os

        sample = soak_harness.proc_sample(os.getpid())
        assert sample["alive"] is True
        assert sample["rss_kb"] > 0
        assert sample["threads"] >= 1
        assert sample["fds"] is None or sample["fds"] > 0

    def test_nonexistent_pid_reports_not_alive_without_raising(self):
        sample = soak_harness.proc_sample(2**30)  # not a real pid
        assert sample["alive"] is False


class TestControlDbWalSample:
    def test_missing_control_db_reports_none_sizes_without_raising(self, tmp_path):
        result = soak_harness.sample_control_db_wal(tmp_path)
        assert result == {"main": None, "-wal": None, "-shm": None}

    def test_present_files_report_real_sizes(self, tmp_path):
        (tmp_path / "control.db").write_bytes(b"x" * 100)
        (tmp_path / "control.db-wal").write_bytes(b"y" * 40)
        result = soak_harness.sample_control_db_wal(tmp_path)
        assert result["main"] == 100
        assert result["-wal"] == 40
        assert result["-shm"] is None


class TestDnsQuery:
    def test_a_real_well_formed_response_is_reported_success(self):
        """A minimal fake UDP DNS responder that echoes back a well-formed
        NOERROR response, proving dns_query's own txid/rcode parsing is
        correct -- not exercising a real dnsdist here (that's the
        installed-appliance acceptance run's job), just this function."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        stop = threading.Event()

        def responder():
            sock.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(512)
                except OSError:
                    continue
                txid = data[:2]
                resp = txid + bytes([0x81, 0x80]) + data[4:]  # flip QR, keep rcode NOERROR
                sock.sendto(resp, addr)

        t = threading.Thread(target=responder, daemon=True)
        t.start()
        try:
            assert soak_harness.dns_query("127.0.0.1", port, "soak-test.example", timeout=1.0) is True
        finally:
            stop.set()
            t.join(timeout=1)
            sock.close()

    def test_nothing_listening_is_reported_failure_not_an_exception(self):
        assert soak_harness.dns_query("127.0.0.1", 1, "soak-test.example", timeout=0.3) is False


class TestApiClientAgainstRealWebapp:
    """Drives soak_harness.ApiClient against the real app.v2.webapp app
    (in-process, via the same uvicorn-subprocess pattern already used by
    tests/v2/test_ui_browser_harness.py), not a mock -- proving the
    harness's own HTTP/cookie/CSRF handling actually round-trips against
    the real API."""

    def test_login_then_authenticated_get_succeeds(self, tmp_path, monkeypatch):
        import os
        import subprocess
        import sys as _sys
        import urllib.request

        state = tmp_path / "state"
        config = tmp_path / "etc"
        app_root = tmp_path / "opt"
        state.mkdir()
        config.mkdir()
        app_root.mkdir()

        from app.v2 import control_db, policy_store

        control_db.initialize(state / "control.db")
        policy_store.ensure_schema(state / "control.db")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        env = os.environ.copy()
        env.update({
            "PYTHONPATH": str(_repo_root),
            "ALDERPOINTDNS_V2_APP_ROOT": str(app_root),
            "ALDERPOINTDNS_V2_CONFIG_ROOT": str(config),
            "ALDERPOINTDNS_V2_STATE_ROOT": str(state),
            "ALDERPOINTDNS_V2_COOKIE_SECURE": "0",
        })
        server = subprocess.Popen(
            [_sys.executable, "-m", "uvicorn", "app.v2.webapp:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=str(_repo_root), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/api/setup/status", timeout=1)
                    break
                except Exception:
                    time.sleep(0.2)
            else:
                pytest.fail("webapp did not start")

            client = soak_harness.ApiClient(f"http://127.0.0.1:{port}", verify_tls=True)
            status, body = client._request(
                "POST", "/api/setup",
                {"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"},
            )
            assert status == 200, body
            assert client.login("admin", "correcthorsebattery12") is True
            status, body = client.get("/api/health")
            assert status == 200
            assert body["status"] in ("ok", "degraded")
            assert "background_workers" in body["components"]
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
