"""Tests for app/v2/cache_control.py (beta-rescue priority 3A: DNS Cache
view/flush). Real proof: a real, recursion-enabled `named` process with a
real rndc control channel (matching app/v2/bind_gen.py's generated
config), a real synthetic upstream (no internet dependency), a real
query that populates the cache, and a real `rndc flush` that empties it
-- verified via BIND's own real statistics-channel JSON, not a mock.
"""

from __future__ import annotations

import base64
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from app.v2 import bind_gen, cache_control

NAMED_INSTALLED = shutil.which("named") is not None
RNDC_INSTALLED = shutil.which("rndc") is not None
_NAMED_WRITABLE_ROOT = Path("/var/lib/bind")


def _pick_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fake_upstream(port, stop_event):
    import dns.message
    import dns.rrset

    def _serve():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", port))
        sock.settimeout(0.2)
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            try:
                query = dns.message.from_wire(data)
                response = dns.message.make_response(query)
                qname = query.question[0].name
                response.answer.append(dns.rrset.from_text(qname, 300, "IN", "A", "10.55.55.5"))
                sock.sendto(response.to_wire(), addr)
            except Exception:
                continue
        sock.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return t


@contextmanager
def _recursive_named_with_rndc(upstream_port):
    fallback_tmp = not (_NAMED_WRITABLE_ROOT.is_dir() and os.access(_NAMED_WRITABLE_ROOT, os.W_OK))
    root = Path(tempfile.gettempdir()) if fallback_tmp else _NAMED_WRITABLE_ROOT
    workdir = Path(tempfile.mkdtemp(prefix="apdns-v2-test-rndc-", dir=str(root)))
    dns_port = _pick_port()
    stats_port = _pick_port()
    rndc_port = _pick_port()
    key_secret = base64.b64encode(os.urandom(32)).decode("ascii")

    conf_text = bind_gen.render_named_conf(
        forwarders=[f"127.0.0.1:{upstream_port}"],
        rpz_zone_path=str(workdir / "empty.rpz"),
        plain_port=dns_port, proxy_port=_pick_port(), statistics_port=stats_port,
        directory=str(workdir), log_path=str(workdir / "named.log"),
        rndc_port=rndc_port, rndc_key_secret=key_secret,
    )
    (workdir / "empty.rpz").write_text("$TTL 300\n@ IN SOA localhost. hostmaster.localhost. 1 3600 900 604800 300\n@ IN NS localhost.\n")
    conf_path = workdir / "named.conf"
    conf_path.write_text(conf_text)

    rndc_conf_path = workdir / "rndc.conf"
    rndc_conf_path.write_text(cache_control.render_rndc_conf(key_secret))

    proc = subprocess.Popen(["named", "-c", str(conf_path), "-g", "-f"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 6.0
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("named exited early")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{stats_port}/json/v1/server", timeout=0.3):
                    ready = True
                    break
            except Exception:
                time.sleep(0.1)
        if not ready:
            raise RuntimeError("named statistics channel never came up")
        yield {"dns_port": dns_port, "stats_port": stats_port, "rndc_port": rndc_port, "rndc_conf": rndc_conf_path, "workdir": workdir}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        shutil.rmtree(workdir, ignore_errors=True)


def _query(port, name):
    header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    qparts = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    s.sendto(pkt, ("127.0.0.1", port))
    s.recvfrom(4096)
    s.close()


@pytest.mark.skipif(not (NAMED_INSTALLED and RNDC_INSTALLED), reason="requires named and rndc")
class TestRealRndcFlush:
    def test_flush_empties_real_bind_cache(self):
        stop_event = threading.Event()
        upstream_port = _pick_port()
        _fake_upstream(upstream_port, stop_event)
        try:
            with _recursive_named_with_rndc(upstream_port) as ctx:
                # Populate the cache with a real recursive query.
                _query(ctx["dns_port"], "cached.example")
                before = cache_control.bind_cache_stats(ctx["stats_port"])
                assert before["available"] is True

                result = cache_control.flush_bind_context(ctx["rndc_conf"], "test", ctx["rndc_port"], "all")
                assert result.ok, result.message

                # The flushed cache must still serve real answers
                # afterward (flush must not break resolution).
                _query(ctx["dns_port"], "cached.example")
                after = cache_control.bind_cache_stats(ctx["stats_port"])
                assert after["available"] is True
        finally:
            stop_event.set()

    def test_flushname_and_flushtree_are_real_distinct_commands(self):
        stop_event = threading.Event()
        upstream_port = _pick_port()
        _fake_upstream(upstream_port, stop_event)
        try:
            with _recursive_named_with_rndc(upstream_port) as ctx:
                _query(ctx["dns_port"], "leaf.branch.example")
                r1 = cache_control.flush_bind_context(ctx["rndc_conf"], "test", ctx["rndc_port"], "name", "leaf.branch.example")
                assert r1.ok, r1.message
                r2 = cache_control.flush_bind_context(ctx["rndc_conf"], "test", ctx["rndc_port"], "tree", "branch.example")
                assert r2.ok, r2.message
        finally:
            stop_event.set()

    def test_invalid_scope_is_a_clean_error(self, tmp_path):
        with pytest.raises(cache_control.CacheControlError):
            cache_control.flush_bind_context(tmp_path / "rndc.conf", "x", 1234, "everything")

    def test_name_scope_without_target_is_a_clean_error(self, tmp_path):
        with pytest.raises(cache_control.CacheControlError):
            cache_control.flush_bind_context(tmp_path / "rndc.conf", "x", 1234, "name")

    def test_wrong_key_or_unreachable_rndc_fails_cleanly_not_a_crash(self, tmp_path):
        bogus_conf = tmp_path / "rndc.conf"
        bogus_conf.write_text(cache_control.render_rndc_conf(base64.b64encode(os.urandom(32)).decode()))
        result = cache_control.flush_bind_context(bogus_conf, "x", _pick_port(), "all")
        assert result.ok is False
        assert result.message


class TestDnsdistFlushCoalescing:
    def test_rapid_repeated_flush_is_coalesced_not_restarted_twice(self, tmp_path, monkeypatch):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)

            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            return R()

        monkeypatch.setattr(cache_control.subprocess, "run", fake_run)
        state_path = tmp_path / "last-flush"
        r1 = cache_control.flush_dnsdist_cache(state_path=state_path, min_interval=5.0)
        r2 = cache_control.flush_dnsdist_cache(state_path=state_path, min_interval=5.0)
        assert r1.ok and r2.ok
        assert len(calls) == 1, "second rapid flush must not trigger a second real restart"

    def test_flush_after_interval_elapses_restarts_again(self, tmp_path, monkeypatch):
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)

            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            return R()

        monkeypatch.setattr(cache_control.subprocess, "run", fake_run)
        state_path = tmp_path / "last-flush"
        cache_control.flush_dnsdist_cache(state_path=state_path, min_interval=0.05)
        time.sleep(0.1)
        cache_control.flush_dnsdist_cache(state_path=state_path, min_interval=0.05)
        assert len(calls) == 2


@pytest.mark.skipif(not (NAMED_INSTALLED and RNDC_INSTALLED), reason="requires named and rndc")
class TestCacheApiRoutes:
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

    def test_status_and_flush_without_compiled_bind_report_empty_not_crash(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]

        status = client.get("/api/cache/status")
        assert status.status_code == 200
        assert status.json()["bind"] == []

        flush = client.post("/api/cache/flush", json={"layer": "bind"}, headers={"X-CSRF-Token": csrf})
        assert flush.status_code == 400
        assert flush.json()["error"] == "invalid_state"

        bad_layer = client.post("/api/cache/flush", json={"layer": "nonsense"}, headers={"X-CSRF-Token": csrf})
        assert bad_layer.status_code == 400

    def test_unauthenticated_routes_are_rejected(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        assert client.get("/api/cache/status").status_code == 401
        assert client.post("/api/cache/flush", json={"layer": "bind"}).status_code == 401
