"""Tests for app/v2/blocklist_subscriptions.py (beta-rescue priority 3B:
subscribed/refreshable Blocklists). Real HTTP fetches against a real
local HTTP server (no mocking of the fetch itself), real compile into
the policy runtime, and TestRealRuntimeProof: subscribe -> refresh ->
real dnsdist NXDOMAIN for a subscribed domain.
"""

from __future__ import annotations

import http.server
import shutil
import socket
import subprocess
import threading
import time

import pytest

from app.v2 import blocklist_subscriptions as bl
from app.v2 import control_db, policy_store as store

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    with control_db.connect(path) as c:
        yield c


def _serve(content: str, status: int = 200):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = content.encode()
            self.send_response(status)
            if status == 200:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if status == 200:
                self.wfile.write(body)

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class TestFetchAndParse:
    def test_real_http_fetch_parses_hosts_and_adblock_and_plain_forms(self):
        content = "# comment\n! also a comment\n0.0.0.0 hosts-form.example\n127.0.0.1 hosts-form2.example\nplain-form.example\n||adblock-form.example^\n\nduplicate.example\nduplicate.example\n"
        server = _serve(content)
        try:
            port = server.server_address[1]
            domains, warnings = bl.fetch_and_parse(f"http://127.0.0.1:{port}/list.txt")
            names = {d for _kind, d in domains}
            assert names == {"hosts-form.example", "hosts-form2.example", "plain-form.example", "adblock-form.example", "duplicate.example"}
            assert len(domains) == 5  # duplicate collapsed
        finally:
            server.shutdown()

    def test_404_raises_clean_error(self):
        server = _serve("", status=404)
        try:
            port = server.server_address[1]
            with pytest.raises(bl.BlocklistSubscriptionError):
                bl.fetch_and_parse(f"http://127.0.0.1:{port}/missing.txt")
        finally:
            server.shutdown()

    def test_empty_content_raises_clean_error(self):
        server = _serve("# only comments\n")
        try:
            port = server.server_address[1]
            with pytest.raises(bl.BlocklistSubscriptionError, match="no valid domains"):
                bl.fetch_and_parse(f"http://127.0.0.1:{port}/list.txt")
        finally:
            server.shutdown()

    def test_unreachable_host_raises_clean_error(self):
        with pytest.raises(bl.BlocklistSubscriptionError):
            bl.fetch_and_parse("http://127.0.0.1:1/unreachable.txt")

    def test_dns_resolution_failure_fails_fast_without_retrying(self):
        """Regression guard for a real defect this pass's own retry fix
        (below) introduced and this pass's own regression suite caught
        live: a genuine DNS resolution failure (a bad/typo'd hostname,
        or a `.invalid`-TLD test domain) is permanent -- no amount of
        retrying resolves it -- so it must fail immediately, not spend
        several real seconds retrying an outcome that cannot change.
        """
        start = time.monotonic()
        with pytest.raises(bl.BlocklistSubscriptionError):
            bl.fetch_and_parse("http://this-hostname-does-not-resolve.invalid/list.txt")
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, (
            f"a real DNS resolution failure took {elapsed:.1f}s -- it must "
            "fail fast (no retry), not spend the retry backoff on a "
            "hostname that structurally cannot ever resolve"
        )

    def test_transient_failure_then_success_recovers_via_retry(self):
        """Regression guard for a real defect found live during RC46/RC47
        KVM clean-install/reboot acceptance: a real remote fetch of one
        of this package's own default blocklist subscriptions
        occasionally exceeded the flat 15s timeout under real
        concurrent host load, with no retry -- permanently failing that
        subscription for the whole refresh cycle even though the same
        endpoint reliably succeeded moments later. A real local server
        that drops the connection (no response at all, the same failure
        shape a real transient network hiccup produces) on its first two
        requests and only serves real content on the third proves the
        real fetch_and_parse() retry actually recovers, not just that
        the retry code exists.
        """
        content = "recovered-after-retry.example\n"
        attempts = {"count": 0}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                attempts["count"] += 1
                if attempts["count"] < 3:
                    # Simulate a transient network failure: close the
                    # connection with no response at all (what a real
                    # dropped/reset connection looks like to the client),
                    # rather than a permanent HTTP error status.
                    self.connection.close()
                    return
                body = content.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            port = server.server_address[1]
            domains, _warnings = bl.fetch_and_parse(f"http://127.0.0.1:{port}/list.txt")
            assert {d for _kind, d in domains} == {"recovered-after-retry.example"}
            assert attempts["count"] == 3, "expected exactly 2 real failed attempts before the successful 3rd"
        finally:
            server.shutdown()

    def test_permanent_failure_does_not_retry(self):
        """A real 404 (or any genuine HTTP-level rejection) must fail
        immediately, not waste real refresh time retrying an outcome
        that cannot change."""
        attempts = {"count": 0}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                attempts["count"] += 1
                self.send_response(404)
                self.end_headers()

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            port = server.server_address[1]
            with pytest.raises(bl.BlocklistSubscriptionError):
                bl.fetch_and_parse(f"http://127.0.0.1:{port}/missing.txt")
            assert attempts["count"] == 1, "a real permanent HTTP error must not be retried"
        finally:
            server.shutdown()


class TestRefreshSubscription:
    def test_refresh_compiles_into_policy_and_is_idempotent(self, conn):
        server = _serve("blocked1.example\nblocked2.example\n")
        try:
            port = server.server_address[1]
            store.create_blocklist_subscription(conn, "sub-a", "Sub A", f"http://127.0.0.1:{port}/list.txt")
            r1 = bl.refresh_subscription(conn, "sub-a")
            assert r1.ok and r1.rule_count == 2
            assert store.is_domain_service_blocked(conn, bl.SUBSCRIPTION_RULESET_ID, "blocked1.example") is not None

            r2 = bl.refresh_subscription(conn, "sub-a")
            assert r2.ok and r2.rule_count == 2  # re-refresh doesn't duplicate/error

            sub = store.get_blocklist_subscription(conn, "sub-a")
            assert sub["last_status"] == "succeeded"
            assert sub["rule_count"] == 2
        finally:
            server.shutdown()

    def test_failed_refresh_keeps_prior_valid_compiled_state(self, conn):
        server = _serve("blocked1.example\nblocked2.example\n")
        try:
            port = server.server_address[1]
            store.create_blocklist_subscription(conn, "sub-b", "Sub B", f"http://127.0.0.1:{port}/list.txt")
            r1 = bl.refresh_subscription(conn, "sub-b")
            assert r1.ok
        finally:
            server.shutdown()

        # The URL is now unreachable (server shut down) -- the previously
        # compiled service must remain exactly as it was.
        r2 = bl.refresh_subscription(conn, "sub-b")
        assert r2.ok is False
        assert store.is_domain_service_blocked(conn, bl.SUBSCRIPTION_RULESET_ID, "blocked1.example") is not None
        sub = store.get_blocklist_subscription(conn, "sub-b")
        assert sub["last_status"] == "failed"
        assert sub["rule_count"] == 2  # unchanged from the successful refresh

    def test_two_subscriptions_accumulate_without_clobbering_each_other(self, conn):
        server_a = _serve("a-domain.example\n")
        server_b = _serve("b-domain.example\n")
        try:
            port_a = server_a.server_address[1]
            port_b = server_b.server_address[1]
            store.create_blocklist_subscription(conn, "sub-x", "Sub X", f"http://127.0.0.1:{port_a}/list.txt")
            store.create_blocklist_subscription(conn, "sub-y", "Sub Y", f"http://127.0.0.1:{port_b}/list.txt")
            bl.refresh_subscription(conn, "sub-x")
            bl.refresh_subscription(conn, "sub-y")
            assert store.is_domain_service_blocked(conn, bl.SUBSCRIPTION_RULESET_ID, "a-domain.example") is not None
            assert store.is_domain_service_blocked(conn, bl.SUBSCRIPTION_RULESET_ID, "b-domain.example") is not None
        finally:
            server_a.shutdown()
            server_b.shutdown()

    def test_remove_subscription_service_only_removes_its_own_domains(self, conn):
        server_a = _serve("keep-me.example\n")
        server_b = _serve("remove-me.example\n")
        try:
            port_a = server_a.server_address[1]
            port_b = server_b.server_address[1]
            store.create_blocklist_subscription(conn, "sub-keep", "Keep", f"http://127.0.0.1:{port_a}/list.txt")
            store.create_blocklist_subscription(conn, "sub-remove", "Remove", f"http://127.0.0.1:{port_b}/list.txt")
            bl.refresh_subscription(conn, "sub-keep")
            bl.refresh_subscription(conn, "sub-remove")
        finally:
            server_a.shutdown()
            server_b.shutdown()

        bl.remove_subscription_service(conn, "sub-remove")
        assert store.is_domain_service_blocked(conn, bl.SUBSCRIPTION_RULESET_ID, "keep-me.example") is not None
        assert store.is_domain_service_blocked(conn, bl.SUBSCRIPTION_RULESET_ID, "remove-me.example") is None


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _dig(port, qname, rdtype="A", timeout=2.0):
    import dns.message
    import dns.query

    q = dns.message.make_query(qname, rdtype)
    return dns.query.udp(q, "127.0.0.1", port=port, timeout=timeout)


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="requires installed dnsdist")
class TestRealRuntimeProof:
    def test_subscribe_refresh_reaches_real_nxdomain(self, conn, tmp_path):
        from app.v2 import runtime_compile
        from app.v2.dnsdist_policy_runtime import compile_multi_policy_dnsdist_config

        server = _serve("subscribed-block.example\n")
        try:
            port = server.server_address[1]
            store.create_blocklist_subscription(conn, "live-sub", "Live Sub", f"http://127.0.0.1:{port}/list.txt")
            result = bl.refresh_subscription(conn, "live-sub")
            assert result.ok
            conn.commit()
        finally:
            server.shutdown()

        bindings = runtime_compile.build_bindings(conn)
        dnsdist_port = _free_port()
        config_text = compile_multi_policy_dnsdist_config(
            f"127.0.0.1:{dnsdist_port}", bindings, analytics_log_address=None, discovery_ingress_address=None,
        )
        conf_path = tmp_path / "dnsdist.conf"
        conf_path.write_text(config_text)
        proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(1.0)
            import dns.rcode

            resp = _dig(dnsdist_port, "subscribed-block.example.", "A")
            assert resp.rcode() == dns.rcode.NXDOMAIN
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


class TestBlocklistApiRoutes:
    def _fresh_webapp(self, tmp_path, monkeypatch):
        import importlib
        import sys

        monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
        (tmp_path / "state").mkdir(parents=True, exist_ok=True)
        control_db.initialize(tmp_path / "state" / "control.db")
        store.ensure_schema(tmp_path / "state" / "control.db")
        sys.modules.pop("app.v2.webapp", None)
        return importlib.import_module("app.v2.webapp")

    def test_create_refresh_toggle_delete_over_http(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]
        headers = {"X-CSRF-Token": csrf}

        server = _serve("http-route-block.example\n")
        try:
            port = server.server_address[1]
            created = client.post("/api/blocklists", json={
                "subscription_id": "http-sub", "name": "HTTP Sub", "url": f"http://127.0.0.1:{port}/list.txt",
            }, headers=headers)
            assert created.status_code == 200, created.text

            dup = client.post("/api/blocklists", json={
                "subscription_id": "http-sub", "name": "HTTP Sub", "url": f"http://127.0.0.1:{port}/list.txt",
            }, headers=headers)
            assert dup.status_code == 409

            refreshed = client.post("/api/blocklists/http-sub/refresh", headers=headers)
            assert refreshed.status_code == 200, refreshed.text
            assert refreshed.json()["status"] == "queued"
            job_id = refreshed.json()["job_id"]
            for _ in range(50):
                job = client.get(f"/api/blocklists/jobs/{job_id}").json()
                if job["status"] != "running":
                    break
                time.sleep(0.1)
            assert job["status"] == "succeeded", job
            assert job["runtime"]["promoted"] is True
            assert job["results"]["http-sub"]["status"] == "succeeded"
        finally:
            server.shutdown()

        payload = client.get("/api/blocklists").json()
        listed = payload["subscriptions"]
        assert listed[0]["rule_count"] == 1
        assert listed[0]["last_success_at"]
        assert listed[0]["next_update_at"]
        assert listed[0]["effective_interval_seconds"] == 86400

        interval = client.post("/api/blocklists/http-sub/interval", json={"update_interval_seconds": 0}, headers=headers)
        assert interval.status_code == 200
        listed = client.get("/api/blocklists").json()["subscriptions"]
        assert listed[0]["effective_interval_seconds"] == 0

        toggled = client.post("/api/blocklists/http-sub/toggle", headers=headers)
        assert toggled.status_code == 200
        assert client.get("/api/blocklists").json()["subscriptions"][0]["enabled"] is False

        deleted = client.delete("/api/blocklists/http-sub", headers=headers)
        assert deleted.status_code == 200
        assert client.get("/api/blocklists").json()["subscriptions"] == []

    def test_unauthenticated_routes_are_rejected(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        assert client.get("/api/blocklists").status_code == 401
        assert client.post("/api/blocklists", json={"subscription_id": "x", "name": "x", "url": "http://x"}).status_code == 401


def test_blocklist_refresh_timer_is_wired_into_packaging():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    service = root / "packaging/v2/alderpointdns-v2-blocklist-refresh.service"
    timer = root / "packaging/v2/alderpointdns-v2-blocklist-refresh.timer"
    assert service.exists()
    assert timer.exists()
    assert "alderpointdns_v2_blocklist_refresh.py" in service.read_text()
    assert "alderpointdns-v2-blocklist-refresh.service" in timer.read_text() or "[Timer]" in timer.read_text()

    build_script = (root / "scripts/build-v2-deb.sh").read_text()
    assert "alderpointdns-v2-blocklist-refresh.service" in build_script
    assert "alderpointdns-v2-blocklist-refresh.timer" in build_script
    assert "alderpointdns_v2_blocklist_refresh.py" in build_script

    postinst = (root / "packaging/v2/postinst").read_text()
    assert "alderpointdns-v2-blocklist-refresh.timer" in postinst
