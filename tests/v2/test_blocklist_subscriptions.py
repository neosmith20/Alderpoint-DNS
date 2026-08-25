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


def _pop_webapp_module() -> None:
    """Forces the NEXT ``from app.v2 import webapp`` (as opposed to
    ``importlib.import_module("app.v2.webapp")``, which this codebase's
    other webapp test fixtures already use) to genuinely reimport rather
    than silently reusing a stale, previous-tmp_path-bound module.

    Real defect found live in this test file itself: popping only
    ``sys.modules["app.v2.webapp"]`` is not enough -- CPython's ``from
    package import submodule`` resolves via ``getattr(package,
    "submodule")`` first, and importing ``app.v2.webapp`` anywhere also
    sets that attribute on the already-imported ``app.v2`` package
    object. A prior test's already-executed ``from app.v2 import
    webapp`` (scripts/v2/alderpointdns_v2_blocklist_refresh.py's own
    import style) left that attribute pointing at ITS webapp module
    instance -- bound to ITS tmp_path's CONTROL_DB -- and popping
    sys.modules alone did not clear it, so the next test's freshly
    ``monkeypatch.setenv()``-ed env vars were silently never read: the
    script ran against the previous test's now-torn-down database and
    (correctly, but confusingly) found nothing due, reporting 0
    subscriptions instead of failing loudly.
    """
    import sys

    sys.modules.pop("app.v2.webapp", None)
    app_v2 = sys.modules.get("app.v2")
    if app_v2 is not None and hasattr(app_v2, "webapp"):
        delattr(app_v2, "webapp")


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
            # Real defect fixed (owner-reported live: "adding a blocklist
            # subscription does not automatically download/process/apply
            # it") -- creation now kicks off the new subscription's own
            # first real update job immediately, same as an explicit
            # "Update Now" would, without waiting for a scheduled
            # interval or a separate manual refresh.
            assert created.json()["job_id"], created.text
            create_job_id = created.json()["job_id"]
            immediate = client.get("/api/blocklists").json()["subscriptions"][0]
            assert immediate["update_in_progress"] is True, immediate

            dup = client.post("/api/blocklists", json={
                "subscription_id": "http-sub", "name": "HTTP Sub", "url": f"http://127.0.0.1:{port}/list.txt",
            }, headers=headers)
            assert dup.status_code == 409

            # The subscription's own initial-pull job is already running
            # (proven above by update_in_progress), so an explicit refresh
            # attempted right now correctly 409s -- exactly the "prevent
            # duplicate concurrent jobs" contract, over the real backend
            # lock, not just the client-side disabled button.
            immediate_refresh = client.post("/api/blocklists/http-sub/refresh", headers=headers)
            assert immediate_refresh.status_code == 409, immediate_refresh.text

            for _ in range(50):
                job = client.get(f"/api/blocklists/jobs/{create_job_id}").json()
                if job["status"] != "running":
                    break
                time.sleep(0.1)
            assert job["status"] == "succeeded", job
            assert job["runtime"]["promoted"] is True
            assert job["results"]["http-sub"]["status"] == "succeeded"

            # Now that the initial pull has finished, an explicit "Update
            # Now" refresh is a normal, separate, successful operation.
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

    def test_new_subscription_initial_pull_failure_stays_editable_and_preserves_runtime(self, tmp_path, monkeypatch):
        """Part 2, failure branch: a new subscription whose first real
        pull fails must not be silently dropped or blocked from editing,
        must show the real error, and -- since a brand-new subscription
        has no prior good content of its own -- must never let the
        failed pull's own (empty) domain set anywhere near a runtime
        promotion. A second, working subscription created in the same
        job batch proves the one failure does not damage the other."""
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        csrf = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"}).json()["csrf"]
        headers = {"X-CSRF-Token": csrf}

        created = client.post("/api/blocklists", json={
            "subscription_id": "will-fail", "name": "Will Fail", "url": "http://blocklist-initial-pull-failure.invalid/list.txt",
        }, headers=headers)
        assert created.status_code == 200, created.text
        job_id = created.json()["job_id"]
        assert job_id
        job = None
        for _ in range(50):
            job = client.get(f"/api/blocklists/jobs/{job_id}").json()
            if job["status"] != "running":
                break
            time.sleep(0.1)
        assert job["status"] == "failed", job
        assert job["results"]["will-fail"]["status"] == "failed"
        assert job["runtime"]["promoted"] is False, "a failed initial pull with nothing successfully downloaded must never promote a runtime"

        listed = client.get("/api/blocklists").json()["subscriptions"]
        assert len(listed) == 1, "a failed initial pull must not remove the subscription"
        sub = listed[0]
        assert sub["subscription_id"] == "will-fail"
        assert sub["last_error"], "the real fetch error must be visible, not swallowed"
        assert sub["consecutive_failure_count"] == 1
        assert sub["update_in_progress"] is False, "must not be left stuck showing updating forever"

        renamed = client.patch("/api/blocklists/will-fail", json={"name": "Still Editable"}, headers=headers)
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["subscription"]["name"] == "Still Editable"

    def test_manual_only_default_interval_still_performs_the_initial_pull(self, tmp_path, monkeypatch):
        """Part 2, requirement 9: "Manual Only" (here, the appliance-wide
        default update interval set to 0/manual) controls FUTURE
        scheduled refreshes only -- it must never suppress a newly
        created subscription's own first real pull."""
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        csrf = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"}).json()["csrf"]
        headers = {"X-CSRF-Token": csrf}

        settings = client.post("/api/blocklists/settings", json={"default_interval_seconds": 0}, headers=headers)
        assert settings.status_code == 200, settings.text

        server = _serve("manual-only-initial-pull.example\n")
        try:
            port = server.server_address[1]
            created = client.post("/api/blocklists", json={
                "subscription_id": "manual-only-sub", "name": "Manual Only Sub", "url": f"http://127.0.0.1:{port}/list.txt",
            }, headers=headers)
            assert created.status_code == 200, created.text
            job_id = created.json()["job_id"]
            assert job_id, "Manual Only must not suppress the initial pull job"
            job = None
            for _ in range(50):
                job = client.get(f"/api/blocklists/jobs/{job_id}").json()
                if job["status"] != "running":
                    break
                time.sleep(0.1)
            assert job["status"] == "succeeded", job
        finally:
            server.shutdown()

        listed = client.get("/api/blocklists").json()["subscriptions"][0]
        assert listed["rule_count"] == 1
        assert listed["last_success_at"]
        # Manual Only means no FUTURE scheduled run, even though the
        # initial pull above already happened.
        assert listed["effective_interval_seconds"] == 0
        assert not listed["next_update_at"]

    def test_unauthenticated_routes_are_rejected(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        assert client.get("/api/blocklists").status_code == 401
        assert client.post("/api/blocklists", json={"subscription_id": "x", "name": "x", "url": "http://x"}).status_code == 401

    def test_deleted_subscription_is_immediately_absent_from_a_fresh_list_call(self, tmp_path, monkeypatch):
        """Real defect fixed here (owner-reported live, blocklist Delete
        UI-consistency pass): the backend side of "deleted row stays
        visible until manual refresh" -- a fresh GET /api/blocklists
        issued immediately after a successful DELETE must never include
        the deleted subscription. (The client-side half -- immediate DOM
        removal, stale-in-flight-GET protection, route-cache
        invalidation -- is proven in the Chromium browser harness.)"""
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        csrf = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"}).json()["csrf"]
        headers = {"X-CSRF-Token": csrf}
        created = client.post("/api/blocklists", json={
            "subscription_id": "gone-fast", "name": "Gone Fast", "url": "http://example.invalid/list.txt",
        }, headers=headers)
        assert created.status_code == 200, created.text
        assert any(s["subscription_id"] == "gone-fast" for s in client.get("/api/blocklists").json()["subscriptions"])

        deleted = client.delete("/api/blocklists/gone-fast", headers=headers)
        assert deleted.status_code == 200, deleted.text

        listed = client.get("/api/blocklists").json()["subscriptions"]
        assert not any(s["subscription_id"] == "gone-fast" for s in listed), (
            "a fresh list call immediately after DELETE must never still include the deleted subscription"
        )

    def test_deletion_during_a_running_update_job_does_not_fail_the_whole_job(self, tmp_path, monkeypatch):
        """Real defect fixed here (owner-reported live, blocklist Delete
        UI-consistency pass): the row's own Delete control is disabled
        client-side while update_in_progress, but this is defense in
        depth for any path that reaches the server regardless -- a
        subscription deleted while Update Now/Update All has it staged
        used to raise uncaught inside the job's own commit transaction,
        rolling back and failing every OTHER subscription in that same
        job too, not just the deleted one."""
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        csrf = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"}).json()["csrf"]
        headers = {"X-CSRF-Token": csrf}

        good = _serve("good-job.example\n")
        deleted = _serve("about-to-be-deleted.example\n")
        try:
            for sid, name, server in (("job-good", "Good", good), ("job-deleted", "Deleted Mid-Job", deleted)):
                r = client.post("/api/blocklists", json={
                    "subscription_id": sid, "name": name, "url": f"http://127.0.0.1:{server.server_address[1]}/list.txt",
                }, headers=headers)
                assert r.status_code == 200, r.text
                # Creation now kicks off its own initial-pull job (see
                # create_blocklist_subscription_route) -- let it finish
                # before this test's own deliberate refresh-all below, so
                # the two don't race over the same subscription_ids and
                # the refresh-all attempt below isn't itself rejected as
                # a duplicate concurrent job.
                create_job_id = r.json()["job_id"]
                for _ in range(50):
                    job = client.get(f"/api/blocklists/jobs/{create_job_id}").json()
                    if job["status"] != "running":
                        break
                    time.sleep(0.1)
                assert job["status"] == "succeeded", job

            real_prepare_refresh = webapp.blocklist_subscriptions.prepare_refresh

            def _prepare_then_delete(sub, **kwargs):
                prepared = real_prepare_refresh(sub, **kwargs)
                if sub["subscription_id"] == "job-deleted":
                    d = client.delete("/api/blocklists/job-deleted", headers=headers)
                    assert d.status_code == 200, d.text
                return prepared

            monkeypatch.setattr(webapp.blocklist_subscriptions, "prepare_refresh", _prepare_then_delete)

            res = client.post("/api/blocklists/refresh-all", headers=headers)
            assert res.status_code == 200, res.text
            job_id = res.json()["job_id"]
            job = None
            for _ in range(50):
                job = client.get(f"/api/blocklists/jobs/{job_id}").json()
                if job["status"] != "running":
                    break
                time.sleep(0.1)
            assert job["status"] == "succeeded", job
            assert job["results"]["job-good"]["status"] == "succeeded"
            assert "job-deleted" not in job["results"]
        finally:
            good.shutdown()
            deleted.shutdown()

        listed = client.get("/api/blocklists").json()["subscriptions"]
        good_row = next(s for s in listed if s["subscription_id"] == "job-good")
        assert good_row["last_status"] == "succeeded"
        assert not any(s["subscription_id"] == "job-deleted" for s in listed)


class TestConsecutiveFailureTracking:
    """Pre-DoH reliability pass, part 3 (owner-clarified semantics): the
    row-level status shows every failure from the first one, but the
    page-level "needs attention" signal only trips after 3 consecutive
    genuine failures, and a single success fully clears it."""

    def _fail_server(self):
        server = _serve("", status=404)
        return server

    def test_three_consecutive_failures_trip_attention_then_success_clears_it(self, conn):
        server = self._fail_server()
        try:
            port = server.server_address[1]
            store.create_blocklist_subscription(conn, "flaky", "Flaky", f"http://127.0.0.1:{port}/missing.txt")
            for n in (1, 2, 3):
                result = bl.refresh_subscription(conn, "flaky")
                assert not result.ok
                sub = store.get_blocklist_subscription(conn, "flaky")
                assert sub["consecutive_failure_count"] == n
                assert sub["first_failure_at"], "first_failure_at must be stamped from the very first failure"
                assert sub["attention_required"] is (n >= 3)
            first_failure_at = store.get_blocklist_subscription(conn, "flaky")["first_failure_at"]
            # A 4th failure must not re-stamp first_failure_at -- it marks
            # when the CURRENT streak started, not the most recent failure.
            bl.refresh_subscription(conn, "flaky")
            assert store.get_blocklist_subscription(conn, "flaky")["first_failure_at"] == first_failure_at
            assert store.get_blocklist_subscription(conn, "flaky")["consecutive_failure_count"] == 4
        finally:
            server.shutdown()

        good = _serve("recovered.example\n")
        try:
            store.update_blocklist_subscription_fields(conn, "flaky", url=f"http://127.0.0.1:{good.server_address[1]}/list.txt")
            result = bl.refresh_subscription(conn, "flaky")
            assert result.ok
            sub = store.get_blocklist_subscription(conn, "flaky")
            assert sub["consecutive_failure_count"] == 0
            assert sub["first_failure_at"] is None
            assert sub["attention_required"] is False
            assert sub["last_error"] == ""
        finally:
            good.shutdown()

    def test_one_or_two_failures_do_not_trip_attention(self, conn):
        server = self._fail_server()
        try:
            port = server.server_address[1]
            store.create_blocklist_subscription(conn, "flaky2", "Flaky2", f"http://127.0.0.1:{port}/missing.txt")
            bl.refresh_subscription(conn, "flaky2")
            bl.refresh_subscription(conn, "flaky2")
            sub = store.get_blocklist_subscription(conn, "flaky2")
            assert sub["consecutive_failure_count"] == 2
            assert sub["attention_required"] is False
        finally:
            server.shutdown()

    def test_disabled_subscription_never_requires_attention_even_after_failures(self, conn):
        server = self._fail_server()
        try:
            port = server.server_address[1]
            store.create_blocklist_subscription(conn, "flaky3", "Flaky3", f"http://127.0.0.1:{port}/missing.txt")
            for _ in range(3):
                bl.refresh_subscription(conn, "flaky3")
            assert store.get_blocklist_subscription(conn, "flaky3")["attention_required"] is True
            store.set_blocklist_subscription_enabled(conn, "flaky3", False)
            assert store.get_blocklist_subscription(conn, "flaky3")["attention_required"] is False
        finally:
            server.shutdown()

    def test_a_check_that_never_attempted_never_increments(self, conn):
        # never_refreshed is the schema default -- record_blocklist_refresh_result
        # is simply never called for a not-due/manual/disabled subscription
        # (the orchestrator's own due-check skips it entirely), so nothing
        # here should ever move failure_count off its default of 0.
        store.create_blocklist_subscription(conn, "never-touched", "Never Touched", "http://example.invalid/list.txt")
        sub = store.get_blocklist_subscription(conn, "never-touched")
        assert sub["consecutive_failure_count"] == 0
        assert sub["last_status"] == "never_refreshed"


class TestRetryTimingUsesEffectiveInterval:
    """Owner-clarified product behavior: a failed subscription retries at
    its own next effective interval, not a separate faster exponential
    schedule -- see blocklist_subscriptions._next_retry_time's own
    docstring."""

    def test_failed_refresh_schedules_retry_no_sooner_than_the_configured_interval(self, conn):
        server = self._fail = _serve("", status=404)
        try:
            port = server.server_address[1]
            store.create_blocklist_subscription(conn, "slow-retry", "Slow Retry", f"http://127.0.0.1:{port}/missing.txt")
            store.set_blocklist_update_interval(conn, "slow-retry", 604800)  # 1 week
            sub = store.get_blocklist_subscription(conn, "slow-retry")
            prepared = bl.prepare_refresh(sub, default_interval_seconds=86400)
            assert not prepared.ok
            from datetime import datetime, timezone

            checked = datetime.fromisoformat(prepared.checked_at)
            retry_at = datetime.fromisoformat(prepared.next_retry_at)
            delta = (retry_at - checked).total_seconds()
            # Must be roughly a week out (interval + up to 10% jitter),
            # never the old 60s-start exponential-backoff schedule.
            assert delta >= 604800, f"retry scheduled only {delta:.0f}s out, expected >= 604800s (the configured interval)"
        finally:
            server.shutdown()

    def test_retry_after_header_pushes_retry_further_out_never_sooner(self, conn):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(503)
                self.send_header("Retry-After", "7200")
                self.end_headers()

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            port = server.server_address[1]
            store.create_blocklist_subscription(conn, "retry-after", "Retry After", f"http://127.0.0.1:{port}/list.txt")
            store.set_blocklist_update_interval(conn, "retry-after", 3600)  # 1 hour -- shorter than the 2h Retry-After
            sub = store.get_blocklist_subscription(conn, "retry-after")
            prepared = bl.prepare_refresh(sub, default_interval_seconds=86400)
            assert not prepared.ok
            from datetime import datetime

            checked = datetime.fromisoformat(prepared.checked_at)
            retry_at = datetime.fromisoformat(prepared.next_retry_at)
            delta = (retry_at - checked).total_seconds()
            assert delta >= 7200, f"Retry-After: 7200 must be honored as a floor, got only {delta:.0f}s"
        finally:
            server.shutdown()


class TestEditBlocklistSubscription:
    def test_editing_only_name_does_not_reset_failure_streak(self, conn):
        server = _serve("", status=404)
        try:
            port = server.server_address[1]
            store.create_blocklist_subscription(conn, "edit-name", "Old Name", f"http://127.0.0.1:{port}/missing.txt")
            for _ in range(3):
                bl.refresh_subscription(conn, "edit-name")
            before = store.get_blocklist_subscription(conn, "edit-name")
            assert before["attention_required"] is True

            url_changed = store.update_blocklist_subscription_fields(conn, "edit-name", name="New Name")
            assert url_changed is False
            after = store.get_blocklist_subscription(conn, "edit-name")
            assert after["name"] == "New Name"
            assert after["consecutive_failure_count"] == before["consecutive_failure_count"]
            assert after["attention_required"] is True
        finally:
            server.shutdown()

    def test_editing_url_resets_failure_streak_and_preserves_compiled_content(self, conn):
        good = _serve("still-active.example\n")
        try:
            port = good.server_address[1]
            store.create_blocklist_subscription(conn, "edit-url", "Edit URL", f"http://127.0.0.1:{port}/list.txt")
            r = bl.refresh_subscription(conn, "edit-url")
            assert r.ok
            assert store.is_domain_service_blocked(conn, bl.SUBSCRIPTION_RULESET_ID, "still-active.example") is not None
        finally:
            good.shutdown()

        bad = _serve("", status=404)
        try:
            port = bad.server_address[1]
            for _ in range(3):
                bl.refresh_subscription(conn, "edit-url")
            assert store.get_blocklist_subscription(conn, "edit-url")["attention_required"] is True

            url_changed = store.update_blocklist_subscription_fields(conn, "edit-url", url=f"http://127.0.0.1:{port}/still-broken.txt")
            assert url_changed is True
            after = store.get_blocklist_subscription(conn, "edit-url")
            assert after["consecutive_failure_count"] == 0
            assert after["first_failure_at"] is None
            assert after["next_update_at"], "edited subscription must be marked pending/due"
            # The OLD content (from the original, working URL) must still
            # be the active compiled filtering -- editing configuration
            # alone must never clear currently active filtering.
            assert store.is_domain_service_blocked(conn, bl.SUBSCRIPTION_RULESET_ID, "still-active.example") is not None
        finally:
            bad.shutdown()

    def test_edit_endpoint_over_http_full_lifecycle(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = TestBlocklistApiRoutes()._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        csrf = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"}).json()["csrf"]
        headers = {"X-CSRF-Token": csrf}

        bad = _serve("", status=404)
        try:
            port = bad.server_address[1]
            created = client.post("/api/blocklists", json={
                "subscription_id": "edit-http", "name": "Edit HTTP", "url": f"http://127.0.0.1:{port}/missing.txt",
            }, headers=headers)
            assert created.status_code == 200, created.text

            # Name-only edit: no job queued, no failure-streak effect (none yet).
            r = client.patch("/api/blocklists/edit-http", json={"name": "Renamed"}, headers=headers)
            assert r.status_code == 200, r.text
            assert r.json()["job_id"] is None
            assert r.json()["subscription"]["name"] == "Renamed"

            # Bad interval value -> structured, field-level error.
            r = client.patch("/api/blocklists/edit-http", json={"update_interval_seconds": 12345}, headers=headers)
            assert r.status_code == 400
            assert r.json()["field"] == "update_interval_seconds"

            # Unknown subscription -> 404, no field-level noise.
            r = client.patch("/api/blocklists/does-not-exist", json={"name": "x"}, headers=headers)
            assert r.status_code == 404
        finally:
            bad.shutdown()

        good = _serve("recovered-http.example\n")
        try:
            port = good.server_address[1]
            r = client.patch("/api/blocklists/edit-http", json={
                "url": f"http://127.0.0.1:{port}/list.txt", "trigger_update": True,
            }, headers=headers)
            assert r.status_code == 200, r.text
            assert r.json()["url_reset_failure_streak"] is True
            job_id = r.json()["job_id"]
            assert job_id
            job = None
            for _ in range(50):
                job = client.get(f"/api/blocklists/jobs/{job_id}").json()
                if job["status"] != "running":
                    break
                time.sleep(0.1)
            assert job["status"] == "succeeded", job
        finally:
            good.shutdown()

        listed = client.get("/api/blocklists").json()["subscriptions"][0]
        assert listed["consecutive_failure_count"] == 0
        assert listed["last_status"] == "succeeded"


class TestOrchestratorExitCode:
    """Real defect fixed here (owner preview, pre-DoH reliability pass):
    scripts/v2/alderpointdns_v2_blocklist_refresh.py used to exit 1 (a
    real systemd unit failure) whenever ANY one subscription failed, even
    with every other due subscription succeeding and the orchestration
    itself working correctly."""

    def _import_script(self):
        import importlib.util
        import sys

        sys.modules.pop("alderpointdns_v2_blocklist_refresh", None)
        spec = importlib.util.spec_from_file_location(
            "alderpointdns_v2_blocklist_refresh",
            __import__("pathlib").Path(__file__).resolve().parents[2] / "scripts/v2/alderpointdns_v2_blocklist_refresh.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_partial_failure_exits_zero_and_persists_run_summary(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
        (tmp_path / "state").mkdir(parents=True, exist_ok=True)
        dbpath = tmp_path / "state" / "control.db"
        control_db.initialize(dbpath)
        store.ensure_schema(dbpath)

        good = _serve("good-orchestrator.example\n")
        bad = _serve("", status=404)
        try:
            from datetime import datetime, timedelta, timezone

            past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            with control_db.connect(dbpath) as conn:
                store.create_blocklist_subscription(conn, "orch-good", "Good", f"http://127.0.0.1:{good.server_address[1]}/list.txt")
                store.create_blocklist_subscription(conn, "orch-bad", "Bad", f"http://127.0.0.1:{bad.server_address[1]}/missing.txt")
                # Explicit, unambiguous "due now" rather than relying on
                # next_update_at defaulting to unset -- deterministic
                # regardless of how a freshly-created subscription's due
                # state is interpreted.
                store.set_blocklist_next_update(conn, "orch-good", past)
                store.set_blocklist_next_update(conn, "orch-bad", past)

            import sys

            _pop_webapp_module()
            mod = self._import_script()
            exit_code = mod.main()
            assert exit_code == 0, "an orchestration that ran to completion must exit 0 even with one subscription failing"

            run_state = __import__("json").loads(mod.webapp.BLOCKLIST_REFRESH_STATE_FILE.read_text())
            assert run_state["orchestration_ok"] is True
            assert run_state["total"] == 2
            assert run_state["succeeded"] == 1
            assert run_state["failed"] == 1
            assert run_state["failed_subscriptions"] == ["orch-bad"]

            with control_db.connect(dbpath) as conn:
                assert store.get_blocklist_subscription(conn, "orch-good")["last_status"] == "succeeded"
                assert store.get_blocklist_subscription(conn, "orch-bad")["last_status"] == "failed"
        finally:
            good.shutdown()
            bad.shutdown()

    def test_subscription_deleted_mid_run_does_not_fail_the_whole_batch(self, tmp_path, monkeypatch):
        """Real defect fixed here (owner-reported live: blocklist Delete
        UI-consistency pass): an operator deleting a subscription in the
        real, narrow window between the orchestrator's own initial due-
        subscription read and its results actually being applied used to
        raise BlocklistSubscriptionError uncaught inside _mutate,
        rolling back and failing the ENTIRE batch -- one legitimate
        delete would have reported a false total orchestration failure
        for every other subscription refreshed in that same run too."""
        monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
        (tmp_path / "state").mkdir(parents=True, exist_ok=True)
        dbpath = tmp_path / "state" / "control.db"
        control_db.initialize(dbpath)
        store.ensure_schema(dbpath)

        good = _serve("good-orchestrator.example\n")
        deleted = _serve("about-to-be-deleted.example\n")
        try:
            from datetime import datetime, timedelta, timezone

            past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            with control_db.connect(dbpath) as conn:
                store.create_blocklist_subscription(conn, "orch-good", "Good", f"http://127.0.0.1:{good.server_address[1]}/list.txt")
                store.create_blocklist_subscription(conn, "orch-deleted", "Deleted Mid-Run", f"http://127.0.0.1:{deleted.server_address[1]}/list.txt")
                store.set_blocklist_next_update(conn, "orch-good", past)
                store.set_blocklist_next_update(conn, "orch-deleted", past)

            _pop_webapp_module()
            mod = self._import_script()

            # Simulate the real race: the operator's own delete lands
            # while this run's own fetch/prepare phase is still in
            # flight, before the mutate-and-promote transaction applies
            # the prepared results.
            real_prepare_refresh = mod.bl.prepare_refresh

            def _prepare_then_delete(sub, **kwargs):
                prepared = real_prepare_refresh(sub, **kwargs)
                if sub["subscription_id"] == "orch-deleted":
                    with control_db.connect(dbpath) as conn:
                        mod.bl.remove_subscription_service(conn, "orch-deleted")
                        store.delete_blocklist_subscription(conn, "orch-deleted")
                return prepared

            monkeypatch.setattr(mod.bl, "prepare_refresh", _prepare_then_delete)
            exit_code = mod.main()
            assert exit_code == 0, "a subscription deleted mid-run must not fail the whole orchestration"

            run_state = __import__("json").loads(mod.webapp.BLOCKLIST_REFRESH_STATE_FILE.read_text())
            assert run_state["orchestration_ok"] is True
            # The deleted subscription is neither succeeded nor failed --
            # it simply no longer exists to have a result at all.
            assert run_state["total"] == 1
            assert run_state["succeeded"] == 1
            assert run_state["failed"] == 0

            with control_db.connect(dbpath) as conn:
                # The OTHER, unrelated subscription's real success is
                # preserved -- not rolled back by the deleted one's race.
                assert store.get_blocklist_subscription(conn, "orch-good")["last_status"] == "succeeded"
                assert store.get_blocklist_subscription(conn, "orch-deleted") is None
        finally:
            good.shutdown()
            deleted.shutdown()

    def test_no_control_db_is_a_clean_noop_not_a_failure(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
        _pop_webapp_module()
        mod = self._import_script()
        assert mod.main() == 0


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
