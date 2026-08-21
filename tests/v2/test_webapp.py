"""Workstream 4B: management API integration tests (in-process, via
FastAPI TestClient -- real TLS handshake proof is a separate real-podman
test, see docs/v2/clean-install-evidence.md; this file proves route
logic, auth, CSRF, and session mechanics thoroughly and fast)."""

import importlib
import json
import os
import shutil
import sys

import pytest


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    sb = tmp_path
    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(sb / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(sb / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(sb / "var" / "lib"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")  # TestClient has no real TLS

    (sb / "var" / "lib").mkdir(parents=True, exist_ok=True)
    from app.v2 import control_db, policy_store

    dbpath = str(sb / "var" / "lib" / "control.db")
    control_db.initialize(dbpath)
    policy_store.ensure_schema(dbpath)

    # Force a fresh import so module-level path constants pick up the
    # patched env vars (webapp.py computes them at import time).
    for mod in list(sys.modules):
        if mod == "app.v2.webapp":
            del sys.modules[mod]
    webapp = importlib.import_module("app.v2.webapp")

    from fastapi.testclient import TestClient

    yield webapp, TestClient(webapp.app)


def _setup_and_login(webapp, client, username="admin", password="correcthorsebattery12"):
    r = client.post("/api/setup", json={"username": username, "password": password, "confirm_password": password})
    assert r.status_code == 200, r.text
    r = client.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf"]


class TestSetupBootstrap:
    """Owner-approved removal of RC42's mandatory SSH-retrieved setup-
    token flow: first-admin creation is gated purely on "no admin account
    exists yet," the same conventional first-run contract V1.1.1 already
    had -- no token file to generate, read, or invalidate.
    """

    def test_setup_required_true_on_fresh_db(self, app_client):
        webapp, client = app_client
        assert client.get("/api/setup/status").json()["setup_required"] is True

    def test_no_setup_token_field_required(self, app_client):
        webapp, client = app_client
        r = client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        assert r.status_code == 200, r.text

    def test_setup_required_false_after_first_admin_created(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        assert client.get("/api/setup/status").json()["setup_required"] is False

    def test_setup_rejected_once_already_configured(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        r = client.post("/api/setup", json={"username": "b", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        assert r.status_code == 409

    def test_second_admin_cannot_be_created_via_setup_even_with_new_credentials(self, app_client):
        # Transactional, not merely "first call wins": once an admin
        # exists, /api/setup can never be used again for any credentials,
        # matching "setup cannot be reused" from the beta-rescue brief.
        webapp, client = app_client
        _setup_and_login(webapp, client)
        r = client.post("/api/setup", json={"username": "totally-different", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        assert r.status_code == 409
        assert client.get("/api/setup/status").json()["setup_required"] is False

    def test_missing_control_db_fails_safely_rather_than_reopening_setup(self, app_client, tmp_path):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        webapp.CONTROL_DB.unlink()
        r = client.get("/api/setup/status")
        # create_if_missing=False (see _db()'s own docstring): a real,
        # already-initialized appliance's control.db going missing must
        # error, never silently look like a fresh, uninitialized
        # appliance that reopens the first-run setup flow.
        assert r.status_code >= 500
        assert r.json().get("setup_required") is not True


class TestAuthRequired:
    PROTECTED_GET = ["/api/networks", "/api/clients", "/api/upstreams", "/api/policy/global", "/api/notifications", "/api/system/status", "/api/tls/status"]

    @pytest.mark.parametrize("path", PROTECTED_GET)
    def test_unauthenticated_get_rejected(self, app_client, path):
        webapp, client = app_client
        r = client.get(path)
        assert r.status_code == 401, path

    def test_unauthenticated_post_rejected(self, app_client):
        webapp, client = app_client
        r = client.post("/api/networks", json={"network_id": "x", "cidr": "10.0.0.0/24"})
        assert r.status_code == 401


class TestLoginLogoutSessions:
    def test_login_wrong_password_rejected(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        r = client.post("/api/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

    def test_cookie_flags_httponly_samesite(self, app_client):
        webapp, client = app_client
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        cookie_header = r.headers.get("set-cookie", "")
        assert "HttpOnly" in cookie_header
        assert "SameSite=strict" in cookie_header

    def test_logout_invalidates_session(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.post("/api/logout", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200
        r2 = client.get("/api/networks")
        assert r2.status_code == 401

    def test_session_rotates_on_each_login(self, app_client):
        webapp, client = app_client
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        r1 = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        r2 = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert r1.json()["csrf"] != r2.json()["csrf"]

    def test_login_rejects_fast_with_503_when_hash_limiter_saturated(self, app_client):
        # Real defect found live during RC12 concurrent-login load testing:
        # /api/login's Argon2id verify call was structurally unable to
        # engage app/v2/webapp.py's own _hash_limiter (auth_hash.
        # verify_and_maybe_rehash had no limiter= parameter at all), so
        # a saturated limiter never protected this endpoint -- 5 real
        # concurrent logins against a real installed package measured
        # ~349s per request instead of the intended fast 503. This pins
        # the fix at the actual HTTP boundary, not just the library call.
        webapp, client = app_client
        _setup_and_login(webapp, client)
        from contextlib import ExitStack

        with ExitStack() as stack:
            for _ in range(webapp._hash_limiter.max_concurrent):
                stack.enter_context(webapp._hash_limiter.slot())
            r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert r.status_code == 503
        assert r.json()["error"] == "auth_busy"

    def test_login_survives_transient_database_lock(self, app_client):
        # Real defect found live during the hardware/performance matrix
        # re-verification (docs/v2/login-database-locked-under-load-fix.md):
        # under real combined DNS+analytics+concurrent-login load, the
        # login_attempts write hit real SQLite write-lock contention that
        # outlasted the 5s busy_timeout, surfacing as an unhandled
        # sqlite3.OperationalError -> raw 500 for an otherwise genuinely
        # successful, already-verified login. Reproduces the exact
        # transient-then-recovers shape live contention has: the first
        # write attempt raises "database is locked", the retry succeeds.
        import sqlite3
        from unittest import mock

        webapp, client = app_client
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})

        real_record = webapp._record_login_attempt
        calls = {"n": 0}

        def flaky_record(conn, ip, ok):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("database is locked")
            return real_record(conn, ip, ok)

        with mock.patch.object(webapp, "_record_login_attempt", side_effect=flaky_record):
            r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert r.status_code == 200, r.text
        assert calls["n"] == 2  # first attempt hit the lock, retry succeeded

    def test_login_returns_clean_503_when_lock_retry_budget_exhausted(self, app_client):
        # The belt-and-suspenders side: once retry_on_locked's bounded
        # budget is genuinely exhausted, the client gets a clean,
        # specific 503 -- never a raw 500/traceback.
        import sqlite3
        from unittest import mock

        webapp, client = app_client
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})

        with mock.patch.object(
            webapp, "_record_login_attempt", side_effect=sqlite3.OperationalError("database is locked")
        ), mock.patch("app.db_retry.time.sleep", return_value=None):  # skip real backoff delay in this test
            r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert r.status_code == 503, r.text
        assert r.json()["error"] == "database_busy"


class TestControlDbMissing:
    """Real defect found and fixed live during this workstream's
    failure-domain/chaos pass (docs/v2/control-db-silent-recreation-
    fix.md): a real installed appliance's control.db, moved aside to
    simulate it becoming unavailable, was silently replaced by dnsdist's
    own webapp with a brand-new, empty, freshly-schema'd database the
    moment any request touched it -- indistinguishable from a genuinely
    fresh, never-configured appliance, with the admin's real
    configuration merely invisible, not actually gone.
    """

    def test_missing_control_db_returns_clear_error_not_silent_fresh_install(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        webapp.CONTROL_DB.unlink()

        r = client.get("/api/setup/status")
        assert r.status_code == 500, r.text
        assert r.json()["error"] == "control_db_missing"
        # The defect this guards against: the file must not have been
        # silently recreated as a side effect of merely handling the
        # request.
        assert not webapp.CONTROL_DB.exists()

    def test_missing_control_db_does_not_get_silently_recreated_via_extended_schemas(self, app_client):
        # _ensure_extended_schemas() (called from nearly every route,
        # not just _db()'s own direct call sites) was the second,
        # independent path that could silently recreate control.db --
        # regression coverage for that path specifically, not just _db().
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        webapp.CONTROL_DB.unlink()

        r = client.get("/api/notifications", headers={"X-CSRF-Token": csrf})
        assert r.status_code in (401, 500)  # session itself is gone too, but never a silent 200
        assert not webapp.CONTROL_DB.exists()

    def test_missing_secret_store_returns_clear_error_not_silent_recreation(self, app_client):
        # Same real defect, same fix, applied to the protected secret
        # store: real secret material (replication CA key, DNSCrypt
        # keys) must never be silently orphaned by an empty directory
        # recreated on next use.
        import shutil

        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        shutil.rmtree(webapp.SECRETS_DIR)

        r = client.post("/api/dns-transports/dnscrypt/rotate", json={}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 500, r.text
        assert r.json()["error"] == "secret_store_missing"
        assert not webapp.SECRETS_DIR.exists()


class TestCsrf:
    def test_post_without_csrf_token_rejected(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        r = client.post("/api/networks", json={"network_id": "x", "cidr": "10.0.0.0/24"})
        assert r.status_code == 403

    def test_post_with_wrong_csrf_token_rejected(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        r = client.post("/api/networks", json={"network_id": "x", "cidr": "10.0.0.0/24"}, headers={"X-CSRF-Token": "wrong"})
        assert r.status_code == 403

    def test_post_with_correct_csrf_token_succeeds(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.post("/api/networks", json={"network_id": "x", "cidr": "10.0.0.0/24"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text


class TestLoginRateLimiting:
    def test_repeated_bad_logins_are_rate_limited(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        results = []
        for _ in range(webapp._LOGIN_FAILURE_MAX + 3):
            r = client.post("/api/login", json={"username": "admin", "password": "wrong"})
            results.append(r.status_code)
        assert 429 in results, results
        # Once rate-limited, even the CORRECT password is rejected (fail
        # closed against brute force), but is recoverable outside the
        # window -- proven at the unit level (_recent_login_failures uses
        # a real time-windowed query, not a permanent lock).
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert r.status_code == 429


class TestBindHealth:
    """Gate #3 acceptance closure §9: BIND recursive-backend health must
    be independently reported, and must never claim full health when a
    configured context is actually unreachable."""

    def test_no_bind_dir_reports_unconfigured_not_ok(self, app_client):
        webapp, client = app_client
        r = client.get("/api/health")
        assert r.status_code == 200
        bind = r.json()["components"]["bind"]
        assert bind["status"] == "unconfigured"
        assert bind["contexts"] == {}

    def test_configured_but_unreachable_context_degrades_overall_status(self, app_client, tmp_path):
        webapp, client = app_client
        ctx_dir = webapp.COMPILED_BIND_DIR / "ctx0"
        ctx_dir.mkdir(parents=True, exist_ok=True)
        (ctx_dir / "named.conf").write_text("// test\n")
        try:
            r = client.get("/api/health")
            body = r.json()
            assert body["components"]["bind"]["status"] == "degraded"
            assert body["components"]["bind"]["contexts"]["ctx0"]["reachable"] is False
            assert body["status"] == "degraded"
        finally:
            (ctx_dir / "named.conf").unlink()

    def test_configured_and_reachable_context_reports_ok(self, app_client):
        import socket as _socket
        import threading

        webapp, client = app_client
        ctx_dir = webapp.COMPILED_BIND_DIR / "ctx0"
        ctx_dir.mkdir(parents=True, exist_ok=True)
        (ctx_dir / "named.conf").write_text("// test\n")
        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 8153))
        srv.listen(1)
        stop = threading.Event()

        def _accept_loop():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                    conn.close()
                except OSError:
                    continue

        t = threading.Thread(target=_accept_loop, daemon=True)
        t.start()
        try:
            r = client.get("/api/health")
            body = r.json()
            assert body["components"]["bind"]["contexts"]["ctx0"]["reachable"] is True
            assert body["components"]["bind"]["status"] == "ok"
        finally:
            stop.set()
            srv.close()
            t.join(timeout=1)
            (ctx_dir / "named.conf").unlink()


class TestBackgroundWorkerHealth:
    """Owner-beta aging/liveness hardening (closure item 1): /api/health
    must report each background worker's real progress, not just whether
    its state file exists -- see app/v2/worker_heartbeat.py's docstring
    for the V1.1.1 field-report failure class this defends against."""

    def test_no_heartbeat_yet_is_reported_stale_not_silently_ok(self, app_client):
        webapp, client = app_client
        r = client.get("/api/health")
        body = r.json()
        workers = body["components"]["background_workers"]
        assert set(workers) == {"analytics-worker", "discovery-worker", "tier-b-worker", "schedule-worker"}
        for name, state in workers.items():
            assert state["status"] == "unknown", name
            assert state["stale"] is True, name
        assert body["status"] == "degraded"

    def test_a_recently_healthy_worker_is_reported_ok_not_stale(self, app_client):
        webapp, client = app_client
        webapp.worker_heartbeat.record_tick_start(webapp.STATE_DIR, "analytics-worker", tick_count=1)
        webapp.worker_heartbeat.record_tick_success(webapp.STATE_DIR, "analytics-worker", tick_count=1, result=7)
        r = client.get("/api/health")
        worker = r.json()["components"]["background_workers"]["analytics-worker"]
        assert worker["status"] == "ok"
        assert worker["stale"] is False
        assert worker["last_result"] == 7

    def test_a_worker_stuck_mid_tick_far_past_its_interval_is_reported_stale(self, app_client):
        """This is the exact failure class: the process never exited (no
        systemd restart, nothing in dmesg), but the loop itself stopped
        making progress -- health must not report this as healthy just
        because a heartbeat file exists at all."""
        webapp, client = app_client
        path = webapp.STATE_DIR / "worker-heartbeats" / "schedule-worker.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        import json as _json
        import time as _time

        path.write_text(_json.dumps({
            "worker": "schedule-worker", "status": "running", "tick_count": 1,
            "tick_started_at": _time.time() - 10_000, "last_success_at": None,
            "last_result": None, "last_error": None,
        }))
        r = client.get("/api/health")
        worker = r.json()["components"]["background_workers"]["schedule-worker"]
        assert worker["status"] == "running"
        assert worker["stale"] is True
        assert r.json()["status"] == "degraded"


class TestSecurityHeaders:
    def test_security_headers_present(self, app_client):
        webapp, client = app_client
        r = client.get("/api/health")
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("x-frame-options") == "DENY"
        assert "no-store" in r.headers.get("cache-control", "")
        assert r.headers.get("content-security-policy")

    def test_no_hsts_header_documented_choice(self, app_client):
        webapp, client = app_client
        r = client.get("/api/health")
        assert "strict-transport-security" not in {k.lower() for k in r.headers}


class TestErrorHandlingNoLeakage:
    def test_validation_error_returns_structured_json_not_traceback(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.post("/api/networks", json={"network_id": "x", "cidr": "not-a-cidr"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 400
        body = r.json()
        assert "Traceback" not in str(body)
        assert body["error"] == "validation_error"


class TestOversizedRequestRejected:
    """Regression for a real finding from adversarial security testing:
    no request body size limit existed anywhere, so an oversized field
    value was accepted through ASGI/Starlette/Pydantic parsing before a
    field-level validator finally rejected it -- and Pydantic's default
    error response echoed the full oversized value back verbatim (a 5 MB
    request produced a ~5 MB response). Now rejected immediately on
    declared Content-Length, before any body parsing."""

    def test_oversized_body_rejected_with_413_before_parsing(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        huge_value = "x" * (webapp.MAX_REQUEST_BODY_BYTES + 1000)
        r = client.post(
            "/api/networks",
            json={"network_id": "x", "cidr": "10.0.0.0/24", "description": huge_value},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 413
        # The oversized value itself must never be echoed back.
        assert huge_value not in r.text
        assert len(r.content) < 1000

    def test_ordinary_sized_request_still_works(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.post(
            "/api/networks", json={"network_id": "y", "cidr": "10.0.1.0/24"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text


class TestPolicyApiReachesRuntime:
    def test_creating_network_promotes_real_compiled_runtime(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.post("/api/networks", json={"network_id": "lan", "cidr": "10.0.0.0/24"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200
        assert r.json()["runtime"]["promoted"] is True
        assert webapp.COMPILED_DNSDIST_CONF.exists()

    def test_policy_mutation_promotes_configured_listen_address_not_loopback_default(self, app_client):
        # Real regression found live during RC1 clean-install acceptance
        # testing: webapp.py's live policy-mutation path used to call
        # runtime_compile.recompile_and_promote() without threading
        # through the appliance's real configured listener at all, so it
        # silently fell back to that function's own default
        # ("127.0.0.1:53") -- rebinding dnsdist to loopback-only (cutting
        # off every real LAN client) the moment any admin made any real
        # policy change through the UI/API, with no error or warning.
        webapp, client = app_client
        webapp.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        webapp.CONFIG_FILE.write_text(
            "schema_version: 1\nlisteners:\n- protocol: udp\n  address: 0.0.0.0\n  port: 53\n"
        )
        csrf = _setup_and_login(webapp, client)
        r = client.post("/api/networks", json={"network_id": "lan", "cidr": "10.0.0.0/24"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert 'setLocal("0.0.0.0:53")' in conf_text
        assert 'setLocal("127.0.0.1:53")' not in conf_text

    def test_policy_mutation_falls_back_to_sane_default_when_config_file_missing(self, app_client):
        # No config file at all (shouldn't normally happen post-install,
        # but must fail toward "still reachable," not loopback-only).
        webapp, client = app_client
        assert not webapp.CONFIG_FILE.exists()
        csrf = _setup_and_login(webapp, client)
        r = client.post("/api/networks", json={"network_id": "lan", "cidr": "10.0.0.0/24"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert 'setLocal("0.0.0.0:53")' in conf_text

    def test_explain_endpoint_returns_structured_no_secrets(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        client.post("/api/clients", json={"name": "kid-laptop"}, headers={"X-CSRF-Token": csrf})
        r = client.get("/api/policy/explain", params={"client_id": 1})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["client_id"] == 1
        assert "password" not in str(body).lower() and "secret" not in str(body).lower()

    def test_explain_endpoint_requires_auth(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        client.cookies.clear()
        r = client.get("/api/policy/explain", params={"client_id": 1})
        assert r.status_code == 401

    def test_custom_ip_response_mode_with_address_promotes_successfully(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/policy/global",
            json={"blocking_response_mode": "custom_ip", "custom_ipv4": "10.9.9.9"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        assert r.json()["runtime"]["promoted"] is True

    def test_custom_ip_response_mode_without_address_fails_cleanly_not_500(self, app_client):
        # Real defect closed: RC42 crashed the compile with an unhandled
        # exception the moment a policy resolved to custom_ip with no
        # configured address. Must be a clean, reportable failure with the
        # previous configuration left promoted, never a raw 500.
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/policy/global", json={"blocking_response_mode": "custom_ip"}, headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 409, r.text
        assert r.json()["error"] == "runtime_promotion_failed"
        # Rolled back: the stored policy must NOT have been left in the
        # broken state either.
        r2 = client.get("/api/policy/global", headers={"X-CSRF-Token": csrf})
        assert r2.json()["policy"]["blocking_response_mode"] != "custom_ip"


class TestDnsTransports:
    # Real defect this closes (docs/v2/encrypted-transport-parity-gap.md):
    # DoT was entirely absent from V2's real config generation.

    def test_get_defaults_disabled(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        r = client.get("/api/dns-transports")
        assert r.status_code == 200, r.text
        assert r.json()["dot_enabled"] is False
        assert r.json()["dot_port"] == 853

    def test_enabling_without_cert_provisioned_does_not_emit_a_listener(self, app_client):
        # A fresh install before ensure-tls-cert has ever run must not
        # crash or emit a listener pointing at cert files that don't
        # exist -- fails safe to "no DoT listener yet," not a broken
        # compiled config.
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        assert not webapp.ACTIVE_CERT_PATH.exists()
        r = client.put("/api/dns-transports", json={"dot_enabled": True, "dot_port": 8853}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert "addTLSLocal" not in conf_text

    def test_enabling_with_cert_provisioned_emits_a_real_dot_listener(self, app_client, tmp_path):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)

        import subprocess

        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(webapp.ACTIVE_KEY_PATH), "-out", str(webapp.ACTIVE_CERT_PATH),
                "-days", "1", "-subj", "/CN=test",
            ],
            check=True, capture_output=True,
        )

        r = client.put("/api/dns-transports", json={"dot_enabled": True, "dot_port": 8853}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        assert r.json()["runtime"]["promoted"] is True
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert 'addTLSLocal("0.0.0.0:8853"' in conf_text

        r2 = client.get("/api/dns-transports")
        assert r2.json()["dot_enabled"] is True
        assert r2.json()["dot_port"] == 8853
        assert r2.json()["cert_provisioned"] is True

    def test_disabling_removes_the_listener_from_the_next_compile(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)

        import subprocess

        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(webapp.ACTIVE_KEY_PATH), "-out", str(webapp.ACTIVE_CERT_PATH),
                "-days", "1", "-subj", "/CN=test",
            ],
            check=True, capture_output=True,
        )
        client.put("/api/dns-transports", json={"dot_enabled": True, "dot_port": 8853}, headers={"X-CSRF-Token": csrf})
        assert "addTLSLocal" in webapp.COMPILED_DNSDIST_CONF.read_text()

        r = client.put("/api/dns-transports", json={"dot_enabled": False, "dot_port": 8853}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        assert "addTLSLocal" not in webapp.COMPILED_DNSDIST_CONF.read_text()

    def test_requires_auth(self, app_client):
        webapp, client = app_client
        r = client.get("/api/dns-transports")
        assert r.status_code == 401
        r2 = client.put("/api/dns-transports", json={"dot_enabled": True, "dot_port": 853})
        assert r2.status_code == 401

    def test_enabling_doh_with_cert_provisioned_emits_a_real_doh_listener(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)

        import subprocess

        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(webapp.ACTIVE_KEY_PATH), "-out", str(webapp.ACTIVE_CERT_PATH),
                "-days", "1", "-subj", "/CN=test",
            ],
            check=True, capture_output=True,
        )

        r = client.put(
            "/api/dns-transports",
            json={"doh_enabled": True, "doh_port": 8444, "doh_path": "/dns-query"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert 'addDOHLocal("0.0.0.0:8444"' in conf_text
        assert '"/dns-query"' in conf_text

    def test_doh_and_dot_both_enabled_simultaneously(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)

        import subprocess

        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(webapp.ACTIVE_KEY_PATH), "-out", str(webapp.ACTIVE_CERT_PATH),
                "-days", "1", "-subj", "/CN=test",
            ],
            check=True, capture_output=True,
        )

        r = client.put(
            "/api/dns-transports",
            json={"dot_enabled": True, "dot_port": 8853, "doh_enabled": True, "doh_port": 8444},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert 'addTLSLocal("0.0.0.0:8853"' in conf_text
        assert 'addDOHLocal("0.0.0.0:8444"' in conf_text

    def test_invalid_doh_path_rejected(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/dns-transports", json={"doh_enabled": True, "doh_path": "no-leading-slash"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 422

    def test_dot_port_conflicting_with_management_api_rejected(self, app_client):
        # Real defect found live during RC21 acceptance testing: a
        # requested port colliding with an already-bound appliance port
        # (tried 8443, the management API's own port) passed real
        # dnsdist --check-config (a syntax check, not a bind attempt)
        # and got promoted -- but the live dnsdist process then
        # crash-looped trying to bind the occupied port, taking down
        # real DNS answering entirely, not just the misconfigured
        # listener. Must now be rejected before promotion, not
        # discovered live.
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/dns-transports", json={"dot_enabled": True, "dot_port": 8443},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 400, r.text
        assert r.json()["error"] == "port_conflict"
        assert not webapp.COMPILED_DNSDIST_CONF.exists() or "addTLSLocal" not in webapp.COMPILED_DNSDIST_CONF.read_text()

    def test_doh_port_conflicting_with_replication_service_rejected(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/dns-transports", json={"doh_enabled": True, "doh_port": 9443},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 400, r.text
        assert r.json()["error"] == "port_conflict"

    def test_dot_and_doh_same_port_rejected(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/dns-transports",
            json={"dot_enabled": True, "dot_port": 9999, "doh_enabled": True, "doh_port": 9999},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 400, r.text
        assert r.json()["error"] == "port_conflict"

    def test_disabled_protocol_port_conflict_not_checked(self, app_client):
        # A leftover/default port value for a protocol that is NOT being
        # enabled must not block an otherwise-valid update.
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/dns-transports",
            json={"dot_enabled": False, "dot_port": 8443, "doh_enabled": False, "doh_port": 8443},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text

    def test_enabling_doq_with_cert_provisioned_emits_a_real_doq_listener(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)

        import subprocess

        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(webapp.ACTIVE_KEY_PATH), "-out", str(webapp.ACTIVE_CERT_PATH),
                "-days", "1", "-subj", "/CN=test",
            ],
            check=True, capture_output=True,
        )

        r = client.put("/api/dns-transports", json={"doq_enabled": True, "doq_port": 8853}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert "addDOQLocal" in conf_text
        assert "0.0.0.0:8853" in conf_text

    def test_dot_and_doq_may_share_the_same_default_port(self, app_client):
        # Real, standard DNS practice (RFC 9250): DoQ (UDP) and DoT
        # (TCP) both conventionally default to port 853 and do not
        # actually conflict -- must not be rejected as a port_conflict.
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)

        import subprocess

        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(webapp.ACTIVE_KEY_PATH), "-out", str(webapp.ACTIVE_CERT_PATH),
                "-days", "1", "-subj", "/CN=test",
            ],
            check=True, capture_output=True,
        )

        r = client.put(
            "/api/dns-transports",
            json={"dot_enabled": True, "dot_port": 853, "doq_enabled": True, "doq_port": 853},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert "addTLSLocal" in conf_text
        assert "addDOQLocal" in conf_text

    def test_doq_port_conflicting_with_management_api_rejected(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/dns-transports", json={"doq_enabled": True, "doq_port": 8443},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 400, r.text
        assert r.json()["error"] == "port_conflict"

    def test_get_reports_real_dnsdist_capabilities(self, app_client):
        # Real capability detection (docs/v2/doh3-transport-implemented.md):
        # reuses app.dnsdist_upgrade.dnsdist_capabilities() -- the same
        # `dnsdist --version` parser V1's install-enhanced-dnsdist command
        # already uses -- rather than a second implementation, so the
        # admin UI can show *why* a toggled-on protocol isn't actually
        # answering queries on a build that lacks it.
        webapp, client = app_client
        _setup_and_login(webapp, client)
        r = client.get("/api/dns-transports")
        assert r.status_code == 200, r.text
        body = r.json()
        assert "doq_supported" in body
        assert "doh3_supported" in body
        assert "dnscrypt_supported" in body
        assert "dnsdist_version" in body
        assert isinstance(body["doq_supported"], bool)

    def test_enabling_doh3_with_cert_provisioned_emits_a_real_doh3_listener(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)

        import subprocess

        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(webapp.ACTIVE_KEY_PATH), "-out", str(webapp.ACTIVE_CERT_PATH),
                "-days", "1", "-subj", "/CN=test",
            ],
            check=True, capture_output=True,
        )

        r = client.put("/api/dns-transports", json={"doh3_enabled": True, "doh3_port": 8446}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert "addDOH3Local" in conf_text
        assert "0.0.0.0:8446" in conf_text

        r2 = client.get("/api/dns-transports")
        assert r2.json()["doh3_enabled"] is True
        assert r2.json()["doh3_port"] == 8446

    def test_doh3_advertised_via_alt_svc_when_doh_also_enabled(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)

        import subprocess

        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(webapp.ACTIVE_KEY_PATH), "-out", str(webapp.ACTIVE_CERT_PATH),
                "-days", "1", "-subj", "/CN=test",
            ],
            check=True, capture_output=True,
        )

        r = client.put(
            "/api/dns-transports",
            json={"doh_enabled": True, "doh_port": 8447, "doh3_enabled": True, "doh3_port": 8447},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert "addDOHLocal" in conf_text
        assert "addDOH3Local" in conf_text
        assert "alt-svc" in conf_text

    def test_doh3_port_conflicting_with_management_api_rejected(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/dns-transports", json={"doh3_enabled": True, "doh3_port": 8443},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 400, r.text
        assert r.json()["error"] == "port_conflict"

    def test_doq_and_doh3_may_share_the_same_default_port(self, app_client):
        # Both are QUIC/UDP-transported -- checked only against reserved
        # appliance ports and the plain DNS listener, never against each
        # other or against DoT/DoH's TCP-only conflict set.
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)

        import subprocess

        webapp.ACTIVE_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(webapp.ACTIVE_KEY_PATH), "-out", str(webapp.ACTIVE_CERT_PATH),
                "-days", "1", "-subj", "/CN=test",
            ],
            check=True, capture_output=True,
        )

        r = client.put(
            "/api/dns-transports",
            json={"doq_enabled": True, "doq_port": 4443, "doh3_enabled": True, "doh3_port": 4443},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert "addDOQLocal" in conf_text
        assert "addDOH3Local" in conf_text


class TestDnscrypt:
    """Real DNSCrypt provisioning + runtime wiring (roadmap continuation:
    closes the last remaining row of the confirmed mandatory-parity gap
    -- see docs/v2/dnscrypt-transport-implemented.md). Every test here
    drives real dnsdist key/cert generation (app/v2/
    dnscrypt_provisioning.py) end to end through the real HTTP API, not
    mocks -- matching the standard the rest of this workstream was held
    to.
    """

    def test_get_reports_unprovisioned_state(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        r = client.get("/api/dns-transports")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["dnscrypt_enabled"] is False
        assert body["dnscrypt_identity_provisioned"] is False
        assert body["dnscrypt_fingerprint"] is None

    def test_enabling_without_provisioning_is_rejected(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/dns-transports", json={"dnscrypt_enabled": True}, headers={"X-CSRF-Token": csrf}
        )
        assert r.status_code == 409, r.text
        assert r.json()["error"] == "dnscrypt_not_provisioned"

    def test_rotate_generates_real_identity_and_certificate(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.post("/api/dns-transports/dnscrypt/rotate", json={}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["rotated_provider"] is True  # first call always generates a provider identity
        assert body["fingerprint"] is not None
        assert len(body["fingerprint"].replace(":", "")) == 64  # 32 real bytes, hex-doubled
        assert body["cert_serial"] == 1
        assert body["cert_valid_until"] is not None

        r2 = client.get("/api/dns-transports")
        assert r2.json()["dnscrypt_identity_provisioned"] is True
        assert r2.json()["dnscrypt_fingerprint"] == body["fingerprint"]

    def test_enabling_after_provisioning_emits_a_real_dnscrypt_listener(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        client.post("/api/dns-transports/dnscrypt/rotate", json={}, headers={"X-CSRF-Token": csrf})

        r = client.put(
            "/api/dns-transports",
            json={"dnscrypt_enabled": True, "dnscrypt_port": 5443, "dnscrypt_provider_name": "2.dnscrypt-cert.pytest.local."},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        assert r.json()["runtime"]["promoted"] is True
        conf_text = webapp.COMPILED_DNSDIST_CONF.read_text()
        assert "addDNSCryptBind" in conf_text
        assert "2.dnscrypt-cert.pytest.local." in conf_text
        # Real materialized files, not just referenced by path.
        assert webapp.DNSCRYPT_CERT_PATH.exists()
        assert webapp.DNSCRYPT_KEY_PATH.exists()
        assert webapp.DNSCRYPT_CERT_PATH.read_bytes()[:4] == b"DNSC"

    def test_routine_rotate_keeps_provider_issues_new_cert(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        first = client.post("/api/dns-transports/dnscrypt/rotate", json={}, headers={"X-CSRF-Token": csrf}).json()

        second = client.post(
            "/api/dns-transports/dnscrypt/rotate", json={"rotate_provider": False}, headers={"X-CSRF-Token": csrf}
        ).json()
        assert second["rotated_provider"] is False
        assert second["fingerprint"] == first["fingerprint"]  # same provider identity
        assert second["cert_serial"] == first["cert_serial"] + 1  # but a fresh cert

    def test_explicit_provider_rotation_changes_fingerprint(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        first = client.post("/api/dns-transports/dnscrypt/rotate", json={}, headers={"X-CSRF-Token": csrf}).json()

        second = client.post(
            "/api/dns-transports/dnscrypt/rotate", json={"rotate_provider": True}, headers={"X-CSRF-Token": csrf}
        ).json()
        assert second["rotated_provider"] is True
        assert second["fingerprint"] != first["fingerprint"]  # real new identity
        assert second["cert_serial"] == 1  # serial sequence restarts under the new identity

    def test_dnscrypt_port_conflicting_with_management_api_rejected(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        client.post("/api/dns-transports/dnscrypt/rotate", json={}, headers={"X-CSRF-Token": csrf})
        r = client.put(
            "/api/dns-transports", json={"dnscrypt_enabled": True, "dnscrypt_port": 8443},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 400, r.text
        assert r.json()["error"] == "port_conflict"

    @pytest.mark.parametrize(
        "payload",
        [
            "2.dnscrypt-cert.test.local.\nos.execute(\"touch /tmp/pwned-pytest\")\n--",
            "\x00nullbyte",
            "2.dnscrypt-cert.test.local.\\",
            "has space",
            "quote\"here",
        ],
    )
    def test_malformed_provider_name_rejected_at_the_api_layer(self, app_client, payload):
        # Real hardening from this workstream's own adversarial security
        # pass: these values previously reached real dnsdist
        # --check-config before being rejected (safely, but later than
        # necessary) or were silently accepted despite having no
        # legitimate reason to contain such bytes. Now rejected by input
        # validation before ever reaching control.db or the compiler.
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.put(
            "/api/dns-transports", json={"dnscrypt_provider_name": payload}, headers={"X-CSRF-Token": csrf}
        )
        assert r.status_code == 422, r.text

    def test_disabling_removes_the_listener_from_the_next_compile(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        client.post("/api/dns-transports/dnscrypt/rotate", json={}, headers={"X-CSRF-Token": csrf})
        client.put("/api/dns-transports", json={"dnscrypt_enabled": True}, headers={"X-CSRF-Token": csrf})
        assert "addDNSCryptBind" in webapp.COMPILED_DNSDIST_CONF.read_text()

        r = client.put("/api/dns-transports", json={"dnscrypt_enabled": False}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        assert "addDNSCryptBind" not in webapp.COMPILED_DNSDIST_CONF.read_text()

    def test_rotate_requires_auth(self, app_client):
        webapp, client = app_client
        r = client.post("/api/dns-transports/dnscrypt/rotate", json={})
        assert r.status_code == 401

    def test_rotate_requires_csrf(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        r = client.post("/api/dns-transports/dnscrypt/rotate", json={})
        assert r.status_code == 403
        assert r.json()["error"] == "invalid_csrf_token"

    def test_failed_promotion_does_not_orphan_secrets(self, app_client):
        # Real defect found live during this workstream's own adversarial
        # security pass: SecretStore.create() writes directly to disk and
        # is NOT part of _mutate_and_promote's SQL transaction. Forcing a
        # post-_mutate failure (recompile_and_promote raising) previously
        # left the freshly-generated provider/resolver private key
        # secrets permanently orphaned on disk -- real key material,
        # referenced by nothing, un-rotatable, un-auditable -- even
        # though control.db correctly rolled back to the unprovisioned
        # state. Fixed: every secret a rotate attempt creates is tracked
        # and deleted on any failure of that same attempt.
        from unittest import mock

        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        secrets_before = set(webapp._secrets().list_ids())

        with mock.patch.object(
            webapp.runtime_compile, "recompile_and_promote", side_effect=RuntimeError("forced failure")
        ):
            # app_client's TestClient propagates unhandled server
            # exceptions rather than returning a response (its default
            # raise_server_exceptions=True) -- the forced failure itself
            # IS the point being tested, so assert it propagates rather
            # than swallowing it.
            with pytest.raises(RuntimeError, match="forced failure"):
                client.post("/api/dns-transports/dnscrypt/rotate", json={}, headers={"X-CSRF-Token": csrf})

        assert set(webapp._secrets().list_ids()) == secrets_before, (
            "a failed rotation must not leave orphaned secret files on disk"
        )
        with webapp._db() as conn:
            settings = webapp.store.load_dnscrypt_settings(conn)
        assert settings.identity_provisioned is False

        # A real, successful rotation afterward must still work correctly
        # -- the failure-path cleanup must not have broken anything.
        r2 = client.post("/api/dns-transports/dnscrypt/rotate", json={}, headers={"X-CSRF-Token": csrf})
        assert r2.status_code == 200, r2.text
        assert len(set(webapp._secrets().list_ids()) - secrets_before) == 2  # provider + resolver secrets


class TestReplicationPeerCertEnrollment:
    """Real replication peer-enrollment endpoint (previously missing
    entirely -- see replication_v2.REPLICATION_CA_KEY_SECRET_ID's and
    webapp.py's replication_issue_peer_cert's docstrings for the real
    gap this closes: found live during RC3 replication acceptance
    testing that no shipped tool could ever establish trust between two
    independently installed nodes)."""

    def test_issue_peer_cert_requires_auth(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        client.cookies.clear()
        r = client.post("/api/replication/issue-peer-cert", json={"remote_node_id": "some-node"})
        assert r.status_code == 401

    def test_issue_peer_cert_without_replication_material_returns_clear_error(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.post("/api/replication/issue-peer-cert", json={"remote_node_id": "some-node"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 409
        assert "not_initialized" in r.text or "replication_not_initialized" in r.text

    def test_issue_peer_cert_without_persisted_ca_key_returns_clear_error(self, app_client):
        # Simulates a node provisioned before this fix: replication TLS
        # material exists on disk, but no CA key was ever persisted.
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        from app.v2 import replication_v2

        ca_pem, ca_key_pem = replication_v2.generate_private_ca("pre-fix-node-ca")
        cert_pem, key_pem = replication_v2.issue_node_cert(ca_pem, ca_key_pem, "pre-fix-node", server_name="localhost")
        webapp.REPLICATION_DIR.mkdir(parents=True, exist_ok=True)
        webapp.REPLICATION_CA_PATH.write_text(ca_pem)
        webapp.REPLICATION_SERVER_CERT_PATH.write_text(cert_pem)
        r = client.post("/api/replication/issue-peer-cert", json={"remote_node_id": "some-node"}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 409
        assert "no_persisted_ca_key" in r.text

    def test_issue_peer_cert_rejects_unsafe_remote_node_id(self, app_client):
        # Real finding from RC11 live security spot-checking: an
        # arbitrary string like "../../etc/passwd" used to be accepted
        # and embedded into a real issued certificate's CN with no
        # format validation at all.
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        for bad in ("../../etc/passwd", '"});os.execute("id")--', "a" * 5000, ""):
            r = client.post(
                "/api/replication/issue-peer-cert",
                json={"remote_node_id": bad},
                headers={"X-CSRF-Token": csrf},
            )
            assert r.status_code == 422, (bad, r.text)

    def test_issue_peer_cert_returns_a_valid_enrollment_bundle(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        from app.v2 import replication_v2

        ca_pem, ca_key_pem = replication_v2.generate_private_ca("this-node-ca")
        cert_pem, key_pem = replication_v2.issue_node_cert(ca_pem, ca_key_pem, "this-node", server_name="localhost")
        webapp.REPLICATION_DIR.mkdir(parents=True, exist_ok=True)
        webapp.REPLICATION_CA_PATH.write_text(ca_pem)
        webapp.REPLICATION_SERVER_CERT_PATH.write_text(cert_pem)
        webapp._secrets().create(ca_key_pem, secret_id=replication_v2.REPLICATION_CA_KEY_SECRET_ID)

        r = client.post(
            "/api/replication/issue-peer-cert",
            json={"remote_node_id": "remote-node-xyz", "server_name": "10.1.2.3"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ca_pem"] == ca_pem
        assert body["expected_cert_sha256"] == replication_v2.cert_fingerprint_sha256(cert_pem)
        assert replication_v2.cert_node_id(body["client_cert_pem"]) == "remote-node-xyz"
        # issued_cert_sha256 is what the remote node's admin needs as
        # THEIR OWN peer-record's expected_incoming_cert_sha256 for a
        # bidirectional relationship -- must be the fingerprint of the
        # cert actually returned, not this node's own server cert.
        assert body["issued_cert_sha256"] == replication_v2.cert_fingerprint_sha256(body["client_cert_pem"])
        assert body["issued_cert_sha256"] != body["expected_cert_sha256"]
        # The CA private key itself must never be returned to the caller.
        assert ca_key_pem not in json.dumps(body)


class TestReplicationSyncErrorHandling:
    """Real defect found live during Gate #3 two-node replication
    failure-isolation testing: a peer being unreachable (its
    replication service stopped) is already a foreseeable outcome that
    push_to_peer records into the peer's own last_error, but the sync
    endpoint had nothing catching that exception -- it fell through to
    the generic unhandled-exception handler and returned an opaque
    {"error": "internal_error"} 500 to whoever called /sync, including
    the admin UI's own "Sync now" action. Now mapped to a specific,
    actionable ApiError instead."""

    def test_sync_against_unreachable_peer_returns_specific_error_not_generic_500(self, app_client, monkeypatch):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        from app.v2 import replication_v2

        def _raise_connection_refused(*_a, **_kw):
            raise ConnectionRefusedError("[Errno 111] Connection refused")

        monkeypatch.setattr(replication_v2, "push_to_peer", _raise_connection_refused)
        r = client.post("/api/replication/peers/some-peer/sync", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 502, r.text
        assert r.json()["error"] == "peer_unreachable"

    def test_sync_against_peer_cert_mismatch_returns_specific_error_not_generic_500(self, app_client, monkeypatch):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        from app.v2 import replication_v2

        def _raise_auth_error(*_a, **_kw):
            raise replication_v2.ReplicationAuthError("peer server certificate fingerprint mismatch")

        monkeypatch.setattr(replication_v2, "push_to_peer", _raise_auth_error)
        r = client.post("/api/replication/peers/some-peer/sync", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 502, r.text
        assert r.json()["error"] == "peer_sync_failed"
        assert "fingerprint mismatch" in r.json()["detail"]


class TestTlsStatusApi:
    def test_tls_status_reports_no_active_cert_when_none_provisioned(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        r = client.get("/api/tls/status")
        assert r.status_code == 200
        assert r.json()["active"] is False  # ctl init-state provisions it in the real deployment, not this test

    def test_tls_replace_with_mismatched_pair_rejected(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        from app.v2.tls_cert import generate_self_signed

        cert1, _ = generate_self_signed()
        _, key2 = generate_self_signed()
        r = client.post(
            "/api/tls/replace",
            json={"certificate_pem": cert1.decode(), "private_key_pem": key2.decode()},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 400

    def test_tls_replace_with_valid_pair_succeeds(self, app_client):
        webapp, client = app_client
        csrf = _setup_and_login(webapp, client)
        from app.v2.tls_cert import generate_self_signed

        cert, key = generate_self_signed()
        r = client.post(
            "/api/tls/replace",
            json={"certificate_pem": cert.decode(), "private_key_pem": key.decode()},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200
        assert r.json()["restart_required"] is True
        assert webapp.ACTIVE_CERT_PATH.exists()
