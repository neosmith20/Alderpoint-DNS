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
    webapp.BOOTSTRAP_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    webapp.BOOTSTRAP_TOKEN_PATH.write_text("tok-abc")
    r = client.post("/api/setup", json={"setup_token": "tok-abc", "username": username, "password": password})
    assert r.status_code == 200, r.text
    r = client.post("/api/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["csrf"]


class TestSetupBootstrap:
    def test_setup_required_true_on_fresh_db(self, app_client):
        webapp, client = app_client
        assert client.get("/api/setup/status").json()["setup_required"] is True

    def test_wrong_token_rejected(self, app_client):
        webapp, client = app_client
        webapp.BOOTSTRAP_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        webapp.BOOTSTRAP_TOKEN_PATH.write_text("real-token")
        r = client.post("/api/setup", json={"setup_token": "wrong", "username": "a", "password": "correcthorsebattery12"})
        assert r.status_code == 403

    def test_token_invalidated_after_success(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        assert not webapp.BOOTSTRAP_TOKEN_PATH.exists()

    def test_setup_rejected_once_already_configured(self, app_client):
        webapp, client = app_client
        _setup_and_login(webapp, client)
        webapp.BOOTSTRAP_TOKEN_PATH.write_text("another-token")
        r = client.post("/api/setup", json={"setup_token": "another-token", "username": "b", "password": "correcthorsebattery12"})
        assert r.status_code == 409

    def test_setup_missing_token_file_rejected(self, app_client):
        webapp, client = app_client
        r = client.post("/api/setup", json={"setup_token": "anything", "username": "a", "password": "correcthorsebattery12"})
        assert r.status_code == 409


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
        webapp.BOOTSTRAP_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        webapp.BOOTSTRAP_TOKEN_PATH.write_text("tok")
        client.post("/api/setup", json={"setup_token": "tok", "username": "admin", "password": "correcthorsebattery12"})
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
        webapp.BOOTSTRAP_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        webapp.BOOTSTRAP_TOKEN_PATH.write_text("tok")
        client.post("/api/setup", json={"setup_token": "tok", "username": "admin", "password": "correcthorsebattery12"})
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
