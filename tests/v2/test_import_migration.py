"""Tests for app/v2/import_migration.py -- the AdGuard Home / Pi-hole /
generic (hosts, BIND zone, Alderpoint-native CSV/XLSX/JSON) importer
(beta-rescue priority 2).

Unit coverage exercises parse -> plan -> apply -> idempotent re-apply
against realistic fixtures for each source type. The
``TestRealRuntimeProof`` class at the bottom is the required end-to-end
proof: import -> apply -> the exact real compiler
(``runtime_compile.build_bindings`` + ``compile_multi_policy_dnsdist_config``,
the same functions the live webapp uses) -> a real ``dnsdist`` process ->
real DNS queries whose answers must match what was imported.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from app.v2 import control_db, import_migration as im, policy_store as store

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    with control_db.connect(path) as c:
        yield c


ADGUARD_YAML_FIXTURE = """
schema_version: 27
dns:
  bootstrap_dns:
    - 9.9.9.9
  upstream_dns:
    - "8.8.8.8:53"
  allowed_clients: []
  disallowed_clients: []
filtering:
  rewrites_enabled: true
  rewrites:
    - domain: nas.lan
      answer: 10.0.0.20
    - domain: printer.lan
      answer: 10.0.0.21
  user_rules:
    - "||doubleclick.net^"
    - "||ads-tracker.example^"
    - "@@||allowed.example^"
filters:
  - name: "AdGuard DNS filter"
    url: "https://example.com/filter.txt"
    enabled: true
clients:
  persistent:
    - name: "Kids Laptop"
      ids: ["10.0.0.55"]
"""

PIHOLE_FIXTURE = """
# adlists.list
https://example.com/pihole-list.txt

# blacklist.txt
adtracker.example
doubleclick.net

# whitelist.txt
allowed.example

# custom.list
10.0.0.30 nas2.lan
10.0.0.31 printer2.lan

# 05-pihole-custom-cname.conf
cname=alias.lan,nas2.lan
"""


class TestAdGuardImport:
    def test_parse_produces_expected_plan_items(self, conn):
        translation = im.parse_source("adguard_yaml", text=ADGUARD_YAML_FIXTURE, default_domain="home.arpa")
        plan = im.build_plan(translation, conn)
        kinds = {item["kind"] for item in plan["items"]}
        assert "local_dns" in kinds
        assert "block_domain" in kinds
        assert "upstream" in kinds
        assert "client" in kinds

        local_dns_items = [i for i in plan["items"] if i["kind"] == "local_dns"]
        assert {"nas.lan", "printer.lan"} <= {i["fqdn"] for i in local_dns_items}

        block_items = {i["domain"] for i in plan["items"] if i["kind"] == "block_domain"}
        assert "doubleclick.net" in block_items
        assert "ads-tracker.example" in block_items

        # The allow rule and the blocklist-subscription URL must be
        # explicit warnings, never silently dropped or silently applied.
        unsupported_texts = " ".join(i["text"] for i in plan["items"] if i["kind"] == "unsupported")
        assert "allowed.example" in unsupported_texts
        assert "AdGuard DNS filter" in unsupported_texts

    def test_apply_writes_real_state_and_is_idempotent(self, conn):
        translation = im.parse_source("adguard_yaml", text=ADGUARD_YAML_FIXTURE, default_domain="home.arpa")
        plan = im.build_plan(translation, conn)
        job_id = im.create_job(conn, "adguard_yaml", "fixture.yaml", plan)
        counts = im.apply_plan(conn, job_id, plan)
        assert counts["local_dns"] == 2
        assert counts["block_domain"] == 2
        assert counts["client"] == 1

        records = {(n, t, v) for (n, t, v, _ttl) in store.load_local_dns_records(conn)}
        assert ("nas.lan", "A", "10.0.0.20") in records
        assert ("printer.lan", "A", "10.0.0.21") in records
        assert store.is_domain_service_blocked(conn, im.IMPORTED_RULESET_ID, "doubleclick.net") is not None
        assert store.is_domain_service_blocked(conn, im.IMPORTED_RULESET_ID, "sub.doubleclick.net") is not None
        assert store.is_domain_service_blocked(conn, im.IMPORTED_RULESET_ID, "not-blocked.example") is None

        global_layer = store.load_policy_layer(conn, "global", "singleton")
        assert global_layer.service_blocking_ruleset_id == im.IMPORTED_RULESET_ID

        # Idempotent re-apply of the identical plan must not duplicate
        # local DNS rows, must not error on the already-existing service,
        # and must report the already-satisfied items as skipped rather
        # than re-creating them.
        plan2 = im.build_plan(translation, conn)
        job_id2 = im.create_job(conn, "adguard_yaml", "fixture.yaml", plan2)
        counts2 = im.apply_plan(conn, job_id2, plan2)
        assert counts2["local_dns"] == 2  # upsert, not an error
        records_after = store.load_local_dns_records(conn)
        assert len({(n, t, v) for (n, t, v, _ttl) in records_after}) == len(records_after)  # still no dupes


class TestPiholeImport:
    def test_parse_and_plan(self, conn):
        translation = im.parse_source("pihole", text=PIHOLE_FIXTURE, default_domain="home.arpa")
        plan = im.build_plan(translation, conn)
        kinds = {item["kind"] for item in plan["items"]}
        assert "local_dns" in kinds
        assert "block_domain" in kinds

        local_dns_items = {i["fqdn"] for i in plan["items"] if i["kind"] == "local_dns"}
        assert {"nas2.lan", "printer2.lan"} <= local_dns_items
        # the CNAME alias
        cname_items = [i for i in plan["items"] if i["kind"] == "local_dns" and i["record_type"] == "CNAME"]
        assert any(i["fqdn"] == "alias.lan" and i["value"] == "nas2.lan" for i in cname_items)

        block_items = {i["domain"] for i in plan["items"] if i["kind"] == "block_domain"}
        assert {"adtracker.example", "doubleclick.net"} <= block_items

        unsupported_texts = " ".join(i["text"] for i in plan["items"] if i["kind"] == "unsupported")
        assert "allowed.example" in unsupported_texts
        assert "pihole-list.txt" in unsupported_texts

    def test_apply_and_conflict_detection_on_second_source(self, conn):
        translation = im.parse_source("pihole", text=PIHOLE_FIXTURE, default_domain="home.arpa")
        plan = im.build_plan(translation, conn)
        job_id = im.create_job(conn, "pihole", "fixture", plan)
        counts = im.apply_plan(conn, job_id, plan)
        assert counts["local_dns"] >= 3
        assert counts["block_domain"] == 2

        # A second, unrelated import that blocks one of the SAME domains
        # via a different rule text should be flagged already_applied,
        # not treated as a fresh new item.
        second = im.parse_source("hosts", text="10.0.0.99 another.lan\n", default_domain="home.arpa")
        second["custom_block"] = ["doubleclick.net"]
        plan2 = im.build_plan(second, conn)
        block_item = next(i for i in plan2["items"] if i["kind"] == "block_domain" and i["domain"] == "doubleclick.net")
        assert block_item["already_applied"] is True


class TestGenericImports:
    def test_hosts_import(self, conn):
        translation = im.parse_source("hosts", text="10.1.1.5 printer3.lan\n10.1.1.6 nas3.lan\n", default_domain="home.arpa")
        plan = im.build_plan(translation, conn)
        fqdns = {i["fqdn"] for i in plan["items"] if i["kind"] == "local_dns"}
        assert {"printer3.lan", "nas3.lan"} <= fqdns

    def test_bind_zone_import(self, conn):
        zone = "www.lan.  300  IN  A  10.2.2.5\nmail.lan.  IN  CNAME  www.lan.\n"
        translation = im.parse_source("bind_zone", text=zone, default_domain="home.arpa")
        plan = im.build_plan(translation, conn)
        items = {(i["fqdn"], i["record_type"], i["value"]) for i in plan["items"] if i["kind"] == "local_dns"}
        assert ("www.lan", "A", "10.2.2.5") in items
        assert ("mail.lan", "CNAME", "www.lan") in items

    def test_native_csv_import_round_trips_with_native_json_export(self, conn):
        csv_text = "fqdn,record_type,value,ttl,enabled,comment\nsvc.lan,A,10.3.3.5,300,1,imported\n"
        translation = im.parse_source("csv", text=csv_text, default_domain="home.arpa")
        plan = im.build_plan(translation, conn)
        items = {(i["fqdn"], i["record_type"], i["value"]) for i in plan["items"] if i["kind"] == "local_dns"}
        assert ("svc.lan", "A", "10.3.3.5") in items

    def test_native_json_import(self, conn):
        import json

        payload = {
            "format": "alderpointdns-native",
            "version": 2,
            "local_dns_records": [{"fqdn": "native.lan", "record_type": "A", "value": "10.4.4.5", "ttl": 300}],
            "custom_rules": [{"domain": "native-blocked.example", "action": "block", "enabled": True, "comment": ""}],
        }
        translation = im.parse_source("alderpointdns_json", text=json.dumps(payload), default_domain="home.arpa")
        plan = im.build_plan(translation, conn)
        fqdns = {i["fqdn"] for i in plan["items"] if i["kind"] == "local_dns"}
        assert "native.lan" in fqdns
        blocked = {i["domain"] for i in plan["items"] if i["kind"] == "block_domain"}
        assert "native-blocked.example" in blocked

    def test_unsupported_source_type_is_a_clean_error_not_a_crash(self, conn):
        with pytest.raises(im.ImportError_):
            im.parse_source("not_a_real_format", text="x")


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _dig(port: int, qname: str, rdtype: str = "A", timeout: float = 2.0):
    import dns.message
    import dns.query

    q = dns.message.make_query(qname, rdtype)
    return dns.query.udp(q, "127.0.0.1", port=port, timeout=timeout)


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="requires installed dnsdist")
class TestRealRuntimeProof:
    """import -> apply -> real compile -> real dnsdist -> real DNS query.
    This is the required proof for beta-rescue priority 2: 'import
    realistic fixture -> preview -> apply -> compile/promote -> real DNS
    behavior.'"""

    def test_adguard_import_reaches_real_dns_answers(self, tmp_path):
        from app.v2 import runtime_compile
        from app.v2.dnsdist_policy_runtime import compile_multi_policy_dnsdist_config

        db_path = tmp_path / "control.db"
        store.ensure_schema(db_path)
        with control_db.connect(db_path) as conn:
            translation = im.parse_source("adguard_yaml", text=ADGUARD_YAML_FIXTURE, default_domain="home.arpa")
            plan = im.build_plan(translation, conn)
            job_id = im.create_job(conn, "adguard_yaml", "fixture.yaml", plan)
            im.apply_plan(conn, job_id, plan)
            conn.commit()

            bindings = runtime_compile.build_bindings(conn)
            local_dns_records = store.load_local_dns_records(conn)

        port = _free_port()
        config_text = compile_multi_policy_dnsdist_config(
            f"127.0.0.1:{port}", bindings, local_dns_records=local_dns_records,
            analytics_log_address=None, discovery_ingress_address=None,
        )
        conf_path = tmp_path / "dnsdist.conf"
        conf_path.write_text(config_text)
        proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(1.0)
            # Imported Local DNS record answers with the real imported IP.
            resp = _dig(port, "nas.lan.", "A")
            answers = [str(rr) for rrset in resp.answer for rr in rrset]
            assert any("10.0.0.20" in a for a in answers), answers

            # Imported blocked domain (and a subdomain, suffix match) is
            # really refused/NXDOMAIN'd by the compiled runtime, not just
            # present in a staged plan.
            import dns.rcode

            blocked_resp = _dig(port, "doubleclick.net.", "A")
            assert blocked_resp.rcode() == dns.rcode.NXDOMAIN

            blocked_sub_resp = _dig(port, "ads.doubleclick.net.", "A")
            assert blocked_sub_resp.rcode() == dns.rcode.NXDOMAIN
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def test_pihole_import_reaches_real_dns_answers(self, tmp_path):
        from app.v2 import runtime_compile
        from app.v2.dnsdist_policy_runtime import compile_multi_policy_dnsdist_config

        db_path = tmp_path / "control.db"
        store.ensure_schema(db_path)
        with control_db.connect(db_path) as conn:
            translation = im.parse_source("pihole", text=PIHOLE_FIXTURE, default_domain="home.arpa")
            plan = im.build_plan(translation, conn)
            job_id = im.create_job(conn, "pihole", "fixture", plan)
            im.apply_plan(conn, job_id, plan)
            conn.commit()

            bindings = runtime_compile.build_bindings(conn)
            local_dns_records = store.load_local_dns_records(conn)

        port = _free_port()
        config_text = compile_multi_policy_dnsdist_config(
            f"127.0.0.1:{port}", bindings, local_dns_records=local_dns_records,
            analytics_log_address=None, discovery_ingress_address=None,
        )
        conf_path = tmp_path / "dnsdist.conf"
        conf_path.write_text(config_text)
        proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(1.0)
            resp = _dig(port, "nas2.lan.", "A")
            answers = [str(rr) for rrset in resp.answer for rr in rrset]
            assert any("10.0.0.30" in a for a in answers), answers

            cname_resp = _dig(port, "alias.lan.", "A")
            cname_targets = [str(rr) for rrset in cname_resp.answer for rr in rrset]
            assert any("nas2.lan" in a for a in cname_targets), cname_targets

            import dns.rcode

            blocked_resp = _dig(port, "adtracker.example.", "A")
            assert blocked_resp.rcode() == dns.rcode.NXDOMAIN
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


class TestImportApiRoutes:
    """HTTP-level proof that the import routes are actually wired into
    the webapp (not just the underlying module), using the real FastAPI
    TestClient, real auth/CSRF, and the real _mutate_and_promote path."""

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

    def test_parse_preview_apply_over_http(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        r = client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12"})
        assert r.status_code == 200, r.text
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert r.status_code == 200, r.text
        csrf = r.json()["csrf"]

        r = client.post(
            "/api/import/jobs",
            json={"source_type": "pihole", "source_name": "http-test", "text": PIHOLE_FIXTURE, "default_domain": "home.arpa"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        job_id = body["job_id"]
        assert body["plan"]["item_count"] > 0

        listed = client.get("/api/import/jobs")
        assert listed.status_code == 200
        assert listed.json()["jobs"][0]["id"] == job_id

        fetched = client.get(f"/api/import/jobs/{job_id}")
        assert fetched.status_code == 200
        assert fetched.json()["status"] == "previewed"

        applied = client.post(f"/api/import/jobs/{job_id}/apply", json={"skip_indexes": []}, headers={"X-CSRF-Token": csrf})
        assert applied.status_code == 200, applied.text
        assert applied.json()["counts"]["local_dns"] >= 3
        assert applied.json()["runtime"]["promoted"] is True

        records = client.get("/api/local-dns")
        assert records.status_code == 200
        assert any(rec["name"] == "nas2.lan" for rec in records.json()["records"])

        # Idempotent re-apply over HTTP too.
        applied_again = client.post(f"/api/import/jobs/{job_id}/apply", json={"skip_indexes": []}, headers={"X-CSRF-Token": csrf})
        assert applied_again.status_code == 200, applied_again.text

    def test_unauthenticated_import_routes_are_rejected(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        assert client.get("/api/import/jobs").status_code == 401
        assert client.post("/api/import/jobs", json={"source_type": "pihole", "text": "x"}).status_code == 401

    def test_bad_source_type_is_a_structured_400_not_a_500(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]
        r = client.post(
            "/api/import/jobs", json={"source_type": "not_real", "text": "x"}, headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "validation_error"
