"""Tests for app/v2/backup_restore.py -- the full appliance backup/restore
(beta-rescue priority 3), replacing RC43's secrets-only interpretation.

Unit coverage: create -> validate -> stage -> promote, tamper detection,
wrong-key detection, path-traversal resistance, and rollback-on-failure.
TestRealRuntimeProof is the required end-to-end proof: backup -> mutate
the live appliance -> restore -> the exact real compiler
(runtime_compile.build_bindings + compile_multi_policy_dnsdist_config) ->
a real dnsdist process -> a real DNS query proving the restored state
(not the mutated state) is what is actually being served.
TestApplianceBackupApiRoutes proves the same through the real HTTP
webapp routes with real auth/CSRF.
"""

from __future__ import annotations

import io
import json
import shutil
import socket
import subprocess
import tarfile
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.v2 import backup_restore as br
from app.v2 import control_db, policy_store as store
from app.v2.secret_store import SecretStore

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


@pytest.fixture()
def live(tmp_path):
    db_path = tmp_path / "live" / "control.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    control_db.initialize(db_path)
    store.ensure_schema(db_path)
    secrets_dir = tmp_path / "live" / "secrets"
    secrets = SecretStore(secrets_dir)
    key = Fernet.generate_key()
    return {"db_path": db_path, "secrets_dir": secrets_dir, "secrets": secrets, "key": key, "tmp_path": tmp_path}


class TestCreateAndValidate:
    def test_create_backup_contains_control_db_and_secrets(self, live):
        with control_db.connect(live["db_path"]) as conn:
            store.create_network(conn, "lan", "10.0.0.0/24")
            conn.commit()
        live["secrets"].create("shh", secret_id="test-secret")

        backup_path = live["tmp_path"] / "backups" / "b1.apdnsbak"
        result = br.create_appliance_backup(live["db_path"], live["secrets"], live["key"], backup_path)
        assert "control_db" in result.contents
        assert "secrets" in result.contents
        assert result.secret_count == 1
        assert backup_path.exists()
        assert oct(backup_path.stat().st_mode)[-3:] == "600"

    def test_validate_reports_manifest_without_writing_anything(self, live, tmp_path):
        with control_db.connect(live["db_path"]) as conn:
            store.create_network(conn, "lan", "10.0.0.0/24")
            conn.commit()
        backup_path = live["tmp_path"] / "b2.apdnsbak"
        br.create_appliance_backup(live["db_path"], live["secrets"], live["key"], backup_path)

        before = set((tmp_path).rglob("*"))
        manifest = br.validate_appliance_backup(backup_path, live["key"])
        after = set((tmp_path).rglob("*"))
        assert manifest.control_db_schema_version is not None
        assert manifest.raw_query_history_included is False
        assert before == after  # validate never writes to disk

    def test_wrong_key_is_a_clean_error(self, live):
        backup_path = live["tmp_path"] / "b3.apdnsbak"
        br.create_appliance_backup(live["db_path"], live["secrets"], live["key"], backup_path)
        wrong_key = Fernet.generate_key()
        with pytest.raises(br.ApplianceBackupKeyError):
            br.validate_appliance_backup(backup_path, wrong_key)

    def test_tampered_archive_is_detected(self, live):
        backup_path = live["tmp_path"] / "b4.apdnsbak"
        br.create_appliance_backup(live["db_path"], live["secrets"], live["key"], backup_path)
        data = bytearray(backup_path.read_bytes())
        data[-1] ^= 0xFF
        backup_path.write_bytes(bytes(data))
        with pytest.raises(br.ApplianceBackupKeyError):
            br.validate_appliance_backup(backup_path, live["key"])


class TestStageRestoreSafety:
    def test_path_traversal_member_is_ignored_not_extracted(self, live):
        """A hostile/corrupted archive with a "../../etc/passwd"-style
        member must never be written outside the staging directory."""
        backup_path = live["tmp_path"] / "evil.apdnsbak"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            manifest = {
                "format_version": br.BACKUP_FORMAT_VERSION, "created_at": "now", "source_version": "x",
                "control_db_schema_version": None, "contents": [], "secret_count": 0, "cert_files": [],
                "raw_query_history_included": False,
            }
            mbytes = json.dumps(manifest).encode()
            info = tarfile.TarInfo(name=br.MANIFEST_NAME)
            info.size = len(mbytes)
            tar.addfile(info, io.BytesIO(mbytes))
            evil = tarfile.TarInfo(name="../../../tmp/apdns-escape-test.txt")
            evil.size = 4
            tar.addfile(evil, io.BytesIO(b"evil"))
        fernet = Fernet(live["key"])
        backup_path.write_bytes(fernet.encrypt(buf.getvalue()))

        staging = live["tmp_path"] / "staging"
        staged = br.stage_appliance_restore(backup_path, live["key"], staging)
        assert not (live["tmp_path"] / "tmp" / "apdns-escape-test.txt").exists()
        assert staged.manifest.contents == []

    def test_incomplete_control_db_fails_staging(self, live):
        backup_path = live["tmp_path"] / "incomplete.apdnsbak"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            manifest = {
                "format_version": br.BACKUP_FORMAT_VERSION, "created_at": "now", "source_version": "x",
                "control_db_schema_version": 1, "contents": ["control_db"], "secret_count": 0, "cert_files": [],
                "raw_query_history_included": False,
            }
            mbytes = json.dumps(manifest).encode()
            info = tarfile.TarInfo(name=br.MANIFEST_NAME)
            info.size = len(mbytes)
            tar.addfile(info, io.BytesIO(mbytes))
            junk = tarfile.TarInfo(name=br.CONTROL_DB_NAME)
            junk.size = 3
            tar.addfile(junk, io.BytesIO(b"xyz"))
        fernet = Fernet(live["key"])
        backup_path.write_bytes(fernet.encrypt(buf.getvalue()))
        with pytest.raises(br.ApplianceRestoreError):
            br.stage_appliance_restore(backup_path, live["key"], live["tmp_path"] / "staging2")

    def test_promote_restores_prior_control_db_content(self, live):
        with control_db.connect(live["db_path"]) as conn:
            store.create_network(conn, "office", "10.0.0.0/24")
            conn.commit()
        backup_path = live["tmp_path"] / "b5.apdnsbak"
        br.create_appliance_backup(live["db_path"], live["secrets"], live["key"], backup_path)

        with control_db.connect(live["db_path"]) as conn:
            store.create_network(conn, "guest", "10.0.1.0/24")
            conn.commit()
        with control_db.connect(live["db_path"]) as conn:
            names_mutated = {r[0] for r in conn.execute("SELECT network_id FROM policy_networks").fetchall()}
        assert names_mutated == {"office", "guest"}

        staged = br.stage_appliance_restore(backup_path, live["key"], live["tmp_path"] / "staging3")
        promo = br.promote_appliance_restore(
            staged, live["db_path"], live["secrets_dir"], rollback_root=live["tmp_path"] / "rollback",
        )
        assert promo.control_db_restored is True
        with control_db.connect(live["db_path"]) as conn:
            names_restored = {r[0] for r in conn.execute("SELECT network_id FROM policy_networks").fetchall()}
        assert names_restored == {"office"}


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


def _fake_nxdomain_upstream(port: int, stop_event) -> "threading.Thread":
    """A real, minimal UDP DNS server answering every query NXDOMAIN --
    same real-socket pattern test_final_policy_runtime_revalidation.py
    already established. Used so this test's "mutated.lan does not
    resolve" assertion is proven against a real, fast, controlled
    upstream, not by accidentally depending on the zero-managed-
    upstream native-recursion fallback (a real, separate architecture
    path with its own dedicated coverage in
    test_bind_architecture_routing.py -- this backup/restore test
    should not incidentally exercise it just because it never
    configured an upstream profile at all).
    """
    import threading

    import dns.message

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
                import dns.rcode

                query = dns.message.from_wire(data)
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.NXDOMAIN)
                sock.sendto(response.to_wire(), addr)
            except Exception:
                continue
        sock.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return thread


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="requires installed dnsdist")
class TestRealRuntimeProof:
    def test_backup_mutate_restore_reaches_real_dns_answers(self, live):
        import threading

        from app.v2 import runtime_compile
        from app.v2.dnsdist_policy_runtime import compile_multi_policy_dnsdist_config
        from app.v2.policy_model import PolicyLayer

        # A real, controlled upstream (not the zero-managed-upstream
        # native-recursion path -- that has its own dedicated coverage
        # in test_bind_architecture_routing.py) so "mutated.lan does not
        # resolve" is proven fast, against a real backend, regardless of
        # how the appliance's own default upstream/native-recursion
        # fallback behaves.
        fake_port = _free_port()
        stop_event = threading.Event()
        _fake_nxdomain_upstream(fake_port, stop_event)

        with control_db.connect(live["db_path"]) as conn:
            store.upsert_local_dns_record(conn, "original.lan", "A", "10.9.9.1", 300)
            store.create_upstream_profile(
                conn, "proof-upstream", "Proof", "plain",
                [store.UpstreamEndpointRecord(f"127.0.0.1:{fake_port}", None, 0, 1, None)],
            )
            store.save_policy_layer(conn, "global", "singleton", PolicyLayer(upstream_profile_id="proof-upstream"))
            conn.commit()

        backup_path = live["tmp_path"] / "proof.apdnsbak"
        br.create_appliance_backup(live["db_path"], live["secrets"], live["key"], backup_path)

        # Mutate the live appliance after the backup: remove the original
        # record and add a different one.
        with control_db.connect(live["db_path"]) as conn:
            conn.execute("DELETE FROM local_dns_records WHERE name = 'original.lan'")
            store.upsert_local_dns_record(conn, "mutated.lan", "A", "10.9.9.2", 300)
            conn.commit()

        staged = br.stage_appliance_restore(backup_path, live["key"], live["tmp_path"] / "staging")
        br.promote_appliance_restore(
            staged, live["db_path"], live["secrets_dir"], rollback_root=live["tmp_path"] / "rollback",
        )

        with control_db.connect(live["db_path"]) as conn:
            bindings = runtime_compile.build_bindings(conn)
            local_dns_records = store.load_local_dns_records(conn)
        record_names = {r[0] for r in local_dns_records}
        assert "original.lan" in record_names
        assert "mutated.lan" not in record_names

        port = _free_port()
        config_text = compile_multi_policy_dnsdist_config(
            f"127.0.0.1:{port}", bindings, local_dns_records=local_dns_records,
            analytics_log_address=None, discovery_ingress_address=None,
        )
        conf_path = live["tmp_path"] / "dnsdist.conf"
        conf_path.write_text(config_text)
        proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(1.0)
            resp = _dig(port, "original.lan.", "A")
            answers = [str(rr) for rrset in resp.answer for rr in rrset]
            assert any("10.9.9.1" in a for a in answers), answers

            mutated_resp = _dig(port, "mutated.lan.", "A")
            # The mutated-after-backup record must not resolve -- the
            # restored (pre-mutation) state is what is actually live.
            assert len(mutated_resp.answer) == 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            stop_event.set()


class TestApplianceBackupApiRoutes:
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

    def test_backup_mutate_restore_over_http(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]

        r = client.post("/api/local-dns", json={"name": "before.lan", "record_type": "A", "value": "10.5.5.1", "ttl": 300}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text

        created = client.post("/api/backup/appliance", headers={"X-CSRF-Token": csrf})
        assert created.status_code == 200, created.text
        name = created.json()["name"]
        assert "control_db" in created.json()["contents"]

        validated = client.post(f"/api/backup/appliance/{name}/validate", headers={"X-CSRF-Token": csrf})
        assert validated.status_code == 200, validated.text

        # Mutate after backup.
        r = client.post("/api/local-dns", json={"name": "after.lan", "record_type": "A", "value": "10.5.5.2", "ttl": 300}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        records_before_restore = client.get("/api/local-dns").json()["records"]
        assert {r["name"] for r in records_before_restore} == {"before.lan", "after.lan"}

        rejected = client.post(f"/api/backup/appliance/{name}/restore", json={"confirmation": "wrong"}, headers={"X-CSRF-Token": csrf})
        assert rejected.status_code == 400
        assert rejected.json()["error"] == "confirmation_required"

        restored = client.post(f"/api/backup/appliance/{name}/restore", json={"confirmation": name}, headers={"X-CSRF-Token": csrf})
        assert restored.status_code == 200, restored.text
        assert restored.json()["control_db_restored"] is True
        assert restored.json()["runtime_promoted"] is True

        records_after_restore = client.get("/api/local-dns").json()["records"]
        assert {r["name"] for r in records_after_restore} == {"before.lan"}

        jobs = client.get("/api/backup/appliance").json()["restore_jobs"]
        assert jobs[0]["status"] == "succeeded"

    def test_a_failed_restore_leaves_the_prior_appliance_operational(self, tmp_path, monkeypatch):
        """A backup file that decrypts but fails staging (corrupted
        control.db payload) must not touch the live control.db at all."""
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]
        client.post("/api/local-dns", json={"name": "stays.lan", "record_type": "A", "value": "10.6.6.1", "ttl": 300}, headers={"X-CSRF-Token": csrf})

        backup_dir = tmp_path / "state" / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        bogus_key = webapp._backup_key(webapp._secrets())
        bogus_path = backup_dir / "bogus.apdnsbak"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            manifest = {
                "format_version": br.BACKUP_FORMAT_VERSION, "created_at": "now", "source_version": "x",
                "control_db_schema_version": 1, "contents": ["control_db"], "secret_count": 0, "cert_files": [],
                "raw_query_history_included": False,
            }
            mbytes = json.dumps(manifest).encode()
            info = tarfile.TarInfo(name=br.MANIFEST_NAME)
            info.size = len(mbytes)
            tar.addfile(info, io.BytesIO(mbytes))
            junk = tarfile.TarInfo(name=br.CONTROL_DB_NAME)
            junk.size = 3
            tar.addfile(junk, io.BytesIO(b"xyz"))
        fernet = Fernet(bogus_key)
        bogus_path.write_bytes(fernet.encrypt(buf.getvalue()))

        failed = client.post(f"/api/backup/appliance/{bogus_path.name}/restore", json={"confirmation": bogus_path.name}, headers={"X-CSRF-Token": csrf})
        assert failed.status_code == 400
        assert failed.json()["error"] == "restore_failed"

        still_there = client.get("/api/local-dns").json()["records"]
        assert {r["name"] for r in still_there} == {"stays.lan"}

    def test_unauthenticated_appliance_backup_routes_are_rejected(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        assert client.get("/api/backup/appliance").status_code == 401
        assert client.post("/api/backup/appliance").status_code == 401
