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
import base64
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
from tests.v2._v1_fixture import build_v1_fixture

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

    def test_portable_backup_requires_correct_passphrase(self, live):
        backup_path = live["tmp_path"] / "portable.apdnsbak"
        br.create_appliance_backup(live["db_path"], live["secrets"], live["key"], backup_path, passphrase="correct passphrase")
        with pytest.raises(br.ApplianceBackupKeyError):
            br.validate_appliance_backup(backup_path, live["key"])
        with pytest.raises(br.ApplianceBackupKeyError):
            br.validate_appliance_backup(backup_path, live["key"], passphrase="wrong passphrase")
        manifest = br.validate_appliance_backup(backup_path, live["key"], passphrase="correct passphrase")
        assert manifest.key_mode == "passphrase"

    def test_hostile_kdf_iterations_are_rejected_before_decrypt(self, live):
        backup_path = live["tmp_path"] / "portable.apdnsbak"
        br.create_appliance_backup(live["db_path"], live["secrets"], live["key"], backup_path, passphrase="correct passphrase")
        payload = backup_path.read_bytes()
        header_raw, ciphertext = payload[len(br.FILE_MAGIC):].split(b"\n", 1)
        header = json.loads(header_raw.decode("utf-8"))
        header["iterations"] = br.PBKDF2_MAX_ITERATIONS + 1
        backup_path.write_bytes(br.FILE_MAGIC + json.dumps(header).encode("utf-8") + b"\n" + ciphertext)
        with pytest.raises(br.ApplianceBackupError):
            br.validate_appliance_backup(backup_path, live["key"], passphrase="correct passphrase")

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
        with pytest.raises(br.ApplianceRestoreError):
            br.stage_appliance_restore(backup_path, live["key"], staging)
        assert not (live["tmp_path"] / "tmp" / "apdns-escape-test.txt").exists()

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


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _v111_tar_gz_fixture(
    tmp_path: Path,
    db_path: Path,
    *,
    components: list[str] | None = None,
    extra_members: list[tarfile.TarInfo] | None = None,
    extra_payloads: dict[str, bytes] | None = None,
) -> Path:
    components = components or ["sqlite_data", "custom_rules", "client_aliases", "user_auth_data", "analytics_history"]
    extra_payloads = extra_payloads or {}
    checksums = {br.LEGACY_V1_DB_ARCHIVE_RELPATH: _sha256_file(db_path)}
    for name, payload in extra_payloads.items():
        checksums[name] = __import__("hashlib").sha256(payload).hexdigest()
    manifest = {
        "backup_format_version": 1,
        "alderpointdns_app_version": "1.1.1",
        "database_schema_version": "fixture-v1.1.1",
        "created_at": "2026-08-23T00:00:00+00:00",
        "source_node_id": "v1-fixture",
        "included_components": components,
        "sha256_checksums": checksums,
        "purpose": "manual",
        "purpose_metadata": {},
    }
    path = tmp_path / "alderpointdns-backup-20260823T000000Z.tar.gz"
    with tarfile.open(path, mode="w:gz") as tar:
        mbytes = json.dumps(manifest).encode("utf-8")
        minfo = tarfile.TarInfo("manifest.json")
        minfo.size = len(mbytes)
        tar.addfile(minfo, io.BytesIO(mbytes))
        tar.add(db_path, arcname=br.LEGACY_V1_DB_ARCHIVE_RELPATH)
        for name, payload in extra_payloads.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        for info in extra_members or []:
            tar.addfile(info)
    return path


class TestLegacyV111BackupCompatibility:
    def test_accepts_archive_created_by_released_v1_backup_module(self, tmp_path, monkeypatch):
        import app.backup as v1backup

        source_db = build_v1_fixture(tmp_path / "v1" / "alderpointdns.db")
        monkeypatch.setattr(v1backup, "DB_PATH", source_db)
        monkeypatch.setattr(v1backup, "DB_ARCHIVE_RELPATH", br.LEGACY_V1_DB_ARCHIVE_RELPATH)
        monkeypatch.setattr(v1backup, "BACKUP_DIR", tmp_path / "v1-backups")
        monkeypatch.setattr(v1backup, "STAGING_DIR", tmp_path / "v1-staging")
        components = {key: False for key in v1backup.COMPONENT_KEYS}
        components["sqlite_data"] = True

        archive = v1backup.create_backup(components)
        manifest = br.validate_legacy_v1_backup(archive)

        assert archive.name.endswith(".tar.gz")
        assert manifest.backup_format == "v1.1.1-tar.gz"
        assert manifest.source_version.startswith("1.1.1")

    def test_validates_released_v111_tar_gz_layout_by_content(self, tmp_path):
        source_db = build_v1_fixture(tmp_path / "v1" / "alderpointdns.db")
        archive = _v111_tar_gz_fixture(tmp_path, source_db)

        manifest = br.validate_legacy_v1_backup(archive)

        assert manifest.backup_format == "v1.1.1-tar.gz"
        assert manifest.product == br.LEGACY_V1_PRODUCT_ID
        assert manifest.source_version == "1.1.1"
        assert "configuration, admins, clients, local DNS, filtering, upstreams, notifications, analytics archive" in manifest.contents

    def test_v111_rejects_symlink_before_extracting(self, tmp_path):
        source_db = build_v1_fixture(tmp_path / "v1" / "alderpointdns.db")
        link = tarfile.TarInfo("var/lib/alderpointdns/compiled/bad-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive = _v111_tar_gz_fixture(tmp_path, source_db, extra_members=[link])

        with pytest.raises(br.ApplianceRestoreError, match="non-regular|special"):
            br.validate_legacy_v1_backup(archive)

    def test_v111_rejects_traversal_manifest_path(self, tmp_path):
        source_db = build_v1_fixture(tmp_path / "v1" / "alderpointdns.db")
        archive = _v111_tar_gz_fixture(tmp_path, source_db, extra_payloads={"../escape": b"bad"})

        with pytest.raises(br.ApplianceRestoreError):
            br.validate_legacy_v1_backup(archive)


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

    def test_portable_backup_upload_preview_restore_over_http(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        passphrase = "portable restore passphrase 2026"

        webapp_a = self._fresh_webapp(tmp_path / "a", monkeypatch)
        client_a = TestClient(webapp_a.app)
        client_a.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        login_a = client_a.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf_a = login_a.json()["csrf"]
        client_a.post("/api/local-dns", json={"name": "portable.lan", "record_type": "A", "value": "10.7.7.7", "ttl": 300}, headers={"X-CSRF-Token": csrf_a})
        created = client_a.post("/api/backup/appliance", json={"passphrase": passphrase}, headers={"X-CSRF-Token": csrf_a})
        assert created.status_code == 200, created.text
        assert created.json()["key_mode"] == "passphrase"
        backup_bytes = (tmp_path / "a" / "state" / "backups" / created.json()["name"]).read_bytes()

        webapp_b = self._fresh_webapp(tmp_path / "b", monkeypatch)
        client_b = TestClient(webapp_b.app)
        client_b.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        login_b = client_b.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf_b = login_b.json()["csrf"]
        assert client_b.get("/api/local-dns").json()["records"] == []

        upload = client_b.post(
            "/api/backup/appliance/upload",
            json={
                "filename": "fixture-a.apdnsbak",
                "data_base64": base64.b64encode(backup_bytes).decode("ascii"),
                "passphrase": passphrase,
            },
            headers={"X-CSRF-Token": csrf_b},
        )
        assert upload.status_code == 200, upload.text
        preview = upload.json()
        assert preview["backup_name"].startswith("uploaded-")
        assert preview["key_mode"] == "passphrase"
        assert "control_db" in preview["contents"]

        restored = client_b.post(
            f"/api/backup/appliance/{preview['backup_name']}/restore",
            json={"confirmation": preview["backup_name"], "passphrase": passphrase},
            headers={"X-CSRF-Token": csrf_b},
        )
        assert restored.status_code == 200, restored.text
        assert restored.json()["pre_restore_backup"].startswith("pre-restore-safety-")
        login_after_restore = client_b.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        assert login_after_restore.status_code == 200, login_after_restore.text
        records = client_b.get("/api/local-dns").json()["records"]
        assert {r["name"] for r in records} == {"portable.lan"}

    def test_upload_rejects_special_archive_entries_without_mutating_target(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        login = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = login.json()["csrf"]
        client.post("/api/local-dns", json={"name": "unchanged.lan", "record_type": "A", "value": "10.8.8.8", "ttl": 300}, headers={"X-CSRF-Token": csrf})

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            manifest = {
                "format_version": br.BACKUP_FORMAT_VERSION, "product": br.PRODUCT_ID, "created_at": "now", "source_version": "x",
                "control_db_schema_version": 1, "contents": [], "secret_count": 0, "cert_files": [], "raw_query_history_included": False,
            }
            mbytes = json.dumps(manifest).encode()
            info = tarfile.TarInfo(name=br.MANIFEST_NAME)
            info.size = len(mbytes)
            tar.addfile(info, io.BytesIO(mbytes))
            link = tarfile.TarInfo(name="certs/bad-link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
        fernet = Fernet(webapp._backup_key(webapp._secrets()))
        payload = fernet.encrypt(buf.getvalue())
        failed = client.post(
            "/api/backup/appliance/upload",
            json={"filename": "bad.apdnsbak", "data_base64": base64.b64encode(payload).decode("ascii")},
            headers={"X-CSRF-Token": csrf},
        )
        assert failed.status_code == 400
        assert failed.json()["error"] == "backup_invalid"
        records = client.get("/api/local-dns").json()["records"]
        assert {r["name"] for r in records} == {"unchanged.lan"}
        assert client.get("/api/backup/appliance").json()["backups"] == []

    def test_upload_previews_legacy_v111_tar_gz_backup(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        login = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = login.json()["csrf"]

        source_db = build_v1_fixture(tmp_path / "v1" / "alderpointdns.db")
        archive = _v111_tar_gz_fixture(tmp_path, source_db)
        upload = client.post(
            "/api/backup/appliance/upload",
            json={
                "filename": "alderpointdns-backup-20260823T000000Z.tar.gz",
                "data_base64": base64.b64encode(archive.read_bytes()).decode("ascii"),
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert upload.status_code == 200, upload.text
        payload = upload.json()
        assert payload["backup_format"] == "v1.1.1-tar.gz"
        assert payload["backup_name"].endswith(".tar.gz")
        assert payload["source_version"] == "1.1.1"
        assert payload["migration_preview"]["included_components"]

        listed = client.get("/api/backup/appliance").json()["backups"]
        assert [b for b in listed if b["name"] == payload["backup_name"]]

    def test_restore_legacy_v111_tar_gz_migrates_into_v2_control_db(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient
        from app.v2 import migration as mig

        monkeypatch.setitem(mig._STAGE_FUNCS, "health_check", lambda state: None)

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        login = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = login.json()["csrf"]

        source_db = build_v1_fixture(tmp_path / "v1" / "alderpointdns.db", upstream_protocol="plain", dot_enabled=False)
        archive = _v111_tar_gz_fixture(tmp_path, source_db)
        upload = client.post(
            "/api/backup/appliance/upload",
            json={
                "filename": "alderpointdns-backup-20260823T000000Z.tar.gz",
                "data_base64": base64.b64encode(archive.read_bytes()).decode("ascii"),
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert upload.status_code == 200, upload.text
        name = upload.json()["backup_name"]

        restored = client.post(
            f"/api/backup/appliance/{name}/restore",
            json={"confirmation": name},
            headers={"X-CSRF-Token": csrf},
        )
        assert restored.status_code == 200, restored.text
        assert restored.json()["backup_format"] == "v1.1.1-tar.gz"
        assert restored.json()["pre_restore_backup"].startswith("pre-restore-safety-")

        with control_db.connect(webapp.CONTROL_DB) as conn:
            local_names = {r[0] for r in conn.execute("SELECT name FROM local_dns_records").fetchall()}
            clients = {r[0] for r in conn.execute("SELECT name FROM clients").fetchall()}
        assert {"nas.lan", "printer.lan"} <= local_names
        assert "Kids Laptop" in clients

    def test_selective_v1_restore_only_blocklist_subscriptions(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        login = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = login.json()["csrf"]
        client.post("/api/local-dns", json={"name": "keep.lan", "record_type": "A", "value": "10.10.10.10", "ttl": 300}, headers={"X-CSRF-Token": csrf})

        source_db = build_v1_fixture(tmp_path / "v1" / "alderpointdns.db")
        archive = _v111_tar_gz_fixture(tmp_path, source_db)
        upload = client.post(
            "/api/backup/appliance/upload",
            json={"filename": "alderpointdns-backup-20260823T000000Z.tar.gz", "data_base64": base64.b64encode(archive.read_bytes()).decode("ascii")},
            headers={"X-CSRF-Token": csrf},
        )
        assert upload.status_code == 200, upload.text
        payload = upload.json()
        cats = {c["id"]: c for c in payload["inventory"]["categories"]}
        assert cats["blocklist_subscriptions"]["found_count"] == 1
        assert "app_config" not in json.dumps(payload["inventory"])

        restored = client.post(
            f"/api/backup/appliance/{payload['backup_name']}/restore",
            json={
                "confirmation": payload["backup_name"],
                "archive_digest": payload["inventory"]["archive_digest"],
                "selected_categories": ["blocklist_subscriptions"],
                "conflict_policy": "merge",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert restored.status_code == 200, restored.text

        local_records = client.get("/api/local-dns").json()["records"]
        assert {r["name"] for r in local_records} == {"keep.lan"}
        blocklists = client.get("/api/blocklists").json()["subscriptions"]
        assert {b["name"] for b in blocklists} == {"StevenBlack"}

    def test_selective_v1_restore_only_local_dns_keeps_clients_unchanged(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        login = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = login.json()["csrf"]
        client.post("/api/clients", json={"name": "Existing Client", "identifiers": [{"kind": "ipv4", "value": "10.20.30.40"}]}, headers={"X-CSRF-Token": csrf})

        source_db = build_v1_fixture(tmp_path / "v1" / "alderpointdns.db")
        archive = _v111_tar_gz_fixture(tmp_path, source_db)
        upload = client.post(
            "/api/backup/appliance/upload",
            json={"filename": "alderpointdns-backup-20260823T000000Z.tar.gz", "data_base64": base64.b64encode(archive.read_bytes()).decode("ascii")},
            headers={"X-CSRF-Token": csrf},
        )
        payload = upload.json()
        restored = client.post(
            f"/api/backup/appliance/{payload['backup_name']}/restore",
            json={
                "confirmation": payload["backup_name"],
                "archive_digest": payload["inventory"]["archive_digest"],
                "selected_categories": ["local_dns"],
                "conflict_policy": "merge",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert restored.status_code == 200, restored.text
        records = client.get("/api/local-dns").json()["records"]
        assert {"nas.lan", "printer.lan"} <= {r["name"] for r in records}
        clients = client.get("/api/clients").json()["clients"]
        assert {c["name"] for c in clients} == {"Existing Client"}

    def test_selective_v2_restore_only_local_dns_keeps_clients_unchanged(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        login = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = login.json()["csrf"]
        client.post("/api/local-dns", json={"name": "backup-only.lan", "record_type": "A", "value": "10.30.30.1", "ttl": 300}, headers={"X-CSRF-Token": csrf})
        with control_db.connect(webapp.CONTROL_DB) as conn:
            cur = conn.execute(
                "INSERT INTO clients (name, description, enabled, created_at, updated_at) VALUES ('Client At Backup', '', 1, 'now', 'now')"
            )
            conn.execute(
                "INSERT INTO client_identifiers (client_id, kind, value, created_at) VALUES (?, 'ipv4', '10.30.30.30', 'now')",
                (cur.lastrowid,),
            )

        created = client.post("/api/backup/appliance", headers={"X-CSRF-Token": csrf})
        assert created.status_code == 200, created.text
        name = created.json()["name"]

        client.post("/api/local-dns", json={"name": "after-backup.lan", "record_type": "A", "value": "10.30.30.2", "ttl": 300}, headers={"X-CSRF-Token": csrf})
        with control_db.connect(webapp.CONTROL_DB) as conn:
            conn.execute("UPDATE clients SET name='Client After Backup'")

        preview = client.post(f"/api/backup/appliance/{name}/validate", headers={"X-CSRF-Token": csrf})
        assert preview.status_code == 200, preview.text
        inv = preview.json()["inventory"]
        restored = client.post(
            f"/api/backup/appliance/{name}/restore",
            json={
                "confirmation": name,
                "archive_digest": inv["archive_digest"],
                "selected_categories": ["local_dns"],
                "conflict_policy": "merge",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert restored.status_code == 200, restored.text
        records = client.get("/api/local-dns").json()["records"]
        assert {r["name"] for r in records} == {"backup-only.lan"}
        with control_db.connect(webapp.CONTROL_DB) as conn:
            clients_after = {r[0] for r in conn.execute("SELECT name FROM clients").fetchall()}
        assert clients_after == {"Client After Backup"}

    def test_runtime_promotion_failure_rolls_back_restored_control_state(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12", "create_local_dns": False})
        login = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = login.json()["csrf"]
        client.post("/api/local-dns", json={"name": "backup-state.lan", "record_type": "A", "value": "10.9.9.9", "ttl": 300}, headers={"X-CSRF-Token": csrf})
        created = client.post("/api/backup/appliance", headers={"X-CSRF-Token": csrf})
        name = created.json()["name"]
        client.post("/api/local-dns", json={"name": "pre-restore-live.lan", "record_type": "A", "value": "10.9.9.10", "ttl": 300}, headers={"X-CSRF-Token": csrf})

        def fail_promote(_mutator):
            raise RuntimeError("forced runtime promotion failure")

        monkeypatch.setattr(webapp, "_mutate_and_promote", fail_promote)
        failed = client.post(
            f"/api/backup/appliance/{name}/restore",
            json={"confirmation": name},
            headers={"X-CSRF-Token": csrf},
        )
        assert failed.status_code == 400
        assert failed.json()["error"] == "restore_failed"
        records = client.get("/api/local-dns").json()["records"]
        assert {r["name"] for r in records} == {"backup-state.lan", "pre-restore-live.lan"}
