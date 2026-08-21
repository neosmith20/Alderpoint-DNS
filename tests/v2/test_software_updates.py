"""Tests for app/v2/software_updates.py and scripts/v2/
alderpointdns_v2_update_apply.py (beta-rescue priority 4).

V2 is private -- there is no real public release channel to test against
-- so all channel/feed coverage here uses deterministic, private test
fixtures (a fake metadata.json feed, real-but-synthetic .deb packages
built with the actually-installed dpkg-deb), per the beta-rescue brief's
explicit instruction. The privileged apply helper's own OS-mutating step
(apt-get install) is dependency-injected in tests, matching V1's existing
``run()``-mocking convention -- this suite never actually installs a
package into the test host.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app.v2 import software_updates as su

DPKG_DEB_INSTALLED = shutil.which("dpkg-deb") is not None


def _build_deb(tmp_path: Path, *, package: str, version: str, arch: str, name: str = "pkg") -> Path:
    root = tmp_path / f"{name}-root"
    (root / "DEBIAN").mkdir(parents=True)
    control = f"Package: {package}\nVersion: {version}\nArchitecture: {arch}\nMaintainer: test\nDescription: test package\n"
    (root / "DEBIAN" / "control").write_text(control)
    out = tmp_path / f"{name}.deb"
    subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(root), str(out)], check=True, capture_output=True)
    return out


@pytest.mark.skipif(not DPKG_DEB_INSTALLED, reason="requires dpkg-deb")
class TestValidateCandidatePackage:
    def test_accepts_a_real_newer_amd64_package(self, tmp_path):
        deb = _build_deb(tmp_path, package="alderpointdns-v2", version="2.0.0~rc44-1", arch="amd64")
        result = su.validate_candidate_package(deb, "2.0.0~rc43-1")
        assert result.candidate_version == "2.0.0~rc44-1"
        assert len(result.sha256) == 64

    def test_rejects_wrong_package_name(self, tmp_path):
        deb = _build_deb(tmp_path, package="some-other-package", version="9.9.9-1", arch="amd64")
        with pytest.raises(su.SoftwareUpdateError, match="package name mismatch"):
            su.validate_candidate_package(deb, "2.0.0~rc43-1")

    def test_rejects_non_amd64_architecture(self, tmp_path):
        deb = _build_deb(tmp_path, package="alderpointdns-v2", version="2.0.0~rc44-1", arch="all")
        with pytest.raises(su.SoftwareUpdateError, match="architecture"):
            su.validate_candidate_package(deb, "2.0.0~rc43-1")

    def test_rejects_same_version_as_installed(self, tmp_path):
        deb = _build_deb(tmp_path, package="alderpointdns-v2", version="2.0.0~rc43-1", arch="amd64")
        with pytest.raises(su.SoftwareUpdateError, match="same as the installed version"):
            su.validate_candidate_package(deb, "2.0.0~rc43-1")

    def test_rejects_downgrade(self, tmp_path):
        deb = _build_deb(tmp_path, package="alderpointdns-v2", version="2.0.0~rc40-1", arch="amd64")
        with pytest.raises(su.SoftwareUpdateError, match="not newer"):
            su.validate_candidate_package(deb, "2.0.0~rc43-1")

    def test_unmanaged_install_skips_version_gate(self, tmp_path):
        deb = _build_deb(tmp_path, package="alderpointdns-v2", version="2.0.0~rc1-1", arch="amd64")
        result = su.validate_candidate_package(deb, None)
        assert result.candidate_version == "2.0.0~rc1-1"


class TestPrivateFeed:
    def test_no_feed_configured_reports_no_public_release(self):
        result = su.check_private_feed(None)
        assert result["public_release_available"] is False
        assert result["feed_configured"] is False
        assert "private" in result["message"].lower()

    def test_configured_but_empty_feed_dir(self, tmp_path):
        feed_dir = tmp_path / "feed"
        feed_dir.mkdir()
        result = su.check_private_feed(feed_dir)
        assert result["feed_configured"] is True
        assert result["public_release_available"] is False

    def test_configured_feed_with_real_metadata(self, tmp_path):
        feed_dir = tmp_path / "feed"
        feed_dir.mkdir()
        (feed_dir / "metadata.json").write_text(json.dumps({
            "version": "2.0.0~rc44-1", "deb_filename": "alderpointdns-v2_2.0.0~rc44-1_amd64.deb", "sha256": "a" * 64,
        }))
        result = su.check_private_feed(feed_dir)
        assert result["public_release_available"] is True
        assert result["candidate"]["version"] == "2.0.0~rc44-1"

    def test_malformed_metadata_is_a_clean_error(self, tmp_path):
        feed_dir = tmp_path / "feed"
        feed_dir.mkdir()
        (feed_dir / "metadata.json").write_text("not json")
        with pytest.raises(su.SoftwareUpdateError):
            su.check_private_feed(feed_dir)


@pytest.mark.skipif(not DPKG_DEB_INSTALLED, reason="requires dpkg-deb")
class TestStageAndRequestApply:
    def test_stage_and_request_apply_writes_expected_files(self, tmp_path):
        deb = _build_deb(tmp_path, package="alderpointdns-v2", version="2.0.0~rc44-1", arch="amd64")
        validated = su.validate_candidate_package(deb, "2.0.0~rc43-1")
        update_dir = tmp_path / "updates"
        staged = su.stage_for_apply(update_dir, deb, validated)
        assert staged.exists()
        assert su.sha256_file(staged) == validated.sha256

        marker_path = su.request_apply(update_dir, 42, validated)
        marker = json.loads(marker_path.read_text())
        assert marker["job_id"] == 42
        assert marker["sha256"] == validated.sha256

        assert su.read_apply_result(update_dir, 42) is None  # helper hasn't run yet


class TestUpdateApplyHelper:
    """Real logic of the privileged helper script, with the actual
    apt-get invocation dependency-injected (this suite never installs
    anything into the test host)."""

    def _import_helper(self):
        import importlib.util

        path = Path(__file__).resolve().parents[2] / "scripts" / "v2" / "alderpointdns_v2_update_apply.py"
        spec = importlib.util.spec_from_file_location("apdns_v2_update_apply", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_no_marker_is_a_clean_noop(self, tmp_path):
        helper = self._import_helper()
        rc = helper.main(tmp_path)
        assert rc == 0
        assert not (tmp_path / "result-1.json").exists()

    def test_successful_install_writes_succeeded_result_and_removes_marker(self, tmp_path):
        helper = self._import_helper()
        tmp_path.mkdir(exist_ok=True)
        staged = tmp_path / helper.STAGED_DEB_NAME
        staged.write_bytes(b"fake deb contents")
        sha = helper.sha256_file(staged)
        marker = tmp_path / helper.APPLY_MARKER_NAME
        marker.write_text(json.dumps({"job_id": 7, "sha256": sha}))

        calls = []

        class FakeProc:
            returncode = 0
            stdout = "Setting up alderpointdns-v2 ...\n"
            stderr = ""

        def fake_install(path):
            calls.append(path)
            return FakeProc()

        rc = helper.main(tmp_path, install_fn=fake_install)
        assert rc == 0
        assert calls == [staged]
        assert not marker.exists()
        result = json.loads((tmp_path / "result-7.json").read_text())
        assert result["status"] == "succeeded"

    def test_failed_install_writes_failed_result(self, tmp_path):
        helper = self._import_helper()
        tmp_path.mkdir(exist_ok=True)
        staged = tmp_path / helper.STAGED_DEB_NAME
        staged.write_bytes(b"fake deb contents")
        sha = helper.sha256_file(staged)
        marker = tmp_path / helper.APPLY_MARKER_NAME
        marker.write_text(json.dumps({"job_id": 8, "sha256": sha}))

        class FakeProc:
            returncode = 1
            stdout = "dpkg: error processing package\n"
            stderr = ""

        rc = helper.main(tmp_path, install_fn=lambda path: FakeProc())
        assert rc == 1
        assert not marker.exists()
        result = json.loads((tmp_path / "result-8.json").read_text())
        assert result["status"] == "failed"

    def test_checksum_mismatch_refuses_to_install_and_fails_closed(self, tmp_path):
        """Real defect class this guards against: the staged file
        changing (corrupted, replaced, tampered with) between web-app
        validation and the privileged helper actually running -- must
        never be installed, ever, regardless of what the marker claims."""
        helper = self._import_helper()
        tmp_path.mkdir(exist_ok=True)
        staged = tmp_path / helper.STAGED_DEB_NAME
        staged.write_bytes(b"fake deb contents")
        marker = tmp_path / helper.APPLY_MARKER_NAME
        marker.write_text(json.dumps({"job_id": 9, "sha256": "0" * 64}))  # wrong checksum

        calls = []
        rc = helper.main(tmp_path, install_fn=lambda path: calls.append(path))
        assert rc == 1
        assert calls == []  # installer never invoked
        assert not marker.exists()
        result = json.loads((tmp_path / "result-9.json").read_text())
        assert result["status"] == "failed"
        assert "checksum" in result["error"]

    def test_missing_staged_file_fails_closed(self, tmp_path):
        helper = self._import_helper()
        tmp_path.mkdir(exist_ok=True)
        marker = tmp_path / helper.APPLY_MARKER_NAME
        marker.write_text(json.dumps({"job_id": 10, "sha256": "a" * 64}))
        rc = helper.main(tmp_path, install_fn=lambda path: (_ for _ in ()).throw(AssertionError("must not be called")))
        assert rc == 1
        result = json.loads((tmp_path / "result-10.json").read_text())
        assert "missing" in result["error"]


@pytest.mark.skipif(not DPKG_DEB_INSTALLED, reason="requires dpkg-deb")
class TestSoftwareUpdatesApiRoutes:
    def _fresh_webapp(self, tmp_path, monkeypatch):
        import importlib
        import sys

        from app.v2 import control_db, policy_store

        monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
        monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
        (tmp_path / "state").mkdir(parents=True, exist_ok=True)
        (tmp_path / "opt").mkdir(parents=True, exist_ok=True)
        (tmp_path / "opt" / "VERSION").write_text("2.0.0~rc44\n")
        control_db.initialize(tmp_path / "state" / "control.db")
        policy_store.ensure_schema(tmp_path / "state" / "control.db")
        sys.modules.pop("app.v2.webapp", None)
        return importlib.import_module("app.v2.webapp")

    def test_status_reports_no_public_release_by_default(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        r = client.get("/api/updates/status")
        assert r.status_code == 200
        body = r.json()
        assert body["channel"] == "private"
        assert body["public_release_available"] is False
        assert body["installed_source_version"] == "2.0.0~rc44"

    def test_upload_validate_and_apply_request_over_http(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]

        deb = _build_deb(tmp_path, package="alderpointdns-v2", version="2.0.0~rc45-1", arch="amd64")
        import base64

        payload = {"filename": deb.name, "data_base64": base64.b64encode(deb.read_bytes()).decode("ascii")}
        r = client.post("/api/updates/upload", json=payload, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200, r.text
        job_id = r.json()["job_id"]
        assert r.json()["candidate_version"] == "2.0.0~rc45-1"

        jobs = client.get("/api/updates/jobs").json()["jobs"]
        assert jobs[0]["status"] == "staged"

        applied = client.post(f"/api/updates/jobs/{job_id}/apply", headers={"X-CSRF-Token": csrf})
        assert applied.status_code == 200, applied.text
        assert applied.json()["status"] == "apply_requested"

        jobs_after = client.get("/api/updates/jobs").json()["jobs"]
        assert jobs_after[0]["status"] == "apply_requested"

        marker = tmp_path / "state" / "updates" / "apply-requested.json"
        assert marker.exists()
        marker_data = json.loads(marker.read_text())
        assert marker_data["job_id"] == job_id

    def test_reject_wrong_package_name_upload(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]
        deb = _build_deb(tmp_path, package="not-alderpointdns", version="1-1", arch="amd64")
        import base64

        payload = {"filename": deb.name, "data_base64": base64.b64encode(deb.read_bytes()).decode("ascii")}
        r = client.post("/api/updates/upload", json=payload, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 400
        assert r.json()["error"] == "package_invalid"

    def test_private_feed_settings_round_trip(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        csrf = r.json()["csrf"]

        feed_dir = tmp_path / "myfeed"
        feed_dir.mkdir()
        (feed_dir / "metadata.json").write_text(json.dumps({"version": "9.9.9-1", "deb_filename": "x.deb", "sha256": "a" * 64}))

        r = client.put("/api/updates/settings", json={"private_feed_dir": str(feed_dir)}, headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200

        status = client.get("/api/updates/status").json()
        assert status["public_release_available"] is True
        assert status["candidate"]["version"] == "9.9.9-1"

    def test_unauthenticated_routes_are_rejected(self, tmp_path, monkeypatch):
        from fastapi.testclient import TestClient

        webapp = self._fresh_webapp(tmp_path, monkeypatch)
        client = TestClient(webapp.app)
        assert client.get("/api/updates/status").status_code == 401
        assert client.get("/api/updates/jobs").status_code == 401


def test_privileged_apply_helper_is_wired_into_packaging():
    root = Path(__file__).resolve().parents[2]
    unit = root / "packaging/v2/alderpointdns-v2-update-apply.service"
    path_unit = root / "packaging/v2/alderpointdns-v2-update-apply.path"
    assert unit.exists()
    assert path_unit.exists()
    assert "alderpointdns_v2_update_apply.py" in unit.read_text()
    assert "apply-requested.json" in path_unit.read_text()
    assert "alderpointdns-v2-update-apply.service" in path_unit.read_text()

    build_script = (root / "scripts/build-v2-deb.sh").read_text()
    assert "alderpointdns-v2-update-apply.service" in build_script
    assert "alderpointdns-v2-update-apply.path" in build_script
    assert "alderpointdns_v2_update_apply.py" in build_script

    postinst = (root / "packaging/v2/postinst").read_text()
    assert "alderpointdns-v2-update-apply.path" in postinst
    prerm = (root / "packaging/v2/prerm").read_text()
    assert "alderpointdns-v2-update-apply.path" in prerm
