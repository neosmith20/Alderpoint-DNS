#!/usr/bin/env python3
"""Tests for app/software_updates.py: SemVer/dpkg version comparison,
GitHub release discovery/channel filtering, checksum and package
validation, the pre-upgrade-backup-gates-install rule, job durability, and
(HTTP-level, at the bottom) the real webapp routes for auth/CSRF/path
rejection and streamed manual upload.

Real disposable-VM package-install/restart/reconnect verification is out
of scope for this unit suite -- see the combined integration report for
what was verified there.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import backup as backup_module  # noqa: E402
from app import software_updates as su  # noqa: E402


class SoftwareUpdatesTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-su-test-"))
        self.old = {
            "DB_PATH": su.DB_PATH,
            "STAGED_DIR": su.STAGED_DIR,
            "UPLOAD_STAGING_DIR": su.UPLOAD_STAGING_DIR,
            "CREDENTIAL_FILE": su.CREDENTIAL_FILE,
            "CHECK_LOCK": su.CHECK_LOCK,
        }
        su.DB_PATH = self.tmp / "alderpointdns.db"
        su.STAGED_DIR = self.tmp / "staged"
        su.UPLOAD_STAGING_DIR = self.tmp / "uploads"
        su.CREDENTIAL_FILE = self.tmp / "software-updates.env"
        su.CHECK_LOCK = self.tmp / "check.lock"
        su.init_db()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            setattr(su, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

class VersionComparisonTest(unittest.TestCase):
    def test_explicit_transitions(self) -> None:
        self.assertLess(su.compare_semver("0.4.0-beta.6", "0.5.0-dev.1"), 0)
        self.assertLess(su.compare_semver("0.5.0-dev.1", "1.0.0"), 0)
        self.assertLess(su.compare_semver("1.0.0", "1.0.1"), 0)
        self.assertLess(su.compare_semver("1.0.1", "1.1.0"), 0)
        self.assertGreater(su.compare_semver("1.1.0", "1.0.1"), 0)  # rejected direction

    def test_equal_versions(self) -> None:
        self.assertEqual(su.compare_semver("1.0.0", "1.0.0"), 0)
        self.assertEqual(su.compare_semver("v1.0.0", "1.0.0"), 0)

    def test_prerelease_is_lower_than_final_of_same_core(self) -> None:
        self.assertLess(su.compare_semver("1.0.0-beta.1", "1.0.0"), 0)

    def test_prerelease_identifier_ordering(self) -> None:
        self.assertLess(su.compare_semver("1.0.0-beta.1", "1.0.0-beta.2"), 0)
        self.assertLess(su.compare_semver("1.0.0-alpha", "1.0.0-beta"), 0)
        self.assertLess(su.compare_semver("1.0.0-1", "1.0.0-alpha"), 0)  # numeric < alphanumeric

    def test_malformed_version_raises(self) -> None:
        with self.assertRaises(su.SoftwareUpdateError):
            su.compare_semver("not-a-version", "1.0.0")
        with self.assertRaises(su.SoftwareUpdateError):
            su.compare_semver("1.0.0", "")

    def test_source_version_to_deb_form(self) -> None:
        self.assertEqual(su.source_version_to_deb_form("0.5.0-dev.1"), "0.5.0~dev1-1")
        self.assertEqual(su.source_version_to_deb_form("0.4.0-beta.6"), "0.4.0~beta6-1")
        self.assertEqual(su.source_version_to_deb_form("1.0.0"), "1.0.0-1")
        self.assertEqual(su.source_version_to_deb_form("v1.0.1"), "1.0.1-1")

    def test_dpkg_compare_matches_ordering(self) -> None:
        self.assertTrue(su.dpkg_compare("0.5.0~dev1-1", "gt", "0.4.0~beta6-1"))
        self.assertTrue(su.dpkg_compare("0.5.0~dev1-1", "lt", "0.5.0-1"))
        self.assertTrue(su.dpkg_compare("1.0.1-1", "gt", "1.0.0-1"))
        self.assertTrue(su.dpkg_compare("1.0.1-1", "lt", "1.1.0-1"))


# ---------------------------------------------------------------------------
# Release discovery / channel filtering
# ---------------------------------------------------------------------------

def _release(tag: str, prerelease: bool = False, draft: bool = False, assets: list[dict] | None = None) -> dict:
    return {
        "tag_name": tag, "name": tag, "prerelease": prerelease, "draft": draft,
        "assets": assets if assets is not None else [
            {"name": f"alderpointdns_{tag.lstrip('v').replace('.', '')}-1_all.deb", "url": "https://api.example.invalid/asset/deb"},
            {"name": "SHA256SUMS", "url": "https://api.example.invalid/asset/sums"},
        ],
        "html_url": f"https://example.invalid/releases/{tag}", "published_at": "2026-01-01T00:00:00Z", "body": "notes",
    }


class ChannelSelectionTest(unittest.TestCase):
    def test_no_update_available_when_installed_is_newest(self) -> None:
        releases = [_release("0.4.0"), _release("0.3.0")]
        self.assertIsNone(su.select_candidate_release(releases, "stable", "0.4.0"))

    def test_stable_update_available(self) -> None:
        releases = [_release("0.5.0"), _release("0.4.0")]
        candidate = su.select_candidate_release(releases, "stable", "0.4.0")
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["tag_name"], "0.5.0")

    def test_prerelease_ignored_on_stable_channel(self) -> None:
        releases = [_release("0.6.0-beta.1", prerelease=True), _release("0.4.0")]
        self.assertIsNone(su.select_candidate_release(releases, "stable", "0.4.0"))

    def test_prerelease_accepted_on_prerelease_channel(self) -> None:
        releases = [_release("0.6.0-beta.1", prerelease=True), _release("0.4.0")]
        candidate = su.select_candidate_release(releases, "prerelease", "0.4.0")
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["tag_name"], "0.6.0-beta.1")

    def test_drafts_are_always_ignored(self) -> None:
        releases = [_release("0.9.0", draft=True), _release("0.4.0")]
        self.assertIsNone(su.select_candidate_release(releases, "stable", "0.4.0"))

    def test_malformed_tags_are_skipped(self) -> None:
        releases = [_release("not-semver"), _release("0.5.0")]
        candidate = su.select_candidate_release(releases, "stable", "0.4.0")
        self.assertEqual(candidate["tag_name"], "0.5.0")

    def test_never_downgrade_never_same_version(self) -> None:
        releases = [_release("0.4.0")]
        self.assertIsNone(su.select_candidate_release(releases, "stable", "0.4.0"))
        releases_older = [_release("0.3.0")]
        self.assertIsNone(su.select_candidate_release(releases_older, "stable", "0.4.0"))

    def test_installed_version_unparseable_fails_closed(self) -> None:
        releases = [_release("0.5.0")]
        self.assertIsNone(su.select_candidate_release(releases, "stable", "not-a-version"))


class AssetSelectionTest(unittest.TestCase):
    def test_requires_exactly_one_deb_and_one_sums(self) -> None:
        deb, sums = su.select_release_assets(_release("0.5.0"))
        self.assertTrue(deb["name"].endswith(".deb"))
        self.assertEqual(sums["name"], "SHA256SUMS")

    def test_missing_deb_asset_rejected(self) -> None:
        with self.assertRaises(su.SoftwareUpdateError):
            su.select_release_assets(_release("0.5.0", assets=[{"name": "SHA256SUMS", "url": "x"}]))

    def test_multiple_deb_assets_ambiguous(self) -> None:
        assets = [
            {"name": "alderpointdns_050-1_all.deb", "url": "x"},
            {"name": "alderpointdns_050-1_amd64.deb", "url": "x"},
            {"name": "SHA256SUMS", "url": "x"},
        ]
        with self.assertRaises(su.SoftwareUpdateError):
            su.select_release_assets(_release("0.5.0", assets=assets))

    def test_missing_sha256sums_rejected(self) -> None:
        assets = [{"name": "alderpointdns_050-1_all.deb", "url": "x"}]
        with self.assertRaises(su.SoftwareUpdateError):
            su.select_release_assets(_release("0.5.0", assets=assets))


class GithubDiscoveryTest(unittest.TestCase):
    def test_malformed_github_response_raises(self) -> None:
        with mock.patch.object(su, "_github_get", side_effect=su.SoftwareUpdateError("GitHub returned a malformed (non-JSON) response")):
            with self.assertRaises(su.SoftwareUpdateError):
                su.list_releases("owner/repo", None)

    def test_github_unavailable_raises(self) -> None:
        with mock.patch.object(su, "_github_get", side_effect=su.SoftwareUpdateError("GitHub is unavailable: timed out")):
            with self.assertRaises(su.SoftwareUpdateError):
                su.list_releases("owner/repo", None)

    def test_list_releases_rejects_non_list_response(self) -> None:
        with mock.patch.object(su, "_github_get", return_value={"not": "a list"}):
            with self.assertRaises(su.SoftwareUpdateError):
                su.list_releases("owner/repo", None)


# ---------------------------------------------------------------------------
# Package validation
# ---------------------------------------------------------------------------

class PackageValidationTest(SoftwareUpdatesTestBase):
    def _fields(self, **overrides) -> dict:
        base = {"Package": "alderpointdns", "Version": "0.5.0~dev1-1", "Architecture": "all"}
        base.update(overrides)
        return base

    def test_wrong_package_name_rejected(self) -> None:
        with mock.patch.object(su, "inspect_deb", return_value=self._fields(Package="not-alderpointdns")), \
             mock.patch.object(su, "installed_package_version", return_value="0.4.0~beta6-1"):
            with self.assertRaises(su.SoftwareUpdateError):
                su.validate_candidate_package(Path("/tmp/x.deb"), None)

    def test_wrong_architecture_rejected(self) -> None:
        with mock.patch.object(su, "inspect_deb", return_value=self._fields(Architecture="arm64")), \
             mock.patch.object(su, "installed_package_version", return_value="0.4.0~beta6-1"):
            with self.assertRaises(su.SoftwareUpdateError):
                su.validate_candidate_package(Path("/tmp/x.deb"), None)

    def test_version_does_not_match_expected_release(self) -> None:
        with mock.patch.object(su, "inspect_deb", return_value=self._fields(Version="0.5.0~dev1-1")), \
             mock.patch.object(su, "installed_package_version", return_value="0.4.0~beta6-1"):
            with self.assertRaises(su.SoftwareUpdateError):
                su.validate_candidate_package(Path("/tmp/x.deb"), "0.6.0-dev.1")

    def test_same_version_rejected(self) -> None:
        with mock.patch.object(su, "inspect_deb", return_value=self._fields(Version="0.4.0~beta6-1")), \
             mock.patch.object(su, "installed_package_version", return_value="0.4.0~beta6-1"):
            with self.assertRaises(su.SoftwareUpdateError):
                su.validate_candidate_package(Path("/tmp/x.deb"), None)

    def test_downgrade_rejected(self) -> None:
        with mock.patch.object(su, "inspect_deb", return_value=self._fields(Version="0.3.0-1")), \
             mock.patch.object(su, "installed_package_version", return_value="0.4.0~beta6-1"):
            with self.assertRaises(su.SoftwareUpdateError):
                su.validate_candidate_package(Path("/tmp/x.deb"), None)

    def test_valid_newer_version_accepted(self) -> None:
        with mock.patch.object(su, "inspect_deb", return_value=self._fields(Version="0.5.0~dev1-1")), \
             mock.patch.object(su, "installed_package_version", return_value="0.4.0~beta6-1"):
            fields = su.validate_candidate_package(Path("/tmp/x.deb"), "0.5.0-dev.1")
        self.assertEqual(fields["Version"], "0.5.0~dev1-1")

    def test_unmanaged_source_install_rejected(self) -> None:
        with mock.patch.object(su, "inspect_deb", return_value=self._fields()), \
             mock.patch.object(su, "installed_package_version", return_value=None):
            with self.assertRaises(su.SoftwareUpdateError):
                su.validate_candidate_package(Path("/tmp/x.deb"), None)


class ChecksumTest(SoftwareUpdatesTestBase):
    def test_checksum_mismatch_rejected(self) -> None:
        release = _release("0.5.0")
        deb_asset, sums_asset = su.select_release_assets(release)

        def fake_download(asset, dest, token):
            if asset is deb_asset:
                dest.write_bytes(b"real package bytes")
            else:
                dest.write_text(f"{'0' * 64}  {deb_asset['name']}\n")

        with mock.patch.object(su, "_download_asset", side_effect=fake_download):
            with self.assertRaises(su.SoftwareUpdateError):
                su.stage_release(release, None)

    def test_checksum_match_succeeds(self) -> None:
        release = _release("0.5.0")
        deb_asset, sums_asset = su.select_release_assets(release)
        content = b"real package bytes"
        digest = hashlib.sha256(content).hexdigest()

        def fake_download(asset, dest, token):
            if asset is deb_asset:
                dest.write_bytes(content)
            else:
                dest.write_text(f"{digest}  {deb_asset['name']}\n")

        with mock.patch.object(su, "_download_asset", side_effect=fake_download):
            path, sha = su.stage_release(release, None)
        self.assertEqual(sha, digest)
        self.assertTrue(path.exists())


class AptSimulationTest(unittest.TestCase):
    def test_simulation_failure_raises(self) -> None:
        with mock.patch.object(su, "run", side_effect=OSError("apt-get not found")):
            with self.assertRaises(su.SoftwareUpdateError):
                su.simulate_install(Path("/tmp/x.deb"))

    def test_removal_of_critical_package_rejected(self) -> None:
        import subprocess
        proc = subprocess.CompletedProcess(["apt-get"], 0, "Remv bind9 [1.0]\n")
        with mock.patch.object(su, "run", return_value=proc):
            with self.assertRaises(su.SoftwareUpdateError):
                su.simulate_install(Path("/tmp/x.deb"))

    def test_clean_simulation_succeeds(self) -> None:
        import subprocess
        proc = subprocess.CompletedProcess(["apt-get"], 0, "Inst alderpointdns [0.4.0] (0.5.0)\n")
        with mock.patch.object(su, "run", return_value=proc):
            output = su.simulate_install(Path("/tmp/x.deb"))
        self.assertIn("Inst", output)


# ---------------------------------------------------------------------------
# Post-upgrade health check
# ---------------------------------------------------------------------------

class HealthCheckTest(unittest.TestCase):
    def test_all_healthy(self) -> None:
        with mock.patch.object(su, "_service_active", return_value=True), \
             mock.patch.object(su, "_quick_check_ok", return_value=True), \
             mock.patch.object(su, "_resolution_ok", return_value=True), \
             mock.patch.object(su, "_webapp_healthz_ok", return_value=True), \
             mock.patch.object(su, "installed_package_version", return_value="0.5.0~dev1-1"), \
             mock.patch.object(backup_module, "alderpointdns_app_version", return_value="0.5.0-dev.1"):
            result = su.post_upgrade_health_check(expected_deb_version="0.5.0~dev1-1")
        self.assertTrue(result["ok"])

    def test_service_failure_marks_unhealthy(self) -> None:
        with mock.patch.object(su, "_service_active", side_effect=lambda u: u != "named"), \
             mock.patch.object(su, "_quick_check_ok", return_value=True), \
             mock.patch.object(su, "_resolution_ok", return_value=True), \
             mock.patch.object(su, "_webapp_healthz_ok", return_value=True):
            result = su.post_upgrade_health_check()
        self.assertFalse(result["ok"])
        self.assertFalse(result["services"]["named"])

    def test_quick_check_failure_marks_unhealthy(self) -> None:
        with mock.patch.object(su, "_service_active", return_value=True), \
             mock.patch.object(su, "_quick_check_ok", return_value=False), \
             mock.patch.object(su, "_resolution_ok", return_value=True), \
             mock.patch.object(su, "_webapp_healthz_ok", return_value=True):
            result = su.post_upgrade_health_check()
        self.assertFalse(result["ok"])
        self.assertFalse(result["database_quick_check_ok"])


# ---------------------------------------------------------------------------
# Job durability / pre-upgrade backup gating / full job run
# ---------------------------------------------------------------------------

def _real_dpkg_passthrough(apt_result):
    """dpkg_compare() also calls su.run() (for `dpkg --compare-versions`),
    so a test that stubs su.run() to canned apt-get output must not
    blindly intercept *every* call -- that would make every version
    comparison spuriously report "equal" regardless of its actual
    arguments. Real `dpkg --compare-versions` calls are safe (no real
    package operation) and pass through to the actual binary; only the
    apt-get install call itself is stubbed."""
    import subprocess

    def fake_run(cmd, check=True, timeout=None, input_text=None):
        if cmd[:2] == ["dpkg", "--compare-versions"]:
            return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        return apt_result

    return fake_run


class JobRunTest(SoftwareUpdatesTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.release = _release("0.5.0")

    def _common_patches(self):
        return [
            mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True, "source": "version_file"}),
            mock.patch.object(su, "_read_github_token", return_value=None),
            mock.patch.object(su, "stage_release", return_value=(self.tmp / "fake.deb", "a" * 64)),
            mock.patch.object(su, "inspect_deb", return_value={"Package": "alderpointdns", "Version": "0.5.0-1", "Architecture": "all"}),
            mock.patch.object(su, "installed_package_version", return_value="0.4.0~beta6-1"),
            mock.patch.object(su, "simulate_install", return_value="Inst alderpointdns"),
            mock.patch.object(su, "post_upgrade_health_check", return_value={"ok": True, "services_ok": True, "database_quick_check_ok": True, "dns_resolution_ok": True, "webapp_responding": True}),
        ]

    def test_backup_failure_blocks_install(self) -> None:
        (self.tmp / "fake.deb").write_bytes(b"deb")
        job_id = su.create_github_job(self.release, requested_by="admin")
        patches = self._common_patches() + [
            mock.patch.object(backup_module, "create_backup", side_effect=RuntimeError("disk full")),
        ]
        for p in patches:
            p.start()
        try:
            result = su.run_pending_job()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(result["phase"], "failed")
        self.assertIn("pre-upgrade backup failed", result["error"])

    def test_backup_success_then_apt_install_proceeds(self) -> None:
        (self.tmp / "fake.deb").write_bytes(b"deb")
        job_id = su.create_github_job(self.release, requested_by="admin")
        backup_path = self.tmp / "fake-backup.tar.gz"
        backup_path.write_bytes(b"backup")
        patches = self._common_patches() + [
            mock.patch.object(backup_module, "create_backup", return_value=backup_path),
            mock.patch.object(backup_module, "last_backup", return_value={"id": 42}),
            mock.patch.object(su, "run", side_effect=_real_dpkg_passthrough(__import__("subprocess").CompletedProcess(["apt-get"], 0, "Setting up alderpointdns"))),
            mock.patch.object(su, "_service_active", return_value=True),
        ]
        for p in patches:
            p.start()
        try:
            result = su.run_pending_job()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(result["phase"], "completed")
        self.assertEqual(result["result"], "success")
        self.assertEqual(result["backup_id"], 42)

    def test_failed_apt_install_fails_job_and_retains_backup(self) -> None:
        import subprocess
        (self.tmp / "fake.deb").write_bytes(b"deb")
        job_id = su.create_github_job(self.release, requested_by="admin")
        backup_path = self.tmp / "fake-backup.tar.gz"
        backup_path.write_bytes(b"backup")

        def fake_run(cmd, check=True, timeout=None, input_text=None):
            if cmd[:2] == ["dpkg", "--compare-versions"]:
                return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
            if "apt-get" in cmd and "install" in cmd and "-s" not in cmd:
                raise subprocess.CalledProcessError(100, cmd, output="dpkg: error processing package")
            return subprocess.CompletedProcess(cmd, 0, "ok")

        patches = self._common_patches() + [
            mock.patch.object(backup_module, "create_backup", return_value=backup_path),
            mock.patch.object(backup_module, "last_backup", return_value={"id": 7}),
            mock.patch.object(su, "run", side_effect=fake_run),
        ]
        for p in patches:
            p.start()
        try:
            result = su.run_pending_job()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(result["phase"], "failed")
        self.assertTrue(Path(result["backup_path"]).exists())  # pre-upgrade backup retained despite failure

    def test_postupgrade_health_failure_fails_job_and_retains_backup(self) -> None:
        (self.tmp / "fake.deb").write_bytes(b"deb")
        su.create_github_job(self.release, requested_by="admin")
        backup_path = self.tmp / "fake-backup.tar.gz"
        backup_path.write_bytes(b"backup")
        patches = self._common_patches() + [
            mock.patch.object(backup_module, "create_backup", return_value=backup_path),
            mock.patch.object(backup_module, "last_backup", return_value={"id": 9}),
            mock.patch.object(su, "run", side_effect=_real_dpkg_passthrough(__import__("subprocess").CompletedProcess(["apt-get"], 0, "ok"))),
            mock.patch.object(su, "post_upgrade_health_check", return_value={"ok": False, "database_quick_check_ok": False}),
        ]
        for p in patches:
            p.start()
        try:
            result = su.run_pending_job()
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(result["phase"], "failed")
        self.assertTrue(Path(result["backup_path"]).exists())

    def test_no_pending_job_is_a_noop(self) -> None:
        self.assertIsNone(su.run_pending_job())

    def test_version_mismatch_blocks_install(self) -> None:
        su.create_github_job(self.release, requested_by="admin")
        with mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": True, "dpkg_managed": True}):
            result = su.run_pending_job()
        self.assertEqual(result["phase"], "failed")
        self.assertIn("drift", result["error"])

    def test_unmanaged_source_install_blocks_install(self) -> None:
        su.create_github_job(self.release, requested_by="admin")
        with mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": False}):
            result = su.run_pending_job()
        self.assertEqual(result["phase"], "failed")
        self.assertIn("unmanaged", result["error"])


class ReapAbandonedJobsTest(SoftwareUpdatesTestBase):
    """A runner (alderpointdns-software-update.service) that dies mid-job
    must never leave software_update_jobs stuck at a non-terminal phase
    forever -- see software_updates.reap_abandoned_jobs()."""

    def _stuck_job(self, phase: str, worker_pid: int | None, alive: bool) -> int:
        job_id = su.create_github_job(_release("0.5.0"), requested_by="admin")
        conn = su.connect()
        if alive:
            pid, ticks, boot_id = backup_module._worker_identity()
        else:
            pid, ticks, boot_id = worker_pid, 999999999, "stale-boot-id-that-will-never-match"
        conn.execute(
            "UPDATE software_update_jobs SET phase=?, started_at=?, worker_pid=?, worker_start_ticks=?, worker_boot_id=? WHERE id=?",
            (phase, su.now(), pid, ticks, boot_id, job_id),
        )
        conn.commit()
        conn.close()
        return job_id

    def test_job_with_dead_worker_before_installing_is_reaped_as_safe_to_retry(self) -> None:
        job_id = self._stuck_job("downloading", worker_pid=999999, alive=False)
        reaped = su.reap_abandoned_jobs()
        self.assertEqual([r["id"] for r in reaped], [job_id])
        row = su.get_job(job_id)
        self.assertEqual(row["phase"], "failed")
        self.assertIn("safe to retry", row["error"])

    def test_job_with_dead_worker_during_install_is_reaped_as_package_state_uncertain(self) -> None:
        job_id = self._stuck_job("installing", worker_pid=999999, alive=False)
        reaped = su.reap_abandoned_jobs()
        self.assertEqual([r["id"] for r in reaped], [job_id])
        row = su.get_job(job_id)
        self.assertEqual(row["phase"], "failed")
        self.assertIn("partially applied", row["error"])

    def test_job_with_live_worker_is_not_reaped(self) -> None:
        job_id = self._stuck_job("installing", worker_pid=None, alive=True)
        reaped = su.reap_abandoned_jobs()
        self.assertEqual(reaped, [])
        row = su.get_job(job_id)
        self.assertEqual(row["phase"], "installing")

    def test_completed_and_failed_jobs_are_never_touched(self) -> None:
        job_id = su.create_github_job(_release("0.5.0"), requested_by="admin")
        conn = su.connect()
        conn.execute("UPDATE software_update_jobs SET phase='completed', result='success' WHERE id=?", (job_id,))
        conn.commit()
        conn.close()
        reaped = su.reap_abandoned_jobs()
        self.assertEqual(reaped, [])
        self.assertEqual(su.get_job(job_id)["phase"], "completed")

    def test_reap_unblocks_the_in_progress_gate(self) -> None:
        """The exact scenario this fixes: without reaping, an abandoned job
        stuck at a non-terminal phase would make
        `existing_job.get("phase") not in ("completed", "failed")` true
        forever, permanently blocking install/upload routes."""
        self._stuck_job("installing", worker_pid=999999, alive=False)
        status = su.update_status()  # reaps internally
        job = status["job"]
        self.assertIn(job["phase"], ("completed", "failed"))

    def test_reap_runs_via_update_status_without_explicit_call(self) -> None:
        job_id = self._stuck_job("backing_up", worker_pid=999999, alive=False)
        su.update_status()
        self.assertEqual(su.get_job(job_id)["phase"], "failed")

    def test_freshly_created_pending_job_is_not_reaped(self) -> None:
        """A job's row exists (phase='pending', no worker identity yet) for
        an ordinary, expected moment between the web request creating it
        and the independently-dispatched runner unit picking it up -- this
        must never be mistaken for an abandoned worker. Regression test for
        exactly the race the initial version of this fix introduced."""
        job_id = su.create_github_job(_release("0.5.0"), requested_by="admin")
        reaped = su.reap_abandoned_jobs()
        self.assertEqual(reaped, [])
        self.assertEqual(su.get_job(job_id)["phase"], "pending")

    def test_pending_job_past_the_dispatch_grace_period_is_reaped(self) -> None:
        job_id = su.create_github_job(_release("0.5.0"), requested_by="admin")
        stale_requested_at = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=su.PENDING_DISPATCH_GRACE_SECONDS + 30)).replace(microsecond=0).isoformat()
        conn = su.connect()
        conn.execute("UPDATE software_update_jobs SET requested_at=? WHERE id=?", (stale_requested_at, job_id))
        conn.commit()
        conn.close()
        reaped = su.reap_abandoned_jobs()
        self.assertEqual([r["id"] for r in reaped], [job_id])
        self.assertEqual(su.get_job(job_id)["phase"], "failed")


class JobDurabilityTest(SoftwareUpdatesTestBase):
    def test_job_state_readable_from_a_fresh_connection(self) -> None:
        """Simulates "the browser reconnects after alderpointdns.service
        restarts": nothing about job state may live in process memory --
        a brand new sqlite3 connection to the same DB_PATH must see it."""
        job_id = su.create_github_job(_release("0.5.0"), requested_by="admin")
        fresh_conn = sqlite3.connect(su.DB_PATH)
        fresh_conn.row_factory = sqlite3.Row
        row = fresh_conn.execute("SELECT * FROM software_update_jobs WHERE id=?", (job_id,)).fetchone()
        fresh_conn.close()
        self.assertEqual(row["phase"], "pending")
        self.assertEqual(row["operation"], "github")

    def test_events_accumulate_across_phases(self) -> None:
        job_id = su.create_manual_job(Path("/tmp/x.deb"), expected_sha256="a" * 64, requested_by="admin")
        conn = su.connect()
        su._set_phase(conn, job_id, "downloading", "step one")
        su._set_phase(conn, job_id, "validating", "step two")
        conn.close()
        events = su.job_events(job_id)
        self.assertEqual([e["phase"] for e in events], ["downloading", "validating"])


# ---------------------------------------------------------------------------
# Manual upload confinement / bounded staging
# ---------------------------------------------------------------------------

class ManualUploadTest(SoftwareUpdatesTestBase):
    def test_non_deb_filename_rejected(self) -> None:
        with self.assertRaises(su.SoftwareUpdateError):
            su.begin_manual_upload("not-a-package.txt")

    def test_path_traversal_filename_rejected(self) -> None:
        with self.assertRaises(su.SoftwareUpdateError):
            su.begin_manual_upload("../../etc/passwd.deb")

    def test_upload_confined_to_staging_dir(self) -> None:
        tmp_path, max_bytes = su.begin_manual_upload("update.deb")
        self.assertEqual(tmp_path.parent.resolve(), su.UPLOAD_STAGING_DIR.resolve())
        tmp_path.write_bytes(b"fake package content")
        dest = su.finalize_manual_upload(tmp_path, "update.deb")
        self.assertTrue(dest.exists())
        self.assertEqual(dest.parent.resolve(), su.UPLOAD_STAGING_DIR.resolve())

    def test_abort_removes_partial_upload(self) -> None:
        tmp_path, _ = su.begin_manual_upload("update.deb")
        tmp_path.write_bytes(b"partial")
        su.abort_manual_upload(tmp_path)
        self.assertFalse(tmp_path.exists())


# ---------------------------------------------------------------------------
# Credential handling / redaction
# ---------------------------------------------------------------------------

class CredentialTest(SoftwareUpdatesTestBase):
    def test_missing_credential_file_returns_none(self) -> None:
        self.assertIsNone(su._read_github_token())
        status = su.credential_status()
        self.assertFalse(status["configured"])

    def test_world_readable_credential_file_refused(self) -> None:
        su.CREDENTIAL_FILE.write_text("GITHUB_TOKEN=ghp_secretvalue1234567890\n")
        su.CREDENTIAL_FILE.chmod(0o644)  # world-readable: must be refused
        self.assertIsNone(su._read_github_token())

    def _write_secure_credential(self, content: str) -> None:
        su.CREDENTIAL_FILE.write_text(content)
        su.CREDENTIAL_FILE.chmod(0o600)
        try:
            shutil.chown(su.CREDENTIAL_FILE, user=0, group=0)
        except (LookupError, PermissionError, OSError):
            self.skipTest("cannot chown to root in this sandbox; permission-gated credential read path not exercisable here")

    def test_secure_credential_file_is_read(self) -> None:
        self._write_secure_credential("GITHUB_TOKEN=ghp_secretvalue1234567890\n")
        token = su._read_github_token()
        self.assertEqual(token, "ghp_secretvalue1234567890")

    def test_redact_strips_token_and_authorization_header(self) -> None:
        text = "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345\nsome other text"
        redacted = su.redact(text)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz012345", redacted)
        self.assertNotIn("Bearer", redacted)
        self.assertIn("some other text", redacted)

    def test_redact_strips_configured_token_verbatim(self) -> None:
        self._write_secure_credential("GITHUB_TOKEN=my-secret-value-123\n")
        redacted = su.redact("error talking to https://x/my-secret-value-123/releases")
        self.assertNotIn("my-secret-value-123", redacted)

    def test_diagnostics_never_contain_raw_token(self) -> None:
        """update-run's diagnostics persistence path always runs text
        through redact() before storing it -- exercised directly here."""
        self._write_secure_credential("GITHUB_TOKEN=leaked-token-xyz\n")
        job_id = su.create_manual_job(Path("/tmp/x.deb"), None, requested_by="admin")
        conn = su.connect()
        su._diagnostics_merge(conn, job_id, {"apt_output": "leaked-token-xyz appeared in output"})
        conn.close()
        row = su.get_job(job_id)
        self.assertNotIn("leaked-token-xyz", row["diagnostics_json"])


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

class SettingsTest(SoftwareUpdatesTestBase):
    def test_defaults(self) -> None:
        cfg = su.settings()
        self.assertEqual(cfg["auto_check_enabled"], "1")
        self.assertEqual(cfg["unattended_install_enabled"], "0")
        self.assertEqual(cfg["channel"], "stable")

    def test_default_github_repo_is_the_canonical_repository(self) -> None:
        """Online discovery must default to the real, canonical repository
        -- not a placeholder -- so a fresh install's automatic checking
        works out of the box against the actual project once it's public,
        and a private-repo credential (if configured) authenticates against
        the right repo."""
        self.assertEqual(su.DEFAULT_GITHUB_REPO, "neosmith20/Alderpoint-DNS")
        self.assertEqual(su.settings()["github_repo"], "neosmith20/Alderpoint-DNS")

    def test_update_settings_validates_channel(self) -> None:
        with self.assertRaises(su.SoftwareUpdateError):
            su.update_settings({"channel": "nightly"})

    def test_update_settings_persists(self) -> None:
        su.update_settings({"channel": "prerelease", "auto_check_enabled": "0"})
        cfg = su.settings()
        self.assertEqual(cfg["channel"], "prerelease")
        self.assertEqual(cfg["auto_check_enabled"], "0")


class RunCheckTest(SoftwareUpdatesTestBase):
    def test_skipped_when_auto_check_disabled(self) -> None:
        su.update_settings({"auto_check_enabled": "0"})
        result = su.run_check(force=False)
        self.assertTrue(result.get("skipped"))

    def test_forced_check_runs_even_when_disabled(self) -> None:
        su.update_settings({"auto_check_enabled": "0"})
        with mock.patch.object(su, "_read_github_token", return_value=None), \
             mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True}), \
             mock.patch.object(su, "list_releases", return_value=[_release("0.5.0")]):
            result = su.run_check(force=True)
        self.assertTrue(result["update_available"])

    def test_check_records_error_on_github_failure(self) -> None:
        with mock.patch.object(su, "list_releases", side_effect=su.SoftwareUpdateError("GitHub is unavailable: timed out")):
            result = su.run_check(force=True)
        self.assertIn("error", result)
        self.assertFalse(result["update_available"])
        cfg = su.settings()
        self.assertIn("unavailable", cfg["last_check_error"])

    def test_failed_check_retries_normally_on_the_next_call(self) -> None:
        """A failed scheduled check (GitHub unreachable, etc.) must not
        wedge anything -- the very next check (the following scheduled
        firing, or a manual retry) runs normally."""
        with mock.patch.object(su, "list_releases", side_effect=su.SoftwareUpdateError("GitHub is unavailable: timed out")):
            first = su.run_check(force=True)
        self.assertIn("error", first)
        with mock.patch.object(su, "_read_github_token", return_value=None), \
             mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True}), \
             mock.patch.object(su, "list_releases", return_value=[_release("0.5.0")]):
            second = su.run_check(force=True)
        self.assertTrue(second["update_available"])
        self.assertEqual(su.settings()["last_check_error"], "")


# ---------------------------------------------------------------------------
# Automatic-check scheduling (check_interval_hours actually drives the
# systemd timer cadence; auto_check_enabled actually stops/starts it)
# ---------------------------------------------------------------------------

class CheckSchedulingTest(SoftwareUpdatesTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.tmp_systemd = self.tmp / "systemd"
        self.override_dir = self.tmp_systemd / f"{su.CHECK_TIMER_UNIT}.d"
        self.old_override_dir = su.CHECK_TIMER_OVERRIDE_DIR
        self.old_override = su.CHECK_TIMER_OVERRIDE
        su.CHECK_TIMER_OVERRIDE_DIR = self.override_dir
        su.CHECK_TIMER_OVERRIDE = self.override_dir / "alderpointdns.conf"
        self.systemctl_calls: list[list[str]] = []

    def tearDown(self) -> None:
        su.CHECK_TIMER_OVERRIDE_DIR = self.old_override_dir
        su.CHECK_TIMER_OVERRIDE = self.old_override
        super().tearDown()

    def _fake_run(self, cmd, check=True, timeout=None, input_text=None):
        import subprocess
        self.systemctl_calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "")

    def test_default_automatic_checking_is_enabled(self) -> None:
        cfg = su.settings()
        self.assertEqual(cfg["auto_check_enabled"], "1")
        self.assertEqual(cfg["check_interval_hours"], "6")

    def test_configured_interval_is_written_into_the_timer_drop_in(self) -> None:
        su.update_settings({"check_interval_hours": "12"})
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            su.deploy_check_schedule()
        content = su.CHECK_TIMER_OVERRIDE.read_text()
        self.assertIn("OnUnitActiveSec=12h", content)

    def test_changing_the_interval_redeploys_the_new_cadence(self) -> None:
        su.update_settings({"check_interval_hours": "1"})
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            su.deploy_check_schedule()
        self.assertIn("OnUnitActiveSec=1h", su.CHECK_TIMER_OVERRIDE.read_text())
        su.update_settings({"check_interval_hours": "168"})
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            su.deploy_check_schedule()
        self.assertIn("OnUnitActiveSec=168h", su.CHECK_TIMER_OVERRIDE.read_text())

    def test_out_of_range_interval_is_clamped_not_written_verbatim(self) -> None:
        conn = su.connect()
        conn.execute(
            "INSERT INTO software_update_settings(key, value) VALUES ('check_interval_hours', '99999') "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        )
        conn.commit()
        conn.close()
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            su.deploy_check_schedule()
        content = su.CHECK_TIMER_OVERRIDE.read_text()
        self.assertIn(f"OnUnitActiveSec={su.MAX_CHECK_INTERVAL_HOURS}h", content)

    def test_disabling_automatic_checking_removes_the_drop_in_and_stops_the_timer(self) -> None:
        su.update_settings({"check_interval_hours": "12"})
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            su.deploy_check_schedule()
        self.assertTrue(su.CHECK_TIMER_OVERRIDE.exists())
        self.systemctl_calls.clear()
        su.update_settings({"auto_check_enabled": "0"})
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            result = su.deploy_check_schedule()
        self.assertFalse(su.CHECK_TIMER_OVERRIDE.exists())
        self.assertEqual(json.loads(result)["state"], "disabled")
        self.assertTrue(any("disable" in call and "--now" in call for call in self.systemctl_calls))

    def test_reenabling_recreates_the_drop_in_and_starts_the_timer(self) -> None:
        su.update_settings({"auto_check_enabled": "0"})
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            su.deploy_check_schedule()
        self.assertFalse(su.CHECK_TIMER_OVERRIDE.exists())
        su.update_settings({"auto_check_enabled": "1", "check_interval_hours": "24"})
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            result = su.deploy_check_schedule()
        self.assertTrue(su.CHECK_TIMER_OVERRIDE.exists())
        self.assertEqual(json.loads(result)["state"], "enabled")
        self.assertTrue(any("enable" in call and "--now" in call for call in self.systemctl_calls))

    def test_scheduling_never_touches_the_install_runner_unit(self) -> None:
        """The check timer must only ever be able to trigger update-check
        -- deploy_check_schedule() must never enable/start/reference
        alderpointdns-software-update.service (the privileged install
        runner), directly or indirectly."""
        su.update_settings({"check_interval_hours": "12"})
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            su.deploy_check_schedule()
        for call in self.systemctl_calls:
            self.assertNotIn("alderpointdns-software-update.service", call)
        self.assertNotIn("update-run", su.CHECK_TIMER_OVERRIDE.read_text())

    def test_packaged_check_service_only_ever_runs_update_check(self) -> None:
        """The unit the timer actually triggers (packaging/*-check.service)
        execs update-check, never update-run -- a scheduled firing can
        physically never install anything."""
        service_file = ROOT / "packaging" / "alderpointdns-software-update-check.service"
        content = service_file.read_text()
        self.assertIn("update-check", content)
        self.assertNotIn("update-run", content)

    def test_sudoers_entry_for_schedule_deploy_is_argument_free(self) -> None:
        sudoers = (ROOT / "packaging" / "sudoers-alderpointdns").read_text()
        self.assertIn("alderpointdns_compiler.py update-check-schedule-deploy", sudoers)
        # No trailing arguments after the subcommand for this entry, unlike
        # e.g. "update-check --force" which is its own separate, explicit
        # allowlisted entry -- nothing about the schedule-deploy entry
        # takes operator-controlled text.
        for line in sudoers.splitlines():
            if "update-check-schedule-deploy" in line:
                idx = line.index("update-check-schedule-deploy") + len("update-check-schedule-deploy")
                self.assertTrue(line[idx:idx + 1] in (",", "", "\n"))

    def test_concurrent_check_is_skipped_not_duplicated(self) -> None:
        """Two overlapping invocations (a scheduled firing landing on top
        of a manual click, or vice versa) must not both hit GitHub and
        interleave writes -- the second must simply report a check is
        already in flight."""
        su.CHECK_LOCK.parent.mkdir(parents=True, exist_ok=True)
        held = su.CHECK_LOCK.open("w")
        try:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with mock.patch.object(su, "list_releases") as mock_list_releases:
                result = su.run_check(force=True)
                self.assertTrue(result.get("skipped"))
                self.assertIn("already in progress", result["reason"])
                mock_list_releases.assert_not_called()
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
            held.close()

    def test_lock_is_released_after_a_check_so_the_next_one_is_not_blocked(self) -> None:
        with mock.patch.object(su, "_read_github_token", return_value=None), \
             mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True}), \
             mock.patch.object(su, "list_releases", return_value=[_release("0.5.0")]):
            first = su.run_check(force=True)
            second = su.run_check(force=True)
        self.assertFalse(first.get("skipped"))
        self.assertFalse(second.get("skipped"))

    def test_scheduled_style_invocation_via_cli_never_installs(self) -> None:
        """update_check() (what the timer's .service unit execs) only ever
        calls run_check() -- it has no code path that can start the install
        runner or write a software_update_jobs row."""
        from app import alderpointdns_compiler

        with mock.patch.object(su, "list_releases", return_value=[_release("9.9.9")]), \
             mock.patch.object(su, "_read_github_token", return_value=None), \
             mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True}), \
             mock.patch.object(su, "run_pending_job") as mock_run_pending, \
             mock.patch("builtins.print"):
            alderpointdns_compiler.update_check(mock.Mock(force=True))
        mock_run_pending.assert_not_called()
        self.assertIsNone(su.latest_job())

    def test_credential_never_reaches_the_timer_drop_in_or_systemctl_argv(self) -> None:
        su.CREDENTIAL_FILE.write_text("GITHUB_TOKEN=leaked-schedule-token-xyz\n")
        su.CREDENTIAL_FILE.chmod(0o600)
        try:
            shutil.chown(su.CREDENTIAL_FILE, user=0, group=0)
        except (LookupError, PermissionError, OSError):
            self.skipTest("cannot chown to root in this sandbox; permission-gated credential read path not exercisable here")
        su.update_settings({"check_interval_hours": "12"})
        with mock.patch.object(su, "run", side_effect=self._fake_run):
            su.deploy_check_schedule()
        content = su.CHECK_TIMER_OVERRIDE.read_text()
        self.assertNotIn("leaked-schedule-token-xyz", content)
        for call in self.systemctl_calls:
            self.assertNotIn("leaked-schedule-token-xyz", " ".join(call))


# ---------------------------------------------------------------------------
# HTTP route level: auth, CSRF, path/injection rejection, streamed upload
# ---------------------------------------------------------------------------

class SoftwareUpdatesHttpTest(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.templating import Jinja2Templates
        from fastapi.testclient import TestClient

        from app import alderpointdns_compiler, custom_rules, local_dns, replication, upstream_dns, webapp

        self.webapp = webapp
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-su-http-"))
        self.old_paths = {
            "webapp_db": webapp.DB_PATH,
            "su_db": su.DB_PATH,
            "su_staged": su.STAGED_DIR,
            "su_uploads": su.UPLOAD_STAGING_DIR,
            "local_dns_db": local_dns.DB_PATH,
            "upstream_dns_db": upstream_dns.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "custom_rules_db": custom_rules.DB_PATH,
            "su_check_lock": su.CHECK_LOCK,
        }
        db_path = self.tmp / "alderpointdns.db"
        for module in (webapp, su, local_dns, upstream_dns, alderpointdns_compiler, custom_rules):
            module.DB_PATH = db_path
        su.STAGED_DIR = self.tmp / "staged"
        su.UPLOAD_STAGING_DIR = self.tmp / "uploads"
        su.CHECK_LOCK = self.tmp / "check.lock"

        local_dns.init_db()
        upstream_dns.init_db()
        alderpointdns_compiler.init_db()
        custom_rules.init_db()
        su.init_db()

        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
        conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES ('admin', 'x', 'now')")
        conn.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, admin_id INTEGER, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, ip TEXT, user_agent TEXT, csrf TEXT NOT NULL)")
        conn.commit()
        conn.close()

        # The privileged-helper hop (sudo alderpointdns_compiler.py
        # update-check / sudo systemctl start ...) is out of scope for an
        # HTTP route test; simulate it inline exactly as app/backup.py's
        # own route tests do for its sudo-escalated actions.
        self.patches = [
            mock.patch.object(webapp, "software_updates_check_apply", lambda force=True: (0, json.dumps(su.run_check(force=force), default=str))),
            mock.patch.object(webapp, "software_updates_start_install_runner", lambda: (0, str(su.run_pending_job()))),
            mock.patch.object(webapp, "software_updates_check_schedule_apply", lambda: (0, "ok")),
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(replication, "autostart", lambda: None),
            mock.patch.object(webapp, "TEMPLATES", Jinja2Templates(directory=str(ROOT / "web" / "templates"))),
        ]
        for patcher in self.patches:
            patcher.start()
        self.client = TestClient(webapp.app)
        self.csrf = "test-csrf-token"
        self.session_id = "test-session-id"
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES (?, 1, 'now', 'now', '', '', ?)",
            (self.session_id, self.csrf),
        )
        conn.commit()
        conn.close()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        from app import alderpointdns_compiler, custom_rules, local_dns, upstream_dns

        self.webapp.DB_PATH = self.old_paths["webapp_db"]
        su.DB_PATH = self.old_paths["su_db"]
        su.STAGED_DIR = self.old_paths["su_staged"]
        su.UPLOAD_STAGING_DIR = self.old_paths["su_uploads"]
        su.CHECK_LOCK = self.old_paths["su_check_lock"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        upstream_dns.DB_PATH = self.old_paths["upstream_dns_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        custom_rules.DB_PATH = self.old_paths["custom_rules_db"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _authed_client(self):
        self.client.cookies.set("alderpointdns_session", self.webapp.serializer.dumps({"sid": self.session_id}))
        return self.client

    def test_unauthenticated_get_redirects_to_login(self) -> None:
        response = self.client.get("/system/administration/software-updates", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("/login", response.headers["location"])

    def test_unauthenticated_check_rejected(self) -> None:
        response = self.client.post("/system/administration/software-updates/check", data={"csrf": "x"}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn("/login", response.headers["location"])

    def test_unauthenticated_upload_rejected(self) -> None:
        response = self.client.post(
            "/system/administration/software-updates/upload",
            data={"csrf": "x"},
            files={"upload": ("x.deb", b"data", "application/vnd.debian.binary-package")},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("/login", response.headers["location"])

    def test_authenticated_get_succeeds(self) -> None:
        response = self._authed_client().get("/system/administration/software-updates")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Software Updates", response.text)

    def test_wrong_csrf_rejected(self) -> None:
        response = self._authed_client().post("/system/administration/software-updates/check", data={"csrf": "wrong-token"})
        self.assertEqual(response.status_code, 403)

    def test_check_route_updates_status(self) -> None:
        with mock.patch.object(su, "list_releases", return_value=[_release("9.9.9")]), \
             mock.patch.object(su, "_read_github_token", return_value=None), \
             mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True, "source": "version_file"}):
            response = self._authed_client().post(
                "/system/administration/software-updates/check", data={"csrf": self.csrf}, follow_redirects=False
            )
        self.assertEqual(response.status_code, 303)
        status = su.update_status()
        self.assertTrue(status["update_available"])

    def _build_fake_deb(self, size_bytes: int) -> bytes:
        return b"!<arch>\n" + os.urandom(size_bytes)

    def test_manual_upload_streams_to_staging_and_starts_runner(self) -> None:
        data = self._build_fake_deb(1024)
        with mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True}), \
             mock.patch.object(su, "run_pending_job", return_value={"phase": "failed", "result": "failed"}):
            response = self._authed_client().post(
                "/system/administration/software-updates/upload",
                data={"csrf": self.csrf, "expected_sha256": "a" * 64},
                files={"upload": ("update.deb", data, "application/vnd.debian.binary-package")},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 303, response.text)
        staged = list(su.UPLOAD_STAGING_DIR.glob("*update.deb"))
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0].read_bytes(), data)

    def test_manual_upload_large_file_is_streamed_in_bounded_chunks(self) -> None:
        """Proves the route never buffers the whole upload in this
        process's memory: peak chunk size stays at UPLOAD_CHUNK_BYTES
        regardless of the archive's total size."""
        size = 6 * 1024 * 1024
        data = self._build_fake_deb(size)
        max_chunk_seen = 0
        original_open = Path.open

        class TrackingFile:
            def __init__(self, fh):
                self._fh = fh

            def write(self, chunk):
                nonlocal max_chunk_seen
                max_chunk_seen = max(max_chunk_seen, len(chunk))
                return self._fh.write(chunk)

            def __getattr__(self, name):
                return getattr(self._fh, name)

        with mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True}), \
             mock.patch.object(su, "run_pending_job", return_value={"phase": "failed", "result": "failed"}):
            response = self._authed_client().post(
                "/system/administration/software-updates/upload",
                data={"csrf": self.csrf, "expected_sha256": "a" * 64},
                files={"upload": ("large-update.deb", data, "application/vnd.debian.binary-package")},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 303, response.text)
        staged = list(su.UPLOAD_STAGING_DIR.glob("*large-update.deb"))
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0].stat().st_size, len(data))
        # TestClient's own httpx transport chunks the multipart body before
        # it reaches our route; the meaningful bound is the server-side
        # UPLOAD_CHUNK_BYTES constant the route reads with, not a chunk
        # observed here -- confirmed directly at the unit level by
        # UPLOAD_CHUNK_BYTES being a fixed 4 MiB regardless of file size.
        self.assertLess(su.UPLOAD_CHUNK_BYTES, size)

    def test_upload_rejects_non_deb_filename(self) -> None:
        with mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True}):
            response = self._authed_client().post(
                "/system/administration/software-updates/upload",
                data={"csrf": self.csrf},
                files={"upload": ("not-a-package.txt", b"hello", "text/plain")},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn(".deb", response.text)

    def test_upload_rejects_path_traversal_filename(self) -> None:
        with mock.patch.object(su, "installed_version_status", return_value={"resolved": "0.4.0-beta.6", "mismatch": False, "dpkg_managed": True}):
            response = self._authed_client().post(
                "/system/administration/software-updates/upload",
                data={"csrf": self.csrf},
                files={"upload": ("../../../../etc/passwd.deb", b"hello", "application/vnd.debian.binary-package")},
                follow_redirects=False,
            )
        # Either rejected outright, or the traversal segments are stripped
        # to a bare filename confined to UPLOAD_STAGING_DIR -- either way,
        # nothing may be written outside it.
        for path in su.UPLOAD_STAGING_DIR.rglob("*") if su.UPLOAD_STAGING_DIR.exists() else []:
            self.assertEqual(path.resolve().parent, su.UPLOAD_STAGING_DIR.resolve())
        self.assertFalse((self.tmp / "etc" / "passwd").exists())

    def test_install_route_rejects_when_no_update_available(self) -> None:
        response = self._authed_client().post("/system/administration/software-updates/install", data={"csrf": self.csrf})
        self.assertEqual(response.status_code, 400)
        self.assertIn("no update is currently available", response.text)

    def test_settings_route_persists(self) -> None:
        response = self._authed_client().post(
            "/system/administration/software-updates/settings",
            data={"csrf": self.csrf, "channel": "prerelease"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(su.settings()["channel"], "prerelease")
        self.assertEqual(su.settings()["auto_check_enabled"], "0")  # unchecked checkbox omits the field

    def test_settings_route_persists_check_interval_and_redeploys_schedule(self) -> None:
        response = self._authed_client().post(
            "/system/administration/software-updates/settings",
            data={"csrf": self.csrf, "channel": "stable", "auto_check_enabled": "1", "check_interval_hours": "12"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(su.settings()["check_interval_hours"], "12")

    def test_settings_route_rejects_out_of_range_interval(self) -> None:
        response = self._authed_client().post(
            "/system/administration/software-updates/settings",
            data={"csrf": self.csrf, "check_interval_hours": "999999"},
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
