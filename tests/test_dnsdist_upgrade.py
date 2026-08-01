#!/usr/bin/env python3
"""Tests for the opt-in `alderpointdns install-enhanced-dnsdist` installer
(app/dnsdist_upgrade.py). This never touches a real system: every
subprocess/network-facing function is mocked, and every step is verified to
fail closed -- an abort at any point must leave the report reflecting no
partial success and must attempt a config restore from the backup it took.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import dnsdist_upgrade  # noqa: E402

STOCK_CAPS = {"doh": True, "dot": True, "doq": False, "doh3": False, "dnscrypt": True}
QUIC_CAPS = {"doh": True, "dot": True, "doq": True, "doh3": True, "dnscrypt": True}


class OsSupportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-osrelease-test-"))

    def _write(self, content: str) -> Path:
        path = self.tmp / "os-release"
        path.write_text(content)
        return path

    def test_accepts_debian_13(self) -> None:
        path = self._write('ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n')
        dnsdist_upgrade.check_os_supported(path)  # must not raise

    def test_rejects_ubuntu(self) -> None:
        path = self._write('ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n')
        with self.assertRaises(dnsdist_upgrade.UpgradeError):
            dnsdist_upgrade.check_os_supported(path)

    def test_rejects_debian_12(self) -> None:
        path = self._write('ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
        with self.assertRaises(dnsdist_upgrade.UpgradeError):
            dnsdist_upgrade.check_os_supported(path)

    def test_missing_os_release_fails_closed(self) -> None:
        with self.assertRaises(dnsdist_upgrade.UpgradeError):
            dnsdist_upgrade.check_os_supported(self.tmp / "does-not-exist")


class SigningKeyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-key-test-"))

    def _write_key(self, body: str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nzz\n-----END PGP PUBLIC KEY BLOCK-----\n") -> Path:
        path = self.tmp / "key.asc"
        path.write_text(body)
        return path

    def test_rejects_non_pgp_content(self) -> None:
        path = self.tmp / "key.asc"
        path.write_text("<html>404 not found</html>")
        with self.assertRaises(dnsdist_upgrade.UpgradeError):
            dnsdist_upgrade.verify_signing_key(path)

    def test_accepts_matching_fingerprint(self) -> None:
        path = self._write_key()
        fake_gpg_output = "fpr:::::::::9FAAA5577E8FCF62093D036C1B0C6205FD380FBB:\n"
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 0, fake_gpg_output)):
            dnsdist_upgrade.verify_signing_key(path, expected_fingerprint="9FAAA5577E8FCF62093D036C1B0C6205FD380FBB")

    def test_rejects_wrong_fingerprint(self) -> None:
        path = self._write_key()
        fake_gpg_output = "fpr:::::::::0000000000000000000000000000000000000000:\n"
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 0, fake_gpg_output)):
            with self.assertRaises(dnsdist_upgrade.UpgradeError):
                dnsdist_upgrade.verify_signing_key(path, expected_fingerprint="9FAAA5577E8FCF62093D036C1B0C6205FD380FBB")

    def test_empty_key_download_fails_closed(self) -> None:
        dest = self.tmp / "empty.asc"
        dest.write_bytes(b"")
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 0, "")):
            with self.assertRaises(dnsdist_upgrade.UpgradeError):
                dnsdist_upgrade.download_signing_key(dest)

    def test_download_failure_raises_fail_closed(self) -> None:
        dest = self.tmp / "key.asc"
        with mock.patch.object(dnsdist_upgrade, "run", side_effect=subprocess.CalledProcessError(6, ["curl"], output="could not resolve host")):
            with self.assertRaises(dnsdist_upgrade.UpgradeError):
                dnsdist_upgrade.download_signing_key(dest)


class AptPolicyTest(unittest.TestCase):
    def test_accepts_supported_2_1_candidate_from_powerdns(self) -> None:
        output = (
            "dnsdist:\n"
            "  Installed: 1.9.15-0+deb13u1\n"
            "  Candidate: 2.1.0-1pdns.debian13\n"
            "  Version table:\n"
            " *** 2.1.0-1pdns.debian13 600\n"
            "        600 http://repo.powerdns.com/debian trixie-dnsdist-21/main amd64 Packages\n"
            "     1.9.15-0+deb13u1 500\n"
            "        500 http://deb.debian.org/debian trixie/main amd64 Packages\n"
        )
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 0, output)):
            self.assertEqual(dnsdist_upgrade.apt_policy_candidate(), "2.1.0-1pdns.debian13")

    def test_rejects_non_2_1_candidate(self) -> None:
        output = "dnsdist:\n  Candidate: 1.9.15-0+deb13u1\n  Version table:\n"
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 0, output)):
            with self.assertRaises(dnsdist_upgrade.UpgradeError):
                dnsdist_upgrade.apt_policy_candidate()

    def test_rejects_candidate_not_from_powerdns_origin(self) -> None:
        # Malicious/misconfigured mirror serving a 2.1.x-looking version string
        # from somewhere that isn't repo.powerdns.com at all.
        output = (
            "dnsdist:\n"
            "  Candidate: 2.1.0-1evil\n"
            "  Version table:\n"
            " *** 2.1.0-1evil 600\n"
            "        600 http://mirror.example.com/debian trixie/main amd64 Packages\n"
        )
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 0, output)):
            with self.assertRaises(dnsdist_upgrade.UpgradeError):
                dnsdist_upgrade.apt_policy_candidate()

    def test_missing_candidate_fails_closed(self) -> None:
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 100, "N: Unable to locate package dnsdist\n")):
            with self.assertRaises(dnsdist_upgrade.UpgradeError):
                dnsdist_upgrade.apt_policy_candidate()


class SimulateInstallTest(unittest.TestCase):
    def test_safe_simulation_passes(self) -> None:
        output = "Inst dnsdist [1.9.15-0+deb13u1] (2.1.0-1pdns.debian13 repo.powerdns.com)\n"
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 0, output)):
            dnsdist_upgrade.simulate_install()  # must not raise

    def test_unsafe_simulation_removing_bind_fails_closed(self) -> None:
        output = "Remv bind9 [1:9.18.0]\nInst dnsdist [1.9.15] (2.1.0-1pdns.debian13 repo.powerdns.com)\n"
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 0, output)):
            with self.assertRaises(dnsdist_upgrade.UpgradeError):
                dnsdist_upgrade.simulate_install()

    def test_unsafe_simulation_removing_alderpointdns_fails_closed(self) -> None:
        output = "Remv alderpointdns [0.4.0]\n"
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 0, output)):
            with self.assertRaises(dnsdist_upgrade.UpgradeError):
                dnsdist_upgrade.simulate_install()

    def test_simulation_nonzero_exit_fails_closed(self) -> None:
        with mock.patch.object(dnsdist_upgrade, "run", return_value=subprocess.CompletedProcess([], 100, "E: broken\n")):
            with self.assertRaises(dnsdist_upgrade.UpgradeError):
                dnsdist_upgrade.simulate_install()


class EnableQuicTransportsOrchestrationTest(unittest.TestCase):
    """Exercises the full install_enhanced_dnsdist() control flow with every
    OS-touching step mocked, to prove idempotency and fail-closed behavior
    without ever touching a real system."""

    def setUp(self) -> None:
        self.addCleanup(mock.patch.stopall)
        # Steps that always run early and are safe to no-op unless a test
        # overrides them to simulate a specific failure.
        mock.patch.object(dnsdist_upgrade, "check_os_supported", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "detect_architecture", return_value="amd64").start()
        mock.patch.object(dnsdist_upgrade, "resolve_repo_host", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "backup_state", return_value=Path("/tmp/fake-backup.tar.gz")).start()
        mock.patch.object(dnsdist_upgrade, "download_signing_key", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "verify_signing_key", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "install_keyring", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "write_apt_sources", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "apt_update", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "apt_policy_candidate", return_value="2.1.0-1pdns.debian13").start()
        mock.patch.object(dnsdist_upgrade, "simulate_install", return_value="Inst dnsdist [...]").start()
        mock.patch.object(dnsdist_upgrade, "apt_install", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "check_config", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "restart_dnsdist_and_verify_services", return_value=None).start()
        mock.patch.object(dnsdist_upgrade, "baseline_dns_test", return_value=None).start()
        self.restore_mock = mock.patch.object(dnsdist_upgrade, "restore_config_from_backup", return_value=None).start()
        self.caps_mock = mock.patch.object(dnsdist_upgrade, "dnsdist_capabilities").start()
        self.version_mock = mock.patch.object(dnsdist_upgrade, "dnsdist_version").start()

    def test_already_satisfied_is_idempotent_no_op(self) -> None:
        self.caps_mock.return_value = QUIC_CAPS
        self.version_mock.return_value = "dnsdist 2.1.0"
        apt_update = mock.patch.object(dnsdist_upgrade, "apt_update").start()
        report = dnsdist_upgrade.install_enhanced_dnsdist()
        self.assertTrue(report.already_satisfied)
        self.assertFalse(report.changed)
        apt_update.assert_not_called()
        # Running it again must behave identically -- no accumulated state.
        report2 = dnsdist_upgrade.install_enhanced_dnsdist()
        self.assertTrue(report2.already_satisfied)

    def test_successful_upgrade_reports_changed(self) -> None:
        self.caps_mock.side_effect = [STOCK_CAPS, QUIC_CAPS]
        self.version_mock.side_effect = ["dnsdist 1.9.15", "dnsdist 2.1.0"]
        report = dnsdist_upgrade.install_enhanced_dnsdist()
        self.assertTrue(report.changed)
        self.assertFalse(report.already_satisfied)
        self.assertEqual(report.version_after, "dnsdist 2.1.0")
        self.restore_mock.assert_not_called()

    def _assert_fails_closed_and_rolls_back(self) -> None:
        with self.assertRaises(dnsdist_upgrade.UpgradeError) as ctx:
            dnsdist_upgrade.install_enhanced_dnsdist()
        self.restore_mock.assert_called_once()
        self.assertIn("Rollback", str(ctx.exception))
        return ctx.exception

    def test_dns_resolution_failure_fails_closed(self) -> None:
        self.caps_mock.return_value = STOCK_CAPS
        self.version_mock.return_value = "dnsdist 1.9.15"
        mock.patch.object(dnsdist_upgrade, "resolve_repo_host", side_effect=dnsdist_upgrade.UpgradeError("could not resolve repo.powerdns.com")).start()
        with self.assertRaises(dnsdist_upgrade.UpgradeError):
            dnsdist_upgrade.install_enhanced_dnsdist()
        # DNS failure happens before the backup step, so no rollback is attempted.
        self.restore_mock.assert_not_called()

    def test_key_download_failure_fails_closed_and_rolls_back(self) -> None:
        self.caps_mock.return_value = STOCK_CAPS
        self.version_mock.return_value = "dnsdist 1.9.15"
        mock.patch.object(dnsdist_upgrade, "download_signing_key", side_effect=dnsdist_upgrade.UpgradeError("download failed")).start()
        self._assert_fails_closed_and_rolls_back()

    def test_wrong_fingerprint_fails_closed_and_rolls_back(self) -> None:
        self.caps_mock.return_value = STOCK_CAPS
        self.version_mock.return_value = "dnsdist 1.9.15"
        mock.patch.object(dnsdist_upgrade, "verify_signing_key", side_effect=dnsdist_upgrade.UpgradeError("fingerprint mismatch")).start()
        self._assert_fails_closed_and_rolls_back()

    def test_bad_repo_metadata_fails_closed_and_rolls_back(self) -> None:
        self.caps_mock.return_value = STOCK_CAPS
        self.version_mock.return_value = "dnsdist 1.9.15"
        mock.patch.object(dnsdist_upgrade, "apt_policy_candidate", side_effect=dnsdist_upgrade.UpgradeError("candidate does not originate from repo.powerdns.com")).start()
        self._assert_fails_closed_and_rolls_back()

    def test_unsafe_simulation_fails_closed_and_rolls_back(self) -> None:
        self.caps_mock.return_value = STOCK_CAPS
        self.version_mock.return_value = "dnsdist 1.9.15"
        mock.patch.object(dnsdist_upgrade, "simulate_install", side_effect=dnsdist_upgrade.UpgradeError("would remove bind9")).start()
        apt_install = mock.patch.object(dnsdist_upgrade, "apt_install").start()
        self._assert_fails_closed_and_rolls_back()
        apt_install.assert_not_called()

    def test_config_validation_failure_fails_closed_and_rolls_back(self) -> None:
        self.caps_mock.side_effect = [STOCK_CAPS, QUIC_CAPS]
        self.version_mock.side_effect = ["dnsdist 1.9.15", "dnsdist 2.1.0"]
        mock.patch.object(dnsdist_upgrade, "check_config", side_effect=dnsdist_upgrade.UpgradeError("check-config failed")).start()
        restart = mock.patch.object(dnsdist_upgrade, "restart_dnsdist_and_verify_services").start()
        self._assert_fails_closed_and_rolls_back()
        restart.assert_not_called()

    def test_service_restart_failure_fails_closed_and_rolls_back(self) -> None:
        self.caps_mock.side_effect = [STOCK_CAPS, QUIC_CAPS]
        self.version_mock.side_effect = ["dnsdist 1.9.15", "dnsdist 2.1.0"]
        mock.patch.object(
            dnsdist_upgrade, "restart_dnsdist_and_verify_services",
            side_effect=dnsdist_upgrade.UpgradeError("service(s) not active after restart: named"),
        ).start()
        self._assert_fails_closed_and_rolls_back()

    def test_missing_capabilities_after_install_fails_closed_and_rolls_back(self) -> None:
        # Installed candidate looked right, but the resulting binary still
        # doesn't actually report the required features -- must not be
        # reported as success just because apt_install() returned 0.
        self.caps_mock.side_effect = [STOCK_CAPS, STOCK_CAPS]
        self.version_mock.side_effect = ["dnsdist 1.9.15", "dnsdist 1.9.15"]
        check_config = mock.patch.object(dnsdist_upgrade, "check_config").start()
        self._assert_fails_closed_and_rolls_back()
        check_config.assert_not_called()


if __name__ == "__main__":
    unittest.main()
