#!/usr/bin/env python3
"""Tests for app.encryption.ensure_doh_altsvc_migration(): the narrowly-scoped,
repeatable migration that brings an already-migrated (pre-Alt-Svc)
dnsdist.conf up to the current doh-altsvc managed block without a full
re-template, so an upgraded install picks up Alt-Svc support without
discarding anything an administrator hand-edited elsewhere in the file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import encryption  # noqa: E402

REAL_TEMPLATE = ROOT / "packaging" / "dnsdist.conf"
BETA4_TEMPLATE = ROOT / "tests" / "fixtures" / "dnsdist-beta4.conf.tmpl"


def _beta4_conf_text() -> str:
    text = BETA4_TEMPLATE.read_text()
    text = text.replace("ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER", "realconsolekey")
    text = text.replace("ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER", "realpassword")
    text = text.replace("ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER", "realapikey")
    return text


def _ok_check_config(command, check=True, env=None, input_text=None):
    return subprocess.CompletedProcess(command, 0, "Configuration OK\n")


def _failing_check_config(command, check=True, env=None, input_text=None):
    return subprocess.CompletedProcess(command, 1, "syntax error near 'end'\n")


class DohAltsvcMigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-altsvc-migration-test-"))
        self.old = {
            "DNSDIST_CONF": encryption.DNSDIST_CONF,
            "DNSDIST_ENV_OVERRIDE": encryption.DNSDIST_ENV_OVERRIDE,
            "BACKUP_DIR": encryption.BACKUP_DIR,
        }
        encryption.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        encryption.DNSDIST_ENV_OVERRIDE = self.tmp / "alderpointdns.conf"
        encryption.BACKUP_DIR = self.tmp / "backups"

    def tearDown(self) -> None:
        for key, value in self.old.items():
            setattr(encryption, key, value)

    def _write_current(self, text: str) -> None:
        encryption.DNSDIST_CONF.write_text(text)

    # -- beta.4-style configuration migrates correctly -----------------------

    def test_beta4_configuration_without_altsvc_migrates_correctly(self) -> None:
        self._write_current(_beta4_conf_text())
        with mock.patch.object(encryption, "run", side_effect=_ok_check_config):
            changed, message = encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        self.assertTrue(changed)
        self.assertIn("doh-altsvc migration", message)
        new_text = encryption.DNSDIST_CONF.read_text()
        self.assertIn(encryption.DOH_ALTSVC_MARKER_BEGIN, new_text)
        self.assertIn(encryption.DOH_ALTSVC_MARKER_END, new_text)
        self.assertIn("customResponseHeaders", new_text)
        self.assertIn('["alt-svc"]', new_text)

    # -- unrelated local edits survive ---------------------------------------

    def test_unrelated_local_edits_survive_migration(self) -> None:
        text = _beta4_conf_text()
        marker_comment = "-- LOCAL ADMIN EDIT: custom rate limit tuning, do not remove\n"
        text = text.replace(
            'setSecurityPollSuffix("")',
            marker_comment + 'setSecurityPollSuffix("")',
        )
        text = text.replace(
            'dbr:setQueryRate(120, 10, "Alderpoint DNS private resolver query rate limit", 60)',
            'dbr:setQueryRate(500, 10, "Locally raised rate limit", 60)',
        )
        self._write_current(text)
        with mock.patch.object(encryption, "run", side_effect=_ok_check_config):
            changed, _ = encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        self.assertTrue(changed)
        new_text = encryption.DNSDIST_CONF.read_text()
        self.assertIn(marker_comment.strip(), new_text)
        self.assertIn('dbr:setQueryRate(500, 10, "Locally raised rate limit", 60)', new_text)
        # And the migration only touched the dohEnabled block, not the rate limit line above it.
        self.assertNotIn('dbr:setQueryRate(120, 10, "Alderpoint DNS private resolver query rate limit", 60)', new_text)

    # -- already-migrated configuration remains byte-stable ------------------

    def test_already_migrated_configuration_is_byte_stable(self) -> None:
        self._write_current(_beta4_conf_text())
        with mock.patch.object(encryption, "run", side_effect=_ok_check_config):
            changed, _ = encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        self.assertTrue(changed)
        migrated_text = encryption.DNSDIST_CONF.read_text()
        migrated_mtime_content = migrated_text
        with mock.patch.object(encryption, "run", side_effect=_ok_check_config) as run_mock:
            changed_again, message_again = encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        self.assertFalse(changed_again)
        self.assertEqual(message_again, "")
        run_mock.assert_not_called()  # no-op must not even attempt to validate/re-check
        self.assertEqual(encryption.DNSDIST_CONF.read_text(), migrated_mtime_content)

    def test_second_upgrade_run_makes_no_additional_changes(self) -> None:
        # Simulates running the migration twice across two upgrades.
        self._write_current(_beta4_conf_text())
        with mock.patch.object(encryption, "run", side_effect=_ok_check_config):
            encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        first_pass = encryption.DNSDIST_CONF.read_text()
        with mock.patch.object(encryption, "run", side_effect=_ok_check_config):
            encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        second_pass = encryption.DNSDIST_CONF.read_text()
        self.assertEqual(first_pass, second_pass)

    # -- invalid generated configuration triggers rollback -------------------

    def test_invalid_migrated_configuration_rolls_back(self) -> None:
        original = _beta4_conf_text()
        self._write_current(original)
        with mock.patch.object(encryption, "run", side_effect=_failing_check_config):
            with self.assertRaises(encryption.EncryptionError) as ctx:
                encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        self.assertIn("rolled back", str(ctx.exception))
        # The live file must be restored to exactly what it was before.
        self.assertEqual(encryption.DNSDIST_CONF.read_text(), original)
        backups = list(encryption.BACKUP_DIR.glob("dnsdist.conf.pre-doh-altsvc-migration.*"))
        self.assertTrue(backups, "expected a backup to have been written before the failed migration attempt")

    # -- fresh-install behavior remains correct ------------------------------

    def test_fresh_install_conf_already_matching_template_is_a_no_op(self) -> None:
        # A brand-new install's dnsdist.conf is produced directly from the
        # current template (via ensure_dnsdist_conf_parameterized), so it
        # already contains the doh-altsvc managed block from day one.
        fresh_conf = REAL_TEMPLATE.read_text()
        fresh_conf = fresh_conf.replace("ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER", "freshkey")
        fresh_conf = fresh_conf.replace("ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER", "freshpass")
        fresh_conf = fresh_conf.replace("ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER", "freshapikey")
        self._write_current(fresh_conf)
        with mock.patch.object(encryption, "run", side_effect=_ok_check_config) as run_mock:
            changed, message = encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        self.assertFalse(changed)
        self.assertEqual(message, "")
        run_mock.assert_not_called()
        self.assertEqual(encryption.DNSDIST_CONF.read_text(), fresh_conf)

    def test_conf_predating_base_parameterization_is_left_for_that_migration(self) -> None:
        self._write_current('setKey("realconsolekey")\nsetWebserverConfig({password="x", apiKey="y"})\n')
        changed, message = encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        self.assertFalse(changed)
        self.assertEqual(message, "")

    def test_hand_edited_dohenabled_block_is_not_touched(self) -> None:
        text = _beta4_conf_text()
        # Simulate an administrator's own customization of the DoH listener
        # block (e.g. an extra option) -- no longer matches the known exact
        # beta.4 shape, so the migration must not guess at how to patch it.
        text = text.replace('ciphers="HIGH:!aNULL:!MD5:!RC4"\n    })\n  end\n  if listenIPv6', 'ciphers="HIGH:!aNULL:!MD5:!RC4",\n      maxConcurrentTCPConnections=5000\n    })\n  end\n  if listenIPv6', 1)
        self._write_current(text)
        with mock.patch.object(encryption, "run", side_effect=_ok_check_config) as run_mock:
            changed, message = encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        self.assertFalse(changed)
        self.assertIn("skipped", message)
        self.assertIn("hand-edited", message)
        run_mock.assert_not_called()
        self.assertEqual(encryption.DNSDIST_CONF.read_text(), text)

    # -- DoH3 enabled/disabled Alt-Svc behavior after migration --------------

    def test_migrated_conf_advertises_altsvc_only_when_doh3_enabled(self) -> None:
        self._write_current(_beta4_conf_text())
        with mock.patch.object(encryption, "run", side_effect=_ok_check_config):
            encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        migrated = encryption.DNSDIST_CONF.read_text()
        self.assertIn("if doh3Enabled then", migrated)
        self.assertIn('alderpointdnsDohOptions.customResponseHeaders', migrated)


@unittest.skipUnless(__import__("shutil").which("dnsdist"), "requires a real dnsdist binary to validate against")
class DohAltsvcMigrationRealDnsdistTest(unittest.TestCase):
    """Runs the same migration against the real dnsdist --check-config, no
    mocking of run() at all, when a dnsdist binary is actually available
    (this sandbox has dnsdist 2.1 installed)."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-altsvc-real-test-"))
        self.old = {
            "DNSDIST_CONF": encryption.DNSDIST_CONF,
            "DNSDIST_ENV_OVERRIDE": encryption.DNSDIST_ENV_OVERRIDE,
            "BACKUP_DIR": encryption.BACKUP_DIR,
        }
        encryption.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        encryption.DNSDIST_ENV_OVERRIDE = self.tmp / "alderpointdns.conf"
        encryption.BACKUP_DIR = self.tmp / "backups"

    def tearDown(self) -> None:
        for key, value in self.old.items():
            setattr(encryption, key, value)

    def test_real_check_config_accepts_migrated_conf(self) -> None:
        encryption.DNSDIST_CONF.write_text(_beta4_conf_text())
        changed, message = encryption.ensure_doh_altsvc_migration(REAL_TEMPLATE)
        self.assertTrue(changed)
        self.assertIn("doh-altsvc migration", message)
        self.assertIn(encryption.DOH_ALTSVC_MARKER_BEGIN, encryption.DNSDIST_CONF.read_text())


def _tool_usable(*args: str) -> bool:
    try:
        return subprocess.run(list(args), capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _netns_usable() -> bool:
    if os.geteuid() != 0:
        return False
    netns = "alderpointdns-altsvc-probe"
    subprocess.run(["ip", "netns", "del", netns], stderr=subprocess.DEVNULL)
    ok = subprocess.run(["ip", "netns", "add", netns], capture_output=True).returncode == 0
    subprocess.run(["ip", "netns", "del", netns], stderr=subprocess.DEVNULL)
    return ok


_LIVE_HEADER_TEST_USABLE = (
    shutil.which("dnsdist") is not None
    and shutil.which("curl") is not None
    and shutil.which("openssl") is not None
    and shutil.which("ip") is not None
    and _netns_usable()
)


@unittest.skipUnless(_LIVE_HEADER_TEST_USABLE, "requires root, dnsdist, curl, openssl, and usable network namespaces")
class DohAltsvcLiveHeaderTest(unittest.TestCase):
    """End-to-end proof that the migrated managed block actually controls a
    real DoH HTTP response header, not just that it validates syntactically.

    Runs a throwaway dnsdist instance inside its own network namespace (so it
    can never collide with a real Alderpoint DNS install's ports on the same
    host) against the exact current packaging/dnsdist.conf template, and
    checks the live `alt-svc` response header with DoH3 enabled and disabled.
    """

    NETNS = "alderpointdns-altsvc-livetest"

    def setUp(self) -> None:
        subprocess.run(["ip", "netns", "del", self.NETNS], stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "netns", "add", self.NETNS], check=True)
        subprocess.run(["ip", "netns", "exec", self.NETNS, "ip", "link", "set", "lo", "up"], check=True)
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-altsvc-livetest-"))
        template = REAL_TEMPLATE.read_text()
        template = template.replace("ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER", "testconsolekey")
        template = template.replace("ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER", "testpassword")
        template = template.replace("ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER", "testapikey")
        self.conf = self.tmp / "dnsdist.conf"
        self.conf.write_text(template)
        self.crt, self.key = self.tmp / "test.crt", self.tmp / "test.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-nodes",
             "-subj", "/CN=test.local", "-keyout", str(self.key), "-out", str(self.crt)],
            check=True, capture_output=True,
        )
        self._proc = None

    def tearDown(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        subprocess.run(["ip", "netns", "del", self.NETNS], stderr=subprocess.DEVNULL)

    def _start_dnsdist(self, doh3_enabled: str) -> None:
        env = {
            **os.environ,
            "ALDERPOINTDNS_DNS_PLAIN": "0",
            "ALDERPOINTDNS_DNS_LISTEN_IPV4": "127.0.0.1",
            "ALDERPOINTDNS_DNS_LISTEN_IPV6": "",
            "ALDERPOINTDNS_DNS_DOH": "1",
            "ALDERPOINTDNS_DNS_DOT": "0",
            "ALDERPOINTDNS_DNS_DOQ": "0",
            "ALDERPOINTDNS_DNS_DOH3": doh3_enabled,
            "ALDERPOINTDNS_DNS_DNSCRYPT": "0",
            "ALDERPOINTDNS_TLS_CERT": str(self.crt),
            "ALDERPOINTDNS_TLS_KEY": str(self.key),
            "ALDERPOINTDNS_DOH_PORT": "443",
            "ALDERPOINTDNS_DOH3_PORT": "444",
        }
        log = open(self.tmp / "dnsdist.log", "wb")
        self._proc = subprocess.Popen(
            ["ip", "netns", "exec", self.NETNS, "dnsdist", "-C", str(self.conf), "--supervised", "--disable-syslog"],
            env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            probe = subprocess.run(["ip", "netns", "exec", self.NETNS, "ss", "-H", "-ltnp"], capture_output=True, text=True)
            if ":443" in probe.stdout:
                return
            time.sleep(0.2)
        raise AssertionError(f"dnsdist did not start listening on :443 in time; log:\n{(self.tmp / 'dnsdist.log').read_text()}")

    def _doh_response_headers(self) -> str:
        query = "q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
        result = subprocess.run(
            ["ip", "netns", "exec", self.NETNS, "curl", "-sk", "-D", "-", "--http2",
             f"https://127.0.0.1:443/dns-query?dns={query}",
             "-H", "accept: application/dns-message", "-o", "/dev/null"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout

    def test_doh3_enabled_returns_altsvc_header(self) -> None:
        self._start_dnsdist(doh3_enabled="1")
        headers = self._doh_response_headers()
        self.assertIn('alt-svc: h3=":444"; ma=86400', headers.lower())

    def test_doh3_disabled_does_not_return_altsvc_header(self) -> None:
        self._start_dnsdist(doh3_enabled="0")
        headers = self._doh_response_headers()
        self.assertNotIn("alt-svc", headers.lower())


if __name__ == "__main__":
    unittest.main()
