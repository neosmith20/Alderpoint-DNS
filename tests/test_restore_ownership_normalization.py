#!/usr/bin/env python3
"""Regression coverage for a real restore failure found on a fresh v1
appliance: a restored TLS private key landed root:root 0640 (tar
extraction's "data" filter always extracts as the extracting process's own
uid/gid -- root:root, since restore runs as root -- regardless of what the
archive's numeric or named ownership claims), `dnsdist --check-config`
validated the config fine (it only checks syntax, not who can read a
referenced file), and the live `_dnsdist`-user dnsdist daemon then failed
to start with "Permission denied" opening it. A rollback attempt after a
later, unrelated failure hit the same class of problem restoring the
pre-restore file back.

Also covers the parallel restore-history secret leak found during that
investigation: `named-checkconf -p` echoes the fully rendered BIND config
verbatim, including any `key "name" { ...; secret "..."; };` block
(RNDC/TSIG shared secret), and that was being persisted into
restore_history.validation_output -- and therefore shown in the UI's
restore history -- completely unredacted.

These tests run as root (matching how restore actually executes) and use
the real, already-present `_dnsdist`/`alderpointdns` system accounts and a
real `sudo -u <user> -- test -r <path>` subprocess call to prove actual
runtime readability, exactly the way app/backup.py's own
_verify_runtime_readable() does -- never by reimplementing Unix
permission-bit logic.
"""
from __future__ import annotations

import contextlib
import grp
import os
import pwd
import stat
import subprocess
import sys
import unittest
import warnings
from contextlib import closing
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import backup  # noqa: E402
from tests.test_backup import BackupTestBase  # noqa: E402

CANARY_RNDC_SECRET = "CANARY-RNDC-SECRET-4f8c9e21-do-not-leak"


def _require_system_account(name: str) -> None:
    try:
        pwd.getpwnam(name)
    except KeyError:
        raise unittest.SkipTest(f"this host has no {name!r} system account (expected on the real appliance target)")


class _RealSudoRunMixin:
    """Like BackupTestBase.fake_run, but also lets `sudo` execute for
    real -- needed so _verify_runtime_readable()'s `sudo -u <user> -g
    <user> -- test -r <path>` calls exercise the *actual* kernel
    permission check against the tmp-sandboxed path and the real
    `_dnsdist`/`alderpointdns` system accounts, instead of being faked to
    an unconditional "ok" like every other subprocess call in these
    tests."""

    def _run_allow_real_sudo(self, command, check: bool = True, input_text=None, env=None):
        if command and (command[0] in self.PASSTHROUGH_COMMANDS or command[0] == "sudo"):
            return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, input=input_text, env=env)
        return self.fake_run(command, check=check, input_text=input_text, env=env)


class RestoreOwnershipNormalizationTest(_RealSudoRunMixin, BackupTestBase):
    def setUp(self) -> None:
        super().setUp()
        _require_system_account("_dnsdist")
        _require_system_account("alderpointdns")
        # tempfile.mkdtemp() (what BackupTestBase.setUp() used for self.tmp)
        # is mode 0700 -- root-only traversal. A real `/etc/...` tree is
        # world-traversable, so a real `sudo -u _dnsdist -- test -r <path>`
        # check against a file several directories under self.tmp would
        # otherwise fail on path *traversal*, not on the target file's own
        # permissions, which would make these tests fail for a reason that
        # has nothing to do with the code under test. Open up traversal
        # (not content) on every directory in the sandbox to match.
        for root, dirs, _files in os.walk(self.tmp):
            os.chmod(root, 0o755)

    def _make_backup(self):
        with mock.patch.object(backup, "run", self.fake_run):
            return backup.create_backup(dict.fromkeys(backup.COMPONENT_KEYS, True))

    def _restore(self, path) -> None:
        with mock.patch.object(backup, "run", self._run_allow_real_sudo), \
                mock.patch.object(backup, "resolves", return_value=True), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))

    def _real_sudo_can_read(self, path: Path, user: str) -> bool:
        proc = subprocess.run(["sudo", "-u", user, "-g", user, "--", "/usr/bin/test", "-r", str(path)], check=False)
        return proc.returncode == 0

    def test_restored_private_key_lands_readable_by_dnsdist_runtime_user(self) -> None:
        # BackupTestBase's fixture writes this file as plain root:root
        # (whatever write_text() as the test process produces) -- exactly
        # tar extraction's real behavior -- so this reproduces the actual
        # bug precondition, not an artificially-already-fixed one.
        path = self._make_backup()
        key_path = backup.CERT_DIR / "alderpointdns-lab.key"
        self._restore(path)
        st = os.stat(key_path)
        self.assertEqual("root", pwd.getpwuid(st.st_uid).pw_name)
        self.assertEqual("_dnsdist", grp.getgrgid(st.st_gid).gr_name)
        self.assertEqual(0o640, stat.S_IMODE(st.st_mode))
        self.assertTrue(
            self._real_sudo_can_read(key_path, "_dnsdist"),
            "the real _dnsdist system account cannot read the restored private key",
        )
        last = backup.last_restore()
        self.assertEqual("deployed", last["status"])
        self.assertIn("dnsdist runtime-read check for alderpointdns-lab.key: ok", last["validation_output"])

    def test_restored_cert_is_readable_and_not_secret(self) -> None:
        path = self._make_backup()
        cert_path = backup.CERT_DIR / "alderpointdns-lab.crt"
        self._restore(path)
        st = os.stat(cert_path)
        self.assertEqual(0o644, stat.S_IMODE(st.st_mode))
        self.assertTrue(self._real_sudo_can_read(cert_path, "_dnsdist"))

    def test_restored_alderpointdns_secrets_readable_by_alderpointdns_runtime_user(self) -> None:
        # app/webapp.py reads secrets.env directly at startup (session
        # secret) as the unprivileged alderpointdns.service process --
        # the same class of bug as the dnsdist key, just for a different
        # runtime account.
        path = self._make_backup()
        self._restore(path)
        for name in ("secrets.env", "dnsdist-api.key", "dnsdist-web.creds"):
            with self.subTest(name=name):
                p = backup.ETC_ALDERPOINTDNS / name
                st = os.stat(p)
                self.assertEqual("root", pwd.getpwuid(st.st_uid).pw_name)
                self.assertEqual("alderpointdns", grp.getgrgid(st.st_gid).gr_name)
                self.assertEqual(0o640, stat.S_IMODE(st.st_mode))
                self.assertTrue(self._real_sudo_can_read(p, "alderpointdns"), f"alderpointdns cannot read restored {name}")
        last = backup.last_restore()
        for name in ("secrets.env", "dnsdist-api.key", "dnsdist-web.creds"):
            self.assertIn(f"alderpointdns runtime-read check for {name}: ok", last["validation_output"])

    def test_do_not_broaden_permissions_ca_key_and_dnscrypt_provider_private_stay_root_root(self) -> None:
        # These two are never opened by the live dnsdist process (only used
        # offline to sign/issue other material) -- restore must not grant
        # _dnsdist (or anyone else) read access just because other keys in
        # the same directory need it.
        path_backup = backup.CERT_DIR / "alderpointdns-ca.key"
        path_backup.write_text("FAKE CA KEY\n")
        provider_private = backup.CERT_DIR / "dnscrypt-provider.private"
        provider_private.write_text("FAKE DNSCRYPT PROVIDER PRIVATE\n")
        path = self._make_backup()
        self._restore(path)
        for name in ("alderpointdns-ca.key", "dnscrypt-provider.private"):
            with self.subTest(name=name):
                p = backup.CERT_DIR / name
                st = os.stat(p)
                self.assertEqual("root", pwd.getpwuid(st.st_uid).pw_name)
                self.assertEqual("root", grp.getgrgid(st.st_gid).gr_name)
                self.assertEqual(0o600, stat.S_IMODE(st.st_mode))
                self.assertFalse(
                    self._real_sudo_can_read(p, "_dnsdist"),
                    f"_dnsdist should NOT be able to read {name} -- permissions were broadened unnecessarily",
                )

    def test_check_config_passing_does_not_mask_a_real_permission_failure(self) -> None:
        # Reproduces the exact reported gap: force ownership normalization
        # off (as if this fix did not exist) so the restored key lands
        # root:root like real tar extraction produces, and prove that
        # `dnsdist --check-config` (faked to always pass here, same as
        # every other test in this module -- it validates syntax only and
        # genuinely does not care about file ownership) is NOT sufficient
        # on its own: the runtime-readability check must catch it and the
        # restore must fail, not silently "succeed" into a state where the
        # live daemon can't actually start.
        # Match the exact reported precondition (mode 0640, not the
        # fixture's plain-write_text default of 0644): tar extraction's
        # "data" filter resets *ownership* but not permission *bits*, so a
        # real archived key keeps its 0640 mode -- meaning, unlike a
        # world-readable 0644 file, whether the *group* actually resolves
        # to _dnsdist is the only thing standing between "readable" and
        # "Permission denied".
        os.chmod(backup.CERT_DIR / "alderpointdns-lab.key", 0o640)
        path = self._make_backup()
        key_path = backup.CERT_DIR / "alderpointdns-lab.key"
        # Disable only the ownership *fix* (_apply_runtime_ownership),
        # leaving _runtime_ownership_for's policy lookup -- which is also
        # how restore_backup() decides *which* restored files need a
        # runtime-readability check -- intact. Blanking out the policy
        # lookup itself would also blind that detection and vacuously
        # "pass" this test by never checking anything at all.
        with mock.patch.object(backup, "_apply_runtime_ownership"):
            with mock.patch.object(backup, "run", self._run_allow_real_sudo), \
                    mock.patch.object(backup, "resolves", return_value=True), \
                    mock.patch.object(backup, "_wait_active", return_value=True):
                with self.assertRaises(RuntimeError):
                    backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        # Without normalization, the restored key really is root:root and
        # really is unreadable by _dnsdist -- confirming this test actually
        # reproduces the bug rather than failing for an unrelated reason.
        st = os.stat(key_path)
        self.assertEqual("root", grp.getgrgid(st.st_gid).gr_name)
        self.assertFalse(self._real_sudo_can_read(key_path, "_dnsdist"))
        last = backup.last_restore()
        self.assertIn(last["status"], ("rolled_back", "rollback_failed"))
        self.assertIn("FAILED", last["validation_output"])

    def test_rollback_repairs_preexisting_wrong_ownership_and_restores_dnsdist_access(self) -> None:
        # The pre-restore live key starts as plain root:root (the fixture's
        # default, unchanged) -- proving rollback actively *repairs*
        # ownership when it restores the pre-restore file, not merely that
        # it happens to preserve an already-correct state.
        path = self._make_backup()
        key_path = backup.CERT_DIR / "alderpointdns-lab.key"
        self.assertEqual("root", grp.getgrgid(os.stat(key_path).st_gid).gr_name)
        os.environ["ALDERPOINTDNS_TEST_FORCE_RESTORE_FAIL"] = "1"
        try:
            with mock.patch.object(backup, "run", self._run_allow_real_sudo), \
                    mock.patch.object(backup, "resolves", return_value=True), \
                    mock.patch.object(backup, "_wait_active", return_value=True):
                with self.assertRaises(RuntimeError):
                    backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        finally:
            del os.environ["ALDERPOINTDNS_TEST_FORCE_RESTORE_FAIL"]
        last = backup.last_restore()
        self.assertEqual("rolled_back", last["status"])
        st = os.stat(key_path)
        self.assertEqual("_dnsdist", grp.getgrgid(st.st_gid).gr_name)
        self.assertEqual(0o640, stat.S_IMODE(st.st_mode))
        self.assertTrue(
            self._real_sudo_can_read(key_path, "_dnsdist"),
            "rollback left the TLS private key unreadable by the dnsdist runtime user -- "
            "\"rollback restart did not restore working DNS\" would reproduce here",
        )


class RestoreHistorySecretRedactionTest(BackupTestBase):
    """A successful validation path (named-checkconf -p succeeding) must
    never persist the rendered BIND config -- including any RNDC/TSIG
    `secret "...";` block -- into restore_history.validation_output."""

    def _run_with_canary_named_checkconf(self, command, check: bool = True, input_text=None, env=None):
        if command and command[0] == "named-checkconf":
            rendered = (
                'options { directory "/var/cache/bind"; };\n'
                'key "rndc-key" {\n'
                '\talgorithm "hmac-sha256";\n'
                f'\tsecret "{CANARY_RNDC_SECRET}";\n'
                "};\n"
                "controls {\n"
                '\tinet 127.0.0.1 allow { 127.0.0.1; } keys { "rndc-key"; };\n'
                "};\n"
            )
            return subprocess.CompletedProcess(command, 0, rendered)
        return self.fake_run(command, check=check, input_text=input_text, env=env)

    def _make_backup(self):
        with mock.patch.object(backup, "run", self.fake_run):
            return backup.create_backup(dict.fromkeys(backup.COMPONENT_KEYS, True))

    def test_restore_history_never_contains_the_canary_secret_on_success(self) -> None:
        path = self._make_backup()
        with mock.patch.object(backup, "run", self._run_with_canary_named_checkconf), \
                mock.patch.object(backup, "resolves", return_value=True), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        last = backup.last_restore()
        self.assertEqual("deployed", last["status"])
        self._assert_canary_absent(last["validation_output"])
        self._assert_canary_absent(last["message"])
        # Never trust only the accessor -- read the raw persisted column
        # directly, since that's what the UI's restore history actually
        # renders.
        with closing(backup.connect()) as conn:
            raw = conn.execute("SELECT validation_output, message FROM restore_history ORDER BY id DESC LIMIT 1").fetchone()
        self._assert_canary_absent(raw["validation_output"])
        self._assert_canary_absent(raw["message"])
        self.assertIn("[REDACTED]", raw["validation_output"] or "")

    def test_restore_history_never_contains_the_canary_secret_on_failure(self) -> None:
        # The redaction must not be conditional on the happy path -- a
        # failed/rolled-back restore's validation_output/message are
        # persisted too (see the finally block), from the exact same
        # accumulated text.
        path = self._make_backup()
        os.environ["ALDERPOINTDNS_TEST_FORCE_RESTORE_FAIL"] = "1"
        try:
            with mock.patch.object(backup, "run", self._run_with_canary_named_checkconf), \
                    mock.patch.object(backup, "resolves", return_value=True), \
                    mock.patch.object(backup, "_wait_active", return_value=True):
                with self.assertRaises(RuntimeError):
                    backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        finally:
            del os.environ["ALDERPOINTDNS_TEST_FORCE_RESTORE_FAIL"]
        with closing(backup.connect()) as conn:
            raw = conn.execute("SELECT validation_output, message, status FROM restore_history ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIn(raw["status"], ("rolled_back", "rollback_failed"))
        self._assert_canary_absent(raw["validation_output"])
        self._assert_canary_absent(raw["message"])

    def _assert_canary_absent(self, text: str | None) -> None:
        self.assertNotIn(CANARY_RNDC_SECRET, text or "", "a synthetic secret leaked into restore_history unredacted")


class RestoreFailureUiWordingTest(unittest.TestCase):
    """The restore route's error message must never point at a
    nonexistent "restore history table". Since backup_restore_apply() now
    only dispatches the independent runner unit and returns immediately
    (see BackupRestoreAsyncDispatchHttpTest), the route no longer emits a
    message about the restore's *outcome* at all -- the actual outcome is
    always visible on the page via the "Last Restore" card, which must
    still exist in the template regardless."""

    def test_backup_restore_route_never_references_a_nonexistent_table(self) -> None:
        source = (ROOT / "app" / "webapp.py").read_text()
        self.assertNotIn("restore history table", source)

    def test_last_restore_card_still_exists_in_the_template(self) -> None:
        with (ROOT / "web" / "templates" / "backup.html").open() as fh:
            template = fh.read()
        self.assertIn("Last Restore", template)


if __name__ == "__main__":
    unittest.main()
