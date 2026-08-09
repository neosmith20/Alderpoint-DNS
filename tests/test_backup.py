#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import warnings
from contextlib import closing
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import backup  # noqa: E402


class BackupTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-backup-test-"))
        self.old = {name: getattr(backup, name) for name in (
            "DB_PATH", "BACKUP_DIR", "STAGING_DIR", "IMPORTS_DIR",
            "ETC_ALDERPOINTDNS", "CERT_DIR", "SECRETS_ENV", "DNSDIST_API_KEY", "DNSDIST_WEB_CREDS",
            "ETC_BIND", "ETC_DNSDIST", "DNSDIST_CONF", "COMPILED_DIR", "LOCAL_ZONE_DIR",
            "LOCAL_ZONES_CONF", "DOWNLOADS_DIR", "SYSTEMD_DIR", "SUDOERS_FILE",
        )}

        backup.DB_PATH = self.tmp / "alderpointdns.db"
        backup.BACKUP_DIR = self.tmp / "backups"
        backup.STAGING_DIR = self.tmp / "staging"
        backup.IMPORTS_DIR = backup.STAGING_DIR / "backup-imports"
        backup.ETC_ALDERPOINTDNS = self.tmp / "etc" / "alderpointdns"
        backup.CERT_DIR = backup.ETC_ALDERPOINTDNS / "certs"
        backup.SECRETS_ENV = backup.ETC_ALDERPOINTDNS / "secrets.env"
        backup.DNSDIST_API_KEY = backup.ETC_ALDERPOINTDNS / "dnsdist-api.key"
        backup.DNSDIST_WEB_CREDS = backup.ETC_ALDERPOINTDNS / "dnsdist-web.creds"
        backup.ETC_BIND = self.tmp / "etc" / "bind"
        backup.ETC_DNSDIST = self.tmp / "etc" / "dnsdist"
        backup.DNSDIST_CONF = backup.ETC_DNSDIST / "dnsdist.conf"
        backup.COMPILED_DIR = self.tmp / "compiled"
        backup.LOCAL_ZONE_DIR = backup.COMPILED_DIR / "bind" / "local"
        backup.LOCAL_ZONES_CONF = backup.COMPILED_DIR / "bind" / "local-zones.conf"
        backup.DOWNLOADS_DIR = self.tmp / "downloads"
        backup.SYSTEMD_DIR = self.tmp / "systemd"
        backup.SUDOERS_FILE = self.tmp / "sudoers-alderpointdns"

        for path in (backup.STAGING_DIR, backup.BACKUP_DIR, backup.ETC_ALDERPOINTDNS, backup.CERT_DIR,
                     backup.ETC_BIND, backup.ETC_DNSDIST, backup.COMPILED_DIR, backup.LOCAL_ZONE_DIR,
                     backup.DOWNLOADS_DIR, backup.SYSTEMD_DIR):
            path.mkdir(parents=True, exist_ok=True)

        backup.ETC_BIND.joinpath("named.conf").write_text("options {};\n")
        backup.ETC_BIND.joinpath("named.conf.local").write_text("// local\n")
        backup.ETC_BIND.joinpath("named.conf.options").write_text("options {};\n")
        backup.DNSDIST_CONF.write_text("setLocal('127.0.0.1:53')\n")
        backup.CERT_DIR.joinpath("alderpointdns-lab.crt").write_text("PUBLIC CERT\n")
        backup.CERT_DIR.joinpath("alderpointdns-lab.key").write_text("PRIVATE KEY\n")
        backup.SECRETS_ENV.write_text("ALDERPOINTDNS_SESSION_SECRET=topsecret\n")
        backup.DNSDIST_API_KEY.write_text("apikeyvalue\n")
        backup.DNSDIST_WEB_CREDS.write_text("webcredsvalue\n")
        backup.COMPILED_DIR.joinpath("bind").mkdir(parents=True, exist_ok=True)
        backup.COMPILED_DIR.joinpath("bind", "cache-options.conf").write_text("max-cache-size 128m;\n")
        backup.LOCAL_ZONE_DIR.mkdir(parents=True, exist_ok=True)
        backup.LOCAL_ZONE_DIR.joinpath("home.arpa.zone").write_text("$TTL 300\n")
        backup.LOCAL_ZONES_CONF.write_text("// local zones\n")
        backup.DOWNLOADS_DIR.joinpath("current").mkdir(parents=True, exist_ok=True)
        backup.DOWNLOADS_DIR.joinpath("current", "1-source.txt").write_text("example.com\n")
        backup.SUDOERS_FILE.write_text("alderpointdns ALL=(root) NOPASSWD: /opt/alderpointdns/app/alderpointdns_compiler.py deploy\n")

        backup.init_db()
        with closing(backup.connect()) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sources (id INTEGER PRIMARY KEY, name TEXT);
                CREATE TABLE IF NOT EXISTS custom_rules (id INTEGER PRIMARY KEY, domain TEXT);
                CREATE TABLE IF NOT EXISTS local_dns_records (id INTEGER PRIMARY KEY, fqdn TEXT);
                CREATE TABLE IF NOT EXISTS local_dns_settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS client_aliases (id INTEGER PRIMARY KEY, cidr TEXT);
                CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT);
                CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY, ip TEXT);
                CREATE TABLE IF NOT EXISTS query_events (id INTEGER PRIMARY KEY, domain TEXT);
                CREATE TABLE IF NOT EXISTS analytics_aggregate_buckets (id INTEGER PRIMARY KEY, bucket_start INTEGER);
                CREATE TABLE IF NOT EXISTS dns_cache_settings (key TEXT PRIMARY KEY, value TEXT);
                """
            )
            conn.execute("INSERT INTO sources(name) VALUES ('AdGuard')")
            conn.execute("INSERT INTO custom_rules(domain) VALUES ('blocked.example')")
            conn.execute("INSERT INTO local_dns_records(fqdn) VALUES ('host.home.arpa')")
            conn.execute("INSERT INTO client_aliases(cidr) VALUES ('172.16.0.1/32')")
            conn.execute("INSERT INTO admins(username) VALUES ('admin')")
            conn.execute("INSERT INTO login_attempts(ip) VALUES ('127.0.0.1')")
            conn.execute("INSERT INTO query_events(domain) VALUES ('example.com')")
            conn.execute("INSERT INTO analytics_aggregate_buckets(bucket_start) VALUES (1)")
            conn.execute("INSERT INTO dns_cache_settings(key, value) VALUES ('max_cache_size_mb', '256')")
            conn.commit()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            setattr(backup, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # Commands that must really execute for the test to mean anything (they
    # build/read the actual archive, all confined to the tmp sandbox by the
    # redirected constants above); everything else (systemctl, named-*,
    # dnsdist, visudo, rndc, dig) is faked so unit tests never touch real
    # system/service state.
    PASSTHROUGH_COMMANDS = {"tar", "git", "openssl"}

    def fake_run(self, command: list[str], check: bool = True, input_text: str | None = None, env=None) -> subprocess.CompletedProcess[str]:
        if command and command[0] in self.PASSTHROUGH_COMMANDS:
            return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, input=input_text, env=env)
        return subprocess.CompletedProcess(command, 0, "ok\n")


class ManifestAndComponentsTest(BackupTestBase):
    def test_select_files_default_excludes_private_keys_and_secrets(self) -> None:
        components = backup.validate_components(None)
        entries = backup.select_files(components)
        names = set(entries.keys())
        self.assertTrue(any(name.endswith("alderpointdns-lab.crt") for name in names))
        self.assertFalse(any(name.endswith("alderpointdns-lab.key") for name in names))
        self.assertFalse(any(name.endswith("secrets.env") for name in names))
        self.assertFalse(any(name.endswith("dnsdist-api.key") for name in names))

    def test_select_files_private_keys_includes_keys_and_secrets(self) -> None:
        components = backup.validate_components({"private_keys": True})
        entries = backup.select_files(components)
        names = set(entries.keys())
        self.assertTrue(any(name.endswith("alderpointdns-lab.key") for name in names))
        self.assertTrue(any(name.endswith("secrets.env") for name in names))
        self.assertTrue(any(name.endswith("dnsdist-api.key") for name in names))

    def test_select_files_user_auth_data_alone_includes_secrets_but_not_tls_key(self) -> None:
        components = backup.validate_components({"private_keys": False, "user_auth_data": True})
        entries = backup.select_files(components)
        names = set(entries.keys())
        self.assertTrue(any(name.endswith("secrets.env") for name in names))
        self.assertFalse(any(name.endswith("alderpointdns-lab.key") for name in names))

    def test_select_files_respects_component_toggles(self) -> None:
        components = backup.validate_components({"bind_source_config": False, "dnsdist_source_config": False})
        entries = backup.select_files(components)
        names = set(entries.keys())
        self.assertFalse(any("named.conf" in name for name in names))
        self.assertFalse(any("dnsdist.conf" in name for name in names))

    def test_alderpointdns_app_version_returns_something_sane(self) -> None:
        version = backup.alderpointdns_app_version()
        self.assertTrue(version)
        self.assertNotEqual(version, "unknown+git.unknown")

    def test_database_schema_version_stable_and_changes_with_schema(self) -> None:
        with closing(backup.connect()) as conn:
            v1 = backup.database_schema_version(conn)
            v1_again = backup.database_schema_version(conn)
        self.assertEqual(v1, v1_again)
        with closing(backup.connect()) as conn:
            conn.execute("CREATE TABLE extra_test_table (id INTEGER PRIMARY KEY)")
            conn.commit()
            v2 = backup.database_schema_version(conn)
        self.assertNotEqual(v1, v2)


class AppVersionTest(BackupTestBase):
    """alderpointdns_app_version() must work on a stock Debian package
    install where /opt/alderpointdns is plain files, not a git checkout,
    and `git` is not installed at all -- see the module docstring in
    backup.py. These pin down the exact clean-VM failure mode: a
    FileNotFoundError from subprocess when 'git' is absent must never
    propagate out of version detection (and therefore out of
    create_backup(), and therefore out of the mandatory pre-import
    backup)."""

    def setUp(self) -> None:
        super().setUp()
        self.approot = self.tmp / "approot"
        self.approot.mkdir()
        self.old_app_root = backup.APP_ROOT
        backup.APP_ROOT = self.approot

    def tearDown(self) -> None:
        backup.APP_ROOT = self.old_app_root
        super().tearDown()

    def test_no_git_executable_falls_back_to_version_file(self) -> None:
        (self.approot / "VERSION").write_text("1.2.3\n")
        with mock.patch.object(backup.shutil, "which", return_value=None):
            self.assertEqual(backup.alderpointdns_app_version(), "1.2.3")

    def test_no_git_executable_never_raises_filenotfounderror(self) -> None:
        # Direct reproduction of the clean-VM failure: no VERSION file, no
        # git binary, no .git directory -- alderpointdns_app_version() must
        # still return a plain string, not raise.
        with mock.patch.object(backup.shutil, "which", return_value=None):
            version = backup.alderpointdns_app_version()
        self.assertIsInstance(version, str)
        self.assertNotIn("git.", version)

    def test_no_git_directory_omits_dev_metadata_even_if_git_installed(self) -> None:
        (self.approot / "VERSION").write_text("1.2.3\n")
        # git is "installed" (which() succeeds) but APP_ROOT/.git does not
        # exist -- a real package install, not a checkout.
        with mock.patch.object(backup.shutil, "which", return_value="/usr/bin/git"):
            version = backup.alderpointdns_app_version()
        self.assertEqual(version, "1.2.3")

    def test_valid_version_file_is_used_verbatim(self) -> None:
        (self.approot / "VERSION").write_text("0.4.0-beta.2\n")
        with mock.patch.object(backup.shutil, "which", return_value=None):
            self.assertEqual(backup.alderpointdns_app_version(), "0.4.0-beta.2")

    def test_missing_version_file_falls_back_to_dpkg_metadata(self) -> None:
        # No VERSION file at all.
        with mock.patch.object(backup.shutil, "which", return_value=None), \
             mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["dpkg-query"], 0, "0.4.0-1\n")) as run_mock:
            version = backup.alderpointdns_app_version()
        self.assertEqual(version, "0.4.0-1")
        run_mock.assert_called_once_with(["dpkg-query", "-W", "-f=${Version}", backup.DPKG_PACKAGE_NAME], check=False)

    def test_malformed_version_file_falls_back_to_dpkg_metadata(self) -> None:
        (self.approot / "VERSION").write_text("\x00binary garbage\nnot a version\n")
        with mock.patch.object(backup.shutil, "which", return_value=None), \
             mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["dpkg-query"], 0, "0.4.0-1\n")):
            self.assertEqual(backup.alderpointdns_app_version(), "0.4.0-1")

    def test_empty_version_file_falls_back_to_dpkg_metadata(self) -> None:
        (self.approot / "VERSION").write_text("   \n")
        with mock.patch.object(backup.shutil, "which", return_value=None), \
             mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["dpkg-query"], 0, "0.4.0-1\n")):
            self.assertEqual(backup.alderpointdns_app_version(), "0.4.0-1")

    def test_no_version_file_and_dpkg_unavailable_reports_unknown_not_a_crash(self) -> None:
        with mock.patch.object(backup.shutil, "which", return_value=None), \
             mock.patch.object(backup, "run", side_effect=FileNotFoundError("dpkg-query")):
            self.assertEqual(backup.alderpointdns_app_version(), "unknown")

    def test_dpkg_query_nonzero_exit_falls_back_to_unknown(self) -> None:
        # e.g. "dpkg-query: no packages found matching alderpointdns" on a
        # non-package (source tree) install with no VERSION file.
        with mock.patch.object(backup.shutil, "which", return_value=None), \
             mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["dpkg-query"], 1, "dpkg-query: no packages found matching alderpointdns\n")):
            self.assertEqual(backup.alderpointdns_app_version(), "unknown")

    def test_git_dev_metadata_included_when_git_and_dotgit_both_present(self) -> None:
        (self.approot / "VERSION").write_text("1.2.3\n")
        (self.approot / ".git").mkdir()

        def fake_run(command, check=True, **kwargs):
            if command[0] == "dpkg-query":
                return subprocess.CompletedProcess(command, 1, "")
            self.assertEqual(command, ["git", "-C", str(self.approot), "rev-parse", "--short", "HEAD"])
            return subprocess.CompletedProcess(command, 0, "abc1234\n")

        with mock.patch.object(backup.shutil, "which", return_value="/usr/bin/git"), \
             mock.patch.object(backup, "run", side_effect=fake_run):
            self.assertEqual(backup.alderpointdns_app_version(), "1.2.3+git.abc1234")

    def test_git_command_failure_is_caught_and_omits_metadata(self) -> None:
        (self.approot / "VERSION").write_text("1.2.3\n")
        (self.approot / ".git").mkdir()
        with mock.patch.object(backup.shutil, "which", return_value="/usr/bin/git"), \
             mock.patch.object(backup, "run", side_effect=FileNotFoundError("git")):
            # which() says git exists but the exec itself races and fails --
            # must not propagate, and must never fabricate a commit id.
            self.assertEqual(backup.alderpointdns_app_version(), "1.2.3")

    def test_git_rev_parse_nonzero_exit_omits_metadata(self) -> None:
        (self.approot / "VERSION").write_text("1.2.3\n")
        (self.approot / ".git").mkdir()
        with mock.patch.object(backup.shutil, "which", return_value="/usr/bin/git"), \
             mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["git"], 128, "fatal: not a git repository\n")):
            self.assertEqual(backup.alderpointdns_app_version(), "1.2.3")

    def test_create_backup_succeeds_with_no_git_executable(self) -> None:
        # The exact clean-VM scenario: stock Debian 13 package install,
        # no git binary anywhere on PATH.
        (self.approot / "VERSION").write_text("0.4.0-beta.2\n")
        with mock.patch.object(backup, "run", self.fake_run), \
             mock.patch.object(backup.shutil, "which", return_value=None):
            path = backup.create_backup(backup.validate_components(None))
        self.assertTrue(path.exists())
        with tempfile.TemporaryDirectory(dir=str(backup.STAGING_DIR)) as tmp:
            extract = Path(tmp) / "x"
            extract.mkdir()
            subprocess.run(["tar", "-xzf", str(path), "-C", str(extract)], check=True)
            manifest = json.loads((extract / "manifest.json").read_text())
            self.assertEqual(manifest["alderpointdns_app_version"], "0.4.0-beta.2")


class VersionConsistencyTest(BackupTestBase):
    """Regression coverage for the single-source-of-truth model documented
    in docs/versioning.md: the VERSION file is primary (it's what
    scripts/build-deb.sh itself derives the .deb Version from at build
    time, so on a normally-built-and-installed package the two already
    agree), dpkg is the fallback when VERSION is missing/unreadable, and a
    disagreement between the two -- which should never happen on a package
    built through the normal pipeline -- is detected and logged rather
    than silently ignored, since an undetected mismatch is exactly what
    would make a future Software Updates version comparison unreliable."""

    def setUp(self) -> None:
        super().setUp()
        self.approot = self.tmp / "approot"
        self.approot.mkdir()
        self.old_app_root = backup.APP_ROOT
        backup.APP_ROOT = self.approot

    def tearDown(self) -> None:
        backup.APP_ROOT = self.old_app_root
        super().tearDown()

    def test_dpkg_version_to_source_form_reverses_build_deb_substitution(self) -> None:
        # Must exactly invert scripts/build-deb.sh's generalized
        # sed -E 's/-([A-Za-z]+)\.([0-9]+)/~\1\2/' plus the appended "-1",
        # for any pre-release tag (beta, dev, rc, ...), not just "beta".
        self.assertEqual(backup._dpkg_version_to_source_form("0.4.0~beta6-1"), "0.4.0-beta.6")
        self.assertEqual(backup._dpkg_version_to_source_form("0.4.0-1"), "0.4.0")
        self.assertEqual(backup._dpkg_version_to_source_form("1.2.3~beta10-2"), "1.2.3-beta.10")
        self.assertEqual(backup._dpkg_version_to_source_form("0.5.0~dev1-1"), "0.5.0-dev.1")
        self.assertEqual(backup._dpkg_version_to_source_form("1.0.0-1"), "1.0.0")

    def test_status_agrees_when_file_and_dpkg_match(self) -> None:
        (self.approot / "VERSION").write_text("0.4.0-beta.6\n")
        with mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["dpkg-query"], 0, "0.4.0~beta6-1\n")):
            status = backup.version_source_status()
        self.assertEqual(status["resolved"], "0.4.0-beta.6")
        self.assertEqual(status["source"], "version_file")
        self.assertFalse(status["mismatch"])

    def test_status_flags_mismatch_when_file_is_stale_relative_to_dpkg(self) -> None:
        # Reproduces this exact repo's real anomaly: a dev checkout with an
        # older VERSION file overlaid on a path where dpkg has a newer
        # package already installed.
        (self.approot / "VERSION").write_text("0.4.0-beta.5\n")
        with mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["dpkg-query"], 0, "0.4.0~beta6-1\n")):
            status = backup.version_source_status()
        self.assertTrue(status["mismatch"])
        self.assertEqual(status["file_version"], "0.4.0-beta.5")
        self.assertEqual(status["dpkg_version_normalized"], "0.4.0-beta.6")
        # The VERSION file still wins for the resolved/reported version --
        # see the module docstring -- but the drift is not silently lost.
        self.assertEqual(status["resolved"], "0.4.0-beta.5")

    def test_mismatch_is_logged_to_stderr(self) -> None:
        (self.approot / "VERSION").write_text("0.4.0-beta.5\n")
        with mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["dpkg-query"], 0, "0.4.0~beta6-1\n")), \
             mock.patch.object(backup.shutil, "which", return_value=None):
            with contextlib.redirect_stderr(io.StringIO()) as captured:
                backup.alderpointdns_app_version()
        self.assertIn("does not match", captured.getvalue())
        self.assertIn("0.4.0-beta.5", captured.getvalue())
        self.assertIn("0.4.0-beta.6", captured.getvalue())

    def test_no_mismatch_log_when_file_and_dpkg_agree(self) -> None:
        (self.approot / "VERSION").write_text("0.4.0-beta.6\n")
        with mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["dpkg-query"], 0, "0.4.0~beta6-1\n")), \
             mock.patch.object(backup.shutil, "which", return_value=None):
            with contextlib.redirect_stderr(io.StringIO()) as captured:
                backup.alderpointdns_app_version()
        self.assertEqual(captured.getvalue(), "")

    def test_status_falls_back_to_dpkg_when_no_version_file(self) -> None:
        with mock.patch.object(backup, "run", return_value=subprocess.CompletedProcess(["dpkg-query"], 0, "0.4.0~beta6-1\n")):
            status = backup.version_source_status()
        self.assertEqual(status["resolved"], "0.4.0-beta.6")
        self.assertEqual(status["source"], "dpkg")
        self.assertFalse(status["mismatch"])

    def test_status_unknown_when_neither_source_available(self) -> None:
        with mock.patch.object(backup, "run", side_effect=FileNotFoundError("dpkg-query")):
            status = backup.version_source_status()
        self.assertEqual(status["resolved"], "unknown")
        self.assertEqual(status["source"], "none")
        self.assertFalse(status["mismatch"])


class SqliteOnlineBackupTest(BackupTestBase):
    def test_sqlite_backup_copy_produces_readable_consistent_db(self) -> None:
        dest = self.tmp / "copy.db"
        backup.sqlite_backup_copy(dest, include_analytics=True, include_auth=True)
        self.assertTrue(dest.exists())
        conn = sqlite3.connect(dest)
        try:
            count = conn.execute("SELECT count(*) FROM sources").fetchone()[0]
            self.assertEqual(count, 1)
            admins = conn.execute("SELECT count(*) FROM admins").fetchone()[0]
            self.assertEqual(admins, 1)
        finally:
            conn.close()

    def test_sqlite_backup_copy_strips_analytics_when_disabled(self) -> None:
        dest = self.tmp / "copy.db"
        backup.sqlite_backup_copy(dest, include_analytics=False, include_auth=True)
        conn = sqlite3.connect(dest)
        try:
            events = conn.execute("SELECT count(*) FROM query_events").fetchone()[0]
            buckets = conn.execute("SELECT count(*) FROM analytics_aggregate_buckets").fetchone()[0]
            self.assertEqual(events, 0)
            self.assertEqual(buckets, 0)
            # unrelated tables are untouched
            self.assertEqual(conn.execute("SELECT count(*) FROM sources").fetchone()[0], 1)
        finally:
            conn.close()

    def test_sqlite_backup_copy_strips_auth_when_disabled(self) -> None:
        dest = self.tmp / "copy.db"
        backup.sqlite_backup_copy(dest, include_analytics=True, include_auth=False)
        conn = sqlite3.connect(dest)
        try:
            self.assertEqual(conn.execute("SELECT count(*) FROM admins").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM login_attempts").fetchone()[0], 0)
        finally:
            conn.close()

    def test_sqlite_backup_copy_reflects_concurrent_writes_consistently(self) -> None:
        # Simulate a writer still inside a transaction while the backup runs;
        # the online backup API must still produce a valid, openable copy.
        writer = sqlite3.connect(backup.DB_PATH)
        writer.execute("INSERT INTO sources(name) VALUES ('concurrent')")
        writer.commit()
        dest = self.tmp / "copy.db"
        backup.sqlite_backup_copy(dest, include_analytics=True, include_auth=True)
        writer.close()
        conn = sqlite3.connect(dest)
        try:
            self.assertEqual(conn.execute("SELECT count(*) FROM sources").fetchone()[0], 2)
        finally:
            conn.close()


class ConcurrentWriteBackupTest(BackupTestBase):
    """Regression coverage for the live-database tar race: scripts/backup.sh
    used to tar var/lib/alderpointdns/alderpointdns.db directly, so a writer
    checkpointing its WAL mid-archive could change the file out from under
    tar ('file changed as we read it'), aborting the acceptance suite's
    tests/test_backup_restore.sh. create_backup() must stay race-free under
    the same load because it only ever archives a completed, already-static
    SQLite online-backup snapshot -- never the live file."""

    def test_backup_and_restore_survive_concurrent_writes(self) -> None:
        stop = threading.Event()
        committed = {"count": 0}
        lock = threading.Lock()

        def writer() -> None:
            conn = sqlite3.connect(backup.DB_PATH, timeout=30)
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                i = 0
                while not stop.is_set():
                    conn.execute("INSERT INTO sources(name) VALUES (?)", (f"race-{i}",))
                    conn.commit()
                    if i % 10 == 0:
                        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    with lock:
                        committed["count"] = i + 1
                    i += 1
            finally:
                conn.close()

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        time.sleep(0.05)  # let the writer get going so the backup genuinely overlaps writes

        tar_output: list[str] = []

        def capturing_run(command, check=True, input_text=None, env=None):
            result = self.fake_run(command, check=check, input_text=input_text, env=env)
            if command and command[0] == "tar":
                tar_output.append(result.stdout or "")
            return result

        try:
            with mock.patch.object(backup, "run", capturing_run):
                path = backup.create_backup(backup.validate_components(None))
        finally:
            stop.set()
            thread.join(timeout=5)

        with lock:
            final_committed = committed["count"]

        # No tar warning about the file changing mid-read.
        combined_tar_output = "".join(tar_output)
        self.assertNotIn("file changed as we read it", combined_tar_output)

        # Successful backup exit status (create_backup raises on failure;
        # confirm the recorded history row agrees).
        self.assertTrue(path.exists())
        last = backup.last_backup()
        self.assertEqual(last["status"], "deployed")

        with tempfile.TemporaryDirectory(dir=str(backup.STAGING_DIR)) as tmp:
            extract = Path(tmp) / "x"
            extract.mkdir()
            subprocess.run(["tar", "-xzf", str(path), "-C", str(extract)], check=True)

            # Valid manifest checksums.
            manifest = json.loads((extract / "manifest.json").read_text())
            self.assertGreater(len(manifest["sha256_checksums"]), 0)
            for relpath, expected in manifest["sha256_checksums"].items():
                self.assertEqual(backup.sha256_file(extract / relpath), expected, relpath)

            # Successful SQLite integrity check on the archived snapshot.
            snapshot = extract / "var/lib/alderpointdns/alderpointdns.db"
            snap_conn = sqlite3.connect(snapshot)
            try:
                self.assertEqual(snap_conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                # Expected committed records: the snapshot must land on a real,
                # fully-committed point in the writer's timeline -- at least the
                # pre-existing seed row, and never more rows than the writer had
                # actually committed by the time the backup finished (a torn
                # read could otherwise report a phantom/partial count).
                snapshot_count = snap_conn.execute("SELECT count(*) FROM sources").fetchone()[0]
            finally:
                snap_conn.close()

        self.assertGreaterEqual(snapshot_count, 1)
        self.assertLessEqual(snapshot_count, final_committed + 1)

        # Successful isolated restore -- confined to this test's temp
        # sandbox by BackupTestBase's path redirection, so this never
        # touches real systemd/services.
        with mock.patch.object(backup, "run", self.fake_run), mock.patch.object(backup, "resolves", return_value=True), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        last_restore = backup.last_restore()
        self.assertEqual(last_restore["status"], "deployed")


class CreateBackupTest(BackupTestBase):
    def test_create_backup_produces_valid_archive_with_manifest_and_checksums(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None))
        self.assertTrue(path.exists())
        with tempfile.TemporaryDirectory(dir=str(backup.STAGING_DIR)) as tmp:
            extract = Path(tmp) / "x"
            extract.mkdir()
            subprocess.run(["tar", "-xzf", str(path), "-C", str(extract)], check=True)
            manifest = json.loads((extract / "manifest.json").read_text())
            self.assertEqual(manifest["backup_format_version"], backup.BACKUP_FORMAT_VERSION)
            self.assertIn("sha256_checksums", manifest)
            self.assertGreater(len(manifest["sha256_checksums"]), 0)
            for relpath, expected in manifest["sha256_checksums"].items():
                actual = backup.sha256_file(extract / relpath)
                self.assertEqual(actual, expected, relpath)
            self.assertTrue((extract / "var/lib/alderpointdns/alderpointdns.db").exists())

    def test_create_backup_records_history_row(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            backup.create_backup(backup.validate_components(None))
        last = backup.last_backup()
        self.assertEqual(last["status"], "deployed")
        self.assertTrue(last["path"])
        self.assertGreater(last["size_bytes"], 0)

    def test_create_backup_encrypts_and_round_trips(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None), password="correct horse battery staple")
        self.assertTrue(path.name.endswith(".enc"))
        with tempfile.TemporaryDirectory(dir=str(backup.STAGING_DIR)) as tmp:
            dest = Path(tmp) / "decrypted.tar.gz"
            backup.decrypt_archive(path, "correct horse battery staple", dest)
            proc = subprocess.run(["tar", "-tzf", str(dest)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("manifest.json", proc.stdout)

    def test_decrypt_with_wrong_password_fails(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None), password="correct-password")
        with tempfile.TemporaryDirectory(dir=str(backup.STAGING_DIR)) as tmp:
            dest = Path(tmp) / "decrypted.tar.gz"
            with self.assertRaises(subprocess.CalledProcessError):
                backup.decrypt_archive(path, "wrong-password", dest)


class ListingTest(BackupTestBase):
    def test_list_backups_discovers_orphaned_legacy_files(self) -> None:
        legacy = backup.BACKUP_DIR / f"{backup.FILENAME_PREFIX}20200101T000000Z.tar.gz"
        legacy.write_bytes(b"not a real archive but present on disk")
        rows = backup.list_backups()
        self.assertTrue(any(row["status"] == "legacy" and row["path"] == str(legacy) for row in rows))

    def test_delete_backup_removes_file_and_history_row(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None))
        backup.delete_backup(path.name)
        self.assertFalse(path.exists())
        self.assertFalse(any(row["path"] == str(path) for row in backup.list_backups()))

    def test_find_backup_path_rejects_outside_managed_dirs(self) -> None:
        with self.assertRaises(backup.BackupError):
            backup.find_backup_path("/etc/passwd")


class PreviewTest(BackupTestBase):
    def test_preview_restore_reports_table_and_file_diffs(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None))
        with closing(backup.connect()) as conn:
            conn.execute("INSERT INTO custom_rules(domain) VALUES ('new-since-backup.example')")
            conn.commit()
        backup.DNSDIST_CONF.write_text("setLocal('127.0.0.1:53') -- changed\n")
        preview = backup.preview_restore(path, None)
        self.assertTrue(preview["compatible"])
        tables = {d["table"]: d for d in preview["table_diffs"]}
        self.assertIn("custom_rules", tables)
        self.assertEqual(tables["custom_rules"]["live_rows"], 2)
        self.assertEqual(tables["custom_rules"]["backup_rows"], 1)
        files = {d["path"] for d in preview["file_diffs"]}
        self.assertTrue(any("dnsdist.conf" in f for f in files))

    def test_preview_restore_never_touches_live_state(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None))
        original = backup.DNSDIST_CONF.read_text()
        with closing(backup.connect()) as conn:
            before = conn.execute("SELECT count(*) FROM custom_rules").fetchone()[0]
        backup.preview_restore(path, None)
        self.assertEqual(backup.DNSDIST_CONF.read_text(), original)
        with closing(backup.connect()) as conn:
            after = conn.execute("SELECT count(*) FROM custom_rules").fetchone()[0]
        self.assertEqual(before, after)

    def test_preview_restore_flags_incompatible_format_version(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None))
        with tempfile.TemporaryDirectory(dir=str(backup.STAGING_DIR)) as tmp:
            extract = Path(tmp) / "x"
            extract.mkdir()
            subprocess.run(["tar", "-xzf", str(path), "-C", str(extract)], check=True)
            manifest = json.loads((extract / "manifest.json").read_text())
            manifest["backup_format_version"] = 999
            (extract / "manifest.json").write_text(json.dumps(manifest))
            rebuilt = backup.BACKUP_DIR / "rebuilt.tar.gz"
            subprocess.run(["tar", "-czf", str(rebuilt), "-C", str(extract), "."], check=True)
        preview = backup.preview_restore(rebuilt, None)
        self.assertFalse(preview["compatible"])
        self.assertTrue(any("backup_format_version" in w for w in preview["warnings"]))

    def test_preview_restore_detects_checksum_tampering(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None))
        with tempfile.TemporaryDirectory(dir=str(backup.STAGING_DIR)) as tmp:
            extract = Path(tmp) / "x"
            extract.mkdir()
            subprocess.run(["tar", "-xzf", str(path), "-C", str(extract)], check=True)
            manifest = json.loads((extract / "manifest.json").read_text())
            tampered_relpath = str(backup.DNSDIST_CONF.relative_to("/"))
            self.assertIn(tampered_relpath, manifest["sha256_checksums"])
            tampered = extract / tampered_relpath
            tampered.write_text("-- tampered content that will not match the manifest checksum\n")
            rebuilt = backup.BACKUP_DIR / "rebuilt.tar.gz"
            subprocess.run(["tar", "-czf", str(rebuilt), "-C", str(extract), "."], check=True)
        with self.assertRaises(backup.BackupError):
            backup.preview_restore(rebuilt, None)


class RestoreTest(BackupTestBase):
    def _make_backup(self) -> Path:
        with mock.patch.object(backup, "run", self.fake_run):
            return backup.create_backup(backup.validate_components(None))

    def test_restore_backup_applies_selected_table_only(self) -> None:
        path = self._make_backup()
        with closing(backup.connect()) as conn:
            conn.execute("INSERT INTO custom_rules(domain) VALUES ('added-after-backup.example')")
            conn.execute("INSERT INTO dns_cache_settings(key, value) VALUES ('unrelated_key', 'unrelated_value')")
            conn.commit()
        with mock.patch.object(backup, "run", self.fake_run), mock.patch.object(backup, "resolves", return_value=True), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            backup.restore_backup(path, None, {key: False for key in backup.COMPONENT_KEYS} | {"sqlite_data": False, "custom_rules": True})
        with closing(backup.connect()) as conn:
            rules = conn.execute("SELECT count(*) FROM custom_rules").fetchone()[0]
            # custom_rules restored to the 1-row state captured at backup time
            self.assertEqual(rules, 1)
            # dns_cache_settings is gated by sqlite_data (off here) and must be untouched
            unrelated = conn.execute("SELECT count(*) FROM dns_cache_settings WHERE key='unrelated_key'").fetchone()[0]
            self.assertEqual(unrelated, 1)

    def test_restore_backup_full_sqlite_data_merges_unmapped_tables(self) -> None:
        path = self._make_backup()
        with closing(backup.connect()) as conn:
            conn.execute("INSERT INTO dns_cache_settings(key, value) VALUES ('unrelated_key', 'unrelated_value')")
            conn.commit()
        with mock.patch.object(backup, "run", self.fake_run), mock.patch.object(backup, "resolves", return_value=True), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        with closing(backup.connect()) as conn:
            unrelated = conn.execute("SELECT count(*) FROM dns_cache_settings WHERE key='unrelated_key'").fetchone()[0]
            self.assertEqual(unrelated, 0)

    def test_restore_backup_rolls_back_on_failed_health_check(self) -> None:
        path = self._make_backup()
        original = backup.DNSDIST_CONF.read_text()
        backup.DNSDIST_CONF.write_text("changed-live-content\n")
        # The post-restore health check fails once (triggering rollback);
        # the rollback's own re-check then succeeds (as it would in reality,
        # since rollback restores exactly the config that was working
        # before the restore attempt began).
        with mock.patch.object(backup, "run", self.fake_run), mock.patch.object(backup, "resolves", side_effect=[False, True]), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            with self.assertRaises(RuntimeError):
                backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        self.assertEqual(backup.DNSDIST_CONF.read_text(), "changed-live-content\n")
        last = backup.last_restore()
        self.assertEqual(last["status"], "rolled_back")

    def test_restore_backup_rolls_back_on_forced_failure(self) -> None:
        path = self._make_backup()
        original = backup.DNSDIST_CONF.read_text()
        backup.DNSDIST_CONF.write_text("changed-live-content\n")
        os.environ["ALDERPOINTDNS_TEST_FORCE_RESTORE_FAIL"] = "1"
        try:
            with mock.patch.object(backup, "run", self.fake_run), mock.patch.object(backup, "resolves", return_value=True), \
                    mock.patch.object(backup, "_wait_active", return_value=True):
                with self.assertRaises(RuntimeError):
                    backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        finally:
            del os.environ["ALDERPOINTDNS_TEST_FORCE_RESTORE_FAIL"]
        self.assertEqual(backup.DNSDIST_CONF.read_text(), "changed-live-content\n")
        last = backup.last_restore()
        self.assertEqual(last["status"], "rolled_back")

    def test_restore_backup_takes_pre_restore_safety_backup(self) -> None:
        path = self._make_backup()
        history_before = len(backup.list_backups())
        with mock.patch.object(backup, "run", self.fake_run), mock.patch.object(backup, "resolves", return_value=True), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        history_after = len(backup.list_backups())
        self.assertGreater(history_after, history_before)
        last = backup.last_restore()
        self.assertTrue(last["pre_restore_backup_path"])


class RetentionTest(BackupTestBase):
    def test_prune_backups_keeps_only_newest_n(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            for _ in range(5):
                backup.create_backup(backup.validate_components(None))
        pruned = backup.prune_backups(retention_count=2)
        self.assertEqual(len(pruned), 3)
        remaining = [row for row in backup.list_backups() if row["status"] != "legacy"]
        self.assertEqual(len(remaining), 2)
        for path in pruned:
            self.assertFalse(Path(path).exists())


class RequestResponseTest(BackupTestBase):
    def test_process_pending_request_create_uses_newest_and_skips_older(self) -> None:
        backup.request_backup("create", {"components": backup.validate_components(None)})
        backup.request_backup("create", {"components": backup.validate_components({"analytics_history": True})})
        with mock.patch.object(backup, "run", self.fake_run):
            result = backup.process_pending_request("create")
        self.assertEqual(result["status"], "done")
        with closing(backup.connect()) as conn:
            statuses = [row["status"] for row in conn.execute("SELECT status FROM backup_requests ORDER BY id")]
        self.assertEqual(statuses, ["skipped", "done"])

    def test_process_pending_request_returns_none_when_nothing_pending(self) -> None:
        result = backup.process_pending_request("restore")
        self.assertIsNone(result)

    def test_password_file_is_consumed_and_deleted(self) -> None:
        backup.request_backup("create", {"components": backup.validate_components(None)}, password="hunter2")
        password_file = backup._pending_password_file("create")
        self.assertTrue(password_file.exists())
        with mock.patch.object(backup, "run", self.fake_run):
            backup.process_pending_request("create")
        self.assertFalse(password_file.exists())


class SettingsTest(BackupTestBase):
    def test_validate_settings_rejects_bad_interval(self) -> None:
        with self.assertRaises(backup.BackupError):
            backup.validate_settings({"schedule_interval_hours": 0})

    def test_validate_settings_rejects_bad_retention(self) -> None:
        with self.assertRaises(backup.BackupError):
            backup.validate_settings({"retention_count": -1})

    def test_update_settings_persists(self) -> None:
        backup.update_settings({"schedule_enabled": "1", "schedule_interval_hours": 12, "retention_count": 3})
        cfg = backup.settings()
        self.assertEqual(cfg["schedule_enabled"], "1")
        self.assertEqual(cfg["schedule_interval_hours"], "12")
        self.assertEqual(cfg["retention_count"], "3")

    def test_validate_settings_rejects_bad_max_upload_mib(self) -> None:
        with self.assertRaises(backup.BackupError):
            backup.validate_settings({"max_upload_mib": 1})  # below the 64 MiB floor

    def test_validate_settings_rejects_max_upload_mib_above_hard_ceiling(self) -> None:
        with self.assertRaises(backup.BackupError):
            backup.validate_settings({"max_upload_mib": backup.HARD_CEILING_MAX_UPLOAD_MIB + 1})

    def test_update_settings_persists_upload_limits(self) -> None:
        backup.update_settings({"max_upload_mib": 256, "max_extracted_mib": 1024})
        self.assertEqual(backup.max_upload_bytes(), 256 * 1024 * 1024)
        self.assertEqual(backup.max_extracted_bytes_setting(), 1024 * 1024 * 1024)


class LargeNativeBackupTest(BackupTestBase):
    """Reproduces the reported production migration blocker: a native
    Alderpoint DNS backup (here, inflated past 10 MiB with a downloaded-list
    file standing in for a long-running server's real Analytics History
    growth) must upload and restore successfully. The old, wrong fix would
    have been raising app/importer.py's MAX_UPLOAD_BYTES; that constant is
    never touched or referenced by anything in this test file, which is the
    point -- backup upload/restore is fully independent of it."""

    def _write_padding(self, size_bytes: int) -> None:
        # Non-compressible content so the gzip'd archive really does exceed
        # size_bytes too, not just the uncompressed member.
        backup.DOWNLOADS_DIR.joinpath("current").mkdir(parents=True, exist_ok=True)
        with backup.DOWNLOADS_DIR.joinpath("current", "1-large-source.txt").open("wb") as fh:
            remaining = size_bytes
            chunk = os.urandom(1024 * 1024)
            while remaining > 0:
                fh.write(chunk[: min(len(chunk), remaining)])
                remaining -= len(chunk)

    def test_backup_over_10mib_creates_and_restores_successfully(self) -> None:
        self._write_padding(12 * 1024 * 1024)  # ~12 MiB, i.e. > the old 10 MiB cap
        components = backup.validate_components({"analytics_history": True, "last_downloaded_lists": True})
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(components)
        self.assertGreater(path.stat().st_size, 10 * 1024 * 1024)
        with mock.patch.object(backup, "run", self.fake_run), mock.patch.object(backup, "resolves", return_value=True), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            restore_id = backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        self.assertIsNotNone(restore_id)
        last = backup.last_restore()
        self.assertEqual(last["status"], "deployed")

    def test_analytics_history_over_10mib_survives_restore(self) -> None:
        # A realistic stand-in for "a long-running test server's Analytics
        # History": enough query_events rows that the archive clears 10
        # MiB on its own, with no padding file involved.
        with closing(backup.connect()) as conn:
            conn.executemany(
                "INSERT INTO query_events(domain) VALUES (?)",
                [(f"host-{i}.example.com.",) for i in range(300_000)],
            )
            conn.commit()
        components = backup.validate_components({"analytics_history": True})
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(components)
        # (Archive-size-over-10-MiB is proven independently by
        # test_backup_over_10mib_creates_and_restores_successfully above,
        # which uses incompressible padding for a size guarantee gzip
        # compression of repetitive SQLite content can't undermine; this
        # test's job is proving 300k real analytics rows round-trip intact.)
        with closing(backup.connect()) as conn:
            conn.execute("DELETE FROM query_events")
            conn.commit()
        with mock.patch.object(backup, "run", self.fake_run), mock.patch.object(backup, "resolves", return_value=True), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            backup.restore_backup(path, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        with closing(backup.connect()) as conn:
            restored = conn.execute("SELECT count(*) FROM query_events").fetchone()[0]
        # +1 for the seed row BackupTestBase.setUp() already inserts.
        self.assertEqual(restored, 300_001)

    def test_configured_max_upload_is_enforced_regardless_of_importer_cap(self) -> None:
        backup.update_settings({"max_upload_mib": 64})
        self._write_padding(70 * 1024 * 1024)
        components = backup.validate_components({"last_downloaded_lists": True})
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(components)
        data = path.read_bytes()
        self.assertGreater(len(data), 64 * 1024 * 1024)
        with self.assertRaises(backup.BackupError) as ctx:
            backup.stage_import(path.name, data)
        self.assertIn("64 MiB", str(ctx.exception))

    def test_stage_import_under_configured_max_succeeds(self) -> None:
        backup.update_settings({"max_upload_mib": 128})
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None))
        staged = backup.stage_import(path.name, path.read_bytes())
        self.assertTrue(staged.exists())
        self.assertTrue(str(staged.parent).startswith(str(backup.IMPORTS_DIR)))


class StreamedUploadTest(BackupTestBase):
    def test_begin_and_finalize_round_trip(self) -> None:
        tmp_path, max_bytes, safe_name = backup.begin_streamed_upload("mybackup.tar.gz", content_length_hint=1024)
        self.assertTrue(tmp_path.exists())
        # 0600 while staged: no group/other access to an in-flight upload.
        self.assertEqual(oct(tmp_path.stat().st_mode)[-3:], "600")
        tmp_path.write_bytes(b"fake archive bytes")
        final = backup.finalize_streamed_upload(tmp_path, safe_name)
        self.assertFalse(tmp_path.exists())
        self.assertTrue(final.exists())
        self.assertEqual(oct(final.stat().st_mode)[-3:], "640")
        self.assertTrue(final.name.endswith("mybackup.tar.gz"))

    def test_begin_streamed_upload_rejects_bad_extension(self) -> None:
        with self.assertRaises(backup.BackupError):
            backup.begin_streamed_upload("not-a-backup.zip")

    def test_begin_streamed_upload_rejects_oversized_content_length_hint(self) -> None:
        backup.update_settings({"max_upload_mib": 64})
        with self.assertRaises(backup.BackupError):
            backup.begin_streamed_upload("huge.tar.gz", content_length_hint=200 * 1024 * 1024)

    def test_abort_streamed_upload_cleans_up_partial_file(self) -> None:
        tmp_path, _, _ = backup.begin_streamed_upload("partial.tar.gz")
        tmp_path.write_bytes(b"only part of the file")
        backup.abort_streamed_upload(tmp_path)
        self.assertFalse(tmp_path.exists())

    def test_begin_streamed_upload_rejects_insufficient_free_space(self) -> None:
        fake_usage = type("Usage", (), {"total": 10**9, "used": 10**9 - 1024, "free": 1024})()
        with mock.patch.object(backup.shutil, "disk_usage", return_value=fake_usage):
            with self.assertRaises(backup.BackupError) as ctx:
                backup.begin_streamed_upload("bigbackup.tar.gz", content_length_hint=50 * 1024 * 1024)
        self.assertIn("free disk space", str(ctx.exception))

    def test_chunk_size_is_bounded_and_small(self) -> None:
        # Proof-by-constant that memory usage does not scale with archive
        # size: webapp.py's upload loop reads exactly this many bytes at a
        # time into memory, however large the archive on disk is.
        self.assertLessEqual(backup.UPLOAD_CHUNK_BYTES, 8 * 1024 * 1024)

    def test_simulated_chunked_stream_never_buffers_whole_archive(self) -> None:
        """Simulates what app/webapp.py's backup_import_route does with a
        FastAPI UploadFile, using a plain in-memory reader, and asserts the
        largest single buffer ever held is one chunk, not the whole file --
        i.e. peak memory is independent of archive size."""
        total_size = 30 * 1024 * 1024
        source = os.urandom(total_size)
        pos = 0
        max_buffer_seen = 0

        def fake_read(n: int) -> bytes:
            nonlocal pos, max_buffer_seen
            chunk = source[pos : pos + n]
            pos += len(chunk)
            max_buffer_seen = max(max_buffer_seen, len(chunk))
            return chunk

        tmp_path, max_bytes, safe_name = backup.begin_streamed_upload("streamed.tar.gz", content_length_hint=total_size)
        total = 0
        with tmp_path.open("wb") as fh:
            while True:
                chunk = fake_read(backup.UPLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                fh.write(chunk)
        final = backup.finalize_streamed_upload(tmp_path, safe_name)
        self.assertEqual(total, total_size)
        self.assertEqual(final.stat().st_size, total_size)
        self.assertLessEqual(max_buffer_seen, backup.UPLOAD_CHUNK_BYTES)


class ArchiveSecurityTest(BackupTestBase):
    """Malicious/corrupt archive handling. These build hand-crafted tar
    archives (not through create_backup) specifically to exercise paths a
    legitimately-created Alderpoint DNS backup would never take."""

    def _valid_manifest_bytes(self) -> bytes:
        return json.dumps(
            {
                "backup_format_version": backup.BACKUP_FORMAT_VERSION,
                "alderpointdns_app_version": "0.0.0-test",
                "database_schema_version": "test",
                "created_at": backup.now(),
                "source_node_id": "test-host",
                "included_components": [],
                "sha256_checksums": {},
            }
        ).encode()

    def _write_tar(self, dest: Path, members: list[tuple[tarfile.TarInfo, bytes | None]]) -> None:
        import tarfile as tf
        from io import BytesIO

        with tf.open(dest, "w:gz") as tar:
            for info, data in members:
                if data is not None:
                    tar.addfile(info, BytesIO(data))
                else:
                    tar.addfile(info)

    def test_rejects_archive_without_manifest(self) -> None:
        import tarfile as tf

        dest = backup.STAGING_DIR / "no-manifest.tar.gz"
        info = tf.TarInfo("some_file.txt")
        info.size = 4
        self._write_tar(dest, [(info, b"data")])
        with self.assertRaises(backup.BackupError) as ctx:
            backup.extract_backup(dest, None, backup.STAGING_DIR / "extract1")
        self.assertIn("not an Alderpoint DNS native backup", str(ctx.exception))

    def test_rejects_absolute_path_member(self) -> None:
        import tarfile as tf

        dest = backup.STAGING_DIR / "abs-path.tar.gz"
        manifest = self._valid_manifest_bytes()
        m_info = tf.TarInfo("manifest.json")
        m_info.size = len(manifest)
        evil_info = tf.TarInfo("/etc/passwd")
        evil_info.size = 4
        self._write_tar(dest, [(m_info, manifest), (evil_info, b"evil")])
        with self.assertRaises(backup.BackupError) as ctx:
            backup.extract_backup(dest, None, backup.STAGING_DIR / "extract2")
        self.assertIn("unsafe path", str(ctx.exception))

    def test_rejects_dot_dot_traversal_member(self) -> None:
        import tarfile as tf

        dest = backup.STAGING_DIR / "traversal.tar.gz"
        manifest = self._valid_manifest_bytes()
        m_info = tf.TarInfo("manifest.json")
        m_info.size = len(manifest)
        evil_info = tf.TarInfo("../../etc/cron.d/evil")
        evil_info.size = 4
        self._write_tar(dest, [(m_info, manifest), (evil_info, b"evil")])
        with self.assertRaises(backup.BackupError) as ctx:
            backup.extract_backup(dest, None, backup.STAGING_DIR / "extract3")
        self.assertIn("unsafe path", str(ctx.exception))

    def test_rejects_symlink_member(self) -> None:
        import tarfile as tf

        dest = backup.STAGING_DIR / "symlink.tar.gz"
        manifest = self._valid_manifest_bytes()
        m_info = tf.TarInfo("manifest.json")
        m_info.size = len(manifest)
        link_info = tf.TarInfo("etc/passwd-link")
        link_info.type = tf.SYMTYPE
        link_info.linkname = "/etc/passwd"
        self._write_tar(dest, [(m_info, manifest), (link_info, None)])
        with self.assertRaises(backup.BackupError) as ctx:
            backup.extract_backup(dest, None, backup.STAGING_DIR / "extract4")
        self.assertIn("symlink", str(ctx.exception))

    def test_rejects_hardlink_member(self) -> None:
        import tarfile as tf

        dest = backup.STAGING_DIR / "hardlink.tar.gz"
        manifest = self._valid_manifest_bytes()
        m_info = tf.TarInfo("manifest.json")
        m_info.size = len(manifest)
        link_info = tf.TarInfo("var/lib/alderpointdns/hardlinked")
        link_info.type = tf.LNKTYPE
        link_info.linkname = "manifest.json"
        self._write_tar(dest, [(m_info, manifest), (link_info, None)])
        with self.assertRaises(backup.BackupError) as ctx:
            backup.extract_backup(dest, None, backup.STAGING_DIR / "extract5")
        self.assertIn("hardlink", str(ctx.exception))

    def test_rejects_device_file_member(self) -> None:
        import tarfile as tf

        dest = backup.STAGING_DIR / "device.tar.gz"
        manifest = self._valid_manifest_bytes()
        m_info = tf.TarInfo("manifest.json")
        m_info.size = len(manifest)
        dev_info = tf.TarInfo("dev/evil")
        dev_info.type = tf.CHRTYPE
        dev_info.devmajor = 1
        dev_info.devminor = 5
        self._write_tar(dest, [(m_info, manifest), (dev_info, None)])
        with self.assertRaises(backup.BackupError) as ctx:
            backup.extract_backup(dest, None, backup.STAGING_DIR / "extract6")
        self.assertIn("unsupported member type", str(ctx.exception))

    def test_rejects_archive_bomb_over_extracted_ceiling(self) -> None:
        import tarfile as tf

        dest = backup.STAGING_DIR / "bomb.tar.gz"
        manifest = self._valid_manifest_bytes()
        m_info = tf.TarInfo("manifest.json")
        m_info.size = len(manifest)
        # A highly-compressible member whose *declared* size alone exceeds
        # the ceiling -- this is what a compressed archive bomb looks like
        # to the extractor: a tiny archive on disk, a huge declared payload.
        bomb_info = tf.TarInfo("var/lib/alderpointdns/bomb.bin")
        bomb_size = 40 * 1024 * 1024
        bomb_info.size = bomb_size
        with self._write_tar_ctx(dest) as tar:
            tar.addfile(m_info, __import__("io").BytesIO(manifest))
            tar.addfile(bomb_info, _ZeroFile(bomb_size))
        with self.assertRaises(backup.BackupError) as ctx:
            backup.extract_backup(dest, None, backup.STAGING_DIR / "extract7", max_extracted_bytes=10 * 1024 * 1024)
        self.assertIn("extracted size exceeds", str(ctx.exception))

    def _write_tar_ctx(self, dest: Path):
        import tarfile as tf

        return tf.open(dest, "w:gz")

    def test_rejects_truncated_archive(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None))
        data = path.read_bytes()
        truncated = backup.STAGING_DIR / "truncated.tar.gz"
        truncated.write_bytes(data[: len(data) // 2])
        with self.assertRaises(backup.BackupError) as ctx:
            backup.extract_backup(truncated, None, backup.STAGING_DIR / "extract8")
        self.assertTrue(
            "corrupt" in str(ctx.exception) or "truncated" in str(ctx.exception) or "not an Alderpoint DNS" in str(ctx.exception)
        )

    def test_restore_backup_rejects_incompatible_format_version(self) -> None:
        with mock.patch.object(backup, "run", self.fake_run):
            path = backup.create_backup(backup.validate_components(None))
        with tempfile.TemporaryDirectory(dir=str(backup.STAGING_DIR)) as tmp:
            extract = Path(tmp) / "x"
            extract.mkdir()
            subprocess.run(["tar", "-xzf", str(path), "-C", str(extract)], check=True)
            manifest = json.loads((extract / "manifest.json").read_text())
            manifest["backup_format_version"] = 999
            (extract / "manifest.json").write_text(json.dumps(manifest))
            rebuilt = backup.BACKUP_DIR / "rebuilt-incompatible.tar.gz"
            subprocess.run(["tar", "-czf", str(rebuilt), "-C", str(extract), "."], check=True)
        # restore_backup catches this internally (same shape as any other
        # restore-time failure) and surfaces it as a RuntimeError after
        # rollback bookkeeping runs, same as the other rollback tests above.
        with mock.patch.object(backup, "run", self.fake_run), mock.patch.object(backup, "resolves", return_value=True), \
                mock.patch.object(backup, "_wait_active", return_value=True):
            with self.assertRaises(RuntimeError) as ctx:
                backup.restore_backup(rebuilt, None, dict.fromkeys(backup.COMPONENT_KEYS, True))
        self.assertIn("not compatible", str(ctx.exception))


class _ZeroFile:
    """File-like object that yields `size` zero bytes without materializing
    them all in memory at once -- used to build a compressed-archive-bomb
    test fixture cheaply."""

    def __init__(self, size: int) -> None:
        self.remaining = size

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = self.remaining
        take = min(n, self.remaining)
        self.remaining -= take
        return b"\x00" * take


if __name__ == "__main__":
    unittest.main()
