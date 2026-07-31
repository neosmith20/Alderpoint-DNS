#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
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


if __name__ == "__main__":
    unittest.main()
