#!/usr/bin/env python3
import contextlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import app.alderpointdns_compiler as compiler
from app.alderpointdns_compiler import SourceResult


class FreshInstallDefaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_ctx = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmp_ctx.name)
        self.originals = {
            "DB_PATH": compiler.DB_PATH,
            "DOWNLOAD_DIR": compiler.DOWNLOAD_DIR,
            "COMPILED_RPZ": compiler.COMPILED_RPZ,
            "STAGING_DIR": compiler.STAGING_DIR,
            "BACKUP_DIR": compiler.BACKUP_DIR,
            "DEPLOY_LOCK": compiler.DEPLOY_LOCK,
            "MIGRATION_LOCK": compiler.MIGRATION_LOCK,
            "LOCAL_ZONES_CONF": compiler.local_dns.LOCAL_ZONES_CONF,
            "CACHE_OPTIONS_CONF": compiler.dns_cache.CACHE_OPTIONS_CONF,
        }
        compiler.DB_PATH = self.tmp / "alderpointdns.db"
        compiler.DOWNLOAD_DIR = self.tmp / "downloads"
        compiler.COMPILED_RPZ = self.tmp / "compiled" / "bind" / "alderpointdns.rpz"
        compiler.STAGING_DIR = self.tmp / "staging"
        compiler.BACKUP_DIR = self.tmp / "backups"
        compiler.DEPLOY_LOCK = self.tmp / "staging" / "deploy.lock"
        compiler.MIGRATION_LOCK = self.tmp / "staging" / "schema-migration.lock"
        compiler.local_dns.LOCAL_ZONES_CONF = self.tmp / "compiled" / "bind" / "local-zones.conf"
        compiler.dns_cache.CACHE_OPTIONS_CONF = self.tmp / "compiled" / "bind" / "cache-options.conf"
        compiler.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        compiler.BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        for name, value in self.originals.items():
            if name == "LOCAL_ZONES_CONF":
                compiler.local_dns.LOCAL_ZONES_CONF = value
            elif name == "CACHE_OPTIONS_CONF":
                compiler.dns_cache.CACHE_OPTIONS_CONF = value
            else:
                setattr(compiler, name, value)
        self.tmp_ctx.cleanup()

    def _mock_deploy_edges(self):
        return contextlib.ExitStack()

    def _patch_successful_deploy_edges(self):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(compiler, "validate_rpz", return_value=None))
        stack.enter_context(mock.patch.object(compiler, "validate_bind", return_value=None))
        stack.enter_context(mock.patch.object(compiler, "reload_bind", return_value=None))
        stack.enter_context(mock.patch.object(compiler, "resolves", return_value=True))
        stack.enter_context(mock.patch.object(compiler, "is_blocked", return_value=True))
        stack.enter_context(mock.patch.object(compiler.local_dns, "deploy_zones", return_value=1))
        stack.enter_context(mock.patch.object(compiler.dns_cache, "deploy_cache_options", return_value=1))
        stack.enter_context(mock.patch.object(compiler.upstream_dns, "deploy_upstreams", return_value=1))
        stack.enter_context(mock.patch.object(compiler.custom_rules, "deploy_dnsdist_layer", return_value=None))
        stack.enter_context(mock.patch.object(compiler.replication, "on_deploy_success", return_value=None))
        return stack

    def _download_side_effect(self, broken_id: int | None = None):
        def _download(source: sqlite3.Row) -> SourceResult:
            path = compiler.source_paths(source)[0]
            if broken_id is not None and source["id"] == broken_id:
                return SourceResult(source["id"], source["name"], source["url"], False, error="temporary upstream failure")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"0.0.0.0 default-{source['id']}.example\n0.0.0.0 overlap.example\n")
            return SourceResult(source["id"], source["name"], source["url"], True, http_status=200, downloaded_bytes=path.stat().st_size, path=path)

        return _download

    def _simulate_established_legacy_db(self) -> None:
        compiler.init_db()
        with compiler.connect() as conn:
            conn.execute("PRAGMA user_version=0")

    def test_default_catalog_is_small_and_canonical(self):
        defaults = compiler.DEFAULT_FRESH_INSTALL_SOURCES
        self.assertEqual(3, len(defaults))
        self.assertEqual(
            [
                (
                    "AdGuard DNS filter",
                    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
                    "AdGuardTeam/AdGuardSDNSFilter",
                ),
                (
                    "StevenBlack Unified Hosts",
                    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                    "StevenBlack/hosts",
                ),
                (
                    "HaGeZi Multi Normal",
                    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
                    "hagezi/dns-blocklists",
                ),
            ],
            [(source.name, source.url, source.upstream_project) for source in defaults],
        )
        self.assertTrue(all(source.purpose for source in defaults))

    def test_fresh_install_seeds_defaults_once_as_ordinary_sources(self):
        compiler.init_db(seed_defaults=True)
        compiler.init_db(seed_defaults=True)
        with compiler.connect() as conn:
            rows = conn.execute("SELECT name, url, enabled, category FROM sources ORDER BY id").fetchall()
            conn.execute("UPDATE sources SET enabled=0 WHERE name=?", (rows[0]["name"],))
            conn.execute("DELETE FROM sources WHERE name=?", (rows[1]["name"],))
            remaining = conn.execute("SELECT count(*) FROM sources").fetchone()[0]
        self.assertEqual(3, len(rows))
        self.assertEqual(2, remaining)
        self.assertTrue(all(row["enabled"] == 1 for row in rows))
        self.assertEqual([source.name for source in compiler.DEFAULT_FRESH_INSTALL_SOURCES], [row["name"] for row in rows])

    def test_fresh_install_init_downloads_compiles_deploys_and_makes_protection_active(self):
        with self._patch_successful_deploy_edges():
            with mock.patch.object(compiler, "download_source", side_effect=self._download_side_effect()):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    compiler.fresh_install_init()
        output = out.getvalue()
        self.assertIn("fresh_install=1 seeded_defaults=3", output)
        self.assertIn("initial_deploy=deployed", output)
        with compiler.connect() as conn:
            rows = conn.execute("SELECT * FROM sources ORDER BY id").fetchall()
            deployment = conn.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(3, len(rows))
        self.assertTrue(all(row["last_success"] for row in rows))
        self.assertEqual("deployed", deployment["status"])
        self.assertGreater(deployment["active_domains"], 0)
        self.assertGreater(len(compiler.COMPILED_RPZ.read_text()), 0)

    def test_download_failure_does_not_mark_protection_active_and_retry_can_succeed(self):
        with self._patch_successful_deploy_edges():
            with mock.patch.object(compiler, "download_source", side_effect=self._download_side_effect(broken_id=2)):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    compiler.fresh_install_init()
        self.assertIn("initial_deploy=failed", out.getvalue())
        self.assertFalse(compiler.COMPILED_RPZ.exists())
        with compiler.connect() as conn:
            deployment = conn.execute("SELECT * FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
            self.assertEqual("rolled_back", deployment["status"])
            self.assertEqual(0, deployment["active_domains"])
            self.assertEqual(3, conn.execute("SELECT count(*) FROM sources").fetchone()[0])

        with self._patch_successful_deploy_edges():
            with mock.patch.object(compiler, "download_source", side_effect=self._download_side_effect()):
                deployment_id = compiler.deploy(download=True, trigger="manual-retry", fail_on_source_errors=True)
        with compiler.connect() as conn:
            retry = conn.execute("SELECT * FROM deployments WHERE id=?", (deployment_id,)).fetchone()
        self.assertEqual("deployed", retry["status"])
        self.assertGreater(retry["active_domains"], 0)
        self.assertTrue(compiler.COMPILED_RPZ.exists())

    def test_existing_install_zero_sources_remains_zero_and_no_deploy_runs(self):
        compiler.init_db()
        with mock.patch.object(compiler, "deploy", side_effect=AssertionError("deploy should not run")):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                compiler.fresh_install_init()
        with compiler.connect() as conn:
            self.assertEqual(0, conn.execute("SELECT count(*) FROM sources").fetchone()[0])
        self.assertIn("fresh_install=0", out.getvalue())

    def test_existing_older_schema_zero_sources_remains_zero_and_no_deploy_runs(self):
        self._simulate_established_legacy_db()
        with mock.patch.object(compiler, "deploy", side_effect=AssertionError("deploy should not run")):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                compiler.fresh_install_init()
        with compiler.connect() as conn:
            self.assertEqual(compiler.SCHEMA_VERSION, conn.execute("PRAGMA user_version").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT count(*) FROM sources").fetchone()[0])
        self.assertIn("fresh_install=0", out.getvalue())

    def test_existing_sources_and_protection_state_remain_unchanged(self):
        compiler.init_db()
        with compiler.connect() as conn:
            conn.execute(
                "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 0, 'ads_trackers')",
                ("Custom disabled", "https://example.invalid/list.txt"),
            )
            conn.execute(
                "INSERT INTO deployments(started_at, finished_at, status, active_domains, message) VALUES (?, ?, 'deployed', 42, 'existing')",
                (compiler.now(), compiler.now()),
            )
        with mock.patch.object(compiler, "deploy", side_effect=AssertionError("deploy should not run")):
            compiler.fresh_install_init()
        with compiler.connect() as conn:
            source = conn.execute("SELECT name, url, enabled FROM sources").fetchone()
            deployment = conn.execute("SELECT active_domains, message FROM deployments").fetchone()
        self.assertEqual(("Custom disabled", "https://example.invalid/list.txt", 0), tuple(source))
        self.assertEqual((42, "existing"), tuple(deployment))

    def test_existing_older_schema_custom_sources_and_protection_off_remain_unchanged(self):
        self._simulate_established_legacy_db()
        with compiler.connect() as conn:
            conn.execute(
                "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                ("Custom enabled", "https://example.test/custom.txt"),
            )
            conn.execute(
                "INSERT INTO deployments(started_at, finished_at, status, active_domains, message) VALUES (?, ?, 'deployed', 0, 'protection off')",
                (compiler.now(), compiler.now()),
            )
            conn.execute("PRAGMA user_version=0")
        with mock.patch.object(compiler, "deploy", side_effect=AssertionError("deploy should not run")):
            compiler.fresh_install_init()
        with compiler.connect() as conn:
            rows = conn.execute("SELECT name, url, enabled FROM sources ORDER BY id").fetchall()
            deployment = conn.execute("SELECT active_domains, message FROM deployments").fetchone()
        self.assertEqual([("Custom enabled", "https://example.test/custom.txt", 1)], [tuple(row) for row in rows])
        self.assertEqual((0, "protection off"), tuple(deployment))

    def test_existing_older_schema_custom_sources_and_protection_on_remain_unchanged(self):
        self._simulate_established_legacy_db()
        with compiler.connect() as conn:
            conn.execute(
                "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 0, 'ads_trackers')",
                ("Custom disabled", "https://example.test/disabled.txt"),
            )
            conn.execute(
                "INSERT INTO deployments(started_at, finished_at, status, active_domains, message) VALUES (?, ?, 'deployed', 17, 'protection on')",
                (compiler.now(), compiler.now()),
            )
            conn.execute("PRAGMA user_version=0")
        with mock.patch.object(compiler, "deploy", side_effect=AssertionError("deploy should not run")):
            compiler.fresh_install_init()
        with compiler.connect() as conn:
            rows = conn.execute("SELECT name, url, enabled FROM sources ORDER BY id").fetchall()
            deployment = conn.execute("SELECT active_domains, message FROM deployments").fetchone()
        self.assertEqual([("Custom disabled", "https://example.test/disabled.txt", 0)], [tuple(row) for row in rows])
        self.assertEqual((17, "protection on"), tuple(deployment))

    def test_compiler_deduplication_handles_overlap_between_defaults(self):
        compiler.init_db(seed_defaults=True)
        with compiler.connect() as conn:
            with mock.patch.object(compiler, "download_source", side_effect=self._download_side_effect()):
                active, _allows, per_source, errors = compiler.collect_rules(conn, download=True)
        self.assertEqual([], errors)
        self.assertEqual({"default-1.example", "default-2.example", "default-3.example", "overlap.example"}, active)
        self.assertEqual(2, per_source[1].unique_active_domains)
        self.assertEqual(1, per_source[2].unique_active_domains)
        self.assertEqual(1, per_source[3].unique_active_domains)


if __name__ == "__main__":
    unittest.main()
