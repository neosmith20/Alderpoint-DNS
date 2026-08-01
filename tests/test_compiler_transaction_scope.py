#!/usr/bin/env python3
"""Regression coverage for the compiler-side half of the beta.5 SQLite
concurrency hotfix: collect_rules()/deploy() must never hold an open SQLite
write transaction while performing network downloads, subprocess execution,
dnsdist/BIND validation, service restarts, or DNS test queries. Before this
fix, collect_rules() wrote each source's download result immediately inside
its per-source download loop, leaving a write transaction open across every
remaining source's network download and, transitively, across deploy()'s
subsequent RPZ validation/BIND validation/service-reload subprocess calls --
exactly the kind of long-held writer lock that produced the "database is
locked" HTTP 500 reported against webapp.py.
"""

from __future__ import annotations

import shutil
import sqlite3
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

from app import alderpointdns_compiler as compiler  # noqa: E402
from app import custom_rules, dns_cache, local_dns  # noqa: E402


class CompilerTransactionScopeTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-txn-scope-test-"))
        self.old = {
            "c_DB_PATH": compiler.DB_PATH,
            "c_DOWNLOAD_DIR": compiler.DOWNLOAD_DIR,
            "c_COMPILED_RPZ": compiler.COMPILED_RPZ,
            "c_STAGING_DIR": compiler.STAGING_DIR,
            "c_BACKUP_DIR": compiler.BACKUP_DIR,
            "c_DEPLOY_LOCK": compiler.DEPLOY_LOCK,
            "c_MIGRATION_LOCK": compiler.MIGRATION_LOCK,
            "l_DB_PATH": local_dns.DB_PATH,
            "dc_DB_PATH": dns_cache.DB_PATH,
            "dc_COMPILED_DIR": dns_cache.COMPILED_DIR,
            "dc_CACHE_OPTIONS_CONF": dns_cache.CACHE_OPTIONS_CONF,
            "dc_NAMED_OPTIONS_CONF": dns_cache.NAMED_OPTIONS_CONF,
            "dc_BACKUP_DIR": dns_cache.BACKUP_DIR,
            "dc_STAGING_DIR": dns_cache.STAGING_DIR,
            "cr_DB_PATH": custom_rules.DB_PATH,
            "cr_COMPILED_DNSDIST_DIR": custom_rules.COMPILED_DNSDIST_DIR,
            "cr_DNSDIST_CONF": custom_rules.DNSDIST_CONF,
            "cr_DNSDIST_PACKAGING_CONF": custom_rules.DNSDIST_PACKAGING_CONF,
            "cr_BACKUP_DIR": custom_rules.BACKUP_DIR,
            "cr_STAGING_DIR": custom_rules.STAGING_DIR,
        }
        db_path = self.tmp / "alderpointdns.db"
        compiler.DB_PATH = db_path
        compiler.DOWNLOAD_DIR = self.tmp / "downloads"
        compiler.COMPILED_RPZ = self.tmp / "compiled" / "bind" / "alderpointdns.rpz"
        compiler.STAGING_DIR = self.tmp / "staging"
        compiler.BACKUP_DIR = self.tmp / "backups"
        compiler.DEPLOY_LOCK = self.tmp / "staging" / "deploy.lock"
        compiler.MIGRATION_LOCK = self.tmp / "staging" / "schema-migration.lock"
        local_dns.DB_PATH = db_path
        dns_cache.DB_PATH = db_path
        dns_cache.COMPILED_DIR = self.tmp / "compiled" / "bind"
        dns_cache.CACHE_OPTIONS_CONF = dns_cache.COMPILED_DIR / "cache-options.conf"
        dns_cache.NAMED_OPTIONS_CONF = self.tmp / "named.conf.options"
        dns_cache.BACKUP_DIR = self.tmp / "backups"
        dns_cache.STAGING_DIR = self.tmp / "staging"
        custom_rules.DB_PATH = db_path
        custom_rules.COMPILED_DNSDIST_DIR = self.tmp / "compiled" / "dnsdist"
        custom_rules.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        custom_rules.DNSDIST_PACKAGING_CONF = self.tmp / "packaging-dnsdist.conf"
        custom_rules.BACKUP_DIR = self.tmp / "backups"
        custom_rules.STAGING_DIR = self.tmp / "staging"
        compiler.STAGING_DIR.mkdir(parents=True)
        dns_cache.NAMED_OPTIONS_CONF.write_text('options {\n\tdirectory "/var/cache/bind";\n};\n')
        custom_rules.DNSDIST_CONF.write_text(
            '-- lab config\naddAction(AllRule(), PoolAction("alderpointdns_bind"))\n'
        )
        compiler.init_db()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            prefix, name = key.split("_", 1)
            module = {"c": compiler, "l": local_dns, "dc": dns_cache, "cr": custom_rules}[prefix]
            setattr(module, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(compiler.DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def fake_run_ok(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "ok\n")

    def add_source_with_content(self, name: str, content: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO sources(name, url, enabled) VALUES (?, ?, 1)",
                (name, f"https://filters.example/{name}.txt"),
            )
            conn.commit()
            source = conn.execute("SELECT * FROM sources WHERE name=?", (name,)).fetchone()
        current_path, _staging_path = compiler.source_paths(source)
        current_path.parent.mkdir(parents=True, exist_ok=True)
        current_path.write_text(content)


class CollectRulesTransactionScopeTests(CompilerTransactionScopeTestBase):
    def test_no_open_write_transaction_during_downloads(self) -> None:
        self.add_source_with_content("source-a", "blocked-a.example\n")
        self.add_source_with_content("source-b", "blocked-b.example\n")

        transaction_open_during_download: list[bool] = []
        conn = self.connect()

        def fake_download_source(source: sqlite3.Row) -> compiler.SourceResult:
            transaction_open_during_download.append(conn.in_transaction)
            current_path, _ = compiler.source_paths(source)
            return compiler.SourceResult(source["id"], source["name"], source["url"], True, path=current_path)

        try:
            with mock.patch.object(compiler, "download_source", side_effect=fake_download_source):
                compiler.collect_rules(conn, download=True)
        finally:
            conn.close()

        self.assertEqual(len(transaction_open_during_download), 2)
        self.assertFalse(
            any(transaction_open_during_download),
            "collect_rules() must not hold an open write transaction while downloading a source",
        )

    def test_collect_rules_commits_before_returning(self) -> None:
        self.add_source_with_content("source-a", "blocked-a.example\n")
        conn = self.connect()
        try:
            compiler.collect_rules(conn, download=False)
            self.assertFalse(conn.in_transaction, "collect_rules() must commit its own writes before returning")
        finally:
            conn.close()


class DeployTransactionScopeTests(CompilerTransactionScopeTestBase):
    def test_deploy_holds_no_open_transaction_during_slow_operations(self) -> None:
        """Every slow step deploy() performs after collect_rules() --
        subprocess-based RPZ/BIND validation, a service reload, each
        deploy_* helper's own subprocess/DNS work, live DNS resolution
        checks, and the post-deploy blocked/allowed-domain polling loops --
        must see no pending write transaction on the shared connection."""
        transaction_states: dict[str, bool] = {}

        def record(conn: sqlite3.Connection, name: str):
            transaction_states[name] = conn.in_transaction

        with mock.patch.object(compiler, "run", self.fake_run_ok), \
                mock.patch.object(custom_rules, "run", self.fake_run_ok), \
                mock.patch.object(compiler, "resolves", lambda domain: True), \
                mock.patch.object(compiler, "is_blocked", lambda domain: True), \
                mock.patch.object(compiler.local_dns, "deploy_zones", lambda conn=None: record(conn, "deploy_zones") or 1), \
                mock.patch.object(compiler.dns_cache, "deploy_cache_options", lambda conn=None: record(conn, "deploy_cache_options") or 1), \
                mock.patch.object(compiler.upstream_dns, "deploy_upstreams", lambda conn=None: record(conn, "deploy_upstreams") or 1), \
                mock.patch.object(compiler.custom_rules, "deploy_dnsdist_layer", lambda conn, active=None: record(conn, "deploy_dnsdist_layer") or {"changed": False, "backups": [], "counts": {}}), \
                mock.patch.object(compiler.replication, "on_deploy_success", lambda conn=None: record(conn, "on_deploy_success")):
            deployment_id = compiler.deploy(download=False)

        with self.connect() as conn:
            row = conn.execute("SELECT status FROM deployments WHERE id=?", (deployment_id,)).fetchone()
        self.assertEqual(row["status"], "deployed")

        self.assertIn("deploy_zones", transaction_states)
        self.assertIn("deploy_cache_options", transaction_states)
        self.assertIn("deploy_upstreams", transaction_states)
        self.assertIn("on_deploy_success", transaction_states)
        for name, in_transaction in transaction_states.items():
            self.assertFalse(in_transaction, f"deploy() entered {name}() with an open write transaction")


if __name__ == "__main__":
    unittest.main()
