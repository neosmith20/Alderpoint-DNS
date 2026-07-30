#!/usr/bin/env python3
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

from app import dns_cache  # noqa: E402


class DNSCacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-dnscache-test-"))
        self.old = {
            "DB_PATH": dns_cache.DB_PATH,
            "COMPILED_DIR": dns_cache.COMPILED_DIR,
            "CACHE_OPTIONS_CONF": dns_cache.CACHE_OPTIONS_CONF,
            "NAMED_OPTIONS_CONF": dns_cache.NAMED_OPTIONS_CONF,
            "BACKUP_DIR": dns_cache.BACKUP_DIR,
            "STAGING_DIR": dns_cache.STAGING_DIR,
        }
        dns_cache.DB_PATH = self.tmp / "alderpointdns.db"
        dns_cache.COMPILED_DIR = self.tmp / "compiled" / "bind"
        dns_cache.CACHE_OPTIONS_CONF = dns_cache.COMPILED_DIR / "cache-options.conf"
        dns_cache.NAMED_OPTIONS_CONF = self.tmp / "named.conf.options"
        dns_cache.BACKUP_DIR = self.tmp / "backups"
        dns_cache.STAGING_DIR = self.tmp / "staging"
        dns_cache.STAGING_DIR.mkdir(parents=True)
        dns_cache.NAMED_OPTIONS_CONF.write_text('options {\n\tdirectory "/var/cache/bind";\n};\n')
        dns_cache.init_db()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            setattr(dns_cache, key, value)
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_run(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "ok\n")

    # -- defaults and validation --------------------------------------

    def test_default_cache_size_is_conservative_fraction_of_memory(self) -> None:
        size = dns_cache.detect_default_cache_size_mb()
        total = dns_cache.detect_total_memory_mb()
        self.assertGreaterEqual(size, 64)
        self.assertLessEqual(size, 512)
        self.assertLessEqual(size, total)

    def test_validate_settings_rejects_out_of_range(self) -> None:
        with self.assertRaises(dns_cache.DNSCacheError):
            dns_cache.validate_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": "8"})

    def test_validate_settings_rejects_cache_size_above_75_percent_of_ram(self) -> None:
        total = dns_cache.detect_total_memory_mb()
        with self.assertRaises(dns_cache.DNSCacheError):
            dns_cache.validate_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": str(total)})

    def test_validate_settings_rejects_min_greater_than_max_ttl(self) -> None:
        with self.assertRaises(dns_cache.DNSCacheError):
            dns_cache.validate_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": "256", "min_cache_ttl": "100", "max_cache_ttl": "50"})

    def test_validate_settings_rejects_min_greater_than_max_ncache_ttl(self) -> None:
        with self.assertRaises(dns_cache.DNSCacheError):
            dns_cache.validate_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": "256", "min_ncache_ttl": "500", "max_ncache_ttl": "100"})

    def test_validate_settings_stale_answer_timeout_off_by_default(self) -> None:
        out = dns_cache.validate_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": "256"})
        self.assertEqual(out["stale_answer_client_timeout"], "off")

    def test_validate_settings_rejects_bad_recursive_client_limit(self) -> None:
        with self.assertRaises(dns_cache.DNSCacheError):
            dns_cache.validate_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": "256", "recursive_clients": "50"})

    def test_update_settings_persists_validated_values(self) -> None:
        dns_cache.update_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": "256", "prefetch_enabled": "1"})
        cfg = dns_cache.settings()
        self.assertEqual(cfg["max_cache_size_mb"], "256")
        self.assertEqual(cfg["prefetch_enabled"], "1")

    # -- rendering -------------------------------------------------------

    def test_render_cache_options_prefetch_disabled_uses_zero_trigger(self) -> None:
        cfg = dict(dns_cache.DEFAULTS)
        cfg["max_cache_size_mb"] = "256"
        content = dns_cache.render_cache_options(cfg)
        self.assertIn("max-cache-size 256m;", content)
        self.assertIn("recursive-clients 1000;", content)
        self.assertIn("prefetch 0;", content)
        self.assertIn("stale-answer-enable no;", content)
        self.assertNotIn("max-stale-ttl", content)

    def test_render_cache_options_prefetch_and_serve_stale_enabled(self) -> None:
        cfg = dict(dns_cache.DEFAULTS)
        cfg.update(max_cache_size_mb="256", prefetch_enabled="1", prefetch_trigger="3", prefetch_eligible="15", serve_stale_enabled="1", max_stale_ttl="7200", stale_answer_client_timeout="1800")
        content = dns_cache.render_cache_options(cfg)
        self.assertIn("prefetch 3 15;", content)
        self.assertIn("stale-answer-enable yes;", content)
        self.assertIn("max-stale-ttl 7200;", content)
        self.assertIn("stale-answer-client-timeout 1800;", content)

    # -- named.conf.options include migration -----------------------------

    def test_ensure_named_options_include_is_idempotent(self) -> None:
        changed_first = dns_cache.ensure_named_options_include()
        self.assertTrue(changed_first)
        self.assertIn(str(dns_cache.CACHE_OPTIONS_CONF), dns_cache.NAMED_OPTIONS_CONF.read_text())
        backups_after_first = list(dns_cache.BACKUP_DIR.glob("named.conf.options.pre-cache.*"))
        self.assertEqual(len(backups_after_first), 1)
        changed_second = dns_cache.ensure_named_options_include()
        self.assertFalse(changed_second)
        backups_after_second = list(dns_cache.BACKUP_DIR.glob("named.conf.options.pre-cache.*"))
        self.assertEqual(len(backups_after_second), 1)

    # -- deploy staged/validate/backup/atomic/health/rollback -------------

    def test_deploy_cache_options_success(self) -> None:
        dns_cache.update_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": "128"})
        with mock.patch.object(dns_cache, "run", self.fake_run), mock.patch.object(dns_cache, "resolves", return_value=True):
            dns_cache.deploy_cache_options()
        self.assertIn("max-cache-size 128m;", dns_cache.CACHE_OPTIONS_CONF.read_text())
        deployment = dns_cache.last_deployment()
        self.assertEqual(deployment["status"], "deployed")

    def test_deploy_cache_options_rolls_back_on_failed_health_check(self) -> None:
        dns_cache.update_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": "128"})
        with mock.patch.object(dns_cache, "run", self.fake_run), mock.patch.object(dns_cache, "resolves", return_value=True):
            dns_cache.deploy_cache_options()
        good_content = dns_cache.CACHE_OPTIONS_CONF.read_text()

        dns_cache.update_settings({**dns_cache.DEFAULTS, "max_cache_size_mb": "256"})
        with self.assertRaises(RuntimeError):
            with mock.patch.object(dns_cache, "run", self.fake_run), mock.patch.object(dns_cache, "resolves", return_value=False):
                dns_cache.deploy_cache_options()
        self.assertEqual(dns_cache.CACHE_OPTIONS_CONF.read_text(), good_content)
        deployment = dns_cache.last_deployment()
        self.assertEqual(deployment["status"], "rolled_back")

    def test_deploy_cache_options_invalid_config_does_not_touch_live_file(self) -> None:
        with dns_cache.connect() as conn:
            dns_cache.init_db(conn)
            conn.execute("UPDATE dns_cache_settings SET value=? WHERE key='max_cache_size_mb'", ("not-a-number",))
            conn.commit()
        with self.assertRaises(ValueError):
            with mock.patch.object(dns_cache, "run", self.fake_run):
                dns_cache.deploy_cache_options()
        self.assertFalse(dns_cache.CACHE_OPTIONS_CONF.exists())

    # -- flush requests -----------------------------------------------------

    def test_request_flush_validates_scope_and_target(self) -> None:
        with self.assertRaises(dns_cache.DNSCacheError):
            dns_cache.request_flush("bogus")
        with self.assertRaises(dns_cache.DNSCacheError):
            dns_cache.request_flush("name", "")
        flush_id = dns_cache.request_flush("name", " Example.COM. ")
        rows = dns_cache.recent_flushes()
        self.assertEqual(rows[0]["id"], flush_id)
        self.assertEqual(rows[0]["target"], "example.com")

    def test_process_pending_flush_all(self) -> None:
        commands = []

        def recording_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return self.fake_run(command, check)

        dns_cache.request_flush("all")
        with mock.patch.object(dns_cache, "run", recording_run):
            dns_cache.process_pending_flush()
        self.assertTrue(any(cmd == ["rndc", "flush"] for cmd in commands))
        self.assertEqual(dns_cache.recent_flushes()[0]["status"], "completed")

    def test_process_pending_flush_name_and_tree(self) -> None:
        commands = []

        def recording_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return self.fake_run(command, check)

        dns_cache.request_flush("name", "example.com")
        with mock.patch.object(dns_cache, "run", recording_run):
            dns_cache.process_pending_flush()
        self.assertIn(["rndc", "flushname", "example.com"], commands)

        dns_cache.request_flush("tree", "example.com")
        with mock.patch.object(dns_cache, "run", recording_run):
            dns_cache.process_pending_flush()
        self.assertIn(["rndc", "flushtree", "example.com"], commands)

    def test_process_pending_flush_only_applies_newest_request(self) -> None:
        dns_cache.request_flush("name", "old.example")
        dns_cache.request_flush("name", "new.example")
        with mock.patch.object(dns_cache, "run", self.fake_run):
            dns_cache.process_pending_flush()
        rows = {row["target"]: row["status"] for row in dns_cache.recent_flushes()}
        self.assertEqual(rows["new.example"], "completed")
        self.assertEqual(rows["old.example"], "skipped")

    def test_process_pending_flush_records_failure(self) -> None:
        def failing_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            raise subprocess.CalledProcessError(1, command, "rndc: connection refused")

        dns_cache.request_flush("all")
        with mock.patch.object(dns_cache, "run", failing_run):
            dns_cache.process_pending_flush()
        self.assertEqual(dns_cache.recent_flushes()[0]["status"], "failed")

    # -- stats ---------------------------------------------------------

    def test_cache_stats_computes_hit_percent(self) -> None:
        fake_payload = {
            "views": {
                "_default": {
                    "resolver": {
                        "cachestats": {
                            "CacheHits": 300,
                            "CacheMisses": 100,
                            "CacheNodes": 42,
                            "TreeMemInUse": 1000,
                            "HeapMemInUse": 500,
                            "DeleteLRU": 2,
                            "DeleteTTL": 5,
                        }
                    }
                }
            }
        }
        with mock.patch.object(dns_cache, "bind_server_stats", return_value=fake_payload):
            stats = dns_cache.cache_stats()
        self.assertTrue(stats["available"])
        self.assertEqual(stats["hits"], 300)
        self.assertEqual(stats["misses"], 100)
        self.assertAlmostEqual(stats["hit_percent"], 75.0)
        self.assertEqual(stats["memory_bytes"], 1500)

    def test_cache_stats_unavailable_does_not_raise(self) -> None:
        with mock.patch.object(dns_cache, "bind_server_stats", side_effect=OSError("connection refused")):
            stats = dns_cache.cache_stats()
        self.assertFalse(stats["available"])
        self.assertIn("error", stats)


if __name__ == "__main__":
    unittest.main()
