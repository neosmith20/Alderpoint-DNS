#!/usr/bin/env python3
from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import warnings
from contextlib import closing
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import encryption, replication  # noqa: E402


class ReplicationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-replication-test-"))
        self.old = {
            "DB_PATH": replication.DB_PATH,
            "BACKUP_DIR": replication.BACKUP_DIR,
            "STAGING_DIR": replication.STAGING_DIR,
            "REPL_DIR": replication.REPL_DIR,
            "SERVER_CERT_PATH": replication.SERVER_CERT_PATH,
            "SERVER_KEY_PATH": replication.SERVER_KEY_PATH,
            "PENDING_ENROLLMENT_TOKEN_HASH": replication.PENDING_ENROLLMENT_TOKEN_HASH,
            "CA_CERT_PATH": encryption.CA_CERT_PATH,
            "CA_KEY_PATH": encryption.CA_KEY_PATH,
            "CA_SERIAL_PATH": encryption.CA_SERIAL_PATH,
        }
        replication.DB_PATH = self.tmp / "alderpointdns.db"
        replication.BACKUP_DIR = self.tmp / "backups"
        replication.STAGING_DIR = self.tmp / "staging"
        replication.REPL_DIR = self.tmp / "replication"
        replication.SERVER_CERT_PATH = replication.REPL_DIR / "replication-server.crt"
        replication.SERVER_KEY_PATH = replication.REPL_DIR / "replication-server.key"
        replication.PENDING_ENROLLMENT_TOKEN_HASH = replication.STAGING_DIR / "pending-enrollment-token-hash"
        encryption.CA_CERT_PATH = self.tmp / "certs" / "ca.crt"
        encryption.CA_KEY_PATH = self.tmp / "certs" / "ca.key"
        encryption.CA_SERIAL_PATH = self.tmp / "certs" / "ca.srl"
        replication.STAGING_DIR.mkdir(parents=True)
        replication.BACKUP_DIR.mkdir(parents=True)
        replication.REPL_DIR.mkdir(parents=True)
        encryption.CA_CERT_PATH.parent.mkdir(parents=True)
        replication.init_db()
        self._create_replicable_schema()

    def tearDown(self) -> None:
        replication.stop_primary_listener()
        replication.stop_replica_poller()
        for key, value in self.old.items():
            if key.startswith("CA_"):
                setattr(encryption, key, value)
            else:
                setattr(replication, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _create_replicable_schema(self) -> None:
        with closing(replication.connect()) as conn:
            conn.executescript(
                """
                CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT, url TEXT, enabled INTEGER DEFAULT 1, category TEXT DEFAULT 'custom');
                CREATE TABLE custom_rules (id INTEGER PRIMARY KEY, domain TEXT, action TEXT DEFAULT 'block', enabled INTEGER DEFAULT 1, comment TEXT DEFAULT '', created_at TEXT DEFAULT '');
                CREATE TABLE categories (id INTEGER PRIMARY KEY, key TEXT, name TEXT, description TEXT);
                CREATE TABLE policy_profiles (id INTEGER PRIMARY KEY, key TEXT, name TEXT, description TEXT, is_custom INTEGER DEFAULT 0);
                CREATE TABLE profile_categories (id INTEGER PRIMARY KEY, profile_key TEXT, category_key TEXT, enabled INTEGER DEFAULT 1);
                CREATE TABLE network_policies (id INTEGER PRIMARY KEY, cidr TEXT, profile_key TEXT, description TEXT, enabled INTEGER DEFAULT 1);
                CREATE TABLE local_dns_records (id INTEGER PRIMARY KEY, name TEXT, fqdn TEXT, record_type TEXT, value TEXT, ttl INTEGER, comment TEXT, enabled INTEGER, auto_ptr INTEGER, created_at TEXT, updated_at TEXT);
                CREATE TABLE client_aliases (id INTEGER PRIMARY KEY, cidr TEXT, display_name TEXT, description TEXT, created_at TEXT, updated_at TEXT);
                CREATE TABLE local_dns_settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE dns_cache_settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE encryption_settings (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE query_events (id INTEGER PRIMARY KEY, domain TEXT);
                """
            )
            conn.execute("INSERT INTO sources(name, url, enabled, category) VALUES ('old', 'file:///old', 1, 'custom')")
            conn.execute("INSERT INTO local_dns_settings(key, value) VALUES ('internal_domain', 'old.home.arpa')")
            conn.execute("INSERT INTO local_dns_settings(key, value) VALUES ('server_hostname', 'replica-only')")
            conn.execute("INSERT INTO dns_cache_settings(key, value) VALUES ('max_cache_size_mb', '128')")
            conn.execute("INSERT INTO encryption_settings(key, value) VALUES ('doh_enabled', '0')")
            conn.execute("INSERT INTO query_events(domain) VALUES ('private.example')")
            conn.commit()

    def test_payload_excludes_sensitive_and_node_local_tables(self) -> None:
        with closing(replication.connect()) as conn:
            payload = replication.build_payload(conn)
        self.assertIn("sources", payload)
        self.assertNotIn("query_events", payload)
        self.assertNotIn("replication_settings", payload)
        self.assertEqual(payload["local_dns_settings"], {"internal_domain": "old.home.arpa"})

    def test_replica_sync_rolls_back_sqlite_changes_when_deploy_fails(self) -> None:
        generation_sections = {
            "sources": [{"name": "primary", "url": "file:///primary", "enabled": 1, "category": "custom"}],
            "local_dns_settings": {"internal_domain": "primary.home.arpa", "default_ttl": "600"},
            "dns_cache_settings": {"max_cache_size_mb": "256", "prefetch_enabled": "1"},
            "encryption_settings": {"doh_enabled": "1", "doh_port": "9443"},
        }
        generation = {
            "generation_number": 1,
            "schema_version": replication.SCHEMA_VERSION,
            "content_hash": replication.content_hash(generation_sections),
            "sections": generation_sections,
        }
        rc = replication.ReplicaContext(
            db_path=replication.DB_PATH,
            primary_host="primary.invalid",
            primary_port=8843,
            ca_cert=self.tmp / "ca.crt",
            client_cert=self.tmp / "client.crt",
            client_key=self.tmp / "client.key",
            deploy_fn=lambda: (False, "simulated deploy failure"),
        )
        with mock.patch.object(replication, "fetch_latest_generation", return_value=generation), mock.patch.object(replication, "ack_generation"):
            result = replication.replica_sync_once(rc, force=True)

        self.assertEqual(result["result"], "failed")
        with closing(replication.connect()) as conn:
            source = conn.execute("SELECT name, url FROM sources").fetchone()
            self.assertEqual(dict(source), {"name": "old", "url": "file:///old"})
            local = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM local_dns_settings")}
            cache = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM dns_cache_settings")}
            enc = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM encryption_settings")}
        self.assertEqual(local, {"internal_domain": "old.home.arpa", "server_hostname": "replica-only"})
        self.assertEqual(cache, {"max_cache_size_mb": "128"})
        self.assertEqual(enc, {"doh_enabled": "0"})

    def test_replica_sync_success_replaces_replicated_settings_without_touching_local_identity(self) -> None:
        generation_sections = {
            "sources": [{"name": "primary", "url": "file:///primary", "enabled": 1, "category": "custom"}],
            "local_dns_settings": {"internal_domain": "primary.home.arpa"},
            "dns_cache_settings": {},
        }
        generation = {
            "generation_number": 2,
            "schema_version": replication.SCHEMA_VERSION,
            "content_hash": replication.content_hash(generation_sections),
            "sections": generation_sections,
        }
        rc = replication.ReplicaContext(
            db_path=replication.DB_PATH,
            primary_host="primary.invalid",
            primary_port=8843,
            ca_cert=self.tmp / "ca.crt",
            client_cert=self.tmp / "client.crt",
            client_key=self.tmp / "client.key",
            deploy_fn=lambda: (True, "ok"),
        )
        with mock.patch.object(replication, "fetch_latest_generation", return_value=generation), mock.patch.object(replication, "ack_generation"):
            result = replication.replica_sync_once(rc, force=True)

        self.assertEqual(result["result"], "success")
        with closing(replication.connect()) as conn:
            local = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM local_dns_settings")}
            cache = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM dns_cache_settings")}
            source = conn.execute("SELECT name FROM sources").fetchone()["name"]
        self.assertEqual(source, "primary")
        self.assertEqual(local, {"internal_domain": "primary.home.arpa", "server_hostname": "replica-only"})
        self.assertEqual(cache, {})

    def test_revoked_replica_certificate_is_rejected(self) -> None:
        fingerprint = "a" * 64
        with closing(replication.connect()) as conn:
            conn.execute(
                """
                INSERT INTO replication_replicas(node_id, display_name, cert_fingerprint, cert_serial, enrolled_at, status)
                VALUES ('node-1', 'replica-1', ?, '01', ?, 'revoked')
                """,
                (fingerprint, replication.now()),
            )
            conn.commit()
            handler_cls = replication._make_handler(
                replication.ServerContext(
                    replication.DB_PATH,
                    self.tmp / "ca.crt",
                    self.tmp / "server.crt",
                    self.tmp / "server.key",
                )
            )
            handler = handler_cls.__new__(handler_cls)
            handler._peer_fingerprint = lambda: fingerprint  # type: ignore[method-assign]
            with self.assertRaisesRegex(PermissionError, "revoked"):
                handler._authenticated_replica(conn)

    def test_enrollment_request_stages_only_valid_pending_token_hash(self) -> None:
        token = replication.generate_enrollment_token("replica-1")
        result = replication.request_enrollment_consumption(token["token"])
        self.assertEqual(result["node_name"], "replica-1")
        self.assertTrue(replication.PENDING_ENROLLMENT_TOKEN_HASH.exists())
        self.assertEqual(replication.PENDING_ENROLLMENT_TOKEN_HASH.read_text(), replication._hash_token(token["token"]))
        with self.assertRaises(replication.ReplicationError):
            replication.request_enrollment_consumption("wrong-token")


if __name__ == "__main__":
    unittest.main()
