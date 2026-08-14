#!/usr/bin/env python3
"""Tests for app/v2/secret_store.py (Workstream 2, §11, §33 SECRETS)."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import secret_store as ss  # noqa: E402


class TestSecretStoreCrud(unittest.TestCase):
    def test_create_get_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            sid = store.create("super-secret-token")
            self.assertEqual(store.get(sid), "super-secret-token")

    def test_create_with_explicit_id(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            sid = store.create("value", secret_id="my-webhook-secret")
            self.assertEqual(sid, "my-webhook-secret")
            self.assertEqual(store.get("my-webhook-secret"), "value")

    def test_create_does_not_overwrite_existing(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            store.create("first", secret_id="dup")
            with self.assertRaises(ss.SecretStoreError):
                store.create("second", secret_id="dup")
            self.assertEqual(store.get("dup"), "first")

    def test_update_replaces_value(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            sid = store.create("old")
            store.update(sid, "new")
            self.assertEqual(store.get(sid), "new")

    def test_update_missing_raises_not_found(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            with self.assertRaises(ss.SecretNotFoundError):
                store.update("nonexistent", "x")

    def test_delete_removes_secret(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            sid = store.create("value")
            store.delete(sid)
            with self.assertRaises(ss.SecretNotFoundError):
                store.get(sid)

    def test_delete_missing_raises_not_found(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            with self.assertRaises(ss.SecretNotFoundError):
                store.delete("nonexistent")

    def test_get_missing_raises_not_found(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            with self.assertRaises(ss.SecretNotFoundError):
                store.get("nonexistent")

    def test_list_ids_returns_ids_only_never_values(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            store.create("v1", secret_id="a")
            store.create("v2", secret_id="b")
            ids = store.list_ids()
            self.assertEqual(ids, ["a", "b"])
            self.assertNotIn("v1", ids)
            self.assertNotIn("v2", ids)


class TestSecretStorePermissions(unittest.TestCase):
    def test_store_directory_is_owner_only(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            mode = os.stat(store.root).st_mode & 0o777
            self.assertEqual(mode, 0o700)

    def test_secret_file_is_owner_only(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            sid = store.create("value")
            path = store.root / sid
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600)


class TestPathTraversalAndSymlinkSafety(unittest.TestCase):
    def test_path_traversal_id_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            with self.assertRaises(ss.InvalidSecretIdError):
                store.create("value", secret_id="../../etc/passwd")

    def test_slash_in_id_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            with self.assertRaises(ss.InvalidSecretIdError):
                store.create("value", secret_id="a/b")

    def test_absolute_path_id_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            with self.assertRaises(ss.InvalidSecretIdError):
                store.get("/etc/passwd")

    def test_get_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td) / "secrets"
            store = ss.SecretStore(secrets_dir)
            outside_secret = Path(td) / "outside.txt"
            outside_secret.write_text("not meant to be readable via the store")
            link_path = secrets_dir / "evil-link"
            link_path.symlink_to(outside_secret)
            with self.assertRaises(ss.SecretSymlinkError):
                store.get("evil-link")

    def test_delete_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            secrets_dir = Path(td) / "secrets"
            store = ss.SecretStore(secrets_dir)
            outside = Path(td) / "outside.txt"
            outside.write_text("do not delete me")
            link_path = secrets_dir / "evil-link"
            link_path.symlink_to(outside)
            with self.assertRaises(ss.SecretSymlinkError):
                store.delete("evil-link")
            self.assertTrue(outside.exists())

    def test_empty_id_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            with self.assertRaises(ss.InvalidSecretIdError):
                store.create("value", secret_id="")

    def test_dot_dot_alone_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            with self.assertRaises(ss.InvalidSecretIdError):
                store.create("value", secret_id="..")


class TestNoPlaintextLeakage(unittest.TestCase):
    def test_metadata_dataclass_never_carries_value(self):
        meta = ss.SecretMetadata(secret_id="abc", created_at="2026-01-01T00:00:00Z")
        field_names = {f.name for f in meta.__dataclass_fields__.values()}
        self.assertEqual(field_names, {"secret_id", "created_at"})
        self.assertFalse(hasattr(meta, "value"))

    def test_new_secret_id_is_filesystem_safe(self):
        sid = ss.new_secret_id()
        self.assertRegex(sid, r"^[A-Za-z0-9_-]+$")


class TestBackupRestoreHooks(unittest.TestCase):
    def test_export_all_returns_everything(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            store.create("v1", secret_id="a")
            store.create("v2", secret_id="b")
            exported = store.export_all()
            self.assertEqual(exported, {"a": "v1", "b": "v2"})

    def test_import_all_restores_into_fresh_store(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            store.import_all({"a": "v1", "b": "v2"})
            self.assertEqual(store.get("a"), "v1")
            self.assertEqual(store.get("b"), "v2")

    def test_import_all_refuses_overwrite_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            store.create("original", secret_id="a")
            with self.assertRaises(ss.SecretStoreError):
                store.import_all({"a": "clobbered"})
            self.assertEqual(store.get("a"), "original")

    def test_import_all_overwrite_true_replaces(self):
        with tempfile.TemporaryDirectory() as td:
            store = ss.SecretStore(Path(td) / "secrets")
            store.create("original", secret_id="a")
            store.import_all({"a": "replaced"}, overwrite=True)
            self.assertEqual(store.get("a"), "replaced")

    def test_export_then_import_roundtrip_into_new_store(self):
        with tempfile.TemporaryDirectory() as td:
            store1 = ss.SecretStore(Path(td) / "secrets1")
            store1.create("hello", secret_id="x")
            exported = store1.export_all()

            store2 = ss.SecretStore(Path(td) / "secrets2")
            store2.import_all(exported)
            self.assertEqual(store2.get("x"), "hello")


if __name__ == "__main__":
    unittest.main()
