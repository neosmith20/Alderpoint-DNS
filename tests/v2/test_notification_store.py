import sqlite3

import pytest

from app.v2 import control_db, notification_store as nstore
from app.v2.secret_store import SecretStore


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    nstore.ensure_schema(path)
    with control_db.connect(path) as c:
        yield c, path


@pytest.fixture()
def secrets(tmp_path):
    return SecretStore(tmp_path / "secrets")


SECRET_VALUE = "sk-super-secret-webhook-token-xyz"


class TestCRUD:
    def test_create_and_get(self, conn, secrets):
        c, _ = conn
        meta = nstore.create_provider(
            c, secrets, "slack-main", "slack", "Main Slack", "https://hooks.example",
            secret_value=SECRET_VALUE,
        )
        assert meta.secret_ref is not None
        loaded = nstore.get_provider(c, "slack-main")
        assert loaded.provider_id == "slack-main"
        assert loaded.secret_ref == meta.secret_ref

    def test_list_providers(self, conn, secrets):
        c, _ = conn
        nstore.create_provider(c, secrets, "a", "webhook", "A", "https://a")
        nstore.create_provider(c, secrets, "b", "webhook", "B", "https://b")
        listed = nstore.list_providers(c)
        assert [p.provider_id for p in listed] == ["a", "b"]

    def test_duplicate_provider_id_rejected(self, conn, secrets):
        c, _ = conn
        nstore.create_provider(c, secrets, "dup", "webhook", "Dup", "https://dup")
        with pytest.raises(nstore.NotificationStoreError):
            nstore.create_provider(c, secrets, "dup", "webhook", "Dup2", "https://dup2")

    def test_invalid_kind_rejected(self, conn, secrets):
        c, _ = conn
        with pytest.raises(nstore.NotificationStoreError):
            nstore.create_provider(c, secrets, "bad", "carrier-pigeon", "Bad", "https://bad")

    def test_provider_without_secret(self, conn, secrets):
        c, _ = conn
        meta = nstore.create_provider(c, secrets, "no-secret", "webhook", "No Secret", "https://x")
        assert meta.secret_ref is None


class TestUpdate:
    def test_update_secret_replaces_and_removes_old(self, conn, secrets):
        c, _ = conn
        meta = nstore.create_provider(
            c, secrets, "p1", "webhook", "P1", "https://p1", secret_value="old-value"
        )
        old_ref = meta.secret_ref
        updated = nstore.update_provider_secret(c, secrets, "p1", "new-value")
        assert updated.secret_ref != old_ref
        assert not secrets.exists(old_ref)
        assert secrets.get(updated.secret_ref) == "new-value"

    def test_update_unknown_provider_rejected(self, conn, secrets):
        c, _ = conn
        with pytest.raises(nstore.NotificationStoreError):
            nstore.update_provider_secret(c, secrets, "ghost", "value")


class TestDelete:
    def test_delete_removes_provider_and_secret(self, conn, secrets):
        c, _ = conn
        meta = nstore.create_provider(
            c, secrets, "gone", "webhook", "Gone", "https://gone", secret_value="v"
        )
        nstore.delete_provider(c, secrets, "gone")
        assert nstore.get_provider(c, "gone") is None
        assert not secrets.exists(meta.secret_ref)

    def test_delete_unknown_provider_rejected(self, conn, secrets):
        c, _ = conn
        with pytest.raises(nstore.NotificationStoreError):
            nstore.delete_provider(c, secrets, "ghost")


class TestMissingSecretHandling:
    def test_resolve_secret_with_no_configured_secret_raises(self, conn, secrets):
        c, _ = conn
        meta = nstore.create_provider(c, secrets, "no-sec", "webhook", "X", "https://x")
        with pytest.raises(nstore.NotificationStoreError):
            nstore.resolve_secret(secrets, meta)

    def test_resolve_secret_with_deleted_backing_secret_raises_explicit_error(self, conn, secrets):
        c, _ = conn
        meta = nstore.create_provider(
            c, secrets, "orphan", "webhook", "X", "https://x", secret_value="v"
        )
        secrets.delete(meta.secret_ref)  # simulate external corruption/manual deletion
        loaded = nstore.get_provider(c, "orphan")
        with pytest.raises(nstore.NotificationStoreError):
            nstore.resolve_secret(secrets, loaded)


class TestNoPlaintextLeakage:
    def test_no_plaintext_secret_in_control_db_raw_bytes(self, conn, secrets, tmp_path):
        c, db_path = conn
        nstore.create_provider(
            c, secrets, "leak-check", "webhook", "X", "https://x", secret_value=SECRET_VALUE
        )
        c.commit() if hasattr(c, "commit") else None
        # Force a WAL checkpoint so the raw main db file actually contains
        # the row, then inspect the file's raw bytes directly -- not via
        # SQL (which could be fooled by an app-level accessor), the actual
        # on-disk bytes.
        c.execute("PRAGMA wal_checkpoint(FULL)")
        raw = db_path.read_bytes()
        assert SECRET_VALUE.encode() not in raw

    def test_secret_absent_from_redacted_dict(self, conn, secrets):
        c, _ = conn
        meta = nstore.create_provider(
            c, secrets, "redact-check", "webhook", "X", "https://x", secret_value=SECRET_VALUE
        )
        redacted = meta.redacted()
        assert SECRET_VALUE not in str(redacted)
        assert redacted["has_secret"] is True

    def test_secret_absent_from_metadata_repr(self, conn, secrets):
        c, _ = conn
        meta = nstore.create_provider(
            c, secrets, "repr-check", "webhook", "X", "https://x", secret_value=SECRET_VALUE
        )
        assert SECRET_VALUE not in repr(meta)

    def test_secret_file_on_disk_separate_from_control_db(self, conn, secrets, tmp_path):
        c, db_path = conn
        meta = nstore.create_provider(
            c, secrets, "sep-check", "webhook", "X", "https://x", secret_value=SECRET_VALUE
        )
        secret_path = secrets.root / meta.secret_ref
        assert secret_path.exists()
        assert secret_path != db_path
        assert SECRET_VALUE.encode() in secret_path.read_bytes()  # value IS there, just not in control.db
