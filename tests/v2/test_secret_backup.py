import pytest
from cryptography.fernet import Fernet

from app.v2.secret_backup import (
    SecretBackupError,
    SecretBackupKeyError,
    create_encrypted_backup,
    restore_encrypted_backup,
)
from app.v2.secret_store import SecretStore, SecretStoreError


@pytest.fixture()
def key():
    return Fernet.generate_key()


@pytest.fixture()
def populated_store(tmp_path):
    store = SecretStore(tmp_path / "secrets")
    store.create("value-a", secret_id="secret-a")
    store.create("value-b", secret_id="secret-b")
    return store


class TestBackupCreation:
    def test_backup_is_encrypted_not_plaintext(self, populated_store, tmp_path, key):
        backup_path = tmp_path / "backup.enc"
        result = create_encrypted_backup(populated_store, backup_path, key)
        assert result.secret_count == 2
        raw = backup_path.read_bytes()
        assert b"value-a" not in raw
        assert b"value-b" not in raw

    def test_backup_is_atomic_write(self, populated_store, tmp_path, key):
        backup_path = tmp_path / "backup.enc"
        create_encrypted_backup(populated_store, backup_path, key)
        assert backup_path.exists()
        assert not (backup_path.parent / f".{backup_path.name}.tmp").exists()


class TestRestoreToSeparateInstance:
    def test_restore_to_completely_different_store(self, populated_store, tmp_path, key):
        backup_path = tmp_path / "backup.enc"
        create_encrypted_backup(populated_store, backup_path, key)

        fresh_store = SecretStore(tmp_path / "another-instance-secrets")
        count = restore_encrypted_backup(backup_path, key, fresh_store)
        assert count == 2
        assert fresh_store.get("secret-a") == "value-a"
        assert fresh_store.get("secret-b") == "value-b"

    def test_restore_preserves_references(self, populated_store, tmp_path, key):
        backup_path = tmp_path / "backup.enc"
        create_encrypted_backup(populated_store, backup_path, key)
        fresh_store = SecretStore(tmp_path / "restored")
        restore_encrypted_backup(backup_path, key, fresh_store)
        assert set(fresh_store.list_ids()) == {"secret-a", "secret-b"}


class TestWrongKeyRejected:
    def test_wrong_key_raises_key_error(self, populated_store, tmp_path, key):
        backup_path = tmp_path / "backup.enc"
        create_encrypted_backup(populated_store, backup_path, key)
        wrong_key = Fernet.generate_key()
        fresh_store = SecretStore(tmp_path / "restored")
        with pytest.raises(SecretBackupKeyError):
            restore_encrypted_backup(backup_path, wrong_key, fresh_store)
        assert fresh_store.list_ids() == []  # nothing partially restored


class TestCorruptedBackupRejected:
    def test_tampered_ciphertext_raises_key_error(self, populated_store, tmp_path, key):
        backup_path = tmp_path / "backup.enc"
        create_encrypted_backup(populated_store, backup_path, key)
        data = bytearray(backup_path.read_bytes())
        data[10:20] = b"TAMPERED!!"
        backup_path.write_bytes(bytes(data))

        fresh_store = SecretStore(tmp_path / "restored")
        with pytest.raises(SecretBackupKeyError):
            restore_encrypted_backup(backup_path, key, fresh_store)

    def test_missing_backup_file_raises(self, tmp_path, key):
        fresh_store = SecretStore(tmp_path / "restored")
        with pytest.raises(SecretBackupError):
            restore_encrypted_backup(tmp_path / "no-such-file.enc", key, fresh_store)

    def test_unsupported_format_version_rejected(self, populated_store, tmp_path, key):
        import json

        from cryptography.fernet import Fernet as _Fernet

        backup_path = tmp_path / "backup.enc"
        f = _Fernet(key)
        bad_payload = json.dumps({"format_version": 999, "secrets": {}}).encode()
        backup_path.write_bytes(f.encrypt(bad_payload))
        fresh_store = SecretStore(tmp_path / "restored")
        with pytest.raises(SecretBackupError):
            restore_encrypted_backup(backup_path, key, fresh_store)


class TestPartialFailureRollback:
    def test_no_plaintext_leak_via_export_all_ordinary_json_dump_comparison(self, populated_store, tmp_path, key):
        # Sanity: the encrypted backup and an ordinary plaintext export
        # must differ -- proves encryption actually happened, not a no-op.
        import json

        backup_path = tmp_path / "backup.enc"
        create_encrypted_backup(populated_store, backup_path, key)
        plain_export = json.dumps(populated_store.export_all()).encode()
        assert backup_path.read_bytes() != plain_export

    def test_restore_conflict_without_overwrite_rejected_atomically(self, populated_store, tmp_path, key):
        backup_path = tmp_path / "backup.enc"
        create_encrypted_backup(populated_store, backup_path, key)

        target = SecretStore(tmp_path / "target")
        target.create("pre-existing", secret_id="secret-a")  # conflicts with backup

        with pytest.raises(SecretBackupError):
            restore_encrypted_backup(backup_path, key, target, overwrite=False)
        # secret-a must be untouched (still the pre-existing value) and
        # secret-b must NOT have been written either -- the whole restore
        # is atomic, not partially applied.
        assert target.get("secret-a") == "pre-existing"
        assert not target.exists("secret-b")

    def test_restore_with_overwrite_replaces_cleanly(self, populated_store, tmp_path, key):
        backup_path = tmp_path / "backup.enc"
        create_encrypted_backup(populated_store, backup_path, key)
        target = SecretStore(tmp_path / "target")
        target.create("stale", secret_id="secret-a")
        restore_encrypted_backup(backup_path, key, target, overwrite=True)
        assert target.get("secret-a") == "value-a"
        assert target.get("secret-b") == "value-b"


class TestSecretStoreImportAllAtomicity:
    """Regression test for the real bug fixed in secret_store.py's
    import_all -- previously wrote entries one at a time, so an invalid
    id partway through a batch left earlier entries already committed."""

    def test_invalid_id_in_batch_leaves_no_partial_write(self, tmp_path):
        store = SecretStore(tmp_path / "store")
        batch = {"good-one": "value1", "bad id with spaces": "value2", "good-two": "value3"}
        with pytest.raises(SecretStoreError):
            store.import_all(batch)
        assert store.list_ids() == []

    def test_conflict_in_batch_leaves_no_partial_write(self, tmp_path):
        store = SecretStore(tmp_path / "store")
        store.create("existing", secret_id="dup")
        batch = {"fresh-one": "value1", "dup": "value2"}
        with pytest.raises(SecretStoreError):
            store.import_all(batch)
        assert store.list_ids() == ["dup"]  # only the pre-existing one
