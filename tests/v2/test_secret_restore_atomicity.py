"""Gate #2 HIGH: secret restore must be atomic -- a write failure partway
through a multi-secret restore must leave the store in exactly its
pre-restore state (no partial commit), not just a validation-time
conflict (already covered by test_secret_backup.py).
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from app.v2.secret_store import SecretStore, SecretStoreError


@pytest.fixture()
def store(tmp_path):
    return SecretStore(tmp_path / "secrets")


class TestWriteFailureMidBatchLeavesNoPartialCommit:
    def test_second_secret_write_failure_rolls_back_first(self, store):
        """Reproduces Dex's exact finding: second-secret write failure
        left the first restored secret committed."""
        real_mkstemp = os_mkstemp = __import__("tempfile").mkstemp
        call_count = {"n": 0}

        def _failing_mkstemp(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError(28, "No space left on device")
            return real_mkstemp(*args, **kwargs)

        with mock.patch("tempfile.mkstemp", side_effect=_failing_mkstemp):
            with pytest.raises(OSError):
                store.import_all({"secret-a": "value-a", "secret-b": "value-b"})

        assert store.list_ids() == []  # NEITHER committed, not just "b" missing

    def test_pre_existing_secrets_untouched_on_staging_failure(self, store):
        store.create("orig-a", secret_id="secret-a")
        store.create("orig-b", secret_id="secret-b")

        call_count = {"n": 0}
        real_mkstemp = __import__("tempfile").mkstemp

        def _failing_mkstemp(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError(28, "No space left on device")
            return real_mkstemp(*args, **kwargs)

        with mock.patch("tempfile.mkstemp", side_effect=_failing_mkstemp):
            with pytest.raises(OSError):
                store.import_all(
                    {"secret-a": "new-a", "secret-b": "new-b"}, overwrite=True
                )

        # Both must be EXACTLY as before -- not "a" updated, "b" stale.
        assert store.get("secret-a") == "orig-a"
        assert store.get("secret-b") == "orig-b"

    def test_promotion_phase_failure_rolls_back_via_backup(self, store):
        """Simulates a failure during the rename/promote phase (not the
        write/staging phase) -- proves the backup-and-restore rollback
        path, not just the "nothing written yet" path."""
        store.create("orig-a", secret_id="secret-a")
        store.create("orig-b", secret_id="secret-b")

        real_replace = os.replace
        call_count = {"n": 0}

        def _failing_replace(src, dst, *args, **kwargs):
            call_count["n"] += 1
            # Let backups happen (calls 1-2), let the first promote
            # succeed (call 3), fail on the second promote (call 4).
            if call_count["n"] == 4:
                raise OSError(13, "Permission denied (simulated)")
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch("os.replace", side_effect=_failing_replace):
            with pytest.raises(OSError):
                store.import_all(
                    {"secret-a": "new-a", "secret-b": "new-b"}, overwrite=True
                )

        assert store.get("secret-a") == "orig-a"
        assert store.get("secret-b") == "orig-b"

    def test_no_leftover_staging_or_backup_files_after_failure(self, store, tmp_path):
        store.create("orig-a", secret_id="secret-a")
        real_mkstemp = __import__("tempfile").mkstemp
        call_count = {"n": 0}

        def _failing_mkstemp(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError(28, "No space left on device")
            return real_mkstemp(*args, **kwargs)

        with mock.patch("tempfile.mkstemp", side_effect=_failing_mkstemp):
            with pytest.raises(OSError):
                store.import_all({"secret-a": "new-a", "secret-b": "value-b"}, overwrite=True)

        remaining = list((tmp_path / "secrets").iterdir())
        names = [p.name for p in remaining]
        assert names == ["secret-a"]  # no .restore-stage./.restore-backup. leftovers

    def test_no_leftover_files_after_promotion_phase_failure(self, store, tmp_path):
        store.create("orig-a", secret_id="secret-a")
        store.create("orig-b", secret_id="secret-b")
        real_replace = os.replace
        call_count = {"n": 0}

        def _failing_replace(src, dst, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 4:
                raise OSError(13, "Permission denied (simulated)")
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch("os.replace", side_effect=_failing_replace):
            with pytest.raises(OSError):
                store.import_all(
                    {"secret-a": "new-a", "secret-b": "new-b"}, overwrite=True
                )

        remaining = sorted(p.name for p in (tmp_path / "secrets").iterdir())
        assert remaining == ["secret-a", "secret-b"]


class TestSuccessfulRestoreStillWorksNormally:
    def test_full_batch_commits_when_nothing_fails(self, store):
        store.import_all({"secret-a": "value-a", "secret-b": "value-b"})
        assert store.get("secret-a") == "value-a"
        assert store.get("secret-b") == "value-b"

    def test_no_leftover_staging_files_after_success(self, store, tmp_path):
        store.import_all({"secret-a": "value-a", "secret-b": "value-b"})
        remaining = sorted(p.name for p in (tmp_path / "secrets").iterdir())
        assert remaining == ["secret-a", "secret-b"]

    def test_empty_batch_is_a_noop(self, store):
        store.import_all({})
        assert store.list_ids() == []


class TestEncryptedBackupRestoreFullChainAtomicity:
    """End-to-end through app/v2/secret_backup.py's restore_encrypted_backup,
    proving the atomicity fix applies at the full backup/restore chain
    level too, not just SecretStore.import_all in isolation."""

    def test_partial_failure_during_full_backup_restore_leaves_store_untouched(self, tmp_path):
        from cryptography.fernet import Fernet

        from app.v2.secret_backup import create_encrypted_backup, restore_encrypted_backup

        source = SecretStore(tmp_path / "source")
        source.create("value-a", secret_id="secret-a")
        source.create("value-b", secret_id="secret-b")

        key = Fernet.generate_key()
        backup_path = tmp_path / "backup.enc"
        create_encrypted_backup(source, backup_path, key)

        target = SecretStore(tmp_path / "target")
        target.create("pre-existing", secret_id="pre-existing-secret")

        real_mkstemp = __import__("tempfile").mkstemp
        call_count = {"n": 0}

        def _failing_mkstemp(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError(28, "No space left on device")
            return real_mkstemp(*args, **kwargs)

        with mock.patch("tempfile.mkstemp", side_effect=_failing_mkstemp):
            with pytest.raises(Exception):
                restore_encrypted_backup(backup_path, key, target)

        # Only the pre-existing secret must remain -- nothing from the
        # backup partially landed.
        assert target.list_ids() == ["pre-existing-secret"]
        assert target.get("pre-existing-secret") == "pre-existing"
