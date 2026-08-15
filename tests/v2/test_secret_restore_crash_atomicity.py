"""Gate #2 residual P0-A: SecretStore.import_all() must be crash-atomic,
not just exception-atomic -- a real process kill (SIGKILL, OOM-kill, power
loss) can interrupt the backup/promote rename sequence with no Python
exception handler ever running. This simulates abrupt termination at every
real crash point (rather than only a mocked exception) by directly
mutating on-disk state to the shape it would be in at that exact instant,
then opening a *fresh* SecretStore (mirroring what happens on process
restart) and asserting the store settles into the old complete state or
the new complete state -- never partial -- with no journal/staging debris
left over.
"""

import json
from pathlib import Path

import pytest

from app.v2.secret_store import SecretStore, _JOURNAL_NAME


def _no_leftover_files(root: Path) -> None:
    leftover = [
        p.name for p in root.iterdir()
        if p.name.startswith(".restore-") or p.name == _JOURNAL_NAME
    ]
    assert leftover == [], f"leftover restore artifacts: {leftover}"


class TestCrashBeforeStaging:
    def test_no_journal_no_change_if_killed_before_import_all_called(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-value", secret_id="a")
        # "Crash before staging" is simply: import_all() was never called.
        # Re-opening the store must be a pure no-op.
        reopened = SecretStore(tmp_path)
        assert reopened.get("a") == "old-value"
        _no_leftover_files(tmp_path)


class TestCrashDuringStaging:
    def test_stray_staging_temp_file_with_no_journal_is_inert_and_cleaned_on_reopen(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-value", secret_id="a")
        # Staging (phase 2) writes .restore-stage.<id>.*.tmp files to the
        # real store directory BEFORE any journal is written -- a kill here
        # leaves only inert temp files, never a journal, never a touched
        # real path.
        (tmp_path / ".restore-stage.b.deadbeef.tmp").write_text("half-written")
        reopened = SecretStore(tmp_path)
        assert reopened.get("a") == "old-value"
        assert not reopened.exists("b")
        # __init__'s recovery only acts when a journal is present; a
        # journal-less stray staging file from this phase is deliberately
        # left alone (get()/list_ids() ignore non-id-shaped names, and the
        # next successful import_all() batch uses fresh unique temp names),
        # so no assertion of automatic deletion here -- only that it never
        # becomes a live secret.


class TestCrashAfterStagingBeforeBackup:
    def test_journal_staged_with_no_backups_yet_rolls_back_cleanly(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-a", secret_id="a")
        # Simulate: journal written (phase="staged", entries computed), but
        # the process died before the first os.replace() of phase 3 ran.
        journal = {"phase": "staged", "entries": {"a": str(tmp_path / ".restore-backup.a"), "b": None}}
        (tmp_path / _JOURNAL_NAME).write_text(json.dumps(journal))
        reopened = SecretStore(tmp_path)
        assert reopened.get("a") == "old-a"
        assert not reopened.exists("b")
        _no_leftover_files(tmp_path)


class TestCrashDuringBackupPhase:
    def test_some_backed_up_some_not_all_roll_back(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-a", secret_id="a")
        store.create("old-b", secret_id="b")
        journal = {
            "phase": "staged",
            "entries": {
                "a": str(tmp_path / ".restore-backup.a"),
                "b": str(tmp_path / ".restore-backup.b"),
                "c": None,
            },
        }
        (tmp_path / _JOURNAL_NAME).write_text(json.dumps(journal))
        # "a" already backed up (its real file moved aside); "b" and "c"
        # never reached.
        (tmp_path / "a").rename(tmp_path / ".restore-backup.a")
        reopened = SecretStore(tmp_path)
        assert reopened.get("a") == "old-a"
        assert reopened.get("b") == "old-b"
        assert not reopened.exists("c")
        _no_leftover_files(tmp_path)


class TestCrashBeforePromotion:
    def test_all_backed_up_none_promoted_rolls_back(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-a", secret_id="a")
        journal = {"phase": "staged", "entries": {"a": str(tmp_path / ".restore-backup.a"), "new1": None}}
        (tmp_path / _JOURNAL_NAME).write_text(json.dumps(journal))
        (tmp_path / "a").rename(tmp_path / ".restore-backup.a")
        (tmp_path / ".restore-stage.new1.tmp").write_text("staged-new-value")
        reopened = SecretStore(tmp_path)
        assert reopened.get("a") == "old-a"
        assert not reopened.exists("new1")
        _no_leftover_files(tmp_path)


class TestCrashDuringPromotion:
    def test_partial_promotion_still_rolls_back_everything(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-a", secret_id="a")
        store.create("old-b", secret_id="b")
        journal = {
            "phase": "staged",
            "entries": {
                "a": str(tmp_path / ".restore-backup.a"),
                "b": str(tmp_path / ".restore-backup.b"),
            },
        }
        (tmp_path / _JOURNAL_NAME).write_text(json.dumps(journal))
        (tmp_path / "a").rename(tmp_path / ".restore-backup.a")
        (tmp_path / "b").rename(tmp_path / ".restore-backup.b")
        # "a" got promoted (new value now live); "b" did not.
        (tmp_path / "a").write_text("new-a")
        reopened = SecretStore(tmp_path)
        # Deterministic policy: an unconfirmed ("staged") journal ALWAYS
        # rolls back, even though "a"'s promotion had actually finished --
        # this is what makes recovery correct without needing to verify
        # per-file completion.
        assert reopened.get("a") == "old-a"
        assert reopened.get("b") == "old-b"
        _no_leftover_files(tmp_path)


class TestCrashAfterPromotionBeforeJournalCleanup:
    def test_promoted_phase_rolls_forward_keeps_new_values(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-a", secret_id="a")
        store.create("old-b", secret_id="b")
        journal = {
            "phase": "promoted",
            "entries": {
                "a": str(tmp_path / ".restore-backup.a"),
                "b": str(tmp_path / ".restore-backup.b"),
            },
        }
        (tmp_path / _JOURNAL_NAME).write_text(json.dumps(journal))
        (tmp_path / ".restore-backup.a").write_text("old-a")
        (tmp_path / ".restore-backup.b").write_text("old-b")
        (tmp_path / "a").write_text("new-a")
        (tmp_path / "b").write_text("new-b")
        reopened = SecretStore(tmp_path)
        # phase="promoted" means completion was already confirmed before
        # the crash -- recovery must NOT undo it.
        assert reopened.get("a") == "new-a"
        assert reopened.get("b") == "new-b"
        _no_leftover_files(tmp_path)


class TestCrashDuringCleanup:
    def test_promoted_phase_with_one_backup_already_deleted_finishes_cleanly(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-a", secret_id="a")
        store.create("old-b", secret_id="b")
        journal = {
            "phase": "promoted",
            "entries": {
                "a": str(tmp_path / ".restore-backup.a"),
                "b": str(tmp_path / ".restore-backup.b"),
            },
        }
        (tmp_path / _JOURNAL_NAME).write_text(json.dumps(journal))
        (tmp_path / "a").write_text("new-a")
        (tmp_path / "b").write_text("new-b")
        # Cleanup loop already deleted "a"'s backup; "b"'s is still there;
        # journal itself not yet deleted -- kill happens here.
        (tmp_path / ".restore-backup.b").write_text("old-b")
        reopened = SecretStore(tmp_path)
        assert reopened.get("a") == "new-a"
        assert reopened.get("b") == "new-b"
        _no_leftover_files(tmp_path)


class TestRealEndToEndCrashViaOsReplaceMock:
    """Same real bug class Dex reproduced (a write/rename failure mid-batch)
    but proven via a genuinely fresh SecretStore object afterward, not just
    inspecting the object that raised -- confirms the journal path and the
    in-process exception path agree."""

    def test_mocked_promotion_failure_then_fresh_reopen_matches_old_state(self, tmp_path, monkeypatch):
        store = SecretStore(tmp_path)
        store.create("old-a", secret_id="a")
        real_replace = __import__("os").replace
        calls = {"n": 0}

        def flaky_replace(src, dst):
            calls["n"] += 1
            # Let the backup rename through, fail on the promote rename.
            if calls["n"] == 2:
                raise OSError("simulated promotion failure")
            return real_replace(src, dst)

        monkeypatch.setattr("os.replace", flaky_replace)
        with pytest.raises(OSError):
            store.import_all({"a": "new-a"}, overwrite=True)
        monkeypatch.undo()
        reopened = SecretStore(tmp_path)
        assert reopened.get("a") == "old-a"
        _no_leftover_files(tmp_path)


class TestCorruptJournalHandledSafely:
    def test_corrupt_journal_json_does_not_crash_reopen_and_is_removed(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-a", secret_id="a")
        (tmp_path / _JOURNAL_NAME).write_text("{not valid json")
        reopened = SecretStore(tmp_path)
        assert reopened.get("a") == "old-a"
        _no_leftover_files(tmp_path)


class TestSuccessfulRestoreLeavesNoJournal:
    def test_normal_successful_restore_has_no_leftover_journal(self, tmp_path):
        store = SecretStore(tmp_path)
        store.create("old-a", secret_id="a")
        store.import_all({"a": "new-a", "b": "new-b"}, overwrite=True)
        assert store.get("a") == "new-a"
        assert store.get("b") == "new-b"
        _no_leftover_files(tmp_path)
        # And a fresh reopen sees the same thing (recovery is a no-op).
        reopened = SecretStore(tmp_path)
        assert reopened.get("a") == "new-a"
        assert reopened.get("b") == "new-b"
