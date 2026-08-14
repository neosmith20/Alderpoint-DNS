#!/usr/bin/env python3
"""Tests for durable migration state (Workstream 2, §12-13, §33 MIGRATION).

Covers what tests/v2/test_migration_scaffold.py's in-memory-resume tests
don't: persistence across a simulated process crash (no in-memory state
survives), idempotent restart from the durable record alone, per-stage
crash injection, and that the source stays untouched throughout.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import migration as mig  # noqa: E402
from app.v2 import migration_state as mstate  # noqa: E402


def _make_fake_source(td: Path) -> Path:
    source = td / "fake-v1-install"
    source.mkdir()
    (source / "alderpointdns.db").write_text("pretend this is a sqlite file")
    return source


class TestMigrationRecordBasics(unittest.TestCase):
    def test_new_record_has_unique_id(self):
        r1 = mstate.MigrationRecord.new(
            source_version="1.1.1", target_version="2.0.0",
            staging_dir="/tmp/a", source_path="/tmp/b",
        )
        r2 = mstate.MigrationRecord.new(
            source_version="1.1.1", target_version="2.0.0",
            staging_dir="/tmp/a", source_path="/tmp/b",
        )
        self.assertNotEqual(r1.migration_id, r2.migration_id)

    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.json"
            record = mstate.MigrationRecord.new(
                source_version="1.1.1", target_version="2.0.0",
                staging_dir=str(td), source_path=str(td),
            )
            mstate.save(path, record)
            loaded = mstate.load(path)
            self.assertEqual(loaded.migration_id, record.migration_id)
            self.assertEqual(loaded.source_version, "1.1.1")

    def test_load_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(mstate.load(Path(td) / "nope.json"))

    def test_load_corrupt_raises_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.json"
            path.write_text("{not valid json")
            with self.assertRaises(json.JSONDecodeError):
                mstate.load(path)

    def test_save_is_atomic_leaves_no_tmp_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.json"
            record = mstate.MigrationRecord.new(
                source_version="1.1.1", target_version="2.0.0",
                staging_dir=str(td), source_path=str(td),
            )
            mstate.save(path, record)
            leftovers = [p for p in Path(td).iterdir() if p.name != "state.json"]
            self.assertEqual(leftovers, [])


class TestDurableStateDuringRun(unittest.TestCase):
    def test_state_persisted_after_each_completed_stage(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            state_path = td / "migration_state.json"
            record = mstate.MigrationRecord.new(
                source_version="1.1.1", target_version="2.0.0",
                staging_dir=str(td / "staging"), source_path=str(source),
            )
            mig.run_migration(
                source, td / "staging", stop_before="migrate_clients",
                durable_record=record, state_path=state_path,
            )
            reloaded = mstate.load(state_path)
            self.assertEqual(
                reloaded.completed_stages,
                ["detect", "backup", "preview", "migrate_config", "migrate_control"],
            )
            self.assertEqual(reloaded.status, "running")
            self.assertFalse(reloaded.commit_point_reached)

    def test_state_marks_completed_after_commit(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            state_path = td / "migration_state.json"
            record = mstate.MigrationRecord.new(
                source_version="1.1.1", target_version="2.0.0",
                staging_dir=str(td / "staging"), source_path=str(source),
            )
            mig.run_migration(source, td / "staging", durable_record=record, state_path=state_path)
            reloaded = mstate.load(state_path)
            self.assertEqual(reloaded.status, "completed")
            self.assertTrue(reloaded.commit_point_reached)
            self.assertIsNotNone(reloaded.completed_at)

    def test_failure_persists_diagnostics_and_failed_stage(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            state_path = td / "migration_state.json"
            record = mstate.MigrationRecord.new(
                source_version="1.1.1", target_version="2.0.0",
                staging_dir=str(td / "staging"), source_path=str(source),
            )
            with mock.patch.dict(
                mig._STAGE_FUNCS,
                {"migrate_secrets": mock.Mock(side_effect=RuntimeError("secret store unreachable"))},
            ):
                with self.assertRaises(mig.MigrationError):
                    mig.run_migration(
                        source, td / "staging", durable_record=record, state_path=state_path,
                    )
            reloaded = mstate.load(state_path)
            self.assertEqual(reloaded.status, "failed")
            self.assertEqual(reloaded.failed_stage, "migrate_secrets")
            self.assertIn("secret store unreachable", reloaded.failure_diagnostics)


class TestCrashRestartAtEachStage(unittest.TestCase):
    """Injects a "crash" (stop_before) at every meaningful stage boundary,
    verifies the durable record on disk alone (no in-memory state) is
    enough to resume correctly and eventually reach commit, and that the
    source is never mutated at any point."""

    def test_crash_restart_at_every_stage_boundary(self):
        for boundary_stage in mig.STAGES:
            with self.subTest(boundary=boundary_stage):
                with tempfile.TemporaryDirectory() as td:
                    td = Path(td)
                    source = _make_fake_source(td)
                    before = (source / "alderpointdns.db").read_text()
                    state_path = td / "migration_state.json"
                    record = mstate.MigrationRecord.new(
                        source_version="1.1.1", target_version="2.0.0",
                        staging_dir=str(td / "staging"), source_path=str(source),
                    )

                    # "Crash" right before boundary_stage.
                    mig.run_migration(
                        source, td / "staging", stop_before=boundary_stage,
                        durable_record=record, state_path=state_path,
                    )

                    # Simulate a fresh process: only the durable record on
                    # disk is trusted, no in-memory state carried over.
                    reloaded = mstate.load(state_path)
                    self.assertIsNotNone(reloaded)
                    resumed_in_memory_state = mig.resume_state_from_durable_record(reloaded)

                    final_state = mig.run_migration(
                        source, td / "staging", resume_state=resumed_in_memory_state,
                        durable_record=reloaded, state_path=state_path,
                    )
                    self.assertTrue(final_state.committed)
                    self.assertEqual(final_state.completed_stages, list(mig.STAGES))

                    after = (source / "alderpointdns.db").read_text()
                    self.assertEqual(before, after, f"source mutated when restarting at {boundary_stage}")

                    final_record = mstate.load(state_path)
                    self.assertEqual(final_record.status, "completed")

    def test_duplicate_resume_after_already_completed_does_not_corrupt(self):
        """Idempotency: resuming an already-fully-completed migration must
        not re-run stages or change the outcome."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            state_path = td / "migration_state.json"
            record = mstate.MigrationRecord.new(
                source_version="1.1.1", target_version="2.0.0",
                staging_dir=str(td / "staging"), source_path=str(source),
            )
            mig.run_migration(source, td / "staging", durable_record=record, state_path=state_path)

            reloaded = mstate.load(state_path)
            resumed_state = mig.resume_state_from_durable_record(reloaded)
            call_log = []
            original = dict(mig._STAGE_FUNCS)

            def _tracking(name):
                def _fn(s):
                    call_log.append(name)
                    return original[name](s)
                return _fn

            with mock.patch.dict(mig._STAGE_FUNCS, {n: _tracking(n) for n in mig.STAGES}):
                final = mig.run_migration(
                    source, td / "staging", resume_state=resumed_state,
                    durable_record=reloaded, state_path=state_path,
                )
            self.assertEqual(call_log, [])  # nothing re-executed
            self.assertTrue(final.committed)

    def test_failed_pre_commit_migration_can_be_treated_as_rolled_back(self):
        """A failure before the commit stage: durable record shows
        commit_point_reached=False, so a caller knows it's safe to discard
        staging and retry from scratch (rollback), not attempt to "resume
        into" a partially-committed state."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            state_path = td / "migration_state.json"
            record = mstate.MigrationRecord.new(
                source_version="1.1.1", target_version="2.0.0",
                staging_dir=str(td / "staging"), source_path=str(source),
            )
            with mock.patch.dict(
                mig._STAGE_FUNCS,
                {"validate": mock.Mock(side_effect=RuntimeError("generated config invalid"))},
            ):
                with self.assertRaises(mig.MigrationError):
                    mig.run_migration(
                        source, td / "staging", durable_record=record, state_path=state_path,
                    )
            reloaded = mstate.load(state_path)
            self.assertFalse(reloaded.commit_point_reached)
            mstate.mark_rolled_back(reloaded)
            mstate.save(state_path, reloaded)
            self.assertEqual(mstate.load(state_path).status, "rolled_back")


if __name__ == "__main__":
    unittest.main()
