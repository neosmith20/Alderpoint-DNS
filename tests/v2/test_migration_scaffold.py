#!/usr/bin/env python3
"""Tests for app.v2.migration — pipeline scaffold, restart/idempotency,
rollback-before-commit, and that the source path is never mutated.

Every test operates on tempdir fixtures. None of these tests open
/var/lib/alderpointdns/alderpointdns.db, live or otherwise — "source" here
is always a disposable copy created by the test itself.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import migration as mig  # noqa: E402


def _make_fake_source(td: Path) -> Path:
    source = td / "fake-v1-install"
    source.mkdir()
    (source / "alderpointdns.db").write_text("pretend this is a sqlite file")
    return source


class TestPreviewDoesNotMutateSource(unittest.TestCase):
    def test_preview_stage_leaves_source_byte_identical(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            before = (source / "alderpointdns.db").read_text()

            state = mig.run_migration(source, td / "staging", stop_before="migrate_config")

            after = (source / "alderpointdns.db").read_text()
            self.assertEqual(before, after)
            self.assertIn("preview", state.completed_stages)


class TestHappyPath(unittest.TestCase):
    def test_full_pipeline_reaches_commit(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            state = mig.run_migration(source, td / "staging")
            self.assertTrue(state.committed)
            self.assertEqual(state.completed_stages, list(mig.STAGES))
            self.assertIsNone(state.failed_stage)

    def test_backup_stage_copies_into_staging_dir(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            mig.run_migration(source, td / "staging")
            backup_copy = td / "staging" / "pre-migration-backup" / "alderpointdns.db"
            self.assertTrue(backup_copy.exists())


class TestFailureRollback(unittest.TestCase):
    def test_failed_migration_before_commit_does_not_set_committed(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)

            with mock.patch.dict(
                mig._STAGE_FUNCS,
                {"migrate_policies": mock.Mock(side_effect=RuntimeError("boom"))},
            ):
                with self.assertRaises(mig.MigrationError) as ctx:
                    mig.run_migration(source, td / "staging")
            self.assertEqual(ctx.exception.stage, "migrate_policies")

    def test_failure_before_commit_leaves_source_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            before = (source / "alderpointdns.db").read_text()

            with mock.patch.dict(
                mig._STAGE_FUNCS,
                {"validate": mock.Mock(side_effect=RuntimeError("validation failed"))},
            ):
                with self.assertRaises(mig.MigrationError):
                    mig.run_migration(source, td / "staging")

            after = (source / "alderpointdns.db").read_text()
            self.assertEqual(before, after)

    def test_detect_stage_failure_on_missing_source(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            missing = td / "does-not-exist"
            with self.assertRaises(mig.MigrationError) as ctx:
                mig.run_migration(missing, td / "staging")
            self.assertEqual(ctx.exception.stage, "detect")


class TestRestartIdempotency(unittest.TestCase):
    def test_resuming_skips_already_completed_stages(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)

            state = mig.run_migration(source, td / "staging", stop_before="migrate_clients")
            self.assertEqual(
                state.completed_stages,
                ["detect", "backup", "preview", "migrate_config", "migrate_control"],
            )

            call_log: list[str] = []
            original = dict(mig._STAGE_FUNCS)

            def _tracking(name):
                def _fn(s):
                    call_log.append(name)
                    return original[name](s)

                return _fn

            with mock.patch.dict(
                mig._STAGE_FUNCS, {name: _tracking(name) for name in mig.STAGES}
            ):
                resumed = mig.run_migration(source, td / "staging", resume_state=state)

            self.assertTrue(resumed.committed)
            # Only the stages that were NOT already completed should have run.
            self.assertNotIn("detect", call_log)
            self.assertNotIn("backup", call_log)
            self.assertIn("migrate_clients", call_log)
            self.assertIn("commit", call_log)


class TestPointOfNoReturn(unittest.TestCase):
    def test_point_of_no_return_is_the_last_stage(self):
        self.assertEqual(mig.STAGES[-1], mig.POINT_OF_NO_RETURN_STAGE)

    def test_is_past_point_of_no_return_false_before_commit(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            state = mig.run_migration(source, td / "staging", stop_before="commit")
            self.assertFalse(state.is_past_point_of_no_return())

    def test_is_past_point_of_no_return_true_after_commit(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            source = _make_fake_source(td)
            state = mig.run_migration(source, td / "staging")
            self.assertTrue(state.is_past_point_of_no_return())


if __name__ == "__main__":
    unittest.main()
