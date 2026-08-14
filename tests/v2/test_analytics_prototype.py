#!/usr/bin/env python3
"""Tests for app.v2.analytics_ingest — bounded queue, segment rotation,
atomic promotion, retention, and writer failure isolation.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import analytics_ingest as ing  # noqa: E402


class TestBoundedQueue(unittest.TestCase):
    def test_push_within_capacity(self):
        q = ing.BoundedQueue(capacity=3)
        q.push({"n": 1})
        q.push({"n": 2})
        self.assertEqual(len(q), 2)
        self.assertEqual(q.dropped_count, 0)

    def test_overflow_drops_oldest_not_newest(self):
        q = ing.BoundedQueue(capacity=2)
        q.push({"n": 1})
        q.push({"n": 2})
        q.push({"n": 3})  # should drop {"n": 1}
        self.assertEqual(len(q), 2)
        self.assertEqual(q.dropped_count, 1)
        drained = q.drain()
        self.assertEqual([r["n"] for r in drained], [2, 3])

    def test_bounded_growth_under_sustained_overflow(self):
        q = ing.BoundedQueue(capacity=10)
        for i in range(10_000):
            q.push({"n": i})
        self.assertEqual(len(q), 10)  # never exceeds capacity
        self.assertEqual(q.dropped_count, 10_000 - 10)

    def test_zero_or_negative_capacity_rejected(self):
        with self.assertRaises(ValueError):
            ing.BoundedQueue(capacity=0)


class TestSegmentRotation(unittest.TestCase):
    def test_flush_batch_promotes_atomically(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            ok = writer.flush_batch([{"domain": "a.example"}, {"domain": "b.example"}])
            self.assertTrue(ok)
            finals = list(Path(td).glob("segment-*.jsonl.gz"))
            tmps = list(Path(td).glob("*.tmp"))
            self.assertEqual(len(finals), 1)
            self.assertEqual(tmps, [])

    def test_multiple_batches_rotate_into_separate_segments(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            writer.flush_batch([{"n": 1}])
            writer.flush_batch([{"n": 2}])
            writer.flush_batch([{"n": 3}])
            finals = sorted(Path(td).glob("segment-*.jsonl.gz"))
            self.assertEqual(len(finals), 3)

    def test_empty_batch_is_a_noop(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            ok = writer.flush_batch([])
            self.assertTrue(ok)
            self.assertEqual(list(Path(td).glob("segment-*.jsonl.gz")), [])


class TestInterruptedSegmentHandling(unittest.TestCase):
    def test_reader_ignores_incomplete_tmp_file(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            writer.flush_batch([{"domain": "good.example"}])
            writer.simulate_crash_mid_write([{"domain": "should-not-appear.example"}])

            records = ing.read_complete_segments(Path(td))
            domains = [r["domain"] for r in records]
            self.assertEqual(domains, ["good.example"])
            self.assertNotIn("should-not-appear.example", domains)

    def test_tmp_file_actually_exists_on_disk_after_simulated_crash(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            writer.simulate_crash_mid_write([{"domain": "x.example"}])
            tmp_files = list(Path(td).glob("*.tmp"))
            self.assertEqual(len(tmp_files), 1)


class TestWriterFailureIsolation(unittest.TestCase):
    def test_flush_failure_does_not_raise(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            with mock.patch("gzip.open", side_effect=OSError("disk full")):
                ok = writer.flush_batch([{"domain": "x.example"}])
            self.assertFalse(ok)  # reported as failure...
            self.assertEqual(writer.stats.flush_failures, 1)
            self.assertIn("disk full", writer.stats.last_error)

    def test_failure_does_not_leave_a_tmp_file_behind(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            real_open = __import__("builtins").open

            def _boom(*args, **kwargs):
                raise OSError("simulated write failure")

            with mock.patch("gzip.open", side_effect=_boom):
                writer.flush_batch([{"domain": "x.example"}])
            self.assertEqual(list(Path(td).glob("*.tmp")), [])

    def test_writer_continues_after_a_failed_flush(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            with mock.patch("gzip.open", side_effect=OSError("transient")):
                writer.flush_batch([{"domain": "lost.example"}])
            # A subsequent flush on the same writer must still succeed —
            # one bad batch must not wedge the writer permanently.
            ok = writer.flush_batch([{"domain": "recovered.example"}])
            self.assertTrue(ok)
            records = ing.read_complete_segments(Path(td))
            self.assertEqual([r["domain"] for r in records], ["recovered.example"])


class TestRetention(unittest.TestCase):
    def test_deletes_oldest_first_keeps_newest(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            for i in range(5):
                writer.flush_batch([{"n": i}])
            deleted = ing.delete_oldest_closed_segments(Path(td), keep_newest=2)
            self.assertEqual(len(deleted), 3)
            remaining = sorted(Path(td).glob("segment-*.jsonl.gz"))
            self.assertEqual(len(remaining), 2)
            # the two newest (segment-000003, segment-000004) must remain
            names = {p.name for p in remaining}
            self.assertIn("segment-000003.jsonl.gz", names)
            self.assertIn("segment-000004.jsonl.gz", names)

    def test_never_deletes_open_tmp_segment(self):
        with tempfile.TemporaryDirectory() as td:
            writer = ing.SegmentWriter(Path(td))
            writer.flush_batch([{"n": 1}])
            writer.simulate_crash_mid_write([{"n": 2}])  # leaves a .tmp behind
            ing.delete_oldest_closed_segments(Path(td), keep_newest=0)
            # retention only globs finalized segments; the .tmp file is untouched
            self.assertEqual(len(list(Path(td).glob("*.tmp"))), 1)


if __name__ == "__main__":
    unittest.main()
