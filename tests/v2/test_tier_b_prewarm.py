#!/usr/bin/env python3
"""Tests for app/v2/tier_b_prewarm.py (Workstream 2, §24-25, §28-29, §33 TIER B)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import tier_b_prewarm as tb  # noqa: E402


class TestWorkingSetIndexBasics(unittest.TestCase):
    def test_record_query_creates_entry(self):
        idx = tb.WorkingSetIndex()
        idx.record_query("example.com", "A", "profile1", ts=1000.0)
        self.assertEqual(len(idx), 1)

    def test_repeated_query_increments_hit_count_not_duplicate_entry(self):
        idx = tb.WorkingSetIndex()
        for _ in range(5):
            idx.record_query("example.com", "A", "profile1", ts=1000.0)
        self.assertEqual(len(idx), 1)
        top = idx.top(1)
        self.assertEqual(top[0].hit_count, 5)

    def test_different_qtype_is_a_different_entry(self):
        idx = tb.WorkingSetIndex()
        idx.record_query("example.com", "A", "profile1", ts=1000.0)
        idx.record_query("example.com", "AAAA", "profile1", ts=1000.0)
        self.assertEqual(len(idx), 2)

    def test_different_cache_profile_is_a_different_entry(self):
        """The same qname under two different effective cache profiles must
        be tracked separately — a hot name under one policy doesn't imply
        it's safe to prewarm under a different, incompatible policy."""
        idx = tb.WorkingSetIndex()
        idx.record_query("example.com", "A", "profile1", ts=1000.0)
        idx.record_query("example.com", "A", "profile2", ts=1000.0)
        self.assertEqual(len(idx), 2)

    def test_bounded_eviction_never_exceeds_max_entries(self):
        idx = tb.WorkingSetIndex(max_entries=10)
        for i in range(100):
            idx.record_query(f"name{i}.example.com", "A", "p1", ts=float(i))
        self.assertLessEqual(len(idx), 10)

    def test_eviction_prefers_removing_coldest(self):
        idx = tb.WorkingSetIndex(max_entries=3)
        idx.record_query("hot.example.com", "A", "p1", ts=1000.0)
        for _ in range(10):
            idx.record_query("hot.example.com", "A", "p1", ts=1000.0)  # very popular
        idx.record_query("warm.example.com", "A", "p1", ts=1000.0)
        idx.record_query("cold1.example.com", "A", "p1", ts=100.0)  # old, one hit
        idx.record_query("cold2.example.com", "A", "p1", ts=100.0)  # triggers eviction
        top_names = {e.qname for e in idx.top(10, now=1001.0)}
        self.assertIn("hot.example.com", top_names)

    def test_top_orders_by_score_descending(self):
        idx = tb.WorkingSetIndex()
        idx.record_query("cold.example.com", "A", "p1", ts=0.0)
        for _ in range(20):
            idx.record_query("hot.example.com", "A", "p1", ts=1000.0)
        ranked = idx.top(2, now=1000.0)
        self.assertEqual(ranked[0].qname, "hot.example.com")


class TestPersistence(unittest.TestCase):
    def test_flush_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "warm-state.json"
            idx = tb.WorkingSetIndex()
            idx.record_query("example.com", "A", "p1", ts=1000.0)
            tb.flush(idx, path)
            loaded = tb.load(path)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded.top(1)[0].qname, "example.com")

    def test_flush_is_atomic_no_leftover_tmp(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "warm-state.json"
            idx = tb.WorkingSetIndex()
            idx.record_query("example.com", "A", "p1", ts=1000.0)
            tb.flush(idx, path)
            leftovers = [p for p in Path(td).iterdir() if p.name != "warm-state.json"]
            self.assertEqual(leftovers, [])

    def test_load_missing_file_returns_empty_index_not_error(self):
        with tempfile.TemporaryDirectory() as td:
            idx = tb.load(Path(td) / "does-not-exist.json")
            self.assertEqual(len(idx), 0)

    def test_load_corrupt_json_returns_empty_index_not_error(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "warm-state.json"
            path.write_text("{not valid json, truncated")
            idx = tb.load(path)  # must not raise
            self.assertEqual(len(idx), 0)

    def test_load_truncated_snapshot_returns_empty_index(self):
        """Simulates a crash mid-write of a NON-atomic hypothetical writer
        (or a copy interrupted partway) — a truncated file must degrade to
        cold, not raise."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "warm-state.json"
            idx = tb.WorkingSetIndex()
            idx.record_query("example.com", "A", "p1", ts=1000.0)
            tb.flush(idx, path)
            full_bytes = path.read_bytes()
            path.write_bytes(full_bytes[: len(full_bytes) // 2])  # simulate truncation
            loaded = tb.load(path)
            self.assertEqual(len(loaded), 0)

    def test_load_wrong_shape_json_returns_empty_index(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "warm-state.json"
            path.write_text('{"entries": [{"qname": "x"}]}')  # missing required keys
            loaded = tb.load(path)
            self.assertEqual(len(loaded), 0)

    def test_record_query_does_no_disk_io(self):
        """Coalesced/batched persistence requirement: record_query must be
        pure in-memory — verified structurally, no file APIs referenced in
        its implementation."""
        import inspect
        src = inspect.getsource(tb.WorkingSetIndex.record_query)
        for banned in ("open(", "os.write", "fsync"):
            self.assertNotIn(banned, src)


class TestPrewarmRateLimitingAndBounds(unittest.TestCase):
    def _entries(self, n):
        return [
            tb.WorkingSetEntry(qname=f"n{i}.example.com", qtype="A", cache_profile_id="p1", last_seen_ts=1000.0)
            for i in range(n)
        ]

    def test_all_entries_resolved_when_under_caps(self):
        resolved = []

        def _resolve(entry):
            resolved.append(entry.qname)
            return True

        clock = {"t": 0.0}
        stats = tb.run_prewarm(
            self._entries(5), _resolve, max_names_per_second=1000, max_total_names=100,
            max_duration_seconds=1000, clock=lambda: clock["t"], sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
        )
        self.assertEqual(stats.attempted, 5)
        self.assertEqual(stats.succeeded, 5)
        self.assertEqual(len(resolved), 5)

    def test_total_name_cap_enforced(self):
        stats = tb.run_prewarm(
            self._entries(50), lambda e: True, max_names_per_second=1000, max_total_names=10,
            max_duration_seconds=1000, sleep=lambda s: None,
        )
        self.assertEqual(stats.attempted, 10)
        self.assertGreater(stats.skipped_total_cap, 0)

    def test_duration_cap_stops_early(self):
        clock = {"t": 0.0}

        def _resolve(entry):
            clock["t"] += 1.0  # each resolve "takes" 1 second
            return True

        stats = tb.run_prewarm(
            self._entries(1000), _resolve, max_names_per_second=1000, max_total_names=10_000,
            max_duration_seconds=5.0, clock=lambda: clock["t"], sleep=lambda s: None,
        )
        self.assertTrue(stats.stopped_on_duration_cap)
        self.assertLess(stats.attempted, 1000)

    def test_rate_limiting_calls_sleep(self):
        sleep_calls = []
        clock = {"t": 0.0}
        tb.run_prewarm(
            self._entries(3), lambda e: True, max_names_per_second=2,  # 0.5s min interval
            max_total_names=100, max_duration_seconds=100,
            clock=lambda: clock["t"], sleep=lambda s: sleep_calls.append(s),
        )
        self.assertTrue(any(s > 0 for s in sleep_calls))

    def test_resource_pressure_pause_stops_prewarm(self):
        calls = {"n": 0}

        def _should_pause():
            calls["n"] += 1
            return calls["n"] > 2  # pause after a couple of attempts

        stats = tb.run_prewarm(
            self._entries(50), lambda e: True, max_names_per_second=1000, max_total_names=1000,
            max_duration_seconds=1000, should_pause=_should_pause, sleep=lambda s: None,
        )
        self.assertTrue(stats.stopped_on_pressure)
        self.assertLess(stats.attempted, 50)

    def test_single_resolve_failure_does_not_abort_prewarm(self):
        def _resolve(entry):
            if entry.qname == "n1.example.com":
                raise RuntimeError("upstream timeout")
            return True

        stats = tb.run_prewarm(
            self._entries(3), _resolve, max_names_per_second=1000, max_total_names=100,
            max_duration_seconds=1000, sleep=lambda s: None,
        )
        self.assertEqual(stats.attempted, 3)
        self.assertEqual(stats.failed, 1)
        self.assertEqual(stats.succeeded, 2)

    def test_resolve_returning_false_counts_as_failed_not_exception(self):
        stats = tb.run_prewarm(
            self._entries(2), lambda e: False, max_names_per_second=1000, max_total_names=100,
            max_duration_seconds=1000, sleep=lambda s: None,
        )
        self.assertEqual(stats.failed, 2)
        self.assertEqual(stats.succeeded, 0)


if __name__ == "__main__":
    unittest.main()
