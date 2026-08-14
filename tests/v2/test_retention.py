"""Tests for app/v2/retention.py (Workstream 2, §6, §33 PARQUET retention)."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

pytest.importorskip("pyarrow")

from app.v2.parquet_writer import ParquetSegmentWriter  # noqa: E402
from app.v2.retention import delete_by_age, delete_by_size_cap, run_retention  # noqa: E402


def _write_n_segments(root: Path, n: int, rows_each: int = 5) -> list[Path]:
    w = ParquetSegmentWriter(root, max_rows_per_segment=rows_each)
    for seg in range(n):
        now = time.time()
        w.ingest([
            dict(id=i, ts=now, client="c", client_name="c", domain="d.example.com",
                 qtype="A", protocol="udp", rcode="NOERROR", latency_ms=1.0, blocked=False,
                 block_reason=None, upstream="1.1.1.1", cache_status="hit", cache_profile_id="p")
            for i in range(rows_each)
        ])
        w.flush()
    return sorted(root.rglob("*.parquet"))


def _age_files(paths: list[Path], ages_seconds: list[float]) -> None:
    now = time.time()
    for p, age in zip(paths, ages_seconds):
        t = now - age
        os.utime(p, (t, t))


def test_delete_by_age_removes_only_old_segments(tmp_path):
    segs = _write_n_segments(tmp_path, 5)
    # oldest to newest: ages 1000, 800, 600, 400, 200 seconds
    _age_files(segs, [1000, 800, 600, 400, 200])
    result = delete_by_age(tmp_path, max_age_seconds=500, protect_most_recent=0)
    assert len(result.deleted) == 3  # 1000, 800, 600
    remaining = sorted(tmp_path.rglob("*.parquet"))
    assert len(remaining) == 2


def test_delete_by_age_protects_most_recent_even_if_old(tmp_path):
    segs = _write_n_segments(tmp_path, 3)
    _age_files(segs, [10000, 10000, 10000])  # all "old"
    result = delete_by_age(tmp_path, max_age_seconds=1, protect_most_recent=1)
    assert len(result.deleted) == 2
    remaining = sorted(tmp_path.rglob("*.parquet"))
    assert len(remaining) == 1
    assert remaining[0] == segs[-1]  # the newest-by-mtime one survives


def test_delete_by_size_cap_deletes_oldest_first(tmp_path):
    segs = _write_n_segments(tmp_path, 5, rows_each=20)
    _age_files(segs, [500, 400, 300, 200, 100])
    total_before = sum(p.stat().st_size for p in segs)
    cap = total_before // 2
    result = delete_by_size_cap(tmp_path, max_total_bytes=cap, protect_most_recent=0)
    assert len(result.deleted) > 0
    # deleted set must be a prefix of the oldest-first ordering
    remaining = set(tmp_path.rglob("*.parquet"))
    newest_survivors = segs[-len(remaining):]
    assert remaining == set(newest_survivors)


def test_size_cap_never_deletes_protected_most_recent(tmp_path):
    segs = _write_n_segments(tmp_path, 3, rows_each=20)
    _age_files(segs, [300, 200, 100])
    result = delete_by_size_cap(tmp_path, max_total_bytes=1, protect_most_recent=1)
    remaining = sorted(tmp_path.rglob("*.parquet"))
    assert remaining == [segs[-1]]


def test_retention_never_touches_temp_files(tmp_path):
    segs = _write_n_segments(tmp_path, 2)
    _age_files(segs, [10000, 10000])
    # Simulate an in-progress writer temp file in the same tree.
    partition_dir = segs[0].parent
    tmp_file = partition_dir / ".99-999999.parquet.tmp"
    tmp_file.write_bytes(b"in progress")
    old_time = time.time() - 99999
    os.utime(tmp_file, (old_time, old_time))

    delete_by_age(tmp_path, max_age_seconds=1, protect_most_recent=0)
    assert tmp_file.exists()  # never touched despite being "old"


def test_run_retention_combines_age_and_size(tmp_path):
    segs = _write_n_segments(tmp_path, 4, rows_each=10)
    _age_files(segs, [10000, 5000, 100, 50])
    result = run_retention(
        tmp_path, max_age_seconds=8000, max_total_bytes=1, protect_most_recent=1,
    )
    remaining = sorted(tmp_path.rglob("*.parquet"))
    assert remaining == [segs[-1]]  # only the protected newest one survives both passes


def test_empty_tree_is_a_noop(tmp_path):
    result = run_retention(tmp_path, max_age_seconds=1, max_total_bytes=1)
    assert result.deleted == []
    assert result.kept_count == 0


def test_delete_errors_are_recorded_not_raised(tmp_path, monkeypatch):
    segs = _write_n_segments(tmp_path, 2)
    _age_files(segs, [10000, 10000])

    orig_unlink = Path.unlink

    def _boom(self, *a, **kw):
        if self == segs[0]:
            raise OSError("simulated permission denied")
        return orig_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", _boom)
    result = delete_by_age(tmp_path, max_age_seconds=1, protect_most_recent=0)
    assert result.errors
    assert "simulated permission denied" in result.errors[0]
