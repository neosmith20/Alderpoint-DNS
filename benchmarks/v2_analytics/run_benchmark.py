#!/usr/bin/env python3
"""V2 Workstream 1 analytics storage benchmark runner.

Compares Parquet+Zstd+DuckDB, SQLite WAL, and compressed JSONL at a chosen
scale. Writes results as JSON under benchmarks/v2_analytics/results/ and
deletes the generated dataset directory afterward (disk is tight on this
host — see docs/v2/benchmark-results.md for the constraint).

Usage:
    python3 benchmarks/v2_analytics/run_benchmark.py --scale 100000 --batch 5000
"""
from __future__ import annotations

import argparse
import gc
import json
import os
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks.v2_analytics.backends import QUERY_NAMES, make_backend  # noqa: E402
from benchmarks.v2_analytics.generate import generate_records  # noqa: E402

DATA_ROOT = Path(__file__).resolve().parent / "data"
RESULTS_ROOT = Path(__file__).resolve().parent / "results"


def _peak_rss_mb() -> float:
    # ru_maxrss is KiB on Linux.
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def _dir_size_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def run_one_backend(kind: str, scale: int, batch_size: int, **backend_kwargs) -> dict:
    backend_root = DATA_ROOT / kind
    if backend_root.exists():
        shutil.rmtree(backend_root)
    backend_root.mkdir(parents=True)

    backend = make_backend(kind, backend_root, **backend_kwargs)

    gc.collect()
    t_ingest_start = time.perf_counter()
    batch: list[dict] = []
    for rec in generate_records(scale, seed=42):
        batch.append(rec)
        if len(batch) >= batch_size:
            backend.ingest(batch)
            batch = []
    if batch:
        backend.ingest(batch)
    t_ingest_end = time.perf_counter()

    ingest_seconds = t_ingest_end - t_ingest_start
    disk_bytes = backend.disk_usage_bytes()

    query_timings = {}
    for name in QUERY_NAMES:
        t0 = time.perf_counter()
        backend.query(name)  # cold
        t1 = time.perf_counter()
        backend.query(name)  # warm
        t2 = time.perf_counter()
        query_timings[name] = {
            "cold_ms": round((t1 - t0) * 1000, 3),
            "warm_ms": round((t2 - t1) * 1000, 3),
        }

    # Retention-deletion cost: delete oldest ~20% of segments/rows.
    retention_start = time.perf_counter()
    if kind == "sqlite_wal":
        cutoff = backend.conn.execute(
            "SELECT ts FROM query_events ORDER BY ts LIMIT 1 OFFSET ?",
            (int(scale * 0.2),),
        ).fetchone()
        if cutoff:
            backend.conn.execute("DELETE FROM query_events WHERE ts < ?", cutoff)
    elif kind == "jsonl_gzip":
        segs = sorted(backend_root.glob("segment-*.jsonl.gz"))
        for p in segs[: max(1, len(segs) // 5)]:
            p.unlink()
    elif kind == "parquet_zstd_duckdb":
        segs = sorted(backend_root.glob("segment-*.parquet"))
        for p in segs[: max(1, len(segs) // 5)]:
            p.unlink()  # filesystem segment deletion only, no DELETE/VACUUM
    retention_seconds = time.perf_counter() - retention_start

    backend.close()

    result = {
        "backend": kind,
        "scale": scale,
        "batch_size": batch_size,
        "ingest_seconds": round(ingest_seconds, 3),
        "ingest_rows_per_sec": round(scale / ingest_seconds, 1) if ingest_seconds > 0 else None,
        "disk_bytes": disk_bytes,
        "disk_mb": round(disk_bytes / (1024 * 1024), 2),
        "bytes_per_row": round(disk_bytes / scale, 2),
        "peak_rss_mb": round(_peak_rss_mb(), 1),
        "retention_delete_seconds": round(retention_seconds, 4),
        "query_timings_ms": query_timings,
    }
    shutil.rmtree(backend_root, ignore_errors=True)
    return result


def _run_backend_in_subprocess(
    kind: str, scale: int, batch: int, row_group_size: int, zstd_level: int
) -> dict:
    """Run one backend's full ingest+query+retention pass in its own child
    process, so its peak-RSS measurement (``resource.getrusage`` inside that
    process) reflects only that backend — not whatever the previous backend
    in the same process happened to allocate.

    This is the fix for the benchmark-quality issue Dex's review identified:
    with all three backends running sequentially in one process,
    ``ru_maxrss`` is the process's high-water mark since start, so a later
    backend's reported "peak RSS" could actually be inherited from an
    earlier backend's larger allocation (observed concretely: JSONL's
    full-dataset in-memory query scan inflated the figure reported for
    Parquet+DuckDB, which ran immediately after it and never itself held the
    whole dataset in Python objects).
    """
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--single-backend",
        kind,
        "--scale",
        str(scale),
        "--batch",
        str(batch),
        "--row-group-size",
        str(row_group_size),
        "--zstd-level",
        str(zstd_level),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"backend {kind!r} subprocess exited {proc.returncode}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    # stdout carries exactly one JSON object on its own trailing line;
    # everything before that (progress prints) is diagnostic only.
    last_line = next(line for line in reversed(proc.stdout.splitlines()) if line.strip())
    return json.loads(last_line)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scale", type=int, required=True)
    ap.add_argument("--batch", type=int, default=5000)
    ap.add_argument(
        "--backends",
        nargs="+",
        default=["sqlite_wal", "jsonl_gzip", "parquet_zstd_duckdb"],
    )
    ap.add_argument("--row-group-size", type=int, default=50_000)
    ap.add_argument("--zstd-level", type=int, default=6)
    ap.add_argument("--out", type=str, default=None)
    ap.add_argument(
        "--single-backend",
        type=str,
        default=None,
        help=(
            "Internal: run exactly one backend in this process and print its "
            "result JSON to stdout, then exit. Used by the parent process to "
            "get isolated per-backend peak-RSS measurements via subprocess."
        ),
    )
    ap.add_argument(
        "--in-process",
        action="store_true",
        help=(
            "Run all backends in one process (the pre-remediation behavior). "
            "Faster for quick iteration, but peak_rss_mb is process-cumulative "
            "across backends, not backend-specific. Prefer the default "
            "(subprocess-isolated) mode when memory figures matter."
        ),
    )
    args = ap.parse_args()

    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

    if args.single_backend:
        # Child-process mode: run one backend, print its result as the last
        # line of stdout, and do nothing else (no results file, no cleanup
        # of DATA_ROOT as a whole — only this backend's own subdirectory).
        kwargs = {}
        if args.single_backend == "parquet_zstd_duckdb":
            kwargs = {"row_group_size": args.row_group_size, "zstd_level": args.zstd_level}
        result = run_one_backend(args.single_backend, args.scale, args.batch, **kwargs)
        print(json.dumps(result))
        return

    results = []
    for kind in args.backends:
        print(f"--- running {kind} @ scale={args.scale} batch={args.batch} ---", file=sys.stderr)
        if args.in_process:
            kwargs = {}
            if kind == "parquet_zstd_duckdb":
                kwargs = {"row_group_size": args.row_group_size, "zstd_level": args.zstd_level}
            result = run_one_backend(kind, args.scale, args.batch, **kwargs)
        else:
            result = _run_backend_in_subprocess(
                kind, args.scale, args.batch, args.row_group_size, args.zstd_level
            )
        results.append(result)
        print(json.dumps(result, indent=2), file=sys.stderr)

    out_name = args.out or f"scale-{args.scale}.json"
    out_path = RESULTS_ROOT / out_name
    out_path.write_text(json.dumps({"scale": args.scale, "results": results}, indent=2))
    print(f"wrote {out_path}", file=sys.stderr)

    shutil.rmtree(DATA_ROOT, ignore_errors=True)


if __name__ == "__main__":
    main()
