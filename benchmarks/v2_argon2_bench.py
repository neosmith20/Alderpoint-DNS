#!/usr/bin/env python3
"""One-off Argon2id parameter benchmark for V2 Workstream 1.

Run on the actual test-server hardware (not emulated) to pick interactive
login parameters. Prints timing for a small grid of (time_cost, memory_cost,
parallelism) combos so a human can pick a ~250-500ms target.

Usage: python3 benchmarks/v2_argon2_bench.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.v2.auth_hash import make_hasher  # noqa: E402

GRID = [
    # (time_cost, memory_cost_kib, parallelism)
    (2, 19456, 1),   # argon2-cffi library default (19 MiB) baseline reference
    (2, 65536, 2),
    (3, 65536, 2),
    (3, 131072, 2),
    (4, 131072, 2),
    (3, 262144, 4),
    (4, 262144, 2),
    (5, 262144, 2),
]

PASSWORD = "a-representative-admin-password-123!"


def main() -> None:
    print(f"{'time_cost':>10} {'mem_kib':>10} {'parallelism':>12} {'hash_ms':>10} {'verify_ms':>10}")
    for time_cost, mem_kib, par in GRID:
        hasher = make_hasher(time_cost=time_cost, memory_cost_kib=mem_kib, parallelism=par)
        t0 = time.perf_counter()
        encoded = hasher.hash(PASSWORD)
        t1 = time.perf_counter()
        hasher.verify(encoded, PASSWORD)
        t2 = time.perf_counter()
        print(
            f"{time_cost:>10} {mem_kib:>10} {par:>12} "
            f"{(t1 - t0) * 1000:>10.1f} {(t2 - t1) * 1000:>10.1f}"
        )


if __name__ == "__main__":
    main()
