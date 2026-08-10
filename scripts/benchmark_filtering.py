#!/usr/bin/env python3
"""Reproducible local performance baseline for Alderpoint DNS filtering.

This script intentionally does not change production behavior. It imports the
current compiler modules, redirects their filesystem/DB paths to a temporary
workspace, generates deterministic synthetic blocklist sources, and measures
the major CPU/memory/I/O phases separately.
"""

from __future__ import annotations

import argparse
import cProfile
import csv
import io
import json
import os
import platform
import pstats
import resource
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import tracemalloc
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app import alderpointdns_compiler as compiler  # noqa: E402
from app import custom_rules  # noqa: E402


DATASETS = {
    "small": 100_000,
    "medium": 500_000,
    "large": 1_000_000,
    "very-large": 3_000_000,
}


@dataclass
class TimerResult:
    wall_s: float = 0.0
    cpu_s: float = 0.0


@dataclass
class BenchmarkResult:
    dataset: str
    target_domains: int
    input_rules: int
    unique_domains: int
    rpz_bytes: int
    peak_tracemalloc_mb: float
    peak_rss_mb: float
    phases: dict[str, TimerResult] = field(default_factory=dict)
    profile_top_cumulative: list[str] = field(default_factory=list)
    profile_top_calls: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_json(self) -> dict:
        data = asdict(self)
        data["phases"] = {key: asdict(value) for key, value in self.phases.items()}
        return data


class PhaseTimer:
    def __init__(self, result: BenchmarkResult, name: str):
        self.result = result
        self.name = name
        self.start_wall = 0.0
        self.start_cpu = 0.0

    def __enter__(self):
        self.start_wall = time.perf_counter()
        self.start_cpu = time.process_time()
        return self

    def __exit__(self, *_exc):
        self.result.phases[self.name] = TimerResult(
            wall_s=time.perf_counter() - self.start_wall,
            cpu_s=time.process_time() - self.start_cpu,
        )


@contextmanager
def patched_paths(workdir: Path):
    original = {
        "compiler_DB_PATH": compiler.DB_PATH,
        "compiler_DOWNLOAD_DIR": compiler.DOWNLOAD_DIR,
        "compiler_COMPILED_RPZ": compiler.COMPILED_RPZ,
        "compiler_STAGING_DIR": compiler.STAGING_DIR,
        "compiler_BACKUP_DIR": compiler.BACKUP_DIR,
        "compiler_DEPLOY_LOCK": compiler.DEPLOY_LOCK,
        "compiler_MIGRATION_LOCK": compiler.MIGRATION_LOCK,
        "custom_DB_PATH": custom_rules.DB_PATH,
        "custom_COMPILED_DNSDIST_DIR": custom_rules.COMPILED_DNSDIST_DIR,
        "custom_STAGING_DIR": custom_rules.STAGING_DIR,
        "custom_BACKUP_DIR": custom_rules.BACKUP_DIR,
    }
    compiler.DB_PATH = workdir / "alderpointdns.db"
    compiler.DOWNLOAD_DIR = workdir / "downloads"
    compiler.COMPILED_RPZ = workdir / "compiled" / "bind" / "alderpointdns.rpz"
    compiler.STAGING_DIR = workdir / "staging"
    compiler.BACKUP_DIR = workdir / "backups"
    compiler.DEPLOY_LOCK = workdir / "staging" / "deploy.lock"
    compiler.MIGRATION_LOCK = workdir / "staging" / "schema-migration.lock"
    custom_rules.DB_PATH = compiler.DB_PATH
    custom_rules.COMPILED_DNSDIST_DIR = workdir / "compiled" / "dnsdist"
    custom_rules.STAGING_DIR = compiler.STAGING_DIR
    custom_rules.BACKUP_DIR = compiler.BACKUP_DIR
    try:
        yield
    finally:
        compiler.DB_PATH = original["compiler_DB_PATH"]
        compiler.DOWNLOAD_DIR = original["compiler_DOWNLOAD_DIR"]
        compiler.COMPILED_RPZ = original["compiler_COMPILED_RPZ"]
        compiler.STAGING_DIR = original["compiler_STAGING_DIR"]
        compiler.BACKUP_DIR = original["compiler_BACKUP_DIR"]
        compiler.DEPLOY_LOCK = original["compiler_DEPLOY_LOCK"]
        compiler.MIGRATION_LOCK = original["compiler_MIGRATION_LOCK"]
        custom_rules.DB_PATH = original["custom_DB_PATH"]
        custom_rules.COMPILED_DNSDIST_DIR = original["custom_COMPILED_DNSDIST_DIR"]
        custom_rules.STAGING_DIR = original["custom_STAGING_DIR"]
        custom_rules.BACKUP_DIR = original["custom_BACKUP_DIR"]


def domain_for(index: int, namespace: str = "bench") -> str:
    return f"d{index:08d}.{namespace}.example"


def generate_source(path: Path, source_index: int, target_domains: int, overlap_stride: int = 5) -> int:
    """Generate one realistic mixed-format source and return input line count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    per_source = target_domains // 3
    start = source_index * per_source
    with path.open("w", newline="\n") as handle:
        handle.write(f"! synthetic source {source_index}\n")
        for i in range(per_source):
            global_index = start + i
            if i % overlap_stride == 0 and source_index:
                global_index = i
            domain = domain_for(global_index)
            kind = i % 10
            if kind in {0, 1, 2, 3}:
                handle.write(f"0.0.0.0 {domain}\n")
            elif kind in {4, 5, 6, 7}:
                handle.write(f"||{domain}^\n")
            elif kind == 8:
                handle.write(f"{domain}\n")
            else:
                handle.write(f"@@||allow-{domain}^\n")
            count += 1
            if i % 23 == 0:
                handle.write(f"0.0.0.0 {domain}\n")
                count += 1
    return count


def setup_db(conn: sqlite3.Connection, source_paths: list[Path]) -> None:
    compiler._apply_schema(conn)
    conn.execute(f"PRAGMA user_version={compiler.SCHEMA_VERSION}")
    for idx, path in enumerate(source_paths, 1):
        conn.execute(
            """
            INSERT INTO sources(id, name, url, enabled, category)
            VALUES (?, ?, ?, 1, 'ads_trackers')
            """,
            (idx, f"bench-source-{idx}", path.as_uri()),
        )
    sample_rules = [
        ("@@||allow-d00000042.bench.example^", "allow overlap"),
        ("||custom-block.bench.example^", "custom block"),
        ("|exact-custom.bench.example^", "custom exact"),
        ("||rewrite-me.bench.example^$dnsrewrite=192.0.2.10", "custom rewrite"),
        ("/(^|\\.)regex-block-[0-9]+\\.bench\\.example$/", "custom regex"),
    ]
    custom_rules.init_db(conn)
    for text, comment in sample_rules:
        for parsed in custom_rules.parse_rule(text):
            if parsed.validation_state == "valid":
                custom_rules._insert_rule(conn, parsed, "benchmark", comment, True, None)
    conn.commit()


def source_rows(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM sources WHERE enabled=1 ORDER BY id"))


def profile_text(profile: cProfile.Profile, sort: str, limit: int = 15) -> list[str]:
    stream = io.StringIO()
    pstats.Stats(profile, stream=stream).strip_dirs().sort_stats(sort).print_stats(limit)
    return stream.getvalue().splitlines()[4:]


def run_named_checkzone(path: Path) -> str:
    if not shutil.which("named-checkzone"):
        return "named-checkzone unavailable"
    proc = subprocess.run(
        ["named-checkzone", compiler.RPZ_ZONE, str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout[-4000:])
    return proc.stdout[-1000:]


def measure_dataset(dataset: str, target_domains: int, keep_workdir: Path | None, validate: bool) -> BenchmarkResult:
    base = keep_workdir or Path(tempfile.mkdtemp(prefix=f"alderpointdns-bench-{dataset}-"))
    result = BenchmarkResult(dataset=dataset, target_domains=target_domains, input_rules=0, unique_domains=0, rpz_bytes=0, peak_tracemalloc_mb=0.0, peak_rss_mb=0.0)
    tracemalloc.start()
    with patched_paths(base):
        compiler.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        paths = [compiler.DOWNLOAD_DIR / "current" / f"{idx + 1}-bench-source-{idx + 1}.txt" for idx in range(3)]
        with PhaseTimer(result, "fixture_generate"):
            result.input_rules = sum(generate_source(path, idx, target_domains) for idx, path in enumerate(paths))
        conn = sqlite3.connect(compiler.DB_PATH)
        conn.row_factory = sqlite3.Row
        with PhaseTimer(result, "db_schema_seed"):
            setup_db(conn, paths)

        profile = cProfile.Profile()
        profile.enable()
        all_blocks: set[str] = set()
        all_allows: set[str] = set()
        per_source_blocks: dict[int, set[str]] = {}
        per_source_stats: dict[int, compiler.ParseStats] = {}
        read_contents: list[tuple[sqlite3.Row, str]] = []
        rows = source_rows(conn)

        with PhaseTimer(result, "source_read"):
            for row in rows:
                current, _staging = compiler.source_paths(row)
                read_contents.append((row, current.read_text(errors="replace")))

        original_normalize = compiler.normalize_domain
        normalize_seconds = 0.0
        normalize_calls = 0

        def timed_normalize(raw: str) -> str | None:
            nonlocal normalize_seconds, normalize_calls
            start = time.perf_counter()
            try:
                return original_normalize(raw)
            finally:
                normalize_seconds += time.perf_counter() - start
                normalize_calls += 1

        compiler.normalize_domain = timed_normalize
        try:
            with PhaseTimer(result, "parse"):
                for row, content in read_contents:
                    blocks, allows, stats = compiler.parse_rules(content)
                    all_blocks.update(blocks)
                    all_allows.update(allows)
                    per_source_blocks[row["id"]] = blocks
                    per_source_stats[row["id"]] = stats
        finally:
            compiler.normalize_domain = original_normalize
        result.phases["normalize_subtime"] = TimerResult(wall_s=normalize_seconds, cpu_s=normalize_seconds)
        result.notes.append(f"normalize_domain calls={normalize_calls}")

        with PhaseTimer(result, "dedupe_unique_contribution"):
            seen: set[str] = set()
            for row in rows:
                stats = per_source_stats[row["id"]]
                blocks = per_source_blocks[row["id"]]
                new_domains = blocks - seen
                stats.unique_active_domains = len(new_domains)
                seen.update(blocks)
                stats.duplicate_domains = (stats.parsed_rules - stats.accepted_domains) + (len(blocks) - stats.unique_active_domains)
            active_blocks = all_blocks - all_allows
        result.unique_domains = len(active_blocks)

        with PhaseTimer(result, "db_write_stats"):
            for row in rows:
                compiler.record_parse_stats(conn, row["id"], per_source_stats[row["id"]])
            conn.execute("UPDATE sources SET final_active_domains=? WHERE enabled=1", (len(active_blocks),))
            conn.commit()

        with PhaseTimer(result, "custom_collect_precedence"):
            custom_active = custom_rules.collect_active(conn)
            active_blocks = custom_rules.subtract_allowed(active_blocks, custom_active)

        with PhaseTimer(result, "rpz_render"):
            rpz_text = compiler.render_rpz(active_blocks, custom_active)

        with PhaseTimer(result, "rpz_write"):
            compiler.COMPILED_RPZ.parent.mkdir(parents=True, exist_ok=True)
            compiler.COMPILED_RPZ.write_text(rpz_text)
        result.rpz_bytes = compiler.COMPILED_RPZ.stat().st_size

        if validate:
            with PhaseTimer(result, "named_checkzone"):
                result.notes.append(run_named_checkzone(compiler.COMPILED_RPZ))

        profile.disable()
        result.profile_top_cumulative = profile_text(profile, "cumulative")
        result.profile_top_calls = profile_text(profile, "calls")
        conn.close()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result.peak_tracemalloc_mb = peak / 1048576
    result.peak_rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    if keep_workdir is None:
        shutil.rmtree(base, ignore_errors=True)
    return result


def write_outputs(results: list[BenchmarkResult], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
        },
        "results": [result.as_json() for result in results],
    }
    output.with_suffix(".json").write_text(json.dumps(payload, indent=2))
    with output.with_suffix(".csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        phase_names = sorted({name for result in results for name in result.phases})
        writer.writerow(["dataset", "target_domains", "input_rules", "unique_domains", "rpz_bytes", "peak_tracemalloc_mb", "peak_rss_mb", *phase_names])
        for result in results:
            writer.writerow([
                result.dataset,
                result.target_domains,
                result.input_rules,
                result.unique_domains,
                result.rpz_bytes,
                f"{result.peak_tracemalloc_mb:.2f}",
                f"{result.peak_rss_mb:.2f}",
                *[f"{result.phases.get(name, TimerResult()).wall_s:.6f}" for name in phase_names],
            ])


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark Alderpoint DNS filtering pipeline")
    parser.add_argument("--datasets", default="small,medium", help="Comma-separated dataset names: small,medium,large,very-large")
    parser.add_argument("--output", default="benchmarks/results/filtering-baseline", help="Output path stem for .json and .csv")
    parser.add_argument("--keep-workdir", type=Path, help="Reuse/keep this temporary work directory for inspection")
    parser.add_argument("--no-validate", action="store_true", help="Skip named-checkzone validation")
    args = parser.parse_args()

    results = []
    for name in [item.strip() for item in args.datasets.split(",") if item.strip()]:
        if name not in DATASETS:
            raise SystemExit(f"unknown dataset {name}; expected one of {', '.join(DATASETS)}")
        print(f"benchmarking {name} ({DATASETS[name]} target domains)", flush=True)
        results.append(measure_dataset(name, DATASETS[name], args.keep_workdir, not args.no_validate))
    write_outputs(results, REPO_ROOT / args.output)
    print(f"wrote {(REPO_ROOT / args.output).with_suffix('.json')}")
    print(f"wrote {(REPO_ROOT / args.output).with_suffix('.csv')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
