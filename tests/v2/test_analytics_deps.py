"""Gate #2 Blocker 3: real production analytics dependency packaging.

Proves the vendored-wheel provisioning mechanism works (mirroring the
project's existing python-multipart precedent), that the real system
python3 -- not dev/.venv-v2-bench -- can use it, and that a missing/broken
dependency produces an observable degraded state rather than looking like
a legitimately-empty result.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from app.v2.analytics_deps import (
    VENDOR_DIR,
    AnalyticsDependencyError,
    check_health,
    provision_vendor_runtime,
)


class TestVendorWheelsPresent:
    def test_vendor_directory_has_real_wheels(self):
        assert VENDOR_DIR.is_dir()
        wheels = list(VENDOR_DIR.glob("*.whl"))
        assert any("pyarrow" in w.name for w in wheels)
        assert any("duckdb" in w.name for w in wheels)

    def test_wheels_match_pinned_requirements(self):
        req_path = VENDOR_DIR / "requirements.txt"
        assert req_path.exists()
        pins = req_path.read_text()
        assert "pyarrow==" in pins
        assert "duckdb==" in pins


@pytest.fixture(scope="module")
def provisioned_target(tmp_path_factory):
    # Each real provision is a ~215MB pip install (pyarrow + duckdb) --
    # shared once per module rather than once per test to avoid exhausting
    # a small tmpfs /tmp under repeated test runs (a real constraint hit
    # and fixed during this session: the first version of this file
    # provisioned a fresh copy per test and filled a 2GB tmpfs /tmp).
    target = tmp_path_factory.mktemp("shared-runtime") / "runtime"
    provision_vendor_runtime(vendor_dir=VENDOR_DIR, target_dir=target)
    return target


class TestProvisioning:
    def test_provision_into_fresh_target_succeeds(self, provisioned_target):
        assert provisioned_target.is_dir()

    def test_provisioned_target_directory_is_world_traversable(self, provisioned_target):
        """Workstream 4B real defect: tempfile.mkdtemp() creates its
        staging directory mode 0700; the old code renamed it directly into
        place, so the promoted target_dir silently inherited owner-only
        permissions -- unreadable (ModuleNotFoundError, indistinguishable
        from "never provisioned") by any non-root service account, which
        is every real process that actually needs these packages. A root
        shell saw no problem, which is exactly how this went unnoticed
        until a real systemd-managed non-root process hit it during
        clean-install testing.
        """
        import stat

        mode = provisioned_target.stat().st_mode
        assert mode & stat.S_IROTH, "target_dir must be world-readable"
        assert mode & stat.S_IXOTH, "target_dir must be world-traversable"

    def test_provision_is_idempotent(self, provisioned_target):
        result2 = provision_vendor_runtime(vendor_dir=VENDOR_DIR, target_dir=provisioned_target)
        assert result2.already_satisfied
        assert not result2.installed

    def test_missing_vendor_dir_raises_clear_error(self, tmp_path):
        with pytest.raises(AnalyticsDependencyError):
            provision_vendor_runtime(vendor_dir=tmp_path / "nowhere", target_dir=tmp_path / "runtime")

    def test_empty_vendor_dir_raises_clear_error(self, tmp_path):
        empty = tmp_path / "empty-vendor"
        empty.mkdir()
        with pytest.raises(AnalyticsDependencyError):
            provision_vendor_runtime(vendor_dir=empty, target_dir=tmp_path / "runtime")

    def test_provisioned_runtime_importable_from_real_system_python(self, provisioned_target):
        # Explicitly uses sys.executable (whatever python3 is actually
        # running this test) with a clean environment PYTHONPATH pointing
        # only at the provisioned target -- proves this doesn't secretly
        # depend on dev/.venv-v2-bench's own site-packages.
        proc = subprocess.run(
            [sys.executable, "-c", "import pyarrow, duckdb; print(pyarrow.__version__, duckdb.__version__)"],
            env={"PYTHONPATH": str(provisioned_target)},
            capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0, proc.stderr
        assert "25.0.1" in proc.stdout
        assert "1.5.5" in proc.stdout

    def test_failed_install_never_leaves_partial_target(self, tmp_path, monkeypatch):
        target = tmp_path / "runtime"
        import app.v2.analytics_deps as deps_mod

        original_run = subprocess.run

        def _failing_run(cmd, **kwargs):
            if "pip" in cmd[3:5] or "install" in cmd:
                class R:
                    returncode = 1
                    stdout = "simulated failure"
                    stderr = "simulated failure"
                return R()
            return original_run(cmd, **kwargs)

        monkeypatch.setattr(deps_mod.subprocess, "run", _failing_run)
        with pytest.raises(AnalyticsDependencyError):
            provision_vendor_runtime(vendor_dir=VENDOR_DIR, target_dir=target)
        assert not target.exists()


class TestHealthCheck:
    def test_healthy_when_dependencies_importable(self):
        health = check_health()
        assert health.pyarrow_available
        assert health.duckdb_available
        assert not health.degraded

    def test_degraded_when_pyarrow_unavailable(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def _blocking_import(name, *args, **kwargs):
            if name == "pyarrow":
                raise ImportError("simulated: pyarrow not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _blocking_import)
        health = check_health(target_dir=Path("/no/such/vendor-runtime"))
        assert not health.pyarrow_available
        assert health.degraded
        assert "pyarrow unavailable" in health.reason


class TestDegradedStateObservableInWriterAndService:
    def test_writer_reports_dependency_unavailable_not_silent(self, tmp_path, monkeypatch):
        import builtins

        from app.v2.parquet_writer import ParquetSegmentWriter

        real_import = builtins.__import__

        def _blocking_import(name, *args, **kwargs):
            if name == "pyarrow":
                raise ImportError("simulated: pyarrow not installed")
            return real_import(name, *args, **kwargs)

        writer = ParquetSegmentWriter(root=tmp_path / "parquet")
        monkeypatch.setattr(builtins, "__import__", _blocking_import)
        writer.ingest([
            {
                "id": 1, "ts": 1000.0, "client": "10.0.0.1", "client_name": "",
                "domain": "x.example", "qtype": "A", "protocol": "udp", "rcode": "NOERROR",
                "latency_ms": 1.0, "blocked": False, "block_reason": "", "upstream": "d",
                "cache_status": "miss", "cache_profile_id": "p1",
            }
        ])
        writer.flush()
        assert writer.stats.dependency_unavailable is True
        assert writer.stats.dropped_count == 1  # never silently discarded without a trace
        assert "pyarrow" in (writer.stats.last_error or "")

    def test_service_returns_degraded_result_not_empty_success(self, tmp_path, monkeypatch):
        import builtins
        import time

        from app.v2 import aggregates_db
        from app.v2.analytics_service import AnalyticsService
        from app.v2.parquet_writer import ParquetSegmentWriter

        aggregates_db.initialize(tmp_path / "aggregates.db")
        # A real segment must exist first, otherwise the reader's own
        # partition-pruning short-circuits to an empty result BEFORE ever
        # attempting to import duckdb at all, and the degraded path this
        # test means to exercise would never actually be reached.
        writer = ParquetSegmentWriter(root=tmp_path / "parquet")
        writer.ingest([
            {
                "id": 1, "ts": time.time() - 1, "client": "10.0.0.1", "client_name": "",
                "domain": "x.example", "qtype": "A", "protocol": "udp", "rcode": "NOERROR",
                "latency_ms": 1.0, "blocked": False, "block_reason": "", "upstream": "d",
                "cache_status": "miss", "cache_profile_id": "p1",
            }
        ])
        writer.flush()
        writer.close()

        service = AnalyticsService(parquet_root=tmp_path / "parquet", aggregates_path=tmp_path / "aggregates.db")

        real_import = builtins.__import__

        def _blocking_import(name, *args, **kwargs):
            if name == "duckdb":
                raise ImportError("simulated: duckdb not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _blocking_import)
        result = service.recent_query_log(minutes=60)
        assert result.degraded is True
        assert result.rows == []
        assert "duckdb" in result.degraded_reason
        service.close()
