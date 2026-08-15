"""Gate #2 residual P0-C: the real V2 analytics provisioning entry point
(scripts/provision-v2-analytics-vendor-runtime.sh) invoked exactly as a
future V2 install-lifecycle step would call it -- as a subprocess, with an
isolated target directory (never the real vendor-runtime-v2-analytics/),
proving: success on a clean target, idempotency on a second run, and a
non-zero exit / clear failure signal when provisioning cannot succeed
(matching the existing V1 postinst's fail-the-install-not-silently-degrade
convention for its own vendor-deps-sync step).
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO_ROOT / "scripts" / "provision-v2-analytics-vendor-runtime.sh"


@pytest.fixture()
def isolated_target(tmp_path):
    target = tmp_path / "vendor-runtime-v2-analytics"
    yield target
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)


def _run(target_dir, vendor_dir=None, timeout=180):
    env = dict(os.environ)
    env["ALDERPOINTDNS_V2_ANALYTICS_TARGET_DIR"] = str(target_dir)
    if vendor_dir is not None:
        env["ALDERPOINTDNS_V2_ANALYTICS_VENDOR_DIR"] = str(vendor_dir)
    return subprocess.run(
        ["sh", str(SCRIPT)], capture_output=True, text=True, timeout=timeout, env=env
    )


class TestRealScriptInvocation:
    def test_fresh_target_provisions_and_exits_zero(self, isolated_target):
        result = _run(isolated_target)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "provisioned" in result.stdout
        assert "degraded=False" in result.stdout
        # Real proof the target is importable, not just that the script
        # claimed success.
        check = subprocess.run(
            ["python3", "-c", "import pyarrow, duckdb"],
            env={**os.environ, "PYTHONPATH": str(isolated_target)},
            capture_output=True,
        )
        assert check.returncode == 0, check.stderr

    def test_second_run_is_idempotent_no_reinstall(self, isolated_target):
        first = _run(isolated_target)
        assert first.returncode == 0
        second = _run(isolated_target)
        assert second.returncode == 0
        assert "already provisioned" in second.stdout

    def test_missing_vendor_dir_fails_the_install_not_silently(self, tmp_path, isolated_target):
        empty_vendor = tmp_path / "no-such-vendor-dir"
        result = _run(isolated_target, vendor_dir=empty_vendor)
        assert result.returncode != 0
        assert not isolated_target.exists() or not any(isolated_target.iterdir())
