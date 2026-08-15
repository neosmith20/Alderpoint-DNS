"""V2 analytics runtime dependency management (Gate #2 Blocker 3).

**Real production dependency model chosen (§3A):** Debian's own archive
does not carry ``python3-pyarrow`` or a ``duckdb``/``python3-duckdb``
package for this target (verified against this host's actual configured
apt sources -- ``apt-cache search pyarrow``/``apt-cache search duckdb``
both return nothing after a real ``apt-get update``, this is not assumed
or guessed). Rather than write a nonexistent Debian dependency into
``packaging/debian/control``, this module extends the SAME vendored-wheel
mechanism the project already uses in production for exactly this
situation (``app/alderpointdns_compiler.py``'s
``sync_vendored_python_deps()``, used today for a python-multipart
version Debian doesn't carry): real, pinned wheel files under
``vendor/v2-analytics/``, installed via ``pip install --no-index
--find-links ... --target ...`` -- never requiring network access at
install time, never touching dpkg-managed site-packages, and proven to
work with the actual system ``python3`` (verified directly, not only in
``dev/.venv-v2-bench``).
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VENDOR_DIR = REPO_ROOT / "vendor" / "v2-analytics"
VENDOR_RUNTIME_DIR = REPO_ROOT / "vendor-runtime-v2-analytics"


class AnalyticsDependencyError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProvisionResult:
    already_satisfied: bool
    installed: bool
    output: str


def provision_vendor_runtime(
    vendor_dir: Path = VENDOR_DIR, target_dir: Path = VENDOR_RUNTIME_DIR
) -> ProvisionResult:
    """Idempotent: if the target dir already has both packages importable,
    does nothing. Installs into a temporary sibling directory first and
    only renames it into place on success, so a failed/partial pip run
    never leaves ``target_dir`` in a half-installed state a later import
    could pick up silently.
    """
    if _importable_from(target_dir):
        return ProvisionResult(already_satisfied=True, installed=False, output="")

    if not vendor_dir.is_dir():
        raise AnalyticsDependencyError(f"vendor directory not found: {vendor_dir}")
    wheels = sorted(vendor_dir.glob("*.whl"))
    if not wheels:
        raise AnalyticsDependencyError(f"no vendored wheels found under {vendor_dir}")

    import tempfile
    import shutil

    tmp_target = Path(tempfile.mkdtemp(prefix=".v2-analytics-provision-", dir=target_dir.parent))
    try:
        proc = subprocess.run(
            [
                sys.executable, "-B", "-m", "pip", "install",
                "--no-index", "--find-links", str(vendor_dir),
                "--target", str(tmp_target), "--no-deps",
                "pyarrow", "duckdb",
            ],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0:
            raise AnalyticsDependencyError(
                f"pip install into vendor runtime failed: {proc.stdout}\n{proc.stderr}"
            )
        # tempfile.mkdtemp() creates its directory mode 0700 (owner-only) --
        # a real defect found via Workstream 4B clean-install testing: the
        # renamed-into-place target_dir silently inherited that mode,
        # making the provisioned runtime unreadable (not merely
        # unwritable) by any non-root service account. Every process that
        # actually needs these packages (the analytics/schedule/tier-b
        # workers, the management API) runs as the dedicated service
        # account, not root -- this broke `import pyarrow`/`import duckdb`
        # for all of them silently (ModuleNotFoundError looks identical to
        # "never provisioned"), while a root shell (e.g. manual testing
        # via `podman exec`) saw no problem at all, which is what let it
        # go unnoticed until a real systemd-managed non-root process hit
        # it. World-readable+traversable (0755), matching every other
        # package-owned, non-secret directory under /opt/alderpointdns-v2.
        os.chmod(tmp_target, 0o755)
        if target_dir.exists():
            shutil.rmtree(target_dir)
        tmp_target.rename(target_dir)
        return ProvisionResult(already_satisfied=False, installed=True, output=proc.stdout)
    finally:
        if tmp_target.exists():
            shutil.rmtree(tmp_target, ignore_errors=True)


def _importable_from(target_dir: Path) -> bool:
    if not target_dir.is_dir():
        return False
    proc = subprocess.run(
        [sys.executable, "-c", "import pyarrow, duckdb"],
        env={"PYTHONPATH": str(target_dir)},
        capture_output=True, timeout=30,
    )
    return proc.returncode == 0


_path_ensured = False


def ensure_on_path(target_dir: Path = VENDOR_RUNTIME_DIR) -> None:
    """Call before any lazy ``import pyarrow``/``import duckdb`` in this
    package. If the packages are already importable (e.g. present in
    system/dev site-packages, as in ``dev/.venv-v2-bench``), this is a
    harmless no-op -- it never overrides an already-working import with a
    vendored one. Only prepends ``target_dir`` to ``sys.path`` when
    needed, and only once per process.
    """
    global _path_ensured
    if _path_ensured:
        return
    try:
        import pyarrow  # noqa: F401
        import duckdb  # noqa: F401

        _path_ensured = True
        return
    except ImportError:
        pass
    if target_dir.is_dir():
        str_dir = str(target_dir)
        if str_dir not in sys.path:
            sys.path.insert(0, str_dir)
    _path_ensured = True


@dataclass(frozen=True)
class AnalyticsDependencyHealth:
    pyarrow_available: bool
    duckdb_available: bool
    degraded: bool
    reason: str


def check_health(target_dir: Path = VENDOR_RUNTIME_DIR) -> AnalyticsDependencyHealth:
    """Real health check (§3C): distinguishes "backend unavailable" from
    "legitimately zero records" -- callers (the analytics ingestion
    pipeline, the query service, an eventual admin-facing health
    endpoint) use this to report an actionable degraded state instead of
    silently returning empty results that look like a healthy system with
    no data.
    """
    ensure_on_path(target_dir)
    pyarrow_ok = True
    duckdb_ok = True
    reasons = []
    try:
        import pyarrow  # noqa: F401
    except ImportError as exc:
        pyarrow_ok = False
        reasons.append(f"pyarrow unavailable: {exc}")
    try:
        import duckdb  # noqa: F401
    except ImportError as exc:
        duckdb_ok = False
        reasons.append(f"duckdb unavailable: {exc}")
    degraded = not (pyarrow_ok and duckdb_ok)
    return AnalyticsDependencyHealth(
        pyarrow_available=pyarrow_ok,
        duckdb_available=duckdb_ok,
        degraded=degraded,
        reason="; ".join(reasons) if reasons else "all analytics dependencies available",
    )
