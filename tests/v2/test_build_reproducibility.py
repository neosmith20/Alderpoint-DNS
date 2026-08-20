"""Real build-reproducibility regression test for scripts/build-v2-deb.sh.

Real defect found and fixed live during a Gate #3 artifact-recovery pass
(docs/v2/build-reproducibility-fix.md): the build script staged every
packaged file via plain `cp`, which stamps each file's mtime with the
real wall-clock time the build happened to run at. `dpkg-deb --build`
preserves those mtimes into the package's tar members *and* separately
stamps the outer ar(5) container's own per-member timestamp with the
real build time -- so two builds of the exact same source commit
produced byte-identical file *content* but different final .deb
SHA-256 hashes purely from timestamp drift, making the single artifact
a Gate #3 review depends on impossible to reproduce or independently
re-verify from source alone.

This test builds the real package twice in a row (from whatever the
current git HEAD is) and asserts the two .deb files are byte-identical
-- the same real proof used to find and confirm the fix live, not a
mock.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build-v2-deb.sh"

DPKG_DEB_INSTALLED = shutil.which("dpkg-deb") is not None

pytestmark = pytest.mark.skipif(not DPKG_DEB_INSTALLED, reason="requires dpkg-deb")


def _build(output_dir: Path) -> Path:
    result = subprocess.run(
        ["sh", str(BUILD_SCRIPT), "--output-dir", str(output_dir)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    debs = list(output_dir.glob("*.deb"))
    assert len(debs) == 1, f"expected exactly one .deb, found {debs}"
    return debs[0]


class TestBuildReproducibility:
    def test_two_consecutive_builds_are_byte_identical(self, tmp_path):
        deb_a = _build(tmp_path / "a")
        deb_b = _build(tmp_path / "b")
        assert deb_a.read_bytes() == deb_b.read_bytes(), (
            "two builds of the exact same source commit must produce byte-identical "
            "packages -- see docs/v2/build-reproducibility-fix.md"
        )

    def test_inner_ar_members_are_byte_identical(self, tmp_path):
        # Finer-grained proof matching the real live investigation: even
        # once the outer .deb differs, the individual ar(5) members
        # (control.tar.xz/data.tar.xz/debian-binary) must each be
        # independently reproducible too -- this is what actually
        # isolated the real root cause (the outer ar container's own
        # timestamp, once the inner tar mtimes were already fixed).
        deb_a = _build(tmp_path / "a")
        deb_b = _build(tmp_path / "b")

        extract_a = tmp_path / "extract-a"
        extract_b = tmp_path / "extract-b"
        extract_a.mkdir()
        extract_b.mkdir()
        subprocess.run(["ar", "x", str(deb_a.resolve())], cwd=extract_a, check=True)
        subprocess.run(["ar", "x", str(deb_b.resolve())], cwd=extract_b, check=True)

        members_a = sorted(p.name for p in extract_a.iterdir())
        members_b = sorted(p.name for p in extract_b.iterdir())
        assert members_a == members_b

        for name in members_a:
            assert (extract_a / name).read_bytes() == (extract_b / name).read_bytes(), (
                f"ar member {name!r} differs between two builds of the same source"
            )


class TestPackageArchitectureMetadata:
    """Real defect closed (beta-rescue pass): RC42 declared "Architecture:
    all" while the package contains real x86_64/CPython 3.13 binary
    payloads (vendor/v2-analytics/'s pyarrow/duckdb wheels) -- inaccurate
    Debian metadata for a package that is not actually portable.
    """

    def test_package_declares_amd64_not_all(self, tmp_path):
        deb = _build(tmp_path / "arch")
        assert deb.name.endswith("_amd64.deb"), deb.name
        result = subprocess.run(
            ["dpkg-deb", "--field", str(deb), "Architecture"],
            capture_output=True, text=True, check=True,
        )
        assert result.stdout.strip() == "amd64"

    def test_vendored_analytics_wheels_are_genuinely_architecture_specific(self):
        # Sanity check on the premise itself: confirms *why* "all" would
        # be inaccurate, so this test fails loudly (not silently) if the
        # vendored wheels are ever swapped for genuinely portable ones,
        # at which point Architecture: all would become correct again.
        vendor_dir = REPO_ROOT / "vendor" / "v2-analytics"
        wheels = list(vendor_dir.glob("*.whl"))
        assert wheels, "expected vendored analytics wheels to exist"
        assert any("x86_64" in w.name for w in wheels), (
            "no architecture-specific wheel found -- if the vendored analytics "
            "dependencies are now genuinely portable (py3-none-any), Architecture: "
            "all would be accurate again and this premise (and the amd64 fix "
            "above) should be revisited"
        )
