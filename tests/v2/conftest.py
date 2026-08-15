"""Ensures the vendored analytics runtime (pyarrow/duckdb) is on
sys.path BEFORE any test module's own module-level
``pytest.importorskip("pyarrow")``/``pytest.importorskip("duckdb")``
guards run at collection time (Gate #2 Blocker 3).

Without this, running the real production runtime's system ``python3``
(which has no pyarrow/duckdb in its normal site-packages -- confirmed,
neither is a real Debian package for this target) would skip every
analytics test that guards on module-level import, even after
``app/v2/analytics_deps.py``'s vendor-runtime mechanism is provisioned,
because those guards run at module-import time, before any individual
test's body (where ``ensure_on_path()`` is already wired into the
lazy-import call sites) gets a chance to run.

This does not itself provision the vendor runtime -- that's a real,
explicit step (``analytics_deps.provision_vendor_runtime()``, mirroring
the project's existing python-multipart vendoring precedent) a real
install/CI step performs once. This conftest only makes an *already
provisioned* vendor runtime visible to import guards; if nothing has
been provisioned and pyarrow/duckdb aren't otherwise installed, the
existing ``importorskip`` guards still skip cleanly, exactly as before.
"""

from app.v2.analytics_deps import ensure_on_path

ensure_on_path()
