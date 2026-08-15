# V2 Analytics Production Dependency Model (Gate #2 Blocker 3)

**Status:** Real, proven against the actual system `python3` (not `dev/.venv-v2-bench`).

## Real dependency reality (verified, not assumed)

```
$ apt-get update   # real network access, confirmed working
$ apt-cache search pyarrow    # (no output)
$ apt-cache search duckdb     # (no output)
```

Debian trixie's own archive carries neither `python3-pyarrow` nor a `duckdb`/`python3-duckdb`
package. Writing either into `packaging/debian/control`'s `Depends:` line would be exactly the
"blindly write nonexistent Debian package names" failure mode this remediation was asked to avoid.

## Chosen model: vendored wheels + `pip install --target`

This project already has a working, production-proven precedent for exactly this situation:
`app/alderpointdns_compiler.py`'s `sync_vendored_python_deps()`, used today because Debian's
`python3-python-multipart` doesn't carry the pinned `0.0.31` version the app needs. This Blocker 3
fix extends the same pattern:

- `vendor/v2-analytics/*.whl` — real, pinned wheel files (`pyarrow==25.0.1`,
  `duckdb==1.5.5`, `cp313-manylinux_2_28_x86_64` — matching this host's actual Python 3.13 /
  glibc target), committed to the repo (same convention as the existing vendored
  `python_multipart` wheel).
- `app/v2/analytics_deps.py::provision_vendor_runtime()` — `pip install --no-index --find-links
  vendor/v2-analytics/ --target vendor-runtime-v2-analytics/ --no-deps pyarrow duckdb`. No network
  access needed at install time. Installs into a temp sibling directory first and only renames it
  into place on success, so a failed/partial pip run never leaves a half-installed state a later
  import could pick up.
- `app/v2/analytics_deps.py::ensure_on_path()` — called at the top of every lazy
  `import pyarrow`/`import duckdb` site in `app/v2/parquet_writer.py` and
  `app/v2/analytics_query.py`. A no-op if the packages are already importable (e.g. present in a
  dev venv's site-packages); only prepends the vendor-runtime directory to `sys.path` when needed.
- `scripts/provision-v2-analytics-vendor-runtime.sh` — the real operational entry point. **Not yet
  wired into `postinst`**, since `app/v2/*` is not deployed as part of the live appliance yet (see
  `docs/v2/architecture-map.md`) — this is the standalone step a future V2 deployment stage calls.

## Clean-runtime proof (§3B, real not simulated)

Verified directly against the real system `python3` (no `dev/.venv-v2-bench` involved):

```
$ rm -rf vendor-runtime-v2-analytics
$ python3 -c "from app.v2.analytics_deps import provision_vendor_runtime; provision_vendor_runtime()"
$ python3 -c "import pyarrow, duckdb; print(pyarrow.__version__, duckdb.__version__)"
25.0.1 1.5.5
```

Followed by a real Parquet write + Parquet read + DuckDB query + `AnalyticsService` detail-view
call, all via `python3` directly — see `tests/v2/test_analytics_deps.py`.

**Full `tests/v2/` suite result under the real system `python3`** (previously: 5 skipped due to
module-level `pytest.importorskip("pyarrow")` guards running before any per-test `ensure_on_path()`
call could fire — fixed by `tests/v2/conftest.py` calling `ensure_on_path()` at collection time):

```
610 passed in 83.38s
```

Zero pyarrow/duckdb-induced skips or failures, once `provision_vendor_runtime()` has been run once
(exactly the real install-time step a future postinst would perform).

## Degraded-state observability (§3C)

A missing/broken pyarrow or duckdb no longer looks like "legitimately zero records":

- `app/v2/parquet_writer.py`'s `WriterStats.dependency_unavailable` is set `True` specifically when
  a flush fails due to `ImportError` (distinct from an ordinary disk/permission write failure).
- `app/v2/analytics_query.py`'s `QueryResult` gained `degraded`/`degraded_reason` fields.
- `app/v2/analytics_service.py`'s detail-view methods (`recent_query_log`, `search`, `top_domains`,
  ...) all route through a wrapper that catches `ImportError` and returns
  `QueryResult(degraded=True, degraded_reason="...")` instead of letting the exception propagate or
  silently returning an empty-but-successful-looking result. `AnalyticsService.health()` exposes
  `app/v2/analytics_deps.py::check_health()` directly for a caller (an eventual admin health
  endpoint) to check proactively.
- DNS remains completely unaffected either way — none of this is on the DNS answer path (proven
  again in `tests/v2/test_failure_domain_live_runtime.py`, which already destroys the Parquet
  directory outright and confirms DNS keeps answering).
