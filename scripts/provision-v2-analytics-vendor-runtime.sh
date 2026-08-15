#!/bin/sh
# Provisions the V2 analytics runtime dependencies (pyarrow, duckdb) from
# vendored wheels under vendor/v2-analytics/ into vendor-runtime-v2-analytics/,
# mirroring the existing python-multipart vendoring mechanism
# (app/alderpointdns_compiler.py's sync_vendored_python_deps()).
#
# Real production dependency model (Gate #2 Blocker 3): Debian's own
# archive carries neither a pyarrow nor a duckdb package for this target
# (verified against the actual configured apt sources, not assumed), so
# this is the supported install path -- no network access needed at
# install/deploy time, never touches dpkg-managed site-packages.
#
# This is the exact entry point a future V2 postinst `configure` step
# calls (P0-C, Gate #2 residual): failure here is fatal and must abort the
# calling install/upgrade, exactly like the existing V1 postinst's
# `vendor-deps-sync`/`dnsdist-conf-migrate` gates -- never silently
# continue and let the analytics subsystem come up degraded without an
# operator being told. NOT yet invoked from packaging/debian/postinst
# itself: V2 (app/v2/*) is not deployed as part of the live appliance yet
# (see docs/v2/architecture-map.md and docs/v2/handoff-workstream-4.md,
# "Priority 1" -- the V2 package/service lifecycle this script plugs into
# does not exist as an installable unit yet). Deliberately does NOT touch
# packaging/debian/postinst (the live V1 install path) to avoid changing
# V1 behavior; wiring happens once Priority 1's dedicated V2 install
# lifecycle exists.
#
# Optional overrides (for testing / an alternate install root), matching
# app/v2/analytics_deps.py's provision_vendor_runtime() parameters:
#   ALDERPOINTDNS_V2_ANALYTICS_VENDOR_DIR   (default: vendor/v2-analytics)
#   ALDERPOINTDNS_V2_ANALYTICS_TARGET_DIR   (default: vendor-runtime-v2-analytics)
set -e
cd "$(dirname "$0")/.."
python3 -c "
import os
from pathlib import Path
from app.v2.analytics_deps import (
    VENDOR_DIR, VENDOR_RUNTIME_DIR, provision_vendor_runtime, check_health,
)

vendor_dir = Path(os.environ.get('ALDERPOINTDNS_V2_ANALYTICS_VENDOR_DIR') or VENDOR_DIR)
target_dir = Path(os.environ.get('ALDERPOINTDNS_V2_ANALYTICS_TARGET_DIR') or VENDOR_RUNTIME_DIR)

result = provision_vendor_runtime(vendor_dir=vendor_dir, target_dir=target_dir)
if result.already_satisfied:
    print('V2 analytics vendor runtime already provisioned and importable.')
else:
    print('V2 analytics vendor runtime provisioned.')
health = check_health(target_dir=target_dir)
print(f'Health: pyarrow={health.pyarrow_available} duckdb={health.duckdb_available} degraded={health.degraded}')
if health.degraded:
    raise SystemExit(1)
"
