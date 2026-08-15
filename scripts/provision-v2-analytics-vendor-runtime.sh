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
# Not yet wired into postinst: V2 (app/v2/*) is not deployed as part of
# the live appliance yet (see docs/v2/architecture-map.md). This script
# is the standalone entry point a future V2 deployment step calls; run it
# manually for now.
set -e
cd "$(dirname "$0")/.."
python3 -c "
from app.v2.analytics_deps import provision_vendor_runtime, check_health
result = provision_vendor_runtime()
if result.already_satisfied:
    print('V2 analytics vendor runtime already provisioned and importable.')
else:
    print('V2 analytics vendor runtime provisioned.')
health = check_health()
print(f'Health: pyarrow={health.pyarrow_available} duckdb={health.duckdb_available} degraded={health.degraded}')
if health.degraded:
    raise SystemExit(1)
"
