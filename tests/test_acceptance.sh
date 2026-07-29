#!/bin/sh
set -eu

/opt/bindguard/tests/test_bind_backend.sh
/opt/bindguard/tests/test_dnsdist_frontend.sh
/opt/bindguard/tests/test_blocklist_deploy.sh
/opt/bindguard/tests/test_blocklist_failure_paths.sh
/opt/bindguard/tests/test_analytics.py
/opt/bindguard/tests/test_local_dns.py
/opt/bindguard/tests/test_dns_cache.py
/opt/bindguard/tests/test_upstream_dns.py
/opt/bindguard/tests/test_dns_cache_benchmark.sh
/opt/bindguard/tests/test_encryption.py
/opt/bindguard/tests/test_importer.py
/opt/bindguard/tests/test_backup.py
/opt/bindguard/tests/test_replication.py
/opt/bindguard/tests/test_web_smoke.sh
/opt/bindguard/tests/test_service_restart_analytics.sh
/opt/bindguard/tests/test_backup_restore.sh

echo "BindGuard acceptance suite passed"
