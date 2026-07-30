#!/bin/sh
set -eu

/opt/alderpointdns/tests/test_bind_backend.sh
/opt/alderpointdns/tests/test_dnsdist_frontend.sh
/opt/alderpointdns/tests/test_blocklist_deploy.sh
/opt/alderpointdns/tests/test_blocklist_failure_paths.sh
/opt/alderpointdns/tests/test_analytics.py
/opt/alderpointdns/tests/test_local_dns.py
/opt/alderpointdns/tests/test_dns_cache.py
/opt/alderpointdns/tests/test_upstream_dns.py
/opt/alderpointdns/tests/test_dns_cache_benchmark.sh
/opt/alderpointdns/tests/test_encryption.py
/opt/alderpointdns/tests/test_importer.py
/opt/alderpointdns/tests/test_backup.py
/opt/alderpointdns/tests/test_replication.py
/opt/alderpointdns/tests/test_install_upgrade_diagnostics.sh
/opt/alderpointdns/tests/test_beta_hardening_docs.sh
/opt/alderpointdns/tests/test_web_smoke.sh
/opt/alderpointdns/tests/test_encryption_layout.sh
/opt/alderpointdns/tests/test_service_restart_analytics.sh
/opt/alderpointdns/tests/test_backup_restore.sh

echo "Alderpoint DNS acceptance suite passed"
