#!/bin/sh
set -eu

/opt/bindguard/tests/test_bind_backend.sh
/opt/bindguard/tests/test_dnsdist_frontend.sh
/opt/bindguard/tests/test_blocklist_deploy.sh
/opt/bindguard/tests/test_blocklist_failure_paths.sh
/opt/bindguard/tests/test_web_smoke.sh
/opt/bindguard/tests/test_backup_restore.sh

echo "BindGuard acceptance suite passed"
