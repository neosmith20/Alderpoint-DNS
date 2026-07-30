#!/bin/sh
set -eu

required_docs="
docs/beta-readiness.md
docs/versioning.md
docs/release-notes.md
docs/known-limitations.md
docs/supported-systems.md
docs/hardware-requirements.md
docs/install.md
docs/upgrade.md
docs/backup-recovery.md
docs/migration.md
docs/security.md
docs/troubleshooting.md
docs/beta-feedback-template.md
docs/bug-report-template.md
docs/feature-request-template.md
docs/hardening-review.md
docs/diagnostics.md
"

for doc in $required_docs; do
  test -s "/opt/alderpointdns/$doc" || {
    echo "missing required beta document: $doc" >&2
    exit 1
  }
done

grep -q "Full reboot test after the final beta commit" /opt/alderpointdns/docs/beta-readiness.md || {
  echo "beta readiness checklist missing reboot item" >&2
  exit 1
}
grep -q "ALDERPOINTDNS_COOKIE_SECURE=1" /opt/alderpointdns/docs/security.md /opt/alderpointdns/docs/hardening-review.md || {
  echo "secure-cookie deployment guidance missing" >&2
  exit 1
}
grep -q "Diagnostics bundle attached" /opt/alderpointdns/docs/beta-feedback-template.md || {
  echo "beta feedback template missing diagnostics prompt" >&2
  exit 1
}
grep -q "apt purge" /opt/alderpointdns/docs/packaging.md || {
  echo "packaging docs missing purge behavior" >&2
  exit 1
}

grep -q 'allow-recursion { "alderpointdns_clients"; };' /opt/alderpointdns/packaging/named.conf.options || {
  echo "packaged BIND config does not restrict recursion to alderpointdns_clients" >&2
  exit 1
}
grep -q 'allow-query-cache { "alderpointdns_clients"; };' /opt/alderpointdns/packaging/named.conf.options || {
  echo "packaged BIND config does not restrict cache queries" >&2
  exit 1
}
grep -q 'ALDERPOINTDNS_DNS_ALLOW_ALL' /opt/alderpointdns/packaging/dnsdist.conf || {
  echo "packaged dnsdist config missing explicit allow-all environment guard" >&2
  exit 1
}
grep -q '"10.0.0.0/8"' /opt/alderpointdns/packaging/dnsdist.conf || {
  echo "packaged dnsdist config missing private-network ACL defaults" >&2
  exit 1
}
if grep -Eq 'setACL\(\{"0[.]0[.]0[.]0/0", "::/0"\}\)' /opt/alderpointdns/packaging/dnsdist.conf &&
   ! grep -q 'allowAll = os.getenv("ALDERPOINTDNS_DNS_ALLOW_ALL") == "1"' /opt/alderpointdns/packaging/dnsdist.conf; then
  echo "packaged dnsdist allow-all ACL is not environment guarded" >&2
  exit 1
fi

/opt/alderpointdns/scripts/alderpointdns-diagnostics --self-test-redaction >/tmp/alderpointdns-hardening-redaction.out
if grep -Eq 'hunter2|BEGIN PRIVATE KEY|secret&client' /tmp/alderpointdns-hardening-redaction.out; then
  echo "diagnostics redaction self-test leaked sensitive text" >&2
  exit 1
fi

python3 -B - <<'PY'
import sys
from unittest import mock
sys.path.insert(0, "/opt/alderpointdns")
from app import webapp
with mock.patch.dict(webapp.os.environ, {"ALDERPOINTDNS_COOKIE_SECURE": "1"}):
    assert webapp.secure_session_cookie_enabled()
with mock.patch.dict(webapp.os.environ, {"ALDERPOINTDNS_COOKIE_SECURE": "0"}):
    assert not webapp.secure_session_cookie_enabled()
PY

echo "beta hardening documentation tests passed"
