#!/bin/sh
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

systemctl is-active --quiet bindguard || fail "bindguard service is not active"
systemctl is-enabled --quiet bindguard || fail "bindguard service is not enabled"
ss -ltnup | grep -Eq '(^|[[:space:]])(0[.]0[.]0[.]0|\*):3000' || fail "bindguard is not listening on 0.0.0.0:3000"
setup_response="$(curl --silent --show-error --include --max-time 5 http://127.0.0.1:3000/setup)"
printf '%s' "$setup_response" | grep -Eq 'Initial administrator setup|303 See Other' || fail "setup page missing or setup redirect invalid"
curl --silent --show-error --include --max-time 5 http://127.0.0.1:3000/ | grep -q '303 See Other' || fail "unauthenticated dashboard did not redirect"
runuser -u bindguard -- sudo -n /opt/bindguard/app/bindguard_compiler.py update-sources | grep -q 'active_domains=' || fail "bindguard sudo helper failed"
python3 -B - <<'PY' || fail "DNS Settings layout overflow checks failed"
import sys
from pathlib import Path

sys.path.insert(0, "/opt/bindguard")
from app.webapp import TEMPLATES  # noqa: E402

template = (Path("/opt/bindguard/web/templates/base.html").read_text() + "\n" + Path("/opt/bindguard/web/templates/dns_settings.html").read_text())
required_css = [
    "grid-template-columns: repeat(auto-fit, minmax(260px, 1fr))",
    "min-width: 0",
    "overflow: hidden",
    "overflow-wrap: anywhere",
    "word-break: break-word",
    "white-space: normal",
    "table-layout: fixed",
]
missing = [rule for rule in required_css if rule not in template]
if missing:
    raise SystemExit("missing CSS: " + ", ".join(missing))

context = {
    "request": {},
    "admin": "smoke",
    "setup_required": False,
    "allowed_clients": [
        "RFC1918 private networks",
        "loopback",
        "fc00::/7",
        "Allow all: Disabled",
    ],
    "backend": "127.0.0.1:5353 plain health/recovery, 127.0.0.1:5354 PROXYv2",
    "maintenance": "1.1.1.2, 1.0.0.2, 4.2.2.1, 4.2.2.2",
    "hostname": "bindguard.local",
    "doh_path": "/dns-query",
    "dnsdist_version": "dnsdist 2.0.0-alpha-really-long-version-string-for-layout-testing",
    "dnsdist_features": " ".join(["dns-over-https(nghttp2)-layout-long-token"] * 20),
    "protocols": [{"name": "Plain DNS", "port": "53/udp,tcp", "state": "listening", "tested": "acceptance-covered"}],
    "cert": {"state": "present", "detail": "/etc/bindguard/certs/bindguard-lab.crt"},
    "proxy_backend": "enabled",
    "client_address_test": {"state": "Passed", "filename": "test_dnsdist_frontend.sh"},
    "csrf": "smoke",
}
html = TEMPLATES.get_template("dns_settings.html").render(**context)
for expected in (
    "RFC1918 private networks",
    "loopback",
    "fc00::/7",
    "Allow all: Disabled",
    "Passed",
    "test_dnsdist_frontend.sh",
):
    if expected not in html:
        raise SystemExit(f"missing rendered content: {expected}")
if "/opt/bindguard/tests/test_dnsdist_frontend.sh" in html:
    raise SystemExit("client address test renders a raw path")
if 'class="mono">/dns-query<' not in html or 'class="mono">dnsdist 2.0.0-alpha' not in html:
    raise SystemExit("monospace styling missing from path/version values")

dashboard = TEMPLATES.get_template("dashboard.html").render(
    request={},
    admin="smoke",
    setup_required=False,
    csrf="smoke",
    bindguard="active",
    bind="active",
    dnsdist="active",
    enabled_sources=1,
    active_rules=42,
    deployment=None,
    sources=[],
    chart_json='[{"t":1,"total":1,"blocked":1}]',
    analytics={
        "range": "24h",
        "has_data": True,
        "buckets": [{"bucket_start": 1, "total_queries": 1, "blocked_queries": 1}],
        "totals": {"total_queries": 1, "blocked_queries": 1, "blocked_percent": 100.0, "avg_latency_ms": 1.2},
        "active_clients": 1,
        "top_clients": [{"label": "2001:db8:ffffffff:ffffffff:ffffffff:ffffffff:ffffffff:ffff", "value": 1}],
        "top_domains": [{"label": "extremely-long-subdomain-name-that-must-wrap.example.invalid", "value": 1}],
        "top_blocked": [],
        "qtypes": [{"label": "AAAA", "value": 1}],
        "rcodes": [{"label": "NOERROR", "value": 1}],
        "protocols": [{"label": "DoH3", "value": 1}],
        "recent": [],
    },
)
if "DNS query volume" not in dashboard or "queryChart" not in dashboard:
    raise SystemExit("dashboard analytics chart did not render")

query_log = TEMPLATES.get_template("query_log.html").render(
    request={},
    admin="smoke",
    setup_required=False,
    csrf="smoke",
    log={
        "rows": [],
        "total": 0,
        "page": 1,
        "limit": 50,
        "filters": {"search": "", "client": "", "domain": "", "qtype": "", "protocol": "", "blocked": "", "rcode": ""},
    },
)
if "No query events match" not in query_log or "Auto-refresh" not in query_log:
    raise SystemExit("query log empty state did not render")
PY

echo "web smoke tests passed"
