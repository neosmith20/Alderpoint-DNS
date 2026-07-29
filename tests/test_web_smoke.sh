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
python3 -B - <<'PY' || fail "web interface layout and analytics checks failed"
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, "/opt/bindguard")
from app import webapp  # noqa: E402
from app.webapp import TEMPLATES  # noqa: E402

template = "\n".join(path.read_text() for path in Path("/opt/bindguard/web/templates").glob("*.html"))
css = Path("/opt/bindguard/web/static/app.css").read_text()
js = Path("/opt/bindguard/web/static/app.js").read_text()
required_css = [
    "grid-template-columns: repeat(auto-fit, minmax(260px, 1fr))",
    "min-width: 0",
    "overflow: hidden",
    "overflow-wrap: anywhere",
    "word-break: break-word",
    "white-space: normal",
    "table-layout: fixed",
    "--bg:",
    "--panel:",
    "--accent:",
    "--blocked:",
    "@media (max-width: 700px)",
    ".mobile-nav-toggle",
    ".status-badge",
]
missing = [rule for rule in required_css if rule not in template + css]
if missing:
    raise SystemExit("missing CSS: " + ", ".join(missing))
if "https://" in template + css + js or "http://" in css + js:
    raise SystemExit("runtime CDN or public asset reference found")
if "/static/app.css" not in template or "/static/app.js" not in template:
    raise SystemExit("local static assets are not referenced")
if "data-nav-toggle" not in template or "appNav" not in template:
    raise SystemExit("mobile navigation hooks are missing")
if "queryChart" not in template or 'data-chart="traffic"' not in template:
    raise SystemExit("dashboard chart hooks are missing")
if "analytics/chart-data" not in Path("/opt/bindguard/app/webapp.py").read_text():
    raise SystemExit("chart data endpoint is missing")
webapp_text = Path("/opt/bindguard/app/webapp.py").read_text()
for route in ("/local-dns", "local_dns_add_host", "local_dns_add_alias", "local_dns_import_preview"):
    if route not in webapp_text:
        raise SystemExit(f"local DNS route missing: {route}")
if "/query-log/partial" not in webapp_text or "query_log_context" not in webapp_text:
    raise SystemExit("query log partial refresh endpoint is missing")
if "bindguardAutoRefresh" not in js or "sessionStorage" not in js or "target.innerHTML" not in js:
    raise SystemExit("query log auto-refresh stateful partial update is missing")
if "setInterval(() => window.location.reload()" in js:
    raise SystemExit("query log auto-refresh still reloads the full page")
if "data-async-form" not in template or "BindGuardAsyncForm" not in js or "showToast" not in js or ".toast" not in css:
    raise SystemExit("Local DNS async form and toast behavior is missing")
local_dns_template = Path("/opt/bindguard/web/templates/local_dns.html").read_text()
for forbidden in (
    'data-confirm="Add this host',
    'data-confirm="Add this advanced record',
    'data-confirm="Edit this local DNS record',
    'data-confirm="Toggle this local DNS record',
):
    if forbidden in local_dns_template:
        raise SystemExit(f"routine Local DNS confirmation still present: {forbidden}")
if 'data-confirm="Delete this local DNS record' not in local_dns_template:
    raise SystemExit("destructive Local DNS delete confirmation is missing")
for expected in (
    'action="/local-dns/hosts" data-async-form',
    'action="/local-dns/records" data-async-form',
    'data-success-message="Local DNS record saved and deployed."',
):
    if expected not in local_dns_template:
        raise SystemExit(f"Local DNS async form hook missing: {expected}")
query_template = Path("/opt/bindguard/web/templates/query_log.html").read_text()
if "queryLogResults" not in query_template or 'data-refresh-url="/query-log/partial"' not in query_template:
    raise SystemExit("query log results refresh target is missing")

request = SimpleNamespace(url=SimpleNamespace(path="/"), query_params={})
base = {
    "request": request,
    "admin": "smoke",
    "setup_required": False,
    "csrf": "smoke",
    "protection": {"label": "Active", "tone": "healthy"},
}
context = {
    **base,
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

long_domain = "extremely-long-subdomain-name-that-must-wrap-without-horizontal-overflow.example.invalid"
long_client = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
long_upstream = "https://resolver.example.invalid/dns-query?very-long-upstream-url-for-layout-testing=1"
dashboard = TEMPLATES.get_template("dashboard.html").render(
    **base,
    bindguard="active",
    bind="active",
    dnsdist="active",
    collector="active",
    enabled_sources=1,
    active_rules=42,
    deployment=None,
    sources=[],
    chart_json='[{"t":1,"total":1,"blocked":1}]',
    category_breakdown=[{"label": "ads_trackers", "value": 1}, {"label": "adult_content", "value": 0}],
    system_health=[{"name": "BIND", "state": "Healthy", "tone": "healthy"}],
    last_refresh="2026-07-29T00:00:00Z",
    analytics={
        "range": "24h",
        "has_data": True,
        "buckets": [{"bucket_start": 1, "total_queries": 1, "blocked_queries": 1, "allowed_queries": 0, "latency_count": 1}],
        "totals": {"total_queries": 1, "blocked_queries": 1, "allowed_queries": 0, "blocked_percent": 100.0, "avg_latency_ms": 1.2},
        "active_clients": 1,
        "top_clients": [{"label": long_client, "value": 1}],
        "top_domains": [{"label": long_domain, "value": 1}],
        "top_blocked": [],
        "qtypes": [{"label": "AAAA", "value": 1}],
        "rcodes": [{"label": "NOERROR", "value": 1}],
        "protocols": [{"label": "DoH3", "value": 1}],
        "recent": [{"ts": "2026-07-29T00:00:00Z", "client": long_client, "domain": long_domain, "qtype": "AAAA", "protocol": "DoH3", "blocked": 1, "rcode": "NOERROR", "latency_ms": 1.2}],
    },
)
if "DNS Query Volume" not in dashboard or "queryChart" not in dashboard:
    raise SystemExit("dashboard analytics chart did not render")
for expected in ("Protection Active", "Disable protection", "Top Upstream Resolvers", "Average Upstream Latency", long_domain, long_client):
    if expected not in dashboard:
        raise SystemExit(f"dashboard missing {expected}")

query_log = TEMPLATES.get_template("query_log.html").render(
    **base,
    log={
        "rows": [],
        "total": 0,
        "page": 1,
        "limit": 50,
        "filters": {"search": "", "client": "", "domain": "", "qtype": "", "protocol": "", "blocked": "", "rcode": ""},
    },
)
if "No query events match" not in query_log or "Auto-refresh" not in query_log or "Reset" not in query_log:
    raise SystemExit("query log empty state did not render")

local_dns = TEMPLATES.get_template("local_dns.html").render(
    **base,
    settings={"internal_domain": "home.arpa", "default_ttl": "300", "server_hostname": "bindguard", "server_ip": "172.16.43.101"},
    records=[{
        "id": 1,
        "fqdn": "alex-pc." + long_domain,
        "record_type": "A",
        "value": "172.16.43.50",
        "ttl": 300,
        "comment": long_upstream,
        "enabled": 1,
        "ptr_record_id": 2,
    }, {
        "id": 2,
        "fqdn": "50.43.16.172.in-addr.arpa",
        "record_type": "PTR",
        "value": "alex-pc.home.arpa",
        "ttl": 300,
        "comment": "reverse",
        "enabled": 1,
        "ptr_record_id": None,
    }],
    aliases=[{"id": 1, "cidr": long_client + "/128", "display_name": "Alex-PC", "description": long_upstream}],
    deployment={"status": "deployed", "forward_zone": "home.arpa", "reverse_zones": 1, "serial": 2026072901, "message": "deployed", "validation_output": "zone home.arpa/IN: loaded serial 2026072901"},
    error=None,
    preview=[{"line": 2, "record": {"fqdn": "csv.home.arpa", "record_type": "A", "value": "172.16.43.70"}, "valid": True, "warnings": []}],
    hosts_preview=[{"line": 1, "valid": True, "records": [{"fqdn": "printer.home.arpa"}]}],
    csv_text="fqdn,record_type,value,ttl,enabled,comment\ncsv.home.arpa,A,172.16.43.70,300,1,imported\n",
    hosts_text="172.16.43.80 printer",
)
for expected in ("Local DNS", "home.arpa", "Add Host", "Advanced Record", "Automatically create reverse PTR record", "Client Aliases", "Import CSV and deploy", long_domain, long_client):
    if expected not in local_dns:
        raise SystemExit(f"local DNS page missing {expected}")

setup_html = TEMPLATES.get_template("setup.html").render(**{**base, "admin": None}, local_dns={"server_hostname": "bindguard", "server_ip": "172.16.43.101"})
for expected in ("Create BindGuard local DNS records", "172.16.43.101", "bindguard.home.arpa"):
    if expected not in setup_html:
        raise SystemExit(f"setup local DNS option missing {expected}")

for name, rendered in {
    "blocklists": TEMPLATES.get_template("blocklists.html").render(**base, sources=[{
        "id": 1,
        "name": "Long Source",
        "url": long_upstream,
        "category": "ads_trackers",
        "enabled": 1,
        "accepted_domains": 1,
        "invalid_rules": 0,
        "unsupported_rules": 0,
        "last_error": long_domain,
    }]),
    "custom_rules": TEMPLATES.get_template("custom_rules.html").render(**base, rules=[{
        "id": 1,
        "domain": long_domain,
        "action": "block",
        "enabled": 1,
        "comment": long_upstream,
    }]),
    "statistics": TEMPLATES.get_template("statistics_settings.html").render(**base, settings={
        "analytics_enabled": "1",
        "detailed_query_logging_enabled": "1",
        "privacy_mode": "full",
        "client_anonymization": "truncate",
        "detailed_retention_days": "7",
        "aggregate_retention_days": "90",
        "db_size_limit_bytes": "268435456",
        "collection_interval": "15",
        "recent_query_limit": "100",
    }, db_size=1234),
    "system": TEMPLATES.get_template("system.html").render(**base, health=[{"name": "Analytics collector", "state": "Healthy", "tone": "healthy"}], logs=long_upstream, compiler={"deployment": None}),
    "local_dns": local_dns,
}.items():
    if "app-topbar" not in rendered or "status-badge" not in rendered:
        raise SystemExit(f"{name} did not use the shared shell")

response = webapp.analytics_chart_data(SimpleNamespace(query_params={"range": "24h"}), None)
if response.status_code != 200 or b'"series"' not in response.body:
    raise SystemExit("chart data endpoint did not return JSON series")
PY

echo "web smoke tests passed"
