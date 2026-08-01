#!/bin/sh
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

systemctl is-active --quiet alderpointdns || fail "alderpointdns service is not active"
systemctl is-enabled --quiet alderpointdns || fail "alderpointdns service is not enabled"
ss -ltnup | grep -Eq '(^|[[:space:]])(0[.]0[.]0[.]0|\*):3000' || fail "alderpointdns is not listening on 0.0.0.0:3000"
setup_response="$(curl --silent --show-error --include --max-time 5 http://127.0.0.1:3000/setup)"
printf '%s' "$setup_response" | grep -Eq 'Initial administrator setup|303 See Other' || fail "setup page missing or setup redirect invalid"
curl --silent --show-error --include --max-time 5 http://127.0.0.1:3000/ | grep -q '303 See Other' || fail "unauthenticated dashboard did not redirect"
for protected_path in /query-log /custom-rules /blocklists /local-dns /dns-settings /dns-cache /encryption /import /backup /replication /statistics-settings /system /system/logs /status/summary
do
  curl --silent --show-error --include --max-time 5 "http://127.0.0.1:3000${protected_path}" | grep -q '303 See Other' || fail "unauthenticated ${protected_path} did not redirect"
done
runuser -u alderpointdns -- sudo -n /opt/alderpointdns/app/alderpointdns_compiler.py update-sources | grep -q 'active_domains=' || fail "alderpointdns sudo helper failed"
python3 -B - <<'PY' || fail "web interface layout and analytics checks failed"
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, "/opt/alderpointdns")
from app import importer, webapp  # noqa: E402
from app.webapp import TEMPLATES  # noqa: E402

template = "\n".join(path.read_text() for path in Path("/opt/alderpointdns/web/templates").glob("*.html"))
css = Path("/opt/alderpointdns/web/static/app.css").read_text()
js = Path("/opt/alderpointdns/web/static/app.js").read_text()
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
    "@media (max-width: 840px)",
    ".app-sidebar",
    ".app-mobilebar",
    ".app-mobilebar__status",
    ".mobile-nav-toggle",
    ".mobile-nav-backdrop",
    ".nav-section",
    ".nav-section__button",
    ".nav-section__panel",
    ".nav-subitem",
    ".status-badge",
    ".sidebar-collapse-toggle",
    "html.sidebar-collapsed",
    ".grid.health",
    ".grid.align-start",
    ".overflow-menu",
    ".category-badge",
    ".table-compact",
    "data-sidebar-collapse",
    "data-row-edit-toggle",
    "alderpointdnsSidebarCollapsed",
]
missing = [rule for rule in required_css if rule not in template + css + js]
if missing:
    raise SystemExit("missing CSS: " + ", ".join(missing))

# Regression guard: a status badge, heading, or card/panel head row must
# never be forced into character-level word wrapping again (this is what
# previously split "Healthy" -> "Heal"/"thy" and "DNSSEC" -> "DNSSE"/"C" on
# the Dashboard System Health cards). The old bug came from a blanket
# ".card *, .panel *" selector pulling in overflow-wrap:anywhere/word-break;
# guard against that shape reappearing rather than just checking today's
# rendered output.
if re.search(r"\.card\s*\*", css) or re.search(r"\.panel\s*\*", css):
    raise SystemExit("a blanket .card */.panel * selector would re-break word wrapping on status badges")
if "overflow-wrap: normal" not in css or "word-break: normal" not in css:
    raise SystemExit("status-badge/heading word-break protection rule is missing")
if "https://" in template + css + js or "http://" in css + js:
    raise SystemExit("runtime CDN or public asset reference found")
if "/static/app.css" not in template or "/static/app.js" not in template:
    raise SystemExit("local static assets are not referenced")
if "data-nav-toggle" not in template or "appNav" not in template or "data-primary-nav" not in template:
    raise SystemExit("mobile navigation hooks are missing")
for nav_hook in ('nav_section("dns"', 'nav_section("security"', 'nav_section("operations"', 'nav_section("system"'):
    if nav_hook not in template:
        raise SystemExit(f"grouped navigation hook missing: {nav_hook}")
for js_hook in ("document.addEventListener('keydown'", "event.key === 'Escape'", "closest('#appNav')", "matchMedia('(max-width: 840px)'", "setNavOpen", "data-nav-section-toggle", "aria-expanded", "panel.hidden", "js-global-service-status"):
    if js_hook not in js:
        raise SystemExit(f"keyboard/click navigation behavior missing: {js_hook}")
for js_hook in ("data-sidebar-collapse", "sidebar-collapsed", "alderpointdnsSidebarCollapsed", "data-row-edit-toggle", "data-overflow-trigger", "closeOverflowMenus"):
    if js_hook not in js:
        raise SystemExit(f"compact UI interaction behavior missing: {js_hook}")
if "localStorage.getItem('alderpointdnsSidebarCollapsed')" not in template:
    raise SystemExit("sidebar collapse anti-flash inline script is missing from base.html")

# -- reusable pending-action button state (disable, spinner, aria-busy,
# restore-on-failure, applied to every form submit) -------------------------
for js_hook in ("startPending", "stopPending", "pendingGerund", "submitterFor", "aria-busy", "data-pending-active", "pageshow"):
    if js_hook not in js:
        raise SystemExit(f"pending-action button behavior missing: {js_hook}")
if "button.disabled = true" not in js:
    raise SystemExit("pending-action button does not disable itself to prevent duplicate submission")
if ".btn-spinner" not in css or "@keyframes btn-spin" not in css:
    raise SystemExit("pending-action spinner CSS is missing")

# -- status-tile card layout (name centered on top, status badge centered
# below it, list-content cards excluded rather than blindly centered) -------
if ".card__head" not in css or "flex-direction: column" not in css:
    raise SystemExit("status-tile card (.card__head) centered layout is missing")
if ".card .stack" not in css:
    raise SystemExit("card list-content exclusion (.card .stack left-aligned) is missing")

# -- shared centered Actions-column table utility ----------------------------
if "actions-col" not in css:
    raise SystemExit("shared .actions-col table utility CSS is missing")
for tpl_file in ("local_dns.html", "blocklists.html", "custom_rules.html", "dns_settings.html", "backup.html", "replication.html"):
    text = (Path("/opt/alderpointdns/web/templates") / tpl_file).read_text()
    if "actions-col" not in text:
        raise SystemExit(f"{tpl_file} does not use the shared actions-col table utility")

# -- collapsed-sidebar logout: icon, accessible name, tooltip ---------------
if 'aria-label="Log out"' not in template or 'title="Log out"' not in template:
    raise SystemExit("collapsed-sidebar logout is missing an accessible name/tooltip")
if 'name == "logout"' not in template:
    raise SystemExit("logout nav icon is missing")

# -- collapsible nav sections with persisted expand/collapse state ----------
for js_hook in ("NAV_SECTION_KEY_PREFIX", "alderpointdnsNavSectionOpen", "window.localStorage.setItem(storageKey", "window.localStorage.getItem(storageKey"):
    if js_hook not in js:
        raise SystemExit(f"nav-section collapse persistence missing: {js_hook}")

if "queryChart" not in template or 'data-chart="traffic"' not in template:
    raise SystemExit("dashboard chart hooks are missing")
if "analytics/chart-data" not in Path("/opt/alderpointdns/app/webapp.py").read_text():
    raise SystemExit("chart data endpoint is missing")
webapp_text = Path("/opt/alderpointdns/app/webapp.py").read_text()
for status_hook in ("globalServiceStatus", "AlderpointDNSStatus", "data-status-label", "/status/summary"):
    if status_hook not in template + js + webapp_text:
        raise SystemExit(f"global service status hook missing: {status_hook}")
for route in ("/local-dns", "local_dns_add_host", "local_dns_add_alias", "local_dns_import_preview"):
    if route not in webapp_text:
        raise SystemExit(f"local DNS route missing: {route}")
if "/query-log/partial" not in webapp_text or "query_log_context" not in webapp_text:
    raise SystemExit("query log partial refresh endpoint is missing")
for route in ("/dns-cache", "dns_cache_settings_post", "/dns-cache/flush", "/dns-cache/flush-name", "/dns-cache/flush-tree"):
    if route not in webapp_text:
        raise SystemExit(f"cache route missing: {route}")
if 'href="/dns-cache"' not in template:
    raise SystemExit("cache nav link is missing")
for route in ("/dns-settings/upstreams/add", "/dns-settings/upstreams/{resolver_id}/edit", "/dns-settings/upstreams/{resolver_id}/toggle", "/dns-settings/upstreams/{resolver_id}/move", "/dns-settings/upstreams/{resolver_id}/delete"):
    if route not in webapp_text:
        raise SystemExit(f"upstream resolver route missing: {route}")
for route in ("/blocklists/categories/add", "/blocklists/categories/{key}/rename", "/blocklists/categories/{key}/merge", "/blocklists/categories/{key}/delete"):
    if route not in webapp_text:
        raise SystemExit(f"blocklist category route missing: {route}")
if "blocklist_categories" not in webapp_text:
    raise SystemExit("blocklists route does not use the managed category module")
for route in ("/system/logs", "fetch_service_log_entries", "service_logs.ALLOWED_UNITS"):
    if route not in webapp_text:
        raise SystemExit(f"system log-access route missing: {route}")
if "journalctl" in webapp_text:
    raise SystemExit("webapp.py calls journalctl directly instead of going through the scoped log-access helper")
for route in ("/encryption", "encryption_settings_post", "/encryption/certificate/self-signed", "/encryption/certificate/local-ca", "/encryption/certificate/upload", "/encryption/certificate/existing-path", "/encryption/certificate/download", "/encryption/apple/"):
    if route not in webapp_text:
        raise SystemExit(f"encryption route missing: {route}")
if 'href="/encryption"' not in template:
    raise SystemExit("encryption nav link is missing")
for route in ("/import", "/import/migration", "import_upload", "/import/jobs/{job_id}", "/import/jobs/{job_id}/status", "/import/jobs/{job_id}/preview", "/import/jobs/{job_id}/remap", "/import/jobs/{job_id}/apply", "/import/jobs/{job_id}/cancel", "/import/jobs/{job_id}/rollback", "/import/migration/adguard/yaml", "/import/migration/adguard/api"):
    if route not in webapp_text:
        raise SystemExit(f"import route missing: {route}")
if 'href="/import"' not in template:
    raise SystemExit("import nav link is missing")
import_migration_template = Path("/opt/alderpointdns/web/templates/import_migration.html").read_text()
if "Pi-hole Migration" not in import_migration_template or 'value="pihole"' not in import_migration_template:
    raise SystemExit("dedicated Pi-hole Migration panel is missing from Import and Migration")
for route in ('"/backup"', '"/backup/create"', '"/backup/import"', '"/backup/preview"', '"/backup/restore"', '"/backup/{identifier}/download"', '"/backup/{identifier}/delete"', '"/backup/schedule"'):
    if route not in webapp_text:
        raise SystemExit(f"backup route missing: {route}")
if 'href="/backup"' not in template:
    raise SystemExit("backup nav link is missing")
for route in ('"/replication"', '"/replication/role"', '"/replication/token"', '"/replication/connect"', '"/replication/sync-now"', '"/replication/drift-check"'):
    if route not in webapp_text:
        raise SystemExit(f"replication route missing: {route}")
if 'href="/replication"' not in template:
    raise SystemExit("replication nav link is missing")
if "alderpointdnsAutoRefresh" not in js or "sessionStorage" not in js or "target.innerHTML" not in js:
    raise SystemExit("query log auto-refresh stateful partial update is missing")
if "setInterval(() => window.location.reload()" in js:
    raise SystemExit("query log auto-refresh still reloads the full page")
if "data-async-form" not in template or "AlderpointDNSAsyncForm" not in js or "showToast" not in js or ".toast" not in css:
    raise SystemExit("Local DNS async form and toast behavior is missing")
local_dns_template = Path("/opt/alderpointdns/web/templates/local_dns.html").read_text()
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
query_template = Path("/opt/alderpointdns/web/templates/query_log.html").read_text()
if "queryLogResults" not in query_template or 'data-refresh-url="/query-log/partial"' not in query_template:
    raise SystemExit("query log results refresh target is missing")

request = SimpleNamespace(url=SimpleNamespace(path="/"), query_params={})
base = {
    "request": request,
    "admin": "smoke",
    "setup_required": False,
    "csrf": "smoke",
    "protection": {"label": "Active", "tone": "healthy"},
    "global_status": {"label": "Active", "tone": "healthy", "detail": "all core services active"},
}
def page_base(path):
    return {**base, "request": SimpleNamespace(url=SimpleNamespace(path=path), query_params={})}

long_domain = "extremely-long-subdomain-name-that-must-wrap-without-horizontal-overflow.example.invalid"
long_client = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
long_upstream = "https://resolver.example.invalid/dns-query?very-long-upstream-url-for-layout-testing=1"

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
    "hostname": "alderpointdns.local",
    "doh_path": "/dns-query",
    "dnsdist_version": "dnsdist 2.0.0-alpha-really-long-version-string-for-layout-testing",
    "dnsdist_features": " ".join(["dns-over-https(nghttp2)-layout-long-token"] * 20),
    "dnsdist_capabilities": {"doh": True, "dot": True, "doq": True, "doh3": True, "dnscrypt": True},
    "protocols": [
        {
            "name": "Plain DNS",
            "endpoint": "53/udp, 53/tcp",
            "port": "53/udp, 53/tcp",
            "build_support": "Available",
            "runtime_status": "Listening",
            "verification": "Automated checks included",
            "state": "listening",
            "tone": "healthy",
            "available": True,
            "enabled": True,
        },
    ],
    "cert": {"state": "present", "detail": "/etc/alderpointdns/certs/alderpointdns-lab.crt"},
    "proxy_backend": "enabled",
    "client_address_test": {"state": "Passed", "filename": "test_dnsdist_frontend.sh"},
    "upstream_resolvers": [{"id": 1, "name": "Cloudflare DoH", "protocol": "doh", "address": long_domain, "port": 443, "doh_path": "/dns-query", "tls_hostname": long_domain, "bootstrap_ips": "1.1.1.1, 1.0.0.1", "enabled": 1, "last_status": "healthy", "last_latency_ms": 4.2, "last_message": "resolved through active upstream set"}],
    "upstream_deployment": {"status": "deployed", "message": "deployed 1 enabled upstream resolver(s)"},
    "upstream_error": None,
}
html = TEMPLATES.get_template("dns_settings.html").render(**context)
for expected in (
    "RFC1918 private networks",
    "loopback",
    "fc00::/7",
    "Allow all: Disabled",
    "Passed",
    "test_dnsdist_frontend.sh",
    "Upstream Resolvers",
    "Cloudflare DoH",
    "DNS-over-HTTPS",
    "1.1.1.1, 1.0.0.1",
    "Add Upstream Resolver",
    'action="/dns-settings/upstreams/1/edit"',
    'action="/dns-settings/upstreams/add"',
    "overflow-menu",
    "Move up",
    "Move down",
    "overflow-menu__divider",
    "data-async-form",
):
    if expected not in html:
        raise SystemExit(f"missing rendered content: {expected}")
if "/opt/alderpointdns/tests/test_dnsdist_frontend.sh" in html:
    raise SystemExit("client address test renders a raw path")
if 'class="mono">/dns-query<' not in html or 'class="mono">dnsdist 2.0.0-alpha' not in html:
    raise SystemExit("monospace styling missing from path/version values")

dashboard = TEMPLATES.get_template("dashboard.html").render(
    **base,
    alderpointdns="active",
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
    cache_stats={"available": True, "hits": 100, "misses": 25, "hit_percent": 80.0, "nodes": 42, "memory_bytes": 1048576, "evicted_lru": 0, "expired_ttl": 3},
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
        "top_upstreams": [{
            "resolver_id": 1,
            "label": "Cloudflare DoH",
            "protocol": "DoH",
            "endpoint": "https://" + long_domain + ":443/dns-query",
            "enabled": 1,
            "health_state": "up",
            "value": 12,
            "successful_responses": 11,
            "failures": 1,
            "timeouts": 0,
            "latency_sum_ms": 55.0,
            "latency_count": 11,
            "recent_latency_ms": 4.7,
            "last_success_at": "2026-07-29T00:00:00Z",
            "last_failure_at": "2026-07-29T00:00:00Z",
            "avg_latency_ms": 5.0,
        }],
        "recent": [{"ts": "2026-07-29T00:00:00Z", "client": long_client, "domain": long_domain, "qtype": "AAAA", "protocol": "DoH3", "blocked": 1, "rcode": "NOERROR", "latency_ms": 1.2}],
    },
)
if "DNS Query Volume" not in dashboard or "queryChart" not in dashboard:
    raise SystemExit("dashboard analytics chart did not render")
for expected in ("Protection Active", "Disable protection", "Top Upstream Resolvers", "Cloudflare DoH", "11 ok", "1 failed", "Resolver attribution is based on dnsdist backend counters", "BIND Cache Effectiveness", "80.0", long_domain, long_client):
    if expected not in dashboard:
        raise SystemExit(f"dashboard missing {expected}")
for expected in (
    'class="nav-link nav-link--primary is-active" href="/" aria-current="page"',
    'id="globalServiceStatus"',
    'class="status-badge status-badge--healthy app-mobilebar__status js-global-service-status"',
    'data-status-url="/status/summary"',
    'data-nav-section="dns"',
    'data-nav-section="security"',
    'data-nav-section="operations"',
    'data-nav-section="system"',
    'data-nav-section-toggle',
    'aria-controls="nav-panel-dns"',
    '>Dashboard</span>',
    '>DNS</span>',
    '>Security</span>',
    '>Operations</span>',
    '>System</span>',
):
    if expected not in dashboard:
        raise SystemExit(f"grouped dashboard navigation missing {expected}")
for href in (
    'href="/"',
    'href="/query-log"',
    'href="/custom-rules"',
    'href="/blocklists"',
    'href="/local-dns"',
    'href="/dns-settings"',
    'href="/dns-cache"',
    'href="/encryption"',
    'href="/import"',
    'href="/backup"',
    'href="/replication"',
    'href="/statistics-settings"',
    'href="/system"',
):
    if href not in dashboard:
        raise SystemExit(f"navigation href missing: {href}")

query_log = TEMPLATES.get_template("query_log.html").render(
    **page_base("/query-log"),
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
if 'data-nav-section="dns"' not in query_log or 'aria-controls="nav-panel-dns" aria-expanded="true" aria-current="true"' not in query_log or 'class="nav-subitem is-active" href="/query-log" aria-current="page"' not in query_log:
    raise SystemExit("query log navigation does not mark the active DNS section and page")

local_dns = TEMPLATES.get_template("local_dns.html").render(
    **page_base("/local-dns"),
    settings={"internal_domain": "home.arpa", "default_ttl": "300", "server_hostname": "alderpointdns", "server_ip": "192.168.1.101"},
    records=[{
        "id": 1,
        "fqdn": "alex-pc." + long_domain,
        "record_type": "A",
        "value": "192.168.1.50",
        "ttl": 300,
        "comment": long_upstream,
        "enabled": 1,
        "ptr_record_id": 2,
    }, {
        "id": 2,
        "fqdn": "50.1.168.192.in-addr.arpa",
        "record_type": "PTR",
        "value": "alex-pc.home.arpa",
        "ttl": 300,
        "comment": "reverse for alex-pc." + long_domain,
        "enabled": 1,
        "ptr_record_id": None,
    }],
    aliases=[{"id": 1, "cidr": long_client + "/128", "display_name": "Alex-PC", "description": long_upstream}],
    deployment={"status": "deployed", "forward_zone": "home.arpa", "reverse_zones": 1, "serial": 2026072901, "message": "deployed", "validation_output": "zone home.arpa/IN: loaded serial 2026072901"},
    error=None,
    preview=[{"line": 2, "record": {"fqdn": "csv.home.arpa", "record_type": "A", "value": "192.168.1.70"}, "valid": True, "warnings": []}],
    hosts_preview=[{"line": 1, "valid": True, "records": [{"fqdn": "printer.home.arpa"}]}],
    csv_text="fqdn,record_type,value,ttl,enabled,comment\ncsv.home.arpa,A,192.168.1.70,300,1,imported\n",
    hosts_text="192.168.1.80 printer",
)
for expected in ("Local DNS", "home.arpa", "Add Host", "Advanced Record", "Automatically create reverse PTR record", "Client Aliases", "Import CSV and deploy", long_domain, long_client, "table-compact", "editRow1", "data-row-edit-toggle", "reverse of"):
    if expected not in local_dns:
        raise SystemExit(f"local DNS page missing {expected}")

dns_cache_html = TEMPLATES.get_template("dns_cache.html").render(
    **page_base("/dns-cache"),
    error=None,
    cache={
        "max_cache_size_mb": "490", "min_cache_ttl": "0", "max_cache_ttl": "604800",
        "min_ncache_ttl": "0", "max_ncache_ttl": "10800", "prefetch_enabled": "0",
        "prefetch_trigger": "2", "prefetch_eligible": "10", "serve_stale_enabled": "0",
        "max_stale_ttl": "86400", "stale_answer_client_timeout": "off",
        "recursive_clients": "1000",
    },
    stats={"available": True, "hits": 1683, "misses": 669, "hit_percent": 71.5, "nodes": 162, "memory_bytes": 196419, "evicted_lru": 0, "expired_ttl": 39},
    deployment={"status": "deployed", "started_at": "2026-07-29T00:00:00Z", "finished_at": "2026-07-29T00:00:00Z", "message": "max-cache-size=490m prefetch=0 serve-stale=0"},
    flushes=[{"requested_at": "2026-07-29T00:00:00Z", "scope": "name", "target": long_domain, "status": "completed"}],
    total_memory_mb=3891,
)
for expected in ("Cache Tuning", "Flush Cache", "Refresh statistics", "Recursive clients", "71.5", "max-cache-size=490m", long_domain, "data-async-form"):
    if expected not in dns_cache_html:
        raise SystemExit(f"cache page missing {expected}")

encryption_html = TEMPLATES.get_template("encryption.html").render(
    **page_base("/encryption"),
    error=None,
    cfg={
        "server_hostname": "alderpointdns.local", "bootstrap_ip": "192.168.1.101",
        "listen_ipv4": "0.0.0.0", "listen_ipv6": "::",
        "doh_enabled": "1", "doh3_enabled": "1", "dot_enabled": "1", "doq_enabled": "1", "dnscrypt_enabled": "0",
        "doh_path": "/dns-query", "doh_port": "443", "doh3_port": "443", "dot_port": "853", "doq_port": "853",
        "dnscrypt_port": "5443", "dnscrypt_provider": "2.dnscrypt-cert.alderpointdns.local",
        "cert_mode": "self_signed", "cert_path": "/etc/alderpointdns/certs/alderpointdns-lab.crt", "key_path": "/etc/alderpointdns/certs/alderpointdns-lab.key",
    },
    cert={
        "available": True, "subject": "CN=" + long_domain, "issuer": "CN=" + long_domain,
        "not_before": "Jul 29 00:00:00 2026 GMT", "not_after": "Oct 31 00:00:00 2028 GMT",
        "days_remaining": 824, "expiring_soon": False, "expired": False,
        "fingerprint_sha256": "AA:BB:CC:DD", "sans": ["DNS:" + long_domain, "IP Address:192.168.1.101"], "self_signed": True,
    },
    deployment={"status": "deployed", "started_at": "2026-07-29T00:00:00Z", "finished_at": "2026-07-29T00:00:00Z", "message": "deployed with protocols: {'plain': 'ok'}", "protocol_tests": "{'plain': 'ok'}"},
    connection_info={"DoH": "https://" + long_domain + "/dns-query", "DoT": "tls://alderpointdns.local:853"},
    dnscrypt_fingerprint=None,
    capabilities={"doh": True, "dot": True, "doh3": True, "doq": True, "dnscrypt": True},
)
for expected in ("Protocols", "Listen IPv4", "Listen IPv6", "0.0.0.0", "Client Connection Information", "Self-signed certificate", "Upload certificate and key", long_domain, "data-async-form"):
    if expected not in encryption_html:
        raise SystemExit(f"encryption page missing {expected}")
if 'data-nav-section="security"' not in encryption_html or 'aria-controls="nav-panel-security" aria-expanded="true" aria-current="true"' not in encryption_html or 'class="nav-subitem is-active" href="/encryption" aria-current="page"' not in encryption_html:
    raise SystemExit("encryption navigation does not mark the active Security section and page")

import_base_html = TEMPLATES.get_template("import_migration.html").render(**page_base("/import"), error=None, jobs=[{"id": 1, "created_at": "2026-07-29T00:00:00Z", "source_type": "csv", "source_name": long_domain, "status": "applied", "valid_rows": 3, "applied_rows": 3}], job=None, preview=None, adguard=None)
for expected in ("Spreadsheet / Text Import", "AdGuard Home Migration", "Column Mapping Reference", long_domain):
    if expected not in import_base_html:
        raise SystemExit(f"import page missing {expected}")
if 'data-nav-section="operations"' not in import_base_html or 'aria-controls="nav-panel-operations" aria-expanded="true" aria-current="true"' not in import_base_html or 'class="nav-subitem is-active" href="/import" aria-current="page"' not in import_base_html:
    raise SystemExit("import navigation does not mark the active Operations section and page")

import_job_html = TEMPLATES.get_template("import_migration.html").render(
    **base, error=None, jobs=[],
    job={"id": 1, "source_type": "csv", "source_name": long_domain, "status": "previewed", "message": "", "report_json": "{}"},
    headers=["Hostname", "IP"], column_map={"hostname": "Hostname", "ipv4": "IP"}, canonical_fields=importer.CANONICAL_FIELDS,
    preview={
        "valid": [{"index": 0, "fqdn": "a." + long_domain, "record_type": "A", "value": "192.168.1.10"}],
        "invalid": [{"index": 1, "error": "bad row"}],
        "duplicates": [],
        "conflicts": [{"index": 2, "fqdn": "b." + long_domain, "record_type": "A", "value": "192.168.1.11", "warnings": ["A hostname already exists."]}],
    },
    adguard=None,
)
for expected in ("Import Job #", "Conflicts", "data-async-form", long_domain):
    if expected not in import_job_html:
        raise SystemExit(f"import job page missing {expected}")

import_adguard_translation = {
    "blocklist_sources": [{"name": "EasyList", "url": long_upstream, "enabled": True, "category": "ads_trackers"}],
    "allowlist_unsupported": [{"name": "Allow", "url": long_upstream, "note": "n/a"}],
    "custom_rules": [
        {"text": "||" + long_domain + "^", "rule": "||" + long_domain + "^", "plain_domain_subdomains": True, "origin": "user_rules", "comment": ""},
    ],
    "custom_allow": [], "custom_block": [],
    "unsupported_rules": [],
    "rewrites_as_local_dns": [{"fqdn": long_domain, "record_type": "A", "value": "192.168.1.12", "ttl": 300, "origin": "dns_rewrites"}],
    "clients_as_aliases": [{"display_name": "Phone", "cidr_or_ip": "192.168.1.77", "all_ids": []}],
    "client_scoped": ["Phone: filtering_enabled has no Alderpoint DNS per-client equivalent yet (schema exists, not enforced at runtime)"],
    "upstream_resolvers": [{"name": "Imported upstream", "protocol": "plain", "address": "9.9.9.9", "port": 53}],
    "untranslatable": ["filtering.safe_search: SafeSearch enforcement is not implemented in Alderpoint DNS"],
}
import_adguard_summary = importer.summarize_migration(import_adguard_translation, "home.arpa")
import_adguard_html = TEMPLATES.get_template("import_migration.html").render(
    **base, error=None, jobs=[], job=None, preview=None,
    adguard=import_adguard_translation,
    migration_summary=import_adguard_summary,
    migration_title="AdGuard Home Migration Preview",
    migration_job_id=1,
    source_path="/var/lib/alderpointdns/imports/AdGuardHome.yaml",
)
for expected in ("AdGuard Home Migration Preview", "Client-scoped items", "Upstream resolvers", "Will import", long_upstream):
    if expected not in import_adguard_html:
        raise SystemExit(f"import adguard preview page missing {expected}")

backup_html = TEMPLATES.get_template("backup.html").render(
    **base, error=None, imported=None, preview_source=None,
    component_keys=["app_config", "sqlite_data", "custom_rules", "private_keys"],
    component_defaults={"app_config": True, "sqlite_data": True, "custom_rules": True, "private_keys": False},
    last_backup={"created_at": "2026-07-29T00:00:00Z", "size_bytes": 1048576, "status": "deployed"},
    last_restore={"started_at": "2026-07-29T00:00:00Z", "finished_at": "2026-07-29T00:00:00Z", "status": "deployed"},
    backup_settings={"schedule_enabled": "1", "schedule_interval_hours": "24", "retention_count": "7"},
    backups=[{"id": 1, "created_at": "2026-07-29T00:00:00Z", "size_bytes": 2097152, "components_summary": long_upstream, "status": "deployed", "path": "alderpointdns-backup-x.tar.gz"}],
    preview={
        "compatible": True, "warnings": [],
        "manifest": {"source_node_id": "alderpointdns-1", "created_at": "2026-07-29T00:00:00Z", "alderpointdns_app_version": "unreleased+git.abc", "database_schema_version": "abc123"},
        "included_components": ["app_config", "sqlite_data"],
        "table_diffs": [{"table": "custom_rules", "component": "custom_rules", "live_rows": 3, "backup_rows": 2}],
        "file_diffs": [{"path": long_domain, "diff": "modified"}],
        "unchanged_file_count": 5,
    },
)
for expected in ("Create Backup", "Preview a Restore", "Restore Preview", "Scheduled Backups", "private_keys", long_upstream, long_domain, "data-async-form"):
    if expected not in backup_html:
        raise SystemExit(f"backup page missing {expected}")

setup_html = TEMPLATES.get_template("setup.html").render(**{**base, "admin": None}, local_dns={"server_hostname": "alderpointdns", "server_ip": "192.168.1.101"})
for expected in ("Create Alderpoint DNS local DNS records", "192.168.1.101", "alderpointdns.home.arpa"):
    if expected not in setup_html:
        raise SystemExit(f"setup local DNS option missing {expected}")
login_html = TEMPLATES.get_template("login.html").render(**{**base, "admin": None}, error=None)
for public_html, name in ((setup_html, "setup"), (login_html, "login")):
    if "app-nav" in public_html or "data-nav-section" in public_html:
        raise SystemExit(f"{name} page renders protected navigation while logged out")

filter_schedule_fixture = {
    "options": (
        ("disabled", "Disabled \u2014 No Updates"),
        ("1", "1 Hour"),
        ("12", "12 Hours"),
        ("24", "1 Day"),
        ("72", "3 Days"),
        ("168", "1 Week"),
    ),
    "interval": "24",
    "interval_label": "1 Day",
    "enabled": True,
    "last_attempt": "2026-07-29T00:00:00+00:00",
    "last_success": "2026-07-29T00:00:00+00:00",
    "last_result": {"status": "deployed", "active_domains": 1, "error": ""},
    "next_run": "Thu 2026-07-30 00:00:00 UTC",
}
blocklist_categories_fixture = [
    {"key": "uncategorized", "name": "Uncategorized", "description": "", "source_count": 0},
    {"key": "ads_trackers", "name": "Ads and trackers", "description": "", "source_count": 1},
    {"key": "malware", "name": "Malware", "description": "", "source_count": 0},
]
blocklists_html = TEMPLATES.get_template("blocklists.html").render(**base, sources=[{
    "id": 1,
    "name": "Long Source",
    "url": long_upstream,
    "category": "ads_trackers",
    "enabled": 1,
    "accepted_domains": 1,
    "parsed_rules": 1,
    "unique_active_domains": 1,
    "duplicate_domains": 0,
    "invalid_rules": 0,
    "unsupported_rules": 0,
    "downloaded_entries": 1,
    "using_cached_copy": 0,
    "last_error": long_domain,
    "last_warning": "",
    "last_attempt": "2026-07-29T00:00:00Z",
    "last_success": "2026-07-29T00:00:00Z",
    "last_compile_success": "2026-07-29T00:00:00Z",
    "health": {"state": "error", "label": "Error", "tone": "down"},
    "rejected_samples_parsed": [{"line": 3, "kind": "invalid", "reason": long_domain, "excerpt": long_domain}],
}], categories=blocklist_categories_fixture, category_error=None, category_filter="", status_filter="", search="", sort="name",
    filter_schedule=filter_schedule_fixture)
for expected in ("Manage Categories", "Ads and trackers", "table-compact", "blocklistEdit1", "category-badge", "overflow-menu", long_upstream, long_domain):
    if expected not in blocklists_html:
        raise SystemExit(f"blocklists page missing {expected}")
for expected in ("Automatic Updates", "Filter Update Interval", "1 Day", "Next scheduled update", "Update All Now", 'action="/blocklists/schedule"'):
    if expected not in blocklists_html:
        raise SystemExit(f"blocklists automatic update panel missing {expected}")
blocklists_disabled_html = TEMPLATES.get_template("blocklists.html").render(
    **base, sources=[], categories=blocklist_categories_fixture, category_error=None,
    category_filter="", status_filter="", search="", sort="name",
    filter_schedule={**filter_schedule_fixture, "interval": "disabled", "interval_label": "Disabled \u2014 No Updates", "enabled": False, "next_run": None},
)
if "Automatic updates disabled" not in blocklists_disabled_html:
    raise SystemExit("blocklists page does not report a disabled automatic update schedule")
if "Thu 2026-07-30 00:00:00 UTC" in blocklists_disabled_html:
    raise SystemExit("blocklists page shows a next automatic update time while updates are disabled")
if 'action="/blocklists/update"' not in blocklists_disabled_html:
    raise SystemExit("manual update-all action is gated by the automatic update schedule")

system_logs_fixture = {
    "available": True, "error": None, "service": "alderpointdns", "severity": "all", "lines": 100,
    "entries": [{"ts": "2026-07-29T00:00:00Z", "priority": 6, "severity": "info", "message": long_upstream}],
}
system_html = TEMPLATES.get_template("system.html").render(**base, health=[{"name": "Analytics collector", "state": "Healthy", "tone": "healthy"}], logs=system_logs_fixture, compiler={"deployment": None})
for expected in ("Recent Logs", "systemLogsResults", 'data-refresh-url="/system/logs"', "Severity", long_upstream):
    if expected not in system_html:
        raise SystemExit(f"system page missing {expected}")
if "journalctl" in system_html.lower():
    raise SystemExit("system page still exposes raw journalctl command-line details")

system_logs_error_html = TEMPLATES.get_template("system.html").render(
    **base, health=[], compiler={"deployment": None},
    logs={"available": False, "error": "log access is not available right now", "service": "named", "severity": "all", "lines": 100, "entries": []},
)
if "Logs unavailable for named" not in system_logs_error_html:
    raise SystemExit("system page does not show a friendly empty state when logs are unavailable")
if "journalctl" in system_logs_error_html.lower() or "insufficient permissions" in system_logs_error_html.lower():
    raise SystemExit("system page leaks raw journalctl error text instead of a friendly message")

for name, rendered in {
    "blocklists": blocklists_html,
    "custom_rules": TEMPLATES.get_template("custom_rules.html").render(**base, rules=[{
        "id": 1,
        "rule_text": "||" + long_domain + "^",
        "normalized": "||" + long_domain + "^",
        "rule_type": "block",
        "action": "block",
        "domain": long_domain,
        "match_subdomains": 1,
        "pattern": None,
        "rewrite_address": None,
        "address_family": None,
        "qtype_restriction": None,
        "priority": 0,
        "enabled": 1,
        "validation_state": "valid",
        "unsupported_reason": "",
        "source_system": "manual",
        "import_job_id": None,
        "comment": long_upstream,
        "created_at": "2026-07-30T00:00:00+00:00",
        "updated_at": "2026-07-30T00:00:00+00:00",
    }], counts={
        "total": 1, "active": 1, "disabled": 0, "allow": 0, "block": 1,
        "rewrite": 0, "regex": 0, "comment": 0, "unsupported": 0, "invalid": 0,
    }, search="", type_filter="", status_filter="", error=None, notice=None,
    bulk_results=None, test_result=None, test_domain=""),
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
    "system": system_html,
    "local_dns": local_dns,
    "dns_cache": dns_cache_html,
    "encryption": encryption_html,
    "import_base": import_base_html,
    "import_job": import_job_html,
    "import_adguard": import_adguard_html,
    "backup": backup_html,
}.items():
    if "app-shell" not in rendered or "app-sidebar" not in rendered or "globalServiceStatus" not in rendered or "data-status-label" not in rendered:
        raise SystemExit(f"{name} did not use the shared shell")

with mock.patch.object(webapp, "service_state", side_effect=lambda name: "active"):
    healthy = webapp.global_service_status()
if healthy["label"] != "Active" or healthy["tone"] != "healthy":
    raise SystemExit("global status healthy state is wrong")
with mock.patch.object(webapp, "service_state", side_effect=lambda name: "inactive" if name == "named" else "active"):
    inactive = webapp.global_service_status()
if inactive["label"] != "Inactive" or inactive["tone"] != "down":
    raise SystemExit("global status inactive state is wrong")
with mock.patch.object(webapp, "service_state", side_effect=lambda name: "inactive" if name == "alderpointdns-analytics" else "active"):
    degraded = webapp.global_service_status()
if degraded["label"] != "Degraded" or degraded["tone"] != "degraded":
    raise SystemExit("global status degraded state is wrong")
with mock.patch.object(webapp, "service_state", side_effect=RuntimeError("boom")):
    unknown = webapp.global_service_status()
if unknown["label"] != "Unknown" or unknown["tone"] != "unavailable":
    raise SystemExit("global status unknown state is wrong")
with mock.patch.dict(webapp.os.environ, {"ALDERPOINTDNS_COOKIE_SECURE": "1"}):
    if not webapp.secure_session_cookie_enabled():
        raise SystemExit("secure session cookie env toggle did not enable")
with mock.patch.dict(webapp.os.environ, {"ALDERPOINTDNS_COOKIE_SECURE": "0"}):
    if webapp.secure_session_cookie_enabled():
        raise SystemExit("secure session cookie env toggle did not disable")

response = webapp.analytics_chart_data(SimpleNamespace(query_params={"range": "24h"}), None)
if response.status_code != 200 or b'"series"' not in response.body:
    raise SystemExit("chart data endpoint did not return JSON series")
PY

echo "web smoke tests passed"
