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
from app import importer, webapp  # noqa: E402
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
for route in ("/dns-cache", "dns_cache_settings_post", "/dns-cache/flush", "/dns-cache/flush-name", "/dns-cache/flush-tree"):
    if route not in webapp_text:
        raise SystemExit(f"cache route missing: {route}")
if 'href="/dns-cache"' not in template:
    raise SystemExit("cache nav link is missing")
for route in ("/encryption", "encryption_settings_post", "/encryption/certificate/self-signed", "/encryption/certificate/local-ca", "/encryption/certificate/upload", "/encryption/certificate/existing-path", "/encryption/certificate/download", "/encryption/apple/"):
    if route not in webapp_text:
        raise SystemExit(f"encryption route missing: {route}")
if 'href="/encryption"' not in template:
    raise SystemExit("encryption nav link is missing")
for route in ("/import", "import_upload", "/import/{job_id}", "/import/{job_id}/remap", "/import/{job_id}/apply", "/import/{job_id}/rollback", "/import/adguard/yaml", "/import/adguard/api", "/import/adguard/apply"):
    if route not in webapp_text:
        raise SystemExit(f"import route missing: {route}")
if 'href="/import"' not in template:
    raise SystemExit("import nav link is missing")
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
        "recent": [{"ts": "2026-07-29T00:00:00Z", "client": long_client, "domain": long_domain, "qtype": "AAAA", "protocol": "DoH3", "blocked": 1, "rcode": "NOERROR", "latency_ms": 1.2}],
    },
)
if "DNS Query Volume" not in dashboard or "queryChart" not in dashboard:
    raise SystemExit("dashboard analytics chart did not render")
for expected in ("Protection Active", "Disable protection", "Top Upstream Resolvers", "BIND Cache Effectiveness", "80.0", long_domain, long_client):
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

dns_cache_html = TEMPLATES.get_template("dns_cache.html").render(
    **base,
    error=None,
    cache={
        "max_cache_size_mb": "490", "min_cache_ttl": "0", "max_cache_ttl": "604800",
        "min_ncache_ttl": "0", "max_ncache_ttl": "10800", "prefetch_enabled": "0",
        "prefetch_trigger": "2", "prefetch_eligible": "10", "serve_stale_enabled": "0",
        "max_stale_ttl": "86400", "stale_answer_client_timeout": "off",
    },
    stats={"available": True, "hits": 1683, "misses": 669, "hit_percent": 71.5, "nodes": 162, "memory_bytes": 196419, "evicted_lru": 0, "expired_ttl": 39},
    deployment={"status": "deployed", "started_at": "2026-07-29T00:00:00Z", "finished_at": "2026-07-29T00:00:00Z", "message": "max-cache-size=490m prefetch=0 serve-stale=0"},
    flushes=[{"requested_at": "2026-07-29T00:00:00Z", "scope": "name", "target": long_domain, "status": "completed"}],
    total_memory_mb=3891,
)
for expected in ("Cache Tuning", "Flush Cache", "71.5", "max-cache-size=490m", long_domain, "data-async-form"):
    if expected not in dns_cache_html:
        raise SystemExit(f"cache page missing {expected}")

encryption_html = TEMPLATES.get_template("encryption.html").render(
    **base,
    error=None,
    cfg={
        "server_hostname": "bindguard.local", "bootstrap_ip": "172.16.43.101",
        "doh_enabled": "1", "doh3_enabled": "1", "dot_enabled": "1", "doq_enabled": "1", "dnscrypt_enabled": "0",
        "doh_path": "/dns-query", "doh_port": "443", "doh3_port": "443", "dot_port": "853", "doq_port": "853",
        "dnscrypt_port": "5443", "dnscrypt_provider": "2.dnscrypt-cert.bindguard.local",
        "cert_mode": "self_signed", "cert_path": "/etc/bindguard/certs/bindguard-lab.crt", "key_path": "/etc/bindguard/certs/bindguard-lab.key",
    },
    cert={
        "available": True, "subject": "CN=" + long_domain, "issuer": "CN=" + long_domain,
        "not_before": "Jul 29 00:00:00 2026 GMT", "not_after": "Oct 31 00:00:00 2028 GMT",
        "days_remaining": 824, "expiring_soon": False, "expired": False,
        "fingerprint_sha256": "AA:BB:CC:DD", "sans": ["DNS:" + long_domain, "IP Address:172.16.43.101"], "self_signed": True,
    },
    deployment={"status": "deployed", "started_at": "2026-07-29T00:00:00Z", "finished_at": "2026-07-29T00:00:00Z", "message": "deployed with protocols: {'plain': 'ok'}", "protocol_tests": "{'plain': 'ok'}"},
    connection_info={"DoH": "https://" + long_domain + "/dns-query", "DoT": "tls://bindguard.local:853"},
    dnscrypt_fingerprint=None,
)
for expected in ("Protocols", "Client Connection Information", "Self-signed certificate", "Upload certificate and key", long_domain, "data-async-form"):
    if expected not in encryption_html:
        raise SystemExit(f"encryption page missing {expected}")

import_base_html = TEMPLATES.get_template("import_migration.html").render(**base, error=None, jobs=[{"id": 1, "created_at": "2026-07-29T00:00:00Z", "source_type": "csv", "source_name": long_domain, "status": "applied", "valid_rows": 3, "applied_rows": 3}], job=None, preview=None, adguard=None)
for expected in ("Spreadsheet / Text Import", "AdGuard Home Migration", "Column Mapping Reference", long_domain):
    if expected not in import_base_html:
        raise SystemExit(f"import page missing {expected}")

import_job_html = TEMPLATES.get_template("import_migration.html").render(
    **base, error=None, jobs=[],
    job={"id": 1, "source_type": "csv", "source_name": long_domain, "status": "previewed", "message": "", "report_json": "{}"},
    headers=["Hostname", "IP"], column_map={"hostname": "Hostname", "ipv4": "IP"}, canonical_fields=importer.CANONICAL_FIELDS,
    preview={
        "valid": [{"index": 0, "fqdn": "a." + long_domain, "record_type": "A", "value": "172.16.43.10"}],
        "invalid": [{"index": 1, "error": "bad row"}],
        "duplicates": [],
        "conflicts": [{"index": 2, "fqdn": "b." + long_domain, "record_type": "A", "value": "172.16.43.11", "warnings": ["A hostname already exists."]}],
    },
    adguard=None,
)
for expected in ("Import Job #", "Conflicts", "data-async-form", long_domain):
    if expected not in import_job_html:
        raise SystemExit(f"import job page missing {expected}")

import_adguard_html = TEMPLATES.get_template("import_migration.html").render(
    **base, error=None, jobs=[], job=None, preview=None,
    adguard={
        "blocklist_sources": [{"name": "EasyList", "url": long_upstream, "enabled": True}],
        "allowlist_unsupported": [{"name": "Allow", "url": long_upstream, "note": "n/a"}],
        "custom_allow": ["a.example"], "custom_block": ["b.example"],
        "unsupported_rules": ["example.com##.ad"],
        "rewrites_as_local_dns": [{"fqdn": long_domain, "record_type": "A", "value": "172.16.43.12"}],
        "clients_as_aliases": [{"display_name": "Phone", "cidr_or_ip": "172.16.43.77", "all_ids": []}],
        "untranslatable": ["safe_search: not implemented"],
    },
    adguard_json="{}",
)
for expected in ("AdGuard Home Migration Preview", "Settings With No BindGuard Equivalent", long_upstream):
    if expected not in import_adguard_html:
        raise SystemExit(f"import adguard preview page missing {expected}")

backup_html = TEMPLATES.get_template("backup.html").render(
    **base, error=None, imported=None, preview_source=None,
    component_keys=["app_config", "sqlite_data", "custom_rules", "private_keys"],
    component_defaults={"app_config": True, "sqlite_data": True, "custom_rules": True, "private_keys": False},
    last_backup={"created_at": "2026-07-29T00:00:00Z", "size_bytes": 1048576, "status": "deployed"},
    last_restore={"started_at": "2026-07-29T00:00:00Z", "finished_at": "2026-07-29T00:00:00Z", "status": "deployed"},
    backup_settings={"schedule_enabled": "1", "schedule_interval_hours": "24", "retention_count": "7"},
    backups=[{"id": 1, "created_at": "2026-07-29T00:00:00Z", "size_bytes": 2097152, "components_summary": long_upstream, "status": "deployed", "path": "bindguard-backup-x.tar.gz"}],
    preview={
        "compatible": True, "warnings": [],
        "manifest": {"source_node_id": "bindguard-1", "created_at": "2026-07-29T00:00:00Z", "bindguard_app_version": "unreleased+git.abc", "database_schema_version": "abc123"},
        "included_components": ["app_config", "sqlite_data"],
        "table_diffs": [{"table": "custom_rules", "component": "custom_rules", "live_rows": 3, "backup_rows": 2}],
        "file_diffs": [{"path": long_domain, "diff": "modified"}],
        "unchanged_file_count": 5,
    },
)
for expected in ("Create Backup", "Preview a Restore", "Restore Preview", "Scheduled Backups", "private_keys", long_upstream, long_domain, "data-async-form"):
    if expected not in backup_html:
        raise SystemExit(f"backup page missing {expected}")

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
    "dns_cache": dns_cache_html,
    "encryption": encryption_html,
    "import_base": import_base_html,
    "import_job": import_job_html,
    "import_adguard": import_adguard_html,
    "backup": backup_html,
}.items():
    if "app-topbar" not in rendered or "status-badge" not in rendered:
        raise SystemExit(f"{name} did not use the shared shell")

response = webapp.analytics_chart_data(SimpleNamespace(query_params={"range": "24h"}), None)
if response.status_code != 200 or b'"series"' not in response.body:
    raise SystemExit("chart data endpoint did not return JSON series")
PY

echo "web smoke tests passed"
