"""Subscribed/refreshable Blocklists (beta-rescue priority 3B).

Distinct from app/v2/import_migration.py's one-time, import-derived
block domains (a snapshot taken once at import time): a subscription is
a URL re-fetched on a schedule. Real HTTP fetch (size-capped, http(s)-
only redirects, timeout-bounded -- reusing app.importer's own already-
audited fetch primitives, the same reuse rationale as import_migration.py's
own docstring), parsed as a plain hosts/adblock-style domain list (one
domain per line, `#`/`!` comments, `||domain^` AdGuard-style lines
accepted too via the same custom_rules.parse_rule classifier
import_migration.py already uses), and compiled into V2's real policy
runtime via the exact same service/service-ruleset mechanism import jobs
already use -- each subscription owns one service (never another
subscription's or import job's domains), accumulated into one shared
ruleset.

Safety:
- The fetch never happens on the DNS query path -- only from an explicit
  operator "Refresh now" action or the periodic refresh timer/service
  (scripts/v2/alderpointdns_v2_blocklist_refresh.py), both of which run
  independently of dnsdist/BIND request handling.
- A failed refresh (network error, oversized response, unparseable
  content) records the failure and returns without touching the
  subscription's already-compiled service -- the previously valid
  compiled filtering for that subscription remains exactly as it was
  ("safe failed refresh retaining prior valid compiled filtering").
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Optional

from app import custom_rules as v1_custom_rules
from app import importer as v1_importer
from app.v2 import policy_store as store
from app.v2.import_migration import IMPORTED_RULESET_ID as SUBSCRIPTION_RULESET_ID

MAX_DOMAINS_PER_SUBSCRIPTION = 200_000


class BlocklistSubscriptionError(ValueError):
    pass


@dataclass(frozen=True)
class RefreshResult:
    ok: bool
    rule_count: int
    message: str


def _service_id_for(subscription_id: str) -> str:
    return f"subscription-{subscription_id}"


def _parse_domains(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Returns (domains as (match_kind, domain) pairs, warnings). Accepts
    plain hosts-style domain-per-line and AdGuard-style ||domain^ lines
    via the same rule classifier import_migration.py already uses, so a
    subscription in either common format works, not just one."""
    domains: list[tuple[str, str]] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if len(line) > v1_importer.MAX_LINE_CHARS:
            warnings.append(f"line {lineno} exceeds the maximum line length and was skipped")
            continue
        # Hosts-file form: "0.0.0.0 domain" / "127.0.0.1 domain" -- treat
        # the hostname column as the domain to block, matching how
        # most public "hosts-style" blocklists are actually published.
        parts = line.split()
        candidate = parts[1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1") else line
        parsed = v1_custom_rules.parse_rule(candidate, source_system="subscription", plain_domain_subdomains=True)
        if not parsed:
            continue
        rule = parsed[0]
        if rule.rule_type != "block" or not rule.domain or rule.validation_state != "valid":
            continue
        key = ("suffix" if rule.match_subdomains else "exact", rule.domain)
        if key in seen:
            continue
        seen.add(key)
        domains.append(key)
        if len(domains) >= MAX_DOMAINS_PER_SUBSCRIPTION:
            warnings.append(f"subscription exceeds {MAX_DOMAINS_PER_SUBSCRIPTION} domains; remaining lines were not imported")
            break
    return domains, warnings


def fetch_and_parse(url: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Real HTTP GET (reusing app.importer's own audited fetch safety:
    http(s)-only redirects, size cap) -- raises BlocklistSubscriptionError
    on any fetch/parse failure, never returns a partial/ambiguous result."""
    import urllib.request

    sanitized = v1_importer.sanitize_url(url)
    try:
        opener = urllib.request.build_opener(v1_importer._HttpOnlyRedirectHandler())
        request = urllib.request.Request(sanitized, headers={"User-Agent": "AlderpointDNS-V2-BlocklistRefresh/1"})
        with opener.open(request, timeout=15) as response:
            body = response.read(v1_importer.MAX_API_RESPONSE_BYTES + 1)
    except Exception as exc:
        raise BlocklistSubscriptionError(f"fetch failed: {exc}") from exc
    if len(body) > v1_importer.MAX_API_RESPONSE_BYTES:
        raise BlocklistSubscriptionError(f"response exceeds {v1_importer.MAX_API_RESPONSE_BYTES // (1024 * 1024)} MiB limit")
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception as exc:
        raise BlocklistSubscriptionError(f"response is not decodable text: {exc}") from exc
    v1_importer.check_text_limits(text)
    domains, warnings = _parse_domains(text)
    if not domains:
        raise BlocklistSubscriptionError("no valid domains found in the fetched content")
    return domains, warnings


def refresh_subscription(conn: sqlite3.Connection, subscription_id: str) -> RefreshResult:
    """Fetches, parses, and -- only if that succeeds -- replaces this
    subscription's own service content. A failure never touches the
    subscription's previously-compiled service, and is recorded on the
    subscription row for the operator to see."""
    sub = store.get_blocklist_subscription(conn, subscription_id)
    if sub is None:
        raise BlocklistSubscriptionError(f"unknown subscription: {subscription_id!r}")

    try:
        domains, warnings = fetch_and_parse(sub["url"])
    except BlocklistSubscriptionError as exc:
        store.record_blocklist_refresh_result(conn, subscription_id, "failed", str(exc))
        return RefreshResult(ok=False, rule_count=sub["rule_count"], message=str(exc))

    service_id = _service_id_for(subscription_id)
    conn.execute(
        "DELETE FROM service_domains WHERE service_row_id IN (SELECT id FROM service_definitions WHERE service_id = ?)",
        (service_id,),
    )
    conn.execute("DELETE FROM service_definitions WHERE service_id = ?", (service_id,))
    store.create_service(conn, service_id, f"Subscribed: {sub['name']}", domains=domains, category=sub["category"] or "subscribed")

    members = store.list_service_ruleset_member_service_ids(conn, SUBSCRIPTION_RULESET_ID)
    if service_id not in members:
        members.append(service_id)
    store.replace_service_ruleset(conn, SUBSCRIPTION_RULESET_ID, members)

    global_layer = store.load_policy_layer(conn, "global", "singleton")
    if not global_layer.service_blocking_ruleset_id:
        from dataclasses import replace as _dc_replace
        store.save_policy_layer(conn, "global", "singleton", _dc_replace(global_layer, service_blocking_ruleset_id=SUBSCRIPTION_RULESET_ID))

    message = f"refreshed: {len(domains)} domains" + (f" ({len(warnings)} warning(s))" if warnings else "")
    store.record_blocklist_refresh_result(conn, subscription_id, "succeeded", "; ".join(warnings), len(domains))
    return RefreshResult(ok=True, rule_count=len(domains), message=message)


def remove_subscription_service(conn: sqlite3.Connection, subscription_id: str) -> None:
    """Removes this subscription's own service and ruleset membership
    (never another subscription's or an import job's) -- called when a
    subscription is deleted."""
    service_id = _service_id_for(subscription_id)
    conn.execute(
        "DELETE FROM service_domains WHERE service_row_id IN (SELECT id FROM service_definitions WHERE service_id = ?)",
        (service_id,),
    )
    conn.execute("DELETE FROM service_definitions WHERE service_id = ?", (service_id,))
    members = store.list_service_ruleset_member_service_ids(conn, SUBSCRIPTION_RULESET_ID)
    if service_id in members:
        members = [m for m in members if m != service_id]
        store.replace_service_ruleset(conn, SUBSCRIPTION_RULESET_ID, members)
