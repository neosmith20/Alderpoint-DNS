"""V2 import/migration: AdGuard Home, Pi-hole, and generic (hosts / BIND
zone / Alderpoint-native CSV & XLSX / Alderpoint-native JSON) import, with
staged preview -> apply, conflict detection, warnings for unsupported
constructs, and idempotent re-apply.

Beta-rescue priority 2. Deliberately reuses ``app.importer``'s and
``app.custom_rules``'s pure, source-format-shaped parsing/classification
functions (``parse_adguard_yaml``, ``fetch_adguard_api``,
``parse_pihole_text``, ``parse_hosts_text``, ``parse_zone_text``,
``parse_alderpointdns_csv``, ``parse_xlsx_bytes``,
``parse_alderpointdns_native_json``, ``custom_rules.parse_rule``) -- these
are mature, already-tested text-in/dict-out transforms with no V1 database
coupling. What is NOT reused is any of V1's *apply* layer: every write
here goes through V2's own control.db + policy_store schema, and every
apply is followed by the ordinary V2 validate -> compile -> promote
pipeline (see webapp._mutate_and_promote), never a bespoke runtime path.

Deliberately NOT implemented: live fetching of AdGuard/Pi-hole blocklist
*subscription* URLs during import. V2 has no subscribed-blocklist-refresh
feature yet (see docs/v2 parity notes), and blindly fetching arbitrary
attacker-influenced URLs from an authenticated import flow is its own
hazard. Each blocklist subscription source found in the translation
becomes an explicit "unsupported" plan item with actionable guidance
(fetch its content and re-import it as a hosts/CSV file) rather than a
silent drop or a fake success.

Block-domain enforcement deliberately reuses the exact same
service/service-ruleset mechanism app/v2/migration_convert.py's V1->V2
package migration already uses (``policy_store.create_service`` +
``create_service_ruleset`` + the global policy layer's
``service_blocking_ruleset_id``) rather than inventing a second storage
path -- this is the only mechanism the real compiled runtime enforces
ad-hoc domain lists through today. Each import job gets its own service
(``import-job-<id>``) so re-applying/removing one job never touches
another's domains; all imported services accumulate into one shared
ruleset (``imported-blocklist``) rather than replacing each other.
"allow" domains have no V2 equivalent yet (same documented gap
migration_convert.py's own migrate_filtering_to_control_db notes for V1
migration) and are reported as an explicit unsupported finding, never
silently dropped or faked.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from app import custom_rules as v1_custom_rules
from app import importer as v1_importer
from app.v2 import policy_store as store

SOURCE_TYPES = (
    "adguard_yaml",
    "adguard_api",
    "pihole",
    "hosts",
    "bind_zone",
    "csv",
    "xlsx",
    "alderpointdns_json",
)

DEFAULT_DOMAIN = "home.arpa"  # matches app/local_dns.py's own DEFAULT_DOMAIN
MAX_PLAN_ITEMS = 20_000
IMPORTED_RULESET_ID = "imported-blocklist"


class ImportError_(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty_translation(**overrides: Any) -> dict[str, Any]:
    base = {
        "blocklist_sources": [],
        "allowlist_unsupported": [],
        "custom_rules": [],
        "custom_allow": [],
        "custom_block": [],
        "unsupported_rules": [],
        "rewrites_as_local_dns": [],
        "clients_as_aliases": [],
        "clients_full": [],
        "access_allowed": [],
        "access_denied": [],
        "client_scoped": [],
        "upstream_resolvers": [],
        "untranslatable": [],
    }
    base.update(overrides)
    return base


def _generic_rows_to_translation(rows: list[dict[str, str]]) -> dict[str, Any]:
    local: list[dict[str, Any]] = []
    for row in rows:
        fqdn = str(row.get("fqdn", "")).strip().strip(".")
        record_type = str(row.get("record_type", "")).strip().upper()
        value = str(row.get("value") or row.get("target") or "").strip()
        if not fqdn or record_type not in ("A", "AAAA", "CNAME", "PTR") or not value:
            continue
        try:
            ttl = int(str(row.get("ttl") or 300))
        except ValueError:
            ttl = 300
        enabled_raw = str(row.get("enabled", "1")).strip().lower()
        local.append({
            "fqdn": fqdn, "record_type": record_type, "value": value, "ttl": ttl,
            "origin": "generic-import", "enabled": enabled_raw not in ("0", "false", ""),
        })
    return _empty_translation(rewrites_as_local_dns=local)


def parse_source(
    source_type: str,
    *,
    text: Optional[str] = None,
    data: Optional[bytes] = None,
    default_domain: Optional[str] = None,
    base_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> dict[str, Any]:
    """Parse raw source content into the common translation dict shape.
    Never writes anywhere -- pure parsing only."""
    if source_type not in SOURCE_TYPES:
        raise ImportError_(f"unsupported source_type: {source_type!r}")
    domain = (default_domain or DEFAULT_DOMAIN).strip().strip(".").lower() or DEFAULT_DOMAIN
    try:
        if source_type == "adguard_yaml":
            if text is None:
                raise ImportError_("adguard_yaml requires uploaded file text")
            return v1_importer.parse_adguard_yaml(text, domain)
        if source_type == "adguard_api":
            if not (base_url and username and password):
                raise ImportError_("adguard_api requires base_url, username, and password")
            return v1_importer.fetch_adguard_api(base_url, username, password, domain)
        if source_type == "pihole":
            if text is None:
                raise ImportError_("pihole requires uploaded file text")
            return v1_importer.parse_pihole_text(text, domain)
        if source_type == "hosts":
            if text is None:
                raise ImportError_("hosts requires uploaded file text")
            return _generic_rows_to_translation(v1_importer.parse_hosts_text(text, domain))
        if source_type == "bind_zone":
            if text is None:
                raise ImportError_("bind_zone requires uploaded file text")
            return _generic_rows_to_translation(v1_importer.parse_zone_text(text, domain))
        if source_type == "csv":
            if text is None:
                raise ImportError_("csv requires uploaded file text")
            return _generic_rows_to_translation(v1_importer.parse_alderpointdns_csv(text))
        if source_type == "xlsx":
            if data is None:
                raise ImportError_("xlsx requires uploaded file bytes")
            _headers, rows = v1_importer.parse_xlsx_bytes(data)
            normalized = [{"fqdn": r.get("fqdn", ""), "record_type": r.get("record_type", ""), "value": r.get("value", ""), "ttl": r.get("ttl", "300"), "enabled": r.get("enabled", "1")} for r in rows]
            return _generic_rows_to_translation(normalized)
        if source_type == "alderpointdns_json":
            if text is None:
                raise ImportError_("alderpointdns_json requires uploaded file text")
            return v1_importer.parse_alderpointdns_native_json(text)
    except v1_importer.ImportError_ as exc:
        raise ImportError_(str(exc)) from exc
    raise ImportError_(f"unsupported source_type: {source_type!r}")  # pragma: no cover


# --- translation -> V2 plan --------------------------------------------------

def _classify_custom_rule(entry: dict[str, Any]) -> Optional[dict[str, Any]]:
    rule_text = str(entry.get("rule") or entry.get("text") or "").strip()
    if not rule_text:
        return None
    plain_subdomains = bool(entry.get("plain_domain_subdomains", True))
    parsed_list = v1_custom_rules.parse_rule(rule_text, source_system="import", plain_domain_subdomains=plain_subdomains)
    if not parsed_list:
        return None
    parsed = parsed_list[0]
    origin = str(entry.get("origin", ""))
    if parsed.rule_type == "comment":
        return None
    if parsed.rule_type == "allow" and parsed.domain and parsed.validation_state == "valid":
        return {"kind": "unsupported", "text": f"allow rule: {parsed.domain}", "reason": "V2 has no global allow-domain override feature yet (only affects a default aggregator blocklist V2 does not have either)", "origin": origin or "custom_rule"}
    if parsed.rule_type == "block" and parsed.domain and parsed.validation_state == "valid":
        return {
            "kind": "block_domain",
            "domain": parsed.domain,
            "match_kind": "suffix" if parsed.match_subdomains else "exact",
            "origin": origin or "custom_rule",
            "note": entry.get("comment", ""),
        }
    reason = parsed.unsupported_reason or f"rule type {parsed.rule_type!r} (e.g. rewrite/regex) has no direct Alderpoint DNS global-blocklist equivalent"
    return {"kind": "unsupported", "text": rule_text, "reason": reason, "origin": origin or "custom_rule"}


def build_plan(translation: dict[str, Any], conn: sqlite3.Connection) -> dict[str, Any]:
    """Build a preview plan from a parsed translation dict. Read-only:
    only inspects existing state to flag conflicts, never writes."""
    store.ensure_local_dns_schema(conn)
    existing_local = {(r["name"], r["type"]) for r in [
        {"name": n, "type": t} for (n, t, _v, _ttl) in store.load_local_dns_records(conn)
    ]}
    existing_local_full = {(n, t, v) for (n, t, v, _ttl) in store.load_local_dns_records(conn)}
    existing_blocked_domains = {
        row[0]
        for row in conn.execute(
            """
            SELECT sdom.domain FROM service_blocking_ruleset_members m
            JOIN service_definitions sd ON sd.id = m.service_row_id
            JOIN service_domains sdom ON sdom.service_row_id = sd.id
            JOIN service_blocking_rulesets r ON r.id = m.ruleset_row_id
            WHERE r.ruleset_id = ?
            """,
            (IMPORTED_RULESET_ID,),
        ).fetchall()
    } if store.service_ruleset_exists(conn, IMPORTED_RULESET_ID) else set()
    global_layer = store.load_policy_layer(conn, "global", "singleton")
    ruleset_conflict = bool(global_layer.service_blocking_ruleset_id) and global_layer.service_blocking_ruleset_id not in (None, IMPORTED_RULESET_ID)
    existing_upstream_ids = {r[0] for r in conn.execute("SELECT upstream_profile_id FROM upstream_profiles").fetchall()}
    existing_client_names = {r[0] for r in conn.execute("SELECT name FROM clients").fetchall()}

    items: list[dict[str, Any]] = []
    seen_local: set[tuple[str, str, str]] = set()

    for rec in translation.get("rewrites_as_local_dns", []):
        if len(items) >= MAX_PLAN_ITEMS:
            break
        fqdn = str(rec.get("fqdn", "")).strip().strip(".")
        rtype = str(rec.get("record_type", "")).strip().upper()
        value = str(rec.get("value", "")).strip()
        if not fqdn or rtype not in ("A", "AAAA", "CNAME", "PTR") or not value:
            items.append({"kind": "unsupported", "text": f"{rec}", "reason": "incomplete local DNS record", "origin": rec.get("origin", "")})
            continue
        key = (fqdn, rtype, value)
        if key in seen_local:
            continue
        seen_local.add(key)
        conflict = key not in existing_local_full and (fqdn, rtype) in existing_local
        items.append({
            "kind": "local_dns", "fqdn": fqdn, "record_type": rtype, "value": value,
            "ttl": int(rec.get("ttl") or 300), "enabled": bool(rec.get("enabled", True)),
            "origin": rec.get("origin", ""), "conflict": conflict,
            "conflict_note": "an existing record with this name/type has a different value and will be overwritten" if conflict else "",
            "already_applied": key in existing_local_full,
        })

    seen_block: set[str] = set()
    for entry in translation.get("custom_rules", []):
        if len(items) >= MAX_PLAN_ITEMS:
            break
        classified = _classify_custom_rule(entry)
        if classified is None:
            continue
        if classified["kind"] == "block_domain":
            domain = classified["domain"]
            if domain in seen_block:
                continue
            seen_block.add(domain)
            classified["already_applied"] = domain in existing_blocked_domains
            classified["conflict"] = ruleset_conflict
        items.append(classified)

    for domain in translation.get("custom_block", []):
        d = str(domain).strip().strip(".")
        if not d or d in seen_block:
            continue
        seen_block.add(d)
        items.append({"kind": "block_domain", "domain": d, "match_kind": "exact", "origin": "custom_block", "note": "", "conflict": ruleset_conflict, "already_applied": d in existing_blocked_domains})
    for domain in translation.get("custom_allow", []):
        d = str(domain).strip().strip(".")
        if not d:
            continue
        items.append({"kind": "unsupported", "text": f"allow domain: {d}", "reason": "V2 has no global allow-domain override feature yet", "origin": "custom_allow"})

    if ruleset_conflict and any(i.get("kind") == "block_domain" for i in items):
        items.insert(0, {
            "kind": "unsupported",
            "text": f"global filtering is already pointed at ruleset {global_layer.service_blocking_ruleset_id!r}",
            "reason": f"imported block domains will be stored in the {IMPORTED_RULESET_ID!r} ruleset but the global policy layer will NOT be repointed at it automatically (that would silently stop enforcing your existing ruleset); assign it from the Filtering page if you want both enforced, or merge the domains manually",
            "origin": "global_policy",
        })

    for src in translation.get("blocklist_sources", []):
        name = src.get("name", "imported list")
        url = src.get("url", "")
        items.append({
            "kind": "unsupported", "text": f"blocklist subscription: {name} ({url})",
            "reason": "V2 has no subscribed-blocklist-URL feature yet; fetch this list's content yourself and re-import it as a hosts or CSV file if you want its domains blocked",
            "origin": "blocklist_sources",
        })

    for resolver in translation.get("upstream_resolvers", []):
        upstream_id = _slugify(resolver.get("name") or resolver.get("address") or "imported-upstream")
        conflict = upstream_id in existing_upstream_ids
        items.append({
            "kind": "upstream", "upstream_profile_id": upstream_id, "name": resolver.get("name") or upstream_id,
            "transport": resolver.get("protocol") or resolver.get("transport") or "plain",
            "address": resolver.get("address", ""), "port": resolver.get("port"),
            "tls_hostname": resolver.get("tls_hostname"), "doh_path": resolver.get("doh_path"),
            "origin": "upstream_resolvers", "conflict": conflict,
            "conflict_note": "an upstream profile with this id already exists and will be skipped (re-run with a different id to add a second copy)" if conflict else "",
            "already_applied": conflict,
        })

    for client in translation.get("clients_full", []):
        name = client.get("name", "")
        if not name:
            continue
        conflict = name in existing_client_names
        items.append({
            "kind": "client", "name": name, "description": client.get("description", "imported"),
            "identifiers": client.get("identifiers", []), "origin": "clients_full", "conflict": conflict,
            "conflict_note": "a client with this name already exists and will be skipped" if conflict else "",
            "already_applied": conflict,
        })
        for weak in client.get("weak_clientids", []):
            items.append({"kind": "unsupported", "text": f"{name}: ClientID {weak}", "reason": "ClientID is below Alderpoint's 192-bit minimum length and was not imported", "origin": "clients_full"})
        for raw in client.get("unrecognized", []):
            items.append({"kind": "unsupported", "text": f"{name}: {raw}", "reason": "not a recognized IPv4/IPv6/CIDR/ClientID identifier", "origin": "clients_full"})

    for note in (
        list(translation.get("unsupported_rules", []))
        + list(translation.get("untranslatable", []))
        + list(translation.get("client_scoped", []))
        + [f"{a.get('name','')}: {a.get('url','')}: {a.get('note','')}" for a in translation.get("allowlist_unsupported", [])]
        + [f"access {r.get('kind')} {r.get('value')}: V2 has no global allow/deny access-rule surface yet" for r in translation.get("access_allowed", []) + translation.get("access_denied", [])]
    ):
        if len(items) >= MAX_PLAN_ITEMS:
            break
        items.append({"kind": "unsupported", "text": str(note), "reason": "reported by the source parser", "origin": "source"})

    summary: dict[str, int] = {}
    for item in items:
        summary[item["kind"]] = summary.get(item["kind"], 0) + 1
    conflicts = sum(1 for i in items if i.get("conflict"))
    return {"items": items, "summary": summary, "conflict_count": conflicts, "item_count": len(items)}


def _slugify(value: str) -> str:
    s = re.sub(r"[^a-z0-9_.-]+", "-", str(value).strip().lower()).strip("-")
    return (s or "imported")[:64]


# --- job persistence ---------------------------------------------------------

def create_job(conn: sqlite3.Connection, source_type: str, source_name: str, plan: dict[str, Any]) -> int:
    return store.create_import_job(conn, source_type, source_name, json.dumps(plan))


def get_job(conn: sqlite3.Connection, job_id: int) -> Optional[dict[str, Any]]:
    job = store.get_import_job(conn, job_id)
    if job is None:
        return None
    job = dict(job)
    job["plan"] = json.loads(job.pop("plan_json") or "{}")
    job["result"] = json.loads(job.pop("result_json") or "{}")
    return job


def list_jobs(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    out = []
    for job in store.list_import_jobs(conn, limit):
        job = dict(job)
        job["plan"] = json.loads(job.pop("plan_json") or "{}")
        job["result"] = json.loads(job.pop("result_json") or "{}")
        out.append(job)
    return out


class ApplyError(ValueError):
    pass


def apply_plan(
    conn: sqlite3.Connection, job_id: int, plan: dict[str, Any], skip_indexes: Optional[set[int]] = None,
) -> dict[str, Any]:
    """Applies a plan's items to control.db within the caller's own
    transaction (see webapp._mutate_and_promote, which wraps this in a
    write + recompile/promote that only commits together). Idempotent:
    re-applying the same plan a second time counts every already-satisfied
    item as "skipped_existing" rather than erroring or duplicating."""
    skip_indexes = skip_indexes or set()
    store.ensure_local_dns_schema(conn)
    counts = {"local_dns": 0, "block_domain": 0, "upstream": 0, "client": 0, "skipped_existing": 0, "skipped_by_operator": 0, "unsupported": 0}
    block_domains: list[tuple[str, str]] = []  # (match_kind, domain)
    for index, item in enumerate(plan.get("items", [])):
        if index in skip_indexes:
            counts["skipped_by_operator"] += 1
            continue
        kind = item.get("kind")
        if kind == "local_dns":
            store.upsert_local_dns_record(conn, item["fqdn"], item["record_type"], item["value"], int(item.get("ttl") or 300), enabled=bool(item.get("enabled", True)))
            counts["local_dns"] += 1
        elif kind == "block_domain":
            block_domains.append((item.get("match_kind", "exact"), item["domain"]))
            counts["block_domain"] += 1
        elif kind == "upstream":
            if item.get("already_applied"):
                counts["skipped_existing"] += 1
                continue
            try:
                endpoint = store.UpstreamEndpointRecord(
                    address=item["address"], tls_hostname=item.get("tls_hostname"), priority=0, weight=1,
                    secret_ref=None, doh_path=item.get("doh_path"),
                )
                transport = item.get("transport") or "plain"
                if transport not in ("plain", "dot", "doh"):
                    transport = "plain"
                store.create_upstream_profile(conn, item["upstream_profile_id"], item["name"], transport, [endpoint])
                counts["upstream"] += 1
            except store.PolicyStoreError:
                counts["skipped_existing"] += 1
        elif kind == "client":
            if item.get("already_applied"):
                counts["skipped_existing"] += 1
                continue
            now = _now()
            cur = conn.execute(
                "INSERT INTO clients(name, description, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
                (item["name"], item.get("description", "imported"), now, now),
            )
            client_id = cur.lastrowid
            for ident in item.get("identifiers", []):
                try:
                    conn.execute(
                        "INSERT INTO client_identifiers(client_id, kind, value, created_at) VALUES (?, ?, ?, ?)",
                        (client_id, ident.get("kind"), ident.get("value"), now),
                    )
                except sqlite3.IntegrityError:
                    continue
            counts["client"] += 1
        else:
            counts["unsupported"] += 1

    if block_domains:
        service_id = f"import-job-{job_id}"
        # Idempotent: this job's own service is fully replaced (not
        # duplicated) on re-apply, then re-added to the shared ruleset's
        # member list if it fell out (it never should on a normal re-run,
        # but a prior partial/rolled-back apply could have left it absent).
        conn.execute(
            "DELETE FROM service_domains WHERE service_row_id IN (SELECT id FROM service_definitions WHERE service_id = ?)",
            (service_id,),
        )
        conn.execute("DELETE FROM service_definitions WHERE service_id = ?", (service_id,))
        store.create_service(conn, service_id, f"Imported blocklist (job {job_id})", domains=block_domains, category="imported")
        members = store.list_service_ruleset_member_service_ids(conn, IMPORTED_RULESET_ID)
        if service_id not in members:
            members.append(service_id)
        store.replace_service_ruleset(conn, IMPORTED_RULESET_ID, members)

        global_layer = store.load_policy_layer(conn, "global", "singleton")
        if not global_layer.service_blocking_ruleset_id:
            from dataclasses import replace as _dc_replace
            store.save_policy_layer(conn, "global", "singleton", _dc_replace(global_layer, service_blocking_ruleset_id=IMPORTED_RULESET_ID))

    return counts
