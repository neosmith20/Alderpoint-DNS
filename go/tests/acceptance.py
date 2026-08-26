#!/usr/bin/env python3
"""Language-neutral black-box acceptance suite for the Go control plane.

Talks only to the HTTP API (no Go-internal knowledge), so it can be
re-pointed at any future implementation of this same contract. Exercises:
setup/login/session, health, YAML validation (implicit via startup),
SQLite migration + rollback, the full Blocklist lifecycle (create with
automatic initial pull, interval, toggle, Update Now, Update All, delete),
the full Local DNS lifecycle, restart persistence, a stale-request race,
and rapid repeated clicking (idempotent double-delete).

Usage: start a `web` instance pointed at an isolated temp dir + a local
fixture HTTP server, then:
    python3 tests/acceptance.py --base http://127.0.0.1:8444 --fixture-base http://127.0.0.1:8299
Exits non-zero with a clear message on the first failure.
"""
import argparse
import json
import os
import subprocess
import sys
import time

PASS = "PASS"
FAIL = "FAIL"
results = []


def check(name, cond, detail=""):
    status = PASS if cond else FAIL
    results.append((name, status, detail))
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and status == FAIL else ""))
    if status == FAIL:
        print("ACCEPTANCE SUITE FAILED, aborting.")
        sys.exit(1)


def curl_json(method, url, cookie=None, csrf=None, body=None, extra=None):
    cmd = ["curl", "-s", "-X", method, url]
    if cookie:
        cmd += ["-b", cookie]
    if csrf:
        cmd += ["-H", f"X-CSRF-Token: {csrf}"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    if extra:
        cmd += extra
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"_raw": out}


def curl_status(method, url, cookie=None, csrf=None, body=None):
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", method, url]
    if cookie:
        cmd += ["-b", cookie]
    if csrf:
        cmd += ["-H", f"X-CSRF-Token: {csrf}"]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--fixture-base", required=True)
    p.add_argument("--cookiejar", default="/tmp/apdns-go-acceptance-cj.txt")
    p.add_argument("--backups-dir", default=None, help="the server's -backups-dir, for a real (not just corrupt-payload) upload round-trip test")
    p.add_argument("--query-log-dir", default=None, help="the server's -query-log-dir, pre-seeded with go/tests/fixtures/make_query_log_fixture.py, for a real (not just degraded-path) Query Log test")
    p.add_argument("--tls-cert-status-path", default=None, help="the server's -tls-cert-status-path, for a real (not just degraded-path) TLS status test")
    args = p.parse_args()
    B, FB, CJ = args.base, args.fixture_base, args.cookiejar

    # --- setup / login / session ---
    status = curl_json("GET", f"{B}/api/setup/status")
    check("setup/status reports setup_required", status.get("setup_required") is True, status)

    setup = curl_json("POST", f"{B}/api/setup", body={
        "username": "accept", "password": "correct-horse-battery-staple",
        "confirm_password": "correct-horse-battery-staple", "create_local_dns": False,
    })
    check("setup creates the first admin", setup.get("status") == "created", setup)

    setup2 = curl_json("POST", f"{B}/api/setup", body={
        "username": "second", "password": "correct-horse-battery-staple",
        "confirm_password": "correct-horse-battery-staple", "create_local_dns": False,
    })
    check("second setup attempt is rejected (already_configured)", setup2.get("error") == "already_configured", setup2)

    login = curl_json("POST", f"{B}/api/login", body={"username": "accept", "password": "correct-horse-battery-staple"}, extra=["-c", CJ])
    check("login succeeds and returns a csrf token", login.get("status") == "ok" and "csrf" in login, login)
    csrf = login["csrf"]

    session = curl_json("GET", f"{B}/api/session", cookie=CJ)
    check("session reports authenticated", session.get("authenticated") is True, session)

    no_csrf_status = curl_status("POST", f"{B}/api/blocklists/settings", cookie=CJ, body={"default_interval_seconds": 0})
    check("mutating request without X-CSRF-Token is rejected (403)", no_csrf_status == "403", no_csrf_status)

    # --- health ---
    health = curl_json("GET", f"{B}/api/health")
    check("health reports ok", health.get("status") == "ok", health)
    check("health reports a schema_version", health.get("components", {}).get("control_db", {}).get("schema_version", 0) >= 1, health)

    # --- blocklist lifecycle ---
    created = curl_json("POST", f"{B}/api/blocklists", cookie=CJ, csrf=csrf, body={
        "name": "Acceptance List", "url": f"{FB}/accept.txt", "category": "standard",
    })
    check("create blocklist returns a job_id (automatic initial pull)", "job_id" in created and created["job_id"], created)
    sub_id = created["subscription_id"]

    job_id = created["job_id"]
    final_job = None
    for _ in range(50):
        job = curl_json("GET", f"{B}/api/blocklists/jobs/{job_id}", cookie=CJ)
        if job.get("state") in ("succeeded", "failed"):
            final_job = job
            break
        time.sleep(0.1)
    check("initial pull job completes", final_job is not None and final_job["state"] == "succeeded", final_job)
    check("initial pull parsed the fixture's 3 domains", final_job["results"][0]["rule_count"] == 3, final_job)

    interval = curl_json("POST", f"{B}/api/blocklists/{sub_id}/interval", cookie=CJ, csrf=csrf, body={"update_interval_seconds": 3600})
    check("set interval to a valid preset", interval.get("status") == "updated", interval)

    bad_interval_status = curl_json("POST", f"{B}/api/blocklists/{sub_id}/interval", cookie=CJ, csrf=csrf, body={"update_interval_seconds": 1234})
    check("set interval rejects a non-preset value", bad_interval_status.get("error") == "validation_error", bad_interval_status)

    toggle = curl_json("POST", f"{B}/api/blocklists/{sub_id}/toggle", cookie=CJ, csrf=csrf)
    check("toggle disables the subscription", toggle.get("status") == "updated", toggle)
    toggle2 = curl_json("POST", f"{B}/api/blocklists/{sub_id}/toggle", cookie=CJ, csrf=csrf)
    check("toggle re-enables the subscription", toggle2.get("status") == "updated", toggle2)

    refresh = curl_json("POST", f"{B}/api/blocklists/{sub_id}/refresh", cookie=CJ, csrf=csrf)
    check("Update Now queues a job", refresh.get("status") == "queued", refresh)

    refresh_all = curl_json("POST", f"{B}/api/blocklists/refresh-all", cookie=CJ, csrf=csrf)
    check("Update All queues a job for all enabled subscriptions", refresh_all.get("status") in ("queued", "empty"), refresh_all)

    # --- rapid repeated clicking: double-delete must not corrupt state ---
    del1_status = curl_status("DELETE", f"{B}/api/blocklists/{sub_id}", cookie=CJ, csrf=csrf)
    del2_status = curl_status("DELETE", f"{B}/api/blocklists/{sub_id}", cookie=CJ, csrf=csrf)
    check("first delete succeeds (200)", del1_status == "200", del1_status)
    check("second rapid delete of the same id is a clean 404, not a crash/500", del2_status == "404", del2_status)

    # --- local dns lifecycle ---
    rec = curl_json("POST", f"{B}/api/local-dns", cookie=CJ, csrf=csrf, body={
        "name": "accept.lan", "record_type": "A", "value": "10.0.0.9", "ttl": 300, "enabled": True,
    })
    check("create local-dns record", rec.get("status") == "created", rec)
    rec_id = rec["record"]["id"]

    bad_rec = curl_json("POST", f"{B}/api/local-dns", cookie=CJ, csrf=csrf, body={
        "name": "bad.lan", "record_type": "A", "value": "not-an-ip", "ttl": 300, "enabled": True,
    })
    check("create local-dns record rejects an invalid IP", bad_rec.get("error") == "validation_error", bad_rec)

    # --- dashboard summary: real counts, not fabricated ---
    summary = curl_json("GET", f"{B}/api/dashboard/summary", cookie=CJ)
    check("dashboard summary reflects the blocklist just deleted above", summary.get("blocklists", {}).get("total") == 0, summary)
    check("dashboard summary reflects the local-dns record just created", summary.get("local_dns", {}).get("total") == 1, summary)
    check("dashboard summary reports enabled local-dns count", summary.get("local_dns", {}).get("enabled") == 1, summary)

    edit = curl_json("PATCH", f"{B}/api/local-dns/{rec_id}", cookie=CJ, csrf=csrf, body={"value": "10.0.0.10"})
    check("edit local-dns record", edit.get("record", {}).get("value") == "10.0.0.10", edit)

    listing = curl_json("GET", f"{B}/api/local-dns", cookie=CJ)
    check("local-dns list contains the edited record", any(r["id"] == rec_id and r["value"] == "10.0.0.10" for r in listing.get("records", [])), listing)

    deleted = curl_json("DELETE", f"{B}/api/local-dns/{rec_id}", cookie=CJ, csrf=csrf)
    check("delete local-dns record", deleted.get("status") == "deleted", deleted)

    # --- upstreams lifecycle (native Go schema/CRUD, not a Python proxy) ---
    up1 = curl_json("POST", f"{B}/api/upstreams", cookie=CJ, csrf=csrf, body={
        "name": "Primary", "transport": "plain", "strategy": "ordered",
        "endpoints": [{"address": "9.9.9.9", "priority": 0, "weight": 1}],
    })
    check("create upstream returns an id", "upstream_profile_id" in up1, up1)
    up1_id = up1["upstream_profile_id"]

    doh_missing_tls = curl_json("POST", f"{B}/api/upstreams", cookie=CJ, csrf=csrf, body={
        "name": "BadDoH", "transport": "doh", "strategy": "ordered",
        "endpoints": [{"address": "1.1.1.1", "priority": 0, "weight": 1}],
    })
    check("DoH endpoint without tls_hostname is rejected", doh_missing_tls.get("error") == "invalid_upstream", doh_missing_tls)

    listed = curl_json("GET", f"{B}/api/upstreams", cookie=CJ)
    check("upstreams list contains the new profile", any(u["upstream_profile_id"] == up1_id for u in listed.get("upstreams", [])), listed)
    check("native_recursion_active is false with an enabled upstream", listed.get("native_recursion_active") is False, listed)

    updated = curl_json("PUT", f"{B}/api/upstreams/{up1_id}", cookie=CJ, csrf=csrf, body={
        "name": "Primary Renamed", "transport": "plain", "strategy": "ordered",
        "endpoints": [{"address": "9.9.9.9", "priority": 0, "weight": 1}, {"address": "149.112.112.112", "priority": 1, "weight": 1}],
    })
    check("update upstream succeeds", updated.get("status") == "updated", updated)
    listed2 = curl_json("GET", f"{B}/api/upstreams", cookie=CJ)
    updated_profile = next((u for u in listed2["upstreams"] if u["upstream_profile_id"] == up1_id), None)
    check("update actually changed the name and added an endpoint", updated_profile and updated_profile["name"] == "Primary Renamed" and len(updated_profile["endpoints"]) == 2, updated_profile)

    disable_no_confirm = curl_json("POST", f"{B}/api/upstreams/{up1_id}/disable", cookie=CJ, csrf=csrf, body={})
    check("disabling the last enabled upstream without confirm is rejected (409)", disable_no_confirm.get("error") == "last_enabled_upstream", disable_no_confirm)
    disable_confirmed = curl_json("POST", f"{B}/api/upstreams/{up1_id}/disable", cookie=CJ, csrf=csrf, body={"confirm_last": True})
    check("disabling the last enabled upstream with confirm succeeds", disable_confirmed.get("status") == "disabled", disable_confirmed)
    listed3 = curl_json("GET", f"{B}/api/upstreams", cookie=CJ)
    check("native_recursion_active is true once the only upstream is disabled", listed3.get("native_recursion_active") is True, listed3)

    reenable = curl_json("POST", f"{B}/api/upstreams/{up1_id}/enable", cookie=CJ, csrf=csrf)
    check("re-enabling the upstream succeeds", reenable.get("status") == "enabled", reenable)

    up2 = curl_json("POST", f"{B}/api/upstreams", cookie=CJ, csrf=csrf, body={
        "name": "Secondary", "transport": "plain", "strategy": "ordered",
        "endpoints": [{"address": "8.8.8.8", "priority": 0, "weight": 1}],
    })
    up2_id = up2["upstream_profile_id"]
    reordered = curl_json("POST", f"{B}/api/upstreams/reorder", cookie=CJ, csrf=csrf, body={"ordered_upstream_profile_ids": [up2_id, up1_id]})
    check("reorder actually changes list order", [u["upstream_profile_id"] for u in reordered.get("upstreams", [])][:2] == [up2_id, up1_id], reordered)

    # Both up1 and up2 are enabled right now, so deleting up2 first is not
    # "the last enabled upstream" -- must succeed outright, no confirm needed.
    del2 = curl_json("DELETE", f"{B}/api/upstreams/{up2_id}", cookie=CJ, csrf=csrf, body={})
    check("delete a non-last upstream succeeds outright", del2.get("status") == "deleted", del2)

    # Now up1 is the sole enabled upstream -- deleting it without confirm
    # must be rejected the same way disabling it was above.
    delete_last_no_confirm = curl_json("DELETE", f"{B}/api/upstreams/{up1_id}", cookie=CJ, csrf=csrf, body={})
    check("deleting the last enabled upstream without confirm is rejected (409)", delete_last_no_confirm.get("error") == "last_enabled_upstream", delete_last_no_confirm)
    del1_confirmed = curl_json("DELETE", f"{B}/api/upstreams/{up1_id}", cookie=CJ, csrf=csrf, body={"confirm_last": True})
    check("delete the final upstream with confirm succeeds", del1_confirmed.get("status") == "deleted", del1_confirmed)

    # --- clients / groups (native Go schema/CRUD) ---
    group1 = curl_json("POST", f"{B}/api/groups", cookie=CJ, csrf=csrf, body={"name": "Kids", "priority": 10})
    check("create group returns an id", "group_id" in group1, group1)
    group1_id = group1["group_id"]

    dup_group = curl_json("POST", f"{B}/api/groups", cookie=CJ, csrf=csrf, body={"name": "Kids", "priority": 0})
    check("duplicate group name is rejected", dup_group.get("error") == "conflict", dup_group)

    client1 = curl_json("POST", f"{B}/api/clients", cookie=CJ, csrf=csrf, body={"name": "Tablet", "description": "Kitchen tablet"})
    check("create client returns an id", "client_id" in client1, client1)
    client1_id = client1["client_id"]

    bad_id = curl_json("POST", f"{B}/api/clients/{client1_id}/identifiers", cookie=CJ, csrf=csrf, body={"kind": "ipv4", "value": "not-an-ip"})
    check("invalid ipv4 identifier is rejected", bad_id.get("error") == "validation_error", bad_id)

    good_id = curl_json("POST", f"{B}/api/clients/{client1_id}/identifiers", cookie=CJ, csrf=csrf, body={"kind": "ipv4", "value": "192.168.1.50"})
    check("valid ipv4 identifier is accepted", good_id.get("status") == "created", good_id)

    dup_id = curl_json("POST", f"{B}/api/clients/{client1_id}/identifiers", cookie=CJ, csrf=csrf, body={"kind": "ipv4", "value": "192.168.1.50"})
    check("duplicate identifier is rejected", dup_id.get("error") == "conflict", dup_id)

    assign = curl_json("POST", f"{B}/api/clients/{client1_id}/groups", cookie=CJ, csrf=csrf, body={"group_id": group1_id})
    check("assigning a client to a group succeeds", assign.get("status") == "created", assign)

    clients_listed = curl_json("GET", f"{B}/api/clients", cookie=CJ)
    c1 = next((c for c in clients_listed.get("clients", []) if c["id"] == client1_id), None)
    check(
        "client list shows the identifier and group assignment",
        c1 is not None and any(i["value"] == "192.168.1.50" for i in c1["identifiers"]) and any(g["group_id"] == group1_id for g in c1["groups"]),
        c1,
    )

    groups_listed = curl_json("GET", f"{B}/api/groups", cookie=CJ)
    g1 = next((g for g in groups_listed.get("groups", []) if g["group_id"] == group1_id), None)
    check("group list shows the member", g1 is not None and any(m["id"] == client1_id for m in g1["members"]), g1)

    # --- shared policy-layer system (native Go, global/network/group/client) ---
    global_before = curl_json("GET", f"{B}/api/policy/global", cookie=CJ)
    check("global policy starts fully inherited (all fields null)", global_before.get("safesearch_mode") is None, global_before)

    set_global = curl_json("PUT", f"{B}/api/policy/global", cookie=CJ, csrf=csrf, body={
        "safesearch_mode": "strict", "query_log_enabled": True, "statistics_enabled": False,
    })
    check("setting global policy succeeds", set_global.get("status") == "updated", set_global)

    global_after = curl_json("GET", f"{B}/api/policy/global", cookie=CJ)
    check("global policy reflects the saved safesearch_mode", global_after.get("safesearch_mode") == "strict", global_after)
    check("global policy statistics_enabled=false round-trips as false, not null", global_after.get("statistics_enabled") is False, global_after)

    set_client_policy = curl_json("PUT", f"{B}/api/policy/client/{client1_id}", cookie=CJ, csrf=csrf, body={"safesearch_mode": "off"})
    check("setting a client's policy succeeds", set_client_policy.get("status") == "updated", set_client_policy)
    clients_with_policy = curl_json("GET", f"{B}/api/clients", cookie=CJ)
    c1_policy = next((c for c in clients_with_policy["clients"] if c["id"] == client1_id), None)
    check("GET /api/clients embeds the client's own policy (not the global one)", c1_policy and c1_policy["policy"]["safesearch_mode"] == "off", c1_policy)

    set_group_policy = curl_json("PUT", f"{B}/api/policy/group/{group1_id}", cookie=CJ, csrf=csrf, body={"ecs_mode": "disabled"})
    check("setting a group's policy succeeds", set_group_policy.get("status") == "updated", set_group_policy)
    groups_with_policy = curl_json("GET", f"{B}/api/groups", cookie=CJ)
    g1_policy = next((g for g in groups_with_policy["groups"] if g["group_id"] == group1_id), None)
    check("GET /api/groups embeds the group's own policy", g1_policy and g1_policy["policy"]["ecs_mode"] == "disabled", g1_policy)

    net1 = curl_json("POST", f"{B}/api/networks", cookie=CJ, csrf=csrf, body={"cidr": "10.20.0.0/24"})
    check("create network returns an id", "network_id" in net1, net1)
    dup_net = curl_json("POST", f"{B}/api/networks", cookie=CJ, csrf=csrf, body={"cidr": "10.20.0.0/24"})
    check("duplicate network CIDR is rejected", dup_net.get("error") == "conflict", dup_net)
    networks_listed = curl_json("GET", f"{B}/api/networks", cookie=CJ)
    check("network list contains the new network", any(n["cidr"] == "10.20.0.0/24" for n in networks_listed.get("networks", [])), networks_listed)

    # --- custom filtering rules (native Go, new functionality) ---
    bad_rewrite = curl_json("POST", f"{B}/api/custom-rules", cookie=CJ, csrf=csrf, body={"rule_type": "rewrite", "pattern": "example.com"})
    check("rewrite rule without rewrite_target is rejected", bad_rewrite.get("error") == "validation_error", bad_rewrite)

    rule1 = curl_json("POST", f"{B}/api/custom-rules", cookie=CJ, csrf=csrf, body={"rule_type": "block", "pattern": "ads.example.com"})
    check("create block rule returns an id", "id" in rule1, rule1)
    rule1_id = rule1["id"]
    rule2 = curl_json("POST", f"{B}/api/custom-rules", cookie=CJ, csrf=csrf, body={"rule_type": "allow", "pattern": "safe.example.com"})
    rule2_id = rule2["id"]
    rule3 = curl_json("POST", f"{B}/api/custom-rules", cookie=CJ, csrf=csrf, body={"rule_type": "rewrite", "pattern": "internal.example.com", "rewrite_target": "10.0.0.9"})
    rule3_id = rule3["id"]

    listed_rules = curl_json("GET", f"{B}/api/custom-rules", cookie=CJ)
    check("all 3 rules appear, in creation/priority order", [r["id"] for r in listed_rules["rules"]] == [rule1_id, rule2_id, rule3_id], listed_rules)

    updated_rule = curl_json("PUT", f"{B}/api/custom-rules/{rule1_id}", cookie=CJ, csrf=csrf, body={"rule_type": "block", "pattern": "ads2.example.com"})
    check("editing a rule succeeds", updated_rule.get("status") == "updated", updated_rule)

    toggled = curl_json("POST", f"{B}/api/custom-rules/{rule1_id}/toggle", cookie=CJ, csrf=csrf, body={"enabled": False})
    check("disabling a rule succeeds", toggled.get("status") == "updated", toggled)
    after_toggle = curl_json("GET", f"{B}/api/custom-rules", cookie=CJ)
    r1 = next(r for r in after_toggle["rules"] if r["id"] == rule1_id)
    check("disabled rule shows enabled=false, edit persisted too", r1["enabled"] is False and r1["pattern"] == "ads2.example.com", r1)

    reordered_rules = curl_json("POST", f"{B}/api/custom-rules/reorder", cookie=CJ, csrf=csrf, body={"ordered_ids": [rule3_id, rule1_id, rule2_id]})
    check("reordering rules changes priority order", [r["id"] for r in reordered_rules.get("rules", [])] == [rule3_id, rule1_id, rule2_id], reordered_rules)

    bulk_en = curl_json("POST", f"{B}/api/custom-rules/bulk-enable", cookie=CJ, csrf=csrf, body={"ids": [rule1_id, rule2_id]})
    check("bulk-enable affects 2 rules", bulk_en.get("count") == 2, bulk_en)

    bulk_del = curl_json("POST", f"{B}/api/custom-rules/bulk-delete", cookie=CJ, csrf=csrf, body={"ids": [rule2_id, rule3_id]})
    check("bulk-delete affects 2 rules", bulk_del.get("count") == 2, bulk_del)
    final_rules = curl_json("GET", f"{B}/api/custom-rules", cookie=CJ)
    check("only the un-deleted rule remains", [r["id"] for r in final_rules["rules"]] == [rule1_id], final_rules)

    # --- backup & restore (native Go format; mandatory pre-restore safety backup; transactional) ---
    backup1 = curl_json("POST", f"{B}/api/backup/appliance", cookie=CJ, csrf=csrf)
    check("create backup returns a manifest", backup1.get("status") == "created", backup1)
    backup1_name = backup1["backup"]["filename"]

    listed_backups = curl_json("GET", f"{B}/api/backup/appliance", cookie=CJ)
    check("backup list contains the new backup", any(b["filename"] == backup1_name for b in listed_backups.get("backups", [])), listed_backups)

    preview1 = curl_json("POST", f"{B}/api/backup/appliance/{backup1_name}/validate", cookie=CJ, csrf=csrf)
    check("preview reads the manifest without error", preview1.get("filename") == backup1_name, preview1)
    check("backup manifest reports structured per-table row counts", isinstance(preview1.get("table_counts"), dict) and "local_dns_records" in preview1["table_counts"], preview1)

    categories_resp = curl_json("GET", f"{B}/api/backup/categories", cookie=CJ)
    category_names = [c["name"] for c in categories_resp.get("categories", [])]
    check("backup categories endpoint lists the expected categories",
          {"local_dns", "custom_rules", "clients"}.issubset(set(category_names)), categories_resp)

    # --- selective restore: only the chosen category's live data should roll back ---
    curl_json("POST", f"{B}/api/local-dns", cookie=CJ, csrf=csrf, body={"name": "selective-before.lan", "record_type": "A", "value": "10.0.0.50", "ttl": 300, "enabled": True})
    curl_json("PUT", f"{B}/api/custom-rules/{rule1_id}", cookie=CJ, csrf=csrf, body={"rule_type": "block", "pattern": "selective-before.example.com"})
    backup2 = curl_json("POST", f"{B}/api/backup/appliance", cookie=CJ, csrf=csrf)
    backup2_name = backup2["backup"]["filename"]

    curl_json("POST", f"{B}/api/local-dns", cookie=CJ, csrf=csrf, body={"name": "selective-after.lan", "record_type": "A", "value": "10.0.0.51", "ttl": 300, "enabled": True})
    curl_json("PUT", f"{B}/api/custom-rules/{rule1_id}", cookie=CJ, csrf=csrf, body={"rule_type": "block", "pattern": "selective-after.example.com"})

    selective_restore = curl_json("POST", f"{B}/api/backup/appliance/{backup2_name}/restore", cookie=CJ, csrf=csrf, body={"categories": ["local_dns"]})
    check("selective restore succeeds", selective_restore.get("status") == "restored", selective_restore)

    dns_after_selective = curl_json("GET", f"{B}/api/local-dns", cookie=CJ)
    dns_names_after = {r["name"] for r in dns_after_selective["records"]}
    check("selective restore rolled back the restored category (local_dns)",
          "selective-before.lan" in dns_names_after and "selective-after.lan" not in dns_names_after, dns_after_selective)

    rules_after_selective = curl_json("GET", f"{B}/api/custom-rules", cookie=CJ)
    r1_after_selective = next(r for r in rules_after_selective["rules"] if r["id"] == rule1_id)
    check("selective restore left an unselected category (custom_rules) untouched",
          r1_after_selective["pattern"] == "selective-after.example.com", rules_after_selective)

    unknown_category_restore = curl_status("POST", f"{B}/api/backup/appliance/{backup2_name}/restore", cookie=CJ, csrf=csrf, body={"categories": ["not_a_real_category"]})
    check("restoring with an unknown category is rejected", unknown_category_restore == "400", unknown_category_restore)

    curl_status("DELETE", f"{B}/api/backup/appliance/{backup2_name}", cookie=CJ, csrf=csrf)
    listed_backups_after_selective = curl_json("GET", f"{B}/api/backup/appliance", cookie=CJ)
    check("the safety backup taken during the selective restore is also listed",
          any(b["reason"] == "pre-restore-safety" for b in listed_backups_after_selective.get("backups", [])), listed_backups_after_selective)

    bad_upload = subprocess.run(
        ["curl", "-sk", "-b", CJ, "-H", f"X-CSRF-Token: {csrf}", "-X", "POST",
         f"{B}/api/backup/appliance/upload?filename=corrupt-test.tar",
         "--data-binary", "not a real tar archive"],
        capture_output=True, text=True,
    ).stdout
    bad_upload_json = json.loads(bad_upload) if bad_upload.strip().startswith("{") else {"_raw": bad_upload}
    check("uploading a corrupt archive is rejected", bad_upload_json.get("error") in ("invalid_archive", "archive_too_large"), bad_upload_json)

    if args.backups_dir:
        real_backup_path = os.path.join(args.backups_dir, backup1_name)
        reupload = subprocess.run(
            ["curl", "-sk", "-b", CJ, "-H", f"X-CSRF-Token: {csrf}", "-X", "POST",
             f"{B}/api/backup/appliance/upload?filename=reuploaded-{backup1_name}",
             "--data-binary", f"@{real_backup_path}"],
            capture_output=True, text=True,
        ).stdout
        reupload_json = json.loads(reupload)
        check("re-uploading a real backup archive succeeds", reupload_json.get("status") == "uploaded", reupload_json)
        check("re-uploaded archive's schema_version matches the original", reupload_json.get("backup", {}).get("control_db_schema_version") == preview1.get("control_db_schema_version"), reupload_json)

    # Change live data, then restore backup1 -- must come back exactly, and a safety backup must be taken automatically.
    curl_json("POST", f"{B}/api/local-dns", cookie=CJ, csrf=csrf, body={"name": "post-backup.lan", "record_type": "A", "value": "10.0.0.77", "ttl": 300, "enabled": True})
    before_restore = curl_json("GET", f"{B}/api/local-dns", cookie=CJ)
    check("local-dns has the post-backup record before restoring", any(r["name"] == "post-backup.lan" for r in before_restore["records"]), before_restore)

    restore_result = curl_json("POST", f"{B}/api/backup/appliance/{backup1_name}/restore", cookie=CJ, csrf=csrf)
    check("restore succeeds and reports a safety backup", restore_result.get("status") == "restored" and "safety_backup" in restore_result, restore_result)

    after_restore = curl_json("GET", f"{B}/api/local-dns", cookie=CJ)
    check("post-backup record is gone after restoring the earlier backup", not any(r["name"] == "post-backup.lan" for r in after_restore["records"]), after_restore)

    listed_backups_after = curl_json("GET", f"{B}/api/backup/appliance", cookie=CJ)
    check("the automatic pre-restore safety backup is itself listed", any(b["filename"] == restore_result["safety_backup"]["filename"] for b in listed_backups_after["backups"]), listed_backups_after)

    delete_backup = curl_status("DELETE", f"{B}/api/backup/appliance/{backup1_name}", cookie=CJ, csrf=csrf)
    check("deleting a backup returns 200", delete_backup == "200", delete_backup)
    listed_backups_final = curl_json("GET", f"{B}/api/backup/appliance", cookie=CJ)
    check("deleted backup no longer appears in the list", not any(b["filename"] == backup1_name for b in listed_backups_final["backups"]), listed_backups_final)

    # --- Query Log (internal/rawquerylog -- the raw-Parquet compatibility boundary) ---
    if args.query_log_dir:
        # A real, pre-seeded Parquet fixture (go/tests/fixtures/make_query_log_fixture.py)
        # is on disk under the server's own -query-log-dir -- this is a
        # genuine end-to-end read, not just the degraded-path shape.
        ql_all = curl_json("GET", f"{B}/api/analytics/query-log?minutes=1440&limit=50", cookie=CJ)
        check("query-log reads real rows from the raw Parquet fixture", ql_all.get("degraded") is False and len(ql_all.get("rows", [])) >= 3, ql_all)
        check("query-log reports files_considered", ql_all.get("files_considered", 0) > 0, ql_all)

        ql_domain = curl_json("GET", f"{B}/api/analytics/query-log?minutes=1440&domain=acceptance-blocked.example.com.", cookie=CJ)
        check("query-log domain filter matches exactly", all(r["domain"] == "acceptance-blocked.example.com." for r in ql_domain["rows"]) and len(ql_domain["rows"]) == 2, ql_domain)

        ql_blocked = curl_json("GET", f"{B}/api/analytics/query-log?minutes=1440&blocked_only=true", cookie=CJ)
        check("query-log blocked_only filter excludes allowed rows", all(r["blocked"] for r in ql_blocked["rows"]) and len(ql_blocked["rows"]) == 2, ql_blocked)

        ql_client = curl_json("GET", f"{B}/api/analytics/query-log?minutes=1440&client=10.10.10.6", cookie=CJ)
        check("query-log client filter matches exactly", len(ql_client["rows"]) == 1 and ql_client["rows"][0]["domain"] == "acceptance-allowed.example.com.", ql_client)

        ql_search = curl_json("GET", f"{B}/api/analytics/query-log?minutes=1440&search=laptop", cookie=CJ)
        check("query-log search filter matches a substring across fields", len(ql_search["rows"]) == 2 and all(r["client_name"] == "laptop" for r in ql_search["rows"]), ql_search)

        top_blocked = curl_json("GET", f"{B}/api/analytics/top-blocked-domains?minutes=1440&limit=10", cookie=CJ)
        check("top-blocked-domains is real, not the honest-unavailable placeholder", top_blocked.get("degraded") is False, top_blocked)
        check("top-blocked-domains includes the fixture's real blocked domain with the right count",
              any(row[0] == "acceptance-blocked.example.com." and row[1] == 2 for row in top_blocked.get("rows", [])), top_blocked)
    else:
        ql_degraded = curl_json("GET", f"{B}/api/analytics/query-log?minutes=60", cookie=CJ)
        check("query-log honestly reports degraded when -query-log-dir isn't configured", ql_degraded.get("degraded") is True and ql_degraded.get("rows") == [], ql_degraded)

        top_blocked_degraded = curl_json("GET", f"{B}/api/analytics/top-blocked-domains?minutes=60", cookie=CJ)
        check("top-blocked-domains honestly reports degraded when -query-log-dir isn't configured", top_blocked_degraded.get("degraded") is True, top_blocked_degraded)

    # --- Encryption (internal/dnstransports native settings storage + internal/tlscert read-only boundary) ---
    transports_initial = curl_json("GET", f"{B}/api/dns-transports", cookie=CJ)
    check("dns-transports GET returns real defaults", transports_initial.get("dot_port") == 853 and transports_initial.get("doh_path") == "/dns-query", transports_initial)
    check("dnscrypt is honestly never provisioned (no secrets store yet)", transports_initial.get("dnscrypt_identity_provisioned") is False, transports_initial)

    transports_update = curl_json("PUT", f"{B}/api/dns-transports", cookie=CJ, csrf=csrf, body={
        "dot_enabled": True, "dot_port": 8853, "doh_enabled": True, "doh_port": 8443, "doh_path": "/custom-query",
        "doq_enabled": False, "doq_port": 853, "doh3_enabled": False, "doh3_port": 443,
        "dnscrypt_enabled": True, "dnscrypt_port": 5444, "dnscrypt_provider_name": "acceptance.provider.example",
    })
    check("dns-transports PUT round-trips every field", transports_update.get("dot_port") == 8853 and transports_update.get("doh_path") == "/custom-query" and transports_update.get("dnscrypt_provider_name") == "acceptance.provider.example", transports_update)

    transports_reloaded = curl_json("GET", f"{B}/api/dns-transports", cookie=CJ)
    check("dns-transports change actually persisted server-side", transports_reloaded.get("dot_port") == 8853, transports_reloaded)

    transports_bad_port = curl_json("PUT", f"{B}/api/dns-transports", cookie=CJ, csrf=csrf, body={
        "dot_port": 99999, "doh_port": 443, "doh_path": "/dns-query", "doq_port": 853, "doh3_port": 443,
        "dnscrypt_port": 5443, "dnscrypt_provider_name": "x",
    })
    check("dns-transports rejects an out-of-range port", transports_bad_port.get("error") == "validation_error", transports_bad_port)

    if args.tls_cert_status_path:
        tls_status = curl_json("GET", f"{B}/api/tls/status", cookie=CJ)
        check("tls status reads a real certificate from the configured path", tls_status.get("active") is True and tls_status.get("subject"), tls_status)
        check("tls status reports a real validity window", bool(tls_status.get("not_valid_after")), tls_status)
    else:
        tls_status_degraded = curl_json("GET", f"{B}/api/tls/status", cookie=CJ)
        check("tls status honestly reports inactive when -tls-cert-status-path isn't configured", tls_status_degraded.get("active") is False, tls_status_degraded)

    print(f"\n{len([r for r in results if r[1] == PASS])}/{len(results)} checks passed.")


if __name__ == "__main__":
    main()
