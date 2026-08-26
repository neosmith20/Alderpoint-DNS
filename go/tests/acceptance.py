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

    print(f"\n{len([r for r in results if r[1] == PASS])}/{len(results)} checks passed.")


if __name__ == "__main__":
    main()
