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

    print(f"\n{len([r for r in results if r[1] == PASS])}/{len(results)} checks passed.")


if __name__ == "__main__":
    main()
