#!/usr/bin/env python3
"""Periodic subscribed-Blocklist refresh (beta-rescue priority 3B),
triggered by alderpointdns-v2-blocklist-refresh.timer. Runs as the same
unprivileged alderpointdns-v2 account as the web service -- refreshing a
subscription is exactly the same control.db + compile/promote operation
an operator's own "Refresh now" click performs, nothing privileged.

Reuses app.v2.webapp's own _mutate_and_promote (the exact same compile
path the live web process uses for every other mutation -- encrypted
transports, rndc wiring, BIND contexts, all of it) rather than
reimplementing a second, narrower compile call that could silently drop
configuration a full recompile is supposed to carry forward.

Refreshes every enabled subscription in turn; one subscription's fetch
failure does not stop the others (each is independently recorded via
app/v2/blocklist_subscriptions.py's own safe-failure contract).

Real defect fixed here (owner preview, pre-DoH reliability pass, part 3):
this used to return exit code 1 whenever ANY single subscription failed,
even when every other due subscription succeeded and the orchestration
itself (fetch loop, compile, promote) worked correctly -- systemd then
reported the whole hourly service as FAILED for one bad external feed,
indistinguishable from a real infrastructure problem. Exit code now
reflects the orchestration's own outcome, not any one subscription's:
0 for "ran to completion" (whether every subscription succeeded or some
failed on their own, each recorded independently and safely -- see
blocklist_subscriptions.py's own module docstring on why a failure never
touches previously compiled content), 1 only when the run itself could
not complete (no control.db, or the shared compile/promote step failed).
A per-run summary is also persisted to STATE_DIR/blocklist/last-refresh-
run.json (same atomic-write pattern as app/v2/schedule_runtime.py's own
state file) so /api/health can report a truthful partial/warning state
without any of this ever flipping core appliance health to degraded.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, "/opt/alderpointdns-v2")

from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: E402

from app.v2 import blocklist_subscriptions as bl  # noqa: E402
from app.v2 import policy_store as store  # noqa: E402
from app.v2 import webapp  # noqa: E402


def _persist_run_state(payload: dict) -> None:
    """Atomic write (tmp + os.replace), same pattern as
    app/v2/schedule_runtime.py's own _persist -- this file is read-only,
    best-effort diagnostic state for /api/health; a write failure here
    must never turn into the orchestration's own exit code."""
    try:
        path = webapp.BLOCKLIST_REFRESH_STATE_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / f".{path.name}.tmp"
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        print(f"warning: failed to persist run state: {exc}", file=sys.stderr)


def main() -> int:
    finished_at = datetime.now(timezone.utc).isoformat()
    if not webapp.CONTROL_DB.exists():
        print("control.db not found; nothing to refresh")
        _persist_run_state({
            "finished_at": finished_at, "orchestration_ok": True, "total": 0,
            "succeeded": 0, "failed": 0, "failed_subscriptions": [], "error": None,
        })
        return 0
    now = datetime.now(timezone.utc)
    with webapp._db() as conn:
        all_subs = [s for s in store.list_blocklist_subscriptions(conn) if s["enabled"]]
        default_interval = int(store.blocklist_settings(conn).get("default_interval_seconds") or "86400")
    subs = []
    for sub in all_subs:
        effective = default_interval if sub.get("update_interval_seconds") is None else int(sub.get("update_interval_seconds") or 0)
        if effective <= 0:
            continue
        due_raw = sub.get("next_retry_at") or sub.get("next_update_at") or ""
        if not due_raw:
            subs.append(sub)
            continue
        try:
            due = datetime.fromisoformat(due_raw)
            if due.tzinfo is None:
                due = due.replace(tzinfo=timezone.utc)
        except ValueError:
            subs.append(sub)
            continue
        if due <= now:
            subs.append(sub)
    if not subs:
        print("no enabled subscriptions due")
        _persist_run_state({
            "finished_at": finished_at, "orchestration_ok": True, "total": 0,
            "succeeded": 0, "failed": 0, "failed_subscriptions": [], "error": None,
        })
        return 0

    prepared = {}
    with ThreadPoolExecutor(max_workers=min(3, max(1, len(subs)))) as pool:
        futures = {pool.submit(bl.prepare_refresh, sub, default_interval_seconds=default_interval): sub["subscription_id"] for sub in subs}
        for future in as_completed(futures):
            prepared[futures[future]] = future.result()
    results = {}

    def _mutate(conn):
        for sub in subs:
            sid = sub["subscription_id"]
            try:
                results[sid] = bl.apply_prepared_refresh(conn, prepared[sid])
            except bl.BlocklistSubscriptionError:
                # Real defect fixed here (owner preview, blocklist Delete
                # UI-consistency pass): an operator deleting a
                # subscription in the real, narrow window between this
                # run's own initial due-subscription read and this
                # transaction actually applying its results used to
                # raise uncaught here -- rolling back EVERY subscription
                # in this batch (not just the deleted one) and reporting
                # a full orchestration failure for what is a perfectly
                # legitimate operator action unrelated to any of the
                # others. A subscription that no longer exists by the
                # time its own prepared refresh is applied is simply
                # skipped (not counted as failed -- deleting it was a
                # deliberate choice, not a broken source), same
                # principle as the deleted-row-can't-be-resurrected
                # contract apply_prepared_refresh's own get_blocklist_subscription
                # check already enforces at the single-subscription level.
                print(f"{sid}: skipped -- deleted before this refresh applied")

    try:
        webapp._mutate_and_promote(_mutate)
    except Exception as exc:  # noqa: BLE001 -- a real orchestration/infrastructure failure
        print(f"refresh/compile/promote failed: {exc}", file=sys.stderr)
        _persist_run_state({
            "finished_at": finished_at, "orchestration_ok": False, "total": len(subs),
            "succeeded": 0, "failed": 0, "failed_subscriptions": [], "error": str(exc),
        })
        return 1

    failed_ids = []
    for subscription_id, result in results.items():
        print(f"{subscription_id}: {'ok' if result.ok else 'FAILED'} -- {result.message}")
        if not result.ok:
            failed_ids.append(subscription_id)
    succeeded = len(results) - len(failed_ids)
    if failed_ids:
        print(f"partial: {succeeded}/{len(results)} subscription(s) succeeded; failed: {', '.join(failed_ids)}")
    _persist_run_state({
        "finished_at": finished_at, "orchestration_ok": True, "total": len(results),
        "succeeded": succeeded, "failed": len(failed_ids), "failed_subscriptions": failed_ids, "error": None,
    })
    # Orchestration itself ran to completion either way -- a per-source
    # failure is real, valuable information (visible above, in the
    # subscription's own row, and in the persisted run state health
    # reads), but it is not an infrastructure failure and must not mark
    # this systemd unit "failed" for what is, product-wise, a partial
    # success.
    return 0


if __name__ == "__main__":
    sys.exit(main())
