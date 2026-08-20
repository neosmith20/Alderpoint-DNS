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
"""

from __future__ import annotations

import sys

sys.path.insert(0, "/opt/alderpointdns-v2")

from app.v2 import blocklist_subscriptions as bl  # noqa: E402
from app.v2 import policy_store as store  # noqa: E402
from app.v2 import webapp  # noqa: E402


def main() -> int:
    if not webapp.CONTROL_DB.exists():
        print("control.db not found; nothing to refresh")
        return 0
    with webapp._db() as conn:
        subs = [s for s in store.list_blocklist_subscriptions(conn) if s["enabled"]]
    if not subs:
        print("no enabled subscriptions")
        return 0

    results = {}

    def _mutate(conn):
        for sub in subs:
            results[sub["subscription_id"]] = bl.refresh_subscription(conn, sub["subscription_id"])

    try:
        webapp._mutate_and_promote(_mutate)
    except Exception as exc:  # noqa: BLE001 -- reported, not swallowed
        print(f"refresh/compile/promote failed: {exc}", file=sys.stderr)
        return 1

    failed = False
    for subscription_id, result in results.items():
        print(f"{subscription_id}: {'ok' if result.ok else 'FAILED'} -- {result.message}")
        failed = failed or not result.ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
