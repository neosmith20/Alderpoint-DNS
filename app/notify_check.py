#!/usr/bin/env python3
"""Periodic evaluation of Alderpoint DNS's "wired" notification event
categories: service up/down/recovered, repeated restarts, blocklist/deploy
failure, backup failure, upstream resolver degraded/all-unavailable, and
replication delayed/failed.

Run by alderpointdns-notify.timer as the unprivileged `alderpointdns`
account -- every check here is read-only (systemctl queries, database
reads), so nothing needs the privileged deploy path. Each check is
edge-detected against app.notifications' notification_check_state table, so
a condition fires once when it starts and once when it clears, not on every
poll (typically every 5 minutes).

TLS certificate expiry, low disk space, and abnormal SERVFAIL rate are
defined event categories (visible and subscribable in System > Notifications)
but intentionally not evaluated here yet -- see docs/known-limitations.md.
"""

from __future__ import annotations

import subprocess

from app import alderpointdns_compiler, analytics, backup, notifications, replication, upstream_dns

SERVICE_UNITS: dict[str, str] = {
    "named": "BIND (named)",
    "dnsdist": "dnsdist",
    "alderpointdns": "Alderpoint DNS web",
    "alderpointdns-analytics": "Analytics collector",
}

REPEATED_RESTART_THRESHOLD = 3


def _systemctl(args: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(["systemctl", *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        return proc.returncode, proc.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)


def _service_state(unit: str) -> str:
    code, out = _systemctl(["is-active", unit])
    return out if code == 0 else "inactive"


def _fire_edge(event_category: str, component: str, currently_bad: bool, summary_bad: str, summary_ok: str, severity: str = "critical") -> None:
    """Dispatches only on state transitions: ok->bad fires the failure
    notification, bad->ok fires a recovery notification, and a state that
    hasn't changed since the last check fires nothing (avoiding a
    notification every single poll for an ongoing problem -- dispatch()'s
    own cooldown/dedup is a second, independent layer of protection on top
    of this)."""
    previous = notifications.get_check_state(event_category, component)
    if currently_bad:
        if previous != "bad":
            notifications.dispatch(event_category, severity, component, summary_bad, recovered=False)
        notifications.set_check_state(event_category, component, "bad")
    else:
        if previous == "bad":
            notifications.dispatch(event_category, severity, component, summary_ok, recovered=True)
        notifications.set_check_state(event_category, component, "ok")


def check_service_availability() -> None:
    for unit, label in SERVICE_UNITS.items():
        state = _service_state(unit)
        _fire_edge(
            "service_unavailable",
            label,
            currently_bad=state != "active",
            summary_bad=f"{label} is not active (systemd state: {state})",
            summary_ok=f"{label} is active again",
            severity="critical",
        )


def check_analytics_writer() -> None:
    """Catches the "active but dead" case: systemd reports the analytics
    unit as active, but its writer thread has stopped making progress (a
    database-lock storm killed it, or it's stuck). analytics.py's own
    writer_loop already notifies and exits nonzero on a genuinely
    unrecoverable failure (so systemd restarts it and this clears on its
    own); this check exists for the gap where the process is still alive
    -- e.g. wedged rather than dead -- but the heartbeat has gone stale."""
    if _service_state("alderpointdns-analytics") != "active":
        # Plain service-down is already covered by check_service_availability.
        return
    health = analytics.writer_health()
    if health["status"] == "unknown":
        return
    bad = health["stale"] or health["status"] == "dead"
    detail = health["detail"] or f"status={health['status']}"
    _fire_edge(
        "service_unavailable",
        "Analytics collector (writer thread)",
        currently_bad=bad,
        summary_bad=f"Analytics service is active but its writer thread is unresponsive: {detail}",
        summary_ok="Analytics writer thread is responsive again",
        severity="critical",
    )


def check_repeated_restarts(threshold: int = REPEATED_RESTART_THRESHOLD) -> None:
    for unit, label in SERVICE_UNITS.items():
        code, out = _systemctl(["show", unit, "--property=NRestarts", "--value"])
        if code != 0:
            continue
        try:
            restarts = int(out.strip())
        except ValueError:
            continue
        previous_raw = notifications.get_check_state("service_repeated_restart", label)
        previous = int(previous_raw) if previous_raw and previous_raw.isdigit() else 0
        if restarts > previous and restarts >= threshold:
            notifications.dispatch(
                "service_repeated_restart",
                "warning",
                label,
                f"{label} has restarted {restarts} times since boot",
                recovered=False,
            )
        notifications.set_check_state("service_repeated_restart", label, str(restarts))


def check_deploy_and_blocklist() -> None:
    alderpointdns_compiler.init_db()
    with alderpointdns_compiler.connect() as conn:
        row = conn.execute("SELECT status, message FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return
    bad = row["status"] != "deployed"
    _fire_edge(
        "deploy_failure",
        "Blocklist/configuration deploy",
        currently_bad=bad,
        summary_bad=f"Latest deployment ended with status {row['status']!r}: {(row['message'] or '')[:200]}",
        summary_ok="Deployment succeeded again",
        severity="critical",
    )


def check_blocklist_sources() -> None:
    """Fires per-source, not just the single deploy-wide check above: an
    individual source can fail to download or stop contributing usable
    rules while the overall deployment still succeeds (the last-known-good
    rules from every other source, and this source's own previous cached
    copy where one exists, are still deployed), so operators need to know
    *which* source is unhealthy and why -- not just that "the deployment"
    is fine."""
    alderpointdns_compiler.init_db()
    with alderpointdns_compiler.connect() as conn:
        sources = alderpointdns_compiler.enabled_sources(conn)
    for source in sources:
        health = alderpointdns_compiler.source_health(source)
        bad = health["state"] in (
            alderpointdns_compiler.HEALTH_ERROR,
            alderpointdns_compiler.HEALTH_USING_CACHED,
            alderpointdns_compiler.HEALTH_UNSUPPORTED_FORMAT,
        )
        reason = source["last_error"] or source["last_warning"] or health["label"]
        detail = reason
        if health["state"] == alderpointdns_compiler.HEALTH_USING_CACHED:
            detail = f"{reason}. Previous compiled copy remains active."
        _fire_edge(
            "blocklist_update_failure",
            source["name"],
            currently_bad=bad,
            summary_bad=detail,
            summary_ok="Source updates and parses cleanly again",
            severity="warning",
        )


def check_backup() -> None:
    with backup.connect() as conn:
        backup.init_db(conn)
        row = conn.execute("SELECT status, message FROM backup_history ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return
    bad = row["status"] != "deployed"
    _fire_edge(
        "backup_failure",
        "Backup",
        currently_bad=bad,
        summary_bad=f"Latest backup ended with status {row['status']!r}: {(row['message'] or '')[:200]}",
        summary_ok="Backup succeeded again",
        severity="warning",
    )


def _latest_resolver_health(conn) -> dict[int, str]:
    rows = conn.execute(
        """
        SELECT resolver_id, health_state FROM upstream_resolver_aggregate_buckets b1
        WHERE bucket_start = (
            SELECT max(bucket_start) FROM upstream_resolver_aggregate_buckets b2 WHERE b2.resolver_id = b1.resolver_id
        )
        """
    ).fetchall()
    return {row["resolver_id"]: row["health_state"] for row in rows}


def check_upstream_resolvers() -> None:
    enabled = upstream_dns.enabled_resolvers()
    if not enabled:
        return
    analytics.init_analytics_db()
    with alderpointdns_compiler.connect() as conn:
        health = _latest_resolver_health(conn)
    down = [r for r in enabled if health.get(r["id"], "unknown") not in ("up", "unknown")]
    all_down = len(down) == len(enabled)
    _fire_edge(
        "resolver_all_unavailable",
        "Upstream resolvers",
        currently_bad=all_down,
        summary_bad="All upstream resolvers are unavailable",
        summary_ok="Upstream resolvers are reachable again",
        severity="critical",
    )
    # Only evaluate "degraded" (partial outage) while not every resolver is
    # down -- that state is already covered, more severely, above.
    degraded = bool(down) and not all_down
    _fire_edge(
        "resolver_degraded",
        "Upstream resolvers",
        currently_bad=degraded,
        summary_bad=f"{len(down)} of {len(enabled)} upstream resolver(s) degraded: {', '.join(r['name'] for r in down)}",
        summary_ok="Upstream resolvers recovered",
        severity="warning",
    )


_HEALTHY_SYNC_STATUSES = {"", "success", "up_to_date", "skipped", "no_generation"}


def check_replication() -> None:
    cfg = replication.settings()
    if cfg.get("role") != "replica":
        return
    status = cfg.get("last_sync_status", "")
    drifted = cfg.get("drift_detected") == "1"
    bad = status not in _HEALTHY_SYNC_STATUSES or drifted
    detail = f"sync status {status!r}" + (" with drift detected" if drifted else "")
    _fire_edge(
        "replication_delayed",
        "Replication",
        currently_bad=bad,
        summary_bad=f"Replication is unhealthy: {detail}",
        summary_ok="Replication is healthy again",
        severity="critical" if status not in _HEALTHY_SYNC_STATUSES else "warning",
    )


CHECKS = (
    check_service_availability,
    check_analytics_writer,
    check_repeated_restarts,
    check_deploy_and_blocklist,
    check_blocklist_sources,
    check_backup,
    check_upstream_resolvers,
    check_replication,
)


def run_all_checks() -> list[str]:
    """Runs every check independently -- one check's failure (e.g. a
    transient systemctl/database error) must never prevent the others from
    running, mirroring app/replication.py's autostart() philosophy."""
    errors = []
    for check in CHECKS:
        try:
            check()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{check.__name__}: {exc}")
    return errors


def main() -> int:
    errors = run_all_checks()
    for error in errors:
        print(f"notify-check: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
