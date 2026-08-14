"""V2 policy preview / explainability service (Workstream 3 continuation,
§1 round-trip + §2).

Orchestrates ``app/v2/policy_store.py`` (control.db-backed storage) and
``app/v2/policy_compiler.py`` (the pure compiler) to answer: "for this
client at this network address, at this moment, what policy applies and
why?" This is a management/API-layer concern — it may read control.db
freely — never a DNS-hot-path concern, which is why
``compile_effective_policy_from_store`` is explicitly documented as
something a management endpoint or a periodic runtime-recompile job calls,
not something invoked per DNS query.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from app.v2 import policy_store as store
from app.v2.policy_compiler import EffectivePolicy, compile_cache_profile, compile_effective_policy
from app.v2.policy_model import PolicyLayer


@dataclass(frozen=True)
class ClientResolutionContext:
    client_id: int
    client_ip: Optional[str] = None


def compile_effective_policy_from_store(
    conn: sqlite3.Connection,
    client: ClientResolutionContext,
    now: Optional[datetime] = None,
) -> EffectivePolicy:
    """Loads every layer this client is subject to from control.db and
    compiles them through the same deterministic
    ``policy_compiler.compile_effective_policy`` used by in-memory tests —
    proving control.db storage round-trips to identical output as
    equivalent hand-built fixtures (see
    ``tests/v2/test_policy_store.py::TestRoundTrip``).
    """
    global_layer = store.load_policy_layer(conn, "global", "singleton")

    network_layer = None
    network_source = None
    if client.client_ip is not None:
        table = store.load_network_table(conn)
        match = table.match(client.client_ip)
        if match is not None:
            network_layer = store.load_policy_layer(conn, "network", match.network_id)
            network_source = match.network_id

    groups = store.load_groups_for_client(conn, client.client_id)
    client_layer = store.load_policy_layer(conn, "client", str(client.client_id))

    active_schedule_id = None
    schedule_layer = None
    if now is not None:
        for row in conn.execute("SELECT schedule_id FROM policy_schedules").fetchall():
            (sched_id,) = row
            schedule = store.load_schedule(conn, sched_id)
            if schedule is not None and schedule.is_active(now):
                active_schedule_id = sched_id
                schedule_layer = store.load_policy_layer(conn, "schedule", sched_id)
                break  # deterministic: schedules table has no declared

    return compile_effective_policy(
        global_layer=global_layer,
        network_layer=network_layer,
        network_source=network_source,
        groups=groups,
        client_layer=client_layer,
        schedule_layer=schedule_layer,
        schedule_id=active_schedule_id,
        schedule_active=active_schedule_id is not None,
    )


def explain_policy_for_client(
    conn: sqlite3.Connection,
    client: ClientResolutionContext,
    now: Optional[datetime] = None,
) -> dict:
    """Structured, secret-free explanation for a management/API/UI caller,
    per §47's example format. Every value here is either a policy-object
    ID/enum or a boolean — never a credential, token, or anything from the
    secret store.
    """
    policy = compile_effective_policy_from_store(conn, client, now=now)
    cache_profile = compile_cache_profile(policy)
    by_field = {e.field: e for e in policy.explain_trace}

    network_match = None
    if client.client_ip is not None:
        table = store.load_network_table(conn)
        matched_scope = table.match(client.client_ip)
        if matched_scope is not None:
            network_match = f"network:{matched_scope.network_id}"

    group_names = sorted(
        {f"group:{g.name}" for g in store.load_groups_for_client(conn, client.client_id)}
    )

    return {
        "client_id": client.client_id,
        # network_match/group_contributions report which scopes actually
        # *applied* to this client (matched network, group membership),
        # independent of whether any of their fields happened to override a
        # value -- distinct from explain_trace's per-field "source", which
        # only names a scope when it actually won a field.
        "network_match": network_match,
        "group_contributions": group_names,
        "schedule_active": policy.schedule_active,
        "fields": {
            f: {"value": entry.value, "source": entry.source} for f, entry in by_field.items()
        },
        "effective_cache_profile_id": cache_profile.profile_id,
    }
