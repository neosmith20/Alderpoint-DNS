"""Test-suite alias for the shared outbound-DNS-reachability probe.

See ``app/v2/net_probe.py`` for the real implementation and the
rationale (a naive ``socket.connect()`` reachability check only proves a
route exists, not that packets survive the round trip -- see
docs/v2/handoff-workstream-6-cc-session.md for the stall this caused).
Kept as a thin alias under ``tests/v2`` so test files only need one
import path and so the same probe is shared with the production
migration health-check code that needed the identical fix.
"""

from __future__ import annotations

from app.v2.net_probe import outbound_dns_reachable as network_reachable

__all__ = ["network_reachable"]
