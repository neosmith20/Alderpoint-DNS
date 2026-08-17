"""Regression for a real defect found by hands-on Tier B load testing
(roadmap Priority 6): scripts/v2/alderpointdns_v2_ctl.py's `tier-b-worker`
subcommand -- the actual packaged/systemd-invoked entry point -- used to
build its own inline ``resolve_fn`` that sent a zero-byte UDP packet and
reported success as soon as ``sendto`` didn't raise, never actually
querying DNS or checking a response. It always "succeeded" even against a
port nothing is listening on. This proves the real ``make_udp_resolve_fn``
wiring is what's actually used now: a genuine query against a live
isolated dnsdist instance succeeds, and the exact same call against a
closed port correctly fails -- the previous fake implementation could not
have told these two cases apart.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from app.v2.tier_b_prewarm import WorkingSetEntry, run_prewarm
from app.v2.tier_b_worker import isolated_dnsdist_instance
from tests.v2._network_probe import network_reachable

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None
NETWORK_OK = network_reachable()

pytestmark = pytest.mark.skipif(
    not (DNSDIST_INSTALLED and NETWORK_OK),
    reason="requires installed dnsdist binary and outbound network reachability",
)


class TestTierBWorkerUsesRealResolveFn:
    def test_resolve_fn_actually_resolves_through_real_dnsdist(self, tmp_path):
        """Reproduces exactly what cmd_tier_b_worker's body now does to
        build its resolve_fn: this must be make_udp_resolve_fn (a real
        query, real response check), not the old inline fake."""
        from app.v2.tier_b_worker import make_udp_resolve_fn

        with isolated_dnsdist_instance(tmp_path, "1.1.1.1:53") as handle:
            resolve_fn = make_udp_resolve_fn("127.0.0.1", handle.listen_port, timeout=3.0)
            entries = [
                WorkingSetEntry(
                    qname="example.com", qtype="A", cache_profile_id="p1",
                    last_seen_ts=time.time(), hit_count=1,
                ),
            ]
            stats = run_prewarm(entries, resolve_fn, max_total_names=10)
            assert stats.attempted == 1
            assert stats.succeeded == 1, "a real dnsdist listener must be reported as a real success"

    def test_resolve_fn_correctly_fails_against_nothing_listening(self):
        """The bug this regresses: the old inline resolve_fn returned True
        here too (a bare UDP sendto to a closed port rarely raises), so it
        could never distinguish a working prewarm target from a dead one.
        """
        from app.v2.tier_b_worker import make_udp_resolve_fn

        resolve_fn = make_udp_resolve_fn("127.0.0.1", 1, timeout=0.5)  # port 1: nothing there
        entries = [
            WorkingSetEntry(
                qname="example.com", qtype="A", cache_profile_id="p1",
                last_seen_ts=time.time(), hit_count=1,
            ),
        ]
        stats = run_prewarm(entries, resolve_fn, max_total_names=10)
        assert stats.attempted == 1
        assert stats.failed == 1

    def test_ctl_module_source_does_not_reintroduce_the_fake_resolve_fn(self):
        """Cheap, direct guard against regressing back to the bug: the
        module source must reference the real make_udp_resolve_fn and must
        not contain the old inline fake's tell (an unconditional `return
        True` inside a bare sendto-then-close resolve helper)."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        source = (repo_root / "scripts" / "v2" / "alderpointdns_v2_ctl.py").read_text()
        assert "make_udp_resolve_fn" in source
        # The old fake defined `def resolve_fn(entry) -> bool:` inline
        # inside cmd_tier_b_worker; that name/shape must be gone.
        assert "def resolve_fn(entry) -> bool:" not in source
