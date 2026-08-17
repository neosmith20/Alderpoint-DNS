import shutil
import time

import pytest

from app.v2.tier_b_prewarm import WorkingSetEntry, run_prewarm
from app.v2.tier_b_worker import isolated_dnsdist_instance, make_udp_resolve_fn
from tests.v2._network_probe import network_reachable

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None

# Uses a real round-trip DNS probe, not just route existence -- a naive
# connect()-only check reports "reachable" even when outbound UDP:53 is
# silently black-holed, which previously let these real-internet-backed
# tests hang for a full per-query timeout instead of skipping cleanly.
# See docs/v2/handoff-workstream-6-cc-session.md.
NETWORK_OK = network_reachable()

pytestmark = pytest.mark.skipif(
    not (DNSDIST_INSTALLED and NETWORK_OK),
    reason="requires installed dnsdist binary and outbound network reachability",
)


class TestIsolatedInstance:
    def test_instance_starts_and_stops_cleanly(self, tmp_path):
        with isolated_dnsdist_instance(tmp_path, "1.1.1.1:53") as handle:
            assert handle.process.poll() is None  # still running
            assert handle.listen_port > 0
        assert handle.process.poll() is not None  # terminated after context exit

    def test_teardown_happens_even_on_exception(self, tmp_path):
        proc_ref = None
        with pytest.raises(RuntimeError):
            with isolated_dnsdist_instance(tmp_path, "1.1.1.1:53") as handle:
                proc_ref = handle.process
                raise RuntimeError("simulated caller failure")
        assert proc_ref.poll() is not None

    def test_isolated_from_live_dnsdist_service(self, tmp_path):
        with isolated_dnsdist_instance(tmp_path, "1.1.1.1:53") as handle:
            # Never binds to a well-known/production port -- ephemeral only.
            assert handle.listen_port >= 1024
            assert handle.listen_port != 53
            assert handle.listen_port != 5300  # not the documented v1 port either


class TestRealResolveFn:
    def test_resolve_returns_true_for_real_query(self, tmp_path):
        with isolated_dnsdist_instance(tmp_path, "1.1.1.1:53") as handle:
            resolve = make_udp_resolve_fn("127.0.0.1", handle.listen_port, timeout=3.0)
            entry = WorkingSetEntry(
                qname="example.com", qtype="A", cache_profile_id="p1",
                last_seen_ts=time.time(), hit_count=1,
            )
            assert resolve(entry) is True

    def test_resolve_returns_false_when_nothing_listening(self):
        resolve = make_udp_resolve_fn("127.0.0.1", 1, timeout=0.5)  # port 1: nothing there
        entry = WorkingSetEntry(
            qname="example.com", qtype="A", cache_profile_id="p1",
            last_seen_ts=time.time(), hit_count=1,
        )
        assert resolve(entry) is False


class TestEndToEndPrewarm:
    def test_run_prewarm_through_real_isolated_dnsdist(self, tmp_path):
        with isolated_dnsdist_instance(tmp_path, "1.1.1.1:53") as handle:
            resolve = make_udp_resolve_fn("127.0.0.1", handle.listen_port, timeout=3.0)
            entries = [
                WorkingSetEntry(
                    qname="example.com", qtype="A", cache_profile_id="p1",
                    last_seen_ts=time.time(), hit_count=5,
                ),
                WorkingSetEntry(
                    qname="cloudflare.com", qtype="A", cache_profile_id="p1",
                    last_seen_ts=time.time(), hit_count=3,
                ),
            ]
            stats = run_prewarm(entries, resolve, max_names_per_second=10.0)
            assert stats.attempted == 2
            assert stats.succeeded == 2
            assert stats.failed == 0
