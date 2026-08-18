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


class TestPrewarmedEntriesAreActuallyReusedByRealClients:
    """Real defect found and fixed live during this workstream's Tier B
    re-verification (docs/v2/tier-b-cache-key-defect-fix.md):
    ``_build_query()`` previously sent a query shape (flags=0x0100, no
    EDNS0) that dnsdist's real packet cache keys differently from what
    real DNS clients actually send (confirmed: AD flag and EDNS0
    presence are both part of the real cache key) -- so a prewarmed
    entry was never reused by realistic client traffic, silently
    defeating Tier B's entire purpose despite ``run_prewarm`` reporting
    success. This class proves the fix with dnsdist's own real
    cache-hit counter, not just "the resolve succeeded.\""""

    def _start_dnsdist_with_cache(self, tmp_path):
        import base64
        import secrets
        import subprocess

        from app.v2.tier_b_worker import _pick_free_udp_port

        dns_port = _pick_free_udp_port()
        console_port = _pick_free_udp_port()
        console_key = base64.b64encode(secrets.token_bytes(32)).decode()
        conf = tmp_path / "cache-reuse-test.conf"
        conf.write_text(
            f'setLocal("127.0.0.1:{dns_port}")\n'
            f'controlSocket("127.0.0.1:{console_port}")\n'
            f'setKey("{console_key}")\n'
            'newServer({address="1.1.1.1:53", pool="p"})\n'
            'pc = newPacketCache(1000, {maxTTL=3600})\n'
            'getPool("p"):setCache(pc)\n'
            'addAction(AllRule(), PoolAction("p"))\n'
        )
        proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.0)
        assert proc.poll() is None, "dnsdist failed to start"
        return proc, dns_port

    def test_prewarmed_entry_is_a_real_cache_hit_for_a_realistic_client_query(self, tmp_path):
        import subprocess

        from app.v2.tier_b_prewarm import WorkingSetIndex
        from app.v2.tier_b_worker import make_udp_resolve_fn

        proc, dns_port = self._start_dnsdist_with_cache(tmp_path)
        try:
            index = WorkingSetIndex(max_entries=10)
            # A real, always-resolvable domain -- avoids any NXDOMAIN-
            # caching-specific edge case muddying this test's real point
            # (positive-answer cache-key compatibility).
            index.record_query("kernel.org", "A", "default")
            entry = index.top(1)[0]
            resolve_fn = make_udp_resolve_fn("127.0.0.1", dns_port, timeout=3.0)
            assert resolve_fn(entry) is True  # real prewarm resolve succeeds

            # A real `dig +nocookie` query -- the realistic modern-stub-
            # resolver shape (EDNS present, no DNS Cookie, AD flag set
            # by BIND dig's own real default) -- checked against
            # dnsdist's own real cache-hits counter below, not inferred
            # from latency.
            subprocess.run(
                ["dig", "@127.0.0.1", "-p", str(dns_port), "kernel.org", "A", "+nocookie", "+time=3", "+tries=1"],
                capture_output=True, timeout=5,
            )

            stats = subprocess.run(
                ["dnsdist", "-C", str(tmp_path / "cache-reuse-test.conf"), "-c"],
                input="dumpStats()", capture_output=True, text=True, timeout=10,
            ).stdout
            hits_lines = [line for line in stats.splitlines() if "cache-hits" in line]
            assert hits_lines, f"could not find cache-hits in dnsdist stats output:\n{stats}"
            hits = int(hits_lines[0].split()[1])
            assert hits >= 1, (
                "a real client query for a name Tier B just prewarmed must be a real "
                f"dnsdist cache hit -- got 0 hits; full stats:\n{stats}"
            )
        finally:
            proc.terminate()
            proc.wait(timeout=5)
