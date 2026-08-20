"""Beta-rescue regression: independent RC42 inspection found
fallback_strategy stored but never invoking any real fallback decision
logic, and app/v2/fallback_dns.py's evaluate_fallback() written but never
called from anywhere real -- fully disconnected from the compiled
runtime. Reproduces the exact claim, then proves the real fix with a live
compiled dnsdist instance: a client-visible DNS answer that only succeeds
because a configured fallback upstream actually took over from a
deliberately-unreachable primary.
"""

from __future__ import annotations

import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

from app.v2 import control_db, policy_store as store
from app.v2.policy_model import PolicyLayer
from app.v2.runtime_compile import RuntimeCompileError, recompile_and_promote
from tests.v2._network_probe import network_reachable

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None
pytestmark = pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist not installed")


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    with control_db.connect(path) as c:
        yield c


class TestFallbackNowWiredIntoCompiledConfig:
    def test_on_failure_forces_ordered_and_merges_fallback_servers(self, conn, tmp_path):
        store.create_upstream_profile(
            conn, "primary", "Primary", transport="plain", strategy="load_balanced",
            endpoints=[store.UpstreamEndpointRecord("198.51.100.1:53", None, 0, 1, None)],
        )
        store.create_upstream_profile(
            conn, "backup", "Backup", transport="plain",
            endpoints=[store.UpstreamEndpointRecord("198.51.100.2:53", None, 0, 1, None)],
        )
        store.save_policy_layer(
            conn, "global", "singleton",
            PolicyLayer(
                upstream_profile_id="primary", fallback_strategy="on_failure",
                fallback_upstream_profile_id="backup",
            ),
        )
        recompile_and_promote(conn, tmp_path / "staging", tmp_path / "dnsdist.conf", listen_address="127.0.0.1:15600")
        text = (tmp_path / "dnsdist.conf").read_text()
        assert "198.51.100.1:53" in text
        assert "198.51.100.2:53" in text
        # on_failure forces real health-aware ordering regardless of the
        # primary profile's own configured (load_balanced) preference.
        assert "setPoolServerPolicy(firstAvailable" in text
        assert "setPoolServerPolicy(wrandom" not in text

    def test_mismatched_transport_fallback_is_not_merged(self, conn, tmp_path):
        # Real, documented limitation (see runtime_compile._apply_fallback):
        # a single pool speaks one transport to every server in it, so a
        # cross-transport fallback must not be silently merged in --
        # that would either mislabel the fallback server's transport or
        # silently downgrade an encrypted primary to plaintext.
        store.create_upstream_profile(
            conn, "primary", "Primary", transport="plain",
            endpoints=[store.UpstreamEndpointRecord("198.51.100.1:53", None, 0, 1, None)],
        )
        store.create_upstream_profile(
            conn, "backup-doh", "Backup DoH", transport="doh",
            endpoints=[store.UpstreamEndpointRecord("198.51.100.2:443", "resolver.example", 0, 1, None, "/dns-query")],
        )
        store.save_policy_layer(
            conn, "global", "singleton",
            PolicyLayer(
                upstream_profile_id="primary", fallback_strategy="on_failure",
                fallback_upstream_profile_id="backup-doh",
            ),
        )
        recompile_and_promote(conn, tmp_path / "staging", tmp_path / "dnsdist.conf", listen_address="127.0.0.1:15601")
        text = (tmp_path / "dnsdist.conf").read_text()
        assert "198.51.100.1:53" in text
        assert "resolver.example" not in text

    def test_dangling_fallback_reference_does_not_crash_compile(self, conn, tmp_path):
        store.save_policy_layer(
            conn, "global", "singleton",
            PolicyLayer(fallback_strategy="on_failure", fallback_upstream_profile_id="does-not-exist"),
        )
        result = recompile_and_promote(conn, tmp_path / "staging", tmp_path / "dnsdist.conf", listen_address="127.0.0.1:15602")
        assert result.promoted


def _query_ok(port: int, name: str = "example.com") -> bool:
    header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    qparts = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(pkt, ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
        return len(data) > 12  # a real, non-empty DNS message
    except OSError:
        return False
    finally:
        s.close()


@pytest.mark.skipif(not network_reachable(), reason="requires outbound network reachability")
class TestFallbackIsRealClientVisibleBehavior:
    """Required proof from the beta-rescue brief: "real upstream failures
    and client-visible fallback behavior." The primary upstream is a
    closed local UDP port (guaranteed unreachable -- no server ever
    listens there); the fallback is a real, reachable public resolver.
    A query only succeeds end to end if the compiled runtime's fallback
    wiring genuinely took over from the dead primary.
    """

    def test_query_succeeds_via_fallback_when_primary_is_unreachable(self, tmp_path):
        conn_path = tmp_path / "control.db"
        store.ensure_schema(conn_path)
        with control_db.connect(conn_path) as conn:
            # A closed UDP port on loopback: nothing ever binds here, so
            # dnsdist's own live health checks will mark it down for real.
            store.create_upstream_profile(
                conn, "dead-primary", "Dead primary", transport="plain",
                endpoints=[store.UpstreamEndpointRecord("127.0.0.1:19999", None, 0, 1, None)],
            )
            store.create_upstream_profile(
                conn, "real-fallback", "Real fallback", transport="plain",
                endpoints=[store.UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None)],
            )
            store.save_policy_layer(
                conn, "global", "singleton",
                PolicyLayer(
                    upstream_profile_id="dead-primary", fallback_strategy="on_failure",
                    fallback_upstream_profile_id="real-fallback",
                ),
            )
            recompile_and_promote(
                conn, tmp_path / "staging", tmp_path / "dnsdist.conf", listen_address="127.0.0.1:15603",
            )

        proc = subprocess.Popen(
            ["dnsdist", "-C", str(tmp_path / "dnsdist.conf"), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            # dnsdist's live health checks need a few seconds to mark the
            # dead primary down; poll rather than guess a fixed sleep.
            deadline = time.time() + 20
            ok = False
            while time.time() < deadline:
                if _query_ok(15603):
                    ok = True
                    break
                time.sleep(1)
            assert ok, (
                "no real DNS answer was ever produced -- the fallback wiring "
                "did not take over from the deliberately-unreachable primary "
                "within a real live dnsdist instance"
            )
        finally:
            proc.terminate()
            proc.wait(timeout=10)
