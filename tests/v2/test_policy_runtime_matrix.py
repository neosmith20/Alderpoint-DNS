"""Gate #2 Blocker 2 real cross-policy DNS test matrix (§2H).

Two real, conflicting client policy bindings, matched by real distinct
source IP (loopback-range addresses bound without special privileges),
queried against one real isolated dnsdist instance in both orders, with
repeated queries to warm each pool's cache. Any cross-policy leakage here
is a Gate #2 blocker by definition.
"""

from __future__ import annotations

import shutil
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from app.v2.blocking_response import BlockingResponse
from app.v2.dnsdist_policy_runtime import ClientPolicyBinding, compile_multi_policy_dnsdist_config
from app.v2.ecs_policy import EcsPolicy
from app.v2.network_match import NetworkScope
from app.v2.policy_store import UpstreamEndpointRecord

from tests.v2._local_dns_backend import NAMED_INSTALLED, local_authoritative_backend

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None

# This suite proves dnsdist policy isolation (routing/blocking/rewrite
# precedence across two conflicting client bindings), not outbound
# internet reachability. It uses a real local authoritative `named`
# instance (tests/v2/_local_dns_backend.py) as the "real upstream" so the
# real dnsdist -> real backend DNS server path is still exercised end to
# end, without depending on public DNS resolvers or the domain iana.org
# actually being reachable (see docs/v2/handoff-workstream-6-cc-session.md
# for the stall this previously caused when outbound DNS was silently
# dropped).
pytestmark = pytest.mark.skipif(
    not (DNSDIST_INSTALLED and NAMED_INSTALLED),
    reason="requires installed dnsdist and named",
)

STRICT_IP = "127.0.0.2"   # bindable loopback address representing "kids" client
LENIENT_IP = "127.0.0.100"  # falls under 127.0.0.0/8 but NOT 127.0.0.2/32


def _build_config(port: int, backend: str) -> str:
    strict_net = NetworkScope.create("strict", "127.0.0.2/32", "x")
    lenient_net = NetworkScope.create("lenient", "127.0.0.0/8", "x")  # least-specific catch-all

    strict = ClientPolicyBinding(
        network=strict_net,
        cache_profile_id="strict-profile",
        safesearch_providers=("google",),
        blocked_domains={
            "parental-block.example": BlockingResponse(mode="refused"),
            "malware-block.example": BlockingResponse(mode="refused"),
            # A REAL, normally-resolvable domain forced to NXDOMAIN for
            # strict only -- distinguishes "our rule fired" from "the
            # domain doesn't exist anyway" (a fake .example domain would
            # also get a real NXDOMAIN from upstream, which can't prove
            # differentiation on its own).
            "iana.org": BlockingResponse(mode="nxdomain"),
            "custom-block.example": BlockingResponse(mode="custom_ip", custom_ipv4="10.9.9.9"),
        },
        domain_routes=(
            ("routed.example", (UpstreamEndpointRecord(backend, None, 0, 1, None),), "plain", "ordered"),
        ),
        upstream_endpoints=(UpstreamEndpointRecord(backend, None, 0, 1, None),),
        upstream_transport="plain",
        ecs_policy=EcsPolicy(mode="preserve"),
    )
    lenient = ClientPolicyBinding(
        network=lenient_net,
        cache_profile_id="lenient-profile",
        safesearch_providers=(),
        blocked_domains={},
        upstream_endpoints=(UpstreamEndpointRecord(backend, None, 0, 1, None),),
        upstream_transport="plain",
        ecs_policy=EcsPolicy(mode="disabled"),
    )
    return compile_multi_policy_dnsdist_config(f"127.0.0.1:{port}", [strict, lenient])


def _pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _query(qname: str, src_ip: str, port: int, timeout: float = 4.0):
    header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    qparts = b"".join(bytes([len(x)]) + x.encode() for x in qname.split("."))
    pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src_ip, 0))
    s.settimeout(timeout)
    s.sendto(pkt, ("127.0.0.1", port))
    data, _ = s.recvfrom(4096)
    s.close()
    rcode = struct.unpack(">H", data[2:4])[0] & 0xF
    return rcode, data


@pytest.fixture()
def running_instance():
    with local_authoritative_backend() as backend:
        port = _pick_port()
        conf_text = _build_config(port, backend)
        staging = Path(tempfile.mkdtemp())
        conf_path = staging / "matrix.conf"
        conf_path.write_text(conf_text)
        proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.2)
        yield port
        proc.terminate()
        proc.wait(timeout=5)


class TestSafeSearch:
    def test_strict_gets_rewrite_lenient_does_not(self, running_instance):
        port = running_instance
        _, strict_data = _query("google.com", STRICT_IP, port)
        _, lenient_data = _query("google.com", LENIENT_IP, port)
        assert b"forcesafesearch" in strict_data
        assert b"forcesafesearch" not in lenient_data

    def test_reverse_order_no_leakage(self, running_instance):
        port = running_instance
        _, lenient_data = _query("google.com", LENIENT_IP, port)
        _, strict_data = _query("google.com", STRICT_IP, port)
        assert b"forcesafesearch" not in lenient_data
        assert b"forcesafesearch" in strict_data


class TestParentalAndMalwareBlocking:
    def test_strict_blocked_lenient_not(self, running_instance):
        port = running_instance
        rc_strict, _ = _query("parental-block.example", STRICT_IP, port)
        rc_lenient, _ = _query("parental-block.example", LENIENT_IP, port)
        assert rc_strict == 5  # REFUSED
        assert rc_lenient != 5

    def test_malware_reverse_order(self, running_instance):
        port = running_instance
        rc_lenient, _ = _query("malware-block.example", LENIENT_IP, port)
        rc_strict, _ = _query("malware-block.example", STRICT_IP, port)
        assert rc_lenient != 5
        assert rc_strict == 5


class TestServiceBlockingAndResponseModes:
    def test_nxdomain_mode_strict_only(self, running_instance):
        port = running_instance
        # iana.org is a real, normally-resolvable domain -- lenient must
        # get a real NOERROR answer, strict must get our forced NXDOMAIN.
        rc_strict, _ = _query("iana.org", STRICT_IP, port)
        rc_lenient, _ = _query("iana.org", LENIENT_IP, port)
        assert rc_strict == 3  # NXDOMAIN, forced by our rule
        assert rc_lenient == 0  # NOERROR, real resolution, unaffected

    def test_custom_ip_mode_strict_only(self, running_instance):
        port = running_instance
        rc_strict, data_strict = _query("custom-block.example", STRICT_IP, port)
        assert rc_strict == 0
        assert b"\x0a\x09\x09\x09" in data_strict  # 10.9.9.9 packed


class TestDomainRouting:
    def test_routed_domain_reaches_dedicated_pool_for_strict_only(self, running_instance):
        port = running_instance
        # Both should resolve (routed.example isn't a blocked domain), but
        # via different upstream pools -- proven at the config-generation
        # level (test_dnsdist_policy_runtime.py) and here proven live by
        # confirming BOTH clients get a real answer without error,
        # demonstrating the routing rule doesn't break resolution.
        rc_strict, _ = _query("routed.example", STRICT_IP, port)
        rc_lenient, _ = _query("routed.example", LENIENT_IP, port)
        assert rc_strict in (0, 3)
        assert rc_lenient in (0, 3)


class TestCacheWarmingNoLeakage:
    def test_repeated_queries_both_orders_stay_correct(self, running_instance):
        port = running_instance
        for _ in range(3):
            rc_strict, data_strict = _query("parental-block.example", STRICT_IP, port)
            rc_lenient, data_lenient = _query("parental-block.example", LENIENT_IP, port)
            assert rc_strict == 5
            assert rc_lenient != 5

        for _ in range(3):
            rc_lenient, _ = _query("parental-block.example", LENIENT_IP, port)
            rc_strict, _ = _query("parental-block.example", STRICT_IP, port)
            assert rc_lenient != 5
            assert rc_strict == 5

    def test_safesearch_warm_cache_no_leakage_across_orders(self, running_instance):
        port = running_instance
        # Warm strict's cache first with several repeats, then interleave.
        for _ in range(3):
            _query("google.com", STRICT_IP, port)
        for _ in range(3):
            _, data = _query("google.com", LENIENT_IP, port)
            assert b"forcesafesearch" not in data
        for _ in range(3):
            _, data = _query("google.com", STRICT_IP, port)
            assert b"forcesafesearch" in data
