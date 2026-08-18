"""V2 Tier B real worker wiring (Workstream 3 continuation, §23).

Workstream 2 built the Tier B popularity index and rate-limited replay
loop (``app/v2/tier_b_prewarm.py``) but ``run_prewarm``'s ``resolve_fn``
had no real caller. This module supplies one: a real raw-UDP DNS resolver
function plus a helper to spawn a fully isolated, disposable
``dnsdist`` instance (generated + validated via ``app/v2/dnsdist_gen.py``,
listening only on an ephemeral localhost port, forwarding to a real
upstream) that prewarm can replay queries through end-to-end.

This proves "resolve through the normal validated DNS path" (§33) using
the *real* installed dnsdist binary rather than a mock, while remaining
completely isolated from the live v1.1.1 appliance: a fresh subprocess,
a fresh port, a fresh config file, torn down at the end of the caller's
``with`` block. Nothing here is registered as a systemd unit or reachable
from the live listeners.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from app.v2.dnsdist_gen import UpstreamServer, generate_dnsdist_config
from app.v2.network_match import NetworkScope
from app.v2.tier_b_prewarm import WorkingSetEntry

_QTYPE_NUMBERS = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2}

# Real defect found live during the RC13/RC14 continuation
# (docs/v2/prewarm-analytics-pollution-fix.md): prewarm deliberately
# replays every query through the real, live DNS path (this module's
# own docstring, "never a bypass") -- which means the appliance's own
# self-generated cache-warming traffic was indistinguishable, in
# dnsdist's protobuf log, from a real client's traffic: both showed up
# as client "127.0.0.1", silently inflating every dashboard/statistic
# with the appliance's own repeated re-queries of its already-popular
# domains. Sourcing prewarm's UDP socket from a second, dedicated
# loopback address (still real, still local, still goes through the
# actual validated DNS path -- 127.0.0.0/8 is entirely loopback on
# Linux, confirmed live: binding and sending from 127.0.0.2 works
# exactly like 127.0.0.1) gives the analytics pipeline a real,
# reliable signal to recognize and exclude this traffic from
# statistics, without needing any cross-process coordination or
# fragile heuristic.
PREWARM_SOURCE_IP = "127.0.0.2"


def _build_query(qname: str, qtype: str, qid: int) -> bytes:
    # Real defect found and fixed live during this workstream's Tier B
    # cold/prewarm re-verification (docs/v2/tier-b-cache-key-defect-fix.md):
    # dnsdist's real packet cache key is sensitive to the query's AD
    # (Authenticated Data) flag and to EDNS0 presence -- confirmed by
    # exhaustive live reproduction against a real dnsdist instance, not
    # assumed. This function previously always sent flags=0x0100 (RD
    # only, AD=0) with no EDNS0 OPT record at all -- a "raw legacy"
    # query shape essentially no real modern DNS client actually sends
    # (confirmed live: real `dig` -- BIND's, the tool used throughout
    # this whole session -- sets AD=1 and EDNS0 by default). The
    # practical effect: every prewarmed cache entry was inserted under a
    # cache key that typical real client traffic could never match,
    # making Tier B prewarm's own core purpose ("so the first real
    # client query is already a cache hit") silently ineffective for
    # the large majority of real-world client query shapes, despite
    # run_prewarm() correctly reporting "succeeded" throughout (the
    # resolves themselves genuinely succeeded -- they just weren't
    # reusable afterward).
    #
    # Fixed: set AD=1 (matching the confirmed-working real-client shape)
    # and include a minimal EDNS0 OPT record (no DNS Cookie -- Cookies
    # are inherently per-query/per-client and correctly bypass any
    # cache regardless of this fix, and are not sent by default by
    # typical stub resolvers, only by diagnostic tools like dig; a
    # cache entry keyed to a specific client's cookie could never be
    # reused anyway, so there is nothing to fix there). Live-verified:
    # a real `dig +nocookie` query (the realistic modern-stub-resolver
    # shape) now correctly reuses a prewarmed entry built by this exact
    # function, confirmed via dnsdist's own real cache-hits counter.
    flags = 0x0120  # RD (0x0100) + AD (0x0020)
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1)  # ARCOUNT=1 for the EDNS0 OPT record below
    qparts = b"".join(bytes([len(p)]) + p.encode("ascii", "ignore") for p in qname.split("."))
    type_num = _QTYPE_NUMBERS.get(qtype.upper(), 1)
    question = qparts + b"\x00" + struct.pack(">HH", type_num, 1)
    # Minimal EDNS0 OPT record: root name (0x00), TYPE=OPT (41),
    # CLASS=UDP payload size (1232, the modern conservative default --
    # matches app/v2/dnsdist_policy_runtime.py's own DoT/DoH default
    # posture of following current real-world conventions rather than
    # the legacy 512/4096 extremes), extended-RCODE/version/flags=0,
    # RDLENGTH=0 (no options -- deliberately no Cookie, see above).
    opt_rr = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)
    return header + question + opt_rr


def make_udp_resolve_fn(
    server_ip: str, port: int, timeout: float = 2.0
) -> Callable[[WorkingSetEntry], bool]:
    """Real resolve_fn: sends an actual UDP DNS query to ``server_ip:port``
    and returns True iff a response was received before ``timeout``. No
    caching/memoization here -- every call is a genuine query, matching
    Tier A's rejected-shortcut principle (Tier B never fakes a resolve).
    """

    def _resolve(entry: WorkingSetEntry) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            # Bind to the dedicated prewarm source address (see
            # PREWARM_SOURCE_IP) rather than the OS-assigned default
            # (would otherwise be 127.0.0.1, same as ordinary local
            # traffic) -- only meaningful when server_ip is itself
            # loopback, which is the only real deployment shape this
            # worker is ever configured for.
            if server_ip.startswith("127."):
                sock.bind((PREWARM_SOURCE_IP, 0))
            pkt = _build_query(entry.qname, entry.qtype, qid=hash(entry.qname) & 0xFFFF)
            sock.sendto(pkt, (server_ip, port))
            sock.recvfrom(4096)
            return True
        except OSError:
            return False
        finally:
            sock.close()

    return _resolve


@dataclass
class IsolatedDnsdistHandle:
    process: subprocess.Popen
    listen_port: int
    config_path: Path

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


def _pick_free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def isolated_dnsdist_instance(
    staging_dir: Path,
    upstream_address: str,
    binary: str = "dnsdist",
    startup_wait_s: float = 1.0,
):
    """Context manager: generates+validates a minimal dnsdist config
    (listener on an ephemeral localhost port, one upstream server, ACL
    restricted to 127.0.0.1 only), starts it as a disposable subprocess,
    yields an ``IsolatedDnsdistHandle``, and always terminates the process
    on exit -- even if the caller's block raises. Never touches
    /etc/dnsdist, the live dnsdist.service, or any port a real listener
    could plausibly use (ephemeral port assignment via a throwaway bind).
    """
    port = _pick_free_udp_port()
    acl = [NetworkScope.create("localhost-only", "127.0.0.1/32", "test")]
    upstreams = [UpstreamServer("test-upstream", upstream_address)]
    config_text = generate_dnsdist_config(f"127.0.0.1:{port}", acl, upstreams)

    config_path = Path(staging_dir) / "isolated-dnsdist.conf"
    config_path.write_text(config_text, encoding="utf-8")

    proc = subprocess.Popen(
        # --supervised: run in the foreground without opening a console,
        # so this subprocess doesn't background/detach itself and become
        # untracked by the Popen handle we need for teardown.
        [binary, "-C", str(config_path), "--supervised", "--disable-syslog"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    handle = IsolatedDnsdistHandle(process=proc, listen_port=port, config_path=config_path)
    try:
        time.sleep(startup_wait_s)
        if proc.poll() is not None:
            raise RuntimeError(
                f"isolated dnsdist process exited early (code {proc.returncode}); "
                "check config validity with dnsdist --check-config first"
            )
        yield handle
    finally:
        handle.stop()
