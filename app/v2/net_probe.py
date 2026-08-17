"""Shared "does a real DNS round trip over the outbound network actually
complete" probe.

Used by production code (``migration.py``'s health-check stage) to tell
"the generated runtime is broken" apart from "there is currently no
outbound route at all, so nothing could have answered regardless of
whether the runtime is correct" -- and by the V2 test suite
(``tests/v2/_network_probe.py``) for the same reason. A naive
``socket.connect()`` on a UDP socket only proves a route exists, not that
packets survive the round trip; sandboxes/appliances that silently
black-hole outbound UDP:53 report "reachable" under that check and then
block for a full per-query timeout instead of degrading cleanly.
"""

from __future__ import annotations

import socket
import struct

_PROBE_QNAME = "iana.org"
_PROBE_SERVERS = (("1.1.1.1", 53), ("8.8.8.8", 53))


def _probe_one(host: str, port: int, timeout: float) -> bool:
    header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    qparts = b"".join(bytes([len(p)]) + p.encode() for p in _PROBE_QNAME.split("."))
    pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(4096)
        return len(data) >= 12
    except OSError:
        return False
    finally:
        s.close()


def outbound_dns_reachable(timeout: float = 2.0) -> bool:
    """True only if a real DNS round trip to a public resolver actually
    completes -- not merely if a route to one exists."""
    return any(_probe_one(host, port, timeout) for host, port in _PROBE_SERVERS)
