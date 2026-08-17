"""Deterministic, network-free authoritative BIND backend for tests that
need dnsdist to forward to and get a real NOERROR answer from a real
upstream DNS daemon, without depending on outbound internet reachability.

This is a real ``named`` process authoritative for a couple of fixed
test zones -- not a mock/stub -- so tests using it still exercise real
dnsdist -> real backend DNS server behavior end to end. It replaces
reliance on public resolvers (1.1.1.1/9.9.9.9) and real internet domains
(iana.org) for tests whose actual intent is proving dnsdist policy
behavior (routing/blocking/rewrite precedence), not proving outbound
internet connectivity.
"""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

NAMED_INSTALLED = shutil.which("named") is not None

# Debian's named AppArmor profile (enforced by default, confirmed via
# `aa-status`) confines `named` to /etc/bind, /var/lib/bind, and
# /var/cache/bind regardless of the invoking user's own permissions --
# an ordinary tmp directory gets "permission denied" reading its own
# named.conf even as root. /var/lib/bind is the profile's writable,
# non-origin-data location, so the ephemeral per-test config/zone
# directory has to live under it, not under a generic tempdir.
_NAMED_WRITABLE_ROOT = Path("/var/lib/bind")

_ZONES = {
    "iana.org": "93.184.216.34",
    # Authoritative for the whole "example" TLD (wildcarded) rather than
    # just "routed.example" -- policy rules that are supposed to be
    # terminal (REFUSED/NXDOMAIN/custom_ip) never reach this backend at
    # all, but a *lenient* query for the same name (e.g.
    # "parental-block.example") legitimately does reach here and must
    # get a real NOERROR, not a local-only-artifact REFUSED, or a
    # BIND-recursion-disabled non-authoritative answer would falsely
    # collide with the strict side's real REFUSED and mask leakage bugs.
    "example": "203.0.113.77",
}

_ZONE_TEMPLATE = """\
$TTL 300
@   IN  SOA ns.{zone}. hostmaster.{zone}. ( 1 3600 900 604800 300 )
    IN  NS  ns.{zone}.
ns  IN  A   127.0.0.1
@   IN  A   {addr}
*   IN  A   {addr}
"""


def _pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextmanager
def local_authoritative_backend():
    """Yields the ``127.0.0.1:<port>`` address of a live, real, local-only
    authoritative ``named`` instance answering for ``_ZONES``."""
    fallback_tmp = not (_NAMED_WRITABLE_ROOT.is_dir() and os.access(_NAMED_WRITABLE_ROOT, os.W_OK))
    root = Path(tempfile.gettempdir()) if fallback_tmp else _NAMED_WRITABLE_ROOT
    workdir = Path(tempfile.mkdtemp(prefix="apdns-v2-test-named-", dir=str(root)))
    port = _pick_port()

    zones_conf = []
    for zone, addr in _ZONES.items():
        zone_file = workdir / f"{zone}.zone"
        zone_file.write_text(_ZONE_TEMPLATE.format(zone=zone, addr=addr))
        zones_conf.append(
            f'zone "{zone}" {{ type master; file "{zone_file}"; }};'
        )

    conf_path = workdir / "named.conf"
    conf_path.write_text(
        "options {\n"
        f'    directory "{workdir}";\n'
        f"    listen-on port {port} {{ 127.0.0.1; }};\n"
        "    listen-on-v6 { none; };\n"
        "    recursion no;\n"
        "    allow-query { any; };\n"
        f'    pid-file "{workdir / "named.pid"}";\n'
        "};\n"
        + "\n".join(zones_conf)
        + "\n"
    )

    proc = subprocess.Popen(
        ["named", "-c", str(conf_path), "-g", "-f"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        # Wait for the daemon to actually *answer a real query*, not just
        # for the process to start or accept a UDP send() call (send()
        # on a UDP socket "succeeds" locally even if nothing is bound to
        # the destination port yet, which previously let this fixture
        # report ready before named had finished loading zones -- real
        # dnsdist queries in the caller then raced named's own startup).
        # Bounded, local-only -- no network dependency.
        deadline = time.monotonic() + 5.0
        probe_name = next(iter(_ZONES))
        header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        qparts = b"".join(bytes([len(p)]) + p.encode() for p in probe_name.split("."))
        probe_pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("named exited early during test-backend startup")
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.settimeout(0.2)
                s.sendto(probe_pkt, ("127.0.0.1", port))
                s.recvfrom(4096)
                ready = True
            except OSError:
                pass
            finally:
                s.close()
            if ready:
                break
            time.sleep(0.05)
        if not ready:
            raise RuntimeError("named did not answer within the startup deadline")
        yield f"127.0.0.1:{port}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        shutil.rmtree(workdir, ignore_errors=True)
