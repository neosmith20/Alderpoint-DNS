#!/usr/bin/env python3
"""Regression tests for the encrypted-DNS runtime status model.

Covers the bug where listener_addresses() discarded socket transport (TCP vs
UDP) and kept only the local address, so a TCP DoH/DoT listener on a shared
numeric port (443, 853) could make dnsdist's UDP-only DoH3/DoQ listeners
falsely appear to be "Listening".
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import encryption, webapp  # noqa: E402

STOCK_1_9_15_VERSION = (
    "dnsdist 1.9.15 (Lua 5.1.4 [LuaJIT])\n"
    "Enabled features: AF_XDP cdb dns-over-tls(openssl) "
    "dns-over-https(nghttp2) dnscrypt ebpf fstrm ipcipher libsodium "
    "lmdb protobuf re2 recvmmsg/sendmmsg snmp systemd\n"
)

QUIC_2_1_0_VERSION = (
    "dnsdist 2.1.0 (Lua 5.1.4 [LuaJIT])\n"
    "Enabled features: AF_XDP cdb dns-over-quic dns-over-http3 "
    "dns-over-tls(openssl) dns-over-https(nghttp2) dnscrypt ebpf fstrm "
    "ipcipher libsodium lmdb protobuf re2 recvmmsg/sendmmsg snmp systemd\n"
)

# Realistic `ss -H -ltnup` rows: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
SS_TCP_ONLY = "\n".join(
    [
        "tcp   LISTEN 0 512 0.0.0.0:53   0.0.0.0:*  users:((\"dnsdist\",pid=1,fd=9))",
        "tcp   LISTEN 0 512 [::]:53      [::]:*     users:((\"dnsdist\",pid=1,fd=10))",
        "udp   UNCONN 0 0   0.0.0.0:53   0.0.0.0:*  users:((\"dnsdist\",pid=1,fd=11))",
        "udp   UNCONN 0 0   [::]:53      [::]:*     users:((\"dnsdist\",pid=1,fd=12))",
        "tcp   LISTEN 0 512 0.0.0.0:443  0.0.0.0:*  users:((\"dnsdist\",pid=1,fd=13))",
        "tcp   LISTEN 0 512 [::]:443     [::]:*     users:((\"dnsdist\",pid=1,fd=14))",
        "tcp   LISTEN 0 512 0.0.0.0:853  0.0.0.0:*  users:((\"dnsdist\",pid=1,fd=15))",
        "tcp   LISTEN 0 512 [::]:853     [::]:*     users:((\"dnsdist\",pid=1,fd=16))",
    ]
)

SS_WITH_QUIC_UDP = SS_TCP_ONLY + "\n" + "\n".join(
    [
        "udp   UNCONN 0 0   0.0.0.0:853  0.0.0.0:*  users:((\"dnsdist\",pid=1,fd=17))",
        "udp   UNCONN 0 0   [::]:853     [::]:*     users:((\"dnsdist\",pid=1,fd=18))",
        "udp   UNCONN 0 0   0.0.0.0:443  0.0.0.0:*  users:((\"dnsdist\",pid=1,fd=19))",
        "udp   UNCONN 0 0   [::]:443     [::]:*     users:((\"dnsdist\",pid=1,fd=20))",
    ]
)

SS_IPV6_ONLY_QUIC = "\n".join(
    [
        "tcp   LISTEN 0 512 [::]:53      [::]:*     users:((\"dnsdist\",pid=1,fd=1))",
        "udp   UNCONN 0 0   [::]:53      [::]:*     users:((\"dnsdist\",pid=1,fd=2))",
        "udp   UNCONN 0 0   [::]:853     [::]:*     users:((\"dnsdist\",pid=1,fd=3))",
    ]
)


def _run_side_effect(ss_output: str, version_output: str):
    def _run(command: list[str]):
        if command[:1] == ["ss"]:
            return 0, ss_output
        if command[:1] == ["dnsdist"]:
            return 0, version_output
        return 0, ""

    return _run


def _caps_run_side_effect(version_output: str):
    def _run(command, check=True, env=None, input_text=None):
        return subprocess.CompletedProcess(command, 0, version_output)

    return _run


class ProtocolStatusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-protocol-status-test-"))
        self.old_db_path = encryption.DB_PATH
        encryption.DB_PATH = self.tmp / "alderpointdns.db"

    def tearDown(self) -> None:
        encryption.DB_PATH = self.old_db_path

    def _by_name(self, protocols: list[dict], name: str) -> dict:
        return next(p for p in protocols if p["name"] == name)

    def _protocols(self, ss_output: str, version_output: str, settings: dict | None = None) -> list[dict]:
        if settings:
            encryption.update_settings({**encryption.settings(), **settings})
        with mock.patch.object(webapp, "_ss_listener_dump", return_value=(0, ss_output)), \
             mock.patch.object(webapp, "run", side_effect=_run_side_effect(ss_output, version_output)), \
             mock.patch.object(encryption, "run", side_effect=_caps_run_side_effect(version_output)):
            return webapp.protocol_statuses()

    # -- transport-specific shared-port checks -----------------------------

    def test_tcp_443_listener_does_not_satisfy_doh3(self) -> None:
        protocols = self._protocols(
            SS_TCP_ONLY, QUIC_2_1_0_VERSION, {"doh3_enabled": "1", "doh_enabled": "1"}
        )
        doh3 = self._by_name(protocols, "DoH3")
        self.assertNotEqual(doh3["runtime_status"], "Listening")
        self.assertEqual(doh3["runtime_status"], "Configured but not listening")

    def test_tcp_853_listener_does_not_satisfy_doq(self) -> None:
        protocols = self._protocols(
            SS_TCP_ONLY, QUIC_2_1_0_VERSION, {"doq_enabled": "1", "dot_enabled": "1"}
        )
        doq = self._by_name(protocols, "DoQ")
        self.assertNotEqual(doq["runtime_status"], "Listening")
        self.assertEqual(doq["runtime_status"], "Configured but not listening")

    def test_udp_443_required_for_doh3_listening(self) -> None:
        protocols = self._protocols(SS_WITH_QUIC_UDP, QUIC_2_1_0_VERSION, {"doh3_enabled": "1"})
        doh3 = self._by_name(protocols, "DoH3")
        self.assertEqual(doh3["runtime_status"], "Listening")

    def test_udp_853_required_for_doq_listening(self) -> None:
        protocols = self._protocols(SS_WITH_QUIC_UDP, QUIC_2_1_0_VERSION, {"doq_enabled": "1"})
        doq = self._by_name(protocols, "DoQ")
        self.assertEqual(doq["runtime_status"], "Listening")

    def test_dot_tcp_and_doh_tcp_still_report_listening_when_shared_udp_ports_absent(self) -> None:
        protocols = self._protocols(SS_TCP_ONLY, QUIC_2_1_0_VERSION, {"doh_enabled": "1", "dot_enabled": "1"})
        self.assertEqual(self._by_name(protocols, "DoH")["runtime_status"], "Listening")
        self.assertEqual(self._by_name(protocols, "DoT")["runtime_status"], "Listening")

    # -- IPv4/IPv6 --------------------------------------------------------

    def test_ipv6_only_listener_satisfies_doq_when_ipv4_is_disabled(self) -> None:
        protocols = self._protocols(
            SS_IPV6_ONLY_QUIC, QUIC_2_1_0_VERSION, {"doq_enabled": "1", "listen_ipv4": "", "listen_ipv6": "::"}
        )
        self.assertEqual(self._by_name(protocols, "DoQ")["runtime_status"], "Listening")

    def test_ipv6_only_listener_is_partial_when_ipv4_still_expected(self) -> None:
        protocols = self._protocols(
            SS_IPV6_ONLY_QUIC, QUIC_2_1_0_VERSION, {"doq_enabled": "1", "listen_ipv4": "0.0.0.0", "listen_ipv6": "::"}
        )
        self.assertEqual(self._by_name(protocols, "DoQ")["runtime_status"], "Degraded")

    # -- unsupported build --------------------------------------------------

    def test_unsupported_build_reports_both_protocols_unsupported(self) -> None:
        protocols = self._protocols(SS_TCP_ONLY, STOCK_1_9_15_VERSION)
        doq = self._by_name(protocols, "DoQ")
        doh3 = self._by_name(protocols, "DoH3")
        self.assertFalse(doq["available"])
        self.assertFalse(doh3["available"])
        self.assertEqual(doq["runtime_status"], "Unavailable")
        self.assertEqual(doh3["runtime_status"], "Unavailable")
        self.assertEqual(doq["build_support"], "Not supported by installed dnsdist")
        self.assertEqual(doq["verification"], "Capability detection tested")

    # -- supported build, settings disabled ---------------------------------

    def test_supported_build_with_settings_disabled_reports_available_disabled(self) -> None:
        protocols = self._protocols(SS_TCP_ONLY, QUIC_2_1_0_VERSION)
        doq = self._by_name(protocols, "DoQ")
        self.assertTrue(doq["available"])
        self.assertEqual(doq["build_support"], "Available")
        self.assertEqual(doq["runtime_status"], "Disabled")
        self.assertNotEqual(doq["runtime_status"], "Listening")
        self.assertEqual(doq["verification"], "Not run")

    # -- supported build, enabled, no socket ---------------------------------

    def test_supported_build_enabled_without_socket_is_configured_not_listening(self) -> None:
        protocols = self._protocols(SS_TCP_ONLY, QUIC_2_1_0_VERSION, {"doh3_enabled": "1"})
        doh3 = self._by_name(protocols, "DoH3")
        self.assertEqual(doh3["runtime_status"], "Configured but not listening")

    # -- supported build, correct socket present -----------------------------

    def test_supported_build_with_udp_socket_reports_listening(self) -> None:
        protocols = self._protocols(SS_WITH_QUIC_UDP, QUIC_2_1_0_VERSION, {"doh3_enabled": "1", "doq_enabled": "1"})
        self.assertEqual(self._by_name(protocols, "DoH3")["runtime_status"], "Listening")
        self.assertEqual(self._by_name(protocols, "DoQ")["runtime_status"], "Listening")

    # -- no raw internal strings rendered ------------------------------------

    def test_no_raw_internal_strings_rendered(self) -> None:
        protocols = self._protocols(SS_WITH_QUIC_UDP, QUIC_2_1_0_VERSION, {"doh3_enabled": "1", "doq_enabled": "1"})
        banned = {"acceptance-covered", "config-validated", "unavailable in build"}
        for protocol in protocols:
            for value in (protocol["build_support"], protocol["runtime_status"], protocol["verification"]):
                self.assertNotIn(value, banned)

    # -- listener_addresses transport parsing --------------------------------

    def test_listener_addresses_preserves_transport(self) -> None:
        with mock.patch.object(webapp, "_ss_listener_dump", return_value=(0, SS_WITH_QUIC_UDP)):
            listeners = webapp.listener_addresses()
        self.assertIn(("tcp", "0.0.0.0:443"), listeners)
        self.assertIn(("udp", "0.0.0.0:443"), listeners)
        self.assertNotIn(("udp", "0.0.0.0:443"), {("tcp", "0.0.0.0:443")})

    def test_listener_addresses_not_truncated_by_shared_run_helper(self) -> None:
        # Regression: webapp.run() keeps only the last 4000 characters of
        # subprocess output. A real `ss -H -ltnup` on a host with a normal
        # number of other listening services can exceed that, silently
        # dropping early lines -- including a real UDP 53/443/853 listener
        # -- if listener_addresses() ever routed through run() again.
        padding = "\n".join(f"tcp   LISTEN 0 128 127.0.0.1:{20000 + i} 0.0.0.0:*  users:((\"pad\",pid=1,fd={i}))" for i in range(200))
        big_output = padding + "\n" + SS_WITH_QUIC_UDP
        self.assertGreater(len(big_output), 4000)
        with mock.patch.object(webapp, "_ss_listener_dump", return_value=(0, big_output)):
            listeners = webapp.listener_addresses()
        self.assertIn(("udp", "0.0.0.0:443"), listeners)
        self.assertIn(("udp", "0.0.0.0:853"), listeners)
        self.assertIn(("tcp", "0.0.0.0:53"), listeners)


if __name__ == "__main__":
    unittest.main()
