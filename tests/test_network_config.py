#!/usr/bin/env python3
"""Tests for app/network_config.py: backend detection, validation, config
rendering, and the apply/rollback/confirm state machine.

These tests never touch a real network interface -- every subprocess call
that would (networkctl, netplan, nmcli, ifup/ifdown, systemd-run) is
patched. Real live-interface reconfiguration (task section 16's TEST A/
TEST B) requires a disposable VM/container/network namespace and is
explicitly out of scope for this unit suite; see docs/network-configuration.md
for what remains to be verified there before production rollout.
"""
from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import network_config as nc  # noqa: E402


class NetworkConfigTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-network-test-"))
        self.old = {
            "STATE_DIR": nc.STATE_DIR,
            "ROLLBACK_STATE_FILE": nc.ROLLBACK_STATE_FILE,
            "ROLLBACK_LOG": nc.ROLLBACK_LOG,
            "NETWORKD_DROPIN_DIR": nc.NETWORKD_DROPIN_DIR,
            "NETPLAN_DIR": nc.NETPLAN_DIR,
            "NETPLAN_FILE": nc.NETPLAN_FILE,
            "IFUPDOWN_INTERFACES": nc.IFUPDOWN_INTERFACES,
            "IFUPDOWN_DROPIN_DIR": nc.IFUPDOWN_DROPIN_DIR,
            "DB_PATH": nc.DB_PATH,
            "CONFIG_FILES_TO_AUDIT": nc.CONFIG_FILES_TO_AUDIT,
        }
        nc.STATE_DIR = self.tmp / "network"
        nc.ROLLBACK_STATE_FILE = nc.STATE_DIR / "rollback-state.json"
        nc.ROLLBACK_LOG = self.tmp / "log" / "network-rollback.log"
        nc.NETWORKD_DROPIN_DIR = self.tmp / "systemd-network"
        nc.NETPLAN_DIR = self.tmp / "netplan"
        nc.NETPLAN_FILE = nc.NETPLAN_DIR / "90-alderpointdns.yaml"
        nc.IFUPDOWN_INTERFACES = self.tmp / "interfaces"
        nc.IFUPDOWN_DROPIN_DIR = self.tmp / "interfaces.d"
        nc.DB_PATH = self.tmp / "alderpointdns.db"
        nc.CONFIG_FILES_TO_AUDIT = [self.tmp / "named.conf", self.tmp / "dnsdist.conf"]

    def tearDown(self) -> None:
        for key, value in self.old.items():
            setattr(nc, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)


class BackendDetectionTest(NetworkConfigTestBase):
    def test_detects_networkd_when_only_networkd_active(self) -> None:
        with mock.patch.object(nc.shutil, "which", return_value=None), \
                mock.patch.object(nc, "_systemctl_is_active", side_effect=lambda u: u == "systemd-networkd.service"):
            info = nc.detect_backend()
        self.assertEqual(info["backend"], nc.BACKEND_NETWORKD)
        self.assertFalse(info["ambiguous"])

    def test_detects_networkmanager_when_only_nm_active(self) -> None:
        with mock.patch.object(nc.shutil, "which", return_value=None), \
                mock.patch.object(nc, "_systemctl_is_active", side_effect=lambda u: u == "NetworkManager.service"):
            info = nc.detect_backend()
        self.assertEqual(info["backend"], nc.BACKEND_NETWORKMANAGER)

    def test_detects_netplan_when_yaml_present_and_binary_available(self) -> None:
        nc.NETPLAN_DIR.mkdir(parents=True)
        (nc.NETPLAN_DIR / "01-netcfg.yaml").write_text("network:\n  version: 2\n")
        with mock.patch.object(nc.shutil, "which", return_value="/usr/sbin/netplan"), \
                mock.patch.object(nc, "_systemctl_is_active", side_effect=lambda u: u == "systemd-networkd.service"):
            info = nc.detect_backend()
        # Netplan takes precedence over the raw networkd renderer beneath it.
        self.assertEqual(info["backend"], nc.BACKEND_NETPLAN)
        self.assertFalse(info["ambiguous"])

    def test_detects_ifupdown_when_interfaces_file_present_and_nothing_else_active(self) -> None:
        nc.IFUPDOWN_INTERFACES.write_text("auto lo\niface lo inet loopback\n")
        with mock.patch.object(nc.shutil, "which", return_value=None), \
                mock.patch.object(nc, "_systemctl_is_active", return_value=False):
            info = nc.detect_backend()
        self.assertEqual(info["backend"], nc.BACKEND_IFUPDOWN)

    def test_no_backend_detected_is_unsupported_not_ambiguous(self) -> None:
        with mock.patch.object(nc.shutil, "which", return_value=None), \
                mock.patch.object(nc, "_systemctl_is_active", return_value=False):
            info = nc.detect_backend()
        self.assertEqual(info["backend"], nc.BACKEND_UNSUPPORTED)
        self.assertFalse(info["ambiguous"])

    def test_networkmanager_and_networkd_both_active_is_ambiguous(self) -> None:
        with mock.patch.object(nc.shutil, "which", return_value=None), \
                mock.patch.object(nc, "_systemctl_is_active", return_value=True):
            info = nc.detect_backend()
        self.assertEqual(info["backend"], nc.BACKEND_UNSUPPORTED)
        self.assertTrue(info["ambiguous"])


class ValidationTest(NetworkConfigTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.list_patch = mock.patch.object(nc, "list_interfaces", return_value=["eth0", "eth1"])
        self.addresses_patch = mock.patch.object(nc, "all_local_addresses", return_value=set())
        self.list_patch.start()
        self.addresses_patch.start()
        self.addCleanup(self.list_patch.stop)
        self.addCleanup(self.addresses_patch.stop)

    def test_rejects_unknown_interface(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed("eth9", "static", "192.168.1.10", 24, "192.168.1.1")

    def test_rejects_invalid_ipv4_syntax(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed("eth0", "static", "not-an-ip", 24, "192.168.1.1")

    def test_rejects_invalid_prefix(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed("eth0", "static", "192.168.1.10", 99, "192.168.1.1")

    def test_rejects_invalid_gateway_syntax(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed("eth0", "static", "192.168.1.10", 24, "not-a-gateway")

    def test_rejects_gateway_outside_subnet(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed("eth0", "static", "192.168.1.10", 24, "10.0.0.1")

    def test_accepts_gateway_within_subnet(self) -> None:
        result = nc.validate_proposed("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        self.assertEqual(result["ipv4"]["address"], "192.168.1.10")

    def test_rejects_loopback_address(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed("eth0", "static", "127.0.0.1", 8, "127.0.0.1")

    def test_rejects_multicast_address(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed("eth0", "static", "224.0.0.5", 24, "224.0.0.1")

    def test_rejects_unspecified_address(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed("eth0", "static", "0.0.0.0", 24, "192.168.1.1")

    def test_rejects_collision_with_another_local_interface(self) -> None:
        with mock.patch.object(nc, "all_local_addresses", return_value={"192.168.1.10"}):
            with self.assertRaises(nc.NetworkConfigError):
                nc.validate_proposed("eth0", "static", "192.168.1.10", 24, "192.168.1.1")

    def test_dhcp_mode_does_not_require_address_fields(self) -> None:
        result = nc.validate_proposed("eth0", "dhcp", None, None, None)
        self.assertEqual(result["ipv4_mode"], "dhcp")
        self.assertNotIn("ipv4", result)

    def test_static_ipv6_validates_and_accepts_link_local_gateway(self) -> None:
        result = nc.validate_proposed(
            "eth0", "unchanged", None, None, None,
            ipv6_mode="static", ipv6_address="2001:db8::10", ipv6_prefix=64, ipv6_gateway="fe80::1",
        )
        self.assertEqual(result["ipv6"]["address"], "2001:db8::10")

    def test_rejects_invalid_ipv6_prefix(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed(
                "eth0", "unchanged", None, None, None,
                ipv6_mode="static", ipv6_address="2001:db8::10", ipv6_prefix=200, ipv6_gateway="2001:db8::1",
            )


class ConfigRenderingTest(NetworkConfigTestBase):
    def test_networkd_static_unit_contains_address_and_gateway(self) -> None:
        text = nc._render_networkd_unit("eth0", {"address": "192.168.1.10", "prefix": 24, "gateway": "192.168.1.1"}, "static", None, "unchanged")
        self.assertIn("Name=eth0", text)
        self.assertIn("Address=192.168.1.10/24", text)
        self.assertIn("Gateway=192.168.1.1", text)

    def test_networkd_dhcp_unit_sets_dhcp_ipv4(self) -> None:
        text = nc._render_networkd_unit("eth0", None, "dhcp", None, "unchanged")
        self.assertIn("DHCP=ipv4", text)

    def test_stage_networkd_writes_file_under_dropin_dir(self) -> None:
        path = nc.stage_networkd("eth0", "static", {"address": "192.168.1.10", "prefix": 24, "gateway": "192.168.1.1"}, "unchanged", None)
        self.assertTrue(path.exists())
        self.assertTrue(str(path).startswith(str(nc.NETWORKD_DROPIN_DIR)))

    def test_netplan_yaml_contains_expected_structure(self) -> None:
        text = nc._render_netplan_yaml("eth0", "static", {"address": "192.168.1.10", "prefix": 24, "gateway": "192.168.1.1"}, "unchanged", None)
        import yaml

        parsed = yaml.safe_load(text)
        self.assertIn("192.168.1.10/24", parsed["network"]["ethernets"]["eth0"]["addresses"])
        self.assertFalse(parsed["network"]["ethernets"]["eth0"]["dhcp4"])

    def test_stage_netplan_file_is_owner_only_readable(self) -> None:
        path = nc.stage_netplan("eth0", "dhcp", None, "unchanged", None)
        self.assertEqual(oct(path.stat().st_mode)[-3:], "600")

    def test_ifupdown_static_stanza_has_address_netmask_gateway(self) -> None:
        nc.IFUPDOWN_INTERFACES.write_text("auto lo\niface lo inet loopback\n")
        path = nc.stage_ifupdown("eth0", "static", {"address": "192.168.1.10", "prefix": 24, "gateway": "192.168.1.1"}, "unchanged", None)
        text = path.read_text()
        self.assertIn("address 192.168.1.10", text)
        self.assertIn("netmask 255.255.255.0", text)
        self.assertIn("gateway 192.168.1.1", text)
        self.assertIn("source /etc/network/interfaces.d/*", nc.IFUPDOWN_INTERFACES.read_text())

    def test_ifupdown_does_not_duplicate_source_line(self) -> None:
        nc.IFUPDOWN_INTERFACES.write_text("auto lo\niface lo inet loopback\nsource /etc/network/interfaces.d/*\n")
        nc.stage_ifupdown("eth0", "dhcp", None, "unchanged", None)
        self.assertEqual(nc.IFUPDOWN_INTERFACES.read_text().count("source /etc/network/interfaces.d/*"), 1)


class ApplyRollbackConfirmTest(NetworkConfigTestBase):
    def setUp(self) -> None:
        super().setUp()
        nc.NETWORKD_DROPIN_DIR.mkdir(parents=True)
        self.existing_unit = nc.NETWORKD_DROPIN_DIR / "10-eth0-original.network"
        self.existing_unit.write_text("[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n")
        self.patches = [
            mock.patch.object(nc, "detect_backend", return_value={"backend": nc.BACKEND_NETWORKD, "ambiguous": False, "detail": "test"}),
            mock.patch.object(nc, "list_interfaces", return_value=["eth0"]),
            mock.patch.object(nc, "all_local_addresses", return_value=set()),
            mock.patch.object(nc, "interface_addresses", return_value={"ipv4": [{"address": "192.168.1.5", "prefixlen": 24}], "ipv6": []}),
            mock.patch.object(nc, "default_gateway", return_value="192.168.1.1"),
            mock.patch.object(nc, "apply_networkd"),
            mock.patch.object(nc, "schedule_rollback_timer", return_value="alderpointdns-network-rollback-test"),
            mock.patch.object(nc, "cancel_rollback_timer"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_apply_change_writes_rollback_state_with_snapshot(self) -> None:
        result = nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        self.assertEqual(result["backend"], nc.BACKEND_NETWORKD)
        state = nc.read_rollback_state()
        self.assertIsNotNone(state)
        self.assertIn(str(self.existing_unit), state["snapshot"]["files"])
        self.assertEqual(state["proposed"]["ipv4"]["address"], "192.168.1.10")
        self.assertFalse(state["confirmed"])

    def test_rollback_state_file_permissions_are_restrictive(self) -> None:
        nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        mode = oct(nc.ROLLBACK_STATE_FILE.stat().st_mode)[-3:]
        self.assertEqual(mode, "640")

    def test_second_apply_while_pending_is_refused(self) -> None:
        nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        with self.assertRaises(nc.NetworkConfigError):
            nc.apply_change("eth0", "static", "192.168.1.20", 24, "192.168.1.1")

    def test_rollback_check_restores_original_persistent_config(self) -> None:
        nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        staged = nc.NETWORKD_DROPIN_DIR / "90-alderpointdns-eth0.network"
        self.assertTrue(staged.exists())
        message = nc.rollback_check()
        self.assertIn("rolled back", message)
        self.assertFalse(nc.ROLLBACK_STATE_FILE.exists())
        # The original file is restored verbatim, and the newly-staged file
        # (which didn't exist before this change) is removed.
        self.assertEqual(self.existing_unit.read_text(), "[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n")
        self.assertFalse(staged.exists())

    def test_rollback_check_calls_apply_networkd_to_restore_live_state(self) -> None:
        nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        apply_mock = nc.apply_networkd
        apply_mock.reset_mock()
        nc.rollback_check()
        # Rollback must reconfigure the *live* interface too, not just files.
        apply_mock.assert_called_with("eth0")

    def test_rollback_check_is_noop_when_nothing_pending(self) -> None:
        message = nc.rollback_check()
        self.assertIn("nothing to roll back", message)

    def test_confirm_change_cancels_timer_and_removes_state(self) -> None:
        nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        message = nc.confirm_change()
        self.assertIn("confirmed", message)
        self.assertFalse(nc.ROLLBACK_STATE_FILE.exists())
        nc.cancel_rollback_timer.assert_called_with("alderpointdns-network-rollback-test")

    def test_rollback_check_after_confirm_is_noop(self) -> None:
        nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        nc.confirm_change()
        message = nc.rollback_check()
        self.assertIn("nothing to roll back", message)

    def test_confirm_with_nothing_pending_raises(self) -> None:
        with self.assertRaises(nc.NetworkConfigError):
            nc.confirm_change()

    def test_apply_failure_triggers_immediate_rollback_not_full_timeout(self) -> None:
        with mock.patch.object(nc, "apply_networkd", side_effect=[subprocess.CalledProcessError(1, ["networkctl"], "boom"), None]):
            with self.assertRaises(nc.NetworkConfigError):
                nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        self.assertFalse(nc.ROLLBACK_STATE_FILE.exists())
        self.assertEqual(self.existing_unit.read_text(), "[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n")

    def test_refuses_on_unsupported_backend(self) -> None:
        with mock.patch.object(nc, "detect_backend", return_value={"backend": nc.BACKEND_UNSUPPORTED, "ambiguous": True, "detail": "ambiguous"}):
            with self.assertRaises(nc.NetworkConfigError):
                nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        self.assertFalse(nc.ROLLBACK_STATE_FILE.exists())


class RequestResponseTest(NetworkConfigTestBase):
    def test_process_pending_request_apply_uses_newest_and_skips_older(self) -> None:
        with mock.patch.object(nc, "detect_backend", return_value={"backend": nc.BACKEND_NETWORKD, "ambiguous": False, "detail": "test"}), \
                mock.patch.object(nc, "list_interfaces", return_value=["eth0"]), \
                mock.patch.object(nc, "all_local_addresses", return_value=set()), \
                mock.patch.object(nc, "snapshot_current", return_value={"backend": nc.BACKEND_NETWORKD, "interface": "eth0", "files": {}, "nm_profile": {}}), \
                mock.patch.object(nc, "stage_networkd"), mock.patch.object(nc, "apply_networkd"), \
                mock.patch.object(nc, "schedule_rollback_timer", return_value="unit-x"):
            nc.request_change({"interface": "eth0", "ipv4_mode": "dhcp"})
            nc.request_change({"interface": "eth0", "ipv4_mode": "static", "ipv4_address": "192.168.1.10", "ipv4_prefix": 24, "ipv4_gateway": "192.168.1.1"})
            result = nc.process_pending_request("apply")
        self.assertEqual(result["status"], "done")
        import sqlite3

        conn = sqlite3.connect(nc.DB_PATH)
        statuses = [row[0] for row in conn.execute("SELECT status FROM network_requests ORDER BY id")]
        conn.close()
        self.assertEqual(statuses, ["skipped", "done"])

    def test_process_pending_request_returns_none_when_nothing_pending(self) -> None:
        result = nc.process_pending_request("apply")
        self.assertIsNone(result)


class AuditTest(NetworkConfigTestBase):
    def test_audit_ip_references_finds_matching_files(self) -> None:
        nc.CONFIG_FILES_TO_AUDIT[0].parent.mkdir(parents=True, exist_ok=True)
        nc.CONFIG_FILES_TO_AUDIT[0].write_text('listen-on { 192.168.1.5; };\n')
        nc.CONFIG_FILES_TO_AUDIT[1].write_text('setLocal("0.0.0.0:53")\n')
        hits = nc.audit_ip_references("192.168.1.5")
        self.assertEqual(hits, [str(nc.CONFIG_FILES_TO_AUDIT[0])])

    def test_audit_ip_references_empty_when_no_match(self) -> None:
        nc.CONFIG_FILES_TO_AUDIT[0].parent.mkdir(parents=True, exist_ok=True)
        nc.CONFIG_FILES_TO_AUDIT[0].write_text("nothing relevant here\n")
        self.assertEqual(nc.audit_ip_references("10.0.0.1"), [])


if __name__ == "__main__":
    unittest.main()
