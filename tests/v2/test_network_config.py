"""Tests for app/v2/network_config.py (beta-rescue priority 4/"Network
Configuration"): the appliance's own host interface/address config,
distinct from turning Alderpoint into a router. This module is a thin
wrapper that reuses V1's already-tested app/network_config.py wholesale,
redirected to V2's own state namespace -- so these tests exercise the
same real orchestration logic V1's own tests/test_network_config.py
proves, through the wrapper, plus the wrapper-specific redirection and
the V2-only ctl subcommands / webapp routes built on top of it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import network_config as v1nc
from app.v2 import network_config as nc


class TestPathRedirection(unittest.TestCase):
    """The wrapper's whole reason to exist: V1 and V2 network-change
    state must never collide even if both are installed on one host."""

    def test_state_paths_point_at_v2_namespace(self):
        self.assertEqual(nc.STATE_DIR, Path("/var/lib/alderpointdns-v2/network"))
        self.assertEqual(nc.ROLLBACK_STATE_FILE, Path("/var/lib/alderpointdns-v2/network/rollback-state.json"))
        self.assertEqual(nc.ROLLBACK_LOG, Path("/var/log/alderpointdns-v2/network-rollback.log"))
        self.assertEqual(nc.ROLLBACK_SYSTEMD_UNIT, "alderpointdns-v2-network-rollback")

    def test_underlying_v1_module_globals_are_actually_redirected(self):
        # apply_change et al. read these out of app.network_config's own
        # module namespace directly -- if this redirection didn't really
        # retarget the underlying globals, V2 would silently write into
        # V1's live state directory.
        self.assertEqual(v1nc.STATE_DIR, nc.STATE_DIR)
        self.assertEqual(v1nc.ROLLBACK_STATE_FILE, nc.ROLLBACK_STATE_FILE)
        self.assertEqual(v1nc.ROLLBACK_LOG, nc.ROLLBACK_LOG)
        self.assertEqual(v1nc.ROLLBACK_SYSTEMD_UNIT, nc.ROLLBACK_SYSTEMD_UNIT)

    def test_wrapper_functions_are_the_real_v1_functions(self):
        self.assertIs(nc.apply_change, v1nc.apply_change)
        self.assertIs(nc.confirm_change, v1nc.confirm_change)
        self.assertIs(nc.rollback_check, v1nc.rollback_check)
        self.assertIs(nc.validate_proposed, v1nc.validate_proposed)
        self.assertIs(nc.detect_backend, v1nc.detect_backend)

    def test_v2_watchdog_callback_targets_v2s_own_ctl_script(self):
        with mock.patch.object(v1nc, "run") as run_mock:
            unit = nc.schedule_rollback_timer(timeout_seconds=5)
        self.assertTrue(unit.startswith("alderpointdns-v2-network-rollback-"))
        (cmd,), _kwargs = run_mock.call_args
        joined = " ".join(cmd)
        self.assertIn("alderpointdns_v2_ctl.py", joined)
        self.assertIn("network-rollback-check", joined)
        self.assertNotIn("alderpointdns_compiler.py", joined)

    def test_v1_apply_change_uses_v2s_schedule_rollback_timer(self):
        # This is the crux of the whole wrapper: if V1's apply_change
        # ever schedules a watchdog via *its own* compiler-pointing
        # implementation instead of V2's, a real V2 install's pending
        # change would depend on a script that may not even exist.
        self.assertIs(v1nc.schedule_rollback_timer, nc.schedule_rollback_timer)
        self.assertIs(v1nc.cancel_rollback_timer, nc.cancel_rollback_timer)


class ApplyRollbackConfirmThroughWrapperTest(unittest.TestCase):
    """Mirrors tests/test_network_config.py's own ApplyRollbackConfirmTest
    exactly, but drives everything through app.v2.network_config to prove
    the wrapper's real end-to-end orchestration, not just its aliasing."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-v2-network-test-"))
        self.old = {
            "STATE_DIR": v1nc.STATE_DIR,
            "ROLLBACK_STATE_FILE": v1nc.ROLLBACK_STATE_FILE,
            "ROLLBACK_LOG": v1nc.ROLLBACK_LOG,
            "NETWORKD_DROPIN_DIR": v1nc.NETWORKD_DROPIN_DIR,
        }
        v1nc.STATE_DIR = self.tmp / "network"
        v1nc.ROLLBACK_STATE_FILE = v1nc.STATE_DIR / "rollback-state.json"
        v1nc.ROLLBACK_LOG = self.tmp / "log" / "network-rollback.log"
        v1nc.NETWORKD_DROPIN_DIR = self.tmp / "systemd-network"
        v1nc.NETWORKD_DROPIN_DIR.mkdir(parents=True)
        self.existing_unit = v1nc.NETWORKD_DROPIN_DIR / "10-eth0-original.network"
        self.existing_unit.write_text("[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n")
        self.patches = [
            mock.patch.object(v1nc, "detect_backend", return_value={"backend": v1nc.BACKEND_NETWORKD, "ambiguous": False, "detail": "test"}),
            mock.patch.object(v1nc, "list_interfaces", return_value=["eth0"]),
            mock.patch.object(v1nc, "all_local_addresses", return_value=set()),
            mock.patch.object(v1nc, "interface_addresses", return_value={"ipv4": [{"address": "192.168.1.5", "prefixlen": 24}], "ipv6": []}),
            mock.patch.object(v1nc, "default_gateway", return_value="192.168.1.1"),
            mock.patch.object(v1nc, "apply_networkd"),
            mock.patch.object(v1nc, "schedule_rollback_timer", return_value="alderpointdns-v2-network-rollback-test"),
            mock.patch.object(v1nc, "cancel_rollback_timer"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        for key, value in self.old.items():
            setattr(v1nc, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_apply_change_through_v2_wrapper_writes_v2_rollback_state(self):
        result = nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        self.assertEqual(result["backend"], v1nc.BACKEND_NETWORKD)
        state = nc.read_rollback_state()
        self.assertIsNotNone(state)
        self.assertEqual(state["proposed"]["ipv4"]["address"], "192.168.1.10")
        self.assertTrue(str(v1nc.ROLLBACK_STATE_FILE).startswith(str(self.tmp)))

    def test_second_apply_while_pending_is_refused(self):
        nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        with self.assertRaises(nc.NetworkConfigError):
            nc.apply_change("eth0", "static", "192.168.1.20", 24, "192.168.1.1")

    def test_rollback_check_restores_original_and_calls_v2_watchdog_cancel_path(self):
        nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        message = nc.rollback_check()
        self.assertIn("rolled back", message)
        self.assertFalse(nc.ROLLBACK_STATE_FILE.exists())
        self.assertEqual(self.existing_unit.read_text(), "[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n")

    def test_confirm_change_cancels_v2_timer_and_removes_state(self):
        nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        message = nc.confirm_change()
        self.assertIn("confirmed", message)
        self.assertFalse(nc.ROLLBACK_STATE_FILE.exists())
        v1nc.cancel_rollback_timer.assert_called_with("alderpointdns-v2-network-rollback-test")

    def test_apply_failure_triggers_immediate_rollback(self):
        with mock.patch.object(v1nc, "apply_networkd", side_effect=[subprocess.CalledProcessError(1, ["networkctl"], "boom"), None]):
            with self.assertRaises(nc.NetworkConfigError):
                nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")
        self.assertFalse(nc.ROLLBACK_STATE_FILE.exists())

    def test_refuses_on_unsupported_backend(self):
        with mock.patch.object(v1nc, "detect_backend", return_value={"backend": v1nc.BACKEND_UNSUPPORTED, "ambiguous": True, "detail": "ambiguous"}):
            with self.assertRaises(nc.NetworkConfigError):
                nc.apply_change("eth0", "static", "192.168.1.10", 24, "192.168.1.1")


class TestValidateProposedThroughWrapper(unittest.TestCase):
    def setUp(self):
        self.patches = [
            mock.patch.object(v1nc, "list_interfaces", return_value=["eth0"]),
            mock.patch.object(v1nc, "all_local_addresses", return_value=set()),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_rejects_unknown_interface(self):
        with self.assertRaises(nc.NetworkConfigError):
            nc.validate_proposed("eth9", "static", "10.0.0.5", 24, "10.0.0.1", "unchanged", None, None, None)

    def test_accepts_valid_static_config(self):
        # Must not raise.
        nc.validate_proposed("eth0", "static", "10.0.0.5", 24, "10.0.0.1", "unchanged", None, None, None)


class TestHostNetworkMetadata(unittest.TestCase):
    def test_preview_metadata_reports_host_interface_and_filters_podman(self):
        payload = {
            "generated_at": "2026-08-24T04:56:00+00:00",
            "management_interface": "eno1",
            "default_ipv4": {"interface": "eno1", "gateway": "172.16.43.1"},
            "default_ipv6": {},
            "interfaces": [
                {"name": "podman0", "ipv4": [{"address": "10.89.0.1", "prefixlen": 24}], "ipv6": []},
                {"name": "eth0", "ipv4": [{"address": "10.89.0.4", "prefixlen": 24}], "ipv6": []},
                {"name": "eno1", "ipv4": [{"address": "172.16.43.100", "prefixlen": 24}], "ipv6": [{"address": "2001:db8::10", "prefixlen": 64}]},
            ],
            "ipv4_mode": "externally managed",
            "ipv6_mode": "externally managed",
        }
        current = nc._validate_host_metadata(payload)
        self.assertEqual(current["interface"], "eno1")
        self.assertEqual(current["ipv4"]["address"], "172.16.43.100")
        self.assertEqual(current["ipv4"]["gateway"], "172.16.43.1")
        self.assertEqual(current["ipv4"]["mode"], "externally managed")
        self.assertEqual(current["source"]["label"], "Detected from appliance host")
        self.assertNotIn("podman0", current["interfaces"])

    def test_malformed_preview_metadata_is_truthful_failure(self):
        with self.assertRaises(nc.NetworkConfigError):
            nc._validate_host_metadata({"generated_at": "not-a-date", "interfaces": []})


class TestCtlNetworkSubcommands(unittest.TestCase):
    """Exercises the real, packaged scripts/v2/alderpointdns_v2_ctl.py
    entry point's network-apply/network-confirm/network-rollback-check
    subcommands -- the root-owned .path-unit-triggered privileged half
    of Network Configuration -- not just the underlying library."""

    def setUp(self):
        import argparse
        import importlib.util
        import sys

        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-v2-ctl-network-test-"))
        self.env_patches = [
            mock.patch.dict("os.environ", {
                "ALDERPOINTDNS_V2_APP_ROOT": str(self.tmp / "opt"),
                "ALDERPOINTDNS_V2_CONFIG_ROOT": str(self.tmp / "etc"),
                "ALDERPOINTDNS_V2_STATE_ROOT": str(self.tmp / "state"),
                "ALDERPOINTDNS_V2_LOG_ROOT": str(self.tmp / "log"),
            }),
        ]
        for p in self.env_patches:
            p.start()
            self.addCleanup(p.stop)

        for mod in ("alderpointdns_v2_ctl", "app.v2.network_config"):
            sys.modules.pop(mod, None)
        # `from app.v2 import network_config` resolves via getattr() on
        # the already-cached `app.v2` package object before it ever
        # consults sys.modules for the fully-qualified name -- popping
        # sys.modules alone is not enough to force a real re-import with
        # the freshly-patched env vars in effect.
        if hasattr(sys.modules.get("app.v2"), "network_config"):
            delattr(sys.modules["app.v2"], "network_config")
        repo_root = Path(__file__).resolve().parents[2]
        ctl_path = repo_root / "scripts" / "v2" / "alderpointdns_v2_ctl.py"
        spec = importlib.util.spec_from_file_location("alderpointdns_v2_ctl", ctl_path)
        self.ctl = importlib.util.module_from_spec(spec)
        sys.modules["alderpointdns_v2_ctl"] = self.ctl
        spec.loader.exec_module(self.ctl)
        self.argparse = argparse

        self.nc = self.ctl.v2_network_config
        self.assertEqual(self.nc.STATE_DIR, self.tmp / "state" / "network")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_network_apply_reads_request_writes_matching_result(self):
        payload = {
            "interface": "eth0", "ipv4_mode": "static", "ipv4_address": "192.168.1.10",
            "ipv4_prefix": 24, "ipv4_gateway": "192.168.1.1", "requested_at": "2026-08-20T00:00:00Z",
        }
        self.ctl.NETWORK_APPLY_REQUEST_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.ctl.NETWORK_APPLY_REQUEST_FILE.write_text(json.dumps(payload))
        fake_result = {"backend": "networkd", "rollback_unit": "u", "rollback_deadline": "later"}
        with mock.patch.object(self.nc, "apply_change", return_value=fake_result) as apply_mock:
            rc = self.ctl.cmd_network_apply(self.argparse.Namespace())
        self.assertEqual(rc, 0)
        apply_mock.assert_called_once()
        _args, kwargs = apply_mock.call_args
        self.assertEqual(kwargs["interface"], "eth0")
        self.assertEqual(kwargs["ipv4_address"], "192.168.1.10")
        result = json.loads(self.ctl.NETWORK_APPLY_RESULT_FILE.read_text())
        self.assertEqual(result["requested_at"], "2026-08-20T00:00:00Z")
        self.assertEqual(result["status"], "done")
        self.assertEqual(result["result"], fake_result)

    def test_network_apply_failure_is_reported_not_crashed(self):
        payload = {"interface": "eth0", "ipv4_mode": "static", "requested_at": "t1"}
        self.ctl.NETWORK_APPLY_REQUEST_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.ctl.NETWORK_APPLY_REQUEST_FILE.write_text(json.dumps(payload))
        with mock.patch.object(self.nc, "apply_change", side_effect=self.nc.NetworkConfigError("boom")):
            rc = self.ctl.cmd_network_apply(self.argparse.Namespace())
        self.assertEqual(rc, 1)
        result = json.loads(self.ctl.NETWORK_APPLY_RESULT_FILE.read_text())
        self.assertEqual(result["status"], "failed")
        self.assertIn("boom", result["error"])

    def test_network_confirm_reads_request_writes_matching_result(self):
        self.ctl.NETWORK_CONFIRM_REQUEST_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.ctl.NETWORK_CONFIRM_REQUEST_FILE.write_text(json.dumps({"requested_at": "t2"}))
        with mock.patch.object(self.nc, "confirm_change", return_value="confirmed: eth0"):
            rc = self.ctl.cmd_network_confirm(self.argparse.Namespace())
        self.assertEqual(rc, 0)
        result = json.loads(self.ctl.NETWORK_CONFIRM_RESULT_FILE.read_text())
        self.assertEqual(result["requested_at"], "t2")
        self.assertEqual(result["status"], "done")

    def test_network_rollback_check_calls_through(self):
        with mock.patch.object(self.nc, "rollback_check", return_value="nothing to roll back") as rb_mock:
            rc = self.ctl.cmd_network_rollback_check(self.argparse.Namespace())
        self.assertEqual(rc, 0)
        rb_mock.assert_called_once()


class TestWebappNetworkRoutes(unittest.TestCase):
    def setUp(self):
        import importlib
        import sys

        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-v2-webapp-network-test-"))
        self.env_patches = [
            mock.patch.dict("os.environ", {
                "ALDERPOINTDNS_V2_APP_ROOT": str(self.tmp / "opt"),
                "ALDERPOINTDNS_V2_CONFIG_ROOT": str(self.tmp / "etc"),
                "ALDERPOINTDNS_V2_STATE_ROOT": str(self.tmp / "state"),
                "ALDERPOINTDNS_V2_COOKIE_SECURE": "0",
            }),
        ]
        for p in self.env_patches:
            p.start()
            self.addCleanup(p.stop)

        from app.v2 import control_db, policy_store

        (self.tmp / "state").mkdir(parents=True, exist_ok=True)
        control_db.initialize(self.tmp / "state" / "control.db")
        policy_store.ensure_schema(self.tmp / "state" / "control.db")
        for mod in ("app.v2.webapp", "app.v2.network_config"):
            sys.modules.pop(mod, None)
        if hasattr(sys.modules.get("app.v2"), "network_config"):
            delattr(sys.modules["app.v2"], "network_config")
        self.webapp = importlib.import_module("app.v2.webapp")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _client(self):
        from fastapi.testclient import TestClient

        client = TestClient(self.webapp.app)
        client.post("/api/setup", json={"username": "admin", "password": "correcthorsebattery12", "confirm_password": "correcthorsebattery12"})
        r = client.post("/api/login", json={"username": "admin", "password": "correcthorsebattery12"})
        return client, r.json()["csrf"]

    def test_status_route_reports_current_and_no_pending_change(self):
        client, _csrf = self._client()
        from app.v2 import network_config as nc

        with mock.patch.object(nc, "read_current_config", return_value={"interface": "eth0"}):
            r = client.get("/api/network/status")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["current"], {"interface": "eth0"})
        self.assertIsNone(body["pending"])

    def test_apply_route_rejects_invalid_payload_without_touching_privileged_marker(self):
        client, csrf = self._client()
        from app.v2 import network_config as nc

        with mock.patch.object(nc, "validate_proposed", side_effect=nc.NetworkConfigError("unknown interface")):
            r = client.post(
                "/api/network/apply",
                json={"interface": "eth9", "ipv4_mode": "static", "ipv4_address": "10.0.0.5", "ipv4_prefix": 24, "ipv4_gateway": "10.0.0.1"},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(r.status_code, 400)
        self.assertFalse((nc.STATE_DIR / "apply-requested.json").exists())

    def test_apply_route_stages_request_marker_for_the_privileged_path_unit(self):
        client, csrf = self._client()
        from app.v2 import network_config as nc

        with mock.patch.object(nc, "validate_proposed"), mock.patch.object(nc, "read_rollback_state", return_value=None):
            r = client.post(
                "/api/network/apply",
                json={"interface": "eth0", "ipv4_mode": "static", "ipv4_address": "10.0.0.5", "ipv4_prefix": 24, "ipv4_gateway": "10.0.0.1"},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "apply_requested")
        marker = json.loads((nc.STATE_DIR / "apply-requested.json").read_text())
        self.assertEqual(marker["interface"], "eth0")
        self.assertEqual(marker["ipv4_address"], "10.0.0.5")
        self.assertIn("requested_at", marker)

    def test_apply_route_refuses_when_a_change_is_already_pending(self):
        client, csrf = self._client()
        from app.v2 import network_config as nc

        with mock.patch.object(nc, "validate_proposed"), mock.patch.object(nc, "read_rollback_state", return_value={"interface": "eth0"}):
            r = client.post(
                "/api/network/apply",
                json={"interface": "eth0", "ipv4_mode": "static", "ipv4_address": "10.0.0.5", "ipv4_prefix": 24, "ipv4_gateway": "10.0.0.1"},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(r.status_code, 409)

    def test_confirm_route_requires_a_pending_change(self):
        client, csrf = self._client()
        from app.v2 import network_config as nc

        with mock.patch.object(nc, "read_rollback_state", return_value=None):
            r = client.post("/api/network/confirm", headers={"X-CSRF-Token": csrf})
        self.assertEqual(r.status_code, 400)

    def test_confirm_route_stages_request_marker(self):
        client, csrf = self._client()
        from app.v2 import network_config as nc

        with mock.patch.object(nc, "read_rollback_state", return_value={"interface": "eth0"}):
            r = client.post("/api/network/confirm", headers={"X-CSRF-Token": csrf})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "confirm_requested")
        marker = json.loads((nc.STATE_DIR / "confirm-requested.json").read_text())
        self.assertIn("requested_at", marker)

    def test_unauthenticated_routes_are_rejected(self):
        from fastapi.testclient import TestClient

        client = TestClient(self.webapp.app)
        self.assertEqual(client.get("/api/network/status").status_code, 401)
        self.assertEqual(client.post("/api/network/apply", json={"interface": "eth0"}).status_code, 401)
        self.assertEqual(client.post("/api/network/confirm").status_code, 401)


if __name__ == "__main__":
    unittest.main()
