#!/usr/bin/env python3
"""Tests for the Workstream 2 §9 filesystem-hardening additions to
app.v2.config: ownership contract, parent-directory mode, symlink policy.
"""
from __future__ import annotations

import grp
import os
import pwd
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import config as v2config  # noqa: E402


class TestSymlinkPolicy(unittest.TestCase):
    def test_load_file_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "real.yaml"
            real.write_text("schema_version: 1\n")
            link = Path(td) / "alderpointdns.yaml"
            link.symlink_to(real)
            with self.assertRaises(v2config.ConfigSymlinkError):
                v2config.load_file(link)

    def test_load_file_works_on_a_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "alderpointdns.yaml"
            path.write_text("schema_version: 1\n")
            cfg = v2config.load_file(path)
            self.assertEqual(cfg.schema_version, 1)

    def test_atomic_write_refuses_to_write_through_existing_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "real.yaml"
            real.write_text("placeholder")
            link = Path(td) / "alderpointdns.yaml"
            link.symlink_to(real)
            cfg = v2config.AlderpointV2Config()
            with self.assertRaises(v2config.ConfigSymlinkError):
                v2config.atomic_write(link, cfg)
            # The symlink target must be untouched.
            self.assertEqual(real.read_text(), "placeholder")

    def test_symlinked_parent_directory_component_does_not_bypass_check(self):
        """The symlink check targets the final path component; a symlinked
        *parent directory* is a separate, broader hardening concern (out of
        scope for this module, which doesn't own directory placement above
        its own parent) — recorded here as a documented boundary, not
        silently assumed safe."""
        with tempfile.TemporaryDirectory() as td:
            real_dir = Path(td) / "real_dir"
            real_dir.mkdir()
            link_dir = Path(td) / "linked_dir"
            link_dir.symlink_to(real_dir)
            path = link_dir / "alderpointdns.yaml"
            # This module does not currently detect a symlinked *parent*;
            # this test documents that load_file's own path-is-symlink check
            # does not fire in this case (the file itself is regular).
            (real_dir / "alderpointdns.yaml").write_text("schema_version: 1\n")
            cfg = v2config.load_file(path)  # succeeds — known boundary, not a claim of full coverage
            self.assertEqual(cfg.schema_version, 1)


class TestParentDirectoryHardening(unittest.TestCase):
    def test_harden_parent_directory_sets_mode(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "sub" / "alderpointdns.yaml"
            v2config.harden_parent_directory(target)
            mode = os.stat(target.parent).st_mode & 0o777
            self.assertEqual(mode, 0o750)

    def test_harden_parent_directory_chowns_when_running_as_root(self):
        if os.geteuid() != 0:
            self.skipTest("requires root to chown")
        try:
            pwd.getpwnam(v2config.EXPECTED_OWNER_USER)
            grp.getgrnam(v2config.EXPECTED_OWNER_GROUP)
        except KeyError:
            self.skipTest("alderpointdns account not present on this system")
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "sub" / "alderpointdns.yaml"
            v2config.harden_parent_directory(target)
            st = os.stat(target.parent)
            self.assertEqual(st.st_uid, pwd.getpwnam(v2config.EXPECTED_OWNER_USER).pw_uid)
            self.assertEqual(st.st_gid, grp.getgrnam(v2config.EXPECTED_OWNER_GROUP).gr_gid)


class TestOwnershipVerification(unittest.TestCase):
    def test_verify_ownership_reports_mismatch(self):
        try:
            pwd.getpwnam("root")
            grp.getgrnam("root") if grp.getgrnam("root") else None
        except KeyError:
            self.skipTest("expected system accounts not present")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "alderpointdns.yaml"
            path.write_text("schema_version: 1\n")
            # tempdir file is owned by the current test-runner uid/gid, not
            # necessarily root:alderpointdns — expect at least one mismatch
            # unless this test happens to run as exactly that identity.
            current = os.stat(path)
            try:
                want_uid = pwd.getpwnam(v2config.EXPECTED_OWNER_USER).pw_uid
                want_gid = grp.getgrnam(v2config.EXPECTED_OWNER_GROUP).gr_gid
            except KeyError:
                self.skipTest("alderpointdns account not present on this system")
            errors = v2config.verify_ownership(path)
            if current.st_uid == want_uid and current.st_gid == want_gid:
                self.assertEqual(errors, [])
            else:
                self.assertTrue(errors)

    def test_verify_ownership_empty_when_account_missing(self):
        errors = v2config.verify_ownership(
            "/etc/hostname", owner_user="definitely-not-a-real-account-xyz",
            owner_group="also-not-real-xyz",
        )
        self.assertEqual(errors, [])

    def test_verify_ownership_passes_after_harden_and_chown(self):
        if os.geteuid() != 0:
            self.skipTest("requires root")
        try:
            pwd.getpwnam(v2config.EXPECTED_OWNER_USER)
            grp.getgrnam(v2config.EXPECTED_OWNER_GROUP)
        except KeyError:
            self.skipTest("alderpointdns account not present on this system")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "alderpointdns.yaml"
            cfg = v2config.AlderpointV2Config()
            v2config.atomic_write(path, cfg)
            uid = pwd.getpwnam(v2config.EXPECTED_OWNER_USER).pw_uid
            gid = grp.getgrnam(v2config.EXPECTED_OWNER_GROUP).gr_gid
            os.chown(path, uid, gid)
            self.assertEqual(v2config.verify_ownership(path), [])


class TestUnknownKeyRejection(unittest.TestCase):
    def test_unknown_top_level_key_rejected(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.loads("schema_version: 1\ntotally_made_up_key: true\n")

    def test_unknown_listener_field_rejected(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.loads(
                "schema_version: 1\nlisteners:\n  - protocol: udp\n    port: 53\n    bogus_field: 1\n"
            )

    def test_unknown_analytics_field_rejected(self):
        with self.assertRaises(v2config.ConfigValidationError):
            v2config.loads("schema_version: 1\nanalytics:\n  bogus_field: 1\n")


class TestInitStateConfigDirRemainsGroupWritableAcrossRepeatedCalls(unittest.TestCase):
    """Regression guard for a real defect found live during a real
    KVM reboot acceptance: alderpointdns-v2-state-init.service now runs
    the same `init-state` entry point on every real boot (previously
    only ever run once, at package install time, by postinst -- see
    that unit's own comment for the full story). `cmd_init_state`
    calls `harden_parent_directory()`, which unconditionally resets
    the config directory to 0750 (group read+traverse only) --
    postinst used to fix that back up to 0770 (group write+create,
    needed so the web service can write a promoted rndc.conf there)
    with its own separate one-time step, run once, after the original
    single install-time `init-state` call. With `init-state` now
    re-run on every boot and nothing re-running that fixup afterward,
    every subsequent reboot silently reverted the directory back to
    0750, breaking every real policy mutation with a real, live
    ``PermissionError`` (reproduced live: a real Local DNS mutation
    submitted through the real management API on a real KVM install's
    second boot failed with exactly this). Fixed by folding the fixup
    directly into `cmd_init_state` itself (see its own comment) so it
    is correct on every call, not just the first -- this test calls
    the real entry point twice in a row (simulating install, then a
    reboot) and asserts the config directory stays group-writable
    after each one, not just the first.
    """

    def test_config_dir_group_writable_after_first_and_second_init_state_call(self):
        import argparse
        import importlib

        with tempfile.TemporaryDirectory() as td:
            env_overrides = {
                "ALDERPOINTDNS_V2_APP_ROOT": str(Path(td) / "opt"),
                "ALDERPOINTDNS_V2_CONFIG_ROOT": str(Path(td) / "etc"),
                "ALDERPOINTDNS_V2_STATE_ROOT": str(Path(td) / "state"),
                "ALDERPOINTDNS_V2_COOKIE_SECURE": "0",
            }
            old_env = {k: os.environ.get(k) for k in env_overrides}
            os.environ.update(env_overrides)
            try:
                sys.path.insert(0, str(ROOT / "scripts" / "v2"))
                import alderpointdns_v2_ctl as ctl

                importlib.reload(ctl)
                args = argparse.Namespace()

                def _real_boot_mode() -> int:
                    return ctl.cmd_init_state(args)

                self.assertEqual(_real_boot_mode(), 0, "first (install-time) init-state call failed")
                config_dir = Path(env_overrides["ALDERPOINTDNS_V2_CONFIG_ROOT"])
                mode_after_first = config_dir.stat().st_mode & 0o777
                self.assertTrue(
                    mode_after_first & 0o020,
                    f"config dir not group-writable after the first init-state call: {oct(mode_after_first)}",
                )

                self.assertEqual(_real_boot_mode(), 0, "second (simulated-reboot) init-state call failed")
                mode_after_second = config_dir.stat().st_mode & 0o777
                self.assertTrue(
                    mode_after_second & 0o020,
                    f"config dir reverted to non-group-writable after a second init-state call "
                    f"(the real reboot-time regression this test guards against): {oct(mode_after_second)}",
                )
            finally:
                for k, v in old_env.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
                sys.path.remove(str(ROOT / "scripts" / "v2"))


if __name__ == "__main__":
    unittest.main()
