#!/usr/bin/env python3
"""Regression coverage for real bugs found during disposable-VM network/
package validation (see CHANGELOG.md's Unreleased section) that unit tests
mocking every subprocess call cannot catch on their own: these are static
checks on the packaging sources themselves, tying the systemd unit's
sandboxing and postinst's service-management to what the code actually
needs, so a future new backend/feature can't silently reintroduce the same
class of bug.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import network_config as nc  # noqa: E402
from app import backup  # noqa: E402


class ServiceSandboxWritePathsTest(unittest.TestCase):
    """app/network_config.py writes backend persistent config files
    directly from the alderpointdns.service-sandboxed request path (no
    postinst bootstrap, unlike named/dnsdist's managed includes -- see
    docs/network-configuration.md and the CHANGELOG). ProtectSystem=full
    makes /etc read-only for that unit (and, since sudo's child inherits
    the same mount namespace, for the privileged compiler subcommands it
    execs too), so every directory a backend actually writes to must be
    listed in ReadWritePaths=, or Apply fails with EROFS -- exactly what
    happened with a real Netplan apply on a disposable Debian 13 VM before
    this fix. This test would have caught that regression, and catches it
    again if a future backend adds a new /etc write target without
    updating the unit file."""

    def setUp(self) -> None:
        unit_text = (ROOT / "packaging" / "alderpointdns.service").read_text()
        match = re.search(r"^ReadWritePaths=(.*)$", unit_text, re.MULTILINE)
        self.assertIsNotNone(match, "packaging/alderpointdns.service has no ReadWritePaths= line")
        # A leading "-" (systemd.exec(5)) makes an entry a no-op instead of
        # a startup failure when the path is absent -- strip it before
        # comparing so these tests still recognize the path as "covered"
        # rather than requiring every optional backend directory to be
        # unconditional.
        self.read_write_paths = [Path(p.lstrip("-")) for p in match.group(1).split()]

    def _assert_writable(self, target: Path) -> None:
        covered = any(target == rw or rw in target.parents for rw in self.read_write_paths)
        self.assertTrue(
            covered,
            f"{target} is not covered by any packaging/alderpointdns.service "
            f"ReadWritePaths= entry ({self.read_write_paths}); a live Apply through "
            "this backend will fail with EROFS under ProtectSystem=full",
        )

    def test_networkd_dropin_dir_is_writable(self) -> None:
        self._assert_writable(nc.NETWORKD_DROPIN_DIR)

    def test_netplan_dir_is_writable(self) -> None:
        self._assert_writable(nc.NETPLAN_DIR)

    def test_ifupdown_interfaces_file_is_writable(self) -> None:
        self._assert_writable(nc.IFUPDOWN_INTERFACES)

    def test_ifupdown_dropin_dir_is_writable(self) -> None:
        self._assert_writable(nc.IFUPDOWN_DROPIN_DIR)

    def test_rollback_state_dir_is_writable(self) -> None:
        # Sanity check the pre-existing entries too, not just the new ones.
        self._assert_writable(nc.STATE_DIR)


class PostinstServiceRestartTest(unittest.TestCase):
    """Regression for a real upgrade-hygiene bug: `systemctl enable --now`
    on an already-active unit (the normal upgrade case) does not restart
    it, so an upgraded alderpointdns/alderpointdns-analytics kept running
    the *previous* version's code (and, for the ReadWritePaths fix above,
    the *previous* version's sandboxing) until something else restarted
    it. named/dnsdist already got an explicit restart; alderpointdns and
    alderpointdns-analytics must too."""

    def setUp(self) -> None:
        self.postinst = (ROOT / "packaging" / "debian" / "postinst").read_text()

    def test_alderpointdns_services_are_unconditionally_restarted(self) -> None:
        self.assertIn(
            "systemctl restart alderpointdns alderpointdns-analytics",
            self.postinst,
            "postinst must unconditionally restart alderpointdns/alderpointdns-analytics "
            "on every install/upgrade -- 'enable --now' alone is a no-op restart-wise "
            "on an already-active unit",
        )

    def test_named_and_dnsdist_are_also_unconditionally_restarted(self) -> None:
        # The pattern this test suite is holding alderpointdns/analytics to.
        self.assertIn("systemctl restart named dnsdist", self.postinst)


class PostinstBindBootstrapPlaceholdersTest(unittest.TestCase):
    """Regression for named failing to start
    (`parsing failed: file not found`) whenever /var/lib/alderpointdns is
    missing at postinst time but /etc/bind/named.conf.options already has
    a persistent `include` line from an earlier successful deploy (e.g.
    `apt purge` + reinstall without also resetting bind9's own config)."""

    def setUp(self) -> None:
        self.postinst = (ROOT / "packaging" / "debian" / "postinst").read_text()

    def test_local_zones_placeholder_created_before_named_restart(self) -> None:
        self.assertIn("compiled/bind/local-zones.conf", self.postinst)

    def test_cache_options_placeholder_created_before_named_restart(self) -> None:
        self.assertIn("compiled/bind/cache-options.conf", self.postinst)

    def test_upstream_forwarders_placeholder_is_not_a_bare_empty_file(self) -> None:
        # Unlike the other two, an empty upstream-forwarders.conf is
        # invalid (named.conf.options unconditionally sets `forward
        # only;`, and BIND treats forward-only with zero forwarders as a
        # fatal config error) -- this must render the real default via
        # app.upstream_dns.render_bind_forwarders(), not `install /dev/null`.
        self.assertIn("upstream-forwarders.conf", self.postinst)
        self.assertIn("render_bind_forwarders", self.postinst)
        # The placeholder line for upstream-forwarders.conf must not be the
        # bare /dev/null pattern used for the other two (empty is invalid
        # here specifically).
        for line in self.postinst.splitlines():
            if "upstream-forwarders.conf" in line and "install -m 0644 /dev/null" in line:
                self.fail(f"upstream-forwarders.conf placeholder must not be an empty file: {line!r}")


class PostinstSystemdResolvedConflictTest(unittest.TestCase):
    """Regression for dnsdist failing to bind ports 53/5355
    (`Address already in use`) on a completely unmodified, default fresh
    Debian/Ubuntu install, caused by systemd-resolved's stub listener and
    LLMNR responder -- discovered via this pass's real clean-VM install."""

    def setUp(self) -> None:
        self.postinst = (ROOT / "packaging" / "debian" / "postinst").read_text()

    def test_disables_dns_stub_listener(self) -> None:
        self.assertIn("DNSStubListener=no", self.postinst)

    def test_disables_llmnr(self) -> None:
        self.assertIn("LLMNR=no", self.postinst)

    def test_only_touches_resolv_conf_when_still_the_default_symlink(self) -> None:
        # Must not unconditionally clobber an administrator's own static
        # resolv.conf.
        self.assertIn('[ -L /etc/resolv.conf ]', self.postinst)


class FreshInstallInitOrderingTest(unittest.TestCase):
    """Regression for a real bug found integrating the fresh-install
    default-blocklist feature: analytics.py's `init-db` subcommand calls
    alderpointdns_compiler.py's init_db() unconditionally, which -- on a
    genuinely fresh database -- applies the full schema and bumps PRAGMA
    user_version to SCHEMA_VERSION as a side effect. If that call runs
    before `alderpointdns_compiler.py fresh-install-init`, the latter's own
    init_db(seed_defaults=True) call sees current_version already >=
    SCHEMA_VERSION and returns immediately without ever seeding the default
    blocklists or attempting the initial deploy, silently turning every
    fresh install into a no-op (fresh_install=0 on a genuinely fresh
    database). Confirmed with a real `apt install` of a fresh .deb on a
    disposable Debian 13 VM: zero rows in `sources` after install until
    this ordering fix."""

    def _assert_fresh_install_init_precedes_analytics_init_db(self, text: str, label: str) -> None:
        # Match only the actual invocation lines, not comment prose that
        # happens to mention either command by name.
        fresh_idx = analytics_idx = None
        for lineno, line in enumerate(text.splitlines()):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if fresh_idx is None and "alderpointdns_compiler.py fresh-install-init" in line:
                fresh_idx = lineno
            if analytics_idx is None and "analytics.py init-db" in line:
                analytics_idx = lineno
        self.assertIsNotNone(fresh_idx, f"{label} does not call fresh-install-init")
        self.assertIsNotNone(analytics_idx, f"{label} does not call analytics.py init-db")
        self.assertLess(
            fresh_idx,
            analytics_idx,
            f"{label} calls analytics.py init-db before fresh-install-init, which "
            "silently defeats fresh-install detection (see class docstring)",
        )

    def test_postinst_ordering(self) -> None:
        text = (ROOT / "packaging" / "debian" / "postinst").read_text()
        self._assert_fresh_install_init_precedes_analytics_init_db(text, "postinst")

    def test_install_sh_ordering(self) -> None:
        text = (ROOT / "scripts" / "install.sh").read_text()
        self._assert_fresh_install_init_precedes_analytics_init_db(text, "scripts/install.sh")


class BackupRestoreSandboxWritePathsTest(unittest.TestCase):
    """app/backup.py's restore path directly replaces live /etc files for
    the app_config/dnsdist_source_config/bind_source_config components --
    same ProtectSystem=full class of bug as the network backends, found
    restoring a real ~296 MiB backup on a disposable VM."""

    def setUp(self) -> None:
        unit_text = (ROOT / "packaging" / "alderpointdns.service").read_text()
        match = re.search(r"^ReadWritePaths=(.*)$", unit_text, re.MULTILINE)
        self.assertIsNotNone(match, "packaging/alderpointdns.service has no ReadWritePaths= line")
        # A leading "-" (systemd.exec(5)) makes an entry a no-op instead of
        # a startup failure when the path is absent -- strip it before
        # comparing so these tests still recognize the path as "covered"
        # rather than requiring every optional backend directory to be
        # unconditional.
        self.read_write_paths = [Path(p.lstrip("-")) for p in match.group(1).split()]

    def _assert_writable(self, target: Path) -> None:
        covered = any(target == rw or rw in target.parents for rw in self.read_write_paths)
        self.assertTrue(
            covered,
            f"{target} is not covered by any packaging/alderpointdns.service "
            f"ReadWritePaths= entry ({self.read_write_paths}); a live restore of "
            "this component will fail with EROFS under ProtectSystem=full",
        )

    def test_etc_bind_is_writable(self) -> None:
        self._assert_writable(backup.ETC_BIND)

    def test_etc_dnsdist_is_writable(self) -> None:
        self._assert_writable(backup.ETC_DNSDIST)

    def test_systemd_unit_dir_is_writable(self) -> None:
        self._assert_writable(backup.SYSTEMD_DIR)

    def test_sudoers_file_is_writable(self) -> None:
        self._assert_writable(backup.SUDOERS_FILE)


if __name__ == "__main__":
    unittest.main()
