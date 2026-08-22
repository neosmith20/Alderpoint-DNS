"""Regression guard for a real defect class found live during rc45
clean-install/purge acceptance testing (beta-rescue continuation):
packaging/v2/postinst's V2_SERVICES list (every unit the package
enables/starts at install time) drifted out of sync with
packaging/v2/prerm's stop list and packaging/v2/postrm's disable
list -- Network Configuration's two new .path units
(alderpointdns-v2-network-apply.path, alderpointdns-v2-network-confirm.path)
were added to postinst but never added to prerm/postrm, so a real
`apt-get remove`/`apt-get purge` left them "not-found active waiting"
in systemd's own view (unit files deleted by dpkg, but systemd never
told to stop/disable them first).

This is a real defect only a real clean-install-then-purge test could
have caught (confirmed live in this session: `systemctl list-units`
after a real purge showed exactly this state) -- this test makes the
underlying invariant (every unit postinst enables is also stopped in
prerm and disabled in postrm) statically checkable without needing a
live container for every future packaging change.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _v2_services() -> set[str]:
    postinst = (ROOT / "packaging/v2/postinst").read_text()
    m = re.search(r'^V2_SERVICES="([^"]+)"', postinst, re.MULTILINE)
    assert m, "packaging/v2/postinst must define V2_SERVICES=\"...\""
    return set(m.group(1).split())


def _units_in_systemctl_line(script_text: str, verb: str) -> set[str]:
    m = re.search(rf"systemctl {verb} ([^\n]+?) >/dev/null", script_text)
    assert m, f"expected a 'systemctl {verb} ...' line in this script"
    return set(m.group(1).split())


def test_every_enabled_unit_is_stopped_in_prerm():
    services = _v2_services()
    prerm = (ROOT / "packaging/v2/prerm").read_text()
    stopped = _units_in_systemctl_line(prerm, "stop")
    missing = services - stopped
    assert not missing, (
        f"packaging/v2/postinst's V2_SERVICES enables {sorted(missing)} but "
        "packaging/v2/prerm never stops them -- a real `apt-get remove` would "
        "leave them running/loaded after their unit files are deleted"
    )


def test_every_enabled_unit_is_disabled_in_postrm_remove_and_purge():
    services = _v2_services()
    postrm = (ROOT / "packaging/v2/postrm").read_text()
    # postrm has two `systemctl disable ...` lines (remove case, purge case).
    disable_lines = re.findall(r"systemctl disable ([^\n]+?) >/dev/null", postrm)
    assert len(disable_lines) == 2, "expected exactly one 'systemctl disable' line each for the remove and purge cases in packaging/v2/postrm"
    for i, line in enumerate(disable_lines):
        disabled = set(line.split())
        missing = services - disabled
        assert not missing, (
            f"packaging/v2/postinst's V2_SERVICES enables {sorted(missing)} but "
            f"packaging/v2/postrm's disable line #{i + 1} never disables them -- "
            "a real `apt-get remove`/`apt-get purge` would leave them "
            "'not-found active' in systemd's own view"
        )


def test_dnsdist_reload_path_has_no_ordering_cycle_with_dnsdist_service():
    """Regression guard for a real defect found live during RC46 KVM
    clean-install/reboot acceptance: alderpointdns-v2-dnsdist-reload.path
    used to declare `After=alderpointdns-v2-dnsdist.service`. Combined
    with every normal unit's implicit default dependency on
    basic.target (which paths.target, and therefore this .path unit
    itself, is part of) and alderpointdns-v2-bind@.service's own
    `Before=alderpointdns-v2-dnsdist.service`, this created a genuine
    systemd ordering cycle on every real fresh boot. systemd resolved
    it by *silently deleting* alderpointdns-v2-dnsdist.service's own
    boot-time start job (not failing it -- deleting it), so real DNS
    answering never came up after a genuine reboot, with no
    operator-visible failed-unit signal at all. The sibling
    alderpointdns-v2-bind-reload.path unit never declared this kind of
    ordering and has never hit this; the watch does not need the
    service it watches to already be running before it starts
    watching.
    """
    text = (ROOT / "packaging/v2/alderpointdns-v2-dnsdist-reload.path").read_text()
    directive_lines = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    assert "After=alderpointdns-v2-dnsdist.service" not in directive_lines, (
        "alderpointdns-v2-dnsdist-reload.path must not order itself "
        "After=alderpointdns-v2-dnsdist.service -- combined with "
        "alderpointdns-v2-bind@.service's Before=alderpointdns-v2-dnsdist.service "
        "and every unit's implicit default dependency on basic.target, this "
        "creates a real systemd ordering cycle that silently drops "
        "dnsdist.service's boot-time start job"
    )


def test_dnsdist_service_memory_cap_fits_default_blocklist_configuration():
    """Regression guard for a real defect found live during RC46 KVM
    clean-install acceptance: alderpointdns-v2-dnsdist.service's
    MemoryMax was 512M, sized without measuring dnsdist's own
    steady-state footprint with the real default three-blocklist
    configuration this exact package seeds on first install (AdGuard
    DNS filter + StevenBlack Unified Hosts + HaGeZi Multi Normal,
    ~450k+ combined domains compiled into dnsdist's in-memory
    ruleset). Measured live (MemoryMax temporarily lifted to
    `infinity` on a real fresh KVM install, real DNS traffic still
    flowing): steady state is ~569M RSS before any query-cache growth
    on top of that -- 512M was therefore always going to be exceeded
    by dnsdist's own default configuration, producing an
    unconditional crash loop (real cgroup oom-kill, unbounded restart
    counter, DNS answering never coming up) rather than a
    load-dependent one.
    """
    text = (ROOT / "packaging/v2/alderpointdns-v2-dnsdist.service").read_text()
    m = re.search(r"^MemoryMax=(\d+)M$", text, re.MULTILINE)
    assert m, "expected a 'MemoryMax=<N>M' line in alderpointdns-v2-dnsdist.service"
    assert int(m.group(1)) >= 1024, (
        "alderpointdns-v2-dnsdist.service's MemoryMax must comfortably exceed "
        "the measured ~569M steady-state RSS of the real default three-"
        "blocklist configuration plus query-cache growth headroom -- 512M "
        "reproducibly crash-loops dnsdist via a real cgroup oom-kill on every "
        "fresh install"
    )
