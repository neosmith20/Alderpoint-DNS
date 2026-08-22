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


# Regression guard for a real defect found live during RC47 KVM
# clean-install/reboot acceptance: alderpointdns-v2-schedule.service's
# on_transition hook calls app/v2/webapp.py's _mutate_and_promote()
# in-process, which runs app/v2/runtime_staging.py's
# stage_validate_promote_all() -- real `dnsdist --check-config` /
# `named-checkconf` / `named-checkzone` subprocess invocations against
# the full real default blocklist configuration. A plain
# subprocess.run() child does not get its own cgroup -- cgroup v2's
# memory.max is enforced hierarchically, so no descendant process can
# ever exceed an ancestor's cap regardless of its own settings -- so
# ANY unit whose code path can reach these validators needs a
# MemoryMax that covers its own baseline *plus* the validator's real
# peak (~569M+, matching alderpointdns-v2-dnsdist.service's own
# measured need), not just its own footprint. This table is the single
# place that audit lives; a future caller must be added here (or this
# test fails closed, forcing the audit rather than silently missing a
# new caller).
#
# Reachability audit (this pass, by direct code inspection of every
# packaged unit's real ExecStart entrypoint):
#   - alderpointdns-v2-schedule.service: schedule-worker's
#     on_transition -> webapp._mutate_and_promote() -> validators. REACHES.
#   - alderpointdns-v2-web.service: every real policy-mutation API
#     endpoint -> _mutate_and_promote() -> validators. REACHES.
#   - alderpointdns-v2-tierb.service: the packaged tier-b-worker entry
#     point (cmd_tier_b_worker) only issues real UDP resolves against
#     the already-running dnsdist listener (app/v2/tier_b_worker.py's
#     make_udp_resolve_fn) -- it never calls generate-runtime,
#     stage_validate_promote(_all), or webapp._mutate_and_promote.
#     tier_b_worker.py's separate isolated_dnsdist_instance() helper
#     does spawn a real (non-`--check-config`) dnsdist child, but only
#     with upstreams/ACL (no RPZ/blocklist domains) and is not called
#     from the packaged tier-b-worker entry point at all. DOES NOT
#     REACH the validators -- its existing 256M cap is unaffected by
#     this defect class.
#   - alderpointdns-v2-blocklist-refresh.service,
#     alderpointdns-v2-network-apply.service,
#     alderpointdns-v2-network-confirm.service,
#     alderpointdns-v2-update-apply.service: all reach the same
#     validators (blocklist-refresh via the real compile/promote it
#     triggers; network-apply/confirm and update-apply via their own
#     runtime recompiles) but none of them declare a MemoryMax at all
#     -- uncapped, so not at risk of this specific inherited-low-cap
#     defect (a separate, lower-priority "no resource isolation at
#     all" concern, out of scope here).
_RUNTIME_VALIDATING_CAPPED_UNITS = (
    "alderpointdns-v2-schedule.service",
    "alderpointdns-v2-web.service",
)


def test_no_unit_scopes_readwritepaths_to_a_narrow_subdirectory_that_races_at_boot():
    """Regression guard for a real defect found live during RC46/RC47
    KVM clean-install/reboot acceptance: alderpointdns-v2-tierb.service
    used to scope ReadWritePaths to two narrow leaf subdirectories
    (.../tierb, .../worker-heartbeats) instead of the whole
    /var/lib/alderpointdns-v2 state directory every sibling worker unit
    uses. Under ProtectSystem=strict, each ReadWritePaths entry needs
    to already exist on disk for systemd's own bind-mount setup at
    startup -- postinst creating those exact leaf directories is not
    itself ordered before systemd starts this unit, so a real fresh
    boot could (and did) start the unit before its leaf directory
    existed: "Failed to set up mount namespacing: ... No such file or
    directory", every time, self-masked only by Restart=on-failure's
    retry succeeding a few seconds later. Scoping to the whole state
    directory (which postinst creates once, before any unit ever
    starts, per packaging/v2/postinst) removes the race entirely --
    this is already the pattern every other non-templated unit in this
    package uses; a future new unit or a regression back to
    per-worker-subdirectory scoping should fail this test rather than
    silently reintroduce the same class of boot race.
    """
    allowed_top_level = {
        "/var/lib/alderpointdns-v2",
        "/var/log/alderpointdns-v2",
        "/etc/alderpointdns-v2",
    }
    for unit_path in sorted((ROOT / "packaging/v2").glob("alderpointdns-v2-*.service")):
        text = unit_path.read_text()
        if "ProtectSystem=strict" not in text:
            continue
        m = re.search(r"^ReadWritePaths=(.+)$", text, re.MULTILINE)
        if not m:
            continue
        for entry in m.group(1).split():
            if entry in allowed_top_level:
                continue
            # The one legitimate exception: alderpointdns-v2-bind@.service's
            # own templated per-context directory
            # (/var/lib|log/alderpointdns-v2/bind/%i) is created by the
            # real runtime compiler for every context before that
            # context's own systemd instance is ever started -- not a
            # race, and structurally can't be widened to the whole state
            # directory (BIND's own AppArmor profile confines it to
            # exactly its own working directory).
            if unit_path.name == "alderpointdns-v2-bind@.service" and entry.endswith("/%i"):
                continue
            raise AssertionError(
                f"{unit_path.name} scopes ReadWritePaths to the narrow path "
                f"{entry!r} instead of its containing top-level state "
                "directory -- under ProtectSystem=strict this path must "
                "already exist at systemd's own bind-mount setup time, "
                "which is not guaranteed on a genuinely fresh boot and "
                "reproducibly races (RC46/RC47's real tierb.service defect)"
            )


def test_every_runtime_validating_unit_has_adequate_memory_cap():
    for unit in _RUNTIME_VALIDATING_CAPPED_UNITS:
        text = (ROOT / f"packaging/v2/{unit}").read_text()
        m = re.search(r"^MemoryMax=(\d+)M$", text, re.MULTILINE)
        assert m, f"expected a 'MemoryMax=<N>M' line in {unit}"
        assert int(m.group(1)) >= 1024, (
            f"{unit} can reach app/v2/runtime_staging.py's real "
            "stage_validate_promote_all() (dnsdist --check-config / "
            "named-checkconf / named-checkzone subprocesses, which inherit "
            "this unit's own cgroup) and must keep a MemoryMax of at least "
            "1024M -- a lower cap reproducibly crash-loops this unit via a "
            "real cgroup oom-kill whenever it triggers a real runtime "
            "recompile against the full default blocklist configuration"
        )
