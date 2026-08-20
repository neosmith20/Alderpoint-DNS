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
