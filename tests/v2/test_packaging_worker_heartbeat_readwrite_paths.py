"""Real defect found live during this pass's own clean-install acceptance
(owner-beta closure item 1/2): alderpointdns-v2-tierb.service's
ReadWritePaths was scoped to only `/var/lib/alderpointdns-v2/tierb` (a
deliberately narrow scope, unlike the other three shared-_run_loop
workers, which already cover the whole state directory -- see that unit
file's own history/comments). app/v2/worker_heartbeat.py writes to
`<state_dir>/worker-heartbeats/<worker>.json`, outside that narrow scope
-- under this unit's own ProtectSystem=strict, tier-b-worker crash-looped
on every single tick with `OSError: [Errno 30] Read-only file system`,
confirmed live in a real `apt-get install` (dpkg's own postinst
`did not reach the active state` check caught it, but only because a
tick was attempted during the install-time promotion). Fixed by adding
the new path explicitly, matching this unit's own narrow-scoping style
rather than widening it to the whole state directory.

This guards the general class: every worker `_run_loop` writes a
heartbeat under `<state_dir>/worker-heartbeats/`, so every packaged unit
that runs one of the four `_run_loop`-based workers must have that path
(or its parent) inside its own ReadWritePaths.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PACKAGING_V2 = REPO_ROOT / "packaging" / "v2"

# unit file -> True if it runs one of the four shared _run_loop workers
# and therefore must be able to write worker-heartbeats/.
HEARTBEAT_WRITING_UNITS = [
    "alderpointdns-v2-tierb.service",
    "alderpointdns-v2-schedule.service",
    "alderpointdns-v2-analytics.service",
    "alderpointdns-v2-discovery.service",
]


def _read_write_paths(unit_file: Path) -> list[str]:
    for line in unit_file.read_text().splitlines():
        if line.startswith("ReadWritePaths="):
            return line.removeprefix("ReadWritePaths=").split()
    return []


class TestHeartbeatWritingUnitsCanWriteTheirHeartbeat:
    @pytest.mark.parametrize("unit_name", HEARTBEAT_WRITING_UNITS)
    def test_read_write_paths_cover_worker_heartbeats_dir(self, unit_name):
        unit_file = PACKAGING_V2 / unit_name
        assert unit_file.exists(), unit_file
        paths = _read_write_paths(unit_file)
        assert paths, f"{unit_name} has no ReadWritePaths= at all"
        state_root = "/var/lib/alderpointdns-v2"
        covered = any(
            p == state_root or p == f"{state_root}/worker-heartbeats" or f"{state_root}/worker-heartbeats".startswith(p + "/")
            for p in paths
        )
        assert covered, f"{unit_name}'s ReadWritePaths {paths} does not cover {state_root}/worker-heartbeats"
