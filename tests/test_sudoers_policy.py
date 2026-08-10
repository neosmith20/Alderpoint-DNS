#!/usr/bin/env python3
"""Regression coverage for the v1.0.1 RC #2 packaging defect: 04fb660 added
a new `upstream-deploy` sudo invocation to app/webapp.py (routing upstream
add/edit/toggle/move/delete through the scoped upstream-only deploy instead
of the full pipeline) but never added the matching entry to
packaging/sudoers-alderpointdns. On a real packaged install, the
`alderpointdns` service account has no NOPASSWD grant for that exact
command, so `sudo` refuses to run it non-interactively ("sudo: a terminal is
required to read the password") -- the click-Disable failure found during
live RC acceptance on dns1.

Nothing in the existing suite would have caught this: every prior test
either called the compiler functions directly in-process (as root, in a
test sandbox, never through `sudo` at all -- see
tests/test_upstream_deploy_ordering.py, tests/test_upstream_scoped_deploy.py)
or mocked `webapp.run`/`webapp.upstream_deploy` away entirely, so none of
them ever asked "would the real installed sudoers policy actually authorize
this exact command for the real unprivileged service account?". This file
closes that gap two ways:

1. A static, source-level check (`SudoersPolicyCoverageTest`): every literal
   `sudo .../alderpointdns_compiler.py <subcommand ...>` invocation
   app/webapp.py can make must appear, verbatim, as a NOPASSWD entry in
   packaging/sudoers-alderpointdns -- this fails immediately the next time a
   new scoped/single-stage deploy route is wired up in webapp.py without its
   matching sudoers entry, without needing a live install to notice. It also
   asserts the policy stays narrow: no `ALL`, no wildcard/glob commands, no
   grant of the bare interpreter or a shell.
2. A live-boundary check (`SudoersLivePermissionTest`, skipped when this
   host has no `alderpointdns` service account or no installed sudoers
   drop-in -- i.e. it runs on a real packaged install/appliance, not a bare
   dev checkout): for every one of those same commands, `sudo -n -l` *as the
   real alderpointdns account* must report it as permitted. `sudo -n -l
   COMMAND` only *checks* authorization (matching sudo's own privilege
   list) and never actually executes the privileged command, so this is
   safe to run against a live host without side effects -- and it is
   exactly the check that would have caught this defect before it reached
   dns1, since it tests the *installed* /etc/sudoers.d/alderpointdns file
   rather than the packaging source tree.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import service_logs  # noqa: E402

WEBAPP_PY = ROOT / "app" / "webapp.py"
SUDOERS_FILE = ROOT / "packaging" / "sudoers-alderpointdns"
COMPILER_PATH = "/opt/alderpointdns/app/alderpointdns_compiler.py"

# Matches `"sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py"`
# followed by zero or more comma-separated string-literal arguments (a
# trailing non-literal argument, e.g. the `unit` variable in the `logs`
# call, simply isn't captured by this -- handled explicitly below).
CALL_RE = re.compile(
    r'"sudo",\s*"' + re.escape(COMPILER_PATH) + r'"((?:\s*,\s*"[^"]*")*)'
)


def _extract_webapp_sudo_commands() -> set[str]:
    """Every literal `sudo .../alderpointdns_compiler.py ...` command
    app/webapp.py can invoke, as the exact space-joined argument string a
    sudoers NOPASSWD entry must match (everything after the compiler
    path)."""
    source = WEBAPP_PY.read_text()
    commands: set[str] = set()
    for match in CALL_RE.finditer(source):
        literal_args = re.findall(r'"([^"]*)"', match.group(1))
        commands.add(" ".join(literal_args).strip())

    # The `logs` route (fetch_service_log_entries) appends a variable `unit`
    # that CALL_RE can't see as a string literal; it's validated against
    # service_logs.ALLOWED_UNITS before ever reaching the sudo call, so the
    # real, complete set of commands it can produce is one per allowed unit.
    assert "logs" in commands, "expected the bare 'logs' call site to be found by CALL_RE"
    commands.discard("logs")
    for unit in service_logs.ALLOWED_UNITS:
        commands.add(f"logs {unit}")

    # software_updates_check_apply() conditionally appends "--force" to the
    # same `args` list after CALL_RE's match window ends; "update-check" is
    # already captured, add the --force variant it can also produce.
    assert "update-check" in commands
    commands.add("update-check --force")

    return commands


def _parse_nopasswd_commands(text: str) -> set[str]:
    """Every command string granted NOPASSWD to the `alderpointdns` compiler
    path in a sudoers file's text (packaging source or an installed
    drop-in), keyed the same way as _extract_webapp_sudo_commands()."""
    commands: set[str] = set()
    prefix = COMPILER_PATH + " "
    # Everything before "NOPASSWD:" is the "user ALL=(root)" rule header,
    # not part of the first comma-separated command -- strip it first so
    # the very first entry in the list (e.g. bare "deploy") isn't missed
    # just because it shares its line with that header.
    marker = "NOPASSWD:"
    idx = text.find(marker)
    if idx != -1:
        text = text[idx + len(marker):]
    for entry in text.split(","):
        entry = entry.strip()
        if entry.startswith(prefix):
            commands.add(entry[len(prefix):].strip())
    return commands


class SudoersPolicyCoverageTest(unittest.TestCase):
    def test_every_webapp_sudo_invocation_is_authorized_in_the_packaged_sudoers_file(self) -> None:
        webapp_commands = _extract_webapp_sudo_commands()
        sudoers_commands = _parse_nopasswd_commands(SUDOERS_FILE.read_text())
        missing = webapp_commands - sudoers_commands
        self.assertEqual(
            missing, set(),
            "app/webapp.py invokes these exact sudo compiler commands, but "
            f"packaging/sudoers-alderpointdns grants none of them: {sorted(missing)} "
            "-- add the matching NOPASSWD entry (this is exactly the dns1 "
            "'sudo: a password is required' defect).",
        )

    def test_upstream_deploy_specifically_is_covered(self) -> None:
        """Pins the exact command from the incident report."""
        sudoers_commands = _parse_nopasswd_commands(SUDOERS_FILE.read_text())
        self.assertIn("upstream-deploy", sudoers_commands)

    def test_sudoers_policy_stays_narrow(self) -> None:
        """Security requirement: fixing missing coverage must never be done
        by widening the grant into unrestricted root execution -- no `ALL`
        target, no bare interpreter/shell, no wildcard compiler invocation,
        no argument-taking entry that isn't itself a fixed, exact string
        (e.g. `logs <unit>` must be one entry per allowed unit, never
        `logs *` or a bare `logs`)."""
        text = SUDOERS_FILE.read_text()
        self.assertNotRegex(text, r"NOPASSWD:\s*ALL\b")
        self.assertNotIn("/usr/bin/python3", text)
        self.assertNotIn("/bin/sh", text)
        self.assertNotIn("/bin/bash", text)
        self.assertNotRegex(text, re.escape(COMPILER_PATH) + r"\s*(,|$)")  # bare, no subcommand
        self.assertNotRegex(text, re.escape(COMPILER_PATH) + r"\s+\*")
        self.assertNotRegex(text, re.escape(COMPILER_PATH) + r"\s+logs\s*(,|$)")
        self.assertNotRegex(text, re.escape(COMPILER_PATH) + r"\s+logs\s+\*")
        for unit in service_logs.ALLOWED_UNITS:
            self.assertIn(f"logs {unit}", text)

    def test_syntax_is_valid(self) -> None:
        if shutil.which("visudo") is None:
            self.skipTest("visudo not available on this host")
        result = subprocess.run(["visudo", "-cf", str(SUDOERS_FILE)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(shutil.which("runuser") and shutil.which("sudo"), "runuser/sudo not available")
class SudoersLivePermissionTest(unittest.TestCase):
    """Exercises the *installed* privilege boundary directly, as the real
    unprivileged service account -- the actual mechanism that failed live on
    dns1. `sudo -n -l COMMAND` only checks whether the command would be
    permitted (matching sudo's own authorization list); it never executes
    it, so this is safe against a real host with no side effects, even for
    commands (like upstream-deploy or backup-create) that would otherwise
    mutate live state if actually run."""

    @classmethod
    def setUpClass(cls) -> None:
        whoami = subprocess.run(["id", "-u", "alderpointdns"], capture_output=True, text=True)
        if whoami.returncode != 0:
            raise unittest.SkipTest("no 'alderpointdns' service account on this host -- not a packaged install")
        if not Path("/etc/sudoers.d/alderpointdns").exists():
            raise unittest.SkipTest("no installed /etc/sudoers.d/alderpointdns drop-in -- not a packaged install")

    def _is_authorized(self, args: list[str]) -> bool:
        result = subprocess.run(
            ["runuser", "-u", "alderpointdns", "--", "sudo", "-n", "-l", COMPILER_PATH, *args],
            capture_output=True, text=True,
        )
        return result.returncode == 0

    def test_every_webapp_sudo_invocation_is_authorized_for_the_real_service_account(self) -> None:
        unauthorized = []
        for command in sorted(_extract_webapp_sudo_commands()):
            if not self._is_authorized(command.split(" ") if command else []):
                unauthorized.append(command)
        self.assertEqual(
            unauthorized, [],
            "the installed /etc/sudoers.d/alderpointdns drop-in does not authorize "
            f"these commands the web app can invoke: {unauthorized} -- reinstall/upgrade "
            "the package to pick up packaging/sudoers-alderpointdns, or (if this failure "
            "shows up right after editing packaging/sudoers-alderpointdns in a dev "
            "checkout) that file was edited without also reinstalling it live.",
        )

    def test_upstream_deploy_is_authorized_for_the_real_service_account(self) -> None:
        """Pins the exact reproduction from the incident report."""
        self.assertTrue(
            self._is_authorized(["upstream-deploy"]),
            "sudo -n -l denies 'upstream-deploy' for the alderpointdns service account -- "
            "this is the exact dns1 'sudo: a password is required' failure.",
        )


if __name__ == "__main__":
    unittest.main()
