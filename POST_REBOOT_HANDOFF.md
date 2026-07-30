# Post-Reboot Handoff: v0.4.0-beta.2 usability/interface-polish milestone

Written: 2026-07-29 21:17 MDT, before the operator-performed reboot.

## Current checkpoint

- Checkpoint commit: `129cb97` (`Complete beta.2 versioning and closeout`)
- Working tree: clean (`git status --short` empty) as of this writing
- Version: `0.4.0-beta.2` (`VERSION`); Debian package version `0.4.0~beta2-1`
- Branch: `main`

Commits in this milestone, oldest first (all after `6f50878`, the prior
session's live-database backup race fix):

1. `1d92adb` Add collapsible desktop sidebar
2. `b92d450` Compact Local DNS interface
3. `b5de669` Clean up DNS Settings upstream resolver actions
4. `abdcefd` Redesign Blocklists and add managed category handling
5. `4865fab` Fix System Status Recent Logs access architecture
6. `ff01d62` Fix Dashboard/System Status health card word-splitting
7. `28050ce` Add shared responsive and visual regression coverage
8. `129cb97` Complete beta.2 versioning and closeout

## Do not redo

All 7 milestone items plus versioning are implemented, tested, and
committed. Do not re-implement, re-design, or "fix" any of the following
unless a real regression is found post-reboot:

- Collapsible desktop sidebar (icon rail, flyout submenus, localStorage
  persistence, anti-flash inline script).
- Compact Local DNS table (truncate+tooltip, collapsed-by-default row
  editor, reverse-record badge).
- DNS Settings action hierarchy (Save/Enable inline, overflow menu for
  Move/Delete).
- Blocklists managed categories (`app/blocklist_categories.py`) and
  compact/filterable source table.
- System Status Recent Logs (`app/service_logs.py`,
  `alderpointdns_compiler.py logs <unit>` subcommand,
  `packaging/sudoers-alderpointdns`).
- Dashboard/System Status health card word-break fix.
- Shared compact-UI CSS/JS primitives (`.table-compact`, `.category-badge`,
  `.overflow-menu`, `data-row-edit-toggle`).

See `AGENT_PROGRESS.md`'s "v0.4.0-beta.2 usability/interface-polish
milestone" section (bottom of the file) for full root-cause/fix detail on
each item, and three side notes disclosed there for transparency (a
harmless `login_attempts` table clear during test cleanup, a pre-existing
unrelated `sudo` hostname-resolution stderr warning, and that
`packaging/sudoers-alderpointdns` was deployed onto this VM's real
`/etc/sudoers.d/alderpointdns` as expected steady state, not a one-off).

## Tests already passed (pre-reboot, on commit `129cb97`)

- `python3 -m unittest discover -s tests -p "test_*.py"` -- 190 tests, OK.
- `sh tests/test_web_smoke.sh` -- passed.
- `sh tests/test_install_upgrade_diagnostics.sh` -- passed (includes new
  sudoers/log-access assertions).
- `sh tests/test_beta_hardening_docs.sh` -- passed.
- Full `sh tests/test_acceptance.sh` -- **exit code 0**, ends with
  "Alderpoint DNS acceptance suite passed".
- Manual service restart cycle (`named`, `dnsdist`, `alderpointdns`,
  `alderpointdns-analytics`) -- all four active afterward.
- Manual DNS/filtering/listener checks (see AGENT_PROGRESS.md for exact
  commands/output) -- all passed.
- Manual fresh `scripts/backup.sh` run -- exit 0, no tar warning,
  extracted snapshot's `PRAGMA integrity_check` = `ok`.
- Chromium headless screenshot verification at desktop/tablet/mobile
  widths for Dashboard, Local DNS, DNS Settings, Blocklists, System
  Status -- confirmed compact layout and no mid-word splitting anywhere.
  Screenshots were session-scratchpad-only, not committed.

## Expected warnings / negative-path output (do not treat as failures)

- BIND `named.conf.options` "option 'allow-proxy'/'allow-proxy-on' is
  experimental" notices during acceptance -- expected warnings.
- A `Traceback ... subprocess.CalledProcessError ... named-checkzone ...`
  pair partway through the acceptance log -- this is the suite's own
  forced invalid-RPZ / forced post-deploy-failure negative-path test,
  not a real failure.
- `sudo: unable to resolve host bindguard-1: No address associated with
  hostname` on every `sudo -n .../alderpointdns_compiler.py ...` call --
  pre-existing, unrelated `/etc/hosts` leftover from the BindGuard->
  Alderpoint rename (see AGENT_PROGRESS.md side notes). Does not affect
  correctness; the new Recent Logs code specifically avoids being
  confused by it (keeps stdout/stderr separate rather than merged).
- The acceptance suite ending in exit code 0 and the literal line
  "Alderpoint DNS acceptance suite passed" is the actual pass signal.

## Exact post-reboot verification still required

Run these after the operator's manual reboot, in order:

1. **Service checks** (all four must be `active`):
   ```sh
   systemctl is-active named dnsdist alderpointdns alderpointdns-analytics
   systemctl is-enabled named dnsdist alderpointdns alderpointdns-analytics
   ```

2. **Listener checks**:
   ```sh
   ss -ltnup | grep -E ':53\b|:443\b|:853\b|:3000\b'
   ```
   Expect plain DNS on `:53`, dnsdist DoH/DoT on `:443`/`:853` (IPv4 and
   IPv6), and the web app on `0.0.0.0:3000`.

3. **DNS checks**:
   ```sh
   dig @127.0.0.1 example.com A +short                      # upstream resolution
   dig @127.0.0.1 -p 5353 adguard.mylan.network A +short     # local DNS (direct BIND, bypass dnsdist)
   dig @127.0.0.1 -p 5353 -x 172.16.43.9 +short              # reverse DNS
   dig @127.0.0.1 doubleclick.net A                          # filtering; expect NXDOMAIN via the real client-facing frontend
   ```

4. **UI persistence checks** (log in as the real `admin` account,
   password known to the operator -- do NOT create another temporary
   admin unless needed, and delete it afterward if you do):
   - Toggle the desktop sidebar collapse button; reload the page; confirm
     it stays collapsed with no visible flash, then expand it again.
   - Confirm Local DNS records render as compact single-line rows and
     that clicking "Edit" on a row expands only that row's editor.
   - Confirm Blocklists shows the category dropdown (not a free-text
     field) and that "Manage Categories" opens and lists categories.
   - Confirm System Status -> Recent Logs shows real log lines (not a
     `journalctl`/"insufficient permissions" error) for all four services
     in the Service selector.
   - Confirm Dashboard's System Health cards show intact words ("Healthy",
     "DNSSEC", etc. -- nothing split mid-character).

5. **Log-access checks**:
   ```sh
   runuser -u bindguard -- sudo -n /opt/alderpointdns/app/alderpointdns_compiler.py logs alderpointdns | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d), 'entries')"
   runuser -u bindguard -- sudo -n /opt/alderpointdns/app/alderpointdns_compiler.py logs sshd   # must be rejected (not in sudoers allowlist)
   ```
   Confirm the first succeeds with valid JSON and the second is denied by
   `sudo` itself (password required / not permitted), not merely by the
   web app.

6. **Backup checks**:
   ```sh
   /opt/alderpointdns/scripts/backup.sh   # must exit 0, no tar warning
   sh /opt/alderpointdns/tests/test_backup_restore.sh   # includes the concurrent-write regression check from the prior session's fix
   ```

7. **Exact test commands still required post-reboot**:
   ```sh
   sh /opt/alderpointdns/tests/test_web_smoke.sh
   sh /opt/alderpointdns/tests/test_acceptance.sh
   ```
   Both must complete and the acceptance suite must end with "Alderpoint
   DNS acceptance suite passed" and exit 0 (allowing for the expected
   warnings/negative-path output described above).

## Unresolved issues

None known. Everything in this milestone passed pre-reboot verification
on this same VM; the checks above exist to confirm nothing regresses
across the actual reboot (fresh service starts, fresh sudo/journal
permission state, etc.), not because a specific defect is expected.
