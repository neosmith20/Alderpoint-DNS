# Alderpoint DNS V2 — CC Verification Session Notes (post-Workstream 4D)

This is a short verification/diligence pass, not a new implementation workstream.
Starting point: HEAD `39a332e79d19cae7410fbebbf30c2b6ab22ef6ff` on
`v2/architecture-storage-foundation`, after Dex's Workstream 4D UI-acceptance
closure. No code changes were made this session; this documents what was
checked, what was found, and what remains open.

## Concurrent-agent state (checked first, before touching anything)

A second agent (Codex, commits as "BindGuard Builder") was found to have an
OS process still resident in this exact worktree (`/root/alderpointdns-work`),
originally reported as live. On inspection its process elapsed time was
~40 hours and no file in the worktree had been modified in the preceding 15
minutes, and `git status`/`HEAD` matched the expected clean state before and
after — so it was a stale/orphaned process, not an active writer. Confirmed
safe to proceed without collision. The package artifact this session found at
`/tmp/alderpointdns-v2-4d-closure-final2-*/alderpointdns-v2_2.0.0~private5-1_all.deb`
hashes to `862ca82b66c0cb838068585533bc0ab1083bf964394850befe54a60c89981964`,
matching the reported Workstream 4D artifact exactly.

## Regression verification

- `tests/v2`: 788 passed (matches the reported baseline exactly).
- `tests --ignore=tests/v2`: 1187 passed / 1 failed on first run
  (`test_backup.py::StreamedUploadTest::test_abort_streamed_upload_cleans_up_partial_file`,
  "insufficient free disk space" — `/tmp` was a 2 GiB tmpfs at 79% full from
  accumulated duplicate `2.0.0~private5-1` build artifacts left by prior
  closure runs). Removed two redundant duplicate build directories
  (`alderpointdns-v2-4d-closure-*`, keeping `-final2` which matches the
  reported SHA-256) to free space; re-ran the failing test alone and it
  passed. Not a code regression — 1188/1188 V1 stands.

## Security review of the Workstream 4D diff (`2f98c46..39a332e`)

Read `app/v2/webapp.py`, `app/v2/ui/app.js`/`app.css` diffs in full (new
query-log filtering API, secret-backup list/validate/restore endpoints and
UI). No defects found:

- Every new mutating route (`create_secret_backup`, `validate_secret_backup`,
  `restore_secret_backup`) requires `current_admin` and calls `check_csrf`.
- `_backup_path_from_name` rejects `/`, `\`, a leading `.` (which also
  catches `..`), and re-checks the resolved path's parent — no traversal
  path found.
- Restore requires typing the exact backup filename as a second confirmation
  in addition to the CSRF-protected POST.
- `app.js`'s `esc()` is applied consistently in the new `activeFilters()`/
  `backupTable()`/`restoreJobs()` renderers; no raw interpolation of
  server-controlled strings into `innerHTML` was introduced.
- `submitOnce()`/CSRF-header injection in `api()` already cover double-submit
  and CSRF for the new forms; no separate handling was needed or missing.

## Package clean-install: could not be fully validated in this session's harness

Built nothing new (reused the existing private5 artifact). Ran
`apt-get install` of the exact private5 `.deb` in a fresh
`localhost/apdns-v2-4c-accept-base:trixie` Debian 13 systemd Podman
container. Result:

- User/group creation, analytics vendor provisioning, `init-state`,
  `generate-runtime` (dnsdist config + RPZ zone validated and promoted),
  node identity, control.db, secret store, and TLS bootstrap all completed
  successfully and match prior evidence.
- `postinst`'s final `systemctl restart $V2_SERVICES` failed:
  `alderpointdns-v2-web.service` and `alderpointdns-v2-replication.service`
  (the two units with `ProtectSystem=strict`/`PrivateTmp=true` plus
  `CapabilityBoundingSet=` hardening) failed with
  `Failed to keep CAP_SYS_ADMIN: Operation not permitted`, which aborts the
  whole `postinst` under `set -e` and fails the `dpkg` install.
- Root cause isolated: this container's own capability set (`capsh --decode`
  on `/proc/1/status`) does not include `cap_sys_admin`, so systemd inside
  the container cannot construct the private mount namespace those two
  units' hardening directives require. Explicitly requesting
  `podman run --cap-add SYS_ADMIN` did not fix it — the container's `/sbin/init`
  then crashes immediately (exits in ~120ms, no journal output) rather than
  granting the capability, which looks like a crun/podman-in-this-environment
  interaction rather than anything about the package. This host's own shell
  has full capabilities (`cap_sys_admin` present in `/proc/self/status`), so
  the restriction is specific to the nested container, not the physical/VM
  host.
- This could not be reconciled against the prior Workstream 4B/4C/4D clean-
  install evidence, which reports these same services starting successfully
  in what are described as similar Podman containers. Either that evidence
  ran with different Podman/host privileges than were available to this
  session, or something changed. **This is flagged, not resolved** — Dex/
  Alex should re-run a clean install of the exact private5 artifact end-to-
  end (not just source-level tests) on the actual target-shaped host used
  for the 4D evidence and confirm `alderpointdns-v2-web` and
  `alderpointdns-v2-replication` both reach `active` before trusting this
  artifact for RC.

## Combined-suite hang: partially characterized, not fully root-caused

Reproduced a real stall running `pytest tests/v2 tests` together (60s and
90s timeouts both got no further than ~60% through, inside `tests/v2`
itself, not at the `tests/v2` → `tests` boundary the earlier workstream docs
describe). Isolated at least one concrete, real contributing cause:
`tests/v2/test_policy_runtime_matrix.py::TestServiceBlockingAndResponseModes`
and likely other tests in that file issue a **real query against the public
internet** (`iana.org`) through a live dnsdist/BIND instance to prove
lenient-mode passthrough. This sandbox's outbound network is dropped
silently (a raw UDP probe to `8.8.8.8:53` timed out with no response), so
any such query stalls for a full upstream-timeout period per test, and there
are enough of them in sequence to look like a hang in a bounded-timeout CI
run. A small targeted combo (`test_control_db.py` + a V1
`test_navigation_consistency.py`) ran cleanly in 3s, so the specific
"first V1 TestClient request hangs" mechanism described in
`docs/v2/handoff-workstream-2.md` was not reproduced this session — this
session's stall has at least one different, independently real cause.
**Not fully resolved**: whether the originally-described TestClient-specific
hang is the same root cause, a second independent one, or already fixed, is
still open. Recommend: (a) mark or skip live-internet-dependent V2 tests
under a `--no-network`-style marker so CI/sandboxed runs don't stall on
environment network policy, independent of whatever the original
TestClient issue turns out to be, and (b) re-run the original repro from
workstream 2 in an environment with normal outbound network to isolate the
two causes.

## Scope note

This was a verification/diligence pass, not the full multi-day roadmap
sweep (realistic V1 fixture matrix, full package upgrade/lifecycle matrix,
1/2/4 GiB hardware re-validation, Argon2id finalization, broad adversarial
pass, RC assembly) requested in the same session's brief. Given (a) the
concurrent-agent state that had to be checked first, (b) this sandbox's
restricted outbound network, and (c) the nested-container capability
limitation on full service-start validation, those items were not
attempted this session rather than attempted and misreported. They remain
open exactly as listed in `docs/v2/handoff-workstream-4.md`'s "Known open
risks" section, plus the two new findings above.
