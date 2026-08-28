# V2 Go/Svelte owner-preview cutover runbook

Status as of 2026-08-28: **all pre-cutover gates rehearsed and proven on disposable
state/alternate ports. The actual standard-port swap has NOT been executed.** This
document is the exact, bounded procedure to execute only after Alex gives the literal
confirmation `GO CUTOVER`.

This is a reversible **owner-preview** takeover, not a public release. Nothing here
tags, packages, or publishes anything externally.

## What this changes

| | Before | After |
|---|---|---|
| `:8443` (management) | Python `apdns-v2-preview` | Go `apdns-go-live` |
| `:53` (DNS UDP+TCP) | Python (dnsdist in `apdns-v2-preview`) | Go (dnsdist via a new, dedicated `apdns-hostagent-live`) |
| `:853`, `:9443` | Mapped but not real DoT/DoH (see below) | Unchanged in meaning -- see "Transports" |
| `:10443` (Go build/proving) | Live | **Untouched, stays live** -- separate container, separate state, separate hostagent |
| Python (`apdns-v2-preview`) | Running | **Stopped, not removed** -- the tested rollback path |

## Transports: exact real scope (verified, not assumed)

Verified by direct inspection before writing this document (see AGENT_PROGRESS.md's
2026-08-28 cutover-prep checkpoint for the full evidence trail):

- **`:53` UDP+TCP** -- real, live, plain DNS. Go already does this; migrated data proven
  correct on disposable alt ports.
- **`:8443`** -- real, live management HTTPS with a real self-signed cert
  (`CN=Alderpoint DNS V2 Local`, fingerprint `C1:33:7B:D4:E5:DA:E4:A6:03:B1:D1:61:1B:C4:84:8C:BD:F1:D1:96:59:37:7B:9D:5F:EE:BF:F4:E8:A2:10:3F`,
  expires 2027-09-24). Go already does this; cert continuity proven on disposable alt
  ports with the real, imported certificate.
- **`:853`** -- mapped by the container's port table but **nothing listens behind it**
  inside the live Python container (confirmed via `ss -tlnp` run *inside* the
  container, not just the host-side forward table). Not a real transport today. No
  cutover blocker: there is nothing functioning to replicate.
- **`:9443`** -- **not DoH.** It is a dedicated Python process
  (`alderpointdns_v2_ctl.py replication-server --host 0.0.0.0 --port 9443`), mTLS,
  serving `replication_peers`. Confirmed via `systemctl show ... ExecStart` and a live
  TLS handshake requesting a client certificate. **Go has no equivalent server-side
  listener yet** (its own Replication is read-only status today, a previously
  disclosed gap) -- but the live control.db has **zero replication peers configured**,
  so this has no functional impact on cutover. It becomes a real, disclosed limitation
  only if/when a second real node is ever added to replicate with. **This is the one
  genuine, disclosed, non-blocking gap in transport parity.**

DoT/DoH are not a real gap of any kind: they are not active on the source system, so
there is nothing to migrate or match. (Go's compiler already supports both, proven
independently by the DNS Performance benchmark's own DoT/DoH test cases -- that
capability exists and is unaffected by this finding, it's simply not needed for this
cutover.)

## Secrets: exact real scope (verified, not assumed)

Per the 2026-08-28 cutover-inventory probe (sanitized manifest at
`/root/cutover-inventory-manifest.json`, 0600, root-only): **zero** upstream endpoints
have an auth secret, **zero** notification providers exist, **zero** replication peers
exist. The only credential that must cross over is the management TLS **cert/key
pair**, for continuity (not a new Go secrets-store entry) -- proven importable via
`internal/tlscert.StageValidatePromote` on disposable alt ports, fingerprint-matched
byte-for-byte against the real live certificate.

## Pre-cutover gates already rehearsed (2026-08-28)

1. **Rollback snapshot**: taken, checksummed, and its restore mechanics rehearsed on a
   disposable alt-port container boot (real health, real DNS answers, then torn down).
   `/root/apdns-v2-preview-cutover-rollback-20260828T080826Z/ROLLBACK.md`.
2. **Secret-backed config inventory**: done via a narrowly authorized one-time
   read-only probe. See above.
3. **Migration rehearsal**: the real `import-python` tool run for real (dry-run then
   apply) against a proper `.backup` snapshot of the live `control.db` -- 47 Local DNS
   records, 3 upstream profiles (8 endpoints), 1 global policy layer, 20 blocklist
   subscriptions, all landed correctly in a disposable Go `app.db`. Migration rollback
   tested too.
4. **Real DNS-runtime validation on disposable alt ports**: a full disposable
   web+hostagent+named+dnsdist stack, loaded from the migrated database and the
   imported real certificate, bound to alternate loopback ports --
   - Management HTTPS on an alt port, presenting the exact real certificate
     (fingerprint-matched).
   - Real authenticated setup/login over that cert.
   - DNS UDP and TCP, both returning real migrated Local DNS answers
     (`3d-printer.mylan.network -> 192.168.32.15`, `wg2.mylan.network -> 104.223.98.238`).
   - A real blocklist subscription refreshed live (904 real rules fetched from the
     real upstream URL), recompiled into the runtime, and a real domain from that list
     (`023hysj.com`) confirmed NXDOMAIN on three repeated queries (no cache leak).
   - Real upstream resolution (`cloudflare.com` resolved via the migrated upstream
     profiles).
   - Real UID separation throughout: hostagent as root, web as the real unprivileged
     `apdns-browsertest` account, communicating correctly over the unix socket.
   - Everything torn down afterward; the real live Python and the real deployed Go
     preview were both checked healthy before and after and were never touched.
5. **Cache/policy correctness**: proven architecturally in the prior session
   (`74467d8`) and re-confirmed behaviorally on the real migrated config above (repeat
   queries to a blocked domain never leaked a different answer).

## Preflight checks (run immediately before executing, not the day before)

All of these are real, automatable checks -- `scripts/v2/cutover.sh preflight` runs
them and refuses to proceed on any failure:

1. **Rollback snapshot present and intact**: `sha256sum -c CHECKSUMS.txt` against the
   snapshot directory; the committed image
   `apdns-v2-preview-rollback:20260828T080826Z` exists in local podman storage.
   **If this snapshot is more than a few hours old relative to cutover time, take a
   fresh one first** (state drifts -- an old rollback target is a real data-loss risk
   on rollback, not just a formality).
2. **Disk space**: at least 2 GB free on `/` (a fresh `control.db` snapshot + a fresh
   Go `app.db` + the pre-migration safety tar together are well under 500 MB based on
   this session's rehearsal, but leave real margin).
3. **Port ownership**: `ss -tlnp`/`ss -ulnp` show exactly `apdns-v2-preview`
   (via `conmon`) on `53/tcp`, `53/udp`, `853/tcp`, `8443/tcp`, `9443/tcp` -- if
   anything else is already bound to any of these, abort (a stale process from a
   failed prior attempt is exactly the kind of thing that turns a bounded cutover into
   an unbounded one).
4. **Migrated-state validation**: run `import-python -dry-run` against a **fresh**
   `.backup` of the real live `control.db` and confirm the reported counts are
   sane and non-zero for `local_dns_records`/`upstream_profiles`/
   `blocklist_subscriptions` (exact expected counts will have drifted from this
   session's 47/3/20 if Alex has changed anything on Python since -- that's expected
   and fine; a **zero** count where the rehearsal saw a real number is not).
5. **Go binary/version**: `alderpointdns-go version` (or equivalent) matches the
   commit this runbook was written against, or a newer one Alex has explicitly
   approved; never an unreviewed binary.
6. **TLS certificate fingerprint**: `openssl x509 -in <python-live-cert> -noout
   -fingerprint -sha256` matches the value recorded above -- if Alex has replaced the
   certificate on Python since this runbook was written, re-run the cert-import step
   fresh rather than reusing a stale copy.
7. **Container/service health**: `apdns-v2-preview`'s own `GET /api/health` returns
   `status: ok` immediately before cutover -- never cut over an already-unhealthy
   instance; fix or investigate that first, separately.

## Execution order (minimizes real interruption)

Everything that can be prepared while Python still serves real traffic IS prepared
first. The only real interruption window is between stopping Python and Go's listener
coming up healthy -- rehearsed at well under 30 seconds on this hardware for the
DNS/BIND/dnsdist startup path alone; management HTTPS comes up in low single-digit
seconds.

0. **Real owner setup, done ahead of time, through the real browser** (not part of
   `execute` at all): the migrated `app.db` and imported cert are staged at
   `/var/lib/apdns-go-live-staging/` (owned by the real `apdns-go-web` UID) and served
   on `0.0.0.0:18443` while Python keeps serving. Alex reaches it at
   `https://<real-host-ip>:18443/`, presents the real one-time bootstrap token (see
   `internal/bootstrap`) at the setup screen, and creates the real owner account
   himself. This script never sees or handles that password in any form. `execute`
   checks for a real admin row in this exact database before proceeding (see step 3)
   and refuses to fabricate one if none exists yet.
1. Fresh `.backup` snapshot of the live `control.db` (safe, non-blocking, Python keeps
   serving) -- only taken if step 0's staged database doesn't already exist.
2. Fresh rollback snapshot per Gate 1's procedure if the existing one is stale.
3. If the staged database from step 0 already exists, reuse it as-is (real migrated
   data AND the real owner account Alex already created -- never regenerated). Only if
   it doesn't exist yet does `execute` fall back to running
   `import-python -dry-run=false` into `$GO_LIVE_STATE/data/app.db` itself, in which
   case Alex must still complete real browser setup before `execute` can continue past
   this point (it will fail loudly rather than proceed without a real admin account).
4. Import the real live TLS cert/key into the new instance's own cert path via
   `go/cmd/cutover-cert-import` (a small, version-controlled tool wrapping the exact
   same `internal/tlscert.StageValidatePromote` code path the real Encryption page's
   upload/replace handler uses -- built fresh from source at cutover time, not a
   standing binary, never prints key material). Root-owned, same mechanism rehearsed;
   Python's own cert files are never modified. Skipped if step 0 already did this.
5. Start a **new**, independent `apdns-hostagent-live` process (own socket, own audit
   log, own `/var/lib/bind/apdns-go-live` directory, own DNS-runtime staging dir) --
   configured with `-dns-runtime-dnsdist-listen-addr 0.0.0.0:53` (the real interface,
   not loopback) but not yet promoted to anything (Python's dnsdist still owns `:53`
   at the kernel level until step 7). Python keeps serving throughout.
6. Start the new Go web container (`apdns-go-live`) bound to `-p 8443:8443` (not yet
   published if using the SAME host ports Python holds -- see the actual interruption
   step below), pointed at the new `app.db`/cert/hostagent-live socket. **This step
   itself does not require Python to stop** if bound to a temporary alt port first,
   confirmed healthy, THEN moved -- but binding directly to `:8443` will conflict with
   Python's own live listener, so this container is created but not started with the
   real `-p 8443:8443` flag until immediately before step 7.
7. **The actual interruption, minimized to this window**:
   - `podman stop apdns-v2-preview` (stop, never `rm`, so instant restart on
     rollback).
   - `podman start apdns-go-live` (already fully configured from steps 3-6, this is
     just the container start -- the slow work already happened).
   - Trigger `dns_runtime.promote` on the new hostagent-live (this brings up the real
     `named`+`dnsdist` bound to the real `0.0.0.0:53`, now free since Python stopped).
8. Run the **immediate post-swap checks** (next section). Any failure inside the error
   budget triggers automatic rollback -- see below.

## Immediate post-swap checks (all must pass within the error budget)

Run by `scripts/v2/cutover.sh verify`, called automatically at the end of `execute`:

1. `GET https://<real-host>:8443/api/health` -> real `200`, `status: ok`.
2. `dig @<real-host> -p 53 <a real migrated Local DNS name> A` (UDP) -> the real
   migrated answer.
3. `dig +tcp @<real-host> -p 53 <a real migrated Local DNS name> A` (TCP) -> the same
   real answer.
4. `dig @<real-host> -p 53 <a real domain known to be on an enabled blocklist> A` ->
   the configured blocked response (NXDOMAIN/REFUSED per policy).
5. `dig @<real-host> -p 53 <a real, non-blocked external domain> A` -> a real resolved
   answer via the migrated upstream profile(s).
6. A real authenticated browser-equivalent check: `POST /api/login` with the real
   owner credentials (Alex's, never guessed/stored by this tooling) -> a real session,
   then one authenticated `GET` (e.g. `/api/local-dns`) succeeds.
7. `podman ps` shows `apdns-go-live` `Up` and `apdns-v2-preview` `Exited` (stopped, not
   gone).

## Error budget and automatic rollback

**Total budget: 90 seconds from `podman stop apdns-v2-preview` to all seven checks
passing.** If any single check fails, or the budget is exceeded, `cutover.sh` does
**not** attempt to debug live -- it immediately executes the rollback:

1. `podman stop apdns-go-live` (if running).
2. Restore `/root/apdns-v2-preview-state/{etc,var-lib}` from the fresh snapshot taken
   in the preflight step **only if** anything under those paths was touched during
   this run (the real cutover procedure above never touches Python's own state dirs
   at all, so this is normally a no-op -- documented explicitly so a future editor of
   this script doesn't "helpfully" add a restore step that overwrites newer real data
   with this run's snapshot when nothing needed restoring).
3. `podman start apdns-v2-preview`.
4. Re-run the same seven checks against Python's real endpoints (`:8443`, `:53`).
5. Report pass/fail plainly. A rollback that itself fails to bring Python back healthy
   is the one scenario this script cannot self-heal from -- it stops and prints the
   exact manual recovery steps from `ROLLBACK.md` rather than retrying blindly.

## Post-rollback verification (if rollback was triggered)

1. `GET https://<real-host>:8443/api/health` -> real `200` from Python.
2. `dig @<real-host> -p 53 example.com A` -> a real answer.
3. `podman ps` shows `apdns-v2-preview` `Up`, `apdns-go-live` gone/stopped.
4. Compare `ss -tlnp`/`ss -ulnp` output against the preflight snapshot -- an exact
   match is the final confirmation nothing was left in a half-migrated state.

## What this run never does

No public release, tag, package publication, or external rollout of any kind. No
change to `:10443` (a fully separate container/state/hostagent). No change to
Python's own certificate, state directories, or control.db beyond a read-only
`.backup` snapshot. No secret value is ever printed, logged, committed, or exposed
through any API/UI at any step.

## Readiness statement

Every gate above that can be proven without taking the real ports down has been
proven, on disposable state, with real data, real binaries, real UID separation, and a
real (not simulated) internet-connected blocklist refresh. The rollback path has been
independently rehearsed and proven restorable. The one thing that has never been
attempted -- because it cannot be, without this exact interruption -- is binding to
the real `:53`/`:8443` while Python holds them.

**Expected real interruption window, based on this session's rehearsal timings:
under 30 seconds** (BIND+dnsdist startup dominates; management HTTPS itself comes up
in low single digits of seconds). The `cutover.sh` script enforces a hard 90-second
budget before it rolls back automatically, giving real margin over the rehearsed
timing without leaving DNS down indefinitely if something is wrong.

**Awaiting the literal confirmation `GO CUTOVER` from Alex before executing
`scripts/v2/cutover.sh execute`.**
