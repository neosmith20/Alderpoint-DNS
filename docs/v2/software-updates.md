# Software Updates (beta-rescue priority 4)

## What this restores

V2 previously had a nav slot and nothing else. This adds a real,
private-channel-honest Software Updates surface, using V1's mature
lessons (package inspection, dpkg version comparison, apt simulation
safety, staged apply) without inventing a new toy updater and without
advertising a public release channel that does not exist.

## Model

- **Installed version**: source `VERSION` file (always available) and,
  when dpkg-managed, the real installed package version via
  `dpkg-query`.
- **Channel**: always `"private"`. There is no public release channel.
- **Private feed** (optional): an operator-configured local directory
  (e.g. a mounted private artifact share) containing a `metadata.json`
  describing one candidate. Unconfigured is the honest default: "no
  public release available," not a fake "up to date."
- **Manual upload**: validated before anything is staged --
  `app/v2/software_updates.py` reuses V1's already-tested, source-format-
  generic `inspect_deb`/`dpkg --compare-versions`/`sha256_file`
  primitives (via `app.software_updates`, never V1's channel/job logic)
  to check: correct package name (`alderpointdns-v2`), amd64-only
  architecture (matching the RC43 package-metadata fix), and a version
  strictly newer than installed (never a same-version reinstall, never a
  downgrade, via this path).

## Privilege separation

The web process never runs apt/dpkg itself. It only validates and
copies a candidate to a fixed staged path, then -- only on the
operator's explicit "Apply" confirmation -- writes a small marker file.
A root-owned systemd `.path` unit
(`alderpointdns-v2-update-apply.path`) watches that marker and triggers
a oneshot `.service` running
`scripts/v2/alderpointdns_v2_update_apply.py`, which:

1. Re-derives the staged package path and **re-verifies its sha256**
   against the marker's own claim -- never trusts the unprivileged
   process across the privilege boundary, even though both are this
   appliance's own code.
2. Runs `apt-get install` only if that checksum matches.
3. Always writes a result file and always removes the marker, so a job
   can never be stuck "in progress" forever and a stale marker can never
   be silently re-applied.

This is the same watch-a-marker-file/oneshot-root-service pattern
already established for `alderpointdns-v2-dnsdist-reload`, not a new
privilege model.

## Progress / reconnect UX

`GET /api/updates/jobs` reconciles any appeared result file into the
job's row on read (no persistent background thread needed in the
unprivileged process). After the operator confirms Apply, the UI polls
`/api/session` until the appliance is reachable again, since a
successful install restarts `alderpointdns-v2-web` -- the very process
serving the request that requested the apply.

## Deterministic private test fixtures

Per the beta-rescue brief's explicit instruction, there is no real
public channel to test against. `tests/v2/test_software_updates.py`
builds real (not mocked) `.deb` packages with the actually-installed
`dpkg-deb` for validation coverage, and a fake `metadata.json` private
feed for channel coverage. The privileged helper's own OS-mutating step
(`apt-get install`) is dependency-injected in tests -- this suite never
installs a package into the test host; `tests/v2/browser/
chromium_ui_harness.js` drives a real upload -> stage -> apply-request
through the UI with a real dpkg-deb-built package and confirms the
privileged helper's marker file is actually written, without letting the
(nonexistent, in this container) real package upgrade proceed.

## Not implemented

Automatic/scheduled update checks (a systemd timer polling a configured
private feed) -- "Refresh" re-runs `check_private_feed` against the
configured directory on demand (the real check-for-updates action); a
timer is a straightforward addition on top of the same function if the
owner wants a scheduled check, but was not built without an explicit
private-feed target to test it against.
