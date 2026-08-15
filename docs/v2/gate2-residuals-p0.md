# Gate #2 Residual Findings (P0) — Fixed

Dex Gate #2 passed with three residual findings. All three fixed and proven this pass.

## P0-A. Secret restore crash atomicity — HIGH

`SecretStore.import_all()` was exception-atomic (an in-process Python exception during
backup/promote correctly rolled back) but not **crash**-atomic: a real `kill -9` between the
backup rename and the promote rename left real secret files sitting under
`.restore-backup.<id>` with no exception handler ever running to restore them.

**Fix**: a durable JSON restore journal (`app/v2/secret_store.py`, `.restore-journal.json` in the
store directory), written atomically (tempfile + fsync + `os.replace`, the same primitive already
used for secret writes) **before** any real secret path is touched, and updated once more
(`phase="staged"` → `phase="promoted"`) only after every promotion has actually succeeded.
`SecretStore.__init__()` now checks for a leftover journal on every open and replays it
deterministically:

- `phase="staged"` (completion never confirmed) → always **roll back**: every entry with a
  recorded backup is force-restored from it; every entry with no prior backup (a brand-new id) is
  force-absent. Safe and idempotent regardless of how far the interrupted run actually got.
- `phase="promoted"` (every promotion already confirmed) → always **roll forward**: finish
  deleting the now-unneeded backups and the journal, never re-apply the old value over a
  committed new one.

A corrupt/unreadable journal (which cannot itself be a torn write, since it is only ever written
via the atomic helper) is treated conservatively — deleted, never guessed at.

**Proof**: `tests/v2/test_secret_restore_crash_atomicity.py` (11 tests) simulates abrupt
termination by directly constructing on-disk state at each of Dex's 8 listed crash points (before
staging / during staging / after staging validation / before promotion / during promotion / after
promotion before cleanup / during cleanup, plus a corrupt-journal case and a real mocked
`os.replace` failure followed by a genuinely fresh `SecretStore` reopen) and opening a **fresh**
`SecretStore` object each time — proving recovery happens on process restart, not just via the
object that was mid-call. Every case settles into the exact old state or the exact new state, with
no leftover `.restore-*`/journal files. Permissions/ownership are preserved automatically (renames
preserve the inode, never a copy).

## P0-B. Legacy REFUSED domain validation — MEDIUM

`dnsdist_gen.render_refused_block_rules()` normalized domains with a bare
`.strip(".").lower()` and never routed them through the central `validate_dns_name()` validator
used by every other generation call site — a legacy helper Dex found bypassing pre-render
validation.

**Fix**: routes every domain through `validate_dns_name()`, raising `DnsdistGenError` (wrapping
`InvalidDnsNameError`) on any invalid entry, consistent with the domain-routing loop in the same
module.

**Proof**: `tests/v2/test_refused_validator_p0b.py` (14 tests) — newline, CR, tab, control chars,
embedded space, empty-label, malformed hyphen labels, overlong label, zone-file-injection shape,
and SQL-metacharacter-shaped payloads all rejected; legitimate domains (including mixed case /
trailing dot) still accepted; one bad domain in an otherwise-valid batch rejects the whole batch
before any render.

## P0-C. V2 analytics provisioning deployment path — LOW

`scripts/provision-v2-analytics-vendor-runtime.sh` worked but was a manual-only entry point with
no test proving it as a real subprocess invocation, and no configurable target for isolated
testing.

**Fix**: the script now accepts `ALDERPOINTDNS_V2_ANALYTICS_VENDOR_DIR` /
`ALDERPOINTDNS_V2_ANALYTICS_TARGET_DIR` overrides (matching `provision_vendor_runtime()`'s own
parameters), documented explicitly as the exact entry point a future V2 postinst `configure` step
will call, with fail-the-install-not-silently-degrade semantics matching the existing V1
postinst's `vendor-deps-sync` gate (non-zero exit on a degraded outcome).

**Deliberately not wired into `packaging/debian/postinst`** in this pass: that file is the live
V1 install path, and V2 (`app/v2/*`) has no installable package/service lifecycle of its own yet
(Priority 1 of the Workstream 4 spec — filesystem layout, package integration, postinst/prerm —
is not built). Wiring this script into an install lifecycle that doesn't exist would mean either
(a) modifying V1's postinst to do V2 work, which the safety constraints explicitly forbid
("do NOT modify current V1 behavior unexpectedly", "V2 must remain isolated until explicit owner
acceptance"), or (b) inventing a placeholder V2 postinst not backed by a real V2 package, which
would not be genuine wiring. This is a real, documented, carried-forward dependency on Priority 1,
not a fabricated completion.

**Proof**: `tests/v2/test_analytics_provisioning_lifecycle_script.py` (3 tests) invokes the real
shell script as a subprocess against an isolated target directory — fresh-target success (real
`import pyarrow, duckdb` proof from a separate subprocess afterward), second-run idempotency, and
a missing-vendor-dir failure that exits non-zero and leaves no partial target.

## Regression

Full `tests/v2/` suite: **708 passed, 0 failed** (up from the Gate #2 baseline of 683 — +25 from
this pass's own new tests), run twice for stability under the real system `python3`.
