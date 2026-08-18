# Real defect found and fixed: a missing control.db or secret store was silently, invisibly replaced by an empty one

Roadmap continuation: failure-domain/chaos pass -- deliberately breaking
each component of a real installed appliance (web/API, analytics,
DuckDB/Parquet, discovery, replication, notifications, schedules,
Tier B, and, per the roadmap's explicit ask, `control.db` and the
secret store themselves) and confirming "DNS must continue wherever
the locked architecture requires... fix accidental coupling."

## What was found

`sqlite3.connect()` (which `app/v2/control_db.py`'s `connect()` wraps)
transparently creates an empty file at its target path if none exists
-- standard, well-known SQLite behavior, but never previously checked
against this appliance's own real failure mode. Live-reproduced: a
real installed appliance's `control.db`, moved aside to simulate it
becoming genuinely unavailable (a failed mount, accidental deletion, a
disk issue), was **silently, invisibly replaced** by a brand-new,
empty, freshly-schema'd database the moment any web request touched
it. Every API caller -- including the admin -- then saw `"setup
required": true`, **indistinguishable from a genuinely fresh,
never-configured appliance**, with no signal whatsoever that the real
configuration (networks, policies, clients, admins, the DNSCrypt
identity, everything) was sitting right there on disk, merely
temporarily unreachable. An admin who then completed setup again would
create a second, disconnected identity while their real state remained
invisible and unrecovered.

**The identical class of defect exists in the protected secret store**
(`app/v2/secret_store.py`'s `SecretStore.__init__`, which also
unconditionally `mkdir(parents=True, exist_ok=True)`s its root):
live-reproduced the same way -- moving the real secrets directory
aside, then calling `POST /api/dns-transports/dnscrypt/rotate` --
silently created a fresh, empty secret store and reported
`"status":"rotated"` as if everything succeeded normally, with the
real `replication-ca-signing-key` (and any other real secrets)
orphaned at the moved-aside path, invisible to the running appliance.

Both are the exact same underlying mistake: a storage-layer connect/
open helper's "create on first use" convenience, correct and necessary
for legitimate bootstrap (`init-state`, run once, root-only, at package
install time), silently and indistinguishably also firing during
**ongoing request-serving against an already-initialized appliance**,
where a missing file means something is genuinely wrong, not that this
is a fresh install.

## Fix

Both `control_db.connect()` and `SecretStore.__init__` gained a
`create_if_missing: bool = True` parameter, **defaulting to the exact
historical behavior every existing legitimate caller already relies
on** (bootstrap/`init-state`, migration, replication cert issuance,
every `ensure_schema()`, tests) -- zero behavior change for any of
those. `app/v2/webapp.py`'s `_db()` and `_secrets()` (the two call
sites representing ongoing request-serving, as opposed to explicit,
deliberate, root-only bootstrap/migration/replication call sites) now
pass `create_if_missing=False`, raising a clear, specific
`ControlDbMissingError`/`SecretStoreMissingError` instead.

**A second, independent path found and fixed**: `webapp.py`'s
`_ensure_extended_schemas()` -- called from nearly every route handler,
not just through `_db()`'s own connect -- calls each extended module's
`ensure_schema()`, every one of which starts with
`control_db.initialize(path)` (itself `connect()` with the historical
default). Fixing `_db()` alone was **not sufficient**; this second,
independent path would have silently recreated a missing `control.db`
regardless. Now guarded with the same fail-closed existence check
before delegating to any `ensure_schema()` call.

Both new exception types get a dedicated FastAPI handler (matching the
`DatabaseBusyError`/`sqlite3.OperationalError` handlers added in
`docs/v2/login-database-locked-under-load-fix.md`): a specific,
distinct error code (`control_db_missing`/`secret_store_missing`) an
admin or monitoring system can recognize apart from ordinary
validation/auth errors -- never a silent success, never a generic,
unhelpful 500.

## Regression coverage

- `tests/v2/test_control_db.py::TestCreateIfMissing` (3 tests): default
  behavior unchanged, `create_if_missing=False` raises without creating
  anything, succeeds normally against a real already-initialized db.
- `tests/v2/test_secret_store.py::TestCreateIfMissing` (3 tests): same
  shape for `SecretStore`.
- `tests/v2/test_webapp.py::TestControlDbMissing` (2 tests): a real
  HTTP request against a live app instance with `control.db` deleted
  gets a clear `500 control_db_missing`, and the file is **not**
  silently recreated as a side effect -- covering both `_db()` and the
  independent `_ensure_extended_schemas()` path.
- `tests/v2/test_webapp.py::TestControlDbMissing::test_missing_secret_store_returns_clear_error_not_silent_recreation`:
  same proof for the secret store, via a real `dnscrypt/rotate` call
  (the exact real defect reproduction).

Full `tests/v2/` suite after both fixes: 973 passed.

## Full failure-domain/chaos pass (the roadmap's original ask)

Real installed RC28 package, real podman container, all real
background services active. For each of the following, DNS
(`dig @127.0.0.1 cloudflare.com`) was confirmed to answer correctly
(`NOERROR`) immediately after, and `alderpointdns-v2-dnsdist`'s
`NRestarts` confirmed to stay at `0` throughout:

- **Individually stopped, then restarted**, each in turn:
  `alderpointdns-v2-web`, `-analytics`, `-analytics-protobuf-receiver`,
  `-discovery`, `-dns-observer`, `-schedule`, `-tierb`, `-replication`.
  DNS unaffected in every case; `systemctl --failed`: zero failed
  units after each restart.
- **Mass `SIGKILL` (not graceful stop) of all eight simultaneously**:
  DNS unaffected throughout; all eight auto-recovered to `active` via
  systemd's own restart policy with zero manual intervention and zero
  failed units.
- **`control.db` made unavailable** (moved aside) while a valid
  compiled runtime already existed: DNS unaffected (the compiled
  `dnsdist.conf` needs no database at all once promoted); `/api/health`
  correctly reported `"status":"degraded"`,
  `control_db: {"status":"unavailable", ...}` -- this was the live
  reproduction that found the silent-recreation defect above, since
  fixed.
- **Secret store made unavailable** (moved aside): DNS unaffected --
  this was the live reproduction that found the second defect above,
  since fixed.
- **Analytics storage corrupted** (`aggregates.db` and a real Parquet
  partition file overwritten with garbage bytes): DNS unaffected;
  every analytics API endpoint tested
  (`/api/analytics/query-log`, `/api/analytics/top-domains`) returned
  a clean `200` with empty results rather than a crash -- the Parquet
  reader already degrades an unreadable partition to "no data from
  this file" rather than propagating an exception, consistent with
  this project's established fail-safe design. (Note: `aggregates_db`-
  backed `time_series_totals`/`top_dimension_from_aggregates` currently
  have no wired API route at all, so this specific corruption couldn't
  be exercised through the live API this pass -- an unrelated, minor
  scope gap noted for awareness, not chased as a chaos-pass defect.)
- **Combined worst case**: `control.db` AND the secret store both
  unavailable simultaneously, plus `alderpointdns-v2-web`,
  `-analytics`, and `-discovery` all `SIGKILL`ed at the same moment --
  DNS still answered correctly, `NRestarts=0`, `dnsdist` `active`
  throughout.

## Conclusion

The locked architecture's core invariant -- DNS answering is
structurally independent of every management-plane/analytics/
replication component, and of `control.db`/secret-store availability
once a runtime has been compiled and promoted -- holds under real,
live, adversarial chaos testing, including simultaneous multi-
component failure. The one real defect this pass surfaced (silent,
invisible database/secret-store recreation) was in the *admin-facing
correctness* of that architecture, not its DNS-availability guarantee
-- found, fixed, and regression-tested.
