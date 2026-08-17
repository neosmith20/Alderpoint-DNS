# Real V1 -> V2 package migration gate (roadmap Priority 1)

This documents the first real, package-level (not Python-call-level) V1 ->
V2 migration exercise: a real `apt-get install` of `alderpointdns` 1.1.1-1,
seeded with sanitized realistic data via direct SQL against the actual V1
schema (never live/private data), a real `apt-get install` of the current
private V2 candidate on the same host, and the new `alderpointdns-v2-ctl
migrate` CLI run against the real preserved `/var/lib/alderpointdns`
directory — the same command a real operator would run.

## What this closed: there was no real migration entry point at all

Before this session, `app/v2/migration.py`'s full pipeline (detect ->
backup -> ... -> commit) was a real, well-tested library, but nothing
outside the test suite ever called `run_migration()` — no CLI subcommand,
no API route (`webapp.py`'s only migration route is `GET
/api/migration/detect`, explicitly commented "read-only preview in this
pass"), no postinst hook. `commit` itself, by design, only finalizes
*staged* output (see its own docstring) — it never touches a live
install. So "the real package migration gate" the roadmap kept asking for
literally could not be exercised through the package, at any fidelity,
until this session.

Closed by:

- `app/v2/migration.py`: `promote_to_live()` — the missing step from
  "committed staging" to "actually on the live install." See its
  docstring for the full safety contract (refuses on an uncommitted
  state; refuses to clobber an already-admin-configured live install
  without `allow_overwrite`; merges secrets via `SecretStore.import_all`
  rather than a raw file copy; regenerates the dnsdist config at the real
  live listen address rather than blindly promoting the staging
  health-check's throwaway-port artifact).
- `scripts/v2/alderpointdns_v2_ctl.py`: new `migrate` subcommand — stages
  by default, `--promote` writes it live, resumable via the existing
  `MIGRATION_DIR/state.json` durable-state mechanism.

## Real package-level run

Host: this session's real KVM VM (not nested), via
`podman run --privileged --systemd=always`.

1. Built and installed real `alderpointdns_1.1.1-1_all.deb` (V1) into a
   fresh Debian 13 systemd container. Clean install, `alderpointdns` +
   `alderpointdns-analytics` reached `active`.
2. Seeded sanitized realistic data directly via SQL against the real V1
   schema (not the simplified test fixture): 1 admin (real Argon2id hash
   via the installed `argon2` library), 5 clients + identifiers, 10 local
   DNS records, 20 custom rules (10 block/10 allow), 1 notification
   provider with a secret, 1 DoT upstream (`1.1.1.1:853`,
   `cloudflare-dns.com`), `encryption_settings` with `dot_enabled` and
   `doh_enabled` both on (matching V1's real defaults), and a batch of
   `query_events` rows (V1's own live analytics-retention worker pruned
   most of these down to 7 during the test, which is real V1 behavior,
   not a test artifact).
3. Stopped V1 services, installed `alderpointdns-v2_2.0.0~private7-1_all.deb`
   on the **same host**. `apt-get install` automatically removed the
   `alderpointdns` package (a `Conflicts`/`Replaces` relationship) but
   explicitly preserved `/var/lib/alderpointdns` ("Alderpoint DNS
   persistent data remains..." — apt's own message), exactly the state a
   real in-place migration needs. V2's own postinst completed normally.
4. `python3 /opt/alderpointdns-v2/scripts/v2/alderpointdns_v2_ctl.py
   migrate /var/lib/alderpointdns` (no flags): staged successfully —
   `{'admins_migrated': 1, 'clients_migrated': 5,
   'client_identifiers_migrated': 5, 'networks_migrated': 1,
   'local_dns_records_migrated': 10, 'filtering_blocked': 10,
   'filtering_allowed': 10, 'upstreams_migrated': 1,
   'notifications_migrated': 1, 'legacy_query_history_rows': 7}` — plus
   the expected encrypted-transport-not-migrated warning (DoH, DoT) and
   the expected network-profile-simplification warning.
5. Re-ran with `--promote`: resumed the same durable migration record
   (`status=completed`), then promoted successfully —
   `{'control_db': '/var/lib/alderpointdns-v2/control.db',
   'secrets_promoted': 1, 'dnsdist_config':
   '/var/lib/alderpointdns-v2/compiled/dnsdist.conf'}`.
6. Restarted `alderpointdns-v2-web`/`alderpointdns-v2-dnsdist`. Verified:
   live `control.db` has the migrated admin; HTTPS management responds
   (real auth-required response, not a crash); a real DNS query for
   `example.com` through the live packaged dnsdist returns `NOERROR` via
   the migrated DoT upstream (`1.1.1.1:853`) — upstream forwarding
   genuinely works end to end post-migration.

## Real defect found by this package-level test that no unit test caught

A query for `host1.lan` (one of the 10 migrated local DNS records)
returned `NXDOMAIN` from the live server, not the migrated `10.20.1.1`
answer. Inspecting the promoted `dnsdist.conf`:

```
setLocal("0.0.0.0:53")
newServer({address="1.1.1.1:853", tls="openssl", subjectName="cloudflare-dns.com"})
setServerPolicy(firstAvailable)
```

The migrated local-DNS zone and RPZ (blocklist) zone files exist on disk,
validated and promoted (`.../compiled/alderpointdns-v2-local.zone`,
`.../compiled/bind/alderpointdns-v2.rpz`) — but the generated
`dnsdist.conf` never references either one. There is no `rpzFile()` call
and no local-zone routing rule. **Neither migrated local DNS records nor
migrated block/allow rules are actually enforced by the live runtime.**
Only upstream forwarding is real.

This is **not a migration-specific bug** — it traces back further:

- `app/v2/dnsdist_gen.py`'s generator (`generate_dnsdist_config`/
  `generate_dnsdist_config_from_profiles`, used by both migration's
  `_stage_generate_runtime_config` and `alderpointdns-v2-ctl
  generate-runtime`) has no RPZ or local-zone parameter at all — it only
  ever emits `setLocal` + upstream `newServer`/pool/routing directives.
- `app/v2/dnsdist_policy_runtime.py` ("V2 real per-effective-policy
  runtime", used by the live management API's `runtime_compile.py` when
  an admin manually configures a client/policy through the web UI) is a
  *separate*, more complete compiler — but grep-verified: nothing
  anywhere in the codebase calls `rpzFile`/`rpzMaster`, so even that path
  does not load the BIND RPZ zone into dnsdist either. Its blocking
  behavior (if any) is presumably native dnsdist rules, not RPZ — this
  needs its own follow-up investigation, out of scope for what this
  session confirmed.
- Compounding this, `mconv.migrate_filtering()`/`mconv.migrate_local_dns()`
  never write into `control.db` at all (grep-verified) — they only ever
  feed the standalone RPZ/zone-file generators. So even redirecting
  migration's runtime-generation step to call the "real" policy compiler
  instead of the simplified generator would not, by itself, fix this: the
  real compiler reads rulesets/bindings from `control.db`
  (`policy_store.py`'s schema), which migration never populates with the
  migrated filtering/local-DNS data today.

**Net effect for a real migrated appliance today: DNS resolution and the
migrated upstream transport work; migrated ad-blocking and migrated LAN
hostnames do not take effect until an admin manually re-adds them through
the (working) management UI.** This is a real, user-visible gap, not
theoretical — found only by testing the actual live packaged runtime
end-to-end, exactly the reason the roadmap called for a real
package-level gate instead of trusting Python-level stage tests alone.

## Fixed (follow-up session, same day)

Implemented option (a): migrated filtering/local-DNS state is now written
into `control.db` in the schema `policy_store.py`/`runtime_compile.py`
already expect, and `promote_to_live` now calls the real compiler
(`runtime_compile.recompile_and_promote`) instead of the simplified
generator.

- `app/v2/policy_store.py`: added `ensure_local_dns_schema`/
  `load_local_dns_records`/`upsert_local_dns_record` — shared, canonical
  local-DNS storage (identical DDL to `webapp.py`'s previously-private
  copy, so either module can create the table first safely).
- `app/v2/dnsdist_policy_runtime.py`: `compile_multi_policy_dnsdist_config`
  gained a `local_dns_records` parameter — compiles appliance-wide,
  highest-precedence `SpoofAction`/`SpoofCNAMEAction` rules for A/AAAA/
  CNAME records (PTR intentionally excluded, needs a different matcher,
  not implemented — now surfaced via a `ptr_records_skipped` count rather
  than silently dropped).
- `app/v2/runtime_compile.py`: `recompile_and_promote` now reads local DNS
  records from control.db and passes them through — this also fixes the
  **fresh-install / live management API path**, not just migration: local
  DNS records added through the working `/api/local-dns` endpoint were
  never enforced by the live runtime either, before this fix.
- `app/v2/migration_convert.py`: new `migrate_local_dns_to_control_db()`
  (writes migrated records into the shared table) and
  `migrate_filtering_to_control_db()` (migrated block domains become one
  `service_definitions`/`service_blocking_ruleset` — reusing the existing,
  already-wired mechanism rather than inventing new storage — pointed at
  by the global policy layer's `service_blocking_ruleset_id`). V1 allow-
  list domains are intentionally not written anywhere: they exist to
  override V1's separate default aggregator blocklist, which is not
  migrated, so they have nothing to override; a preview/migration warning
  now says this explicitly instead of the domains just vanishing with no
  explanation. Also fixed a second, related wiring gap found while doing
  this: `migrate_upstreams` created the `migrated-default` upstream
  profile row but never pointed the global policy layer's
  `upstream_profile_id` at it — the real compiler (unlike the simplified
  generator used before this fix) only ever uses a profile a policy layer
  references, so without this the migrated DoT upstream would have been
  silently ignored in favor of the hardcoded default resolvers the moment
  promotion switched to the real compiler.
- `app/v2/migration.py`: `_stage_migrate_policies` now persists into
  control.db in addition to the existing in-memory/JSON tracking (still
  used by the RPZ/local-zone file generators, kept as secondary defense-
  in-depth); `promote_to_live` now calls `runtime_compile.
  recompile_and_promote()` against the live control.db as the actual
  source of the live `dnsdist.conf`, instead of the simplified single-
  upstream generator.

**Re-verified with a full real package-level retest** (private8, same
procedure as above: real V1 install, same sanitized seed data, real V2
install on the same host, real `alderpointdns-v2-ctl migrate --promote`,
real service restart):

- `host1.lan` (migrated local DNS record): real UDP query → `NOERROR`,
  answer contains `10.20.1.1`.
- `rule2.example.test` (migrated blocked domain): real UDP query →
  `NXDOMAIN`.
- `example.com` (real upstream, via the migrated DoT profile): real UDP
  query → `NOERROR`.

New regression coverage: `tests/v2/test_dnsdist_policy_runtime.py`
(`TestLocalDnsRecords`, 6 tests incl. real `dnsdist --check-config`
validation) and `tests/v2/test_migration_promote_live.py` (2 new tests,
one starting a real dnsdist process against the promoted config and
proving both a local-DNS answer and a blocked-domain refusal over the
wire). `tests/v2`: 820 passed (812 + 8). V1 unaffected (1188 passed,
unchanged).

Everything else the real package-level test exercised — V1 detection,
backup, preview, per-object migration (admins/clients/notifications/
upstreams), secret extraction and promotion, control.db promotion,
upstream DoT forwarding, the encrypted-transport-not-migrated warning,
service restart picking up the promoted state — worked correctly with a
real installed package on a real host, both before and after this fix.
