# Import: AdGuard Home / Pi-hole / generic (beta-rescue priority 2)

## What this restores

V2 previously had no import surface at all. This adds a staged
preview -> apply importer for:

- AdGuard Home (uploaded YAML config, or a live API connection)
- Pi-hole (pasted/concatenated exported lists: adlists, exact/regex
  block+allow, `custom.list` hosts, `cname=` rewrites)
- hosts files
- BIND zone files (a practical subset: `name [ttl] [IN] TYPE data`)
- Alderpoint-native CSV / XLSX / JSON

## Design

`app/v2/import_migration.py` reuses `app.importer`'s and
`app.custom_rules`'s pure, source-format-shaped parsing/classification
functions (mature, already covered by V1's own test suite) but never V1's
apply/database layer. Every write goes through V2's own control.db +
`policy_store` schema, and every apply is followed by the ordinary V2
validate -> compile -> promote pipeline (`webapp._mutate_and_promote`) --
there is no bespoke import-only runtime path.

Local DNS entries (rewrites/hosts/zone/custom.list/cname) become normal
`local_dns_records` rows via `policy_store.upsert_local_dns_record`.

Block-domain rules reuse the exact mechanism
`app/v2/migration_convert.py`'s V1->V2 package migration already
established for this: one `service_definitions` row per import job
(`import-job-<id>`), accumulated into a shared
`service_blocking_rulesets` ruleset (`imported-blocklist`), with the
global policy layer's `service_blocking_ruleset_id` pointed at it *only*
if nothing else already claimed that single slot -- if the operator (or
a prior V1 migration) already has a ruleset assigned there, the import is
still stored but flagged as an explicit conflict/unsupported item rather
than silently displacing existing enforcement.

## Deliberately NOT implemented

- **Blocklist-subscription URLs** (AdGuard `filters:`, Pi-hole
  `adlists.list`): V2 has no subscribed/refreshable blocklist feature.
  Each subscription source becomes an explicit unsupported finding with
  actionable guidance (fetch the list yourself, import it as hosts/CSV)
  rather than a live fetch of an operator-supplied URL from an
  authenticated import endpoint, or a silent drop.
- **Global allow-domain overrides**: V1's "allow" domains exist to
  override entries in V1's much larger default aggregator blocklist,
  which V2 does not have either -- same documented gap
  `migration_convert.py` already notes for V1->V2 package migration.
- Regex/adblock-syntax rules beyond plain block/allow domains (no V2
  regex-domain-match engine); reported as unsupported with the original
  rule text preserved.
- AdGuard per-client scoped settings, access allow/disallow lists: no V2
  runtime equivalent yet; reported, not silently dropped.

## Proof

- `tests/v2/test_import_migration.py`: unit coverage for every source
  type's parse -> plan -> apply -> idempotent re-apply, an HTTP-level
  round trip through the real webapp routes, and
  `TestRealRuntimeProof`: import -> apply -> the exact
  `runtime_compile.build_bindings` + `compile_multi_policy_dnsdist_config`
  the live webapp uses -> a real `dnsdist` process -> real DNS queries
  proving the imported Local DNS record answers with the imported IP and
  the imported blocked domain (and, for AdGuard's `||domain^` suffix
  rules, its subdomains) is really NXDOMAIN'd.
- `tests/v2/browser/chromium_ui_harness.js`: a full pihole and a full
  AdGuard import driven entirely through the UI (parse -> preview ->
  apply), including a real multipart file upload via the File API for
  the AdGuard path.
