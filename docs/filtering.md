# Filtering, custom rules, and RPZ deployment

Alderpoint DNS filtering is implemented by `app/alderpointdns_compiler.py`
(external blocklists, RPZ compilation, staged deployment) and
`app/custom_rules.py` (the first-class custom filtering rule subsystem).

## External blocklists

- SQLite state at `/var/lib/alderpointdns/alderpointdns.db`
- Public source tracking with per-source parse statistics and last errors
- A curated 19-source public blocklist catalog seeded with `seed-public`,
  spanning AdGuard-hosted assets and GitHub raw URLs
- Bulk source updates with `update-sources` and single-source refreshes with
  `update-source <id>`
- Downloads through the host resolver with connection and total timeouts
- Maximum source size limit of 25 MiB per list
- Preservation of the last successful downloaded copy when an update fails
- Plain domain, hosts-file, basic `||domain^`, and basic `@@||domain^`
  parsing with IDN normalization and invalid/unsupported/duplicate counts
- Generated RPZ at `/var/lib/alderpointdns/compiled/bind/alderpointdns.rpz`

Unsupported AdGuard syntax inside downloaded blocklists (regex rules,
modifiers, cosmetic rules, browser-only rules) is counted and reported, not
interpreted as DNS policy. Custom rules the operator enters directly get the
much richer treatment described below.

## Custom filtering rules

Custom rules live in the `custom_filter_rules` table and are managed from
the Filters page (`/custom-rules`), the `add-custom` CLI subcommand, and the
Import and Migration workflows. Every submitted rule is stored — including
unsupported and invalid ones, which are kept inactive and visible with the
exact reason — so an imported ruleset never silently loses entries.

### Supported rule forms

| Form | Example | Result |
| --- | --- | --- |
| Subdomain block | `\|\|example.org^` | Blocks `example.org` and all subdomains |
| Exact block | `\|example.org^` | Blocks only `example.org` |
| Allow (exception) | `@@\|\|example.org^`, `@@\|example.org^` | Un-blocks, subdomain-wide or exact |
| Hosts sentinel | `0.0.0.0 ads.example.org`, `:: v6.example.org` | Exact-host block (0.0.0.0 and :: are blocking sentinels) |
| Hosts rewrite | `192.168.1.50 nas.example.org`, `::1 v6.example.org` | Exact-host rewrite answering exactly that address (A vs AAAA preserved). Multiple hostnames on one line become one rule each; inline `#` comments are kept |
| Plain domain | `tracker.example` | Blocks domain **and** subdomains (AdGuard Home semantics). The Pi-hole importer requests exact-host semantics instead — see below |
| Comment | `! section`, `# note` | Stored for organization, no DNS effect |
| Regex block | `/^ads[0-9]+\./` | dnsdist-layer NXDOMAIN for matching query names |
| Regex allow | `@@/^good\./` | dnsdist-layer pass that defeats regex blocks |
| Rewrite modifier | `\|\|nas.example^$dnsrewrite=192.168.1.9`, `$dnsrewrite=NOERROR;A;1.2.3.4` | A/AAAA rewrite; follows the base rule's exact-vs-subdomain anchor |
| Important | `\|\|ads.example^$important` | Priority boost used only for allow/block conflict resolution |

### Plain-domain semantics: AdGuard vs Pi-hole

AdGuard Home treats a plain domain in a DNS filter as covering the domain
and its subdomains; Pi-hole's "exact" domain entries cover only the exact
host. `custom_rules.parse_rule(text, source_system, plain_domain_subdomains)`
exposes this as a parameter: manual entry and the AdGuard importer use
subdomain semantics (`True`), the Pi-hole exact-list importer passes
`False`. Conformance tests cover both.

### Unsupported-modifier policy

A narrowing modifier is never stripped to activate the broadened base rule.
Rules carrying `$client`, `$dnstype`, `$denyallow`, `$ctag`, `$badfilter`,
non-address `$dnsrewrite` forms (CNAME, NXDOMAIN, TXT, ...), or any unknown
modifier are stored with `validation_state='unsupported'`, kept inactive,
listed in the UI, and carry an exact reason (for example: "modifier $client
cannot be preserved: Alderpoint DNS has no per-client rule enforcement").
`$important` is translated: it only matters for allow/block conflict
resolution, which the priority column preserves exactly.

### Regex safety model

Regex rules execute inside dnsdist (`RegexRule`), which compiles patterns
with POSIX `regcomp(REG_EXTENDED | REG_ICASE)`. Alderpoint DNS therefore
accepts only a conservative POSIX-ERE-compatible subset:

- maximum length 512 characters; no control characters or newlines (this
  also protects the line-oriented data files from injection)
- must compile with Python `re` *and* pass a POSIX-ERE portability check
- rejected as unsupported (kept, inactive, exact reason): Perl escapes
  (`\d`, `\w`, `\s`, `\b`, any alphanumeric escape), lookaround and every
  other `(?...)` group construct, backreferences (`\1`), non-greedy
  quantifiers (`*?`, `+?`, `??`, `{n,m}?`), and named groups
- rejected as unsupported (kept, inactive, exact reason): a quantified atom
  directly nested inside a quantified group (`(a+)+`, `(a*)*`, `(ab+)*`, ...).
  dnsdist's own POSIX `regcomp` is a non-backtracking automaton and immune to
  this, but the same stored pattern is also matched with Python's
  backtracking `re` engine for the admin-facing "Test a domain" evaluation
  panel (`evaluate_domain`), so it is rejected unconditionally rather than
  only when reachable from that panel

dnsdist matches the query name via `DNSName::toStringNoDot()` (no trailing
dot) case-insensitively. To stay robust either way, the *deployed* copy of a
pattern ending in `$` is rewritten to `\.?$`; the stored pattern is never
modified. Regex blocks answer NXDOMAIN at the dnsdist layer.

## Precedence

Deterministic, highest first:

1. **Local DNS authoritative zones.** dnsdist routes local-zone suffixes to
   BIND before any custom-rule dnsdist action, and BIND answers
   authoritatively, so local zones always win.
2. **Rewrite rules.** RPZ local-data A/AAAA records at the owner name.
   Hosts-style rewrites are exact-host only — no wildcard is emitted, so a
   rewrite for `a.b.example.com` never takes over `b.example.com` or
   `example.com`, and unrelated public records under the same parent keep
   resolving. `$dnsrewrite` on a `||domain^` base also rewrites subdomains.
3. **Explicit allow rules.** Compile-time subdomain-aware subtraction of
   matching entries from the merged external block set — recomputed on
   every compile, so allows survive blocklist refreshes and stored
   blocklist data is never modified — plus emitted `CNAME rpz-passthru.`
   records (exact, and a wildcard for subdomain allows) so allows also
   defeat wildcard blocks of parent domains.
4. **Explicit block rules.** `CNAME .` at the name; a wildcard line is
   emitted only when the rule matches subdomains.
5. **Regex allow, then regex block** (dnsdist layer, evaluated before the
   query reaches BIND). The generated dnsdist rules are ordered: local-zone
   suffix passes, subdomain allow/rewrite suffix passes, exact allow/rewrite
   name passes, regex allow passes, regex block NXDOMAIN — which preserves
   precedences 1–4 against regex blocks. A regex allow defeats regex blocks
   only; it does not subtract external blocklist entries (use a domain
   allow rule for that).
6. **External blocklists.** `CNAME .` plus wildcard, unchanged behavior.

Conflicts at the same owner name are resolved at compile time (RPZ cannot
hold two conflicting records at one name): **rewrite > allow > block**,
except that a block whose priority exceeds the allow's priority (an
`$important` block versus a normal allow) beats the allow entirely. Across
different owner names, standard RPZ most-specific matching applies: an
exact entry beats a wildcard, and a longer wildcard beats a shorter one, so
a block for `child.parent.example` still wins under an allow for
`parent.example` subdomains. The "Test a domain" panel on the Filters page
(`custom_rules.evaluate_domain`) reproduces exactly this walk and also
reports whether the currently compiled RPZ file would block the name.

## Compilation and deployment flow

Every mutation runs the single staged deploy path under the exclusive
`DEPLOY_LOCK` (no overlapping compiles):

1. Collect external blocklists and the active (`enabled=1`,
   `validation_state='valid'`) custom rules; resolve same-owner conflicts;
   subtract allows from the external set.
2. Render the RPZ (custom records first; external entries skip any owner a
   custom record occupies) and stage it.
3. Stage the dnsdist layer under `/var/lib/alderpointdns/compiled/dnsdist/`:
   `custom-rules.conf` (a **static** Lua loader — no user-controlled text is
   ever interpolated into Lua) plus plain one-entry-per-line data files:
   `custom-pass-suffixes.txt`, `custom-pass-exact.txt`,
   `custom-regex-allow.txt`, `custom-regex-block.txt`.
4. Validate: `named-checkzone`, `named-checkconf`, and — when the dnsdist
   layer content actually changed — `dnsdist --check-config` against a
   staged composite of the live dnsdist.conf with the include retargeted at
   the staged files.
5. Atomically activate (`os.replace`), reload BIND, and restart dnsdist
   **only** when the dnsdist-layer file content changed.
6. Health-check: ordinary resolution, a blocked-domain test, an
   allowed-domain test, and a rewrite test when rewrites exist.
7. On any failure, roll back all moved files (RPZ and dnsdist layer),
   reload/restart services, and record the result.
8. Record a sanitized deployment row (counts and test domains only; never
   rule contents, secrets, or query data).

`packaging/dnsdist.conf` includes `custom-rules.conf` through a guarded
`io.open`/`dofile` block placed after the REFUSED opcode rules and before
the final `addAction(AllRule(), PoolAction("alderpointdns_bind"))`.
`custom_rules.ensure_dnsdist_custom_include()` idempotently inserts the same
block into an existing live dnsdist.conf that predates it, taking a backup
copy first.

### Analytics note

dnsdist-layer regex blocks answer NXDOMAIN directly, so they appear in
analytics as NXDOMAIN responses *without* the RPZ SOA marker that
RPZ-blocked queries carry. Regex-blocked queries are therefore counted as
errors/NXDOMAIN rather than as RPZ blocks in block-rate charts.

### Legacy migration

Installs that predate the custom-rule subsystem migrate automatically and
idempotently: rows from the legacy `custom_rules` table are copied once into
`custom_filter_rules` (`source_system='legacy'`, subdomain matching
preserved, enabled state/comment/creation time kept), tracked by a
`migrated_to_v2` column. The legacy table remains for backup and replication
compatibility, but the compile path and UI read only `custom_filter_rules`.
`custom_filter_rules` is included in the `custom_rules` backup component and
in the replication allowlist (`import_job_id` is node-local and not
replicated).

## Commands

Seed the lab source and deploy:

```sh
/opt/alderpointdns/app/alderpointdns_compiler.py init-db
/opt/alderpointdns/app/alderpointdns_compiler.py seed-lab
/opt/alderpointdns/app/alderpointdns_compiler.py deploy
/opt/alderpointdns/app/alderpointdns_compiler.py update-sources
```

Refresh one source without touching the other configured sources:

```sh
/opt/alderpointdns/app/alderpointdns_compiler.py update-source 1
```

Seed the larger public catalog when operationally ready (use
`seed-public --disabled` to load the catalog without enabling it):

```sh
/opt/alderpointdns/app/alderpointdns_compiler.py seed-public
/opt/alderpointdns/app/alderpointdns_compiler.py update-sources
/opt/alderpointdns/app/alderpointdns_compiler.py deploy
```

Add a custom rule from the CLI (writes through the new model, subdomain
semantics preserved):

```sh
/opt/alderpointdns/app/alderpointdns_compiler.py add-custom block ads.example.org
/opt/alderpointdns/app/alderpointdns_compiler.py add-custom allow cdn.example.org --comment "needed by TV"
```

Run tests:

```sh
python3 -m unittest tests.test_custom_rules tests.test_blocklist_parser
/opt/alderpointdns/tests/test_blocklist_deploy.sh
/opt/alderpointdns/tests/test_blocklist_failure_paths.sh
```
